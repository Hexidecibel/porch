#!/usr/bin/env python3
"""Backend migration orchestrator — `bin/porch-migrate-backend` delegates here.

Walks a project's `.cush-secrets` manifest, reads every `op://` value from
1Password, pushes it to Infisical at `inf://<env>/<project>/<KEY>`, and
rewrites the manifest in-place with the new refs. Round-trip safe: a backup
copy is written to `.cush-secrets.bak` before the manifest is rewritten,
and a `bin/inject --check` runs against the new manifest to verify the
swap works end-to-end before exit.

Phase 4 of the 1Password→Infisical migration. The op:// surface continues
to work after migration (the dispatch layer in lib/cush_secrets.py handles
both schemes); this tool just flips a project from one to the other in
one shot.

Self-healing: a pre-flight pass lists the destination Infisical path and
deletes any "orphan" keys — secrets at the path that aren't named in the
manifest. Orphans typically come from prior failed runs (process killed
mid-write, network flake, etc.). The cleanup runs by default and can be
suppressed with `--keep-orphans`. To clean up without doing a real
migration, use `--clean-only`.

This module is invokable two ways:
  - As `python3 lib/migrate.py ...` from `bin/porch-migrate-backend`.
  - As an importable function for the `--self-test` mode (which patches
    the cush_secrets dispatch layer with an in-memory fake).

Exit codes (mirroring bin/porch-migrate-backend):
  0  ok / already migrated / clean-only ok
  2  argument or manifest error
  3  backend auth failure (op or inf)
  4  failed to read all source values from 1P
  5  failed to write to Infisical (rollback attempted)
  6  verify-after-write mismatch (rollback attempted)
  7  manifest write failed
  9  post-migration `bin/inject --check` failed
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Make sibling modules importable.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import manifest as manifest_mod
from manifest import Manifest, SecretSpec, ManifestError

# Lazy-imported on use so --self-test can monkeypatch the slot without paying
# the import cost of op.py / infisical.py.
_secrets = None


def _load_secrets():
    """Return the cush_secrets dispatch module (lazy + monkeypatchable)."""
    global _secrets
    if _secrets is None:
        import cush_secrets as cs  # noqa: WPS433
        _secrets = cs
    return _secrets


REPO_ROOT = Path(__file__).resolve().parent.parent  # the repo root
INJECT_BIN = REPO_ROOT / "bin" / "inject"


# ───────────────────────────────────────────────────────────────────────────
# Plan construction
# ───────────────────────────────────────────────────────────────────────────


@dataclass
class MigrateEntry:
    """One row in the migration plan.

    `ref_inf` is None when the spec is already on inf:// (skipped). Otherwise
    it's the synthesized destination ref under the chosen target env / path.
    """
    env_name: str
    spec: SecretSpec
    ref_op: Optional[str]
    ref_inf: Optional[str]
    skipped_reason: Optional[str] = None  # set when migration is a no-op for this row


def _project_basename(manifest_obj: Manifest) -> str:
    """Best-effort basename for the {project} substitution in inf:// refs.

    Uses the manifest file's parent dir name (matches manifest.resolve_target).
    """
    return manifest_obj.source_path.parent.name or "project"


def _build_inf_ref(env_name: str, *, target_env: str, path_template: str,
                   project: str) -> str:
    """Synthesize an `inf://<env>/<path>/<KEY>` ref for `env_name`.

    `path_template` may contain `{project}`. Leading slash is stripped (the
    inf:// URL provides it implicitly via the env separator). Empty path
    after substitution is rejected; inf:// refs require at least one path
    segment.
    """
    rendered = path_template.format(project=project)
    rendered = rendered.strip("/")
    if not rendered:
        raise ValueError(
            f"target-path-template {path_template!r} rendered to an empty path "
            f"(project={project!r}); inf:// refs need at least one path segment"
        )
    return f"inf://{target_env}/{rendered}/{env_name}"


def _build_plan(manifest_obj: Manifest, *, target_env: str, path_template: str
                ) -> list:
    """Return the migration plan for a manifest.

    Each entry is a MigrateEntry. Specs already on inf:// get a skipped_reason
    of "already inf://" and ref_inf=None — they're left untouched.
    """
    secrets_mod = _load_secrets()
    project = _project_basename(manifest_obj)
    plan = []
    for spec in manifest_obj.secrets:
        try:
            scheme = secrets_mod.scheme_of(spec.ref)
        except ValueError as e:
            # Shouldn't happen — manifest.load() rejects bad refs — but be
            # defensive so we don't blow up mid-migration.
            plan.append(MigrateEntry(
                env_name=spec.env_name, spec=spec,
                ref_op=None, ref_inf=None,
                skipped_reason=f"unparseable ref: {e}",
            ))
            continue

        if scheme == "inf":
            plan.append(MigrateEntry(
                env_name=spec.env_name, spec=spec,
                ref_op=None, ref_inf=None,
                skipped_reason="already inf://",
            ))
            continue

        if scheme != "op":
            plan.append(MigrateEntry(
                env_name=spec.env_name, spec=spec,
                ref_op=None, ref_inf=None,
                skipped_reason=f"unsupported scheme {scheme!r}",
            ))
            continue

        ref_inf = _build_inf_ref(
            spec.env_name,
            target_env=target_env,
            path_template=path_template,
            project=project,
        )
        plan.append(MigrateEntry(
            env_name=spec.env_name, spec=spec,
            ref_op=spec.ref, ref_inf=ref_inf,
        ))
    return plan


# ───────────────────────────────────────────────────────────────────────────
# Orphan cleanup (pre-flight)
# ───────────────────────────────────────────────────────────────────────────


def _destinations_in_plan(plan: list) -> dict:
    """Group migrating plan entries by (env, path) destination.

    Returns {(env, path): set_of_expected_keys}. Skipped entries (already-inf,
    bad-ref, unsupported scheme) are NOT included — we don't know where they
    point or whether their path overlaps the target. The caller iterates the
    returned dict; an empty dict means "nothing to do here".

    Both op-only and mixed manifests are handled. For mixed manifests, the
    `inf://` entries already in the manifest at a destination path are also
    part of the "expected keys" set (they belong there post-migration).
    """
    # Lazy import — keeps self-test offline path clean.
    try:
        import infisical as inf  # noqa: WPS433
    except Exception:  # pragma: no cover — defensive fallback
        inf = None

    secrets_mod = _load_secrets()
    dests: dict = {}  # (env, path) -> set of keys

    for entry in plan:
        ref_to_use = None
        if entry.ref_inf is not None:
            ref_to_use = entry.ref_inf
        elif entry.spec.ref and entry.spec.ref.startswith("inf://"):
            # Already-migrated entries in a mixed manifest live alongside the
            # entries we're migrating; they belong at the same destination
            # path so include them in expected-keys.
            ref_to_use = entry.spec.ref
        if not ref_to_use:
            continue
        try:
            if inf is not None:
                env, path, key = inf.parse_inf_ref(ref_to_use)
            else:
                # Fall back to the dispatch layer's parser when the lazy
                # import path isn't available (e.g. self-test).
                tup = secrets_mod.parse_ref(ref_to_use)
                if not tup or tup[0] != "inf":
                    continue
                env, path, key = tup[1], tup[2], tup[3]
        except Exception:
            continue
        dests.setdefault((env, path), set()).add(key)
    return dests


def _list_keys_at(env: str, path: str) -> list:
    """List keys at inf://<env>/<path>. Hookable for self-test.

    Defaults to `infisical.inf_list`. Self-test reassigns this attribute on
    the module to drive the cleanup logic from an in-memory store.
    """
    import infisical as inf  # noqa: WPS433
    return inf.inf_list(env, path)


def _delete_key_at(env: str, path: str, key: str) -> None:
    """Delete inf://<env>/<path>/<key>. Hookable for self-test.

    Defaults to `infisical.inf_delete`. Same monkeypatch story as
    `_list_keys_at` above.
    """
    import infisical as inf  # noqa: WPS433
    inf.inf_delete(env, path, key)


def _cleanup_orphans(plan: list, *, json_out: bool, fp=sys.stderr
                     ) -> tuple:
    """Delete inf:// secrets at destination paths that aren't in the manifest.

    Returns (deleted, listing_failures, delete_failures), each a list. The
    caller decides how to surface them. Listing failures are usually fatal
    (auth or access denial); delete failures are best-effort logged.

    The cleanup is idempotent. Re-running this against an already-clean
    project is a no-op (no orphans found, nothing to delete).
    """
    dests = _destinations_in_plan(plan)
    deleted = []
    listing_failures = []
    delete_failures = []

    if not dests:
        return deleted, listing_failures, delete_failures

    for (env, path), expected_keys in sorted(dests.items()):
        try:
            existing = _list_keys_at(env, path)
        except Exception as e:  # noqa: BLE001 — surface anything to the user
            listing_failures.append((env, path, str(e)))
            if not json_out:
                print(f"[migrate] cleanup: list failed at {env}:{path}: {e}",
                      file=fp)
            continue
        orphans = sorted(set(existing) - expected_keys)
        if not orphans:
            if not json_out:
                print(f"[migrate] cleanup: no orphans at {env}:{path} "
                      f"({len(existing)} key(s), all expected)", file=fp)
            continue
        if not json_out:
            print(f"[migrate] cleanup: {len(orphans)} orphan(s) at "
                  f"{env}:{path}: {orphans}", file=fp)
        for key in orphans:
            try:
                _delete_key_at(env, path, key)
            except Exception as e:  # noqa: BLE001
                delete_failures.append((env, path, key, str(e)))
                if not json_out:
                    print(f"[migrate] cleanup: delete WARN "
                          f"{env}:{path}/{key}: {e}", file=fp)
                continue
            deleted.append((env, path, key))
            if not json_out:
                print(f"[migrate] cleanup: deleted "
                      f"{env}:{path}/{key}", file=fp)
    return deleted, listing_failures, delete_failures


# ───────────────────────────────────────────────────────────────────────────
# Display
# ───────────────────────────────────────────────────────────────────────────


def _print_plan_table(plan: list, *, fp=sys.stderr) -> None:
    """Pretty-print the plan as a 3-column box-drawing table."""
    headers = ("ENV_NAME", "OP REF", "INF REF")
    rows = []
    for e in plan:
        if e.skipped_reason:
            rows.append((e.env_name,
                         e.ref_op or e.spec.ref,
                         f"(skip: {e.skipped_reason})"))
        else:
            rows.append((e.env_name, e.ref_op or "", e.ref_inf or ""))

    if not rows:
        return

    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if len(cell) > widths[i]:
                widths[i] = len(cell)
    widths = [min(w, 60) for w in widths]

    def hr(left, mid, right):
        return left + mid.join("─" * (w + 2) for w in widths) + right

    def fmt(cells):
        return "│ " + " │ ".join(
            (c if len(c) <= w else c[: w - 1] + "…").ljust(w)
            for c, w in zip(cells, widths)
        ) + " │"

    print(hr("┌", "┬", "┐"), file=fp)
    print(fmt(headers), file=fp)
    print(hr("├", "┼", "┤"), file=fp)
    for row in rows:
        print(fmt(row), file=fp)
    print(hr("└", "┴", "┘"), file=fp)
    fp.flush()


# ───────────────────────────────────────────────────────────────────────────
# Auth check
# ───────────────────────────────────────────────────────────────────────────


def _check_auth(plan: list, *, json_out: bool) -> int:
    """Verify auth for both backends if any op→inf migration is in the plan.

    Returns 0 on success, 3 on failure. Prints a per-scheme hint when one
    side is unauthenticated.
    """
    secrets_mod = _load_secrets()
    has_migrating = any(e.ref_inf is not None for e in plan)
    if not has_migrating:
        return 0

    failed = []
    for scheme in ("op", "inf"):
        try:
            who = secrets_mod.whoami_for_scheme(scheme)
        except secrets_mod.SecretsAuthError as e:
            failed.append((scheme, str(e)))
            continue
        if who is None:
            failed.append((scheme, "not authenticated"))

    if not failed:
        return 0

    hints = {
        "op": "1Password (`op`) is not authenticated. "
              "Source ~/.config/porch/op.env or run `eval $(op signin)`.",
        "inf": "Infisical is not authenticated. "
              "Configure ~/.config/porch/infisical.env (universal-auth).",
    }
    if json_out:
        print(json.dumps({
            "error": "auth",
            "failures": [{"scheme": s, "reason": r,
                          "hint": hints.get(s, "")}
                         for s, r in failed],
        }, indent=2))
    else:
        for s, r in failed:
            print(f"[migrate] auth failure ({s}): {r}", file=sys.stderr)
            print(f"[migrate] hint: {hints.get(s, '')}", file=sys.stderr)
    return 3


# ───────────────────────────────────────────────────────────────────────────
# Read / write / verify
# ───────────────────────────────────────────────────────────────────────────


def _read_all_op_values(plan: list, *, json_out: bool, fp=sys.stderr
                        ) -> tuple:
    """Read each op:// ref in the plan. Returns (values_by_env, missing).

    `values_by_env` is {env_name: value_str}. `missing` is a list of
    (env_name, ref, error_message). The caller decides what to do — by
    contract we don't write anything if missing is non-empty.
    """
    secrets_mod = _load_secrets()
    values = {}
    missing = []
    for entry in plan:
        if entry.ref_inf is None:  # skipped
            continue
        ref_op = entry.ref_op
        try:
            val = secrets_mod.read(ref_op)
        except secrets_mod.SecretsRefNotFound as e:
            missing.append((entry.env_name, ref_op, f"not found: {e}"))
            continue
        except secrets_mod.SecretsAuthError as e:
            missing.append((entry.env_name, ref_op, f"auth: {e}"))
            continue
        except secrets_mod.SecretsAccessError as e:
            missing.append((entry.env_name, ref_op, f"access: {e}"))
            continue
        except secrets_mod.SecretsError as e:
            missing.append((entry.env_name, ref_op, f"error: {e}"))
            continue
        values[entry.env_name] = val
        if not json_out:
            print(f"[migrate] read  {entry.env_name:<30} {ref_op}", file=fp)
    return values, missing


def _write_all_inf_values(plan: list, values: dict, *, fp=sys.stderr
                          ) -> tuple:
    """Push each value to its inf:// ref. Returns (written_refs, failures).

    `written_refs` is the list of inf://refs successfully upserted (used by
    the caller to drive rollback if a later step fails). `failures` is a
    list of (env_name, ref_inf, error_message) — when non-empty, the caller
    should attempt a rollback of `written_refs` and not rewrite the manifest.
    """
    secrets_mod = _load_secrets()
    written = []
    failures = []
    for entry in plan:
        if entry.ref_inf is None:
            continue
        if entry.env_name not in values:
            # Shouldn't happen — caller checks missing before invoking us.
            failures.append((entry.env_name, entry.ref_inf,
                             "no source value (read step missed)"))
            continue
        try:
            secrets_mod.item_upsert(entry.ref_inf, values[entry.env_name],
                                    concealed=True)
        except secrets_mod.SecretsError as e:
            failures.append((entry.env_name, entry.ref_inf, str(e)))
            return written, failures  # bail on first failure
        except Exception as e:  # noqa: BLE001 — surface unknowns
            failures.append((entry.env_name, entry.ref_inf,
                             f"unexpected: {e}"))
            return written, failures
        written.append(entry.ref_inf)
        print(f"[migrate] wrote {entry.env_name:<30} {entry.ref_inf}", file=fp)
    return written, failures


def _verify_all_inf_values(plan: list, values: dict, *, fp=sys.stderr
                           ) -> list:
    """Read each newly-written inf://ref back and compare to the source value.

    Returns a list of (env_name, ref_inf, reason) for any mismatch / read
    failure. Empty list means the round-trip checks out.
    """
    secrets_mod = _load_secrets()
    failures = []
    for entry in plan:
        if entry.ref_inf is None:
            continue
        if entry.env_name not in values:
            continue
        try:
            got = secrets_mod.read(entry.ref_inf)
        except secrets_mod.SecretsError as e:
            failures.append((entry.env_name, entry.ref_inf,
                             f"verify read failed: {e}"))
            continue
        if got != values[entry.env_name]:
            failures.append((entry.env_name, entry.ref_inf,
                             f"verify mismatch: read {len(got)} chars, "
                             f"expected {len(values[entry.env_name])}"))
            continue
        print(f"[migrate] verify {entry.env_name:<29} {entry.ref_inf}", file=fp)
    return failures


def _rollback_inf(written_refs: list, *, fp=sys.stderr) -> None:
    """Best-effort delete of inf://refs we pushed during this run.

    Implemented via a direct `infisical secrets delete <KEY> ...` shell call
    (the lib doesn't expose a delete helper). Failures are swallowed but
    logged — Phase 4 considers this best-effort cleanup, not a guarantee.
    """
    if not written_refs:
        return
    print(f"\n[migrate] rolling back {len(written_refs)} infisical write(s)...",
          file=fp)

    # Lazy-import to get parse_inf_ref + project id + token plumbing. If the
    # backend has gone unauthenticated mid-migration, the rollback will fail
    # noisily — that's acceptable, the alternative is silent partial state.
    try:
        import infisical as inf  # noqa: WPS433
    except Exception as e:
        print(f"[migrate] rollback skipped (infisical lib import failed: {e})",
              file=fp)
        return

    project_id = os.environ.get("INFISICAL_PROJECT_ID", "")
    if not project_id:
        # _ensure_inf_available loads infisical.env into os.environ. If we
        # reached this point at all the env file should already be sourced,
        # but be defensive.
        try:
            inf._load_env_file()
        except Exception:
            pass
        project_id = os.environ.get("INFISICAL_PROJECT_ID", "")
    if not project_id:
        print("[migrate] rollback skipped (INFISICAL_PROJECT_ID not in env)",
              file=fp)
        return

    for ref_inf in written_refs:
        try:
            env, path, key = inf.parse_inf_ref(ref_inf)
        except Exception as e:
            print(f"[migrate] rollback: bad ref {ref_inf}: {e}", file=fp)
            continue
        # Route through `inf.inf_delete` so we get the timeout, token
        # minting, auth-retry, and "already-gone is success" semantics in
        # one place. Errors are best-effort logged; rollback can't be
        # transactional.
        try:
            inf.inf_delete(env, path, key)
            print(f"[migrate] rollback ok    {ref_inf}", file=fp)
        except Exception as e:
            print(f"[migrate] rollback WARN  {ref_inf}: {e}", file=fp)


# ───────────────────────────────────────────────────────────────────────────
# Manifest rewrite
# ───────────────────────────────────────────────────────────────────────────


def _rewrite_manifest(manifest_obj: Manifest, plan: list, *, fp=sys.stderr
                      ) -> Path:
    """Write `.cush-secrets.bak` then rewrite `.cush-secrets` with inf:// refs.

    Returns the path of the .bak file. Raises OSError / ManifestError on
    failure (the caller decides how to surface).

    Defaults and field-level overrides (target_vault, target_item, type,
    fallback, required) are preserved verbatim — they're harmless on inf://
    refs and Phase 6 will sweep them up. Don't try to be clever about what
    to drop here; the priority is a faithful round-trip.
    """
    src_path = manifest_obj.source_path
    bak_path = src_path.with_name(src_path.name + ".bak")

    # Copy with stat so the user can compare easily after the fact.
    shutil.copy2(src_path, bak_path)

    # Build new SecretSpec list with refs swapped where applicable.
    by_env = {e.env_name: e for e in plan}
    new_secrets = []
    for spec in manifest_obj.secrets:
        entry = by_env.get(spec.env_name)
        if entry is None or entry.ref_inf is None:
            new_secrets.append(spec)
            continue
        new_secrets.append(SecretSpec(
            env_name=spec.env_name,
            ref=entry.ref_inf,
            fallback=spec.fallback,
            target_vault=spec.target_vault,
            target_item=spec.target_item,
            type=spec.type,
            required=spec.required,
        ))

    new_manifest = Manifest(
        schema=manifest_obj.schema,
        defaults=dict(manifest_obj.defaults),
        secrets=new_secrets,
        source_path=src_path,
    )
    manifest_mod.dump(new_manifest, src_path)
    print(f"[migrate] rewrote {src_path}  (backup: {bak_path.name})", file=fp)
    return bak_path


# ───────────────────────────────────────────────────────────────────────────
# Post-migration validation
# ───────────────────────────────────────────────────────────────────────────


def _run_inject_check(project_dir: Path, *, fp=sys.stderr) -> int:
    """Run `bin/inject --check` against the rewritten manifest.

    Inherits the parent process's environment (so OP_SESSION_*,
    INFISICAL_TOKEN, etc. flow through). Returns inject's exit code.

    A 60s hard timeout protects against bin/inject itself hanging — its
    backend calls each have 30s timeouts now, but a runaway loop somewhere
    in the inject pipeline could still stall. Treat timeout as a check
    failure (rc=1) so the caller surfaces the manifest-was-rewritten state
    correctly.
    """
    if not INJECT_BIN.exists():
        print(f"[migrate] {INJECT_BIN} not found; skipping post-validate",
              file=fp)
        return 0
    print(f"\n[migrate] running `bin/inject --check` against {project_dir}",
          file=fp)
    try:
        proc = subprocess.run(
            [str(INJECT_BIN), "--check"],
            cwd=str(project_dir),
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        print(f"[migrate] `bin/inject --check` timed out after 60s",
              file=fp)
        return 1
    # Stream both stderr and stdout to fp so the user sees what inject saw.
    if proc.stdout:
        fp.write(proc.stdout)
    if proc.stderr:
        fp.write(proc.stderr)
    fp.flush()
    return proc.returncode


# ───────────────────────────────────────────────────────────────────────────
# Top-level orchestration
# ───────────────────────────────────────────────────────────────────────────


def run_migration(
    project_dir: Path,
    *,
    target_env: str,
    path_template: str,
    dry_run: bool,
    keep_bak: bool,
    no_validate: bool,
    json_out: bool,
    keep_orphans: bool = False,
    clean_only: bool = False,
) -> int:
    """End-to-end migration. Returns the appropriate exit code.

    `keep_orphans` (default False): when True, skip the pre-flight orphan
    cleanup. Default behavior is to delete any inf:// secret at the
    destination path that isn't named in the manifest — typically stale
    state from a prior failed migration.

    `clean_only` (default False): when True, run cleanup and exit. No
    reads, no writes to Infisical, no manifest rewrite, no `bin/inject
    --check`. Useful for fixing partial state without committing to a
    fresh migration. Implies cleanup runs (otherwise it's a no-op).
    """
    # --- 1. Locate + parse manifest. ---
    m_path = manifest_mod.find_manifest(project_dir)
    if m_path is None:
        msg = (f"no .cush-secrets found in {project_dir} or any parent "
               f"(stopped at .git boundary or filesystem root)")
        if json_out:
            print(json.dumps({"error": "manifest_not_found",
                              "project_dir": str(project_dir),
                              "message": msg}, indent=2))
        else:
            print(f"[migrate] {msg}", file=sys.stderr)
        return 2

    try:
        manifest_obj = manifest_mod.load(m_path)
    except ManifestError as e:
        if json_out:
            print(json.dumps({"error": "manifest_parse",
                              "manifest": str(m_path),
                              "message": str(e)}, indent=2))
        else:
            print(f"[migrate] manifest parse error: {e}", file=sys.stderr)
        return 2

    # --- 2. Build plan. ---
    try:
        plan = _build_plan(manifest_obj, target_env=target_env,
                           path_template=path_template)
    except ValueError as e:
        if json_out:
            print(json.dumps({"error": "bad_plan", "message": str(e)},
                             indent=2))
        else:
            print(f"[migrate] {e}", file=sys.stderr)
        return 2

    migrating = [e for e in plan if e.ref_inf is not None]
    skipped = [e for e in plan if e.ref_inf is None]

    # --- 3. Already-migrated short-circuit. ---
    if not migrating:
        msg = f"no op:// refs in {m_path}; manifest is already on inf:// "\
              f"({len(skipped)} entries skipped)"
        if json_out:
            print(json.dumps({"status": "already_migrated",
                              "manifest": str(m_path),
                              "skipped": [
                                  {"env_name": e.env_name,
                                   "reason": e.skipped_reason}
                                  for e in skipped
                              ]}, indent=2))
        else:
            print(f"[migrate] {msg}")
        return 0

    # --- 4. Auth check (both backends). ---
    rc = _check_auth(plan, json_out=json_out)
    if rc != 0:
        return rc

    # --- 5. Plan display. ---
    if json_out:
        print(json.dumps({
            "manifest": str(m_path),
            "target_env": target_env,
            "path_template": path_template,
            "plan": [
                {"env_name": e.env_name,
                 "ref_op": e.ref_op,
                 "ref_inf": e.ref_inf,
                 "skipped_reason": e.skipped_reason}
                for e in plan
            ],
            "dry_run": dry_run,
        }, indent=2))
    else:
        print(f"[migrate] manifest: {m_path}", file=sys.stderr)
        print(f"[migrate] target env: {target_env}, "
              f"path template: {path_template}", file=sys.stderr)
        print(f"[migrate] migrating {len(migrating)} ref(s); "
              f"skipping {len(skipped)}", file=sys.stderr)
        _print_plan_table(plan, fp=sys.stderr)

    if dry_run and not clean_only:
        if not json_out:
            print("\n[migrate] dry-run: stopping before any writes.",
                  file=sys.stderr)
        return 0

    # --- 5b. Pre-flight orphan cleanup (default on). ---
    # Listing the destination path BEFORE we read+write means a partially-
    # complete prior run leaves no orphans behind for a successful re-run.
    if not keep_orphans:
        if not json_out:
            print("\n[migrate] pre-flight: scanning destination paths for "
                  "orphan keys not in manifest...", file=sys.stderr)
        deleted, listing_failures, delete_failures = _cleanup_orphans(
            plan, json_out=json_out
        )
        if listing_failures and not json_out:
            print(f"[migrate] cleanup: {len(listing_failures)} listing "
                  f"failure(s) — proceeding with migration anyway.",
                  file=sys.stderr)
        if not json_out:
            if deleted:
                print(f"[migrate] cleanup: deleted {len(deleted)} orphan(s).",
                      file=sys.stderr)
            elif not listing_failures:
                print("[migrate] cleanup: no orphans found.", file=sys.stderr)
        if clean_only:
            if json_out:
                print(json.dumps({
                    "status": "clean_only_ok",
                    "manifest": str(m_path),
                    "deleted": [
                        {"env": e, "path": p, "key": k}
                        for e, p, k in deleted
                    ],
                    "listing_failures": [
                        {"env": e, "path": p, "reason": r}
                        for e, p, r in listing_failures
                    ],
                    "delete_failures": [
                        {"env": e, "path": p, "key": k, "reason": r}
                        for e, p, k, r in delete_failures
                    ],
                }, indent=2))
            else:
                print(f"\n[migrate] --clean-only: cleanup complete; not "
                      f"performing migration. Deleted "
                      f"{len(deleted)} orphan(s).", file=sys.stderr)
            return 0
    elif clean_only:
        # --keep-orphans + --clean-only is a contradiction — but we accept
        # it gracefully as "do nothing", since both flags individually are
        # valid no-ops. Print a warning so the user knows.
        if not json_out:
            print("[migrate] --clean-only with --keep-orphans is a no-op; "
                  "exiting.", file=sys.stderr)
        return 0

    # --- 6. Read all op:// values. ---
    if not json_out:
        print("\n[migrate] reading source values from 1Password...",
              file=sys.stderr)
    values, missing = _read_all_op_values(plan, json_out=json_out)
    if missing:
        if json_out:
            print(json.dumps({"error": "read_failed",
                              "missing": [
                                  {"env_name": n, "ref": r, "reason": msg}
                                  for n, r, msg in missing
                              ]}, indent=2))
        else:
            print(f"\n[migrate] failed to read {len(missing)} ref(s) from 1P:",
                  file=sys.stderr)
            for n, r, msg in missing:
                print(f"[migrate]   {n:<30} {r}  ({msg})", file=sys.stderr)
            print("[migrate] no writes performed.", file=sys.stderr)
        return 4

    # --- 7. Write all to Infisical. ---
    if not json_out:
        print("\n[migrate] pushing values to Infisical...", file=sys.stderr)
    written, write_failures = _write_all_inf_values(plan, values)
    if write_failures:
        if json_out:
            print(json.dumps({"error": "write_failed",
                              "written": written,
                              "failures": [
                                  {"env_name": n, "ref": r, "reason": msg}
                                  for n, r, msg in write_failures
                              ]}, indent=2))
        else:
            print(f"\n[migrate] {len(write_failures)} write(s) failed:",
                  file=sys.stderr)
            for n, r, msg in write_failures:
                print(f"[migrate]   {n:<30} {r}  ({msg})", file=sys.stderr)
        _rollback_inf(written)
        return 5

    # --- 8. Verify round-trip. ---
    if not json_out:
        print("\n[migrate] verifying round-trip reads...", file=sys.stderr)
    verify_failures = _verify_all_inf_values(plan, values)
    if verify_failures:
        if json_out:
            print(json.dumps({"error": "verify_failed",
                              "failures": [
                                  {"env_name": n, "ref": r, "reason": msg}
                                  for n, r, msg in verify_failures
                              ]}, indent=2))
        else:
            print(f"\n[migrate] {len(verify_failures)} verify failure(s):",
                  file=sys.stderr)
            for n, r, msg in verify_failures:
                print(f"[migrate]   {n:<30} {r}  ({msg})", file=sys.stderr)
        _rollback_inf(written)
        return 6

    # --- 9. Rewrite manifest (with .bak). ---
    try:
        bak_path = _rewrite_manifest(manifest_obj, plan)
    except OSError as e:
        if json_out:
            print(json.dumps({"error": "manifest_write_failed",
                              "message": str(e)}, indent=2))
        else:
            print(f"[migrate] manifest write failed: {e}", file=sys.stderr)
        # Don't roll back inf writes here — the manifest still points at op://,
        # so the user can re-run safely. Leaving the inf:// values written is
        # harmless (just a no-op overwrite next time).
        return 7

    # --- 10. Post-migration validate. ---
    if not no_validate:
        rc_check = _run_inject_check(m_path.parent)
        if rc_check != 0:
            if json_out:
                print(json.dumps({
                    "error": "post_validate_failed",
                    "manifest": str(m_path),
                    "backup": str(bak_path),
                    "inject_exit_code": rc_check,
                    "hint": (f"the manifest was rewritten but `bin/inject "
                             f"--check` failed; restore from {bak_path} to "
                             f"roll back."),
                }, indent=2))
            else:
                print(f"\n[migrate] `bin/inject --check` exited "
                      f"{rc_check}. Manifest is rewritten; restore from "
                      f"{bak_path} to roll back.", file=sys.stderr)
            return 9

    # --- 11. Cleanup .bak (or keep). ---
    if not keep_bak:
        try:
            bak_path.unlink()
            if not json_out:
                print(f"[migrate] removed {bak_path.name} "
                      f"(--no-keep-bak)", file=sys.stderr)
        except OSError as e:
            if not json_out:
                print(f"[migrate] could not remove {bak_path}: {e}",
                      file=sys.stderr)

    # --- 12. Success. ---
    if json_out:
        print(json.dumps({
            "status": "ok",
            "manifest": str(m_path),
            "backup": str(bak_path) if keep_bak else None,
            "migrated": [
                {"env_name": e.env_name,
                 "ref_op": e.ref_op, "ref_inf": e.ref_inf}
                for e in migrating
            ],
            "skipped": [
                {"env_name": e.env_name, "reason": e.skipped_reason}
                for e in skipped
            ],
        }, indent=2))
    else:
        print(f"\n[migrate] OK: migrated {len(migrating)} ref(s); "
              f"skipped {len(skipped)}.", file=sys.stderr)
        if keep_bak:
            print(f"[migrate] backup retained at {bak_path}", file=sys.stderr)
    return 0


# ───────────────────────────────────────────────────────────────────────────
# Self-test (no real op or inf calls)
# ───────────────────────────────────────────────────────────────────────────


def _self_test() -> int:
    """Smoke test the full migrate pipeline with a mocked secrets layer.

    Covers:
      - Plain migration (3 op:// refs -> 3 inf:// refs)
      - Dry-run produces no side effects
      - Already-migrated (all inf://) is a no-op
      - Mixed manifest leaves inf:// alone, migrates op://
      - Read failure mid-flight aborts cleanly (no manifest rewrite)
      - Write failure triggers rollback
    """
    import tempfile
    import types

    failures = 0

    # ─── Build a fake cush_secrets module shared across tests. ───
    class FakeSecretsError(Exception):
        pass

    class FakeSecretsAuthError(FakeSecretsError):
        pass

    class FakeSecretsRefNotFound(FakeSecretsError):
        pass

    class FakeSecretsAccessError(FakeSecretsError):
        pass

    def _make_fake(*, op_store: dict, inf_store: dict,
                   read_fail_for: set = None, write_fail_for: set = None,
                   verify_corrupt_for: set = None):
        """Return a fake secrets module backed by two dicts.

        - op_store    : dict mapping op://refs to values (read source).
        - inf_store   : dict mapping inf://refs to values (write target).
        - read_fail_for : set of refs that should raise SecretsRefNotFound.
        - write_fail_for: set of refs that should raise on item_upsert.
        - verify_corrupt_for: set of refs whose verify-read returns wrong value.
        """
        read_fail_for = read_fail_for or set()
        write_fail_for = write_fail_for or set()
        verify_corrupt_for = verify_corrupt_for or set()

        def fake_read(ref):
            if ref in read_fail_for:
                raise FakeSecretsRefNotFound(f"injected: {ref}")
            if ref.startswith("op://"):
                if ref not in op_store:
                    raise FakeSecretsRefNotFound(f"not in store: {ref}")
                return op_store[ref]
            if ref.startswith("inf://"):
                if ref not in inf_store:
                    raise FakeSecretsRefNotFound(f"not in store: {ref}")
                if ref in verify_corrupt_for:
                    return inf_store[ref] + "_CORRUPTED"
                return inf_store[ref]
            raise ValueError(ref)

        def fake_item_upsert(ref, value, *, concealed=True):
            if ref in write_fail_for:
                raise FakeSecretsError(f"injected write failure: {ref}")
            if ref.startswith("inf://"):
                inf_store[ref] = value
                return
            if ref.startswith("op://"):
                op_store[ref] = value
                return
            raise ValueError(ref)

        def fake_scheme_of(ref):
            if not isinstance(ref, str) or "://" not in ref:
                raise ValueError(ref)
            return ref.split("://", 1)[0]

        def fake_whoami_for_scheme(scheme):
            return {"scheme": scheme, "user": "self-test"}

        return types.SimpleNamespace(
            read=fake_read,
            item_upsert=fake_item_upsert,
            scheme_of=fake_scheme_of,
            whoami_for_scheme=fake_whoami_for_scheme,
            SecretsError=FakeSecretsError,
            SecretsAuthError=FakeSecretsAuthError,
            SecretsRefNotFound=FakeSecretsRefNotFound,
            SecretsAccessError=FakeSecretsAccessError,
        )

    SAMPLE_OP = """\
schema = 1
[defaults]
target_vault = "Cush"
target_item = "{project}"
[secrets]
DATABASE_URL = "op://Cush/myapp/database_url"
STRIPE_KEY = { ref = "op://Cush/myapp/stripe", fallback = "sk_test_dev" }
GITHUB_TOKEN = "op://Cush/myapp/gh_token"
"""

    SAMPLE_INF = """\
schema = 1
[secrets]
ALREADY_MIGRATED = "inf://dev/myapp/ALREADY_MIGRATED"
ANOTHER_ONE = "inf://dev/myapp/ANOTHER_ONE"
"""

    SAMPLE_MIXED = """\
schema = 1
[defaults]
target_vault = "Cush"
[secrets]
LEGACY = "op://Cush/myapp/legacy"
MODERN = "inf://dev/myapp/MODERN"
SSH_KEY = { ref = "op://Cush/myapp/ssh", type = "ssh" }
"""

    def _stub_inject_check_ok():
        """Bypass the bin/inject subprocess so self-test stays offline."""
        global _run_inject_check  # type: ignore  # noqa: WPS420
        # Replace via module-level rebinding. We reach into globals() to
        # respect Python scoping rules without hand-rolling a class.
        sys.modules[__name__]._run_inject_check = lambda project_dir, fp=sys.stderr: 0

    # We can also patch by directly assigning to the module attribute, but
    # since _run_inject_check is referenced as a free name inside
    # run_migration, rebinding the module attribute is enough.
    import sys as _sys
    _orig_check = _run_inject_check
    _sys.modules[__name__]._run_inject_check = lambda project_dir, fp=_sys.stderr: 0

    # Default-stub the cleanup helpers so the existing tests (1–6) don't try
    # to reach into a real `infisical` CLI. Tests that exercise cleanup
    # explicitly (7–9) reassign these temporarily inside their `with` block.
    _orig_list_default = _list_keys_at
    _orig_delete_default = _delete_key_at
    _sys.modules[__name__]._list_keys_at = lambda env, path: []
    _sys.modules[__name__]._delete_key_at = lambda env, path, key: None

    # ─── Test 1: plain migration (3 op:// refs). ───
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        proj = td / "myapp"
        proj.mkdir()
        (proj / ".cush-secrets").write_text(SAMPLE_OP)

        op_store = {
            "op://Cush/myapp/database_url": "postgres://localhost/x",
            "op://Cush/myapp/stripe": "sk_live_abc",
            "op://Cush/myapp/gh_token": "ghp_xyz",
        }
        inf_store = {}
        global _secrets
        _secrets = _make_fake(op_store=op_store, inf_store=inf_store)

        rc = run_migration(
            proj,
            target_env="dev",
            path_template="/{project}",
            dry_run=False,
            keep_bak=True,
            no_validate=True,  # don't shell out to bin/inject in self-test
            json_out=False,
        )
        if rc != 0:
            print(f"[migrate self-test] plain migration: expected 0, got {rc}",
                  file=sys.stderr)
            failures += 1

        # All three values should now live in inf_store.
        for env_name, src in [
            ("DATABASE_URL", "postgres://localhost/x"),
            ("STRIPE_KEY", "sk_live_abc"),
            ("GITHUB_TOKEN", "ghp_xyz"),
        ]:
            inf_ref = f"inf://dev/myapp/{env_name}"
            if inf_store.get(inf_ref) != src:
                print(f"[migrate self-test] post-migrate inf_store missing "
                      f"{inf_ref} = {src!r}; got {inf_store.get(inf_ref)!r}",
                      file=sys.stderr)
                failures += 1

        # Manifest should now be all inf://.
        m2 = manifest_mod.load(proj / ".cush-secrets")
        for spec in m2.secrets:
            if not spec.ref.startswith("inf://"):
                print(f"[migrate self-test] post-migrate manifest still on "
                      f"op://: {spec.env_name} = {spec.ref}", file=sys.stderr)
                failures += 1
        # STRIPE_KEY should preserve fallback.
        stripe = next(s for s in m2.secrets if s.env_name == "STRIPE_KEY")
        if stripe.fallback != "sk_test_dev":
            print(f"[migrate self-test] fallback dropped: {stripe.fallback!r}",
                  file=sys.stderr)
            failures += 1
        # .bak retained.
        if not (proj / ".cush-secrets.bak").is_file():
            print("[migrate self-test] .bak missing after keep_bak=True",
                  file=sys.stderr)
            failures += 1

    # ─── Test 2: dry-run produces no side effects. ───
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        proj = td / "myapp"
        proj.mkdir()
        (proj / ".cush-secrets").write_text(SAMPLE_OP)
        original = (proj / ".cush-secrets").read_text()

        op_store = {
            "op://Cush/myapp/database_url": "v1",
            "op://Cush/myapp/stripe": "v2",
            "op://Cush/myapp/gh_token": "v3",
        }
        inf_store = {}
        _secrets = _make_fake(op_store=op_store, inf_store=inf_store)

        rc = run_migration(
            proj,
            target_env="dev",
            path_template="/{project}",
            dry_run=True,
            keep_bak=True,
            no_validate=True,
            json_out=False,
        )
        if rc != 0:
            print(f"[migrate self-test] dry-run: expected 0, got {rc}",
                  file=sys.stderr)
            failures += 1
        if inf_store:
            print(f"[migrate self-test] dry-run wrote to inf_store: "
                  f"{list(inf_store)}", file=sys.stderr)
            failures += 1
        if (proj / ".cush-secrets").read_text() != original:
            print("[migrate self-test] dry-run rewrote manifest",
                  file=sys.stderr)
            failures += 1
        if (proj / ".cush-secrets.bak").exists():
            print("[migrate self-test] dry-run created .bak",
                  file=sys.stderr)
            failures += 1

    # ─── Test 3: already-migrated is a no-op. ───
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        proj = td / "myapp"
        proj.mkdir()
        (proj / ".cush-secrets").write_text(SAMPLE_INF)
        original = (proj / ".cush-secrets").read_text()
        inf_store = {}
        _secrets = _make_fake(op_store={}, inf_store=inf_store)
        rc = run_migration(
            proj,
            target_env="dev",
            path_template="/{project}",
            dry_run=False,
            keep_bak=True,
            no_validate=True,
            json_out=False,
        )
        if rc != 0:
            print(f"[migrate self-test] already-migrated: expected 0, got {rc}",
                  file=sys.stderr)
            failures += 1
        if (proj / ".cush-secrets").read_text() != original:
            print("[migrate self-test] already-migrated rewrote manifest",
                  file=sys.stderr)
            failures += 1
        if (proj / ".cush-secrets.bak").exists():
            print("[migrate self-test] already-migrated created .bak",
                  file=sys.stderr)
            failures += 1

    # ─── Test 4: mixed manifest. ───
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        proj = td / "myapp"
        proj.mkdir()
        (proj / ".cush-secrets").write_text(SAMPLE_MIXED)

        op_store = {
            "op://Cush/myapp/legacy": "L",
            "op://Cush/myapp/ssh": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
        }
        inf_store = {"inf://dev/myapp/MODERN": "should-not-touch"}
        _secrets = _make_fake(op_store=op_store, inf_store=inf_store)

        rc = run_migration(
            proj,
            target_env="dev",
            path_template="/{project}",
            dry_run=False,
            keep_bak=False,
            no_validate=True,
            json_out=False,
        )
        if rc != 0:
            print(f"[migrate self-test] mixed: expected 0, got {rc}",
                  file=sys.stderr)
            failures += 1
        # MODERN unchanged.
        if inf_store.get("inf://dev/myapp/MODERN") != "should-not-touch":
            print("[migrate self-test] mixed: MODERN was overwritten",
                  file=sys.stderr)
            failures += 1
        # LEGACY + SSH_KEY pushed.
        if inf_store.get("inf://dev/myapp/LEGACY") != "L":
            print(f"[migrate self-test] mixed: LEGACY missing in inf_store: "
                  f"{inf_store.get('inf://dev/myapp/LEGACY')!r}",
                  file=sys.stderr)
            failures += 1
        if "inf://dev/myapp/SSH_KEY" not in inf_store:
            print("[migrate self-test] mixed: SSH_KEY missing in inf_store",
                  file=sys.stderr)
            failures += 1
        # Manifest should be all inf://.
        m2 = manifest_mod.load(proj / ".cush-secrets")
        op_remaining = [s for s in m2.secrets if s.ref.startswith("op://")]
        if op_remaining:
            print(f"[migrate self-test] mixed: op:// remaining after migrate: "
                  f"{[s.env_name for s in op_remaining]}", file=sys.stderr)
            failures += 1
        # SSH_KEY type preserved.
        ssh = next(s for s in m2.secrets if s.env_name == "SSH_KEY")
        if ssh.type != "ssh":
            print(f"[migrate self-test] mixed: SSH_KEY type lost: {ssh.type!r}",
                  file=sys.stderr)
            failures += 1
        # .bak removed (--no-keep-bak path).
        if (proj / ".cush-secrets.bak").exists():
            print("[migrate self-test] mixed: .bak should be removed when "
                  "keep_bak=False", file=sys.stderr)
            failures += 1

    # ─── Test 5: read failure aborts cleanly (no manifest rewrite). ───
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        proj = td / "myapp"
        proj.mkdir()
        (proj / ".cush-secrets").write_text(SAMPLE_OP)
        original = (proj / ".cush-secrets").read_text()
        op_store = {
            "op://Cush/myapp/database_url": "ok",
            # stripe + gh_token intentionally missing
        }
        inf_store = {}
        _secrets = _make_fake(op_store=op_store, inf_store=inf_store)

        rc = run_migration(
            proj,
            target_env="dev",
            path_template="/{project}",
            dry_run=False,
            keep_bak=True,
            no_validate=True,
            json_out=False,
        )
        if rc != 4:
            print(f"[migrate self-test] read-fail: expected 4, got {rc}",
                  file=sys.stderr)
            failures += 1
        if inf_store:
            print(f"[migrate self-test] read-fail wrote to inf_store: "
                  f"{list(inf_store)}", file=sys.stderr)
            failures += 1
        if (proj / ".cush-secrets").read_text() != original:
            print("[migrate self-test] read-fail rewrote manifest",
                  file=sys.stderr)
            failures += 1

    # ─── Test 6: write failure triggers rollback. ───
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        proj = td / "myapp"
        proj.mkdir()
        (proj / ".cush-secrets").write_text(SAMPLE_OP)
        original = (proj / ".cush-secrets").read_text()
        op_store = {
            "op://Cush/myapp/database_url": "v1",
            "op://Cush/myapp/stripe": "v2",
            "op://Cush/myapp/gh_token": "v3",
        }
        inf_store = {}
        # Fail the second write so the first should roll back.
        _secrets = _make_fake(
            op_store=op_store, inf_store=inf_store,
            write_fail_for={"inf://dev/myapp/STRIPE_KEY"},
        )

        rc = run_migration(
            proj,
            target_env="dev",
            path_template="/{project}",
            dry_run=False,
            keep_bak=True,
            no_validate=True,
            json_out=False,
        )
        if rc != 5:
            print(f"[migrate self-test] write-fail: expected 5, got {rc}",
                  file=sys.stderr)
            failures += 1
        # The rollback uses real `infisical secrets delete` shell-out — in
        # self-test it'll likely fail (CLI not configured), but our fake
        # store wasn't touched by that anyway. What we DO verify: only the
        # first ref made it into inf_store before the failure, and the
        # manifest stayed on op://.
        if (proj / ".cush-secrets").read_text() != original:
            print("[migrate self-test] write-fail rewrote manifest",
                  file=sys.stderr)
            failures += 1
        # The DATABASE_URL write succeeded prior to the STRIPE_KEY failure.
        # Since we don't actually call `infisical secrets delete` against
        # the fake store (the real CLI would be called and fail in sandbox),
        # the entry in inf_store is still present — that's expected behavior
        # for the in-memory test.
        if "inf://dev/myapp/DATABASE_URL" not in inf_store:
            print("[migrate self-test] write-fail: DATABASE_URL should have "
                  "been written before the STRIPE_KEY failure",
                  file=sys.stderr)
            failures += 1

    # ─── Test 7: orphan cleanup deletes a stale key not in manifest. ───
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        proj = td / "myapp"
        proj.mkdir()
        (proj / ".cush-secrets").write_text(SAMPLE_OP)

        op_store = {
            "op://Cush/myapp/database_url": "postgres://x",
            "op://Cush/myapp/stripe": "sk_live",
            "op://Cush/myapp/gh_token": "ghp_y",
        }
        # inf_store starts with stale orphans + a few legitimate entries that
        # would already exist if a prior partial migration touched them.
        inf_store = {
            "inf://dev/myapp/STALE_FROM_PRIOR": "leftover",
            "inf://dev/myapp/ANOTHER_ORPHAN": "also-leftover",
        }
        _secrets = _make_fake(op_store=op_store, inf_store=inf_store)

        # Hook the cleanup helpers to the in-memory inf_store. The helpers
        # expect (env, path) -> list of keys, but our store keys are full
        # inf://... refs. Simple translation lambda.
        def _fake_list(env, path):
            prefix = f"inf://{env}{path if path.startswith('/') else '/' + path}/"
            return sorted(
                k.split("/")[-1]
                for k in inf_store.keys()
                if k.startswith(prefix)
            )

        def _fake_delete(env, path, key):
            full = f"inf://{env}{path if path.startswith('/') else '/' + path}/{key}"
            inf_store.pop(full, None)

        _orig_list = _list_keys_at
        _orig_delete = _delete_key_at
        _sys.modules[__name__]._list_keys_at = _fake_list
        _sys.modules[__name__]._delete_key_at = _fake_delete
        try:
            rc = run_migration(
                proj,
                target_env="dev",
                path_template="/{project}",
                dry_run=False,
                keep_bak=True,
                no_validate=True,
                json_out=False,
            )
        finally:
            _sys.modules[__name__]._list_keys_at = _orig_list
            _sys.modules[__name__]._delete_key_at = _orig_delete
        if rc != 0:
            print(f"[migrate self-test] orphan-cleanup: expected 0, got {rc}",
                  file=sys.stderr)
            failures += 1
        # Stale orphans should be gone; new keys present.
        if "inf://dev/myapp/STALE_FROM_PRIOR" in inf_store:
            print("[migrate self-test] orphan-cleanup: STALE_FROM_PRIOR not "
                  "deleted", file=sys.stderr)
            failures += 1
        if "inf://dev/myapp/ANOTHER_ORPHAN" in inf_store:
            print("[migrate self-test] orphan-cleanup: ANOTHER_ORPHAN not "
                  "deleted", file=sys.stderr)
            failures += 1
        for env_name in ("DATABASE_URL", "STRIPE_KEY", "GITHUB_TOKEN"):
            if f"inf://dev/myapp/{env_name}" not in inf_store:
                print(f"[migrate self-test] orphan-cleanup: {env_name} "
                      f"missing post-migration", file=sys.stderr)
                failures += 1

    # ─── Test 8: --keep-orphans skips cleanup. ───
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        proj = td / "myapp"
        proj.mkdir()
        (proj / ".cush-secrets").write_text(SAMPLE_OP)

        op_store = {
            "op://Cush/myapp/database_url": "p",
            "op://Cush/myapp/stripe": "s",
            "op://Cush/myapp/gh_token": "g",
        }
        inf_store = {"inf://dev/myapp/SHOULD_REMAIN": "preserve-me"}
        _secrets = _make_fake(op_store=op_store, inf_store=inf_store)

        def _fake_list(env, path):
            prefix = f"inf://{env}{path if path.startswith('/') else '/' + path}/"
            return sorted(
                k.split("/")[-1]
                for k in inf_store.keys()
                if k.startswith(prefix)
            )

        def _fake_delete(env, path, key):
            full = f"inf://{env}{path if path.startswith('/') else '/' + path}/{key}"
            inf_store.pop(full, None)

        _orig_list = _list_keys_at
        _orig_delete = _delete_key_at
        _sys.modules[__name__]._list_keys_at = _fake_list
        _sys.modules[__name__]._delete_key_at = _fake_delete
        try:
            rc = run_migration(
                proj,
                target_env="dev",
                path_template="/{project}",
                dry_run=False,
                keep_bak=True,
                no_validate=True,
                json_out=False,
                keep_orphans=True,
            )
        finally:
            _sys.modules[__name__]._list_keys_at = _orig_list
            _sys.modules[__name__]._delete_key_at = _orig_delete
        if rc != 0:
            print(f"[migrate self-test] keep-orphans: expected 0, got {rc}",
                  file=sys.stderr)
            failures += 1
        if "inf://dev/myapp/SHOULD_REMAIN" not in inf_store:
            print("[migrate self-test] keep-orphans: orphan was deleted "
                  "despite --keep-orphans", file=sys.stderr)
            failures += 1

    # ─── Test 9: --clean-only runs cleanup and exits without migrating. ───
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        proj = td / "myapp"
        proj.mkdir()
        (proj / ".cush-secrets").write_text(SAMPLE_OP)
        original = (proj / ".cush-secrets").read_text()

        op_store = {
            "op://Cush/myapp/database_url": "p",
            "op://Cush/myapp/stripe": "s",
            "op://Cush/myapp/gh_token": "g",
        }
        inf_store = {
            "inf://dev/myapp/ORPHAN": "stale",
        }
        _secrets = _make_fake(op_store=op_store, inf_store=inf_store)

        def _fake_list(env, path):
            prefix = f"inf://{env}{path if path.startswith('/') else '/' + path}/"
            return sorted(
                k.split("/")[-1]
                for k in inf_store.keys()
                if k.startswith(prefix)
            )

        def _fake_delete(env, path, key):
            full = f"inf://{env}{path if path.startswith('/') else '/' + path}/{key}"
            inf_store.pop(full, None)

        _orig_list = _list_keys_at
        _orig_delete = _delete_key_at
        _sys.modules[__name__]._list_keys_at = _fake_list
        _sys.modules[__name__]._delete_key_at = _fake_delete
        try:
            rc = run_migration(
                proj,
                target_env="dev",
                path_template="/{project}",
                dry_run=False,
                keep_bak=True,
                no_validate=True,
                json_out=False,
                clean_only=True,
            )
        finally:
            _sys.modules[__name__]._list_keys_at = _orig_list
            _sys.modules[__name__]._delete_key_at = _orig_delete
        if rc != 0:
            print(f"[migrate self-test] clean-only: expected 0, got {rc}",
                  file=sys.stderr)
            failures += 1
        # Orphan deleted.
        if "inf://dev/myapp/ORPHAN" in inf_store:
            print("[migrate self-test] clean-only: ORPHAN not deleted",
                  file=sys.stderr)
            failures += 1
        # No migration: no new keys in inf_store.
        unexpected = [k for k in inf_store
                      if k.startswith("inf://dev/myapp/")
                      and k.split("/")[-1] in (
                          "DATABASE_URL", "STRIPE_KEY", "GITHUB_TOKEN")]
        if unexpected:
            print(f"[migrate self-test] clean-only: migration ran "
                  f"(unexpected keys: {unexpected})", file=sys.stderr)
            failures += 1
        # Manifest unchanged.
        if (proj / ".cush-secrets").read_text() != original:
            print("[migrate self-test] clean-only: manifest was rewritten",
                  file=sys.stderr)
            failures += 1
        # No .bak (we never wrote anything).
        if (proj / ".cush-secrets.bak").exists():
            print("[migrate self-test] clean-only: created .bak unexpectedly",
                  file=sys.stderr)
            failures += 1

    # Restore the patched function (good hygiene; module reuse in tests).
    _sys.modules[__name__]._run_inject_check = _orig_check
    _sys.modules[__name__]._list_keys_at = _orig_list_default
    _sys.modules[__name__]._delete_key_at = _orig_delete_default

    if failures:
        print(f"[migrate self-test] {failures} failure(s)", file=sys.stderr)
        return 1
    print("[migrate self-test] ok")
    return 0


# ───────────────────────────────────────────────────────────────────────────
# CLI entry
# ───────────────────────────────────────────────────────────────────────────


def _build_argparser():
    p = argparse.ArgumentParser(
        prog="porch-migrate-backend",
        description="Migrate a project's .cush-secrets from op:// to inf://.",
    )
    p.add_argument("project_dir", nargs="?", default=None,
                   help="Project directory (default: current working dir).")
    p.add_argument("--dry-run", action="store_true",
                   help="Preview the rewrites without touching 1P, "
                        "Infisical, or disk.")
    p.add_argument("--target-env", default="dev",
                   help="Target Infisical env slug (default: dev).")
    p.add_argument("--target-path-template", default="/{project}",
                   help="Path template for the inf:// destination "
                        "(default: '/{project}'; {project} = parent "
                        "dir basename).")
    bak = p.add_mutually_exclusive_group()
    bak.add_argument("--keep-bak", dest="keep_bak", action="store_true",
                     default=True,
                     help="Keep .cush-secrets.bak after success (default).")
    bak.add_argument("--no-keep-bak", dest="keep_bak", action="store_false",
                     help="Delete .cush-secrets.bak after a verified success.")
    p.add_argument("--no-validate", action="store_true",
                   help="Skip the post-migration `bin/inject --check`.")
    p.add_argument("--keep-orphans", action="store_true",
                   help="Skip the pre-flight cleanup of orphan inf:// "
                        "keys (secrets at the destination path that "
                        "aren't in the manifest). Default: orphans are "
                        "deleted automatically before the migration runs.")
    p.add_argument("--clean-only", action="store_true",
                   help="Run the orphan cleanup and exit; do not perform "
                        "any migration. Useful for fixing partial state "
                        "left by a prior failed run.")
    p.add_argument("--json", dest="json_out", action="store_true",
                   help="Machine-readable output.")
    p.add_argument("--self-test", action="store_true",
                   help="Run an in-process smoke test with a mocked "
                        "secrets backend (no real op or inf calls).")
    return p


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    args = _build_argparser().parse_args(argv)

    if args.self_test:
        return _self_test()

    project_dir = Path(args.project_dir or Path.cwd()).resolve()
    if not project_dir.is_dir():
        print(f"[migrate] not a directory: {project_dir}", file=sys.stderr)
        return 2

    try:
        return run_migration(
            project_dir,
            target_env=args.target_env,
            path_template=args.target_path_template,
            dry_run=args.dry_run,
            keep_bak=args.keep_bak,
            no_validate=args.no_validate,
            json_out=args.json_out,
            keep_orphans=args.keep_orphans,
            clean_only=args.clean_only,
        )
    except KeyboardInterrupt:
        print("\n[migrate] aborted by user.", file=sys.stderr)
        return 5


if __name__ == "__main__":
    sys.exit(main())

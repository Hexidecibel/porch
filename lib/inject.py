#!/usr/bin/env python3
"""Inject orchestrator — `bin/inject` delegates here.

Responsibilities:
  1. Parse the `.cush-secrets` manifest (lib/manifest.py).
  2. Determine which refs resolve in 1Password (single batched `op inject`).
  3. For missing refs, optionally auto-spawn `bin/secure-entry --save-to-op`
     tunnels (parallel, capped). Display a table + ASCII QR codes.
  4. Block on sentinel files until each tunnel reports a successful op write.
  5. Re-render via `op inject` to fetch the now-present values.
  6. Materialize as a chmod-600 `.env` file or eval-able exports on stdout.

This module is invokable two ways:
  - As an importable function (cmd_check / cmd_resolve) called by tests.
  - As `python3 lib/inject.py ...` from `bin/inject`.

A small `--self-test` mode exercises the manifest walk-up and the rendering
table without touching `op` or spawning subprocesses (op_inject is monkey-
patched).

Exit codes (mirroring bin/inject):
  0  ok
  2  arg error
  3  op auth
  4  op error
  5  user aborted (Ctrl-C)
  6  --no-prompt and missing
  7  .env write failed
  8  partial / timeout
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

# Make sibling modules importable.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import manifest as manifest_mod
from manifest import Manifest, SecretSpec, ManifestError

# Lazy-imported on use to keep --self-test free of cush_secrets.py overhead.
_secrets = None


def _load_secrets():
    """Return the cush_secrets dispatch module.

    Lazy-imported so --self-test can monkeypatch this slot with a fake module
    without paying the import cost of op.py / infisical.py.
    """
    global _secrets
    if _secrets is None:
        import cush_secrets as cs  # noqa: WPS433
        _secrets = cs
    return _secrets


REPO_ROOT = Path(__file__).resolve().parent.parent  # cush-tools/
SECURE_ENTRY_BIN = REPO_ROOT / "bin" / "secure-entry"
QR_BIN = REPO_ROOT / "bin" / "qr"
STATUS_BIN = REPO_ROOT / "bin" / "status"


# ───────────────────────────────────────────────────────────────────────────
# Existence check
# ───────────────────────────────────────────────────────────────────────────


# A sentinel marker we wrap each rendered value with so we can split a single
# `op inject` output back into per-key results. Using a marker rather than
# parsing line-by-line lets values legitimately contain `=` and newlines.
_BEGIN = "<<<CUSH_INJECT_BEGIN:{key}>>>"
_END = "<<<CUSH_INJECT_END:{key}>>>"


def _build_template(specs):
    """Build a single op-inject template that wraps each ref with markers.

    Format (per key):
        <<<CUSH_INJECT_BEGIN:KEY>>>{{ op://... }}<<<CUSH_INJECT_END:KEY>>>
    Lines are newline-separated so we can scan for unresolved {{ tokens.
    """
    lines = []
    for spec in specs:
        lines.append(
            _BEGIN.format(key=spec.env_name)
            + f"{{{{ {spec.ref} }}}}"
            + _END.format(key=spec.env_name)
        )
    return "\n".join(lines) + "\n"


_RESOLVED_RE = re.compile(
    r"<<<CUSH_INJECT_BEGIN:(?P<key>[^>]+)>>>(?P<val>.*?)<<<CUSH_INJECT_END:(?P=key)>>>",
    re.DOTALL,
)


def _parse_render(rendered: str):
    """Extract {env_name: value} from a rendered template.

    Any envs whose marker block is missing — or whose value still contains
    a literal `{{` (op-inject leaves unresolved templates verbatim by default
    but exits non-zero; we fall back to per-ref op_read in that case) — are
    treated as unresolved.
    """
    found = {}
    for m in _RESOLVED_RE.finditer(rendered):
        val = m.group("val")
        if "{{" in val:
            continue  # unresolved placeholder
        found[m.group("key")] = val
    return found


def _existence_check(manifest_obj):
    """Return (resolved_dict, missing_specs).

    Approach: build a single template, run a batched render once. Successful
    output yields rendered values for all refs. If render fails for any
    reason (including a single missing ref — `op inject` exits non-zero on
    the first unresolved ref), fall back to per-ref reads so we can
    categorize each one as resolved / missing without losing partial
    progress.
    """
    secrets_mod = _load_secrets()
    template = _build_template(manifest_obj.secrets)

    try:
        rendered = secrets_mod.inject_template(template)
    except secrets_mod.SecretsAuthError:
        raise
    except secrets_mod.SecretsAccessError:
        raise
    except secrets_mod.SecretsError:
        # Per-ref fallback. The batched call exits non-zero on the first
        # unresolved ref; rather than parse stderr to figure out which
        # ones, we just bisect via per-ref reads. This is O(N) backend
        # calls but only in the failure path; the happy path remains O(1)
        # (or O(N) per-ref for inf-only manifests, which is the same).
        rendered = ""

    resolved = _parse_render(rendered) if rendered else {}

    missing = []
    if len(resolved) == len(manifest_obj.secrets):
        return resolved, missing

    # Per-ref classification for everything not in `resolved`.
    for spec in manifest_obj.secrets:
        if spec.env_name in resolved:
            continue
        try:
            val = secrets_mod.read(spec.ref)
            resolved[spec.env_name] = val
        except secrets_mod.SecretsRefNotFound:
            missing.append(spec)
        except secrets_mod.SecretsAuthError:
            raise
        except secrets_mod.SecretsAccessError:
            raise
        except secrets_mod.SecretsError:
            # Treat ambiguous failure as "missing" so the user can re-fill.
            # Surface the issue via the missing list rather than crashing.
            missing.append(spec)

    return resolved, missing


# ───────────────────────────────────────────────────────────────────────────
# Auto-spawn flow
# ───────────────────────────────────────────────────────────────────────────


@dataclass
class SpawnedTunnel:
    env_name: str
    ref: str
    label: str
    url: str
    sentinel: Path
    spec: SecretSpec


def _short_uuid() -> str:
    return uuid.uuid4().hex[:8]


def _slugify_for_label(s: str) -> str:
    """Normalize an env_name into a tunnel-label slug: [a-z0-9-]."""
    s = s.lower()
    s = re.sub(r"[^a-z0-9-]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s or "secret"


def _spawn_one(spec, run_dir, entry_type):
    """Spawn `bin/secure-entry <label> --save-to-op <ref> --signal-file ... --bg`.

    Returns a SpawnedTunnel record. Raises CalledProcessError on subprocess
    failure (the caller surfaces a friendly message).
    """
    label = f"{_slugify_for_label(spec.env_name)}-{_short_uuid()}"
    sentinel = run_dir / f"{spec.env_name}.done"
    # Defensive: ensure no stale sentinel from a prior run with the same name.
    if sentinel.exists():
        sentinel.unlink()

    # `--save-to-secrets` is the generic flag covering both op:// and inf://;
    # `secure-entry` accepts either spelling for back-compat but prefers the
    # generic name.
    cmd = [
        str(SECURE_ENTRY_BIN),
        label,
        "--save-to-secrets", spec.ref,
        "--signal-file", str(sentinel),
        "--bg",
        "--type", entry_type or spec.type,
    ]
    # Bubble stderr so the caller can pass it through if the spawn errors.
    # 30s is generous: secure-entry --bg returns as soon as the daemon
    # double-forks; if it hasn't returned by 30s something's wedged.
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(
            f"secure-entry spawn timed out after 30s for {spec.env_name}"
        ) from e
    if proc.returncode != 0:
        # Surface the failure to caller; stderr from secure-entry has the
        # actionable detail (e.g. op auth failure, port in use).
        raise RuntimeError(
            f"failed to spawn secure-entry for {spec.env_name}: "
            f"{(proc.stderr or proc.stdout).strip()}"
        )

    # `bin/secure-entry --bg` prints "Secure entry: <url>" on success. The URL
    # now ends in a random path token (/<token>/) that only the launcher
    # knows, so it has to be read from that line; the bare host 404s. Fall
    # back to the host only if the line is missing (older secure-entry).
    import porch_config
    tunnel_base = porch_config.get().tunnel_base
    url = f"https://entry-{label}.{tunnel_base}"
    m = re.search(
        r"^Secure entry:\s*(https://entry-" + re.escape(label)
        + r"\." + re.escape(tunnel_base) + r"/[A-Za-z0-9_-]+/)\s*$",
        proc.stdout or "", re.MULTILINE)
    if m:
        url = m.group(1)
    return SpawnedTunnel(
        env_name=spec.env_name,
        ref=spec.ref,
        label=label,
        url=url,
        sentinel=sentinel,
        spec=spec,
    )


def _spawn_many(specs, run_dir, *, parallel: bool, max_parallel: int, entry_type: str):
    """Spawn tunnels in parallel (capped) or serially.

    Returns the list of SpawnedTunnel records, in the same order as `specs`.
    """
    results = [None] * len(specs)
    if not parallel or max_parallel <= 1:
        for i, spec in enumerate(specs):
            results[i] = _spawn_one(spec, run_dir, entry_type)
        return results

    cap = max(1, min(max_parallel, len(specs)))
    with ThreadPoolExecutor(max_workers=cap) as ex:
        futures = {ex.submit(_spawn_one, spec, run_dir, entry_type): i
                   for i, spec in enumerate(specs)}
        for fut in as_completed(futures):
            idx = futures[fut]
            results[idx] = fut.result()  # propagate RuntimeError on failure
    return results


# ───────────────────────────────────────────────────────────────────────────
# Display
# ───────────────────────────────────────────────────────────────────────────


def _print_table(spawned, *, qr: bool, fp=sys.stderr):
    """Print a box-drawing table of (ENV, REF, URL). After the table, print
    an ASCII QR for each URL (delegated to bin/qr --terminal) unless qr is
    False.
    """
    if not spawned:
        return

    headers = ("ENV", "OP REF", "URL")
    rows = [(t.env_name, t.ref, t.url) for t in spawned]

    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if len(cell) > widths[i]:
                widths[i] = len(cell)
    # Cap URL/ref widths so we don't blow up the terminal on long values.
    widths = [min(w, 60) for w in widths]

    def hr(left, mid, right):
        return left + mid.join("─" * (w + 2) for w in widths) + right

    def fmt(cells):
        return "│ " + " │ ".join(
            (c if len(c) <= w else c[: w - 1] + "…").ljust(w)
            for c, w in zip(cells, widths)
        ) + " │"

    print("Missing secrets — fill these in:", file=fp)
    print(hr("┌", "┬", "┐"), file=fp)
    print(fmt(headers), file=fp)
    print(hr("├", "┼", "┤"), file=fp)
    for row in rows:
        print(fmt(row), file=fp)
    print(hr("└", "┴", "┘"), file=fp)
    fp.flush()

    if qr and QR_BIN.exists():
        for t in spawned:
            print(f"\n{t.env_name}  ({t.url}):", file=fp)
            try:
                # bin/qr --terminal prints to stdout; redirect to fp.
                proc = subprocess.run(
                    [str(QR_BIN), "--terminal", t.url],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if proc.returncode == 0:
                    fp.write(proc.stdout)
                else:
                    print(
                        f"(qr failed: {proc.stderr.strip() or 'unknown'})",
                        file=fp,
                    )
            except Exception as e:
                print(f"(qr error: {e})", file=fp)
            fp.flush()


# ───────────────────────────────────────────────────────────────────────────
# Wait loop
# ───────────────────────────────────────────────────────────────────────────


def _wait_for_sentinels(spawned, *, timeout_sec: int, fp=sys.stderr):
    """Poll sentinel files at 1Hz until each appears or timeout elapses.

    Returns (filled_set, still_missing_set). On Ctrl-C, raises
    KeyboardInterrupt — the caller is expected to clean up tunnels.
    """
    secrets_mod = _load_secrets()
    pending = {t.env_name: t for t in spawned}
    filled = set()
    total = len(spawned)
    deadline = time.monotonic() + timeout_sec

    while pending and time.monotonic() < deadline:
        for env_name, t in list(pending.items()):
            if t.sentinel.exists():
                # Belt-and-braces re-validation. If the read fails after
                # the sentinel touched, log a warning but accept the signal.
                try:
                    secrets_mod.read(t.ref)
                except Exception as e:
                    print(
                        f"[inject] warning: sentinel for {env_name} flipped but "
                        f"read failed: {e}",
                        file=fp,
                    )
                filled.add(env_name)
                pending.pop(env_name)
                done_n = len(filled)
                print(f"[{done_n}/{total}] {env_name}  RECEIVED", file=fp)
                fp.flush()
        if not pending:
            break
        time.sleep(1.0)

    still_missing = set(pending.keys())
    return filled, still_missing


# ───────────────────────────────────────────────────────────────────────────
# Cleanup
# ───────────────────────────────────────────────────────────────────────────


def _close_tunnel(label: str):
    """Best-effort `bin/status close <label>`. Errors are swallowed."""
    try:
        subprocess.run(
            [str(STATUS_BIN), "close", label],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:
        pass


def _cleanup(spawned, run_dir):
    for t in spawned:
        # The tunnel's daemon registers under "entry-<label>".
        _close_tunnel(f"entry-{t.label}")
        try:
            t.sentinel.unlink()
        except FileNotFoundError:
            pass
    try:
        if run_dir.exists():
            # Only rm if it's our run dir (uuid prefix means safe).
            shutil.rmtree(run_dir, ignore_errors=True)
    except Exception:
        pass


# ───────────────────────────────────────────────────────────────────────────
# Render + materialize
# ───────────────────────────────────────────────────────────────────────────


def _render_via_secrets(specs):
    """Resolve all specs via the dispatch layer. Raises on any failure.

    For op-only templates this dispatches to a single `op inject` invocation
    (one backend call total). For mixed manifests or those containing inf://
    refs, the dispatch layer falls back to per-ref reads internally — same
    semantics, slightly chattier on the wire.
    """
    secrets_mod = _load_secrets()
    template = _build_template(specs)
    rendered = secrets_mod.inject_template(template)
    parsed = _parse_render(rendered)
    missing = [s.env_name for s in specs if s.env_name not in parsed]
    if missing:
        raise secrets_mod.SecretsRefNotFound(
            f"render succeeded but template parse missed: {missing}"
        )
    return parsed


def _quote_for_env(value: str) -> str:
    """Quote a value for a `.env` file.

    .env semantics differ across loaders, but the common-denominator rule is:
    if the value contains whitespace / `=` / `"` / `'` / control chars,
    wrap in single quotes (no escapes inside) and escape any single quote
    by closing/reopening: foo'bar -> 'foo'\''bar'.
    For safety we always wrap.
    """
    return "'" + value.replace("'", "'\\''") + "'"


def _quote_for_export(value: str) -> str:
    """shlex-quote suitable for `export KEY=...`."""
    return shlex.quote(value)


def _is_world_writable_path(path):
    """Refuse to write into a directory whose path contains a world-writable
    component. Catches the case where the user runs inject from /tmp or a
    sticky-bit dir and accidentally drops .env into someone else's view.
    """
    p = Path(path).resolve()
    cur = p
    while True:
        try:
            st = cur.stat()
        except FileNotFoundError:
            cur = cur.parent
            continue
        if st.st_mode & stat.S_IWOTH and not (st.st_mode & stat.S_ISVTX):
            return True
        if cur.parent == cur:
            return False
        cur = cur.parent


def _ensure_gitignore(out_path: Path):
    """Append the basename of out_path to .gitignore if not already present.

    Idempotent. Creates .gitignore if missing.
    """
    target_dir = out_path.parent
    gi = target_dir / ".gitignore"
    base = out_path.name
    existing = ""
    if gi.exists():
        existing = gi.read_text()
        # Match a line that's exactly `<base>` (allowing leading ./ or trailing /).
        for line in existing.splitlines():
            stripped = line.strip()
            if stripped == base or stripped == f"./{base}" or stripped == f"/{base}":
                return
            if stripped == ".env" and base == ".env":
                return
    suffix = "" if existing.endswith("\n") or existing == "" else "\n"
    with open(gi, "a") as f:
        f.write(f"{suffix}{base}\n")


def _is_git_tracked(path: Path) -> bool:
    """Best-effort `git ls-files --error-unmatch <path>` check."""
    if not shutil.which("git"):
        return False
    try:
        proc = subprocess.run(
            ["git", "ls-files", "--error-unmatch", str(path)],
            capture_output=True,
            text=True,
            cwd=path.parent,
            timeout=5,
        )
        return proc.returncode == 0
    except Exception:
        return False


_MATERIALIZED_DIR = ".cush-secrets.materialized"


def _materialize_file_sidecar(env_dir, env_name, b64_value):
    """Decode a base64-encoded `file`-type secret to a sidecar binary file.

    Path: <env_dir>/.cush-secrets.materialized/<env_name>, mode 600.
    Returns the absolute path so the caller can set <env_name>_FILE in .env.

    base64 strict mode: the value is expected to be a `file`-type secret
    written by `secure-entry --type file --save-to-op` (which always emits
    pure base64 with no decoration). If decoding fails the caller should
    fall back to treating the value as opaque text.
    """
    sidecar_dir = Path(env_dir) / _MATERIALIZED_DIR
    sidecar_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(sidecar_dir, 0o700)
    except OSError:
        pass
    sidecar_path = sidecar_dir / env_name
    try:
        raw = base64.b64decode(b64_value, validate=False)
    except Exception as e:
        raise RuntimeError(
            f"failed to base64-decode `file`-type value for {env_name}: {e}"
        )
    fd = os.open(
        str(sidecar_path),
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
    return sidecar_path.resolve()


def _ensure_materialized_gitignore(env_dir):
    """Append `.cush-secrets.materialized/` to .gitignore in env_dir if absent.

    Idempotent. Distinct from `_ensure_gitignore` (which handles the .env
    basename).
    """
    gi = Path(env_dir) / ".gitignore"
    target = f"{_MATERIALIZED_DIR}/"
    existing = ""
    if gi.exists():
        existing = gi.read_text()
        for line in existing.splitlines():
            stripped = line.strip()
            if stripped == target or stripped == _MATERIALIZED_DIR:
                return
    suffix = "" if existing.endswith("\n") or existing == "" else "\n"
    with open(gi, "a") as f:
        f.write(f"{suffix}{target}\n")


def _write_env_file(out_path, values, *, type_map=None):
    """Write a chmod-600 .env file with shell-safe quoting.

    `type_map` is an optional {env_name: type} dict from the manifest. When
    a value is `file`-typed, the binary content (base64-decoded) is written
    to a sidecar file at <env_dir>/.cush-secrets.materialized/<env_name>
    and the .env line is set to <env_name>_FILE pointing at the absolute
    sidecar path. The original env name is dropped from .env (the binary
    is on disk, no point shipping b64 in .env).
    """
    if _is_world_writable_path(out_path.parent):
        raise RuntimeError(
            f"refusing to write {out_path}: parent dir is world-writable. "
            "Re-run from a private directory."
        )
    out_path.parent.mkdir(parents=True, exist_ok=True)

    type_map = type_map or {}
    materialized_any = False

    fd = os.open(str(out_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            for k, v in values.items():
                ftype = type_map.get(k, "string")
                if ftype == "file":
                    try:
                        sidecar = _materialize_file_sidecar(out_path.parent, k, v)
                    except RuntimeError as e:
                        # Surface and treat as missing — partial write is worse
                        # than no write for binary secrets.
                        raise RuntimeError(str(e))
                    materialized_any = True
                    f.write(f"{k}_FILE={_quote_for_env(str(sidecar))}\n")
                else:
                    # ssh + string: write multi-line text quoted with shlex-ish
                    # single-quote rules. _quote_for_env already handles this.
                    f.write(f"{k}={_quote_for_env(v)}\n")
    finally:
        # In case fdopen succeeded, fd is already closed; otherwise close.
        try:
            os.close(fd)
        except OSError:
            pass

    _ensure_gitignore(out_path)
    if materialized_any:
        _ensure_materialized_gitignore(out_path.parent)
    if _is_git_tracked(out_path):
        sys.stderr.write(
            f"\n*** WARNING: {out_path} is tracked by git. "
            f"Run `git rm --cached {out_path.name}` then commit. ***\n\n"
        )


def _write_exports(values, fp=sys.stdout, *, type_map=None):
    """Write `export KEY=value` lines suitable for `eval`.

    For `file`-typed secrets, no sidecar is materialized (we'd have nowhere
    durable to put it); instead we export the base64 verbatim and let the
    consumer decode. Documented in the inject docstring.
    """
    type_map = type_map or {}
    for k, v in values.items():
        ftype = type_map.get(k, "string")
        if ftype == "file":
            # No sidecar in --env mode. Export with a _B64 suffix to flag the
            # encoding to the consumer.
            fp.write(f"export {k}_B64={_quote_for_export(v)}\n")
        else:
            fp.write(f"export {k}={_quote_for_export(v)}\n")


# ───────────────────────────────────────────────────────────────────────────
# Top-level commands
# ───────────────────────────────────────────────────────────────────────────


def _print_status(label, env_name, ref, msg, fp=sys.stderr):
    print(f"[inject] {label:<10} {env_name:<24} {ref:<40} {msg}", file=fp)


def _print_auth_or_vault_error(e, *, kind: str, json_out: bool):
    """Emit auth/access failures to the user. With --json, stdout gets a
    parseable error object; without, stderr gets the human-readable message.
    """
    if json_out:
        print(json.dumps({"error": kind, "message": str(e)}, indent=2))
    else:
        print(f"[inject] secrets {kind}: {e}", file=sys.stderr)


def _check_auth_for_manifest(manifest_obj, *, json_out: bool) -> int:
    """Verify auth for every backend scheme present in the manifest.

    Returns 0 on success, 3 on auth failure. Prints a friendly hint per
    scheme that fails. Used by both cmd_check and cmd_resolve to replace the
    legacy bash-level cush_op_check probe.
    """
    secrets_mod = _load_secrets()
    schemes = secrets_mod.schemes_in_manifest([s.ref for s in manifest_obj.secrets])
    if not schemes:
        return 0
    for scheme in sorted(schemes):
        try:
            who = secrets_mod.whoami_for_scheme(scheme)
        except secrets_mod.SecretsAuthError as e:
            _print_auth_or_vault_error(e, kind="auth", json_out=json_out)
            return 3
        if who is None:
            # whoami doesn't raise; None means probe failed. Surface a
            # scheme-specific hint so the user knows which backend to fix.
            hint = {
                "op": "1Password (`op`) is not authenticated. "
                      "Configure ~/.config/cush-tools/op.env or run `op signin`.",
                "inf": "Infisical is not authenticated. "
                      "Configure ~/.config/cush-tools/infisical.env (universal-auth).",
            }.get(scheme, f"backend {scheme!r} not authenticated")
            _print_auth_or_vault_error(hint, kind="auth", json_out=json_out)
            return 3
    return 0


def _identifier_ok(s: str) -> bool:
    """Check that `s` is a usable item/field name (printable ASCII, no /).

    1Password's UI accepts a wide range, but we conservatively flag empty
    strings, slashes, and control characters.
    """
    if not s:
        return False
    for ch in s:
        if ch == "/" or ch == "\\" or ord(ch) < 0x20:
            return False
    return True


def cmd_validate(manifest_obj, *, json_out: bool) -> int:
    """Schema-only validation. No op calls, no spawn.

    Checks (per-secret):
      - ref parses as op://Vault/Item/Field (3 segments after op://)
      - type ∈ {string, file, ssh}
      - target_vault, target_item are strings if present
      - resolve_target() can synthesize a valid (vault, item, field) given
        the manifest's [defaults] and {project}/{key} substitutions

    Returns 0 if everything's valid, 2 otherwise.

    Note: most of these checks are already enforced at parse time by
    lib/manifest.py. This function exists for explicit pre-flight validation
    (e.g. CI lint of `.cush-secrets`) and surfaces issues that only manifest
    after substitution (e.g. {project}/{key} producing an invalid identifier).
    """
    issues = []  # list of (env_name, severity, message)

    # Schema field is enforced at load time, but state it explicitly here for
    # future-proofing (e.g. if someone constructs a Manifest object directly).
    if manifest_obj.schema != 1:
        issues.append((
            "<schema>", "ERROR",
            f"unsupported schema version {manifest_obj.schema!r}",
        ))

    # Defaults sanity. Strings only.
    for k, v in (manifest_obj.defaults or {}).items():
        if not isinstance(v, str):
            issues.append((
                f"<defaults.{k}>", "ERROR",
                f"value must be a string (got {type(v).__name__})",
            ))

    if not manifest_obj.secrets:
        issues.append(("<secrets>", "WARN", "no secrets declared"))

    # Per-secret validation.
    for spec in manifest_obj.secrets:
        env_name = spec.env_name

        # Ref structure. Validation is offline-friendly: we don't trigger a
        # backend auth check just to lint the manifest. Accept op:// or
        # inf:// shapes that match their respective segment counts.
        ref = spec.ref or ""
        if ref.startswith("op://"):
            parts = ref[len("op://"):].split("/")
            if len(parts) < 3 or any(not p for p in parts[:3]):
                issues.append((env_name, "ERROR",
                               f"ref must be op://Vault/Item/Field (got {ref!r})"))
                continue
        elif ref.startswith("inf://"):
            parts = ref[len("inf://"):].split("/")
            if len(parts) < 3 or any(not p for p in parts):
                issues.append((env_name, "ERROR",
                               f"ref must be inf://<env>/<path>/<KEY> (got {ref!r})"))
                continue
        else:
            issues.append((env_name, "ERROR",
                           f"ref must start with op:// or inf:// (got {ref!r})"))
            continue

        # Type.
        if spec.type not in ("string", "file", "ssh"):
            issues.append((env_name, "ERROR",
                           f"type must be one of string|file|ssh (got {spec.type!r})"))

        # target_vault / target_item types (parser already enforces; recheck).
        if spec.target_vault is not None and not isinstance(spec.target_vault, str):
            issues.append((env_name, "ERROR",
                           f"target_vault must be a string"))
        if spec.target_item is not None and not isinstance(spec.target_item, str):
            issues.append((env_name, "ERROR",
                           f"target_item must be a string"))

        # Substitution rendering: {project} / {key} -> a usable identifier.
        # Only relevant for stash auto-create — the inject path uses spec.ref
        # directly. So missing target_vault is a WARN (stash will fail later)
        # not an ERROR (inject may still work). Likewise, an unusable rendered
        # identifier is a WARN.
        try:
            vault, item, field_name = manifest_mod.resolve_target(
                manifest_obj, env_name
            )
        except manifest_mod.ManifestError as e:
            issues.append((env_name, "WARN",
                           f"target resolution: {e} "
                           f"(inject will use spec.ref; only affects stash auto-create)"))
            continue
        except KeyError as e:
            issues.append((env_name, "ERROR", str(e)))
            continue
        if not _identifier_ok(item):
            issues.append((env_name, "WARN",
                           f"resolved item {item!r} contains unusual characters"))
        if not _identifier_ok(field_name):
            issues.append((env_name, "WARN",
                           f"resolved field {field_name!r} contains unusual characters"))
        if not _identifier_ok(vault):
            issues.append((env_name, "WARN",
                           f"resolved vault {vault!r} contains unusual characters"))

    has_error = any(sev == "ERROR" for _, sev, _ in issues)

    if json_out:
        out = {
            "valid": not has_error,
            "manifest": str(manifest_obj.source_path),
            "issues": [
                {"env_name": n, "severity": s, "message": m}
                for n, s, m in issues
            ],
        }
        print(json.dumps(out, indent=2))
    else:
        print(f"validating {manifest_obj.source_path}", file=sys.stderr)
        # Print per-secret status: OK lines for clean specs, then issues.
        secrets_with_issues = {n for n, _, _ in issues}
        for spec in manifest_obj.secrets:
            if spec.env_name not in secrets_with_issues:
                print(f"OK    {spec.env_name:<24} {spec.ref}")
        for env_name, sev, msg in issues:
            print(f"{sev:<5} {env_name:<24} {msg}")
        # Summary on stderr after per-secret lines (so the verdict is the
        # last thing the user sees).
        sys.stdout.flush()
        n_err = sum(1 for _, s, _ in issues if s == "ERROR")
        n_warn = sum(1 for _, s, _ in issues if s == "WARN")
        n_secrets = len(manifest_obj.secrets)
        verdict = "INVALID" if has_error else "OK"
        print(
            f"\n{verdict}: {n_secrets} secret(s), {n_err} error(s), "
            f"{n_warn} warning(s)",
            file=sys.stderr,
        )

    return 2 if has_error else 0


def cmd_check(manifest_obj, *, allow_fallback: bool, json_out: bool) -> int:
    """Report which refs resolve and which are missing.

    Exit 0 if all resolve. Exit 6 if any missing (with allow_fallback,
    fallbacks are considered "resolved" for the purposes of exit code).
    """
    secrets_mod = _load_secrets()

    # Per-scheme auth probe (replaces the legacy bash-level cush_op_check).
    rc = _check_auth_for_manifest(manifest_obj, json_out=json_out)
    if rc != 0:
        return rc

    try:
        resolved, missing_specs = _existence_check(manifest_obj)
    except secrets_mod.SecretsAuthError as e:
        _print_auth_or_vault_error(e, kind="auth", json_out=json_out)
        return 3
    except secrets_mod.SecretsAccessError as e:
        _print_auth_or_vault_error(e, kind="access", json_out=json_out)
        return 4

    # Apply fallbacks if requested.
    fallback_used = []
    still_missing = []
    for spec in missing_specs:
        if allow_fallback and spec.fallback is not None:
            fallback_used.append(spec.env_name)
        else:
            still_missing.append(spec)

    if json_out:
        out = {
            "manifest": str(manifest_obj.source_path),
            "resolved": sorted(resolved.keys()),
            "fallback": sorted(fallback_used),
            "missing": [s.env_name for s in still_missing],
        }
        print(json.dumps(out, indent=2))
    else:
        for env_name in sorted(resolved):
            ref = next(s.ref for s in manifest_obj.secrets if s.env_name == env_name)
            _print_status("OK", env_name, ref, "resolved")
        for env_name in sorted(fallback_used):
            ref = next(s.ref for s in manifest_obj.secrets if s.env_name == env_name)
            _print_status("FALLBACK", env_name, ref, "using manifest fallback")
        for spec in still_missing:
            _print_status("MISSING", spec.env_name, spec.ref, "not in 1Password")

    if still_missing:
        return 6
    return 0


def cmd_resolve(
    manifest_obj,
    *,
    output_mode: str,
    out_path,
    no_prompt: bool,
    allow_fallback: bool,
    parallel: bool,
    max_parallel: int,
    qr: bool,
    timeout_sec: int,
    json_out: bool,
) -> int:
    """Full pipeline: existence check → optional auto-spawn → wait → render."""
    secrets_mod = _load_secrets()

    # Per-scheme auth probe (replaces the legacy bash-level cush_op_check).
    rc = _check_auth_for_manifest(manifest_obj, json_out=json_out)
    if rc != 0:
        return rc

    try:
        resolved, missing_specs = _existence_check(manifest_obj)
    except secrets_mod.SecretsAuthError as e:
        _print_auth_or_vault_error(e, kind="auth", json_out=json_out)
        return 3
    except secrets_mod.SecretsAccessError as e:
        _print_auth_or_vault_error(e, kind="access", json_out=json_out)
        return 4

    # Filter optional-with-fallback specs out of "missing" if allow_fallback.
    fallback_values = {}
    if allow_fallback:
        keep = []
        for spec in missing_specs:
            if spec.fallback is not None:
                fallback_values[spec.env_name] = spec.fallback
            else:
                keep.append(spec)
        missing_specs = keep

    if missing_specs:
        if no_prompt:
            print(
                f"[inject] {len(missing_specs)} secret(s) missing in 1Password; "
                f"--no-prompt is set. Aborting.",
                file=sys.stderr,
            )
            for spec in missing_specs:
                _print_status("MISSING", spec.env_name, spec.ref, "")
            return 6

        # Spawn tunnels.
        run_id = uuid.uuid4().hex[:12]
        run_dir = Path("/tmp/cush-inject") / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        spawned = []
        try:
            try:
                # Pass entry_type=None so _spawn_one falls back to spec.type
                # (per-secret type from the manifest).
                spawned = _spawn_many(
                    missing_specs, run_dir,
                    parallel=parallel,
                    max_parallel=max_parallel,
                    entry_type=None,
                )
            except RuntimeError as e:
                print(f"[inject] spawn failed: {e}", file=sys.stderr)
                _cleanup(spawned, run_dir)
                return 4

            _print_table(spawned, qr=qr, fp=sys.stderr)
            print("\nWaiting for submissions (Ctrl-C to abort)...\n", file=sys.stderr)

            try:
                filled, still_missing = _wait_for_sentinels(
                    spawned, timeout_sec=timeout_sec
                )
            except KeyboardInterrupt:
                print("\n[inject] aborted by user; cleaning up tunnels.", file=sys.stderr)
                _cleanup(spawned, run_dir)
                return 5

            if still_missing:
                print(
                    f"\n[inject] timeout after {timeout_sec}s. Still missing: "
                    f"{sorted(still_missing)}",
                    file=sys.stderr,
                )
                _cleanup(spawned, run_dir)
                return 8

        finally:
            # On the success path we still want to close tunnels and remove
            # the sentinel dir — but only AFTER the re-render below succeeds,
            # because the user might want to re-trigger if op reads fail.
            # We defer cleanup to after re-render in the happy path.
            pass

        # Re-render the entire manifest (one batched call where possible)
        # to fetch all values, including the newly-submitted ones.
        try:
            final = _render_via_secrets(manifest_obj.secrets)
        except secrets_mod.SecretsError as e:
            print(f"[inject] secrets error after submission: {e}", file=sys.stderr)
            _cleanup(spawned, run_dir)
            return 4

        _cleanup(spawned, run_dir)
        resolved = final
    else:
        # Nothing was missing — render everything in one go.
        try:
            resolved = _render_via_secrets(manifest_obj.secrets)
        except secrets_mod.SecretsError as e:
            print(f"[inject] secrets error: {e}", file=sys.stderr)
            return 4

    # Merge fallback values.
    for k, v in fallback_values.items():
        resolved.setdefault(k, v)

    # Order values per manifest order, dropping any spec we still don't have.
    ordered = {}
    for spec in manifest_obj.secrets:
        if spec.env_name in resolved:
            ordered[spec.env_name] = resolved[spec.env_name]

    # Build type_map so file-typed secrets get sidecar materialization.
    type_map = {s.env_name: s.type for s in manifest_obj.secrets}

    # Materialize.
    if output_mode == "exports":
        _write_exports(ordered, fp=sys.stdout, type_map=type_map)
        if json_out:
            # JSON is not meaningful in --env mode, but if requested print
            # to stderr as a status report.
            print(
                json.dumps({"mode": "exports", "keys": list(ordered.keys())}),
                file=sys.stderr,
            )
        return 0

    # env-file mode.
    try:
        _write_env_file(out_path, ordered, type_map=type_map)
    except RuntimeError as e:
        print(f"[inject] {e}", file=sys.stderr)
        return 7
    except OSError as e:
        print(f"[inject] failed to write {out_path}: {e}", file=sys.stderr)
        return 7

    if json_out:
        print(json.dumps({"mode": "env-file", "path": str(out_path),
                          "keys": list(ordered.keys())}, indent=2))
    else:
        print(
            f"[inject] wrote {out_path} ({len(ordered)} key(s), mode 600)",
            file=sys.stderr,
        )
    return 0


# ───────────────────────────────────────────────────────────────────────────
# Self-test (no real op calls)
# ───────────────────────────────────────────────────────────────────────────


def _self_test() -> int:
    """Smoke test the manifest+template flow with a mocked secrets layer."""
    import tempfile, types

    sample = """\
schema = 1
[defaults]
target_vault = "Personal"
target_item = "{project}"
[secrets]
A = "op://Personal/proj/a"
B = { ref = "op://Personal/proj/b", fallback = "default-b" }
C = "op://Personal/proj/c"
"""
    failures = 0

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        m_path = td / ".cush-secrets"
        m_path.write_text(sample)
        m = manifest_mod.load(m_path)

        # Mock cush_secrets dispatch layer. The fakes mirror the public
        # surface inject.py uses: inject_template, read, schemes_in_manifest,
        # whoami_for_scheme, plus the SecretsError hierarchy.
        canned = {
            "op://Personal/proj/a": "value-a",
            # b is intentionally missing
            "op://Personal/proj/c": "value-c with spaces",
        }

        class FakeSecretsError(Exception): pass
        class FakeSecretsAuthError(FakeSecretsError): pass
        class FakeSecretsRefNotFound(FakeSecretsError): pass
        class FakeSecretsAccessError(FakeSecretsError): pass

        def fake_inject_template(template):
            # Render only refs we know about; raise on the first unresolved,
            # mirroring `op inject`'s behavior so the fallback path is
            # exercised.
            out = []
            for line in template.splitlines():
                m2 = re.search(r"\{\{ ((?:op|inf)://[^}]+) \}\}", line)
                if not m2:
                    out.append(line)
                    continue
                ref = m2.group(1).strip()
                if ref in canned:
                    out.append(line.replace(m2.group(0), canned[ref]))
                else:
                    raise FakeSecretsError(f"unresolved: {ref}")
            return "\n".join(out) + "\n"

        def fake_read(ref):
            if ref in canned:
                return canned[ref]
            raise FakeSecretsRefNotFound(f"not found: {ref}")

        def fake_schemes_in_manifest(refs):
            out = set()
            for r in refs or []:
                if isinstance(r, str) and "://" in r:
                    out.add(r.split("://", 1)[0])
            return out

        def fake_whoami_for_scheme(scheme):
            # Always-authenticated mock — keeps the auth-probe path quiet
            # during self-test.
            return {"scheme": scheme, "user": "self-test"}

        fake_secrets = types.SimpleNamespace(
            inject_template=fake_inject_template,
            read=fake_read,
            schemes_in_manifest=fake_schemes_in_manifest,
            whoami_for_scheme=fake_whoami_for_scheme,
            SecretsError=FakeSecretsError,
            SecretsAuthError=FakeSecretsAuthError,
            SecretsRefNotFound=FakeSecretsRefNotFound,
            SecretsAccessError=FakeSecretsAccessError,
        )
        global _secrets
        _secrets = fake_secrets

        # Test existence_check: should resolve A, C; mark B as missing.
        resolved, missing = _existence_check(m)
        if set(resolved.keys()) != {"A", "C"}:
            print(f"[inject self-test] resolved set wrong: {set(resolved)}", file=sys.stderr)
            failures += 1
        if [s.env_name for s in missing] != ["B"]:
            print(f"[inject self-test] missing set wrong: "
                  f"{[s.env_name for s in missing]}", file=sys.stderr)
            failures += 1

        # Test cmd_check no fallback -> exit 6.
        rc = cmd_check(m, allow_fallback=False, json_out=False)
        if rc != 6:
            print(f"[inject self-test] cmd_check expected 6, got {rc}", file=sys.stderr)
            failures += 1

        # Test cmd_check with fallback -> exit 0 (B has fallback).
        rc = cmd_check(m, allow_fallback=True, json_out=False)
        if rc != 0:
            print(f"[inject self-test] cmd_check w/ fallback expected 0, got {rc}",
                  file=sys.stderr)
            failures += 1

        # Test table render path on a fake spawn list (no real spawn).
        fake_spawned = [
            SpawnedTunnel(
                env_name="B",
                ref="op://Personal/proj/b",
                label="b-deadbeef",
                url="https://entry-b-deadbeef.tunnel.cush.rocks",
                sentinel=td / "sentinel.B",
                spec=next(s for s in m.secrets if s.env_name == "B"),
            )
        ]
        # Suppress stderr for this — we just want it to not crash.
        import io
        buf = io.StringIO()
        _print_table(fake_spawned, qr=False, fp=buf)
        if "B" not in buf.getvalue() or "entry-b-deadbeef" not in buf.getvalue():
            print(f"[inject self-test] table missing data: {buf.getvalue()!r}",
                  file=sys.stderr)
            failures += 1

        # Test render via dispatch (B missing, A and C resolve). Exercise
        # just A and C here.
        only_ac = [s for s in m.secrets if s.env_name in ("A", "C")]
        rendered = _render_via_secrets(only_ac)
        if rendered.get("A") != "value-a" or rendered.get("C") != "value-c with spaces":
            print(f"[inject self-test] render values wrong: {rendered}", file=sys.stderr)
            failures += 1

        # Test env-file write + quoting.
        env_path = td / ".env"
        _write_env_file(env_path, {"A": "value-a", "C": "value-c with spaces"})
        text = env_path.read_text()
        if "A='value-a'" not in text:
            print(f"[inject self-test] env quoting (A) wrong: {text!r}", file=sys.stderr)
            failures += 1
        if "C='value-c with spaces'" not in text:
            print(f"[inject self-test] env quoting (C) wrong: {text!r}", file=sys.stderr)
            failures += 1
        # Check mode 600.
        st = env_path.stat()
        mode = st.st_mode & 0o777
        if mode != 0o600:
            print(f"[inject self-test] env file mode wrong: {oct(mode)}",
                  file=sys.stderr)
            failures += 1
        # gitignore appended.
        gi = (td / ".gitignore").read_text()
        if ".env" not in gi:
            print(f"[inject self-test] gitignore not updated: {gi!r}", file=sys.stderr)
            failures += 1

    if failures:
        print(f"[inject self-test] {failures} failure(s)", file=sys.stderr)
        return 1
    print("[inject self-test] ok")
    return 0


# ───────────────────────────────────────────────────────────────────────────
# CLI entry (called by bin/inject)
# ───────────────────────────────────────────────────────────────────────────


def _build_argparser():
    p = argparse.ArgumentParser(
        prog="inject",
        description="Materialize a .env from a .cush-secrets manifest via 1Password.",
    )
    p.add_argument("--manifest", help="Path to .cush-secrets (default: walk up from cwd).")
    p.add_argument("--out", default=".env", help="Output .env path (default: ./.env).")
    p.add_argument("--env", dest="env_mode", action="store_true",
                   help="Print `export KEY=value` to stdout instead of writing a file.")
    p.add_argument("--check", action="store_true",
                   help="Dry run; report status, exit 6 if any missing.")
    p.add_argument("--validate", action="store_true",
                   help="Schema-only validation (no op calls). Exit 0 if "
                        "valid, 2 otherwise.")
    p.add_argument("--no-prompt", action="store_true",
                   help="Don't auto-spawn forms; exit 6 on any missing ref.")
    p.add_argument("--allow-fallback", action="store_true",
                   help="Use manifest fallbacks for missing values.")
    parmode = p.add_mutually_exclusive_group()
    parmode.add_argument("--serial", action="store_true",
                         help="Spawn forms one at a time.")
    parmode.add_argument("--parallel", action="store_true", default=True,
                         help="Spawn forms in parallel (default).")
    p.add_argument("--max-parallel", type=int, default=5,
                   help="Cap on concurrent forms when --parallel (default 5).")
    p.add_argument("--timeout", type=int, default=60,
                   help="Total wait timeout in MINUTES (default 60).")
    p.add_argument("--no-qr", dest="qr", action="store_false", default=True,
                   help="Suppress ASCII QR output.")
    p.add_argument("--json", dest="json_out", action="store_true",
                   help="Machine-readable status output.")
    p.add_argument("--self-test", action="store_true",
                   help="Run an in-process smoke test with mocked op.")
    return p


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    args = _build_argparser().parse_args(argv)

    if args.self_test:
        return _self_test()

    # Resolve manifest path.
    if args.manifest:
        m_path = Path(args.manifest)
        if not m_path.is_file():
            print(f"[inject] manifest not found: {m_path}", file=sys.stderr)
            return 2
    else:
        m_path = manifest_mod.find_manifest()
        if m_path is None:
            print(
                "[inject] no .cush-secrets found in this directory or any parent.",
                file=sys.stderr,
            )
            return 2

    try:
        manifest_obj = manifest_mod.load(m_path)
    except ManifestError as e:
        # Validation mode: render parser failures in the same shape so
        # consumers don't have to special-case them.
        if args.validate:
            if args.json_out:
                print(json.dumps({
                    "valid": False,
                    "manifest": str(m_path),
                    "issues": [
                        {"env_name": "<parse>", "severity": "ERROR",
                         "message": str(e)}
                    ],
                }, indent=2))
            else:
                print(f"validating {m_path}", file=sys.stderr)
                print(f"ERROR <parse>                  {e}")
                sys.stdout.flush()
                print(f"\nINVALID: TOML parse failed", file=sys.stderr)
            return 2
        print(f"[inject] {e}", file=sys.stderr)
        return 2

    if args.validate:
        return cmd_validate(manifest_obj, json_out=args.json_out)

    if args.check:
        return cmd_check(
            manifest_obj,
            allow_fallback=args.allow_fallback,
            json_out=args.json_out,
        )

    out_path = Path(args.out).resolve()
    output_mode = "exports" if args.env_mode else "env-file"
    timeout_sec = max(1, args.timeout) * 60

    return cmd_resolve(
        manifest_obj,
        output_mode=output_mode,
        out_path=out_path,
        no_prompt=args.no_prompt,
        allow_fallback=args.allow_fallback,
        parallel=not args.serial,
        max_parallel=args.max_parallel,
        qr=args.qr,
        timeout_sec=timeout_sec,
        json_out=args.json_out,
    )


if __name__ == "__main__":
    sys.exit(main())

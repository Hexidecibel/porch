#!/usr/bin/env python3
"""Bulk wrapper around `bin/cush-migrate-backend`.

Walks one or more roots, finds every `.cush-secrets` manifest, and migrates
each one (op:// → inf://) by shelling out to the per-project tool. Two-phase
flow by default:

  1. dry-run pass: invoke `bin/cush-migrate-backend --dry-run` for every
     project. Bails on the first failure (unless --continue-on-error).
  2. confirmation prompt (TTY only).
  3. real-run pass: invoke `bin/cush-migrate-backend` for every project.
     Bails on the first failure (unless --continue-on-error).

Already-migrated manifests (only inf:// refs) are skipped before either
pass — the per-project tool would no-op them anyway, but skipping keeps
the output uncluttered. Manifests with zero secrets are also skipped.

Resume safety: a partially-completed bulk run leaves successfully-migrated
projects on inf:// (so re-running this tool skips them as no-ops), and the
current project's `.cush-secrets.bak` intact if the per-project tool got
that far. Re-running is always safe.

Exit codes:
  0  all projects succeeded (or were already migrated)
  1  at least one project failed migration
  2  argument or discovery error
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Make sibling modules importable.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import manifest as manifest_mod
from manifest import Manifest, ManifestError


REPO_ROOT = Path(__file__).resolve().parent.parent  # cush-tools/
MIGRATE_BIN = REPO_ROOT / "bin" / "cush-migrate-backend"

# Mirror lib/audit.py's exclusions, plus the extras called out in the spec.
SKIP_DIR_NAMES = frozenset({
    "node_modules", ".git", ".cush-secrets.materialized",
    "vendor", "target", "dist", "build",
    ".next", ".nuxt", "__pycache__", ".venv", "venv", ".tox",
    ".cache", "coverage",
})

# Path-segment exclusions (matched against any component of the relative
# path under a root). `.claude/worktrees/` denotes Claude Code agent
# worktrees — these are duplicates of canonical projects and would migrate
# the same secrets twice.
SKIP_PATH_SEGMENTS = (
    (".claude", "worktrees"),
)


# ───────────────────────────────────────────────────────────────────────────
# Data classes
# ───────────────────────────────────────────────────────────────────────────


@dataclass
class ProjectEntry:
    """One discovered manifest, with its categorization."""
    project_dir: Path                          # parent dir of .cush-secrets
    manifest_path: Path
    op_count: int = 0
    inf_count: int = 0
    other_count: int = 0                       # unparseable / unknown scheme
    category: str = "unknown"                  # op-only / mixed / inf-only / empty / invalid
    parse_error: Optional[str] = None
    # populated during run:
    dry_run_rc: Optional[int] = None
    real_run_rc: Optional[int] = None
    skipped_reason: Optional[str] = None       # e.g. "already migrated", "empty manifest"


@dataclass
class BulkResult:
    succeeded: list = field(default_factory=list)        # ProjectEntry
    skipped: list = field(default_factory=list)
    failed: list = field(default_factory=list)
    aborted: bool = False                                # user Ctrl-C or stop-on-error halt


# ───────────────────────────────────────────────────────────────────────────
# Discovery
# ───────────────────────────────────────────────────────────────────────────


def _scheme_of(ref: str) -> str:
    """Return 'op', 'inf', or 'other' for a ref string. Loose, no imports."""
    if not isinstance(ref, str) or "://" not in ref:
        return "other"
    head = ref.split("://", 1)[0]
    if head in ("op", "inf"):
        return head
    return "other"


def _path_skipped(rel_parts: tuple) -> bool:
    """Return True if this relative path lives under a skipped segment combo."""
    for seg_combo in SKIP_PATH_SEGMENTS:
        # match any contiguous run of `rel_parts` to seg_combo
        for i in range(len(rel_parts) - len(seg_combo) + 1):
            if rel_parts[i:i + len(seg_combo)] == seg_combo:
                return True
    return False


def find_manifests(root: Path) -> list:
    """Walk `root` and return a sorted list of `.cush-secrets` paths.

    Skips well-known dependency / build directories and .claude/worktrees/.
    Symlinks to directories are not followed.
    """
    root = root.resolve()
    if not root.exists():
        return []
    found = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        if ".cush-secrets" in filenames:
            mp = Path(dirpath) / ".cush-secrets"
            try:
                rel = mp.relative_to(root)
            except ValueError:
                rel = Path(mp.name)
            if not _path_skipped(rel.parts):
                found.append(mp)
    return sorted(set(found))


def categorize(manifest_path: Path) -> ProjectEntry:
    """Load + classify one manifest. Always returns a ProjectEntry; parse
    errors are captured in `parse_error` and category becomes "invalid"."""
    project_dir = manifest_path.parent.resolve()
    entry = ProjectEntry(
        project_dir=project_dir, manifest_path=manifest_path.resolve(),
    )
    try:
        m = manifest_mod.load(manifest_path)
    except ManifestError as e:
        entry.category = "invalid"
        entry.parse_error = str(e)
        return entry

    for spec in m.secrets:
        s = _scheme_of(spec.ref)
        if s == "op":
            entry.op_count += 1
        elif s == "inf":
            entry.inf_count += 1
        else:
            entry.other_count += 1

    total = entry.op_count + entry.inf_count + entry.other_count
    if total == 0:
        entry.category = "empty"
    elif entry.op_count == 0 and entry.inf_count > 0:
        entry.category = "inf-only"
    elif entry.op_count > 0 and entry.inf_count == 0:
        entry.category = "op-only"
    elif entry.op_count > 0 and entry.inf_count > 0:
        entry.category = "mixed"
    else:
        entry.category = "unknown"
    return entry


def _glob_matches(path: Path, patterns: list) -> bool:
    """True if `path` (or any of its string forms) matches any glob in `patterns`."""
    if not patterns:
        return False
    candidates = [str(path), path.name, str(path) + "/"]
    for pat in patterns:
        for c in candidates:
            if fnmatch.fnmatch(c, pat):
                return True
    return False


def filter_entries(entries: list, *, include: list, exclude: list) -> list:
    out = []
    for e in entries:
        if include and not _glob_matches(e.project_dir, include):
            continue
        if exclude and _glob_matches(e.project_dir, exclude):
            continue
        out.append(e)
    return out


# ───────────────────────────────────────────────────────────────────────────
# Plan rendering
# ───────────────────────────────────────────────────────────────────────────


def _print_plan_table(entries: list, *, fp=sys.stderr) -> None:
    """ASCII table summarizing each discovered project."""
    if not entries:
        return
    headers = ("PROJECT", "CATEGORY", "OP", "INF", "OTHER")
    rows = []
    for e in entries:
        rows.append((
            str(e.project_dir),
            e.category,
            str(e.op_count),
            str(e.inf_count),
            str(e.other_count),
        ))

    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if len(cell) > widths[i]:
                widths[i] = len(cell)
    widths = [min(w, 70) for w in widths]

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
# Per-project subprocess invocation
# ───────────────────────────────────────────────────────────────────────────


def _build_per_project_args(
    *,
    dry_run: bool,
    target_env: str,
    target_path_template: str,
    keep_bak: Optional[bool],
    no_validate: bool,
    keep_orphans: bool = False,
    clean_only: bool = False,
) -> list:
    """Build the argv (excluding the binary itself) for cush-migrate-backend."""
    args = []
    if dry_run:
        args.append("--dry-run")
    if target_env and target_env != "dev":
        args.extend(["--target-env", target_env])
    if target_path_template and target_path_template != "/{project}":
        args.extend(["--target-path-template", target_path_template])
    if keep_bak is True:
        args.append("--keep-bak")
    elif keep_bak is False:
        args.append("--no-keep-bak")
    if no_validate:
        args.append("--no-validate")
    if keep_orphans:
        args.append("--keep-orphans")
    if clean_only:
        args.append("--clean-only")
    return args


# 5 minutes per project: enough for an op→inf round-trip plus the
# post-validate `bin/inject --check` (each backend call is ≤30s, plus
# slack for slow networks). Enforced by the bulk runner so the entire
# flight can't be stalled by one stuck project.
PER_PROJECT_TIMEOUT_SEC = 300


def _run_one(
    entry: ProjectEntry,
    *,
    dry_run: bool,
    target_env: str,
    target_path_template: str,
    keep_bak: Optional[bool],
    no_validate: bool,
    keep_orphans: bool = False,
    clean_only: bool = False,
    runner=None,
    timeout: Optional[int] = PER_PROJECT_TIMEOUT_SEC,
) -> int:
    """Invoke `bin/cush-migrate-backend` for one project. Streams output live
    so the user sees per-project progress for long bulk runs.

    `runner` lets tests inject a fake subprocess.run-like callable.
    `timeout` is the total wall-clock budget per project (default 5 min) —
    if the per-project tool stalls, the bulk runner won't hang waiting.
    Tests pass `timeout=None` to skip enforcement on the fake runner.
    """
    cmd = [str(MIGRATE_BIN)] + _build_per_project_args(
        dry_run=dry_run,
        target_env=target_env,
        target_path_template=target_path_template,
        keep_bak=keep_bak,
        no_validate=no_validate,
        keep_orphans=keep_orphans,
        clean_only=clean_only,
    )
    runner = runner or subprocess.run
    # The fake runner used in self-test doesn't accept `timeout`, so only
    # pass it when we're using the real subprocess.run.
    kwargs = {"cwd": str(entry.project_dir), "text": True}
    if runner is subprocess.run and timeout is not None:
        kwargs["timeout"] = timeout
    try:
        proc = runner(cmd, **kwargs)
    except subprocess.TimeoutExpired:
        print(f"[migrate-all] per-project tool timed out after {timeout}s "
              f"for {entry.project_dir}; treating as failure",
              file=sys.stderr, flush=True)
        return 124  # conventional shell timeout exit
    return proc.returncode


# ───────────────────────────────────────────────────────────────────────────
# Bulk orchestration
# ───────────────────────────────────────────────────────────────────────────


def _phase(
    label: str,
    entries: list,
    *,
    dry_run: bool,
    target_env: str,
    target_path_template: str,
    keep_bak: Optional[bool],
    no_validate: bool,
    continue_on_error: bool,
    keep_orphans: bool = False,
    clean_only: bool = False,
    fp=sys.stderr,
    runner=None,
) -> tuple:
    """Run one phase (dry or real) across `entries`. Returns (results, halted).

    `results` is a list of (entry, rc) tuples in the same order as `entries`.
    `halted` is True iff we stopped on a failure before exhausting `entries`.
    """
    results = []
    halted = False
    total = len(entries)
    for i, e in enumerate(entries, 1):
        print(f"\n[migrate-all] {label} ({i}/{total}) {e.project_dir}",
              file=fp, flush=True)
        try:
            rc = _run_one(
                e,
                dry_run=dry_run,
                target_env=target_env,
                target_path_template=target_path_template,
                keep_bak=keep_bak,
                no_validate=no_validate,
                keep_orphans=keep_orphans,
                clean_only=clean_only,
                runner=runner,
                timeout=(None if runner is not None else PER_PROJECT_TIMEOUT_SEC),
            )
        except KeyboardInterrupt:
            print(f"\n[migrate-all] aborted by user during {label}",
                  file=fp, flush=True)
            results.append((e, 130))
            halted = True
            break
        except Exception as ex:  # noqa: BLE001 — surface unexpected errors
            print(f"[migrate-all] {label} unexpected error: {ex}",
                  file=fp, flush=True)
            rc = 1
            results.append((e, rc))
            if not continue_on_error:
                halted = True
                break
            continue

        results.append((e, rc))
        if rc == 0:
            print(f"[migrate-all] {label} ok    {e.project_dir}",
                  file=fp, flush=True)
        else:
            print(f"[migrate-all] {label} FAIL  {e.project_dir} (rc={rc})",
                  file=fp, flush=True)
            if not continue_on_error:
                halted = True
                break
    return results, halted


def _confirm_real_run(n: int, *, fp=sys.stderr) -> bool:
    """TTY-aware confirmation prompt. Returns True if we should proceed."""
    if not sys.stdin.isatty():
        # Non-interactive: proceed automatically (caller decided to run).
        print(f"[migrate-all] non-interactive stdin; proceeding with {n} project(s)",
              file=fp, flush=True)
        return True
    try:
        ans = input(
            f"\n[migrate-all] Proceed with real migration of {n} project(s)? [y/N]: "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("", file=fp)
        return False
    return ans in ("y", "yes")


def run_bulk(
    roots: list,
    *,
    dry_run_only: bool,
    skip_dry_run: bool,
    continue_on_error: bool,
    include: list,
    exclude: list,
    target_env: str,
    target_path_template: str,
    keep_bak: Optional[bool],
    no_validate: bool,
    json_out: bool,
    keep_orphans: bool = False,
    clean_only: bool = False,
    fp=sys.stderr,
    runner=None,
    confirm=_confirm_real_run,
) -> int:
    """End-to-end bulk migration. Returns exit code (0/1/2).

    `keep_orphans` (default False): pass through to per-project tool. When
    False, each per-project run pre-flights an orphan cleanup at its
    destination path.

    `clean_only` (default False): bulk-level cleanup mode. Walks every
    matching manifest, runs the per-project tool with `--clean-only` (and
    only that), and summarizes. No dry-run / real-run phases. Useful when
    a prior bulk run left orphans across many projects.
    """
    # ─── 1. Discover. ───
    all_manifests = []
    for r in roots:
        all_manifests.extend(find_manifests(r))
    # de-dup if roots overlap
    seen = set()
    deduped = []
    for mp in all_manifests:
        if mp in seen:
            continue
        seen.add(mp)
        deduped.append(mp)

    entries = [categorize(mp) for mp in deduped]
    entries = filter_entries(entries, include=include, exclude=exclude)
    entries.sort(key=lambda e: str(e.project_dir))

    if not entries:
        msg = f"no .cush-secrets manifests found under: {[str(r) for r in roots]}"
        if json_out:
            print(json.dumps({"error": "no_manifests", "roots": [str(r) for r in roots]},
                             indent=2))
        else:
            print(f"[migrate-all] {msg}", file=fp)
        return 2

    # Categorize for the plan + decide which to migrate.
    to_migrate = [e for e in entries if e.category in ("op-only", "mixed")]
    already_migrated = [e for e in entries if e.category == "inf-only"]
    empties = [e for e in entries if e.category == "empty"]
    invalids = [e for e in entries if e.category == "invalid"]

    # ─── 2. Plan display. ───
    if not json_out:
        print(f"[migrate-all] discovered {len(entries)} manifest(s) under "
              f"{len(roots)} root(s)", file=fp)
        print(f"[migrate-all]   to migrate (op/mixed): {len(to_migrate)}",
              file=fp)
        print(f"[migrate-all]   already migrated (inf): {len(already_migrated)}",
              file=fp)
        if empties:
            print(f"[migrate-all]   empty manifests: {len(empties)}",
                  file=fp)
        if invalids:
            print(f"[migrate-all]   INVALID manifests: {len(invalids)}",
                  file=fp)
        print("", file=fp)
        _print_plan_table(entries, fp=fp)

    if invalids and not json_out:
        print("\n[migrate-all] WARNING: skipping invalid manifests:", file=fp)
        for e in invalids:
            print(f"[migrate-all]   {e.project_dir}: {e.parse_error}",
                  file=fp)

    # Mark non-migrating skip reasons up front for the summary.
    for e in already_migrated:
        e.skipped_reason = "already migrated (inf-only)"
    for e in empties:
        e.skipped_reason = "empty manifest"
    for e in invalids:
        e.skipped_reason = f"invalid manifest: {e.parse_error}"

    if not to_migrate:
        if json_out:
            print(json.dumps({
                "status": "nothing_to_do",
                "skipped": [
                    {"project_dir": str(e.project_dir),
                     "category": e.category,
                     "reason": e.skipped_reason}
                    for e in (already_migrated + empties + invalids)
                ],
            }, indent=2))
        else:
            print("\n[migrate-all] nothing to migrate; exiting.", file=fp)
        return 0

    # ─── 3a. Bulk --clean-only short-circuit. ───
    # Run cleanup on every op-only / mixed project (the ones that have
    # destinations on inf://) and exit. No dry-run, no real-run, no
    # confirmation prompt.
    if clean_only:
        if not json_out:
            print(f"\n[migrate-all] === CLEAN-ONLY PASS "
                  f"({len(to_migrate)} project(s)) ===", file=fp)
        clean_results, halted = _phase(
            "clean-only", to_migrate,
            dry_run=False,
            target_env=target_env,
            target_path_template=target_path_template,
            keep_bak=keep_bak,
            no_validate=no_validate,
            continue_on_error=continue_on_error,
            keep_orphans=keep_orphans,
            clean_only=True,
            fp=fp,
            runner=runner,
        )
        clean_failed = [(e, rc) for e, rc in clean_results if rc != 0]
        clean_ok = [(e, rc) for e, rc in clean_results if rc == 0]
        if json_out:
            print(json.dumps({
                "status": ("ok" if not clean_failed and not halted
                           else "partial" if clean_ok else "failed"),
                "cleaned": [str(e.project_dir) for e, _ in clean_ok],
                "failed": [
                    {"project_dir": str(e.project_dir), "rc": rc}
                    for e, rc in clean_failed
                ],
                "halted": halted,
            }, indent=2))
        else:
            print(f"\n[migrate-all] clean-only summary: "
                  f"{len(clean_ok)} ok, {len(clean_failed)} failed",
                  file=fp)
            for e, rc in clean_failed:
                print(f"[migrate-all]   FAIL {e.project_dir} (rc={rc})",
                      file=fp)
        return 0 if not clean_failed and not halted else 1

    # ─── 3. Dry-run pass (unless skipped). ───
    if not skip_dry_run:
        if not json_out:
            print(f"\n[migrate-all] === DRY-RUN PASS ({len(to_migrate)} project(s)) ===",
                  file=fp)
        dry_results, halted = _phase(
            "dry-run", to_migrate,
            dry_run=True,
            target_env=target_env,
            target_path_template=target_path_template,
            keep_bak=keep_bak,
            no_validate=no_validate,
            continue_on_error=continue_on_error,
            keep_orphans=keep_orphans,
            fp=fp,
            runner=runner,
        )
        for e, rc in dry_results:
            e.dry_run_rc = rc

        dry_failures = [e for e, rc in dry_results if rc != 0 and rc != 130]
        ki_during_dry = any(rc == 130 for _, rc in dry_results)
        if halted or dry_failures:
            if not json_out:
                if ki_during_dry:
                    print(f"\n[migrate-all] dry-run pass interrupted by user. "
                          f"To resume, just re-run the same command — "
                          f"already-migrated projects auto-skip.",
                          file=fp)
                else:
                    print(f"\n[migrate-all] dry-run pass FAILED "
                          f"({len(dry_failures)} failure(s)); refusing real run.",
                          file=fp)
                    for e in dry_failures:
                        print(f"[migrate-all]   {e.project_dir} (rc={e.dry_run_rc})",
                              file=fp)
            if json_out:
                print(json.dumps({
                    "status": ("dry_run_aborted" if ki_during_dry
                               else "dry_run_failed"),
                    "failures": [
                        {"project_dir": str(e.project_dir),
                         "rc": e.dry_run_rc}
                        for e in dry_failures
                    ],
                }, indent=2))
            return 1
    else:
        if not json_out:
            print("\n[migrate-all] --skip-dry-run: skipping the dry-run pass.",
                  file=fp)

    if dry_run_only:
        if not json_out:
            print(f"\n[migrate-all] --dry-run: stopping after dry-run pass. "
                  f"All {len(to_migrate)} project(s) passed dry-run.",
                  file=fp)
        if json_out:
            print(json.dumps({
                "status": "dry_run_ok",
                "to_migrate": [
                    {"project_dir": str(e.project_dir),
                     "op_count": e.op_count,
                     "inf_count": e.inf_count}
                    for e in to_migrate
                ],
                "skipped": [
                    {"project_dir": str(e.project_dir),
                     "reason": e.skipped_reason}
                    for e in (already_migrated + empties + invalids)
                ],
            }, indent=2))
        return 0

    # ─── 4. Confirm. ───
    if not confirm(len(to_migrate), fp=fp):
        if not json_out:
            print("[migrate-all] aborted at confirmation prompt.", file=fp)
        return 0

    # ─── 5. Real-run pass. ───
    if not json_out:
        print(f"\n[migrate-all] === REAL-RUN PASS ({len(to_migrate)} project(s)) ===",
              file=fp)
    real_results, halted = _phase(
        "real", to_migrate,
        dry_run=False,
        target_env=target_env,
        target_path_template=target_path_template,
        keep_bak=keep_bak,
        no_validate=no_validate,
        continue_on_error=continue_on_error,
        keep_orphans=keep_orphans,
        fp=fp,
        runner=runner,
    )
    for e, rc in real_results:
        e.real_run_rc = rc

    succeeded = [e for e, rc in real_results if rc == 0]
    failed = [e for e, rc in real_results if rc != 0]
    not_attempted = [e for e in to_migrate
                     if all(e is not de for de, _ in real_results)]

    # ─── 6. Summary. ───
    skipped_all = already_migrated + empties + invalids
    if json_out:
        print(json.dumps({
            "status": ("ok" if not failed and not halted else
                       "partial" if succeeded else "failed"),
            "succeeded": [str(e.project_dir) for e in succeeded],
            "failed": [
                {"project_dir": str(e.project_dir), "rc": e.real_run_rc}
                for e in failed
            ],
            "not_attempted": [str(e.project_dir) for e in not_attempted],
            "skipped": [
                {"project_dir": str(e.project_dir),
                 "reason": e.skipped_reason}
                for e in skipped_all
            ],
            "halted": halted,
        }, indent=2))
    else:
        print(f"\n[migrate-all] === SUMMARY ===", file=fp)
        print(f"[migrate-all] succeeded: {len(succeeded)}", file=fp)
        print(f"[migrate-all] failed:    {len(failed)}", file=fp)
        if not_attempted:
            print(f"[migrate-all] not attempted (halted early): "
                  f"{len(not_attempted)}", file=fp)
        if skipped_all:
            print(f"[migrate-all] skipped:   {len(skipped_all)} "
                  f"(already migrated / empty / invalid)", file=fp)
        if failed:
            print("\n[migrate-all] failures:", file=fp)
            for e in failed:
                print(f"[migrate-all]   {e.project_dir} (rc={e.real_run_rc})",
                      file=fp)
        if not_attempted:
            print("\n[migrate-all] not attempted (run halted before reaching them):",
                  file=fp)
            for e in not_attempted:
                print(f"[migrate-all]   {e.project_dir}", file=fp)
        if halted or any(rc == 130 for _, rc in real_results):
            print("\n[migrate-all] To resume, just re-run the same command — "
                  "already-migrated projects auto-skip.", file=fp)

    if failed or not_attempted:
        return 1
    return 0


# ───────────────────────────────────────────────────────────────────────────
# Self-test (offline, fakes subprocess invocations)
# ───────────────────────────────────────────────────────────────────────────


def _self_test() -> int:
    """In-process smoke test. Builds temp manifests, fakes subprocess.run."""
    import tempfile
    from types import SimpleNamespace

    failures = 0

    SAMPLE_OP = """\
schema = 1
[secrets]
A = "op://Cush/p/a"
B = "op://Cush/p/b"
"""
    SAMPLE_INF = """\
schema = 1
[secrets]
X = "inf://dev/p/X"
"""
    SAMPLE_MIXED = """\
schema = 1
[secrets]
A = "op://Cush/p/a"
B = "inf://dev/p/B"
"""
    SAMPLE_EMPTY = """\
schema = 1
"""

    def _make_runner(rc_by_path: dict, default_rc: int = 0):
        """Return a fake subprocess.run that consults `rc_by_path` by cwd."""
        calls = []

        def fake_run(cmd, *, cwd, text):
            calls.append({"cmd": list(cmd), "cwd": cwd})
            rc = rc_by_path.get(cwd, default_rc)
            return SimpleNamespace(returncode=rc, stdout="", stderr="")

        return fake_run, calls

    def _setup_projects(td: Path, layout: dict):
        """Create per-project manifest files, return list of project paths."""
        for sub, content in layout.items():
            d = td / sub
            d.mkdir(parents=True, exist_ok=True)
            (d / ".cush-secrets").write_text(content)
        return td

    # ─── Test 1: all-success path. ───
    with tempfile.TemporaryDirectory() as td_str:
        td = Path(td_str)
        _setup_projects(td, {
            "p1": SAMPLE_OP,
            "p2": SAMPLE_OP,
            "p3": SAMPLE_INF,        # already migrated, should skip
            "p4": SAMPLE_EMPTY,      # empty, should skip
        })
        # all projects-to-migrate succeed (rc=0).
        runner, calls = _make_runner({}, default_rc=0)

        rc = run_bulk(
            [td],
            dry_run_only=False,
            skip_dry_run=False,
            continue_on_error=False,
            include=[], exclude=[],
            target_env="dev",
            target_path_template="/{project}",
            keep_bak=None,
            no_validate=False,
            json_out=False,
            fp=open(os.devnull, "w"),
            runner=runner,
            confirm=lambda n, *, fp: True,
        )
        if rc != 0:
            print(f"[migrate-all self-test] all-success: expected 0, got {rc}",
                  file=sys.stderr)
            failures += 1
        # Two phases × two migrating projects = 4 calls.
        if len(calls) != 4:
            print(f"[migrate-all self-test] all-success: expected 4 calls, "
                  f"got {len(calls)}", file=sys.stderr)
            failures += 1

    # ─── Test 2: mid-flight failure with default stop-on-error. ───
    with tempfile.TemporaryDirectory() as td_str:
        td = Path(td_str)
        _setup_projects(td, {"p1": SAMPLE_OP, "p2": SAMPLE_OP, "p3": SAMPLE_OP})

        # Make p2's dry-run fail.
        runner, calls = _make_runner({str((td / "p2").resolve()): 4}, default_rc=0)

        rc = run_bulk(
            [td],
            dry_run_only=False,
            skip_dry_run=False,
            continue_on_error=False,
            include=[], exclude=[],
            target_env="dev",
            target_path_template="/{project}",
            keep_bak=None,
            no_validate=False,
            json_out=False,
            fp=open(os.devnull, "w"),
            runner=runner,
            confirm=lambda n, *, fp: True,  # shouldn't be reached
        )
        if rc != 1:
            print(f"[migrate-all self-test] stop-on-error: expected 1, got {rc}",
                  file=sys.stderr)
            failures += 1
        # Should stop after p1 (ok) + p2 (fail) — 2 calls in dry phase, no real phase.
        if len(calls) != 2:
            print(f"[migrate-all self-test] stop-on-error: expected 2 calls, "
                  f"got {len(calls)}", file=sys.stderr)
            failures += 1

    # ─── Test 3: mid-flight failure with --continue-on-error. ───
    with tempfile.TemporaryDirectory() as td_str:
        td = Path(td_str)
        _setup_projects(td, {"p1": SAMPLE_OP, "p2": SAMPLE_OP, "p3": SAMPLE_OP})
        runner, calls = _make_runner({str((td / "p2").resolve()): 4}, default_rc=0)

        rc = run_bulk(
            [td],
            dry_run_only=False,
            skip_dry_run=False,
            continue_on_error=True,
            include=[], exclude=[],
            target_env="dev",
            target_path_template="/{project}",
            keep_bak=None,
            no_validate=False,
            json_out=False,
            fp=open(os.devnull, "w"),
            runner=runner,
            confirm=lambda n, *, fp: True,
        )
        # Dry-run pass: 3 calls, 1 fails. Bulk wrapper still bails before
        # real run since dry-run had failures (--continue-on-error governs
        # iteration-level continuation, not phase-level — design choice).
        if rc != 1:
            print(f"[migrate-all self-test] continue-on-error: expected 1, got {rc}",
                  file=sys.stderr)
            failures += 1
        if len(calls) != 3:
            print(f"[migrate-all self-test] continue-on-error: expected 3 calls, "
                  f"got {len(calls)}", file=sys.stderr)
            failures += 1

    # ─── Test 4: --include / --exclude filters. ───
    with tempfile.TemporaryDirectory() as td_str:
        td = Path(td_str)
        _setup_projects(td, {
            "myapp": SAMPLE_OP, "yourapp": SAMPLE_OP, "skipme": SAMPLE_OP,
        })
        runner, calls = _make_runner({}, default_rc=0)

        rc = run_bulk(
            [td],
            dry_run_only=True,           # stop after dry-run, simpler
            skip_dry_run=False,
            continue_on_error=False,
            include=["*myapp*"],
            exclude=[],
            target_env="dev",
            target_path_template="/{project}",
            keep_bak=None,
            no_validate=False,
            json_out=False,
            fp=open(os.devnull, "w"),
            runner=runner,
            confirm=lambda n, *, fp: True,
        )
        # `*myapp*` (shell-style fnmatch) matches /tmp/.../myapp but NOT
        # /tmp/.../yourapp — "yourapp" doesn't contain the literal substring
        # "myapp". Expect only `myapp` to be included.
        if rc != 0:
            print(f"[migrate-all self-test] include: expected 0, got {rc}",
                  file=sys.stderr)
            failures += 1
        if len(calls) != 1:
            print(f"[migrate-all self-test] include: expected 1 call, "
                  f"got {len(calls)} (cwds: "
                  f"{[c['cwd'] for c in calls]})", file=sys.stderr)
            failures += 1
        elif "myapp" not in calls[0]["cwd"] or "yourapp" in calls[0]["cwd"]:
            print(f"[migrate-all self-test] include: expected myapp, "
                  f"got {calls[0]['cwd']}", file=sys.stderr)
            failures += 1

        # exclude `*skipme*` should keep all but skipme.
        runner, calls = _make_runner({}, default_rc=0)
        rc = run_bulk(
            [td],
            dry_run_only=True,
            skip_dry_run=False,
            continue_on_error=False,
            include=[], exclude=["*skipme*"],
            target_env="dev",
            target_path_template="/{project}",
            keep_bak=None,
            no_validate=False,
            json_out=False,
            fp=open(os.devnull, "w"),
            runner=runner,
            confirm=lambda n, *, fp: True,
        )
        if rc != 0:
            print(f"[migrate-all self-test] exclude: expected 0, got {rc}",
                  file=sys.stderr)
            failures += 1
        if len(calls) != 2:
            print(f"[migrate-all self-test] exclude: expected 2 calls, "
                  f"got {len(calls)}", file=sys.stderr)
            failures += 1

    # ─── Test 5: skip already-migrated and empty. ───
    with tempfile.TemporaryDirectory() as td_str:
        td = Path(td_str)
        _setup_projects(td, {"a": SAMPLE_INF, "b": SAMPLE_EMPTY})
        runner, calls = _make_runner({}, default_rc=0)
        rc = run_bulk(
            [td],
            dry_run_only=False,
            skip_dry_run=False,
            continue_on_error=False,
            include=[], exclude=[],
            target_env="dev",
            target_path_template="/{project}",
            keep_bak=None,
            no_validate=False,
            json_out=False,
            fp=open(os.devnull, "w"),
            runner=runner,
            confirm=lambda n, *, fp: True,
        )
        if rc != 0:
            print(f"[migrate-all self-test] all-skipped: expected 0, got {rc}",
                  file=sys.stderr)
            failures += 1
        if calls:
            print(f"[migrate-all self-test] all-skipped: expected 0 calls, "
                  f"got {len(calls)}", file=sys.stderr)
            failures += 1

    # ─── Test 6: mixed manifest is treated as op-to-migrate. ───
    with tempfile.TemporaryDirectory() as td_str:
        td = Path(td_str)
        _setup_projects(td, {"m": SAMPLE_MIXED})
        entries = [categorize(p) for p in find_manifests(td)]
        if len(entries) != 1 or entries[0].category != "mixed":
            print(f"[migrate-all self-test] mixed: expected 1 mixed entry, "
                  f"got {[(e.project_dir.name, e.category) for e in entries]}",
                  file=sys.stderr)
            failures += 1
        if entries and (entries[0].op_count != 1 or entries[0].inf_count != 1):
            print(f"[migrate-all self-test] mixed: count wrong "
                  f"(op={entries[0].op_count}, inf={entries[0].inf_count})",
                  file=sys.stderr)
            failures += 1

    # ─── Test 7: skipped path segments (.claude/worktrees). ───
    with tempfile.TemporaryDirectory() as td_str:
        td = Path(td_str)
        good = td / "real-project"
        good.mkdir()
        (good / ".cush-secrets").write_text(SAMPLE_OP)
        wt = td / ".claude" / "worktrees" / "agent-1"
        wt.mkdir(parents=True)
        (wt / ".cush-secrets").write_text(SAMPLE_OP)
        manifests = find_manifests(td)
        if len(manifests) != 1:
            print(f"[migrate-all self-test] worktrees-skip: expected 1 manifest, "
                  f"got {[str(m) for m in manifests]}", file=sys.stderr)
            failures += 1

    if failures:
        print(f"[migrate-all self-test] {failures} failure(s)", file=sys.stderr)
        return 1
    print("[migrate-all self-test] ok")
    return 0


# ───────────────────────────────────────────────────────────────────────────
# CLI
# ───────────────────────────────────────────────────────────────────────────


def _build_argparser():
    p = argparse.ArgumentParser(
        prog="cush-migrate-all",
        description=(
            "Bulk wrapper around bin/cush-migrate-backend. Walks one or more "
            "roots, finds every .cush-secrets manifest, and migrates each "
            "from op:// to inf://."
        ),
    )
    p.add_argument(
        "roots", nargs="*", default=None,
        help="Root directories to scan (default: ~/local/src).",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Only run dry-run on each project; never touch backends or disk.",
    )
    p.add_argument(
        "--skip-dry-run", action="store_true",
        help="Skip the dry-run preflight pass; go straight to real-run.",
    )
    p.add_argument(
        "--continue-on-error", action="store_true",
        help="Don't stop at first failure; carry on and report at the end.",
    )
    p.add_argument(
        "--include", action="append", default=[],
        help="Only migrate projects whose path matches the glob (repeatable).",
    )
    p.add_argument(
        "--exclude", action="append", default=[],
        help="Skip projects whose path matches the glob (repeatable).",
    )
    p.add_argument(
        "--no-validate", action="store_true",
        help="Pass through to per-project migrator (skip bin/inject --check).",
    )
    p.add_argument(
        "--keep-orphans", action="store_true",
        help="Pass-through: skip the per-project pre-flight orphan cleanup.",
    )
    p.add_argument(
        "--clean-only", action="store_true",
        help="Bulk cleanup mode: walk every matching manifest, run "
             "`cush-migrate-backend --clean-only` on each, and summarize. "
             "Does NOT migrate.",
    )
    p.add_argument(
        "--target-env", default="dev",
        help="Target Infisical env slug (default: dev). Pass-through.",
    )
    p.add_argument(
        "--target-path-template", default="/{project}",
        help="inf:// path template (default: '/{project}'). Pass-through.",
    )
    bak = p.add_mutually_exclusive_group()
    bak.add_argument("--keep-bak", dest="keep_bak", action="store_const",
                     const=True, default=None,
                     help="Pass-through: keep .cush-secrets.bak after success.")
    bak.add_argument("--no-keep-bak", dest="keep_bak", action="store_const",
                     const=False,
                     help="Pass-through: delete .cush-secrets.bak after success.")
    p.add_argument(
        "--json", dest="json_out", action="store_true",
        help="Emit a final JSON summary on stdout.",
    )
    p.add_argument(
        "--self-test", action="store_true",
        help="Run an in-process smoke test (no real subprocess calls).",
    )
    return p


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    args = _build_argparser().parse_args(argv)

    if args.self_test:
        return _self_test()

    if args.dry_run and args.skip_dry_run:
        print("[migrate-all] --dry-run and --skip-dry-run are mutually exclusive",
              file=sys.stderr)
        return 2

    if args.roots:
        roots = [Path(r).expanduser().resolve() for r in args.roots]
    else:
        roots = [(Path.home() / "local" / "src").resolve()]

    bad = [r for r in roots if not r.exists()]
    if bad:
        for r in bad:
            print(f"[migrate-all] root does not exist: {r}", file=sys.stderr)
        return 2

    if not MIGRATE_BIN.is_file():
        print(f"[migrate-all] per-project tool not found: {MIGRATE_BIN}",
              file=sys.stderr)
        return 2

    try:
        return run_bulk(
            roots,
            dry_run_only=args.dry_run,
            skip_dry_run=args.skip_dry_run,
            continue_on_error=args.continue_on_error,
            include=args.include,
            exclude=args.exclude,
            target_env=args.target_env,
            target_path_template=args.target_path_template,
            keep_bak=args.keep_bak,
            no_validate=args.no_validate,
            json_out=args.json_out,
            keep_orphans=args.keep_orphans,
            clean_only=args.clean_only,
        )
    except KeyboardInterrupt:
        # Top-level catch: if Ctrl-C escaped any inner handler, surface a
        # clear "what's done, what isn't" hint. Already-migrated projects
        # are inf-only and skipped on re-run, so resume is a re-run of the
        # same command.
        print("\n[migrate-all] aborted by user.", file=sys.stderr)
        print("[migrate-all] To resume, just re-run the same command — "
              "already-migrated projects auto-skip.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

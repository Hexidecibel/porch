#!/usr/bin/env python3
"""Find empty / missing 1Password fields referenced from `.cush-secrets`.

Walks one or more `.cush-secrets` manifests, runs `op read` for each
`op://...` ref, and classifies each field as OK / EMPTY / MISSING / ERROR.

Useful for diagnosing migration failures (e.g. `bin/porch-migrate-backend`
exiting with rc=5 because Infisical refused to accept an empty value
returned by `op read`). Highlights the exact fields the user needs to
populate in 1Password before re-running migration.

Auth: relies on whatever auth `op` itself is configured with — service
account token, signed-in session, or desktop integration. Bails early
with a clear hint if `op whoami` fails (exit 3).

Public functions:
  classify_ref(ref)              -> ('OK'|'EMPTY'|'MISSING'|'ERROR'|'n/a', detail)
  scan_manifest(manifest_path)   -> list[dict]   (rows for that project)
  scan_root(root)                -> list[dict]   (rows across all projects)

CLI entry point lives in `bin/porch-find-empties`.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Iterable, Optional

# Make sibling lib modules importable when loaded by `bin/porch-find-empties`.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import manifest as manifest_mod  # noqa: E402
from op import (  # noqa: E402
    op_read,
    op_whoami,
    OpAuthError,
    OpRefNotFound,
    OpVaultAccessError,
    OpError,
)

# Reuse the discovery helper from migrate_all so we honor the same
# exclusions (`node_modules`, `.git`, `.cush-secrets.materialized`,
# `.claude/worktrees/`, etc.) — keeps `--all` consistent with the bulk
# migrate tool the user just ran.
from migrate_all import find_manifests  # noqa: E402


# ───────────────────────────────────────────────────────────────────────────
# Classification
# ───────────────────────────────────────────────────────────────────────────


# Statuses, in display priority order (worst first).
STATUS_OK = "OK"
STATUS_EMPTY = "EMPTY"
STATUS_MISSING = "MISSING"
STATUS_ERROR = "ERROR"
STATUS_NA = "n/a"

# Statuses that count as a problem worth surfacing in --all default mode.
PROBLEM_STATUSES = frozenset({STATUS_EMPTY, STATUS_MISSING, STATUS_ERROR})


def classify_ref(ref: str) -> tuple[str, str]:
    """Look up a manifest ref and return ``(status, detail)``.

    Status values:
      - ``OK``       — value is non-empty
      - ``EMPTY``    — `op read` returned exit 0 with empty stdout
      - ``MISSING``  — item or field doesn't resolve
      - ``ERROR``    — other op failure (vault access, malformed ref, etc.)
      - ``n/a``      — non-`op://` ref (e.g. `inf://`); skipped here

    Never raises `OpRefNotFound` / `OpError`; raises `OpAuthError` so the
    CLI can short-circuit with a single auth hint and exit 3.
    """
    if not isinstance(ref, str):
        return STATUS_ERROR, f"non-string ref: {ref!r}"
    if not ref.startswith("op://"):
        return STATUS_NA, "non-op ref"
    try:
        value = op_read(ref)
    except OpRefNotFound as e:
        return STATUS_MISSING, str(e)
    except OpVaultAccessError as e:
        # Vault access is op auth-shaped but per-ref, so report it as ERROR
        # rather than tearing down the whole scan with OpAuthError.
        return STATUS_ERROR, f"vault access: {e}"
    except OpAuthError:
        # Re-raise so the CLI can bail once with a clear setup hint.
        raise
    except OpError as e:
        return STATUS_ERROR, str(e)
    if value == "":
        return STATUS_EMPTY, "op read returned empty value"
    return STATUS_OK, ""


# ───────────────────────────────────────────────────────────────────────────
# Scanning
# ───────────────────────────────────────────────────────────────────────────


def scan_manifest(manifest_path: Path) -> list[dict]:
    """Walk one manifest's secrets and classify each ref.

    Returns one row per secret. Manifest-load errors yield a single
    ``invalid-manifest`` row rather than raising — keeps `--all` resilient
    when a single project's TOML is broken.
    """
    project_dir = manifest_path.parent
    project_name = project_dir.name or str(project_dir)
    rows: list[dict] = []
    try:
        m = manifest_mod.load(manifest_path)
    except manifest_mod.ManifestError as e:
        rows.append({
            "project": project_name,
            "project_dir": str(project_dir),
            "manifest_path": str(manifest_path),
            "env_name": "(manifest)",
            "ref": "",
            "status": STATUS_ERROR,
            "detail": f"invalid manifest: {e}",
        })
        return rows

    for spec in m.secrets:
        status, detail = classify_ref(spec.ref)
        rows.append({
            "project": project_name,
            "project_dir": str(project_dir),
            "manifest_path": str(manifest_path),
            "env_name": spec.env_name,
            "ref": spec.ref,
            "status": status,
            "detail": detail,
        })
    return rows


def scan_root(root: Path) -> list[dict]:
    """Find every `.cush-secrets` under `root` and scan each."""
    rows: list[dict] = []
    for mp in find_manifests(root):
        rows.extend(scan_manifest(mp))
    return rows


# ───────────────────────────────────────────────────────────────────────────
# Rendering
# ───────────────────────────────────────────────────────────────────────────


def _filter_for_display(rows: list[dict], *, verbose: bool) -> list[dict]:
    if verbose:
        return rows
    return [r for r in rows if r["status"] in PROBLEM_STATUSES]


def render_table(rows: list[dict]) -> str:
    """Pipe-separated table matching the project's other CLI outputs."""
    headers = ("PROJECT", "ENV_NAME", "REF", "STATUS")
    table = [(r["project"], r["env_name"], r["ref"], r["status"]) for r in rows]

    widths = [len(h) for h in headers]
    for row in table:
        for i, cell in enumerate(row):
            if len(cell) > widths[i]:
                widths[i] = len(cell)
    # Cap REF to keep the table readable; truncate with ellipsis.
    widths[2] = min(widths[2], 60)

    def fmt(cells):
        out = []
        for i, c in enumerate(cells):
            w = widths[i]
            if len(c) > w:
                c = c[: w - 1] + "…"
            out.append(c.ljust(w))
        return " | ".join(out)

    lines = [fmt(headers), "-+-".join("-" * w for w in widths)]
    for row in table:
        lines.append(fmt(row))
    return "\n".join(lines) + "\n"


def render_json(rows: list[dict]) -> str:
    payload = {
        "rows": rows,
        "summary": _summary_counts(rows),
    }
    return json.dumps(payload, indent=2) + "\n"


def _summary_counts(rows: list[dict]) -> dict:
    counts = {STATUS_OK: 0, STATUS_EMPTY: 0, STATUS_MISSING: 0,
              STATUS_ERROR: 0, STATUS_NA: 0}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    counts["total"] = len(rows)
    return counts


# ───────────────────────────────────────────────────────────────────────────
# CLI
# ───────────────────────────────────────────────────────────────────────────


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="porch-find-empties",
        description=(
            "Scan `.cush-secrets` manifests and report which `op://` refs "
            "resolve to empty / missing / errored values in 1Password. "
            "Useful for diagnosing migration failures."
        ),
    )
    p.add_argument(
        "project_dir", nargs="?", default=None,
        help="Project directory containing `.cush-secrets` (default: $PWD).",
    )
    p.add_argument(
        "--all", action="store_true",
        help="Scan every project under ~/local/src instead of one project.",
    )
    p.add_argument(
        "--root", action="append", default=[],
        help="Custom root for --all (repeatable). Default: ~/local/src.",
    )
    p.add_argument(
        "--json", dest="json_out", action="store_true",
        help="Emit machine-readable JSON instead of a table.",
    )
    p.add_argument(
        "--verbose", action="store_true",
        help="In --all mode, show OK rows too (default: only problems).",
    )
    return p


def _resolve_manifest_for_dir(project_dir: Path) -> Optional[Path]:
    candidate = project_dir / ".cush-secrets"
    if candidate.is_file():
        return candidate
    return None


def main(argv: Optional[list[str]] = None) -> int:
    args = _build_argparser().parse_args(argv)

    # Single-project and --all are mutually exclusive in spirit; if both
    # are given, --all wins (with a heads-up).
    if args.all and args.project_dir:
        print(
            "[porch-find-empties] --all overrides PROJECT_DIR; ignoring "
            f"{args.project_dir!r}",
            file=sys.stderr,
        )

    # Auth probe up front: one cheap call instead of N silent failures.
    if op_whoami() is None:
        print(
            "[porch-find-empties] 1Password CLI is not authenticated.\n"
            "  Mode 1 (service account): export OP_SERVICE_ACCOUNT_TOKEN.\n"
            "  Mode 2 (stored creds):    eval \"$(op signin)\" or refresh\n"
            "                            ~/.config/porch/op.env then\n"
            "                            re-source it.\n"
            "See: https://developer.1password.com/docs/cli/get-started/",
            file=sys.stderr,
        )
        return 3

    rows: list[dict] = []
    try:
        if args.all:
            roots = [Path(r).expanduser() for r in args.root] or [
                Path.home() / "local" / "src"
            ]
            bad = [r for r in roots if not r.exists()]
            if bad:
                for r in bad:
                    print(f"[porch-find-empties] root does not exist: {r}",
                          file=sys.stderr)
                return 2
            for r in roots:
                rows.extend(scan_root(r.resolve()))
        else:
            project_dir = Path(args.project_dir or os.getcwd()).expanduser().resolve()
            if not project_dir.is_dir():
                print(f"[porch-find-empties] not a directory: {project_dir}",
                      file=sys.stderr)
                return 2
            mp = _resolve_manifest_for_dir(project_dir)
            if mp is None:
                # Walk up like `bin/inject` does, in case the user invoked
                # from a subdirectory of a project.
                mp = manifest_mod.find_manifest(project_dir)
            if mp is None:
                print(
                    f"[porch-find-empties] no .cush-secrets found at or above "
                    f"{project_dir}",
                    file=sys.stderr,
                )
                return 2
            rows.extend(scan_manifest(mp))
    except OpAuthError as e:
        print(f"[porch-find-empties] op auth lost mid-scan: {e}",
              file=sys.stderr)
        return 3

    display_rows = _filter_for_display(rows, verbose=args.verbose or not args.all)

    if args.json_out:
        sys.stdout.write(render_json(display_rows))
    else:
        if not display_rows:
            mode = "across all scanned projects" if args.all else "in this project"
            print(f"[porch-find-empties] no problems found {mode}.")
        else:
            sys.stdout.write(render_table(display_rows))

    counts = _summary_counts(rows)
    # Non-zero exit if anything actionable surfaced — lets callers chain
    # `bin/porch-find-empties && ...` for "everything's fine, proceed".
    if any(counts[s] for s in PROBLEM_STATUSES):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

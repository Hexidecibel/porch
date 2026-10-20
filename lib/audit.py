#!/usr/bin/env python3
"""Drift detector for the cush-tools secret-hygiene workflow.

Scans one or more roots for `.env`-style files, groups them by project,
classifies the project against any `.cush-secrets` manifest, and reports
drift in human or JSON form. Pure filesystem-side; never calls 1Password
and never echoes secret values.

CLI entry point lives in `bin/cush-audit`. This module exposes:

  - find_env_files(root)        → iterator of Path
  - find_project_root(path)     → Path
  - parse_env_keys(path)        → dict[str, str]   (key → value)
  - classify_value(value)       → str | None       (pattern label or None)
  - is_git_tracked(path)        → bool
  - audit_roots(roots)          → list[ProjectReport]
  - render_human(reports, ...)  → str
  - render_json(reports, ...)   → str
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Optional

# Make sibling modules importable when this file is loaded by `bin/cush-audit`.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import manifest as manifest_mod  # noqa: E402


# ───────────────────────────────────────────────────────────────────────────
# Constants
# ───────────────────────────────────────────────────────────────────────────


SKIP_DIR_NAMES = frozenset({
    "node_modules", ".git", "vendor", "target", "dist", "build",
    ".next", ".nuxt", "__pycache__", ".venv", "venv", ".tox",
    ".cache", "coverage",
})

# Suffixes (after the leading `.env`) that indicate a non-secret template.
_TEMPLATE_SUFFIXES = frozenset({"example", "sample", "template", "dist"})

# Project-root markers, in priority order. `.cush-secrets` first so that a
# manifest in a subdir is treated as its own project.
_PROJECT_MARKERS = (
    ".cush-secrets",
    ".git",
    "package.json",
    "Cargo.toml",
    "pyproject.toml",
    "go.mod",
)

# Pattern → label map for "looks secret-y" classification on TRACKED files.
_HOT_PATTERNS = (
    (re.compile(r"^sk_live_"),                  "sk_live_*"),
    (re.compile(r"^(ghp_|gho_|ghs_)"),          "github_pat"),
    (re.compile(r"^AKIA"),                       "AKIA*"),
    (re.compile(r"^xox[bpa]-"),                  "slack_token"),
    (re.compile(r"-----BEGIN "),                 "pem_private_key"),
    (re.compile(r"^postgres://[^/]+:[^@]+@"),   "postgres_with_password"),
    (re.compile(r"^mysql://[^/]+:[^@]+@"),      "mysql_with_password"),
)

# `KEY=value` regex (mirrors lib/stash.py).
_ENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")


# ───────────────────────────────────────────────────────────────────────────
# Data classes
# ───────────────────────────────────────────────────────────────────────────


@dataclass
class EnvFileReport:
    path: Path                                    # absolute
    rel_path: str                                 # relative to project root
    keys: list[str] = field(default_factory=list)
    tracked: bool = False
    hot_keys: list[tuple[str, str]] = field(default_factory=list)  # (key, label)
    parse_error: Optional[str] = None


@dataclass
class ProjectReport:
    path: Path                                    # absolute
    state: str                                    # CLEAN / MISSING_MANIFEST / ...
    files: list[EnvFileReport] = field(default_factory=list)
    manifest_keys: Optional[list[str]] = None     # None = no manifest
    issues: list[dict] = field(default_factory=list)
    severity: str = "OK"                          # OK / INFO / DRIFT


# ───────────────────────────────────────────────────────────────────────────
# Discovery
# ───────────────────────────────────────────────────────────────────────────


def _is_env_filename(name: str) -> bool:
    """Decide if a filename qualifies as a secret-bearing dotenv-style file."""
    if name == ".env":
        return True
    if name.startswith(".env."):
        suffix = name[len(".env."):]
        # Skip shared template suffixes anywhere in the dotted parts —
        # covers `.env.example`, `.env.example.local`, `.env.staging.example`,
        # etc. We treat any segment matching a template marker as a signal
        # that the file is a checked-in skeleton, not real secret material.
        for part in suffix.split("."):
            if part in _TEMPLATE_SUFFIXES:
                return False
        return True
    # Cloudflare Workers `.dev.vars` / `.dev.vars.<env>` use the same
    # KEY=VALUE dotenv syntax as wrangler's local-secrets format.
    if name == ".dev.vars":
        return True
    if name.startswith(".dev.vars."):
        suffix = name[len(".dev.vars."):]
        for part in suffix.split("."):
            if part in _TEMPLATE_SUFFIXES:
                return False
        return True
    if name == ".envrc":
        return True
    if name in {"secrets.env", "credentials", "credentials.env", "credentials.json"}:
        return True
    if name in {"secrets.yml", "secrets.yaml", "secrets.json", "secrets.toml"}:
        return True
    return False


def find_env_files(root: Path) -> Iterator[Path]:
    """Yield paths matching the env-style inventory patterns under `root`.

    Skips well-known dependency / build directories. Symlinks to directories
    are not followed (cheap protection against pathological loops).
    """
    root = root.resolve()
    if not root.exists():
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Prune in-place so os.walk doesn't descend.
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for fn in filenames:
            if _is_env_filename(fn):
                yield Path(dirpath) / fn


def find_project_root(env_path: Path, scan_root: Path) -> Path:
    """Walk up from `env_path` looking for a project marker.

    Stops at the first dir containing one of `_PROJECT_MARKERS`. If nothing
    matches before reaching `scan_root`, the env file's parent dir is the
    project (covers loose `.env` files in a flat tree).
    """
    scan_root = scan_root.resolve()
    cur = env_path.parent.resolve()
    while True:
        for marker in _PROJECT_MARKERS:
            if (cur / marker).exists():
                return cur
        if cur == scan_root or cur.parent == cur:
            # Use the env file's parent dir as a fallback project root.
            return env_path.parent.resolve()
        if scan_root not in cur.parents and cur != scan_root:
            # We've walked above the scan root; stop.
            return env_path.parent.resolve()
        cur = cur.parent


# ───────────────────────────────────────────────────────────────────────────
# Parsing
# ───────────────────────────────────────────────────────────────────────────


def parse_env_keys(path: Path) -> tuple[dict[str, str], Optional[str]]:
    """Stream a `.env`-style file and return ({key: value}, error_or_None).

    Values are unquoted minimally so the pattern classifier can run on them.
    We deliberately keep this lightweight — full dotenv parsing lives in
    `lib/stash.py` and only matters for migration.
    """
    out: dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                m = _ENV_LINE_RE.match(line)
                if not m:
                    continue
                key = m.group(1)
                rest = m.group(2).lstrip()
                if rest.startswith('"') or rest.startswith("'"):
                    quote = rest[0]
                    end = rest.find(quote, 1)
                    if end == -1:
                        # Unterminated; record raw remainder.
                        value = rest[1:]
                    else:
                        value = rest[1:end]
                else:
                    # Strip inline comment for unquoted values.
                    val = rest
                    for i, ch in enumerate(val):
                        if ch == "#" and (i == 0 or val[i - 1].isspace()):
                            val = val[:i]
                            break
                    value = val.rstrip()
                out[key] = value
        return out, None
    except OSError as e:
        return {}, str(e)


def classify_value(value: str) -> Optional[str]:
    """Return a pattern label if `value` looks like a known secret format."""
    for rx, label in _HOT_PATTERNS:
        if rx.search(value):
            return label
    return None


# ───────────────────────────────────────────────────────────────────────────
# Git tracked check
# ───────────────────────────────────────────────────────────────────────────


def is_git_tracked(path: Path) -> bool:
    """True iff `path` is tracked by git in its enclosing repo."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "--error-unmatch", "--", path.name],
            cwd=path.parent,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return result.returncode == 0
    except (OSError, FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ───────────────────────────────────────────────────────────────────────────
# Audit core
# ───────────────────────────────────────────────────────────────────────────


def _load_manifest_keys(project_path: Path) -> Optional[list[str]]:
    manifest_path = project_path / ".cush-secrets"
    if not manifest_path.is_file():
        return None
    try:
        m = manifest_mod.load(manifest_path)
    except manifest_mod.ManifestError:
        # Treat a malformed manifest as "no manifest" — surface it as an
        # issue so the user fixes it rather than silently losing tracking.
        return None
    return [s.env_name for s in m.secrets]


def audit_project(project_path: Path, env_files: list[Path]) -> ProjectReport:
    project_path = project_path.resolve()
    manifest_keys = _load_manifest_keys(project_path)

    # Surface a malformed-manifest condition explicitly.
    manifest_path = project_path / ".cush-secrets"
    manifest_present = manifest_path.is_file()
    manifest_load_error: Optional[str] = None
    if manifest_present and manifest_keys is None:
        try:
            manifest_mod.load(manifest_path)
        except manifest_mod.ManifestError as e:
            manifest_load_error = str(e)
            manifest_keys = []  # treat as empty manifest for diff purposes

    file_reports: list[EnvFileReport] = []
    union_env_keys: set[str] = set()
    extra_keys_per_file: dict[str, list[str]] = {}

    for ep in env_files:
        try:
            rel = str(ep.relative_to(project_path))
        except ValueError:
            rel = str(ep)
        keys_dict, err = parse_env_keys(ep)
        keys = sorted(keys_dict.keys())
        union_env_keys.update(keys)
        tracked = is_git_tracked(ep)
        hot: list[tuple[str, str]] = []
        if tracked:
            for k, v in keys_dict.items():
                label = classify_value(v)
                if label:
                    hot.append((k, label))
        # Compute "extra in env" only relative to manifest (if one exists).
        if manifest_keys is not None:
            extras = [k for k in keys if k not in set(manifest_keys)]
            if extras:
                extra_keys_per_file[rel] = sorted(extras)
        file_reports.append(EnvFileReport(
            path=ep,
            rel_path=rel,
            keys=keys,
            tracked=tracked,
            hot_keys=hot,
            parse_error=err,
        ))

    issues: list[dict] = []
    state: str
    severity: str = "OK"

    has_tracked = any(fr.tracked for fr in file_reports)
    has_tracked_hot = any(fr.hot_keys for fr in file_reports)

    if manifest_keys is None:
        if env_files:
            state = "MISSING_MANIFEST"
            severity = "DRIFT"
            issues.append({
                "severity": "DRIFT",
                "type": "missing_manifest",
                "files": [fr.rel_path for fr in file_reports],
            })
        else:
            # No env files and no manifest: shouldn't reach here from caller,
            # but classify defensively.
            state = "CLEAN"
    else:
        if manifest_load_error:
            state = "MANIFEST_INVALID"
            severity = "DRIFT"
            issues.append({
                "severity": "DRIFT",
                "type": "manifest_invalid",
                "error": manifest_load_error,
            })
        elif extra_keys_per_file:
            state = "MANIFEST_MISMATCH"
            severity = "DRIFT"
            for rel, extras in extra_keys_per_file.items():
                issues.append({
                    "severity": "DRIFT",
                    "type": "extra_keys_in_env",
                    "file": rel,
                    "keys": extras,
                })
            # Orphans (keys in manifest but not in any env file) get a
            # secondary INFO-level note alongside the mismatch.
            orphans = sorted(set(manifest_keys) - union_env_keys)
            if orphans:
                issues.append({
                    "severity": "INFO",
                    "type": "manifest_orphan_keys",
                    "keys": orphans,
                })
        else:
            orphans = sorted(set(manifest_keys) - union_env_keys)
            if orphans and env_files:
                state = "MANIFEST_ORPHAN"
                severity = "INFO"
                issues.append({
                    "severity": "INFO",
                    "type": "manifest_orphan_keys",
                    "keys": orphans,
                })
            elif orphans and not env_files:
                # Manifest with keys, but no .env materialized — usually
                # fine (someone uses `bin/inject --env` on demand). INFO.
                state = "MANIFEST_ORPHAN"
                severity = "INFO"
                issues.append({
                    "severity": "INFO",
                    "type": "manifest_orphan_keys",
                    "keys": orphans,
                })
            else:
                state = "CLEAN"

    # TRACKED_ENV(_HOT) bumps the severity and (if not already drift) the
    # state. We don't want it to mask a MANIFEST_MISMATCH, so keep the
    # primary state and add a tracked-env issue.
    if has_tracked:
        if has_tracked_hot:
            issues.append({
                "severity": "HIGH",
                "type": "tracked_env_hot",
                "files": [
                    {
                        "file": fr.rel_path,
                        "labels": sorted({lbl for _, lbl in fr.hot_keys}),
                        "keys": sorted({k for k, _ in fr.hot_keys}),
                    }
                    for fr in file_reports if fr.hot_keys
                ],
            })
            if state == "CLEAN":
                state = "TRACKED_ENV_HOT"
            severity = "DRIFT"
        else:
            issues.append({
                "severity": "DRIFT",
                "type": "tracked_env",
                "files": [fr.rel_path for fr in file_reports if fr.tracked],
            })
            if state == "CLEAN":
                state = "TRACKED_ENV"
            severity = "DRIFT"

    return ProjectReport(
        path=project_path,
        state=state,
        files=file_reports,
        manifest_keys=manifest_keys,
        issues=issues,
        severity=severity,
    )


def audit_roots(roots: Iterable[Path]) -> list[ProjectReport]:
    """Top-level entry point. Walk roots, group by project, classify each."""
    grouped: dict[Path, list[Path]] = {}
    seen_files: set[Path] = set()
    for root in roots:
        root = root.resolve()
        for ep in find_env_files(root):
            if ep in seen_files:
                continue
            seen_files.add(ep)
            proj = find_project_root(ep, root)
            grouped.setdefault(proj, []).append(ep)

    reports = [audit_project(proj, files) for proj, files in grouped.items()]
    reports.sort(key=lambda r: str(r.path))
    return reports


# ───────────────────────────────────────────────────────────────────────────
# Rendering
# ───────────────────────────────────────────────────────────────────────────


def _summary_counts(reports: list[ProjectReport]) -> dict:
    clean = sum(1 for r in reports if r.severity == "OK")
    info = sum(1 for r in reports if r.severity == "INFO")
    drift = sum(1 for r in reports if r.severity == "DRIFT")
    tracked_hot = sum(
        1 for r in reports
        for iss in r.issues
        if iss.get("type") == "tracked_env_hot"
    )
    return {
        "total": len(reports),
        "clean": clean,
        "info": info,
        "drift": drift,
        "tracked_hot": tracked_hot,
    }


def render_human(
    reports: list[ProjectReport],
    *,
    roots: list[Path],
    quiet: bool,
) -> str:
    counts = _summary_counts(reports)
    lines: list[str] = []
    lines.append("cush-audit summary")
    n_roots = len(roots)
    root_word = "root" if n_roots == 1 else "roots"
    lines.append(
        f"  scanned: {counts['total']} project(s) under {n_roots} {root_word}"
    )
    lines.append(f"  clean:   {counts['clean']}")
    if counts["info"]:
        lines.append(f"  info:    {counts['info']}")
    lines.append(f"  drift:   {counts['drift']}")
    if counts["tracked_hot"]:
        lines.append(f"  tracked-hot: {counts['tracked_hot']}")
    lines.append("")

    drift_reports = [r for r in reports if r.severity == "DRIFT"]
    info_reports = [r for r in reports if r.severity == "INFO"]
    clean_reports = [r for r in reports if r.severity == "OK"]

    if drift_reports:
        lines.append("Drift detected:")
        lines.append("")
        for r in drift_reports:
            lines.extend(_render_project_human(r))
            lines.append("")
    else:
        lines.append("No drift detected.")
        lines.append("")

    if info_reports and not quiet:
        lines.append("Informational:")
        lines.append("")
        for r in info_reports:
            lines.extend(_render_project_human(r))
            lines.append("")

    if clean_reports and not quiet:
        lines.append("Clean projects:")
        for r in clean_reports:
            lines.append(f"  [CLEAN] {r.path}")
        lines.append("")

    lines.append("Run `bin/cush-audit --format json` for machine output.")
    return "\n".join(lines).rstrip() + "\n"


def _render_project_human(r: ProjectReport) -> list[str]:
    out: list[str] = []
    out.append(f"[{r.state}] {r.path}")
    if r.state == "MISSING_MANIFEST":
        for fr in r.files:
            out.append(f"  {fr.rel_path} ({len(fr.keys)} secret(s))  → no .cush-secrets in this project")
        out.append(f"  fix: cd {r.path} && bin/cush-init && bin/stash")
    elif r.state == "MANIFEST_MISMATCH":
        for iss in r.issues:
            if iss.get("type") == "extra_keys_in_env":
                out.append(f"  {iss['file']} has keys not in .cush-secrets:")
                for k in iss["keys"]:
                    out.append(f"    {k}")
            elif iss.get("type") == "manifest_orphan_keys":
                out.append("  manifest has keys not in any .env:")
                for k in iss["keys"]:
                    out.append(f"    {k}")
        out.append("  fix: bin/stash --in <env-file> (will merge into existing manifest)")
    elif r.state == "MANIFEST_ORPHAN":
        for iss in r.issues:
            if iss.get("type") == "manifest_orphan_keys":
                out.append("  manifest has keys not in any .env (might be intentional):")
                for k in iss["keys"]:
                    out.append(f"    {k}")
    elif r.state == "MANIFEST_INVALID":
        for iss in r.issues:
            if iss.get("type") == "manifest_invalid":
                out.append(f"  manifest invalid: {iss.get('error')}")
        out.append("  fix: edit .cush-secrets to repair the TOML, then re-run audit")
    elif r.state == "TRACKED_ENV":
        for iss in r.issues:
            if iss.get("type") == "tracked_env":
                for f in iss["files"]:
                    out.append(f"  {f} is git-tracked")
        out.append("  fix: git rm --cached <file> && bin/stash --in <file>")
    elif r.state == "TRACKED_ENV_HOT":
        for iss in r.issues:
            if iss.get("type") == "tracked_env_hot":
                for entry in iss["files"]:
                    labels = ", ".join(entry["labels"])
                    out.append(
                        f"  {entry['file']} is git-tracked AND contains values matching {labels}"
                    )
        out.append("  fix: ROTATE first (these are in git history), then bin/stash + git rm --cached")
    else:
        # Catch-all for unforeseen states.
        for iss in r.issues:
            out.append(f"  {iss.get('type')}: {iss}")

    # Surface secondary issues that weren't the primary state, e.g. an INFO
    # tracked_env attached to a DRIFT MANIFEST_MISMATCH.
    primary_types = {
        "MISSING_MANIFEST": {"missing_manifest"},
        "MANIFEST_MISMATCH": {"extra_keys_in_env", "manifest_orphan_keys"},
        "MANIFEST_ORPHAN": {"manifest_orphan_keys"},
        "MANIFEST_INVALID": {"manifest_invalid"},
        "TRACKED_ENV": {"tracked_env"},
        "TRACKED_ENV_HOT": {"tracked_env_hot"},
        "CLEAN": set(),
    }.get(r.state, set())
    for iss in r.issues:
        if iss.get("type") in primary_types:
            continue
        if iss.get("type") == "tracked_env":
            for f in iss["files"]:
                out.append(f"  also: {f} is git-tracked")
        elif iss.get("type") == "tracked_env_hot":
            for entry in iss["files"]:
                labels = ", ".join(entry["labels"])
                out.append(
                    f"  also: {entry['file']} git-tracked AND matches {labels} (ROTATE!)"
                )
    return out


def render_json(
    reports: list[ProjectReport],
    *,
    roots: list[Path],
) -> str:
    counts = _summary_counts(reports)
    payload = {
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "roots": [str(r) for r in roots],
        "projects": [
            {
                "path": str(r.path),
                "state": r.state,
                "severity": r.severity,
                "files": [
                    {
                        "path": fr.rel_path,
                        "tracked": fr.tracked,
                        "key_count": len(fr.keys),
                        "hot_labels": sorted({lbl for _, lbl in fr.hot_keys}),
                        "parse_error": fr.parse_error,
                    }
                    for fr in r.files
                ],
                "issues": r.issues,
            }
            for r in reports
        ],
        "summary": {
            "scanned": counts["total"],
            "clean": counts["clean"],
            "info": counts["info"],
            "drift": counts["drift"],
            "tracked_hot": counts["tracked_hot"],
        },
    }
    return json.dumps(payload, indent=2, sort_keys=False) + "\n"


# ───────────────────────────────────────────────────────────────────────────
# CLI
# ───────────────────────────────────────────────────────────────────────────


def main(argv: Optional[list[str]] = None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        prog="cush-audit",
        description=(
            "Re-scan one or more roots for .env-style files and report drift "
            "against each project's `.cush-secrets` manifest."
        ),
    )
    p.add_argument("--root", action="append", default=[], help="Directory to scan (repeatable). Default: ~/local/src")
    p.add_argument("--format", choices=("human", "json"), default="human", help="Output format.")
    p.add_argument("--strict", action="store_true", help="Exit non-zero if any drift detected.")
    p.add_argument("--quiet", action="store_true", help="Suppress projects with no issues.")
    args = p.parse_args(argv)

    if not args.root:
        default_root = Path.home() / "local" / "src"
        roots = [default_root]
    else:
        roots = [Path(r) for r in args.root]

    bad_roots = [r for r in roots if not r.exists()]
    if bad_roots:
        for r in bad_roots:
            print(f"cush-audit: root does not exist: {r}", file=sys.stderr)
        return 2

    try:
        reports = audit_roots(roots)
    except Exception as e:
        print(f"cush-audit: scan failure: {e}", file=sys.stderr)
        return 2

    if args.quiet and args.format == "json":
        # Filter out CLEAN projects in JSON-quiet mode too.
        reports_for_render = [r for r in reports if r.severity != "OK"]
    else:
        reports_for_render = reports

    if args.format == "human":
        sys.stdout.write(render_human(reports_for_render, roots=roots, quiet=args.quiet))
    else:
        sys.stdout.write(render_json(reports_for_render, roots=roots))

    if args.strict and any(r.severity == "DRIFT" for r in reports):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

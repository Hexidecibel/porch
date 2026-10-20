#!/usr/bin/env python3
"""Stash orchestrator — `bin/stash` delegates here.

Migrate an existing `.env` file into 1Password and emit a `.cush-secrets`
manifest pointing at the newly-created refs. Intended workflow:

    cd /path/to/myapp
    bin/stash         # interactively walks ./.env line by line, writes to op,
                      # emits ./.cush-secrets, leaves .env on disk + gitignored.
    bin/inject        # phase 2: re-renders ./.env from the manifest.

This module is invokable two ways:
  - As an importable function (cmd_stash) called by tests.
  - As `python3 lib/stash.py ...` — but `bin/stash` is the supported CLI.

A small `--self-test` mode exercises the parse + emit flow with a mocked
op layer (no real op calls).

Exit codes (mirroring bin/stash):
  0  ok
  2  arg error
  3  op auth (op not installed / token missing)
  4  op vault inaccessible / write failed / aborted by user on op error
  5  user aborted (Ctrl-C, n on overall confirmation, etc.)
  7  manifest write failed
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
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
from manifest import Manifest, SecretSpec, ManifestError

# Lazy-imported on use to keep --self-test free of cush_secrets.py overhead.
# stash is op-specific by design (it migrates `.env` -> 1Password and emits
# op:// refs in the manifest output), but it goes through the cush_secrets
# dispatch layer so the exception names + auth probe stay aligned with the
# rest of the codebase.
_secrets = None


def _load_secrets():
    global _secrets
    if _secrets is None:
        import cush_secrets as cs  # noqa: WPS433
        _secrets = cs
    return _secrets


# ───────────────────────────────────────────────────────────────────────────
# Public API
# ───────────────────────────────────────────────────────────────────────────


@dataclass
class StashOptions:
    in_path: Path
    out_path: Path
    vault: str
    item_template: str = "{project}"
    project_name: str = ""
    dry_run: bool = False
    yes: bool = False
    # post_action ∈ {"gitignore-env", "delete-env", "keep-env"}
    post_action: str = "gitignore-env"


@dataclass
class ParsedLine:
    """One non-blank, non-comment line from a dotenv file."""
    env_name: str
    value: str
    comment: Optional[str]
    line_number: int


# ───────────────────────────────────────────────────────────────────────────
# Dotenv parser (hand-rolled — stdlib only)
# ───────────────────────────────────────────────────────────────────────────


# Match: optional leading `export `, then KEY, then `=`, then the rest.
# Key chars: letters, digits, underscore (env-var convention).
_ENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")


def _strip_inline_comment(rest: str) -> tuple[str, Optional[str]]:
    """Split an *unquoted* RHS into (value, comment).

    Inline comments only apply to unquoted values — `KEY="a # b"` keeps the
    `#` as part of the value. Caller is responsible for not invoking this
    on a quoted RHS.
    """
    # Find the first ' #' (space + hash) or leading '#' boundary.
    # Use a simple state machine: walk chars, return on first '#' that's
    # preceded by whitespace or is at column 0 of `rest`.
    for i, ch in enumerate(rest):
        if ch == "#" and (i == 0 or rest[i - 1].isspace()):
            value = rest[:i].rstrip()
            comment = rest[i + 1:].strip() or None
            return value, comment
    return rest.rstrip(), None


def _dedup_last_wins(parsed: list["ParsedLine"]) -> list["ParsedLine"]:
    """Remove duplicate env_names from a parsed dotenv list, last-write-wins.

    When the same env_name appears multiple times, only the LAST occurrence
    is kept (matching shell `source` semantics: the later assignment shadows
    the earlier one). The position of each kept entry is the position of its
    LAST occurrence in the input — so the output preserves the order in
    which the *final* values were declared.

    Emits a stderr warning per duplicated key, listing all line numbers
    where the key appeared.

    This must run BEFORE the upsert loop so we don't waste op calls on
    values that are about to be overwritten anyway, and BEFORE manifest
    emission so the on-disk TOML has exactly one entry per env_name (the
    fix for the duplicate-TOML-key bug that broke `bin/inject`).
    """
    # Group line numbers by env_name in order of appearance.
    occurrences: dict[str, list[int]] = {}
    for pl in parsed:
        occurrences.setdefault(pl.env_name, []).append(pl.line_number)

    # Warn about every key that appears more than once.
    for name, lines in occurrences.items():
        if len(lines) > 1:
            if len(lines) == 2:
                lines_str = f"lines {lines[0]} and {lines[1]}"
            else:
                lines_str = "lines " + ", ".join(str(n) for n in lines[:-1]) + f" and {lines[-1]}"
            print(
                f"stash: warning: {name!r} defined "
                f"{'twice' if len(lines) == 2 else f'{len(lines)} times'} "
                f"in .env ({lines_str}) — last value wins",
                file=sys.stderr,
            )

    # Walk in reverse, keeping only the first time we see each name (which
    # is the LAST occurrence in original order). Then reverse back.
    seen: set[str] = set()
    kept_reversed: list[ParsedLine] = []
    for pl in reversed(parsed):
        if pl.env_name in seen:
            continue
        seen.add(pl.env_name)
        kept_reversed.append(pl)
    return list(reversed(kept_reversed))


def parse_dotenv(text: str) -> list[ParsedLine]:
    """Parse a dotenv string into [ParsedLine, ...].

    Handles:
      - `KEY=value`
      - `KEY="quoted value"` and `KEY='quoted value'` (preserves interior whitespace)
      - `export KEY=value` (strips the `export ` prefix)
      - `# comment lines` (skipped)
      - inline `# comment` after an unquoted value (preserved as ParsedLine.comment)
      - blank lines (skipped)

    Lines that don't match any pattern are warned about on stderr and skipped.
    """
    out: list[ParsedLine] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        m = _ENV_LINE_RE.match(raw)
        if not m:
            print(
                f"[stash] skipping unparseable line {lineno}: {raw!r}",
                file=sys.stderr,
            )
            continue
        env_name = m.group(1)
        rest = m.group(2)

        # Trim leading whitespace on the RHS only — preserve trailing for
        # quoted strings.
        rest = rest.lstrip()

        comment: Optional[str] = None
        # Quoted forms: keep the interior verbatim, then look for a comment
        # AFTER the closing quote.
        if rest.startswith('"') or rest.startswith("'"):
            quote = rest[0]
            # Find the matching closing quote. Dotenv typically doesn't
            # support backslash-escaped quotes inside; we mirror that.
            end = rest.find(quote, 1)
            if end == -1:
                print(
                    f"[stash] skipping line {lineno} with unterminated quote: {raw!r}",
                    file=sys.stderr,
                )
                continue
            value = rest[1:end]
            after = rest[end + 1:]
            # Optional trailing comment: must be whitespace + '#'.
            after_stripped = after.strip()
            if after_stripped:
                if after_stripped.startswith("#"):
                    comment = after_stripped[1:].strip() or None
                else:
                    # Junk after closing quote — warn but keep the value.
                    print(
                        f"[stash] line {lineno}: ignoring junk after quoted value: "
                        f"{after_stripped!r}",
                        file=sys.stderr,
                    )
        else:
            value, comment = _strip_inline_comment(rest)

        out.append(ParsedLine(
            env_name=env_name,
            value=value,
            comment=comment,
            line_number=lineno,
        ))
    return out


# ───────────────────────────────────────────────────────────────────────────
# Ref + value display helpers
# ───────────────────────────────────────────────────────────────────────────


def _truncate_value(value: str, *, limit: int = 60) -> str:
    """Single-line, length-capped representation of a value for display.

    Newlines are escaped so multi-line values don't visually break the prompt.
    """
    flat = value.replace("\n", "\\n")
    if len(flat) <= limit:
        return flat
    head_len = max(6, limit // 2 - 2)
    tail_len = max(6, limit - head_len - 3)
    return f"{flat[:head_len]}...{flat[-tail_len:]}"


# 1Password fields are case-insensitive in practice, and lowercase reads
# better in `op://...` URIs (which appear verbatim in the manifest the user
# will commit). We lowercase the env_name to derive the field; users who want
# to preserve case can re-key via the `e=edit` prompt or hand-edit the
# manifest afterwards.
def compute_default_ref(env_name: str, vault: str, item_template: str, project_name: str) -> str:
    item = item_template.format(project=project_name, key=env_name.lower())
    field_name = env_name.lower()
    return f"op://{vault}/{item}/{field_name}"


_OP_REF_RE = re.compile(r"^op://([^/]+)/([^/]+)/(.+)$")


def _is_valid_op_ref(s: str) -> bool:
    if not s.startswith("op://"):
        return False
    return bool(_OP_REF_RE.match(s))


# ───────────────────────────────────────────────────────────────────────────
# Interactive prompt loop
# ───────────────────────────────────────────────────────────────────────────


def _prompt(msg: str) -> str:
    """input() wrapper that surfaces EOF/Ctrl-D as KeyboardInterrupt-style abort."""
    try:
        return input(msg)
    except EOFError:
        raise KeyboardInterrupt()


def _prompt_for_line(
    pl: ParsedLine,
    default_ref: str,
    *,
    index: int,
    total: int,
) -> tuple[str, str]:
    """Prompt the user about one line. Return ('proceed'|'skip', final_ref).

    Choices:
      Y (default on Enter): proceed with this ref
      n: skip this line (caller drops it)
      e: edit ref; re-prompt with the new ref
      s: print full value, re-prompt without 's'
    """
    ref = default_ref
    show_full = False  # latched once `s` is pressed; affects display only
    s_available = True

    while True:
        # Header lines.
        sys.stderr.write(f"\n[{index}/{total}] {pl.env_name}  → {ref}\n")
        if show_full:
            sys.stderr.write(f"       value: {pl.value} ({len(pl.value)} chars)\n")
        else:
            sys.stderr.write(
                f"       value: {_truncate_value(pl.value)} "
                f"({len(pl.value)} chars)\n"
            )
        if pl.comment:
            sys.stderr.write(f"       comment: {pl.comment}\n")

        choices = "[Y]es / [n]o-skip / [e]dit-ref"
        if s_available:
            choices += " / [s]how-value-then-ask"
        choices += " : "
        sys.stderr.flush()

        choice = _prompt(choices).strip().lower()
        if choice in ("", "y", "yes"):
            return "proceed", ref
        if choice in ("n", "no", "skip"):
            return "skip", ref
        if choice in ("s", "show") and s_available:
            show_full = True
            s_available = False
            continue
        if choice in ("e", "edit"):
            while True:
                new = _prompt(f"Enter ref [{ref}]: ").strip()
                if not new:
                    break  # keep current ref
                if _is_valid_op_ref(new):
                    ref = new
                    break
                sys.stderr.write(
                    f"  not a valid op:// ref ({new!r}); expected op://Vault/Item/field\n"
                )
            continue
        sys.stderr.write(f"  unrecognized choice: {choice!r}\n")


def _prompt_on_error(env_name: str, ref: str, err_msg: str) -> str:
    """On a generic op error for a single item, ask retry/skip/abort.

    Returns 'retry' | 'skip' | 'abort'. Default (Enter) is retry.
    """
    sys.stderr.write(
        f"\n[stash] op error on {env_name} → {ref}:\n"
        f"  {err_msg}\n"
        f"  [R]etry / [s]kip / [a]bort : "
    )
    sys.stderr.flush()
    choice = _prompt("").strip().lower()
    if choice in ("", "r", "retry"):
        return "retry"
    if choice in ("s", "skip"):
        return "skip"
    if choice in ("a", "abort"):
        return "abort"
    return "retry"


# ───────────────────────────────────────────────────────────────────────────
# Manifest emit (with merge-on-existing)
# ───────────────────────────────────────────────────────────────────────────


_PROD_INPUT_HINTS = (".env.production", ".env.prod", ".env.staging")


def _looks_like_prod_input(in_path: Path) -> bool:
    """True if the input filename matches a non-dev environment hint."""
    name = in_path.name
    return any(name == hint or name.endswith(hint) for hint in _PROD_INPUT_HINTS)


def _maybe_merge(
    out_path: Path,
    new_secrets: list,
    *,
    yes: bool,
    incoming_item_template: str = "",
    in_path: Optional[Path] = None,
) -> tuple[list, dict]:
    """If out_path exists, prompt merge/overwrite/abort. Returns (final_specs, defaults_to_use_if_unchanged).

    On `merge`: existing entries with the same env_name are replaced
    last-write-wins; entries that aren't in the new set are preserved.
    On `overwrite`: new_secrets wins entirely.
    On `abort`: raises KeyboardInterrupt.

    Returns a tuple (specs, existing_defaults_or_None). Caller decides whether
    to use the existing manifest's defaults or the freshly-computed ones.

    If the incoming run's `item-template` differs from the existing manifest's
    `defaults.target_item` AND any incoming env_names overlap with existing
    entries, emit a clear stderr warning suggesting a separate manifest. The
    classic trap: dev was stashed to `.cush-secrets` with `{project}`, then
    prod is stashed to the same `.cush-secrets` with `{project}-prod`, and
    every overlapping key gets silently overwritten with prod refs.
    """
    if not out_path.exists():
        return new_secrets, {}

    if yes:
        # Non-interactive: default to merge (the safest preserving option).
        choice = "m"
    else:
        sys.stderr.write(
            f"\n[stash] {out_path} already exists.\n"
            "  [M]erge with existing / [o]verwrite / [a]bort : "
        )
        sys.stderr.flush()
        raw = _prompt("").strip().lower()
        choice = raw[:1] if raw else "m"

    if choice == "a":
        raise KeyboardInterrupt()
    if choice == "o":
        return new_secrets, {}

    # Merge.
    try:
        existing = manifest_mod.load(out_path)
    except ManifestError as e:
        sys.stderr.write(
            f"[stash] cannot parse existing manifest, falling back to overwrite: {e}\n"
        )
        return new_secrets, {}

    by_name = {s.env_name: s for s in existing.secrets}

    # ── Dev/prod overwrite-trap detection ────────────────────────────────
    # If the new run's item-template differs from the existing manifest's
    # defaults.target_item AND any incoming env_names collide with existing
    # ones, the merge will silently rewrite those refs — typically clobbering
    # dev refs with prod refs (or vice versa). Warn loudly. Don't abort: the
    # user might genuinely want the overwrite.
    existing_template = (existing.defaults or {}).get("target_item", "") or ""
    incoming_names = {s.env_name for s in new_secrets}
    overlapping = sorted(incoming_names & set(by_name.keys()))
    if (
        incoming_item_template
        and existing_template
        and incoming_item_template != existing_template
        and overlapping
    ):
        suggested_out = out_path
        # Heuristic: when stashing from a non-dev source file, suggest a
        # parallel manifest sibling like `.cush-secrets.prod`.
        if in_path is not None and _looks_like_prod_input(in_path):
            # Pick the suffix from the input file (.production → .prod is
            # too cute; just reuse the simplest discriminator).
            if in_path.name.endswith(".env.production") or in_path.name == ".env.production":
                suggested_out = out_path.with_name(out_path.name + ".prod")
            elif in_path.name.endswith(".env.prod") or in_path.name == ".env.prod":
                suggested_out = out_path.with_name(out_path.name + ".prod")
            elif in_path.name.endswith(".env.staging") or in_path.name == ".env.staging":
                suggested_out = out_path.with_name(out_path.name + ".staging")

        preview = ", ".join(overlapping[:5])
        if len(overlapping) > 5:
            preview += f", … (+{len(overlapping) - 5} more)"
        sys.stderr.write(
            "\n*** stash: WARNING — incoming entries (item-template "
            f"{incoming_item_template!r}) would overwrite existing\n"
            f"    refs in {str(out_path)!r} (item-template {existing_template!r}).\n"
            f"    Overlapping keys: {preview}\n"
            f"    Suggested: use --out {suggested_out.name} to keep dev and "
            "prod manifests separate.\n"
            "    Continuing with merge as requested. ***\n\n"
        )
        sys.stderr.flush()

    for spec in new_secrets:
        if spec.env_name in by_name:
            sys.stderr.write(
                f"[stash] replacing existing entry: {spec.env_name}\n"
            )
        by_name[spec.env_name] = spec
    # Preserve manifest order: existing entries first (in their original
    # order), then any newly-added ones (in stash order).
    merged = []
    seen = set()
    for s in existing.secrets:
        merged.append(by_name[s.env_name])
        seen.add(s.env_name)
    for s in new_secrets:
        if s.env_name not in seen:
            merged.append(s)
            seen.add(s.env_name)
    return merged, dict(existing.defaults)


def _atomic_dump(manifest: Manifest, out_path: Path) -> None:
    """Write the manifest via temp-file + rename, atomic on POSIX."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Sibling temp file (same directory => same filesystem => atomic rename).
    tmp = out_path.with_name(out_path.name + ".tmp")
    manifest_mod.dump(manifest, tmp)
    os.rename(tmp, out_path)


# ───────────────────────────────────────────────────────────────────────────
# Post-action handlers (.gitignore / delete / keep)
# ───────────────────────────────────────────────────────────────────────────


def _is_git_tracked(path: Path) -> bool:
    if not shutil.which("git"):
        return False
    try:
        proc = subprocess.run(
            ["git", "ls-files", "--error-unmatch", str(path)],
            capture_output=True,
            text=True,
            cwd=path.parent if path.parent.exists() else Path.cwd(),
            timeout=5,
        )
        return proc.returncode == 0
    except Exception:
        return False


def _ensure_gitignore_entry(env_path: Path) -> None:
    """Append `<basename>` to env_path.parent/.gitignore if not already there.

    Idempotent — matches exact basename only (e.g. `.env`, `./.env`, `/.env`).
    Doesn't match wildcards like `.env*`.
    """
    target_dir = env_path.parent if env_path.parent != Path() else Path.cwd()
    target_dir.mkdir(parents=True, exist_ok=True)
    gi = target_dir / ".gitignore"
    base = env_path.name
    existing = ""
    if gi.exists():
        existing = gi.read_text()
        for line in existing.splitlines():
            stripped = line.strip()
            if stripped == base or stripped == f"./{base}" or stripped == f"/{base}":
                return
    suffix = "" if existing.endswith("\n") or existing == "" else "\n"
    with open(gi, "a") as f:
        f.write(f"{suffix}{base}\n")


def _do_post_action(opts: StashOptions, *, fp=sys.stderr) -> str:
    """Run the configured post-action. Returns a human-readable summary.

    `delete-env` falls through to `gitignore-env` semantics if the user
    declines confirmation.
    """
    action = opts.post_action
    in_path = opts.in_path

    if action == "keep-env":
        return "keep-env (.env left untouched)"

    if action == "delete-env":
        if not in_path.exists():
            return "delete-env (no source file to delete)"
        do_delete = opts.yes
        if not do_delete:
            sys.stderr.write(f"\n[stash] Confirm delete {in_path}? [y/N]: ")
            sys.stderr.flush()
            ans = _prompt("").strip().lower()
            do_delete = ans in ("y", "yes")
        if do_delete:
            try:
                os.unlink(in_path)
                return f"delete-env ({in_path} removed)"
            except OSError as e:
                print(f"[stash] failed to delete {in_path}: {e}", file=fp)
                # Fall through to gitignore behavior.
                action = "gitignore-env"
        else:
            print("[stash] delete declined; falling back to gitignore-env", file=fp)
            action = "gitignore-env"

    # action == "gitignore-env"
    _ensure_gitignore_entry(in_path)
    note = "appended to .gitignore"
    if _is_git_tracked(in_path):
        sys.stderr.write(
            f"\n*** WARNING: {in_path} is currently tracked by git.\n"
            f"    Run `git rm --cached {in_path.name}` and commit to stop "
            f"tracking the now-secret file. ***\n\n"
        )
        note += " (warning: still git-tracked)"
    return f"gitignore-env ({in_path} still on disk; {note})"


# ───────────────────────────────────────────────────────────────────────────
# Main command
# ───────────────────────────────────────────────────────────────────────────


def cmd_stash(opts: StashOptions) -> int:
    fp = sys.stderr  # All status output goes to stderr.

    # Read source.
    if not opts.in_path.exists():
        print(f"[stash] source not found: {opts.in_path}", file=fp)
        return 2
    try:
        text = opts.in_path.read_text()
    except OSError as e:
        print(f"[stash] failed to read {opts.in_path}: {e}", file=fp)
        return 2

    parsed = parse_dotenv(text)
    if not parsed:
        print(f"[stash] {opts.in_path}: no parseable entries", file=fp)
        return 2

    # Deduplicate before any op calls or manifest emission. If the source
    # .env has the same key declared more than once, last-write-wins (mirrors
    # `source .env` shell semantics). Without this, the manifest would
    # contain duplicate TOML keys — invalid TOML, and `bin/inject` would
    # fail to parse it.
    parsed = _dedup_last_wins(parsed)

    # Defensive op-auth probe. The bash wrapper sources op.sh (and now
    # infisical.sh) but no longer runs cush_op_check pre-flight — Python
    # owns the auth check now, per-scheme. stash is op-specific, so we
    # probe the 'op' backend directly.
    #
    # Workaround note (kept from phase 1.5): the underlying `op_whoami()`
    # in lib/op.py used to false-negative on Mode 2 if
    # OP_SERVICE_ACCOUNT_TOKEN wasn't set. The current op.py is auth-mode-
    # agnostic, but the fallback op_read probe is cheap insurance.
    if not opts.dry_run:
        secrets_mod = _load_secrets()
        try:
            who = secrets_mod.whoami_for_scheme("op")
            if who is None:
                # Fall back to a direct read probe so we get a real
                # classifying error instead of a false negative.
                try:
                    secrets_mod.read("op://")
                    # Should never succeed, but if it does, auth must be ok.
                except secrets_mod.SecretsAuthError as e:
                    print(f"[stash] op auth: {e}", file=fp)
                    return 3
                except secrets_mod.SecretsRefNotFound:
                    # "op://" isn't a valid ref but auth IS working — proceed.
                    pass
                except secrets_mod.SecretsError:
                    # Ambiguous; treat as a non-auth failure and proceed.
                    pass
        except secrets_mod.SecretsAuthError as e:
            print(f"[stash] op auth: {e}", file=fp)
            return 3

    # Determine project name for {project} substitution.
    project_name = opts.project_name or opts.in_path.parent.resolve().name or "project"

    print(
        f"[stash] migrating {len(parsed)} entries from {opts.in_path} → "
        f"vault={opts.vault!r} item={opts.item_template!r} (project={project_name!r})"
        + (" [DRY RUN]" if opts.dry_run else ""),
        file=fp,
    )

    new_specs: list = []
    skipped: list[str] = []
    errors: list[tuple[str, str]] = []  # (env_name, message)

    for i, pl in enumerate(parsed, start=1):
        default_ref = compute_default_ref(
            pl.env_name, opts.vault, opts.item_template, project_name,
        )

        # Decide ref + go/skip.
        if opts.yes or opts.dry_run:
            decision, ref = "proceed", default_ref
            print(
                f"[{i}/{len(parsed)}] {pl.env_name}  → {ref}  "
                f"({len(pl.value)} chars)"
                + ("  [dry-run]" if opts.dry_run else ""),
                file=fp,
            )
        else:
            try:
                decision, ref = _prompt_for_line(
                    pl, default_ref, index=i, total=len(parsed),
                )
            except KeyboardInterrupt:
                print("\n[stash] aborted by user.", file=fp)
                return 5

        if decision == "skip":
            skipped.append(pl.env_name)
            print(f"[stash] skipped {pl.env_name}", file=fp)
            continue

        # Parse ref into (vault, item, field) for the SecretSpec sidecar.
        m = _OP_REF_RE.match(ref)
        if not m:
            # Shouldn't happen — _prompt_for_line validates — but defend.
            print(f"[stash] internal: invalid ref {ref!r}, skipping", file=fp)
            skipped.append(pl.env_name)
            continue
        ref_vault, ref_item, _ref_field = m.group(1), m.group(2), m.group(3)

        # Upsert (skip on dry-run).
        if not opts.dry_run:
            secrets_mod = _load_secrets()
            while True:
                try:
                    # cush_secrets.item_upsert takes the full ref string
                    # (rather than the (vault, item, field) tuple) and
                    # dispatches by scheme. stash always emits op:// refs,
                    # so this resolves to op_item_upsert under the hood.
                    secrets_mod.item_upsert(ref, pl.value, concealed=True)
                    print(f"[stash] stored {ref}", file=fp)
                    break
                except secrets_mod.SecretsRefNotFound as e:
                    # Shouldn't happen — upsert creates if missing — but if
                    # the backend surfaces this, surface and continue.
                    msg = str(e)
                    print(f"[stash] unexpected ref-not-found on upsert: {msg}", file=fp)
                    errors.append((pl.env_name, msg))
                    decision = "skip"
                    break
                except secrets_mod.SecretsAccessError as e:
                    print(
                        f"\n[stash] vault {opts.vault!r} is inaccessible: {e}\n"
                        f"  All subsequent items would fail too. Aborting.",
                        file=fp,
                    )
                    # Summary of what we already wrote.
                    print(f"[stash] wrote {len(new_specs)} item(s) before abort.", file=fp)
                    return 4
                except secrets_mod.SecretsAuthError as e:
                    print(f"\n[stash] op auth failure mid-run: {e}", file=fp)
                    return 3
                except secrets_mod.SecretsError as e:
                    if opts.yes:
                        # Non-interactive: log, mark error, continue.
                        msg = str(e)
                        print(f"[stash] op error on {pl.env_name}: {msg}", file=fp)
                        errors.append((pl.env_name, msg))
                        decision = "skip"
                        break
                    try:
                        choice = _prompt_on_error(pl.env_name, ref, str(e))
                    except KeyboardInterrupt:
                        print("\n[stash] aborted by user.", file=fp)
                        print(f"[stash] wrote {len(new_specs)} item(s) before abort.", file=fp)
                        return 5
                    if choice == "retry":
                        continue
                    if choice == "skip":
                        errors.append((pl.env_name, str(e)))
                        decision = "skip"
                        break
                    if choice == "abort":
                        print(f"[stash] aborting; {len(new_specs)} item(s) already written.", file=fp)
                        return 4

        if decision == "skip":
            # Error path inside the upsert loop fell through to skip.
            skipped.append(pl.env_name)
            continue

        # Append SecretSpec to manifest builder.
        new_specs.append(SecretSpec(
            env_name=pl.env_name,
            ref=ref,
            target_vault=ref_vault,
            target_item=ref_item,
            type="string",
            required=True,
        ))

    # Emit / merge the manifest.
    try:
        final_specs, existing_defaults = _maybe_merge(
            opts.out_path,
            new_specs,
            yes=opts.yes,
            incoming_item_template=opts.item_template,
            in_path=opts.in_path,
        )
    except KeyboardInterrupt:
        print("\n[stash] aborted at manifest-merge step.", file=fp)
        return 5

    defaults = existing_defaults or {
        "target_vault": opts.vault,
        "target_item": opts.item_template,
        "field_template": "{key}",
    }

    manifest_obj = Manifest(
        schema=1,
        defaults=defaults,
        secrets=final_specs,
        source_path=opts.out_path.resolve(),
    )

    try:
        _atomic_dump(manifest_obj, opts.out_path)
    except (OSError, ManifestError) as e:
        print(f"[stash] failed to write manifest {opts.out_path}: {e}", file=fp)
        return 7

    # Post-action.
    post_summary = _do_post_action(opts, fp=fp)

    # Summary.
    skipped_str = (
        f"{len(skipped)} ({', '.join(skipped)})" if skipped else "0"
    )
    print(
        f"\nstash complete:\n"
        f"  stored:   {len(new_specs)}\n"
        f"  skipped:  {skipped_str}\n"
        f"  errors:   {len(errors)}\n"
        f"  manifest: {opts.out_path}\n"
        f"  post:     {post_summary}",
        file=fp,
    )
    return 0


# ───────────────────────────────────────────────────────────────────────────
# Self-test (no real op calls)
# ───────────────────────────────────────────────────────────────────────────


def _self_test() -> int:
    """Smoke test the parse + stash flow with a mocked op layer."""
    import tempfile, types

    failures = 0

    sample = (
        "# leading comment\n"
        "DATABASE_URL=postgres://localhost/myapp_dev\n"
        "\n"
        "export STRIPE_KEY=\"sk_test_value with spaces\"\n"
        "API_TOKEN='single-quoted-value' # single-quoted, with comment\n"
        "PORT=3000  # default port\n"
        "MULTILINE_BAD=\n"
        "garbage line that doesn't match\n"
    )

    # 1. parse_dotenv basic checks.
    parsed = parse_dotenv(sample)
    names = [pl.env_name for pl in parsed]
    expected_names = ["DATABASE_URL", "STRIPE_KEY", "API_TOKEN", "PORT", "MULTILINE_BAD"]
    if names != expected_names:
        print(f"[stash self-test] parse names: {names} != {expected_names}", file=sys.stderr)
        failures += 1

    by_name = {pl.env_name: pl for pl in parsed}
    if by_name["STRIPE_KEY"].value != "sk_test_value with spaces":
        print(
            f"[stash self-test] STRIPE_KEY value wrong: {by_name['STRIPE_KEY'].value!r}",
            file=sys.stderr,
        )
        failures += 1
    if by_name["API_TOKEN"].value != "single-quoted-value":
        print(
            f"[stash self-test] API_TOKEN value wrong: {by_name['API_TOKEN'].value!r}",
            file=sys.stderr,
        )
        failures += 1
    if by_name["API_TOKEN"].comment != "single-quoted, with comment":
        print(
            f"[stash self-test] API_TOKEN comment wrong: {by_name['API_TOKEN'].comment!r}",
            file=sys.stderr,
        )
        failures += 1
    if by_name["PORT"].comment != "default port":
        print(
            f"[stash self-test] PORT comment wrong: {by_name['PORT'].comment!r}",
            file=sys.stderr,
        )
        failures += 1
    if by_name["PORT"].value != "3000":
        print(f"[stash self-test] PORT value wrong: {by_name['PORT'].value!r}", file=sys.stderr)
        failures += 1
    # MULTILINE_BAD has empty value — that's allowed.
    if by_name["MULTILINE_BAD"].value != "":
        print(
            f"[stash self-test] empty value lost: {by_name['MULTILINE_BAD'].value!r}",
            file=sys.stderr,
        )
        failures += 1

    # 2. Mocked secrets dispatch layer + cmd_stash with yes=True.
    upsert_calls: list[tuple] = []

    class FakeSecretsError(Exception): pass
    class FakeSecretsAuthError(FakeSecretsError): pass
    class FakeSecretsRefNotFound(FakeSecretsError): pass
    class FakeSecretsAccessError(FakeSecretsError): pass

    def fake_item_upsert(ref, value, *, concealed=True):
        # Parse the ref so the assertion side of the test can keep checking
        # (vault, item, field) the same way it always has.
        m = _OP_REF_RE.match(ref)
        if not m:
            raise FakeSecretsError(f"bad ref: {ref}")
        vault, item, field_ = m.group(1), m.group(2), m.group(3)
        upsert_calls.append((vault, item, field_, value, concealed))

    def fake_whoami_for_scheme(scheme):
        return {"scheme": scheme, "user": "test"}

    def fake_read(ref):
        raise FakeSecretsRefNotFound(f"not found: {ref}")

    fake_secrets = types.SimpleNamespace(
        item_upsert=fake_item_upsert,
        whoami_for_scheme=fake_whoami_for_scheme,
        read=fake_read,
        SecretsError=FakeSecretsError,
        SecretsAuthError=FakeSecretsAuthError,
        SecretsRefNotFound=FakeSecretsRefNotFound,
        SecretsAccessError=FakeSecretsAccessError,
    )
    global _secrets
    _secrets = fake_secrets

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        in_path = td / ".env"
        in_path.write_text(sample)
        out_path = td / ".cush-secrets"

        opts = StashOptions(
            in_path=in_path,
            out_path=out_path,
            vault="TestVault",
            item_template="{project}",
            project_name="myapp",
            dry_run=False,
            yes=True,
            post_action="gitignore-env",
        )
        rc = cmd_stash(opts)
        if rc != 0:
            print(f"[stash self-test] cmd_stash returned {rc}, expected 0", file=sys.stderr)
            failures += 1

        # Manifest emitted, parseable.
        if not out_path.exists():
            print(f"[stash self-test] manifest not written: {out_path}", file=sys.stderr)
            failures += 1
        else:
            try:
                m = manifest_mod.load(out_path)
            except ManifestError as e:
                print(f"[stash self-test] manifest reload failed: {e}", file=sys.stderr)
                failures += 1
                m = None
            if m is not None:
                got_names = {s.env_name for s in m.secrets}
                # All non-skipped lines should be in the manifest.
                expected = set(expected_names)  # all 5 parsed lines
                if got_names != expected:
                    print(
                        f"[stash self-test] manifest names: {got_names} != {expected}",
                        file=sys.stderr,
                    )
                    failures += 1
                # Refs follow op://TestVault/myapp/<lower>.
                for s in m.secrets:
                    expected_ref = f"op://TestVault/myapp/{s.env_name.lower()}"
                    if s.ref != expected_ref:
                        print(
                            f"[stash self-test] ref for {s.env_name}: "
                            f"{s.ref!r} != {expected_ref!r}",
                            file=sys.stderr,
                        )
                        failures += 1
                # Defaults preserved.
                if m.defaults.get("target_vault") != "TestVault":
                    print(
                        f"[stash self-test] defaults.target_vault: "
                        f"{m.defaults.get('target_vault')!r}",
                        file=sys.stderr,
                    )
                    failures += 1

        # Upsert call count == number of parsed lines (yes=True accepts all).
        if len(upsert_calls) != len(expected_names):
            print(
                f"[stash self-test] upsert calls: {len(upsert_calls)} != "
                f"{len(expected_names)}",
                file=sys.stderr,
            )
            failures += 1

        # gitignore should now contain `.env`.
        gi = td / ".gitignore"
        if not gi.exists() or ".env" not in gi.read_text():
            print(
                f"[stash self-test] .gitignore not updated: "
                f"{gi.read_text() if gi.exists() else '(missing)'}",
                file=sys.stderr,
            )
            failures += 1

        # Source .env still on disk (gitignore-env policy).
        if not in_path.exists():
            print(
                "[stash self-test] gitignore-env should leave .env in place, "
                "but it's missing",
                file=sys.stderr,
            )
            failures += 1

    # 3. Dry-run path: no upsert calls.
    upsert_calls.clear()
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        in_path = td / ".env"
        in_path.write_text("FOO=bar\nBAZ=qux\n")
        out_path = td / ".cush-secrets"

        opts = StashOptions(
            in_path=in_path,
            out_path=out_path,
            vault="V",
            item_template="{project}",
            project_name="proj",
            dry_run=True,
            yes=True,
            post_action="keep-env",
        )
        rc = cmd_stash(opts)
        if rc != 0:
            print(f"[stash self-test] dry-run returned {rc}, expected 0", file=sys.stderr)
            failures += 1
        if upsert_calls:
            print(
                f"[stash self-test] dry-run made upsert calls: {upsert_calls}",
                file=sys.stderr,
            )
            failures += 1
        # Manifest still emitted.
        if not out_path.exists():
            print("[stash self-test] dry-run did not emit manifest", file=sys.stderr)
            failures += 1
        else:
            m = manifest_mod.load(out_path)
            if {s.env_name for s in m.secrets} != {"FOO", "BAZ"}:
                print(
                    f"[stash self-test] dry-run manifest mismatch: "
                    f"{[s.env_name for s in m.secrets]}",
                    file=sys.stderr,
                )
                failures += 1

    # 4. Merge path: out_path already exists with one entry not in new run.
    upsert_calls.clear()
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        in_path = td / ".env"
        in_path.write_text("NEW_KEY=v1\n")
        out_path = td / ".cush-secrets"
        # Pre-populate manifest with OLD_KEY.
        out_path.write_text(
            'schema = 1\n'
            '[defaults]\ntarget_vault = "V"\ntarget_item = "{project}"\n'
            'field_template = "{key}"\n\n'
            '[secrets]\nOLD_KEY = "op://V/proj/old_key"\n'
        )
        opts = StashOptions(
            in_path=in_path, out_path=out_path,
            vault="V", item_template="{project}", project_name="proj",
            dry_run=True, yes=True, post_action="keep-env",
        )
        rc = cmd_stash(opts)
        if rc != 0:
            print(f"[stash self-test] merge run returned {rc}", file=sys.stderr)
            failures += 1
        m = manifest_mod.load(out_path)
        names = {s.env_name for s in m.secrets}
        if names != {"OLD_KEY", "NEW_KEY"}:
            print(f"[stash self-test] merge result: {names} != {{OLD_KEY, NEW_KEY}}",
                  file=sys.stderr)
            failures += 1

    if failures:
        print(f"[stash self-test] {failures} failure(s)", file=sys.stderr)
        return 1
    print("[stash self-test] ok")
    return 0


# ───────────────────────────────────────────────────────────────────────────
# CLI entry (called by bin/stash)
# ───────────────────────────────────────────────────────────────────────────


def _build_argparser():
    p = argparse.ArgumentParser(
        prog="stash",
        description="Migrate a .env into 1Password and emit a .cush-secrets manifest.",
    )
    p.add_argument("--in", dest="in_path", default=".env",
                   help="Source .env (default: ./.env).")
    p.add_argument("--out", dest="out_path", default=".cush-secrets",
                   help="Destination manifest (default: ./.cush-secrets).")
    p.add_argument("--vault", default="cush",
                   help="Default vault for new items (default: cush).")
    p.add_argument("--item-template", default="{project}",
                   help="Item name template; {project} is substituted (default: {project}).")
    p.add_argument("--project-name", default="",
                   help="Override {project} substitution (default: basename of in_path's parent).")
    p.add_argument("--dry-run", action="store_true",
                   help="Show what would be created; do not call op.")
    p.add_argument("--yes", action="store_true",
                   help="Non-interactive: accept all defaults, no prompts.")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--gitignore-env", dest="post_action", action="store_const",
                   const="gitignore-env",
                   help="(default) append .env to .gitignore, leave file in place.")
    g.add_argument("--keep-env", dest="post_action", action="store_const",
                   const="keep-env",
                   help="Leave .env entirely alone (no gitignore touch).")
    g.add_argument("--delete-env", dest="post_action", action="store_const",
                   const="delete-env",
                   help="rm .env after success (with confirmation unless --yes).")
    p.set_defaults(post_action="gitignore-env")
    p.add_argument("--self-test", action="store_true",
                   help="Run an in-process smoke test with mocked op.")
    return p


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    args = _build_argparser().parse_args(argv)

    if args.self_test:
        return _self_test()

    in_path = Path(args.in_path).resolve()
    out_path = Path(args.out_path).resolve()

    project_name = args.project_name or in_path.parent.name or "project"

    opts = StashOptions(
        in_path=in_path,
        out_path=out_path,
        vault=args.vault,
        item_template=args.item_template,
        project_name=project_name,
        dry_run=args.dry_run,
        yes=args.yes,
        post_action=args.post_action,
    )

    try:
        return cmd_stash(opts)
    except KeyboardInterrupt:
        print("\n[stash] aborted by user.", file=sys.stderr)
        return 5


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Dispatch layer over the 1Password (`op`) and Infisical (`inf`) backends.

Exposes a unified API keyed by ref scheme:

    op://Vault/Item/field      -> handled by lib/op.py
    inf://<env>/<path>/<KEY>   -> handled by lib/infisical.py

Naming note: this module is `cush_secrets` rather than the more obvious
`secrets` because Python's stdlib already ships a `secrets` module
(`secrets.token_bytes(...)` etc.) that `lib/authserver.py` depends on. With
`lib/` on sys.path, a local `lib/secrets.py` would shadow the stdlib and
break authserver. The `cush_secrets` rename preserves the stdlib import
chain while still providing a single dispatch entrypoint for Porch's
secret backends.

Public API:
  parse_ref(ref)              -> ('op', vault, item, field) | ('inf', env, path, key)
  read(ref)                   -> str
  item_upsert(ref, value, *, concealed=True) -> None
  inject_template(template)   -> str
  whoami_for_scheme(scheme)   -> dict | None
  schemes_in_manifest(refs)   -> set[str]

Exception hierarchy (re-exported as a single set of names for call sites):
  SecretsError
  ├── SecretsAuthError       (op missing, auth failed, etc.)
  ├── SecretsRefNotFound     (item or field doesn't exist)
  └── SecretsAccessError     (permission denied for vault/project/path)

Backend-specific exception classes (op.OpError, infisical.InfError, …)
inherit from these via multiple inheritance, so existing call sites that
catch backend-named exceptions keep working.
"""

from __future__ import annotations

import re
import sys
from typing import Optional


# ───────────────────────────────────────────────────────────────────────────
# Generic exception hierarchy
# ───────────────────────────────────────────────────────────────────────────


class SecretsError(Exception):
    """Generic secret-backend failure."""


class SecretsAuthError(SecretsError):
    """Backend CLI missing, credentials missing, or whoami failed."""


class SecretsRefNotFound(SecretsError):
    """Reference does not resolve (item/key missing)."""


class SecretsAccessError(SecretsError):
    """Token/credentials lack access to the requested vault/project."""


# ───────────────────────────────────────────────────────────────────────────
# Lazy backend loaders. Importing op or infisical at module load time would
# trigger a cycle (infisical.py imports cush_secrets to derive its base
# classes). Each call site below imports lazily; the imports are cached by
# Python after the first hit.
# ───────────────────────────────────────────────────────────────────────────


def _load_op():
    import op  # type: ignore  # noqa: WPS433
    return op


def _load_inf():
    import infisical  # type: ignore  # noqa: WPS433
    return infisical


# ───────────────────────────────────────────────────────────────────────────
# Ref parsing
# ───────────────────────────────────────────────────────────────────────────


_SCHEME_RE = re.compile(r"^([a-z][a-z0-9+.\-]*)://")

# Pattern matching either op or inf placeholders inside a template.
# Whitespace around the ref is tolerated, mirroring `op inject`.
_TEMPLATE_PLACEHOLDER_RE = re.compile(
    r"\{\{\s*((?:op|inf)://[^\s}]+)\s*\}\}"
)


def parse_ref(ref: str) -> tuple[str, ...]:
    """Return a scheme-prefixed tuple describing `ref`.

    Returns:
      ('op',  vault, item, field)        for op://Vault/Item/field
      ('inf', env,   path,  key)         for inf://<env>/<path>/<KEY>

    Raises ValueError on malformed input or an unknown scheme.
    """
    if not isinstance(ref, str) or not ref:
        raise ValueError(f"not a valid ref: {ref!r}")
    m = _SCHEME_RE.match(ref)
    if not m:
        raise ValueError(f"ref has no scheme: {ref!r}")
    scheme = m.group(1)
    if scheme == "op":
        op = _load_op()
        vault, item, field = op.parse_op_ref(ref)
        return ("op", vault, item, field)
    if scheme == "inf":
        inf = _load_inf()
        env, path, key = inf.parse_inf_ref(ref)
        return ("inf", env, path, key)
    raise ValueError(f"unknown ref scheme {scheme!r}: {ref!r}")


def _scheme_of(ref: str) -> str:
    """Return the scheme of `ref` without parsing the rest. Raises ValueError on miss."""
    if not isinstance(ref, str) or not ref:
        raise ValueError(f"not a valid ref: {ref!r}")
    m = _SCHEME_RE.match(ref)
    if not m:
        raise ValueError(f"ref has no scheme: {ref!r}")
    return m.group(1)


# ───────────────────────────────────────────────────────────────────────────
# Read / upsert dispatch
# ───────────────────────────────────────────────────────────────────────────


def read(ref: str) -> str:
    """Resolve a single ref by dispatching to the right backend."""
    scheme = _scheme_of(ref)
    if scheme == "op":
        return _load_op().op_read(ref)
    if scheme == "inf":
        return _load_inf().inf_read(ref)
    raise ValueError(f"unknown ref scheme {scheme!r}: {ref!r}")


def item_upsert(ref: str, value: str, *, concealed: bool = True) -> None:
    """Upsert `value` at `ref`, dispatching to the right backend.

    Note the API shape difference from op.op_item_upsert(vault, item, field,
    value, ...): we take a single ref string and parse it. This matches how
    inf.inf_item_upsert works and keeps the dispatch surface uniform. Call
    sites that already have (vault, item, field) tuples can re-encode them
    as `f"op://{vault}/{item}/{field}"` before calling.
    """
    scheme = _scheme_of(ref)
    if scheme == "op":
        op = _load_op()
        vault, item, field = op.parse_op_ref(ref)
        op.op_item_upsert(vault, item, field, value, concealed=concealed)
        return
    if scheme == "inf":
        inf = _load_inf()
        inf.inf_item_upsert(ref, value, concealed=concealed)
        return
    raise ValueError(f"unknown ref scheme {scheme!r}: {ref!r}")


# ───────────────────────────────────────────────────────────────────────────
# Template injection
# ───────────────────────────────────────────────────────────────────────────


def inject_template(template: str) -> str:
    """Render `{{ op://... }}` and/or `{{ inf://... }}` placeholders in `template`.

    For op-only templates, defers to op.op_inject for batch performance (one
    `op` invocation handles all refs). For mixed or inf-containing templates,
    falls back to per-ref reads with a regex substitute — this is O(N) calls
    but only on templates that mention any inf:// ref, and N is typically
    small for Porch manifests.
    """
    if not template:
        return template

    # Detect which schemes appear in the template.
    schemes = {m.group(1).split("://", 1)[0] for m in _TEMPLATE_PLACEHOLDER_RE.finditer(template)}

    if not schemes:
        # No recognized placeholders. Defer to op.op_inject anyway in case
        # the template uses a syntax we didn't match (op inject is tolerant
        # — non-placeholder text passes through verbatim).
        try:
            return _load_op().op_inject(template)
        except Exception:
            # If op isn't available and there's nothing to inject, return as-is.
            return template

    if schemes == {"op"}:
        return _load_op().op_inject(template)

    # Mixed or inf-only: per-ref substitution.
    def repl(m: re.Match) -> str:
        ref = m.group(1)
        return read(ref)

    return _TEMPLATE_PLACEHOLDER_RE.sub(repl, template)


# ───────────────────────────────────────────────────────────────────────────
# Whoami / manifest helpers
# ───────────────────────────────────────────────────────────────────────────


def whoami_for_scheme(scheme: str) -> Optional[dict]:
    """Probe whether the backend for `scheme` is authenticated.

    Returns the backend-specific status dict on success (op_whoami / inf_whoami),
    None on failure or unknown scheme. Doesn't raise.
    """
    if scheme == "op":
        return _load_op().op_whoami()
    if scheme == "inf":
        return _load_inf().inf_whoami()
    return None


def scheme_of(ref: str) -> str:
    """Return the scheme prefix of `ref` (e.g. 'op', 'inf'). ValueError on miss.

    Public alias for `_scheme_of` so call sites don't reach into private state.
    """
    return _scheme_of(ref)


def validate_persist_ref_shape(ref: str, *, multi_field: bool) -> None:
    """Validate `ref` matches the segment count required for the given mode.

    Used by `secure-entry` to pre-flight `--save-to-secrets` / `--save-to-op`:

      - Single-field mode (multi_field=False): ref must include a key segment.
        - op://Vault/Item/field      (exactly 3 segments)
        - inf://env/path.../KEY      (3+ segments, last is the key)

      - Multi-field mode (multi_field=True): ref is a parent path, no key.
        - op://Vault/Item            (exactly 2 segments)
        - inf://env/path...          (2+ segments — env + at least one path
                                       segment, no trailing key)

    Raises ValueError on mismatch with a message tuned for end-user output.
    """
    if not isinstance(ref, str) or not ref:
        raise ValueError(f"ref must be a non-empty string (got {ref!r})")

    if ref.startswith("op://"):
        parts = ref[len("op://"):].split("/")
        if multi_field:
            # Need exactly 2 non-empty segments (Vault/Item).
            if len(parts) >= 3 and all(parts[:3]):
                raise ValueError(
                    "use `op://Vault/Item` (no trailing field) when "
                    "collecting multiple fields"
                )
            if len(parts) < 2 or not parts[0] or not parts[1]:
                raise ValueError(
                    f"--save-to-secrets must be op://Vault/Item (got {ref!r})"
                )
            return
        # Single-field: need exactly 3 non-empty segments.
        if len(parts) < 3 or not all(parts[:3]):
            raise ValueError(
                "specify --field one or more times, or use "
                "`op://Vault/Item/field` for single-field mode"
            )
        return

    if ref.startswith("inf://"):
        parts = ref[len("inf://"):].split("/")
        if multi_field:
            # Need at least 2 non-empty segments (env + path).
            if len(parts) < 2 or any(not p for p in parts):
                raise ValueError(
                    f"--save-to-secrets must be inf://<env>/<path...> "
                    f"(got {ref!r})"
                )
            return
        # Single-field: need at least 3 non-empty segments (env + path + key).
        if len(parts) < 3 or any(not p for p in parts):
            raise ValueError(
                "specify --field one or more times, or use "
                "`inf://<env>/<path>/<KEY>` for single-field mode"
            )
        return

    raise ValueError(
        f"--save-to-secrets must start with 'op://' or 'inf://' (got {ref!r})"
    )


def join_multi_field_ref(parent_ref: str, field_name: str) -> str:
    """Construct a per-field ref from a multi-field parent ref + field name.

    op://Vault/Item       + username -> op://Vault/Item/username
    inf://dev/myapp       + username -> inf://dev/myapp/username
    inf://dev/team/myapp  + username -> inf://dev/team/myapp/username
    """
    if not isinstance(parent_ref, str) or not parent_ref:
        raise ValueError(f"parent_ref must be a non-empty string (got {parent_ref!r})")
    if not isinstance(field_name, str) or not field_name:
        raise ValueError(f"field_name must be a non-empty string (got {field_name!r})")
    # Append `/<field_name>` for both schemes — semantics differ slightly
    # (op fields vs. infisical keys) but the URI shape is identical.
    return parent_ref.rstrip("/") + "/" + field_name


def schemes_in_manifest(refs: list) -> set:
    """Return the set of distinct ref schemes present in `refs`.

    Used by call sites at startup to decide which backends to auth-check —
    e.g. an op-only manifest skips infisical auth, a mixed manifest needs
    both, an inf-only manifest skips op.

    Refs whose scheme can't be parsed are silently skipped — a malformed
    entry will surface later when someone tries to read or upsert it.
    """
    out = set()
    for r in refs or []:
        try:
            out.add(_scheme_of(r))
        except ValueError:
            continue
    return out


# ───────────────────────────────────────────────────────────────────────────
# CLI entrypoint (smoke test)
# ───────────────────────────────────────────────────────────────────────────


def _main(argv: list) -> int:
    if len(argv) < 2:
        print("usage: cush_secrets.py {parse <ref>|read <ref>|whoami <scheme>}", file=sys.stderr)
        return 2
    cmd = argv[1]
    try:
        if cmd == "parse":
            if len(argv) < 3:
                print("usage: cush_secrets.py parse <ref>", file=sys.stderr)
                return 2
            print(parse_ref(argv[2]))
            return 0
        if cmd == "read":
            if len(argv) < 3:
                print("usage: cush_secrets.py read <ref>", file=sys.stderr)
                return 2
            print(read(argv[2]))
            return 0
        if cmd == "whoami":
            if len(argv) < 3:
                print("usage: cush_secrets.py whoami <scheme>", file=sys.stderr)
                return 2
            who = whoami_for_scheme(argv[2])
            if who is None:
                print("not authenticated", file=sys.stderr)
                return 3
            import json
            print(json.dumps(who, indent=2))
            return 0
        print(f"unknown subcommand: {cmd}", file=sys.stderr)
        return 2
    except SecretsAuthError as e:
        print(f"[secrets] auth: {e}", file=sys.stderr)
        return 3
    except SecretsRefNotFound as e:
        print(f"[secrets] not-found: {e}", file=sys.stderr)
        return 6
    except SecretsAccessError as e:
        print(f"[secrets] access: {e}", file=sys.stderr)
        return 4
    except SecretsError as e:
        print(f"[secrets] error: {e}", file=sys.stderr)
        return 4
    except ValueError as e:
        print(f"[secrets] bad ref: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv))

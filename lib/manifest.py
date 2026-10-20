#!/usr/bin/env python3
"""TOML reader/writer for `.cush-secrets` manifests.

Format reference (schema = 1):

    schema = 1

    [defaults]
    target_vault   = "Personal"
    target_item    = "{project}"     # {project} = basename of project dir
    field_template = "{key}"

    [secrets]
    DATABASE_URL = "op://Personal/myapp/database_url"
    STRIPE_KEY   = { ref = "op://Personal/myapp/stripe", fallback = "sk_test_dev" }
    GITHUB_TOKEN = { ref = "op://Work/shared/gh_token" }

    [secrets.WEIRD_ONE]               # per-secret overrides via [secrets.<name>] form
    ref          = "op://Shared/legacy/api"
    target_vault = "Shared"
    required     = true

Bare-string values are shorthand for `{ ref = "..." }`. Inline-table values
support `ref`, `fallback`, `target_vault`, `target_item`, `type`, `required`.
The `[secrets.<name>]` section form is equivalent — used for readability when
overrides are extensive.

Reading uses Python's stdlib `tomllib` (3.11+). Writing is hand-rolled to
avoid pulling in `tomli_w` as a dep.

CLI smoke test:
  python3 lib/manifest.py            # round-trip a sample manifest
"""

from __future__ import annotations

import os
import sys
import tomllib
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# ───────────────────────────────────────────────────────────────────────────
# Data classes
# ───────────────────────────────────────────────────────────────────────────


@dataclass
class SecretSpec:
    env_name: str
    ref: str
    fallback: Optional[str] = None
    target_vault: Optional[str] = None
    target_item: Optional[str] = None
    type: str = "string"
    required: bool = True


@dataclass
class Manifest:
    schema: int
    defaults: dict
    secrets: list  # list[SecretSpec]
    source_path: Path = field(default_factory=lambda: Path("."))


class ManifestError(ValueError):
    """Surfaced for malformed manifest files."""


# ───────────────────────────────────────────────────────────────────────────
# Reading
# ───────────────────────────────────────────────────────────────────────────


_VALID_TYPES = ("string", "file", "ssh")
_KNOWN_FIELDS = {
    "ref", "fallback", "target_vault", "target_item", "type", "required",
}


def _validate_ref(ref, ctx: str) -> str:
    """Validate a manifest ref string.

    Accepted schemes (Phase 2b):
      - op://Vault/Item/field        (exactly 3 segments, all non-empty)
      - inf://<env>/<path...>/<KEY>  (3+ segments — at least one path
                                      segment plus a trailing key)

    The exact parse for each scheme lives in op.parse_op_ref /
    infisical.parse_inf_ref. We do a loose structural check here so the
    manifest can be validated offline (no op/infisical CLI required).
    """
    if not isinstance(ref, str):
        raise ManifestError(
            f"{ctx}: 'ref' must be a string starting with 'op://' or 'inf://' "
            f"(got {ref!r})"
        )
    if ref.startswith("op://"):
        parts = ref[len("op://"):].split("/")
        if len(parts) < 3 or any(not p for p in parts[:3]):
            raise ManifestError(
                f"{ctx}: ref must be op://Vault/Item/field (got {ref!r})"
            )
        return ref
    if ref.startswith("inf://"):
        # inf://<env>/<path...>/<KEY>: at least 3 non-empty segments after
        # the scheme — env + at least one path segment + key.
        parts = ref[len("inf://"):].split("/")
        if len(parts) < 3 or any(not p for p in parts):
            raise ManifestError(
                f"{ctx}: ref must be inf://<env>/<path>/<KEY> "
                f"(got {ref!r})"
            )
        return ref
    raise ManifestError(
        f"{ctx}: 'ref' must start with 'op://' or 'inf://' (got {ref!r})"
    )


def _parse_secret(env_name: str, value, ctx: str) -> SecretSpec:
    if isinstance(value, str):
        return SecretSpec(env_name=env_name, ref=_validate_ref(value, ctx))
    if not isinstance(value, dict):
        raise ManifestError(
            f"{ctx}: secret entry must be a string ref or table (got {type(value).__name__})"
        )

    extra = set(value) - _KNOWN_FIELDS
    if extra:
        raise ManifestError(
            f"{ctx}: unknown fields {sorted(extra)}; expected subset of {sorted(_KNOWN_FIELDS)}"
        )

    if "ref" not in value:
        raise ManifestError(f"{ctx}: missing required field 'ref'")

    ref = _validate_ref(value["ref"], ctx)

    sec_type = value.get("type", "string")
    if sec_type not in _VALID_TYPES:
        raise ManifestError(
            f"{ctx}: type must be one of {_VALID_TYPES} (got {sec_type!r})"
        )

    required = value.get("required", True)
    if not isinstance(required, bool):
        raise ManifestError(f"{ctx}: 'required' must be a bool (got {required!r})")

    fallback = value.get("fallback")
    if fallback is not None and not isinstance(fallback, str):
        raise ManifestError(f"{ctx}: 'fallback' must be a string (got {fallback!r})")

    target_vault = value.get("target_vault")
    if target_vault is not None and not isinstance(target_vault, str):
        raise ManifestError(f"{ctx}: 'target_vault' must be a string")

    target_item = value.get("target_item")
    if target_item is not None and not isinstance(target_item, str):
        raise ManifestError(f"{ctx}: 'target_item' must be a string")

    return SecretSpec(
        env_name=env_name,
        ref=ref,
        fallback=fallback,
        target_vault=target_vault,
        target_item=target_item,
        type=sec_type,
        required=required,
    )


def _parse_defaults(raw) -> dict:
    if not isinstance(raw, dict):
        raise ManifestError("[defaults] must be a table")
    allowed = {"target_vault", "target_item", "field_template"}
    extra = set(raw) - allowed
    if extra:
        raise ManifestError(
            f"[defaults] unknown keys {sorted(extra)}; expected subset of {sorted(allowed)}"
        )
    out = {}
    for k in allowed:
        if k in raw:
            if not isinstance(raw[k], str):
                raise ManifestError(f"[defaults].{k} must be a string")
            out[k] = raw[k]
    return out


def load(path) -> Manifest:
    """Parse a `.cush-secrets` TOML file from disk.

    Raises ManifestError on schema mismatch or malformed entries.
    """
    p = Path(path)
    if not p.exists():
        raise ManifestError(f"manifest not found: {p}")
    try:
        with open(p, "rb") as f:
            raw = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise ManifestError(f"{p}: invalid TOML: {e}") from e

    schema = raw.get("schema", 1)
    if schema != 1:
        raise ManifestError(
            f"{p}: unsupported schema version {schema!r} (this build understands schema = 1)"
        )

    defaults = _parse_defaults(raw.get("defaults", {}))

    secrets_raw = raw.get("secrets", {})
    if not isinstance(secrets_raw, dict):
        raise ManifestError(f"{p}: [secrets] must be a table")

    secrets = []
    for env_name, value in secrets_raw.items():
        if not env_name:
            raise ManifestError(f"{p}: empty env name in [secrets]")
        ctx = f"{p}: [secrets].{env_name}"
        secrets.append(_parse_secret(env_name, value, ctx))

    return Manifest(
        schema=schema,
        defaults=defaults,
        secrets=secrets,
        source_path=p.resolve(),
    )


def find_manifest(start=None):
    """Walk up parent dirs looking for `.cush-secrets`.

    Stops at:
      - a hit (returns the path)
      - a directory containing `.git` (boundary; only checked AFTER looking
        for `.cush-secrets` in that dir, so a manifest at the project root
        next to `.git` is still found)
      - the filesystem root (returns None)
    """
    cur = Path(start or Path.cwd()).resolve()
    while True:
        candidate = cur / ".cush-secrets"
        if candidate.is_file():
            return candidate
        if (cur / ".git").exists():
            # We're at the git root and there's no manifest here. Stop —
            # walking past a git root would silently grab a manifest from a
            # parent project, which is rarely what the user wants.
            return None
        if cur.parent == cur:
            return None
        cur = cur.parent


# ───────────────────────────────────────────────────────────────────────────
# Writing
# ───────────────────────────────────────────────────────────────────────────


def _toml_escape_basic_string(s: str) -> str:
    """Escape a value for emission as a TOML basic string ("...").

    Per TOML spec, basic strings need: backslash, double-quote, control chars
    (\\b, \\t, \\n, \\f, \\r, U+0000..U+001F, U+007F) escaped.
    """
    out = []
    for ch in s:
        c = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\r":
            out.append("\\r")
        elif c < 0x20 or c == 0x7F:
            out.append(f"\\u{c:04X}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


_BARE_KEY_RE = None


def _is_bare_key(s: str) -> bool:
    # TOML bare keys: A-Z a-z 0-9 _ -
    if not s:
        return False
    for ch in s:
        if not (ch.isalnum() or ch in "_-"):
            return False
    return True


def _emit_key(key: str) -> str:
    if _is_bare_key(key):
        return key
    return _toml_escape_basic_string(key)


def _emit_value(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return _toml_escape_basic_string(v)
    raise ManifestError(f"unsupported value type for TOML emit: {type(v).__name__}")


def _spec_uses_inline(spec: SecretSpec) -> bool:
    """A spec is bare-string-emittable iff only `ref` is set + required default."""
    return (
        spec.fallback is not None
        or spec.target_vault is not None
        or spec.target_item is not None
        or spec.type != "string"
        or spec.required is not True
    )


def _emit_inline_table_for_spec(spec: SecretSpec) -> str:
    parts = [f"ref = {_emit_value(spec.ref)}"]
    if spec.fallback is not None:
        parts.append(f"fallback = {_emit_value(spec.fallback)}")
    if spec.target_vault is not None:
        parts.append(f"target_vault = {_emit_value(spec.target_vault)}")
    if spec.target_item is not None:
        parts.append(f"target_item = {_emit_value(spec.target_item)}")
    if spec.type != "string":
        parts.append(f"type = {_emit_value(spec.type)}")
    if spec.required is not True:
        parts.append(f"required = {_emit_value(spec.required)}")
    return "{ " + ", ".join(parts) + " }"


def dump(manifest: Manifest, path) -> None:
    """Emit a Manifest to disk as valid TOML.

    Strategy: bare-string form when only `ref` is set; inline-table form
    otherwise. Section form ([secrets.NAME]) is reserved for the human-edit
    case and is NOT emitted here — round-tripping such a manifest produces
    inline-table form, which is semantically identical.
    """
    p = Path(path)
    lines = [f"schema = {manifest.schema}"]
    lines.append("")

    if manifest.defaults:
        lines.append("[defaults]")
        # Emit in a stable order.
        for k in ("target_vault", "target_item", "field_template"):
            if k in manifest.defaults:
                lines.append(f"{_emit_key(k)} = {_emit_value(manifest.defaults[k])}")
        lines.append("")

    if manifest.secrets:
        lines.append("[secrets]")
        for spec in manifest.secrets:
            key = _emit_key(spec.env_name)
            if _spec_uses_inline(spec):
                lines.append(f"{key} = {_emit_inline_table_for_spec(spec)}")
            else:
                lines.append(f"{key} = {_emit_value(spec.ref)}")
        lines.append("")

    text = "\n".join(lines).rstrip() + "\n"
    p.write_text(text)


# ───────────────────────────────────────────────────────────────────────────
# Resolution
# ───────────────────────────────────────────────────────────────────────────


def resolve_target(manifest: Manifest, env_name: str):
    """Return (vault, item, field) for a given env_name.

    Resolution order:
      - Per-secret override (target_vault / target_item) wins.
      - Otherwise [defaults] target_vault / target_item.
      - field_template defaults to {key}.
      - {project} is substituted with the manifest's parent dir basename.
      - {key} is substituted with env_name lowercased.

    Raises KeyError if env_name is not in the manifest, ManifestError if
    target_vault is neither defaulted nor overridden.
    """
    spec = next((s for s in manifest.secrets if s.env_name == env_name), None)
    if spec is None:
        raise KeyError(f"no secret named {env_name!r} in manifest")

    project = manifest.source_path.parent.name or "project"
    field_template = manifest.defaults.get("field_template", "{key}")

    vault = spec.target_vault or manifest.defaults.get("target_vault")
    if not vault:
        raise ManifestError(
            f"target_vault not set for {env_name} (neither per-secret nor [defaults])"
        )

    item_template = spec.target_item or manifest.defaults.get("target_item", "{project}")
    item = item_template.format(project=project, key=env_name.lower())
    field_name = field_template.format(project=project, key=env_name.lower())

    return vault, item, field_name


# ───────────────────────────────────────────────────────────────────────────
# Self-test
# ───────────────────────────────────────────────────────────────────────────


_SAMPLE = """\
schema = 1

[defaults]
target_vault = "Personal"
target_item = "{project}"
field_template = "{key}"

[secrets]
DATABASE_URL = "op://Personal/myapp/database_url"
STRIPE_KEY = { ref = "op://Personal/myapp/stripe", fallback = "sk_test_dev" }
GITHUB_TOKEN = { ref = "op://Work/shared/gh_token" }
WEIRD_ONE = { ref = "op://Shared/legacy/api", target_vault = "Shared", required = false }
"""


def _self_test() -> int:
    """Round-trip a sample manifest. parse -> emit -> reparse -> compare."""
    import tempfile

    failures = 0

    # 1. Direct parse of a tomllib-friendly string.
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        m1_path = td / ".cush-secrets"
        m1_path.write_text(_SAMPLE)
        m1 = load(m1_path)
        assert m1.schema == 1
        assert m1.defaults["target_vault"] == "Personal"
        assert {s.env_name for s in m1.secrets} == {
            "DATABASE_URL", "STRIPE_KEY", "GITHUB_TOKEN", "WEIRD_ONE"
        }
        stripe = next(s for s in m1.secrets if s.env_name == "STRIPE_KEY")
        assert stripe.fallback == "sk_test_dev"
        weird = next(s for s in m1.secrets if s.env_name == "WEIRD_ONE")
        assert weird.required is False
        assert weird.target_vault == "Shared"

        # 2. Round-trip: emit + re-parse.
        m2_path = td / ".cush-secrets.out"
        dump(m1, m2_path)
        m2 = load(m2_path)
        if {s.env_name for s in m1.secrets} != {s.env_name for s in m2.secrets}:
            print(f"[manifest self-test] mismatch: env names differ", file=sys.stderr)
            failures += 1

        # Compare each spec's effective fields.
        for s1 in m1.secrets:
            s2 = next((s for s in m2.secrets if s.env_name == s1.env_name), None)
            if s2 is None:
                print(f"[manifest self-test] missing in roundtrip: {s1.env_name}", file=sys.stderr)
                failures += 1
                continue
            for fld in ("ref", "fallback", "target_vault", "target_item", "type", "required"):
                if getattr(s1, fld) != getattr(s2, fld):
                    print(
                        f"[manifest self-test] field mismatch on {s1.env_name}.{fld}: "
                        f"{getattr(s1, fld)!r} != {getattr(s2, fld)!r}",
                        file=sys.stderr,
                    )
                    failures += 1

        # 3. resolve_target sanity check.
        vault, item, field_name = resolve_target(m1, "DATABASE_URL")
        if vault != "Personal":
            print(f"[manifest self-test] resolve_target vault wrong: {vault}", file=sys.stderr)
            failures += 1
        # item template = {project}; project = m1_path.parent.name (the tmpdir).
        if item != m1_path.parent.name:
            print(
                f"[manifest self-test] resolve_target item wrong: {item} (expected {m1_path.parent.name})",
                file=sys.stderr,
            )
            failures += 1
        if field_name != "database_url":
            print(f"[manifest self-test] resolve_target field wrong: {field_name}", file=sys.stderr)
            failures += 1

        # 4. find_manifest walkup.
        sub = td / "a" / "b" / "c"
        sub.mkdir(parents=True)
        found = find_manifest(sub)
        if found != m1_path.resolve():
            print(
                f"[manifest self-test] find_manifest walkup failed: got {found}, expected {m1_path.resolve()}",
                file=sys.stderr,
            )
            failures += 1

    if failures:
        print(f"[manifest self-test] {failures} failure(s)", file=sys.stderr)
        return 1
    print("[manifest self-test] ok")
    return 0


if __name__ == "__main__":
    sys.exit(_self_test())

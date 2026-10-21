#!/usr/bin/env python3
"""Thin wrapper around the 1Password `op` CLI.

Centralizes the error matrix for Porch's op integrations:

  - `op` not on PATH                  -> OpAuthError (with install link)
  - OP_SERVICE_ACCOUNT_TOKEN missing  -> OpAuthError (with setup hint)
  - Auth failure / token invalid      -> OpAuthError
  - Ref does not resolve              -> OpRefNotFound
  - Vault not in token's scope        -> OpVaultAccessError
  - Anything else                     -> OpError

Public functions:
  op_whoami()           -> dict | None
  op_read(ref)          -> str
  op_inject(template)   -> str
  op_item_upsert(...)   -> None  (idempotent: edit, fall back to create)

CLI smoke test:
  python3 lib/op.py whoami
  python3 lib/op.py read op://Personal/something/field
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from typing import Optional


OP_INSTALL_URL = "https://developer.1password.com/docs/cli/get-started/"
OP_SERVICE_ACCOUNTS_URL = "https://developer.1password.com/docs/service-accounts/"


# Generic-base hookup. The lib/cush_secrets.py dispatch layer exports a
# unified SecretsError hierarchy; we want OpError etc. to inherit from those
# so call sites can catch either name (legacy `except OpError` keeps working,
# new `except SecretsError` also catches op failures). Lazy-import to avoid
# a hard dependency at module load: if cush_secrets.py isn't importable for
# any reason, fall back to plain Exception bases so op.py stays usable.
def _generic_bases():
    try:
        from cush_secrets import (  # type: ignore
            SecretsError,
            SecretsAuthError,
            SecretsRefNotFound,
            SecretsAccessError,
        )
        return SecretsError, SecretsAuthError, SecretsRefNotFound, SecretsAccessError
    except Exception:
        return Exception, Exception, Exception, Exception


_SecretsError, _SecretsAuthError, _SecretsRefNotFound, _SecretsAccessError = _generic_bases()


class OpError(_SecretsError):
    """Generic op failure."""


class OpAuthError(OpError, _SecretsAuthError):
    """op not installed, token missing/invalid, or whoami failed."""


class OpRefNotFound(OpError, _SecretsRefNotFound):
    """An op://... reference does not resolve (item or field missing)."""


class OpVaultAccessError(OpError, _SecretsAccessError):
    """The service-account token does not have access to the requested vault."""


# ───────────────────────────────────────────────────────────────────────────
# Internals
# ───────────────────────────────────────────────────────────────────────────


_op_available_checked = False


def _ensure_op_available() -> None:
    """Raise OpAuthError if `op` is missing or `op whoami` fails.

    Trusts whatever auth mode `op` itself has been configured with — service
    account token, signed-in session (e.g. set up by `lib/op.sh` Mode 2),
    desktop-app integration, etc. We don't care *how* op is authed, only
    whether it is. The result is cached for the life of the process.
    """
    global _op_available_checked
    if _op_available_checked:
        return
    if not shutil.which("op"):
        raise OpAuthError(
            "1Password CLI (`op`) is not installed or not on PATH.\n"
            f"Install: {OP_INSTALL_URL}"
        )
    try:
        proc = subprocess.run(
            ["op", "whoami"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired as e:
        raise OpAuthError(
            "op whoami timed out after 30s (network or daemon issue)"
        ) from e
    if proc.returncode != 0:
        # Mode 2 fallback: try to re-mint the session non-interactively.
        if _resignin():
            try:
                proc = subprocess.run(
                    ["op", "whoami"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            except subprocess.TimeoutExpired as e:
                raise OpAuthError(
                    "op whoami (post-resignin) timed out after 30s"
                ) from e
        if proc.returncode != 0:
            raise OpAuthError(
                "1Password CLI (`op`) is not authenticated (`op whoami` failed; "
                "auto-resignin attempted).\n"
                "Configure auth with one of:\n"
                f"  - OP_SERVICE_ACCOUNT_TOKEN env var ({OP_SERVICE_ACCOUNTS_URL})\n"
                "  - Stored credentials in ~/.config/porch/op.env (Mode 2)\n"
                "Run any Porch op-aware command with -h "
                "(e.g. `bin/secure-entry --save-to-op ... -h`) to see the full "
                "setup hint."
            )
    _op_available_checked = True


def _classify_stderr(stderr: str) -> type:
    """Discriminate an op stderr blob into a concrete exception class.

    op's stderr text is the only signal we have — there are no machine-readable
    error codes. Patterns observed across `op read` / `op item edit` / etc:
      - "isn't a service account" / "session expired" -> auth
      - "doesn't seem to be an item"                  -> ref not found
      - "couldn't resolve" / "not found"              -> ref not found
      - "isn't a vault in this account"               -> vault access
      - "no vault matched"                            -> vault access
    """
    s = (stderr or "").lower()
    auth_markers = (
        "service account",
        "session expired",
        "not currently signed in",
        "authentication required",
        "invalid token",
        "unauthorized",
    )
    notfound_markers = (
        "isn't an item",
        "doesn't seem to be an item",
        "couldn't resolve",
        "not found",
        "no item matched",
        "could not find",
        "no field",
    )
    vault_markers = (
        "isn't a vault",
        "no vault matched",
        "vault access",
        "doesn't have access to vault",
    )
    if any(m in s for m in auth_markers):
        return OpAuthError
    if any(m in s for m in vault_markers):
        return OpVaultAccessError
    if any(m in s for m in notfound_markers):
        return OpRefNotFound
    return OpError


def _run_once(argv: list, *, input_text: Optional[str] = None, env_extra: Optional[dict] = None, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run an op subprocess with a hard timeout.

    `timeout` defaults to 60s — enough for `op item create` / `op item edit`
    over a slow link, and short enough to fail loudly if the CLI hangs (e.g.
    a stale signin daemon, network partition, or `op` waiting for tty input).
    Raises OpError on timeout — never let `subprocess.TimeoutExpired` escape
    raw to call sites.
    """
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    try:
        return subprocess.run(
            argv,
            input=input_text,
            text=True,
            capture_output=True,
            env=env,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise OpError(
            f"op CLI call timed out after {timeout}s: {' '.join(argv[:3])}..."
        ) from e


_OP_SH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "op.sh")


def _resignin() -> bool:
    """Attempt a fresh Mode 2 signin via lib/op.sh's _cush_op_signin_fresh.

    Returns True if a new OP_SESSION_<shorthand> was minted and adopted into
    os.environ. Used to recover from stale-session auth failures in
    long-running daemons (secure-entry, drop, exchange, etc.) whose inherited
    OP_SESSION expires after ~30 min idle.

    No-op (returns False) if Mode 2 credentials aren't configured — service
    accounts and other modes have no fallback we can drive.
    """
    if not os.environ.get("OP_MASTER_PASSWORD"):
        return False
    try:
        proc = subprocess.run(
            ["bash", "-c", f'. "{_OP_SH_PATH}" && _cush_op_signin_fresh && env | grep ^OP_SESSION_ || true'],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return False
    if proc.returncode != 0:
        return False
    minted = False
    for line in proc.stdout.splitlines():
        if line.startswith("OP_SESSION_") and "=" in line:
            k, v = line.split("=", 1)
            os.environ[k] = v
            minted = True
    return minted


def _run(argv: list, *, input_text: Optional[str] = None, env_extra: Optional[dict] = None, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run an op subprocess, auto-retrying once on stale-session auth failure.

    Long-running daemons inherit OP_SESSION_* at spawn; the session expires
    after ~30 min idle. When that happens, the next op call returns non-zero
    with an auth-class stderr. We detect that, attempt a fresh signin via
    lib/op.sh's _cush_op_signin_fresh, and retry the original call once.

    `timeout` is forwarded to `_run_once` and applies independently to each
    of the (initial, post-resignin) calls.
    """
    proc = _run_once(argv, input_text=input_text, env_extra=env_extra, timeout=timeout)
    if proc.returncode == 0:
        return proc
    if _classify_stderr(proc.stderr) is not OpAuthError:
        return proc
    if not _resignin():
        return proc
    return _run_once(argv, input_text=input_text, env_extra=env_extra, timeout=timeout)


# ───────────────────────────────────────────────────────────────────────────
# Public API
# ───────────────────────────────────────────────────────────────────────────


def op_whoami() -> Optional[dict]:
    """Return parsed `op whoami --format=json`, or None on failure.

    Used as a low-cost auth probe. Doesn't raise — callers that want strict
    auth checking should use _ensure_op_available() and inspect this result.

    Auth-mode-agnostic: trusts whatever auth `op` itself has been configured
    with (service-account token, signed-in session via lib/op.sh Mode 2,
    desktop-app integration, etc.). The previous OP_SERVICE_ACCOUNT_TOKEN
    precheck blocked Mode 2 callers; we now just shell out and report the
    result.
    """
    if not shutil.which("op"):
        return None
    proc = _run(["op", "whoami", "--format=json"], timeout=30)
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def op_read(ref: str) -> str:
    """Read a single op://... ref and return its value.

    Raises OpRefNotFound / OpAuthError / OpVaultAccessError / OpError.
    """
    _ensure_op_available()
    proc = _run(["op", "read", ref], timeout=30)
    if proc.returncode == 0:
        # `op read` includes a trailing newline; strip exactly one.
        return proc.stdout.rstrip("\n")
    cls = _classify_stderr(proc.stderr)
    raise cls(f"op read {ref} failed: {proc.stderr.strip() or 'unknown error'}")


def op_inject(template: str) -> str:
    """Render `{{ op://... }}` placeholders in `template` and return the result.

    Uses `op inject` over stdin/stdout. Same error semantics as op_read.
    """
    _ensure_op_available()
    proc = _run(["op", "inject"], input_text=template, timeout=30)
    if proc.returncode == 0:
        return proc.stdout
    cls = _classify_stderr(proc.stderr)
    raise cls(f"op inject failed: {proc.stderr.strip() or 'unknown error'}")


def _field_entry(field: str, value: str, *, concealed: bool) -> dict:
    """Build a single JSON-template field entry.

    Concealed -> CONCEALED type (renders dotted in UI, suitable for secrets).
    Otherwise -> STRING type.
    """
    return {
        "id": field,
        "type": "CONCEALED" if concealed else "STRING",
        "label": field,
        "value": value,
    }


def _build_create_template(
    vault: str,
    item: str,
    field: str,
    value: str,
    *,
    concealed: bool,
) -> tuple[dict, bool]:
    """Build the JSON template for `op item create -`.

    Returns (template, needs_generate_password). The PASSWORD category requires
    a non-empty `password` field with purpose=PASSWORD ("ps value"). If the
    upsert target IS the password field, set it directly. Otherwise, the
    caller must pass `--generate-password` so op fills the password field with
    a random value to satisfy validation. (We cannot leave the password field
    out or empty.)
    """
    fields = []
    if field == "password":
        # Upsert target is the password field itself: set it directly,
        # mirroring op item template get Password's structure.
        fields.append({
            "id": "password",
            "type": "CONCEALED",
            "purpose": "PASSWORD",
            "label": "password",
            "value": value,
        })
        needs_gen = False
    else:
        # Custom field. The password field will be filled by --generate-password.
        fields.append(_field_entry(field, value, concealed=concealed))
        needs_gen = True
    template = {
        "title": item,
        "category": "PASSWORD",
        "vault": {"name": vault},
        "fields": fields,
    }
    return template, needs_gen


def _merge_field_into_item(item_json: dict, field: str, value: str, *, concealed: bool) -> dict:
    """Return a copy of `item_json` with `field` set to `value`.

    If a field with id or label matching `field` already exists, update its
    value in place (preserving id, purpose, section, etc.). Otherwise, append
    a new custom field entry. `op item edit` via JSON template stdin REPLACES
    the entire fields array, so the caller must pass back every field they
    want preserved — this helper takes care of that by mutating the existing
    structure.
    """
    out = dict(item_json)
    fields = list(out.get("fields") or [])
    found = False
    for i, f in enumerate(fields):
        if f.get("id") == field or f.get("label") == field:
            new = dict(f)
            new["value"] = value
            # If we're explicitly setting type, prefer CONCEALED for secrets,
            # but don't overwrite a built-in's type/purpose (e.g. "password"
            # field's purpose=PASSWORD must stay).
            if "type" not in new or not new["type"]:
                new["type"] = "CONCEALED" if concealed else "STRING"
            fields[i] = new
            found = True
            break
    if not found:
        fields.append(_field_entry(field, value, concealed=concealed))
    out["fields"] = fields
    return out


def op_item_upsert(
    vault: str,
    item: str,
    field: str,
    value: str,
    *,
    concealed: bool = True,
) -> None:
    """Idempotently set `field` on `item` in `vault` to `value`.

    Strategy (tested against op CLI 2.34.0):
      1. Try `op item get <item> --vault=<vault> --format=json` to detect
         whether the item exists.
      2. If exists: merge the field into the JSON (update by id/label or
         append) and pipe the full template to `op item edit <item> --vault
         --format=json` via stdin. NB: edit-via-template REPLACES the full
         fields array, so the round-trip is required.
      3. If not exists: build a minimal create template and pipe it to
         `op item create -`, with `--generate-password` when the target field
         is something other than "password" (the PASSWORD category requires
         a non-empty `password` field with purpose=PASSWORD).
      4. Race handling: if create reports "already exists", retry the edit
         path once.

    The value is passed via stdin JSON (subprocess `input=`), never via argv,
    so plaintext does not appear in /proc/<pid>/cmdline. JSON-encoding handles
    embedded newlines, quotes, backslashes, and leading "@" characters
    naturally.
    """
    _ensure_op_available()

    # Step 1: probe for existing item.
    get = _run([
        "op", "item", "get", item,
        "--vault", vault,
        "--format=json",
    ])

    if get.returncode == 0:
        try:
            existing = json.loads(get.stdout)
        except json.JSONDecodeError as e:
            raise OpError(f"op item get returned malformed JSON: {e}")
        merged = _merge_field_into_item(existing, field, value, concealed=concealed)
        edit = _run(
            ["op", "item", "edit", item, "--vault", vault],
            input_text=json.dumps(merged),
        )
        if edit.returncode == 0:
            return
        cls = _classify_stderr(edit.stderr)
        raise cls(f"op item edit failed: {edit.stderr.strip() or 'unknown error'}")

    # Item didn't resolve. If the failure is auth/vault rather than
    # "no such item", surface immediately.
    cls = _classify_stderr(get.stderr)
    if cls in (OpAuthError, OpVaultAccessError):
        raise cls(f"op item get failed: {get.stderr.strip()}")

    # Step 2: create.
    template, needs_gen = _build_create_template(
        vault, item, field, value, concealed=concealed,
    )
    create_argv = ["op", "item", "create", "-"]
    if needs_gen:
        create_argv.append("--generate-password")
    create = _run(create_argv, input_text=json.dumps(template))
    if create.returncode == 0:
        return

    # Step 3: if create lost a race (item now exists), retry the edit path
    # once with a fresh GET.
    c_stderr = (create.stderr or "").lower()
    if "already exists" in c_stderr or "duplicate" in c_stderr or "conflict" in c_stderr:
        get2 = _run([
            "op", "item", "get", item,
            "--vault", vault,
            "--format=json",
        ])
        if get2.returncode == 0:
            try:
                existing2 = json.loads(get2.stdout)
            except json.JSONDecodeError as e:
                raise OpError(f"op item get (retry) returned malformed JSON: {e}")
            merged2 = _merge_field_into_item(existing2, field, value, concealed=concealed)
            retry = _run(
                ["op", "item", "edit", item, "--vault", vault],
                input_text=json.dumps(merged2),
            )
            if retry.returncode == 0:
                return
            cls = _classify_stderr(retry.stderr)
            raise cls(f"op item edit (retry) failed: {retry.stderr.strip()}")

    cls = _classify_stderr(create.stderr)
    raise cls(f"op item create failed: {create.stderr.strip() or 'unknown error'}")


# ───────────────────────────────────────────────────────────────────────────
# Helpers consumers may reuse
# ───────────────────────────────────────────────────────────────────────────


_OP_REF_RE = re.compile(r"^op://([^/]+)/([^/]+)/(.+)$")


def parse_op_ref(ref: str) -> tuple[str, str, str]:
    """Split `op://Vault/Item/field` into (vault, item, field).

    Raises ValueError on malformed input.
    """
    m = _OP_REF_RE.match(ref or "")
    if not m:
        raise ValueError(f"not a valid op:// ref: {ref!r}")
    return m.group(1), m.group(2), m.group(3)


# ───────────────────────────────────────────────────────────────────────────
# CLI entrypoint (smoke test)
# ───────────────────────────────────────────────────────────────────────────


def _main(argv: list) -> int:
    if len(argv) < 2:
        print("usage: op.py {whoami|read <ref>|inject}", file=sys.stderr)
        return 2
    cmd = argv[1]
    try:
        if cmd == "whoami":
            who = op_whoami()
            if who is None:
                print("not authenticated", file=sys.stderr)
                return 3
            print(json.dumps(who, indent=2))
            return 0
        if cmd == "read":
            if len(argv) < 3:
                print("usage: op.py read <ref>", file=sys.stderr)
                return 2
            print(op_read(argv[2]))
            return 0
        if cmd == "inject":
            print(op_inject(sys.stdin.read()), end="")
            return 0
        print(f"unknown subcommand: {cmd}", file=sys.stderr)
        return 2
    except OpAuthError as e:
        print(f"[op] auth: {e}", file=sys.stderr)
        return 3
    except OpRefNotFound as e:
        print(f"[op] not-found: {e}", file=sys.stderr)
        return 6
    except OpVaultAccessError as e:
        print(f"[op] vault: {e}", file=sys.stderr)
        return 4
    except OpError as e:
        print(f"[op] error: {e}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(_main(sys.argv))

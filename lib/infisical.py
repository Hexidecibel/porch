#!/usr/bin/env python3
"""Thin wrapper around the Infisical CLI.

Mirrors lib/op.py's contract for `inf://<env>/<path...>/<KEY>` refs. The
public API is intentionally shape-compatible with op.py so the dispatch
layer in lib/secrets.py can pick a backend per scheme.

Error matrix:

  - `infisical` not on PATH         -> InfAuthError
  - infisical.env missing           -> InfAuthError
  - universal-auth login failed     -> InfAuthError
  - secret missing / no folder      -> InfRefNotFound
  - permission / forbidden          -> InfAccessError
  - anything else                   -> InfError

Public functions:
  inf_whoami()           -> dict | None
  inf_read(ref)          -> str
  inf_item_upsert(...)   -> None  (idempotent: ensures folder, then sets)
  parse_inf_ref(ref)     -> (env, path, key)

CLI smoke test:
  python3 lib/infisical.py whoami
  python3 lib/infisical.py read inf://dev/myapp/DB_URL
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional


INFISICAL_INSTALL_URL = "https://infisical.com/docs/cli/overview"
try:
    from porch_paths import env_first as _env_first, user_config_file as _user_config_file
except ImportError:  # loaded from outside lib/
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from porch_paths import env_first as _env_first, user_config_file as _user_config_file
# ~/.config/porch/infisical.env (the pre-rename ~/.config/cush-tools/ one when
# only that exists); PORCH_INFISICAL_ENV_FILE / CUSH_INFISICAL_ENV_FILE win.
INFISICAL_ENV_FILE = _env_first("PORCH_INFISICAL_ENV_FILE", "CUSH_INFISICAL_ENV_FILE",
                                default=_user_config_file("infisical.env"))
INFISICAL_DEFAULT_DOMAIN = "https://app.infisical.com/api"


# Exception hierarchy. We import cush_secrets.py's generic classes lazily here
# (avoiding an import cycle: cush_secrets imports infisical at module load
# time) and use multiple inheritance so callers can catch either name.
#
# Naming note: this module is `cush_secrets`, not `secrets`, because the
# stdlib already has a `secrets` module that lib/authserver.py imports for
# token generation. Putting `secrets.py` on sys.path would shadow stdlib.
def _generic_bases():
    """Return the generic SecretsError hierarchy as a tuple of base classes.

    Lazy import keeps `lib/cush_secrets.py` -> `lib/infisical.py` cycles
    safe. Falls back to (Exception,) if cush_secrets.py isn't importable for
    any reason (e.g. partial install during development).
    """
    try:
        from cush_secrets import (  # type: ignore
            SecretsError,
            SecretsAuthError,
            SecretsRefNotFound,
            SecretsAccessError,
        )
        return SecretsError, SecretsAuthError, SecretsRefNotFound, SecretsAccessError
    except Exception:  # pragma: no cover — defensive fallback
        return Exception, Exception, Exception, Exception


_SecretsError, _SecretsAuthError, _SecretsRefNotFound, _SecretsAccessError = _generic_bases()


class InfError(_SecretsError):
    """Generic infisical failure."""


class InfAuthError(InfError, _SecretsAuthError):
    """infisical not installed, env file missing, or login failed."""


class InfRefNotFound(InfError, _SecretsRefNotFound):
    """An inf://... reference does not resolve (key or folder missing)."""


class InfAccessError(InfError, _SecretsAccessError):
    """Token does not have permission for the requested project/env/path."""


# ───────────────────────────────────────────────────────────────────────────
# Internals
# ───────────────────────────────────────────────────────────────────────────


_inf_available_checked = False


def _token_cache_path() -> Path:
    """Pick a path for the cached universal-auth token.

    Prefers XDG_RUNTIME_DIR (tmpfs, cleared on reboot); falls back to
    XDG_CACHE_HOME. Both are written at chmod 600.
    """
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime and os.path.isdir(runtime) and os.access(runtime, os.W_OK):
        return Path(runtime) / "cush-infisical-token"
    cache = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    cache_dir = Path(cache) / "cush-tools"
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return cache_dir / "infisical-token"


_env_loaded = False


def _load_env_file() -> None:
    """Source INFISICAL_ENV_FILE (~/.config/porch/infisical.env) into os.environ.

    Idempotent — only reads the file once per process. Uses a minimal parser
    that handles `export KEY=VALUE` and `KEY=VALUE` lines, stripping single
    or double quotes around the value if present.
    """
    global _env_loaded
    if _env_loaded:
        return
    _env_loaded = True
    if not os.path.isfile(INFISICAL_ENV_FILE):
        return
    try:
        with open(INFISICAL_ENV_FILE, "r") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[len("export "):].lstrip()
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip()
                if (v.startswith("'") and v.endswith("'")) or (
                    v.startswith('"') and v.endswith('"')
                ):
                    v = v[1:-1]
                # Don't clobber a value already set in the env (caller may
                # have overridden it intentionally, e.g. for CI).
                os.environ.setdefault(k, v)
    except OSError:
        pass


def _mint_token() -> str:
    """Run `infisical login --method=universal-auth` and return the token.

    Raises InfAuthError on any failure.
    """
    cid = os.environ.get("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", "")
    csec = os.environ.get("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET", "")
    if not cid or not csec:
        raise InfAuthError(
            "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID / "
            "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET not set "
            f"(check {INFISICAL_ENV_FILE})"
        )
    try:
        proc = subprocess.run(
            [
                "infisical", "login",
                "--method=universal-auth",
                f"--client-id={cid}",
                f"--client-secret={csec}",
                "--silent", "--plain",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired as e:
        raise InfAuthError(
            "infisical universal-auth login timed out after 30s"
        ) from e
    # `infisical login --plain` prints just the token to stdout. Some
    # versions also emit a notice on stderr — tolerate that and use stdout.
    token = (proc.stdout or "").strip()
    if proc.returncode != 0 or not token:
        raise InfAuthError(
            "infisical universal-auth login failed: "
            f"{(proc.stderr or proc.stdout or 'unknown error').strip()}"
        )
    return token


def _read_cached_token() -> Optional[str]:
    """Return the token from the cache file, or None if absent/unreadable."""
    cache = _token_cache_path()
    try:
        with open(cache, "r") as f:
            tok = f.read().strip()
        return tok or None
    except OSError:
        return None


def _write_cached_token(token: str) -> None:
    """Atomically write the token to the cache file at chmod 600."""
    cache = _token_cache_path()
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    tmp = cache.with_suffix(cache.suffix + f".tmp.{os.getpid()}")
    try:
        # O_CREAT | O_EXCL would race with concurrent procs; use plain write
        # then chmod, then rename. The brief window where mode may be 0644
        # is on a tmpfs/private dir so the exposure is minimal.
        with open(tmp, "w") as f:
            f.write(token)
        os.chmod(tmp, 0o600)
        os.replace(tmp, cache)
    except OSError:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def _ensure_inf_available() -> None:
    """Raise InfAuthError if `infisical` is missing or login can't mint a token.

    Cached for the life of the process, mirroring op.py's _ensure_op_available.
    """
    global _inf_available_checked
    if _inf_available_checked:
        return
    if not shutil.which("infisical"):
        raise InfAuthError(
            "Infisical CLI (`infisical`) is not installed or not on PATH.\n"
            f"Install: {INFISICAL_INSTALL_URL}"
        )
    _load_env_file()
    if not os.environ.get("INFISICAL_PROJECT_ID"):
        raise InfAuthError(
            "INFISICAL_PROJECT_ID not set "
            f"(check {INFISICAL_ENV_FILE})"
        )
    # Validate by minting a token (or reusing a cached one) and probing.
    if _get_or_mint_token(force_refresh=False) is None:
        raise InfAuthError("infisical token mint failed")
    _inf_available_checked = True


def _get_or_mint_token(*, force_refresh: bool) -> Optional[str]:
    """Return a usable INFISICAL_TOKEN, minting fresh if needed.

    The cache is treated as authoritative until a call fails — _run_inf
    triggers force_refresh=True on auth-class failure and retries once,
    mirroring op.py's stale-session retry pattern.
    """
    if not force_refresh:
        cached = _read_cached_token()
        if cached:
            return cached
    try:
        tok = _mint_token()
    except InfAuthError:
        return None
    _write_cached_token(tok)
    return tok


# Stderr fragments classified by exception type.
_AUTH_MARKERS = (
    "unauthorized",
    "invalid token",
    "invalid credentials",
    "authentication failed",
    "401",
    "expired",
)
_NOTFOUND_MARKERS = (
    "not found",
    "404",
    "secret with name",
    "folder with path",
    "no secret found",
)
_ACCESS_MARKERS = (
    "permission",
    "forbidden",
    "403",
    "access denied",
    "not authorized",
)


def _classify_stderr(stderr: str) -> type:
    s = (stderr or "").lower()
    if any(m in s for m in _AUTH_MARKERS):
        return InfAuthError
    if any(m in s for m in _ACCESS_MARKERS):
        return InfAccessError
    if any(m in s for m in _NOTFOUND_MARKERS):
        return InfRefNotFound
    return InfError


def _run_once(argv: list, *, token: str, input_text: Optional[str] = None) -> subprocess.CompletedProcess:
    """Run an `infisical` subprocess with INFISICAL_TOKEN set in env.

    A 30s timeout is enforced on every call: the Infisical CLI can hang
    indefinitely when auth state is partially configured (e.g. Universal
    Auth env vars present but no token), and we'd rather fail loudly than
    block a migration / rollback forever.
    """
    env = os.environ.copy()
    env["INFISICAL_TOKEN"] = token
    try:
        return subprocess.run(
            argv,
            input=input_text,
            text=True,
            capture_output=True,
            env=env,
            timeout=30,
        )
    except subprocess.TimeoutExpired as e:
        raise InfError(
            f"infisical CLI call timed out after 30s: {' '.join(argv)}"
        ) from e


def _run_inf(argv: list, *, input_text: Optional[str] = None) -> subprocess.CompletedProcess:
    """Run an infisical subprocess, retrying once on auth-class failure with a fresh token.

    Mirrors op.py's _run pattern. If the first call fails with stderr that
    looks like an auth error, mint a fresh token, retry once.
    """
    token = _get_or_mint_token(force_refresh=False)
    if token is None:
        raise InfAuthError("infisical token unavailable")
    proc = _run_once(argv, token=token, input_text=input_text)
    if proc.returncode == 0:
        return proc
    if _classify_stderr(proc.stderr) is not InfAuthError:
        return proc
    fresh = _get_or_mint_token(force_refresh=True)
    if fresh is None:
        return proc
    return _run_once(argv, token=fresh, input_text=input_text)


# ───────────────────────────────────────────────────────────────────────────
# Public API
# ───────────────────────────────────────────────────────────────────────────


def inf_whoami() -> Optional[dict]:
    """Verify creds work. Returns a small status dict on success, None on failure.

    Side effect: triggers a token mint if not already cached. Doesn't raise —
    callers wanting strict auth checking should use _ensure_inf_available()
    and inspect this result.
    """
    if not shutil.which("infisical"):
        return None
    _load_env_file()
    project_id = os.environ.get("INFISICAL_PROJECT_ID")
    if not project_id:
        return None
    token = _get_or_mint_token(force_refresh=False)
    if token is None:
        return None
    # Probe with a low-cost listing on / of the dev env. Success means the
    # token is live and the project is accessible.
    proc = _run_once(
        [
            "infisical", "secrets",
            f"--projectId={project_id}",
            "--env=dev",
            "--path=/",
            "--plain", "--silent",
        ],
        token=token,
    )
    if proc.returncode != 0:
        # One refresh-and-retry: the cached token may be expired.
        token = _get_or_mint_token(force_refresh=True)
        if token is None:
            return None
        proc = _run_once(
            [
                "infisical", "secrets",
                f"--projectId={project_id}",
                "--env=dev",
                "--path=/",
                "--plain", "--silent",
            ],
            token=token,
        )
        if proc.returncode != 0:
            return None
    return {
        "project_id": project_id,
        "env_slug": "dev",
    }


_INF_REF_RE = re.compile(r"^inf://([^/]+)/(.+)$")


def parse_inf_ref(ref: str) -> tuple[str, str, str]:
    """Split `inf://<env>/<path...>/<KEY>` into (env, path, key).

    Path always starts with '/'. Requires at least 3 segments after `inf://`
    (so `inf://dev/KEY` raises — the path segment is required).

    Examples:
      inf://dev/myapp/DB_URL       -> ('dev', '/myapp', 'DB_URL')
      inf://dev/team/myapp/DB_URL  -> ('dev', '/team/myapp', 'DB_URL')
      inf://dev/DB_URL             -> ValueError
    """
    m = _INF_REF_RE.match(ref or "")
    if not m:
        raise ValueError(f"not a valid inf:// ref: {ref!r}")
    env = m.group(1)
    rest = m.group(2)
    parts = rest.split("/")
    if len(parts) < 2:
        # Only the key, no folder — explicitly disallowed by spec.
        raise ValueError(
            f"inf:// ref needs at least one path segment before the key: {ref!r}"
        )
    key = parts[-1]
    path = "/" + "/".join(parts[:-1])
    if not env or not key:
        raise ValueError(f"inf:// ref has empty env or key: {ref!r}")
    return env, path, key


def inf_read(ref: str) -> str:
    """Read a single inf://... ref and return its value.

    Raises InfRefNotFound / InfAuthError / InfAccessError / InfError.
    """
    _ensure_inf_available()
    env, path, key = parse_inf_ref(ref)
    project_id = os.environ["INFISICAL_PROJECT_ID"]
    # `secrets get` doesn't accept --type. Defaults to "shared" semantically;
    # disable secret-overriding so a personal-typed shadow doesn't surprise us.
    proc = _run_inf([
        "infisical", "secrets", "get", key,
        "--plain", "--silent",
        f"--projectId={project_id}",
        f"--env={env}",
        f"--path={path}",
        "--secret-overriding=false",
    ])
    if proc.returncode == 0:
        # Quirk: `infisical secrets get --plain` returns rc=0 with EMPTY
        # stdout when the secret doesn't exist (only the folder must exist).
        # Distinguish "secret missing" from "secret with empty value" by
        # re-querying without --plain and looking for the *not found*
        # marker that the table-mode rendering emits. Empty-string secrets
        # are vanishingly rare in practice, but we want correct behavior.
        out = (proc.stdout or "").rstrip("\n")
        if out:
            return out
        probe = _run_inf([
            "infisical", "secrets", "get", key,
            "--silent",
            f"--projectId={project_id}",
            f"--env={env}",
            f"--path={path}",
            "--secret-overriding=false",
        ])
        if probe.returncode == 0 and "*not found*" in (probe.stdout or ""):
            raise InfRefNotFound(
                f"infisical secrets get {ref} failed: secret not found"
            )
        # Genuine empty-string secret value.
        return out
    cls = _classify_stderr(proc.stderr)
    raise cls(f"infisical secrets get {ref} failed: {proc.stderr.strip() or 'unknown error'}")


def inf_list(env: str, path: str) -> list:
    """List the secret keys present at `inf://<env>/<path>`.

    Returns a sorted list of key names (strings). Returns an empty list when
    the folder exists but holds no secrets, or when the folder itself is
    missing (Infisical's `secrets` subcommand returns 0 + empty output for a
    non-existent path; we treat that as "nothing to clean up").

    Raises InfAuthError / InfAccessError / InfError on hard failures. The
    caller (cleanup logic) treats those as fatal and bails out.

    Implementation: shells out to `infisical secrets --plain` which prints
    one `KEY=VALUE` pair per line. We only parse the key half — values are
    discarded immediately and never logged.
    """
    _ensure_inf_available()
    project_id = os.environ["INFISICAL_PROJECT_ID"]
    if not path.startswith("/"):
        path = "/" + path
    proc = _run_inf([
        "infisical", "secrets",
        f"--projectId={project_id}",
        f"--env={env}",
        f"--path={path}",
        "--plain", "--silent",
    ])
    if proc.returncode != 0:
        # Folder-doesn't-exist looks like a "not found" — treat as empty.
        cls = _classify_stderr(proc.stderr)
        if cls is InfRefNotFound:
            return []
        raise cls(
            f"infisical secrets list at {env}:{path} failed: "
            f"{proc.stderr.strip() or 'unknown error'}"
        )
    keys = []
    for line in (proc.stdout or "").splitlines():
        line = line.rstrip("\n")
        if not line:
            continue
        # `infisical secrets --plain` prints `KEY=VALUE`. The KEY half is
        # everything before the first `=`. Tolerate values that themselves
        # contain `=` (the split is on the first one only).
        if "=" not in line:
            # Some CLI versions / no-value rows just print the key. Accept it.
            keys.append(line.strip())
            continue
        k = line.split("=", 1)[0].strip()
        if k:
            keys.append(k)
    return sorted(set(keys))


def inf_delete(env: str, path: str, key: str) -> None:
    """Delete the secret at `inf://<env>/<path>/<key>`.

    Idempotent-ish: a "not found" outcome is treated as success (the secret's
    already gone, which is what the caller wanted). Raises InfAuthError /
    InfAccessError / InfError on hard failures.

    Routes through `_run_inf` so we get token minting/caching, the auth-retry
    pattern, and the 30s timeout from `_run_once`. Mirrors the rollback path
    in lib/migrate.py — kept here as a public helper so cleanup logic can
    reach it without reaching into private `_run_inf`.
    """
    _ensure_inf_available()
    project_id = os.environ["INFISICAL_PROJECT_ID"]
    if not path.startswith("/"):
        path = "/" + path
    proc = _run_inf([
        "infisical", "secrets", "delete", key,
        f"--projectId={project_id}",
        f"--env={env}",
        f"--path={path}",
        "--type=shared",
        "--silent",
    ])
    if proc.returncode == 0:
        return
    # Already-gone is fine.
    cls = _classify_stderr(proc.stderr)
    if cls is InfRefNotFound:
        return
    raise cls(
        f"infisical secrets delete {env}:{path}/{key} failed: "
        f"{proc.stderr.strip() or 'unknown error'}"
    )


def _ensure_folder(env: str, path: str, project_id: str) -> None:
    """Idempotently create the folder at `path` (and any missing parents) under env.

    `infisical secrets folders create -p <parent> -n <name>` creates one
    folder; we recurse to handle nested paths. Already-exists errors are
    swallowed (the CLI prints them on stderr, we re-list to detect the case).
    """
    if path == "/" or not path:
        return
    parts = [p for p in path.strip("/").split("/") if p]
    cur = ""
    for name in parts:
        parent = "/" + cur if cur else "/"
        proc = _run_inf([
            "infisical", "secrets", "folders", "create",
            "-p", parent,
            "-n", name,
            f"--projectId={project_id}",
            f"--env={env}",
            "--silent",
        ])
        if proc.returncode != 0:
            stderr_lower = (proc.stderr or "").lower()
            # Already-exists is fine; anything else propagates.
            if "already exists" not in stderr_lower and "duplicate" not in stderr_lower:
                cls = _classify_stderr(proc.stderr)
                raise cls(
                    f"infisical folders create {parent}/{name} failed: "
                    f"{proc.stderr.strip() or 'unknown error'}"
                )
        cur = (cur + "/" + name) if cur else name


def inf_item_upsert(ref: str, value: str, *, concealed: bool = True) -> None:
    """Idempotently set the secret at `ref` to `value`.

    Strategy:
      1. Parse ref into (env, path, key).
      2. Ensure the folder at `path` exists (recursive create — Infisical
         requires a parent folder for set; missing folder yields 404).
      3. Run `infisical secrets set KEY=VALUE --type=shared ...`. The value
         is passed via --file (a temp file at chmod 600), not argv, so the
         plaintext doesn't appear in /proc/<pid>/cmdline.

    `concealed` is accepted for API parity with op_item_upsert but Infisical
    has no equivalent toggle — secrets are uniformly concealed.
    """
    _ensure_inf_available()
    env, path, key = parse_inf_ref(ref)
    project_id = os.environ["INFISICAL_PROJECT_ID"]

    _ensure_folder(env, path, project_id)

    # Pass value via --file to avoid leaking on argv. The CLI's --file expects
    # dotenv format (KEY=VALUE per line). Use mkstemp for a chmod-600 tempfile.
    import tempfile
    fd, tmp_path = tempfile.mkstemp(prefix="cush-inf-set-", suffix=".env")
    try:
        os.fchmod(fd, 0o600)
        # Quote the value as a single-quoted dotenv to handle newlines, =, etc.
        # Single-quoted dotenv: foo'bar -> 'foo'\''bar'.
        quoted = "'" + value.replace("'", "'\\''") + "'"
        with os.fdopen(fd, "w") as f:
            f.write(f"{key}={quoted}\n")
        proc = _run_inf([
            "infisical", "secrets", "set",
            "--type=shared",
            f"--projectId={project_id}",
            f"--env={env}",
            f"--path={path}",
            "--file", tmp_path,
            "--silent",
        ])
    finally:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass

    if proc.returncode == 0:
        return
    cls = _classify_stderr(proc.stderr)
    raise cls(
        f"infisical secrets set {ref} failed: "
        f"{proc.stderr.strip() or 'unknown error'}"
    )


# ───────────────────────────────────────────────────────────────────────────
# CLI entrypoint (smoke test)
# ───────────────────────────────────────────────────────────────────────────


def _main(argv: list) -> int:
    if len(argv) < 2:
        print("usage: infisical.py {whoami|read <ref>}", file=sys.stderr)
        return 2
    cmd = argv[1]
    try:
        if cmd == "whoami":
            who = inf_whoami()
            if who is None:
                print("not authenticated", file=sys.stderr)
                return 3
            import json
            print(json.dumps(who, indent=2))
            return 0
        if cmd == "read":
            if len(argv) < 3:
                print("usage: infisical.py read <ref>", file=sys.stderr)
                return 2
            print(inf_read(argv[2]))
            return 0
        print(f"unknown subcommand: {cmd}", file=sys.stderr)
        return 2
    except InfAuthError as e:
        print(f"[infisical] auth: {e}", file=sys.stderr)
        return 3
    except InfRefNotFound as e:
        print(f"[infisical] not-found: {e}", file=sys.stderr)
        return 6
    except InfAccessError as e:
        print(f"[infisical] access: {e}", file=sys.stderr)
        return 4
    except InfError as e:
        print(f"[infisical] error: {e}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(_main(sys.argv))

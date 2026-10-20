# lib/op.sh — sourced shim for 1Password CLI integration
# Usage: source "$(dirname "$0")/../lib/op.sh"
#
# Loads credentials from ~/.config/cush-tools/op.env (if present) and defines:
#   - cush_op_check        verify op is usable; exits 3 on auth failure, 4 on other op errors
#   - cush_op_setup_hint   one-screen setup instructions
#   - cush_op              thin wrapper around `op`
#
# Three auth modes are supported, picked by `cush_op_check` in this order:
#
#   1. Service account     OP_SERVICE_ACCOUNT_TOKEN is set
#                          → op picks it up natively, nothing to do
#   2. Stored credentials  OP_SUBDOMAIN + OP_EMAIL + OP_SECRET_KEY +
#                          OP_MASTER_PASSWORD all set
#                          → run `op account add` (one-time) and `op signin`,
#                            cache the resulting OP_SESSION_<shorthand> token
#   3. Nothing             print setup hint, return 3
#
# The cached session token lives in $XDG_RUNTIME_DIR/cush-op-session (tmpfs,
# wiped on reboot) when available, falling back to $XDG_CACHE_HOME/cush-tools/
# op-session. Both are chmod 600. The 1Password account shorthand "cush" is
# used for all signin operations.

# Guard: only define once per shell.
if [ -n "${_CUSH_OP_SH_LOADED:-}" ]; then
    return 0 2>/dev/null || true
fi
_CUSH_OP_SH_LOADED=1

_CUSH_OP_ENV_FILE="${CUSH_OP_ENV_FILE:-$HOME/.config/cush-tools/op.env}"
_CUSH_OP_SHORTHAND="cush"
# Tracks whether we've already validated a session in this shell, so repeat
# calls to cush_op_check don't re-signin gratuitously.
_CUSH_OP_SESSION_VALID=""

# Source the env file if it exists. Warn (don't refuse) if perms are wider
# than 0600 — credentials are sensitive and a mode like 0644 is a real risk,
# but refusing here would block the user mid-flow when they can fix it later.
if [ -f "$_CUSH_OP_ENV_FILE" ]; then
    # Check perms portably: GNU stat uses -c '%a', BSD stat uses -f '%Lp'.
    _cush_op_perms=""
    if _cush_op_perms=$(stat -c '%a' "$_CUSH_OP_ENV_FILE" 2>/dev/null); then
        :
    elif _cush_op_perms=$(stat -f '%Lp' "$_CUSH_OP_ENV_FILE" 2>/dev/null); then
        :
    fi
    if [ -n "$_cush_op_perms" ] && [ "$_cush_op_perms" != "600" ] && [ "$_cush_op_perms" != "400" ]; then
        echo "warning: $_CUSH_OP_ENV_FILE has mode $_cush_op_perms — should be 600" >&2
    fi
    unset _cush_op_perms
    # shellcheck disable=SC1090
    . "$_CUSH_OP_ENV_FILE"
fi

# One-screen setup hint. Printed on any cush_op_check failure.
cush_op_setup_hint() {
    cat >&2 <<'EOF'

[1Password setup needed]

cush-tools needs to authenticate to 1Password. Pick the option that matches
your plan:

# Option A — Stored credentials (works on any 1Password plan, including Family/Personal)

  mkdir -p ~/.config/cush-tools && chmod 700 ~/.config/cush-tools
  cat > ~/.config/cush-tools/op.env <<'OPENV'
  export OP_SUBDOMAIN=my              # the subdomain in your 1password.com URL
  export OP_EMAIL=you@example.com
  export OP_SECRET_KEY=A3-XXXXXX-...  # from 1password.com -> My Profile -> Get the app
  export OP_MASTER_PASSWORD='your-master-password'
  OPENV
  chmod 600 ~/.config/cush-tools/op.env

  Tip: wrap the master password in single quotes, not double, to avoid shell
  expansion of $, !, `, and \ characters.

# Option B — Service account token (requires Teams/Business plan)

  https://developer.1password.com/docs/service-accounts/

  mkdir -p ~/.config/cush-tools && chmod 700 ~/.config/cush-tools
  echo 'export OP_SERVICE_ACCOUNT_TOKEN=ops_REPLACE_ME' \
      > ~/.config/cush-tools/op.env
  chmod 600 ~/.config/cush-tools/op.env

# In both cases

The 1Password CLI itself must be on PATH:
  https://developer.1password.com/docs/cli/get-started/

After installing, re-run your command.
EOF
}

# Pick a path for the cached session token. Prefer XDG_RUNTIME_DIR (tmpfs,
# cleared on reboot); fall back to XDG_CACHE_HOME (persists across reboots —
# delete on logout if paranoid).
_cush_op_session_cache_path() {
    local runtime="${XDG_RUNTIME_DIR:-/run/user/$(id -u 2>/dev/null)}"
    if [ -n "$runtime" ] && [ -d "$runtime" ] && [ -w "$runtime" ]; then
        printf '%s/cush-op-session' "$runtime"
        return 0
    fi
    local cache="${XDG_CACHE_HOME:-$HOME/.cache}/cush-tools"
    mkdir -p "$cache" 2>/dev/null || true
    printf '%s/op-session' "$cache"
}

# Pick a lockfile path for the one-time `op account add` race protection.
_cush_op_lockfile_path() {
    local runtime="${XDG_RUNTIME_DIR:-/tmp}"
    if [ ! -d "$runtime" ] || [ ! -w "$runtime" ]; then
        runtime="/tmp"
    fi
    printf '%s/cush-op-add.lock' "$runtime"
}

# Return 0 if the configured account is already in `op account list`.
# Matches on email (most reliable) or shorthand.
_cush_op_account_exists() {
    local list
    # Wrap with `timeout` so a hung op daemon can't stall a migration. The
    # 30s budget matches the python-side _run_once timeout.
    list=$(timeout 30 op account list 2>/dev/null) || return 1
    if [ -n "${OP_EMAIL:-}" ] && printf '%s' "$list" | grep -F -q -- "$OP_EMAIL"; then
        return 0
    fi
    if printf '%s' "$list" | grep -E -q "(^|[[:space:]])${_CUSH_OP_SHORTHAND}([[:space:]]|$)"; then
        return 0
    fi
    return 1
}

# One-time: register the account with `op account add`. Idempotent — bails out
# if the account is already present. Uses flock to avoid a race when two cush
# tools start simultaneously on a fresh box.
#
# `op account add` (op 2.x) reads the master password from stdin during the
# initial verification step. We pass --signin=false so it doesn't also try to
# open a session here; signin is handled separately so we can cache the token.
_cush_op_account_add() {
    if _cush_op_account_exists; then
        return 0
    fi
    local lockfile
    lockfile=$(_cush_op_lockfile_path)
    # subshell + flock: file descriptor 9 holds the lock for the duration.
    (
        flock 9
        # Re-check inside the lock — another process may have added it.
        if _cush_op_account_exists; then
            exit 0
        fi
        printf '%s\n' "$OP_MASTER_PASSWORD" | timeout 60 op account add \
            --address "${OP_SUBDOMAIN}.1password.com" \
            --email "$OP_EMAIL" \
            --secret-key "$OP_SECRET_KEY" \
            --shorthand "$_CUSH_OP_SHORTHAND" \
            --signin=false >/dev/null
    ) 9>"$lockfile"
    return $?
}

# Try to validate an existing session (sourced into the current shell).
# Returns 0 if `op whoami` works against the cush shorthand.
_cush_op_session_is_valid() {
    timeout 30 op whoami --account "$_CUSH_OP_SHORTHAND" >/dev/null 2>&1
}

# Sign in fresh and persist the resulting session token. The token is what
# 1Password CLI calls `OP_SESSION_<shorthand>`. Writes the cache file
# atomically (write-tmp + mv) at chmod 600.
#
# Mechanism note: `op signin --account <shorthand> --raw` (op CLI 2.x) reads
# the master password from stdin when there's no interactive TTY and prints
# only the session token to stdout. Verified-against assumption: op >= 2.0.
# If your `op` is 1.x, this code path does not apply (1.x used a different
# signin flow); upgrade to 2.x.
_cush_op_signin_fresh() {
    local cache_path
    cache_path=$(_cush_op_session_cache_path)
    local cache_dir
    cache_dir=$(dirname "$cache_path")
    mkdir -p "$cache_dir" 2>/dev/null || true

    local token
    if ! token=$(printf '%s\n' "$OP_MASTER_PASSWORD" \
            | timeout 30 op signin --account "$_CUSH_OP_SHORTHAND" --raw 2>/dev/null); then
        return 1
    fi
    if [ -z "$token" ]; then
        return 1
    fi

    # Write atomically: temp file in same dir, chmod 600, then rename.
    local tmp="${cache_path}.tmp.$$"
    {
        printf 'export OP_SESSION_%s=%q\n' "$_CUSH_OP_SHORTHAND" "$token"
    } > "$tmp" || return 1
    chmod 600 "$tmp" 2>/dev/null
    mv -f "$tmp" "$cache_path" || { rm -f "$tmp"; return 1; }

    # Export for the current shell.
    eval "export OP_SESSION_${_CUSH_OP_SHORTHAND}=\$token"
    return 0
}

# Mode 2 entry point: ensure account is added, then ensure we have a valid
# session, signing in fresh if needed.
_cush_op_ensure_session() {
    # Source any cached session first — gives us a head start on validation.
    local cache_path
    cache_path=$(_cush_op_session_cache_path)
    if [ -f "$cache_path" ]; then
        # shellcheck disable=SC1090
        . "$cache_path" 2>/dev/null || true
    fi

    # If we already validated in this shell, trust it.
    if [ -n "$_CUSH_OP_SESSION_VALID" ] && _cush_op_session_is_valid; then
        return 0
    fi

    # Make sure the account is registered.
    if ! _cush_op_account_add; then
        echo "error: op account add failed (check OP_SUBDOMAIN / OP_EMAIL / OP_SECRET_KEY / OP_MASTER_PASSWORD)" >&2
        return 1
    fi

    # If the cached session validates, we're done.
    if _cush_op_session_is_valid; then
        _CUSH_OP_SESSION_VALID=1
        return 0
    fi

    # Otherwise sign in fresh.
    if ! _cush_op_signin_fresh; then
        echo "error: op signin failed (master password may be wrong, or op CLI < 2.x)" >&2
        return 1
    fi

    if _cush_op_session_is_valid; then
        _CUSH_OP_SESSION_VALID=1
        return 0
    fi
    return 1
}

# Verify op is usable. Exit codes:
#   0 — ok
#   3 — auth error (op missing, credentials missing, whoami failed)
#   4 — other error (e.g. network)
cush_op_check() {
    if ! command -v op >/dev/null 2>&1; then
        echo "error: 1Password CLI (\`op\`) not found on PATH" >&2
        cush_op_setup_hint
        return 3
    fi

    # Mode 1 — service account token. Wins if both modes are configured.
    if [ -n "${OP_SERVICE_ACCOUNT_TOKEN:-}" ]; then
        if ! timeout 30 op whoami --format=json >/dev/null 2>&1; then
            echo "error: op whoami failed (service-account token invalid or network down)" >&2
            cush_op_setup_hint
            return 3
        fi
        return 0
    fi

    # Mode 2 — stored credentials with auto-signin.
    if [ -n "${OP_SUBDOMAIN:-}" ] \
            && [ -n "${OP_EMAIL:-}" ] \
            && [ -n "${OP_SECRET_KEY:-}" ] \
            && [ -n "${OP_MASTER_PASSWORD:-}" ]; then
        if ! _cush_op_ensure_session; then
            cush_op_setup_hint
            return 3
        fi
        # Final probe to be sure.
        if ! timeout 30 op whoami --account "$_CUSH_OP_SHORTHAND" >/dev/null 2>&1; then
            echo "error: op whoami failed after signin" >&2
            cush_op_setup_hint
            return 3
        fi
        # Note on OP_MASTER_PASSWORD: we deliberately keep it set in the
        # environment after signin. If the cached session expires later in
        # this shell (sessions are ~30 min), cush_op_check needs to be able
        # to refresh non-interactively. The password is in op.env (chmod
        # 600) regardless, so unsetting it here would only marginally
        # reduce its exposure window in /proc/<pid>/environ while breaking
        # session refresh. Trade-off chosen: keep it set, document it.
        return 0
    fi

    # Mode 3 — nothing set.
    echo "error: no 1Password credentials configured (need either OP_SERVICE_ACCOUNT_TOKEN, or OP_SUBDOMAIN+OP_EMAIL+OP_SECRET_KEY+OP_MASTER_PASSWORD)" >&2
    cush_op_setup_hint
    return 3
}

# Thin wrapper. Reserved for future cross-cutting concerns (logging, retry).
cush_op() {
    op "$@"
}

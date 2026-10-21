# lib/infisical.sh — sourced shim for Infisical CLI integration
# Usage: source "$(dirname "$0")/../lib/infisical.sh"
#
# Loads credentials from ~/.config/porch/infisical.env (or the pre-rename
# ~/.config/cush-tools/infisical.env; chmod 600) and
# defines:
#   - cush_infisical_check        verify infisical is usable; exit 3 on auth
#                                 failure, 4 on other infisical errors
#   - cush_infisical_setup_hint   one-screen setup instructions
#   - cush_infisical              thin wrapper around `infisical` (with token)
#
# Auth model (machine identity, universal-auth):
#
#   1. Read ~/.config/porch/infisical.env which sets:
#        - INFISICAL_PROJECT_ID
#        - INFISICAL_UNIVERSAL_AUTH_CLIENT_ID
#        - INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET
#   2. If we have a cached token at $XDG_RUNTIME_DIR/cush-infisical-token
#      (or $XDG_CACHE_HOME/cush-tools/infisical-token), try it first.
#   3. If the cached token doesn't validate (or doesn't exist), mint a new
#      one via `infisical login --method=universal-auth --client-id=... \
#      --client-secret=... --silent --plain` and persist it.
#   4. Subsequent calls export INFISICAL_TOKEN from the cache so child
#      `infisical` invocations inherit it.

# Guard: only define once per shell.
if [ -n "${_CUSH_INFISICAL_SH_LOADED:-}" ]; then
    return 0 2>/dev/null || true
fi
_CUSH_INFISICAL_SH_LOADED=1

# shellcheck disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/porch-user-config.sh"
# PORCH_INFISICAL_ENV_FILE wins; CUSH_INFISICAL_ENV_FILE is its old name.
_CUSH_INFISICAL_ENV_FILE="${PORCH_INFISICAL_ENV_FILE:-${CUSH_INFISICAL_ENV_FILE:-$(porch_user_config_file infisical.env)}}"
# Tracks whether we've already validated a token in this shell.
_CUSH_INFISICAL_TOKEN_VALID=""

# Source the env file if it exists. Warn (don't refuse) if perms are wider
# than 0600 — credentials are sensitive and a mode like 0644 is a real risk,
# but refusing here would block the user mid-flow when they can fix it later.
if [ -f "$_CUSH_INFISICAL_ENV_FILE" ]; then
    _cush_inf_perms=""
    if _cush_inf_perms=$(stat -c '%a' "$_CUSH_INFISICAL_ENV_FILE" 2>/dev/null); then
        :
    elif _cush_inf_perms=$(stat -f '%Lp' "$_CUSH_INFISICAL_ENV_FILE" 2>/dev/null); then
        :
    fi
    if [ -n "$_cush_inf_perms" ] && [ "$_cush_inf_perms" != "600" ] && [ "$_cush_inf_perms" != "400" ]; then
        echo "warning: $_CUSH_INFISICAL_ENV_FILE has mode $_cush_inf_perms — should be 600" >&2
    fi
    unset _cush_inf_perms
    # shellcheck disable=SC1090
    . "$_CUSH_INFISICAL_ENV_FILE"
fi

# One-screen setup hint. Printed on any cush_infisical_check failure.
cush_infisical_setup_hint() {
    cat >&2 <<'EOF'

[Infisical setup needed]

Porch needs to authenticate to Infisical. Use a machine identity with
universal-auth:

  1. Install the CLI:
       https://infisical.com/docs/cli/overview

  2. Create a machine identity in your Infisical project, scoped to the
     environments/paths Porch should access. Capture its
     CLIENT_ID and CLIENT_SECRET.

  3. Drop credentials in ~/.config/porch/infisical.env (chmod 600):

       mkdir -p ~/.config/porch && chmod 700 ~/.config/porch
       cat > ~/.config/porch/infisical.env <<'INFENV'
       export INFISICAL_PROJECT_ID=your_project_id_here
       export INFISICAL_UNIVERSAL_AUTH_CLIENT_ID=your_client_id_here
       export INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET=your_client_secret_here
       INFENV
       chmod 600 ~/.config/porch/infisical.env

After that, re-run your command.
EOF
}

# Pick a path for the cached token. Prefer XDG_RUNTIME_DIR (tmpfs, cleared
# on reboot); fall back to XDG_CACHE_HOME.
_cush_infisical_token_path() {
    local runtime="${XDG_RUNTIME_DIR:-/run/user/$(id -u 2>/dev/null)}"
    if [ -n "$runtime" ] && [ -d "$runtime" ] && [ -w "$runtime" ]; then
        printf '%s/cush-infisical-token' "$runtime"
        return 0
    fi
    local cache="${XDG_CACHE_HOME:-$HOME/.cache}/cush-tools"
    mkdir -p "$cache" 2>/dev/null || true
    printf '%s/infisical-token' "$cache"
}

# Try to validate the current INFISICAL_TOKEN by listing the dev env root.
# Returns 0 on success.
_cush_infisical_token_is_valid() {
    [ -n "${INFISICAL_TOKEN:-}" ] || return 1
    [ -n "${INFISICAL_PROJECT_ID:-}" ] || return 1
    infisical secrets \
        --projectId="$INFISICAL_PROJECT_ID" \
        --env=dev \
        --path=/ \
        --plain --silent >/dev/null 2>&1
}

# Mint a fresh universal-auth token and persist it.
# Writes the cache file atomically (write-tmp + mv) at chmod 600.
_cush_infisical_signin_fresh() {
    local cache_path
    cache_path=$(_cush_infisical_token_path)
    local cache_dir
    cache_dir=$(dirname "$cache_path")
    mkdir -p "$cache_dir" 2>/dev/null || true

    if [ -z "${INFISICAL_UNIVERSAL_AUTH_CLIENT_ID:-}" ] \
            || [ -z "${INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET:-}" ]; then
        return 1
    fi

    local token
    if ! token=$(infisical login \
            --method=universal-auth \
            --client-id="$INFISICAL_UNIVERSAL_AUTH_CLIENT_ID" \
            --client-secret="$INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET" \
            --silent --plain 2>/dev/null); then
        return 1
    fi
    if [ -z "$token" ]; then
        return 1
    fi

    local tmp="${cache_path}.tmp.$$"
    printf '%s' "$token" > "$tmp" || return 1
    chmod 600 "$tmp" 2>/dev/null
    mv -f "$tmp" "$cache_path" || { rm -f "$tmp"; return 1; }

    export INFISICAL_TOKEN="$token"
    return 0
}

# Ensure we have a usable INFISICAL_TOKEN. Sources the cache if present and
# valid, otherwise mints a fresh token.
_cush_infisical_ensure_token() {
    local cache_path
    cache_path=$(_cush_infisical_token_path)
    if [ -z "${INFISICAL_TOKEN:-}" ] && [ -f "$cache_path" ]; then
        INFISICAL_TOKEN=$(cat "$cache_path" 2>/dev/null)
        export INFISICAL_TOKEN
    fi

    if [ -n "$_CUSH_INFISICAL_TOKEN_VALID" ] && _cush_infisical_token_is_valid; then
        return 0
    fi

    if _cush_infisical_token_is_valid; then
        _CUSH_INFISICAL_TOKEN_VALID=1
        return 0
    fi

    if ! _cush_infisical_signin_fresh; then
        echo "error: infisical universal-auth login failed (check INFISICAL_UNIVERSAL_AUTH_CLIENT_ID / INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET)" >&2
        return 1
    fi

    if _cush_infisical_token_is_valid; then
        _CUSH_INFISICAL_TOKEN_VALID=1
        return 0
    fi
    return 1
}

# Verify infisical is usable. Exit codes:
#   0 — ok
#   3 — auth error (cli missing, env file missing, login failed)
#   4 — other error (e.g. network)
cush_infisical_check() {
    if ! command -v infisical >/dev/null 2>&1; then
        echo "error: Infisical CLI (\`infisical\`) not found on PATH" >&2
        cush_infisical_setup_hint
        return 3
    fi

    if [ ! -f "$_CUSH_INFISICAL_ENV_FILE" ]; then
        echo "error: $_CUSH_INFISICAL_ENV_FILE not found" >&2
        cush_infisical_setup_hint
        return 3
    fi

    if [ -z "${INFISICAL_PROJECT_ID:-}" ] \
            || [ -z "${INFISICAL_UNIVERSAL_AUTH_CLIENT_ID:-}" ] \
            || [ -z "${INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET:-}" ]; then
        echo "error: missing INFISICAL_PROJECT_ID / INFISICAL_UNIVERSAL_AUTH_CLIENT_ID / INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET" >&2
        cush_infisical_setup_hint
        return 3
    fi

    if ! _cush_infisical_ensure_token; then
        cush_infisical_setup_hint
        return 4
    fi

    return 0
}

# Thin wrapper. Reserved for future cross-cutting concerns (logging, retry).
cush_infisical() {
    infisical "$@"
}

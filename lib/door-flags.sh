# door-flags.sh — the expiry / share-rule flags every door launcher accepts.
# Sourced by lib/tunnel-state.sh. Parsing and validation live in one place:
# lib/door_state.py (time parsing, scrypt hashing, guest tokens).
#
#   --expires 30m|2h|1d|<ISO-8601 time>|never   (default: 1 hour)
#   --password        PORCH_DOOR_PASSWORD, else a prompt on the terminal.
#                     Never argv; never stdin (paste/exchange read content there).
#   --guest-link      a ?k=<token> link that lets its holder in
#   --max-opens N     the door closes after N page views
#   --burn            = --max-opens 1
#   --inspect         record every request (lib/inspect_store.py; secret headers
#                     masked) and put the door proxy in front even without rules
#   --inspect-raw     the same, unmasked (a warning is printed)
#   --reopen          open a closed door again from its launch recipe
#                     (lib/door_recipe.py): its rules come from the recipe, not
#                     the command line; only --expires may go with it
#
# Usage in a launcher:
#   door_flags_parse "$@" || exit 2; set -- "${DOOR_REST[@]}"
#   ...
#   door_spec_build "$BG_MODE" "$NAME" || exit 2   # before the --bg block
#   ...
#   door_recipe_write "$NAME" <type> [--path F] [--flag F]... [--owned F]
#   tunnel_state_register ...                 # writes expires + rules
#   door_print_summary "$NAME"
#
# The spec (expiry as an epoch, rules with the password HASH only) travels in
# the shell variable _PORCH_DOOR_SPEC. It is exported only across the --bg
# re-exec (daemonize passes env, not argv), and un-exported everywhere else so
# the app server and frpc never inherit it.

_DOOR_LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOOR_REST=()
DOOR_FLAG_ARGS=()
DOOR_REOPEN=""

door_flags_parse() {
    DOOR_REST=()
    DOOR_FLAG_ARGS=()
    DOOR_REOPEN=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --expires|--max-opens)
                if [ $# -lt 2 ] || [ -z "$2" ]; then
                    echo "Error: $1 needs a value" >&2
                    return 2
                fi
                DOOR_FLAG_ARGS+=("$1" "$2")
                shift 2
                continue
                ;;
            --expires=*|--max-opens=*)
                DOOR_FLAG_ARGS+=("${1%%=*}" "${1#*=}") ;;
            --password|--guest-link|--burn|--inspect|--inspect-raw)
                DOOR_FLAG_ARGS+=("$1") ;;
            --reopen)
                DOOR_REOPEN=1 ;;
            --password=*)
                echo "Error: --password takes no value on the command line (it would show in ps)." >&2
                echo "       Set PORCH_DOOR_PASSWORD or type it at the prompt." >&2
                return 2
                ;;
            *)
                DOOR_REST+=("$1") ;;
        esac
        shift
    done
    return 0
}

# $1: non-empty when this process is about to daemonize (--bg, not yet re-exec'd).
# $2: the door name (needed by --reopen, which reads the door's recipe).
door_spec_build() {
    local bg="${1:-}" name="${2:-}"
    if [ -n "$DOOR_REOPEN" ]; then
        # Rules come from the recipe only; a flag that changes them would be
        # a different door. --expires picks how long it stays open (1h default).
        local exp="1h" i
        for ((i = 0; i < ${#DOOR_FLAG_ARGS[@]}; i++)); do
            if [ "${DOOR_FLAG_ARGS[$i]}" = "--expires" ]; then
                exp="${DOOR_FLAG_ARGS[$((i + 1))]}"; i=$((i + 1))
            else
                echo "Error: --reopen takes the door's own rules; only --expires goes with it" >&2
                return 2
            fi
        done
        if [ -z "$name" ]; then
            echo "Error: this launcher can't --reopen" >&2
            return 2
        fi
        local spec
        spec="$(python3 "$_DOOR_LIB/door_recipe.py" spec "$name" --expires "$exp")" || return 2
        _PORCH_DOOR_SPEC="$spec"
    elif [ "${#DOOR_FLAG_ARGS[@]}" -gt 0 ]; then
        local spec
        spec="$(python3 "$_DOOR_LIB/door_state.py" spec "${DOOR_FLAG_ARGS[@]}")" || return 2
        _PORCH_DOOR_SPEC="$spec"
    elif [ "${_CUSH_DAEMONIZED:-}" != "1" ]; then
        # Only a --bg re-exec of ourselves may hand a spec in through env.
        _PORCH_DOOR_SPEC=""
    fi
    unset PORCH_DOOR_PASSWORD
    if [ -n "$bg" ] && [ "${_CUSH_DAEMONIZED:-}" != "1" ] && [ -n "$_PORCH_DOOR_SPEC" ]; then
        export _PORCH_DOOR_SPEC
    else
        export -n _PORCH_DOOR_SPEC 2>/dev/null || true
    fi
    return 0
}

# Print expiry, rules and the guest link (only when door flags were given).
# A daemon's stdout is its log file: the guest token stays out of it.
door_print_summary() {
    [ -n "${_PORCH_DOOR_SPEC:-}" ] || return 0
    local tok=""
    [ "${_CUSH_DAEMONIZED:-}" = "1" ] && tok="--no-token"
    _PORCH_DOOR_SPEC="$_PORCH_DOOR_SPEC" python3 "$_DOOR_LIB/door_state.py" summary "$1" $tok
}

# Exit 0 when the door's state file has share rules.
door_has_rules() {
    python3 "$_DOOR_LIB/door_state.py" has-rules "$1" 2>/dev/null
}

# Exit 0 when the door needs lib/doorproxy.py: share rules, the inspector, or
# a capture-only hook.
door_needs_proxy() {
    python3 "$_DOOR_LIB/door_state.py" needs-proxy "$1" 2>/dev/null
}

# The doorproxy flags the state file asks for (--inspect, --inspect-raw,
# --capture), one per line.
door_proxy_args() {
    python3 "$_DOOR_LIB/door_state.py" proxy-args "$1" 2>/dev/null
}

# Write the door's launch recipe (lib/door_recipe.py: data/doors/<name>.json)
# so it can be reopened after it closes. Call it in the process that runs the
# door, right before tunnel_state_register. Never fails the launch.
# Usage: door_recipe_write <name> <type> [--path F] [--flag F]... [--owned F] [--owned-dir D]
door_recipe_write() {
    local name="$1" type="$2"
    shift 2
    _PORCH_DOOR_SPEC="${_PORCH_DOOR_SPEC:-}" python3 "$_DOOR_LIB/door_recipe.py" write \
        --name "$name" --type "$type" --pid "$$" "$@" 2>/dev/null || true
}

# In a launcher's exit trap: "keep" when the door's owned files stay for a
# reopen (it expired or its owner closed it), else "shred" (burned or used
# up, or no recipe: delete them as before).
door_owned_release() {
    python3 "$_DOOR_LIB/door_recipe.py" release "$1" 2>/dev/null || echo shred
}

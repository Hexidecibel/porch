# tunnel-state.sh — sourced library for tunnel state management and timeouts
# Usage: source "$(dirname "$0")/../lib/tunnel-state.sh"

TUNNEL_STATE_DIR="/tmp/tunnel-state"

# Domain config: PORCH_TUNNEL_BASE, PORCH_AUTH_HOST, ... (see lib/porch-config.sh).
source "$(dirname "${BASH_SOURCE[0]}")/porch-config.sh"
# Door flags: --expires/--password/--guest-link/--max-opens/--burn (lib/door-flags.sh).
source "$(dirname "${BASH_SOURCE[0]}")/door-flags.sh"

# A tunnel name is a DNS label: it becomes <name>.<tunnel base>, a file at
# /tmp/tunnel-state/<name>.json, an frpc config at /tmp/frpc-<name>-XXXXX.toml,
# and (for drop/photos/media/music) a directory under $HOME. Anything outside
# the DNS-label charset either never worked as a subdomain or escapes those
# paths -- `../..` in a name walks the watchdog's `rm -rf` out of /tmp.
# Every launcher validates before it creates anything.
tunnel_name_is_valid() {
    case "$1" in
        *[!A-Za-z0-9-]*|""|-*|*-) return 1 ;;
    esac
    [ "${#1}" -le 63 ]
}

# Validate or die. $2 is the label used in the error message ("name"/"label").
tunnel_require_valid_name() {
    if ! tunnel_name_is_valid "$1"; then
        printf 'Error: invalid %s: %s\n' "${2:-name}" "$1" >&2
        echo "Names must be 1-63 chars of [A-Za-z0-9-], not starting or ending with a hyphen." >&2
        exit 2
    fi
}

wait_for_port() {
    local port="$1" timeout="${2:-5}" elapsed=0
    while ! (echo >/dev/tcp/localhost/$port) 2>/dev/null; do
        sleep 0.1
        elapsed=$(echo "$elapsed + 0.1" | bc)
        if (( $(echo "$elapsed >= $timeout" | bc -l) )); then
            echo "Error: server failed to start on port $port within ${timeout}s" >&2
            return 1
        fi
    done
}

# Usage: tunnel_state_register <name> <type> <pid> <port> [flag...]
# Any trailing flags (e.g. media's --view-only) are recorded in the launch
# history so a revive can re-apply them even when the argv can't be read back.
# The door spec from door_spec_build (_PORCH_DOOR_SPEC: expires + rules, the
# password as a hash only) goes in through the environment, never argv; with
# none, the door expires in an hour and has no rules. The file is 0600: it
# can carry a password hash and a guest token.
tunnel_state_register() {
    local name="$1" type="$2" pid="$3" port="$4"
    shift 4
    local now
    now=$(date +%s)

    mkdir -p "$TUNNEL_STATE_DIR"
    # A new door under this name starts with fresh cookies and lock.
    rm -f "${TUNNEL_STATE_DIR}/.${name}.secret" "${TUNNEL_STATE_DIR}/.${name}.lock"

    ( umask 077
      _PORCH_DOOR_SPEC="${_PORCH_DOOR_SPEC:-}" python3 -c "
import json, os, sys
sys.path.insert(0, sys.argv[8])
import door_state
now = int(sys.argv[5])
try:
    spec = json.loads(os.environ.get('_PORCH_DOOR_SPEC') or '{}')
except ValueError:
    spec = {}
if not isinstance(spec, dict):
    spec = {}
expires = spec.get('expires', now + door_state.DEFAULT_TTL) if spec else now + door_state.DEFAULT_TTL
if expires is not None:
    expires = int(expires)
print(json.dumps({
    'name': sys.argv[1],
    'type': sys.argv[2],
    'pid': int(sys.argv[3]),
    'port': int(sys.argv[4]),
    'started': now,
    'expires': expires,
    'log': sys.argv[6],
    'daemonized': sys.argv[7] == 'true',
    'keep_alive': expires is None,
    'rules': door_state.clean_rules(spec.get('rules')),
    'opens': 0,
    'last_open': None,
    **({'inspect': door_state.clean_inspect(spec.get('inspect'))}
       if door_state.clean_inspect(spec.get('inspect')) else {}),
}, indent=2))
" "$name" "$type" "$pid" "$port" "$now" "${PORCH_LOG_FILE:-${CUSH_LOG_FILE:-}}" "$( [ -n "${_CUSH_DAEMONIZED:-}" ] && echo true || echo false )" "$_DOOR_LIB" > "${TUNNEL_STATE_DIR}/${name}.json.tmp" )

    # This launch's recipe (lib/door_recipe.py) puts its cookie key back, so a
    # reopened door keeps its sessions; a recipe left by an older door under
    # this name is dropped. Before the state file appears: the door proxy
    # starts after that and must find the key in place.
    python3 "$_DOOR_LIB/door_recipe.py" launched "$name" "$pid" 2>/dev/null || true

    mv "${TUNNEL_STATE_DIR}/${name}.json.tmp" "${TUNNEL_STATE_DIR}/${name}.json"

    # Record a launch-history line so the status API can revive a tunnel after
    # it expires. This step must NEVER fail the launch — wrap it defensively.
    (
        local _ts_dir
        _ts_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        # PORCH_HISTORY_FILE wins; CUSH_HISTORY_FILE is its old name.
        local _history_file="${PORCH_HISTORY_FILE:-${CUSH_HISTORY_FILE:-$_ts_dir/../data/history.jsonl}}"
        mkdir -p "$(dirname "$_history_file")"
        # history.jsonl records argv and cwd: owner-only. umask covers a fresh
        # file; the chmod below tightens one an older version left loose.
        umask 077
        python3 -c "
import json, os, sys

name, type_, pid, port, started, log_file, history_file = sys.argv[1:8]
flags = sys.argv[8:]
pid = int(pid)

# Capture the launch argv + cwd from /proc; fall back to [name, type] on failure.
cmd = None
cwd = ''
try:
    with open('/proc/%d/cmdline' % pid, 'rb') as f:
        raw = f.read()
    argv = [a.decode('utf-8', 'replace') for a in raw.split(b'\x00') if a]
    argv = [a for a in argv if a != '--bg']
    if argv:
        cmd = argv
except OSError:
    pass
try:
    cwd = os.readlink('/proc/%d/cwd' % pid)
except OSError:
    cwd = ''
if not cmd:
    cmd = [name, type_]

rec = {
    'event': 'start',
    'name': name,
    'type': type_,
    'port': int(port),
    'started': int(started),
    'cmd': cmd,
    'cwd': cwd,
    'log': log_file,
    'ts': int(started),
}
if flags:
    rec['flags'] = flags
fd = os.open(history_file, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
with os.fdopen(fd, 'a') as f:
    try:
        os.fchmod(f.fileno(), 0o600)
    except OSError:
        pass
    f.write(json.dumps(rec) + '\n')
" "$name" "$type" "$pid" "$port" "$now" "${PORCH_LOG_FILE:-${CUSH_LOG_FILE:-}}" "$_history_file" "$@"
    ) 2>/dev/null || true
}

# Daemonize: re-exec via a Python fork/setsid helper so the process survives
# parent shell death. Uses lib/daemonize.py instead of setsid(1) because
# macOS does not ship setsid (only GNU/Linux does).
# Usage: cush_daemonize <name> <log_file> <cmd> [args...]
# Returns 0 if daemon started successfully (caller should print URL and exit).
# The re-exec'd process has _CUSH_DAEMONIZED=1 set.
cush_daemonize() {
    local name="$1"
    local log_file="$2"
    shift 2

    mkdir -p "$(dirname "$log_file")"
    # daemonize.py opens the log 0600 (and fchmods an existing one); do it
    # here too so the file is never readable by others, even briefly.
    (umask 077; touch "$log_file") 2>/dev/null && chmod 600 "$log_file" 2>/dev/null

    # Locate the daemonize helper. This library is at lib/tunnel-state.sh,
    # so the helper is at ../lib/daemonize.py relative to this file.
    local _ts_dir
    _ts_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local daemonize_py="$_ts_dir/daemonize.py"

    if [ ! -f "$daemonize_py" ]; then
        echo "Error: missing $daemonize_py" >&2
        return 1
    fi

    export _CUSH_DAEMONIZED=1
    export PORCH_LOG_FILE="$log_file"
    # daemonize.py forks twice, setsid's, reopens std streams to $log_file,
    # then execvp's the command. Parent returns immediately after first fork.
    python3 "$daemonize_py" "$log_file" "$@"
    local rc=$?
    unset _CUSH_DAEMONIZED
    unset PORCH_LOG_FILE

    if [ "$rc" -ne 0 ]; then
        echo "Error: daemonize helper exited with status $rc" >&2
        return 1
    fi

    # Wait for state file to confirm startup (up to 8s)
    local state_file="${TUNNEL_STATE_DIR}/${name}.json"
    local elapsed=0
    while [ ! -f "$state_file" ] && [ "$elapsed" -lt 80 ]; do
        sleep 0.1
        elapsed=$((elapsed + 1))
    done

    if [ -f "$state_file" ]; then
        return 0
    else
        echo "Error: daemon failed to start. Check $log_file" >&2
        return 1
    fi
}

# PIDs whose executable NAME matches $1 (a glob: "frpc", "python*") and whose
# command line contains the literal string $2. Both conditions must hold, so a
# shell, editor or grep that merely mentions the strings is never returned —
# `pkill -f <substring>` alone has repeatedly killed exactly those.
cush_pids_for() {
    local want_comm="$1" needle="$2" pid cmdline comm
    for pid in $(pgrep -f "$needle" 2>/dev/null); do
        [ "$pid" = "$$" ] && continue
        comm="$(ps -o comm= -p "$pid" 2>/dev/null)"
        case "$comm" in
            $want_comm) ;;
            *) continue ;;
        esac
        if [ -r "/proc/$pid/cmdline" ]; then
            cmdline="$(tr '\0' ' ' < "/proc/$pid/cmdline")"
        else
            cmdline="$(ps -o args= -p "$pid" 2>/dev/null)"
        fi
        case "$cmdline" in
            *"$needle"*) printf '%s\n' "$pid" ;;
        esac
    done
}

# Kill only the frpc processes that belong to <name>: a real frpc binary whose
# command line names this tunnel's generated config.
# (bin/status carries an equivalent copy — it is deliberately standalone and
# does not source this library. Keep the two in sync.)
tunnel_kill_frpc() {
    local name="$1" pid arg suffix killed=1
    for pid in $(cush_pids_for 'frpc' "/tmp/frpc-${name}-"); do
        for arg in $(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null \
                     || ps -o args= -p "$pid" 2>/dev/null); do
            case "$arg" in
                "/tmp/frpc-${name}-"*.toml) ;;
                *) continue ;;
            esac
            # The mktemp suffix is one alphanumeric run — checking it stops
            # name "verifi" from matching verifi-sp's config.
            suffix="${arg#/tmp/frpc-${name}-}"
            suffix="${suffix%.toml}"
            case "$suffix" in
                ""|*[!A-Za-z0-9]*) continue ;;
            esac
            kill "$pid" 2>/dev/null && killed=0
            break
        done
    done
    return "$killed"
}

# Per-user private run dir for <tool> ($XDG_RUNTIME_DIR/porch/<tool>, or
# /tmp/porch-$UID/<tool>), resolved and verified by lib/rundir.py. Prints
# nothing (and returns non-zero) if the dir is unsafe or python fails, so
# callers must treat an empty result as "nothing to clean".
tunnel_run_dir() {
    local _ts_dir
    _ts_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    python3 "$_ts_dir/rundir.py" "$1" 2>/dev/null
}

tunnel_state_cleanup() {
    local name="$1"
    rm -f "${TUNNEL_STATE_DIR}/${name}.json" "${TUNNEL_STATE_DIR}/.${name}.lock" \
          "${TUNNEL_STATE_DIR}/.${name}.secret"
    # The request inspector's records (lib/inspect_store.py) go with the door.
    if tunnel_name_is_valid "$name"; then
        local _insp_dir
        _insp_dir="$(tunnel_run_dir inspect)"
        [ -n "$_insp_dir" ] && rm -f "${_insp_dir}/${name}.jsonl" "${_insp_dir}/${name}.sock"
    fi
}

tunnel_state_watchdog() {
    local name="$1"
    # Optional signal_file arg — secure-entry --save-to-op uses it to coordinate
    # with bin/inject; we sweep it on watchdog-driven cleanup.
    local signal_file="${2:-}"
    local state_file="${TUNNEL_STATE_DIR}/${name}.json"

    while true; do
        sleep 30

        # If state file is gone, exit
        [ -f "$state_file" ] || exit 0

        # Read keep_alive, expires, pid, type, and log from state file.
        # expires null = never (same as keep_alive).
        eval "$(python3 -c "
import json, sys, shlex
with open(sys.argv[1]) as f:
    s = json.load(f)
exp = s.get('expires')
print('_ka=%s' % ('true' if s.get('keep_alive') or exp is None else 'false'))
print('_expires=%d' % (int(exp) if exp is not None else 0))
print('_pid=%d' % s['pid'])
print('_type=%s' % shlex.quote(s.get('type', '')))
print('_log=%s' % shlex.quote(s.get('log', '')))
" "$state_file" 2>/dev/null)" || { tunnel_state_cleanup "$name"; exit 0; }

        # If PID is dead, cleanup and exit
        if ! kill -0 "$_pid" 2>/dev/null; then
            tunnel_state_cleanup "$name"
            exit 0
        fi

        # If keep_alive, skip timeout check
        [ "$_ka" = "true" ] && continue

        # If expired, kill the process, cleanup, exit
        local now
        now=$(date +%s)
        if [ "$now" -gt "$_expires" ]; then
            # Say why first: the launcher's exit trap then keeps a reopenable
            # door's files (lib/door_recipe.py).
            python3 "$_DOOR_LIB/door_recipe.py" closed "$name" expired \
                --state-file "$state_file" 2>/dev/null || true
            kill -- -"$_pid" 2>/dev/null || kill "$_pid" 2>/dev/null

            # Clean up temp files based on tool type
            case "$_type" in
                secure-entry)
                    local label="${name#entry-}"
                    # Multi-field secure-entry creates a directory <dir>/<label>/
                    # with one file per --field; single-field creates a flat
                    # file. Handle both, in the per-user run dir (current
                    # tools) and in /tmp/secure-entry (files left by older
                    # versions).
                    #
                    # A `<dir>/*` prefix test is NOT a containment check:
                    # "<dir>/../../home/alice" matches it and would hand an
                    # `rm -rf` a path outside the dir entirely. Validate the
                    # label instead -- it can then contain no slashes and no
                    # dots, so the path cannot escape.
                    if tunnel_name_is_valid "$label"; then
                        local _se_dir _se_target
                        for _se_dir in "$(tunnel_run_dir secure-entry)" /tmp/secure-entry; do
                            [ -n "$_se_dir" ] || continue
                            _se_target="${_se_dir}/${label}"
                            if [ -d "$_se_target" ] && [ ! -L "$_se_target" ]; then
                                rm -rf "$_se_target"
                            else
                                rm -f "$_se_target"
                            fi
                        done
                    fi
                    # signal_file may live outside /tmp/secure-entry (e.g.
                    # /tmp/cush-inject/<run>/<env>.done); sweep it explicitly.
                    [ -n "$signal_file" ] && rm -f "$signal_file"
                    ;;
                exchange)
                    local _ex_dir
                    _ex_dir="$(tunnel_run_dir exchange)"
                    [ -n "$_ex_dir" ] && rm -f "${_ex_dir}/${name}"
                    # Legacy locations from older versions.
                    rm -f "/tmp/exchange/${name}"
                    rm -f /tmp/exchange-"${name}"-*
                    ;;
            esac

            # Clean up log file
            [ -n "$_log" ] && rm -f "$_log"

            tunnel_state_cleanup "$name"
            exit 0
        fi
    done
}

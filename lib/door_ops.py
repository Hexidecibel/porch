"""The door control plane: list, extend, expire, keep, stop, history, revive,
reopen, launch, share rules and the inspector, shared by the panel
(lib/statusserver.py), Pocket and `porch door` (lib/porch_setup/cmd_door.py).

Pure functions, no HTTP. A refusal raises DoorOpError(status, message,
code=None, **extra); its status and message are exactly what the panel has
always answered, so a handler only has to turn it into JSON. Callers that
tests re-point (statusserver's REPO_ROOT and DOMAIN) pass `repo_root=` and
`domain=` at call time; None means this module's own.

Everything runs as the owner's user against the same /tmp/tunnel-state files
and door_state locks as the launchers and the door proxy.
"""

import collections
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

_LIB = os.path.dirname(os.path.abspath(__file__))
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
import door_recipe  # noqa: E402
import door_state  # noqa: E402
import inspect_store  # noqa: E402
import porch_config  # noqa: E402

REPO_ROOT = Path(_LIB).parent

LAUNCHABLE_TYPES = ('drop', 'photos', 'media', 'music', 'exchange', 'secure-entry', 'paste')
NAME_RE = re.compile(r'^[a-z0-9][a-z0-9-]{0,40}$')

# Launch flags a type may carry, as recorded in the history's `flags` list.
# A revive that has to rebuild argv re-applies only these; anything else in a
# history record is ignored rather than passed to a launcher.
REVIVE_FLAGS = {'media': ('--view-only', '--no-guest-upload')}

# Types a revive may re-launch. argv is rebuilt from type + name (+ the flags
# in REVIVE_FLAGS); nothing else from a history record is executed. paste
# (needs its content), serve (a directory), tunnel (a port) and the rest take
# arguments history can't be trusted to supply, so they are not revivable.
REVIVABLE_TYPES = ('drop', 'photos', 'media', 'music', 'exchange', 'secure-entry')

# Launch history: only the newest HISTORY_KEEP records survive a compaction,
# which runs once the file passes HISTORY_MAX records.
HISTORY_MAX = 1000
HISTORY_KEEP = 500
HISTORY_LIMIT = 25

REOPEN_EXPIRES = ('1h', '24h')          # what an approval may open a door for
REQUESTS_PAGE = 200
PROXY_WAIT = 15                         # s a live first-rule switch may take

# Door flags a Pocket launch may add (the panel never sends any).
LAUNCH_EXPIRES = ('30m', '1h', '24h', '7d', 'never')
# Never handed to a launcher: they would make it skip daemonizing, reuse a
# parent's door spec or log file, or carry a password it did not ask for.
LAUNCHER_ENV_DROP = tuple(dict.fromkeys(door_recipe.ENV_DROP + (
    '_CUSH_DAEMONIZED', 'CUSH_LOG_FILE', '_PORCH_DOOR_SPEC', 'TUNNEL_NO_STATE',
    'PORCH_DOOR_PASSWORD')))

# set_rules: a key left at KEEP is not touched.
KEEP = object()

LaunchPlan = collections.namedtuple(
    'LaunchPlan', 'argv cwd name rtype stdin env log_path timeout')


class DoorOpError(Exception):
    """A refusal: `status` (an HTTP code), a user-facing `message`, an
    optional stable `code` and any extra fields for the reply."""

    def __init__(self, status, message, code=None, **extra):
        super().__init__(message)
        self.status = status
        self.message = message
        self.code = code
        self.extra = extra

    def reply(self):
        out = {'status': 'error', 'message': self.message}
        if self.code:
            out['code'] = self.code
        out.update(self.extra)
        return out


def log(msg):
    sys.stderr.write(f"[door-ops] {msg}\n")


def _domain(domain):
    return domain if domain is not None else porch_config.get()


def _root(repo_root):
    return Path(repo_root) if repo_root is not None else REPO_ROOT


def is_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except (OSError, TypeError, ValueError, OverflowError):
        return False


def read_state(path):
    with open(path, 'r') as f:
        return json.load(f)


def tunnel_url(name, domain=None):
    return _domain(domain).tunnel_url(name)


def tunnel_name_for(rtype, name):
    """The tunnel/state-file name a launch of `rtype` registers under.
    bin/secure-entry <label> registers entry-<label>; everything else uses
    the name as given."""
    if rtype == 'secure-entry' and not name.startswith('entry-'):
        return f'entry-{name}'
    return name


def secure_entry_url(stdout, tunnel_name, domain=None):
    """The token URL from bin/secure-entry's `Secure entry: <url>` line, or
    None. Same pattern as lib/inject.py: the bare host 404s, only the
    launcher knows the random path token."""
    m = re.search(
        r"^Secure entry:\s*(https://" + re.escape(tunnel_name)
        + r"\." + re.escape(_domain(domain).tunnel_base) + r"/[A-Za-z0-9_-]+/)\s*$",
        stdout or '', re.MULTILINE)
    return m.group(1) if m else None


# frpc matching + kill live in lib/door_state.py (the door proxy's burn path
# stops a door the same way).
def kill_frpc_for(name):
    killed = 0
    for pid in door_state.frpc_pids_for(name):
        try:
            os.kill(pid, signal.SIGTERM)
            killed += 1
        except OSError:
            pass
    return killed


# ---- listing -------------------------------------------------------------------

def enrich(tunnel, domain=None):
    # Every field is fetched defensively. A state file is written by a separate
    # process and can be read mid-write, truncated by a crash, or simply be a
    # stray .json someone dropped in the dir. This used to do tunnel['name']
    # and tunnel['pid'] directly, so ONE malformed file raised KeyError out of
    # the listing and killed it entirely — the client saw a dropped
    # connection and reported "lost contact with the status API", which reads
    # like the daemon is down rather than like one bad file. Degrade per-entry
    # instead: a record we can't fully understand is still worth showing.
    name = tunnel.get('name')
    if not name:
        return None
    tunnel['name'] = name
    tunnel['url'] = tunnel_url(name, domain)
    tunnel['alive'] = is_alive(tunnel.get('pid', -1))
    # expires: epoch, or null = never (keep_alive is the older spelling).
    exp = door_state.expires_of(tunnel)
    tunnel['expires'] = exp
    tunnel['never'] = exp is None
    tunnel['time_remaining'] = None if exp is None else max(0, exp - int(time.time()))
    # Which rules are on -- never the password hash or the guest token.
    tunnel['rules'] = door_state.public_rules(tunnel.get('rules'))
    try:
        tunnel['opens'] = max(0, int(tunnel.get('opens') or 0))
    except (TypeError, ValueError):
        tunnel['opens'] = 0
    lo = tunnel.get('last_open')
    tunnel['last_open'] = lo if isinstance(lo, int) and not isinstance(lo, bool) else None
    tunnel.pop('proxy', None)
    # Inspector / webhook: booleans only (a hook's configured body stays out).
    ins = door_state.clean_inspect(tunnel.get('inspect'))
    tunnel['capture'] = isinstance(tunnel.get('capture'), dict)
    tunnel['inspect'] = bool(ins) or tunnel['capture']
    tunnel['inspect_raw'] = bool(ins and ins['raw'])
    return tunnel


def find_unmanaged_frpc(state_dir, domain=None):
    """Find frpc processes not tracked in state files."""
    state_dir = Path(state_dir)
    managed_pids = set()
    managed_names = set()
    if state_dir.is_dir():
        for path in state_dir.glob('*.json'):
            if path.name.endswith('.json.tmp'):
                continue
            try:
                with open(path, 'r') as f:
                    state = json.load(f)
                    if 'pid' in state:
                        managed_pids.add(state['pid'])
                managed_names.add(path.stem)
            except (json.JSONDecodeError, OSError):
                continue

    unmanaged = []
    try:
        result = subprocess.run(
            ['pgrep', '-a', '-f', 'frpc -c'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.split(None, 1)
                if len(parts) < 2:
                    continue
                pid = int(parts[0])
                cmdline = parts[1]
                if pid in managed_pids:
                    continue
                # pgrep -f also matches any shell whose command line mentions
                # "frpc -c"; only a real frpc process is a tunnel.
                if os.path.basename(cmdline.split(None, 1)[0]) != 'frpc':
                    continue

                # Extract name from config path: /tmp/frpc-<NAME>-XXXXX.toml
                name_match = re.search(r'frpc-(.+)-[A-Za-z0-9]+\.toml', cmdline)
                name = name_match.group(1) if name_match else f'pid-{pid}'
                # The launcher's pid is in the state file, frpc is its child:
                # a frpc for a door with a state file belongs to that door.
                if name in managed_names:
                    continue

                unmanaged.append({
                    'name': name,
                    'type': 'unmanaged',
                    'pid': pid,
                    'url': tunnel_url(name, domain),
                    'time_remaining': None,
                    'expires': None,
                    'keep_alive': False,
                    'alive': True,
                    'started': None,
                })
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        pass

    return unmanaged


def list_doors(state_dir, *, unmanaged=True, cleanup=True, domain=None, log=log):
    """Every live door, newest first (the panel's /api/tunnels). A state file
    whose launcher is gone is deleted (`cleanup`); unreadable or nameless
    ones are skipped, never fatal. `unmanaged` adds frpc processes no state
    file knows about."""
    state_dir = Path(state_dir)
    tunnels = []
    if state_dir.is_dir():
        for entry in state_dir.iterdir():
            if not entry.name.endswith('.json') or entry.name.endswith('.json.tmp'):
                continue
            try:
                tunnel = read_state(entry)
            except (json.JSONDecodeError, OSError):
                continue

            if not is_alive(tunnel.get('pid', -1)):
                if cleanup:
                    log(f"Cleaning up dead tunnel: {tunnel.get('name', entry.stem)} "
                        f"(pid {tunnel.get('pid')})")
                    try:
                        entry.unlink()
                    except OSError:
                        pass
                continue

            # enrich() returns None for a record with no usable name.
            # Skip it and keep going rather than failing the whole list.
            try:
                enriched = enrich(tunnel, domain)
            except Exception:
                log(f"Skipping unreadable state file: {entry.name}")
                continue
            if enriched is None:
                log(f"Skipping state file with no tunnel name: {entry.name}")
                continue
            tunnels.append(enriched)

    if unmanaged:
        tunnels.extend(find_unmanaged_frpc(state_dir, domain))

    tunnels.sort(key=lambda t: t.get('started') or 0, reverse=True)
    return tunnels


# ---- expiry --------------------------------------------------------------------

def _state_file(state_dir, name):
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise DoorOpError(400, 'Invalid name')
    return Path(state_dir) / f'{name}.json'


def _edit_state(state_dir, name, fn, log=log):
    """Locked read-modify-write (shared with the door proxy's open counter)."""
    path = _state_file(state_dir, name)
    try:
        return door_state.update_state(str(path), fn)
    except FileNotFoundError:
        raise DoorOpError(404, 'Tunnel not found') from None
    except (OSError, ValueError, UnicodeDecodeError) as e:
        log(f"Unreadable state file for '{name}': {e}")
        raise DoorOpError(409, 'Tunnel state file is unreadable') from None


def expiry_reply(state):
    exp = door_state.expires_of(state)
    return {
        'status': 'ok',
        'expires': exp,
        'never': exp is None,
        'keep_alive': exp is None,
        'time_remaining': None if exp is None else max(0, int(exp - time.time())),
    }


def extend(state_dir, name, seconds=3600, log=log):
    """Push the expiry `seconds` past max(now, current); a never-expiring
    door is left alone."""
    now = int(time.time())

    def fn(t):
        cur = door_state.expires_of(t)
        if cur is None:
            return False        # never-expiring: nothing to extend
        t['expires'] = max(cur, now) + seconds
    return expiry_reply(_edit_state(state_dir, name, fn, log))


def set_expires(state_dir, name, at, log=log):
    """`at`: epoch | "never" | None | "+2h" | "30m" | ISO-8601."""
    try:
        at = door_state.coerce_expires(at)
    except door_state.DoorError as e:
        raise DoorOpError(400, str(e)) from None

    def fn(t):
        t['expires'] = at
        t['keep_alive'] = at is None
    return expiry_reply(_edit_state(state_dir, name, fn, log))


def toggle_keep(state_dir, name, log=log):
    """The panel's keep-alive switch: never <-> back on a timer (the old
    expiry if still ahead, else an hour)."""
    now = int(time.time())

    def fn(t):
        if door_state.expires_of(t) is None:
            t['keep_alive'] = False
            exp = t.get('expires')
            if not isinstance(exp, int) or exp <= now:
                t['expires'] = now + 3600
        else:
            t['keep_alive'] = True
    return expiry_reply(_edit_state(state_dir, name, fn, log))


# ---- stop ----------------------------------------------------------------------

def stop(state_dir, name, log=log):
    """Close a door: its recipe records 'closed' (so it stays reopenable),
    the launcher gets SIGTERM, the frpc running exactly its config is
    killed, its files go. A name with no state file kills a matching
    unmanaged frpc only: {'status': 'ok', 'killed': n}."""
    path = _state_file(state_dir, name)
    if not path.is_file():
        n = kill_frpc_for(name)
        log(f"Stopped unmanaged tunnel '{name}' ({n} frpc)")
        return {'status': 'ok', 'killed': n}
    try:
        tunnel = read_state(path)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        tunnel = {}
    door_state.record_close(name, 'closed', tunnel if isinstance(tunnel, dict) else None)
    pid = tunnel.get('pid') if isinstance(tunnel, dict) else None
    if isinstance(pid, int) and not isinstance(pid, bool) and pid > 1:
        try:
            os.kill(pid, signal.SIGTERM)
            log(f"Sent SIGTERM to tunnel '{name}' (pid {pid})")
        except OSError:
            pass

    # Plus the frpc running exactly this tunnel's config (never a
    # substring match: stopping `c` must not kill chat's frpc).
    kill_frpc_for(name)

    try:
        path.unlink()
    except OSError:
        pass
    door_state.cleanup_files(name, str(state_dir))  # .lock / .secret
    log(f"Stopped tunnel '{name}'")
    return {'status': 'ok'}


def stop_all(state_dir, exclude=(), exclude_types=(), log=log):
    """Stop every live managed door except the names in `exclude` and the
    types in `exclude_types`. {'stopped': [names], 'skipped': [{name, why}]}."""
    stopped, skipped = [], []
    for d in list_doors(state_dir, unmanaged=False, log=log):
        name = d.get('name')
        if name in exclude or d.get('type') in exclude_types:
            skipped.append({'name': name, 'why': 'excluded'})
            continue
        if not isinstance(name, str) or not NAME_RE.match(name):
            skipped.append({'name': name, 'why': 'invalid name'})
            continue
        try:
            stop(state_dir, name, log=log)
            stopped.append(name)
        except DoorOpError as e:
            skipped.append({'name': name, 'why': e.message})
    return {'stopped': stopped, 'skipped': skipped}


# ---- history -------------------------------------------------------------------

_history_lock = threading.Lock()
_history_cache = {'key': None, 'records': []}


def write_history(history_path, records):
    """Atomically replace the history with `records` (0600 temp, fsync)."""
    path = Path(history_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.history.', suffix='.tmp', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w') as f:
            for rec in records:
                f.write(json.dumps(rec) + '\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    with _history_lock:
        _history_cache['key'] = None


def read_history(history_path, log=log):
    """Parse the history JSONL file into a list of records (oldest -> newest).

    Cached on (mtime, size), so a request does not re-parse an unchanged
    file. Past HISTORY_MAX records the file is compacted to the newest
    HISTORY_KEEP. Returns [] if the file is missing or unreadable.
    """
    try:
        st = os.stat(history_path)
    except (OSError, TypeError):
        return []
    key = (st.st_mtime_ns, st.st_size)
    with _history_lock:
        if _history_cache['key'] == key:
            return list(_history_cache['records'])
    records = []
    try:
        with open(history_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(rec, dict):
                    records.append(rec)
    except OSError:
        return []
    if len(records) > HISTORY_MAX:
        records = records[-HISTORY_KEEP:]
        try:
            # A line the launcher appends between our read and this rename
            # is lost; that costs one Revive entry, nothing more.
            write_history(history_path, records)
            log(f"Compacted history to {len(records)} records")
        except OSError as e:
            log(f"History compaction failed: {e}")
        return records
    with _history_lock:
        _history_cache['key'] = key
        _history_cache['records'] = records
    return list(records)


def revive_argv(rec, name, repo_root=None):
    """argv for re-launching history record `rec` under `name`, or None.

    Built only from an allowlisted type, the validated name and the type's
    allowlisted flags. The stored cmd/cwd/log are never used: the history
    file is plain data that anything running as this user can append to.
    """
    rtype = rec.get('type')
    if rtype not in REVIVABLE_TYPES or not NAME_RE.match(name or ''):
        return None
    arg = name
    if rtype == 'secure-entry':
        # bin/secure-entry <label> registers the tunnel as entry-<label>.
        if not name.startswith('entry-'):
            return None
        arg = name[len('entry-'):]
        if not NAME_RE.match(arg):
            return None
    argv = [str(_root(repo_root) / 'bin' / rtype), arg]
    flags = rec.get('flags')
    if isinstance(flags, list):
        allowed = REVIVE_FLAGS.get(rtype, ())
        argv += [f for f in flags if f in allowed]
    return argv + ['--bg']


def tool_log_path(name, repo_root=None):
    """Where --bg launchers log: logs/<name>.log. Computed, never read from
    a history record (that was an arbitrary file read)."""
    if not NAME_RE.match(name or ''):
        return None
    return str(_root(repo_root) / 'logs' / f'{name}.log')


def latest_start_by_name(records):
    """Map name -> latest 'start' record (last write wins by file order)."""
    out = {}
    for rec in records:
        if rec.get('event') != 'start':
            continue
        name = rec.get('name')
        if not name:
            continue
        out[name] = rec
    return out


def history(history_path, state_dir, doors_dir=None, limit=HISTORY_LIMIT, *,
            repo_root=None, domain=None, log=log):
    """Recently closed doors, newest first: what a Revive would run, and
    whether its launch recipe can reopen it (and why not)."""
    state_dir = Path(state_dir)
    root = _root(repo_root)
    try:
        door_recipe.prune(doors_dir, str(state_dir))
    except OSError as e:
        log(f"Recipe prune failed: {e}")
    records = read_history(history_path, log)
    latest = latest_start_by_name(records)

    items = []
    for name, rec in latest.items():
        if not isinstance(name, str) or not NAME_RE.match(name):
            continue
        # Exclude anything currently running (live state file present).
        if (state_dir / f"{name}.json").is_file():
            continue
        argv = revive_argv(rec, name, root)
        try:
            recipe = door_recipe.check(name, doors_dir, str(state_dir))
            why = ''
        except door_recipe.RecipeError as e:
            recipe, why = None, str(e)
        items.append({
            'name': name,
            'type': rec.get('type', '') if isinstance(rec.get('type'), str) else '',
            'started': rec.get('started'),
            # What a Revive would run (rebuilt, not the recorded cmd).
            'cmd': [os.path.relpath(argv[0], root)] + argv[1:] if argv else [],
            'url': tunnel_url(name, domain),
            'revivable': argv is not None,
            # A launch recipe reopens it as it was (same file, rules, guest
            # link); it replaces Revive for those doors.
            'reopenable': recipe is not None,
            'reopen_why': why if recipe is None and door_recipe.load(name, doors_dir) else '',
            'closed': recipe.get('closed') if recipe else None,
            'reason': recipe.get('reason') if recipe else None,
        })

    items.sort(key=lambda it: latest[it['name']].get('ts') or 0, reverse=True)
    return items[:limit]


def forget(history_path, name, log=log):
    records = read_history(history_path, log)
    kept = [r for r in records if r.get('name') != name]
    try:
        write_history(history_path, kept[-HISTORY_KEEP:])
    except OSError as e:
        raise DoorOpError(500, f'Failed to rewrite history: {e}') from None
    log(f"Forgot history for '{name}'")
    return {'status': 'ok'}


def revive_plan(history_path, state_dir, name, *, repo_root=None, log=log):
    """The LaunchPlan that revives `name` from its latest start record."""
    rec = latest_start_by_name(read_history(history_path, log)).get(name)
    if rec is None:
        raise DoorOpError(404, f'No history for {name}')
    if (Path(state_dir) / f"{name}.json").is_file():
        raise DoorOpError(409, f'{name} is already running')
    argv = revive_argv(rec, name, repo_root)
    if argv is None:
        raise DoorOpError(400, f'{name} is not revivable')
    return LaunchPlan(argv, str(_root(repo_root)), name, rec.get('type'), None, None,
                      tool_log_path(name, repo_root), 20)


def reopen(name, expires, doors_dir=None, state_dir=None, *, reopener=None, domain=None,
           log=log):
    """Open a closed door again from its launch recipe, for 1h or 24h."""
    if expires not in REOPEN_EXPIRES:
        raise DoorOpError(400, 'expires must be 1h or 24h')
    fn = reopener or (lambda n, exp: door_recipe.reopen(
        n, exp, doors_dir, None if state_dir is None else str(state_dir), ok_if_open=True))
    try:
        fn(name, expires)
    except door_recipe.RecipeError as e:
        raise DoorOpError(409, str(e)) from None
    except Exception as e:  # noqa: BLE001
        raise DoorOpError(500, str(e) or 'reopen failed') from None
    log(f"Reopened '{name}' for {expires}")
    return {'status': 'ok', 'name': name, 'url': tunnel_url(name, domain)}


# ---- launch --------------------------------------------------------------------

def launcher_env(password=None, base=None):
    """The environment for a launcher started with door flags: the parent's,
    minus LAUNCHER_ENV_DROP, plus PORCH_DOOR_PASSWORD when there is one (the
    password never goes in argv)."""
    env = {k: v for k, v in (os.environ if base is None else base).items()
           if k not in LAUNCHER_ENV_DROP}
    if password:
        env['PORCH_DOOR_PASSWORD'] = password
    return env


def _door_flags(expires, rules):
    """argv door flags + the password (env only) for a launch with rules."""
    flags, password = [], None
    if expires is not None:
        if expires not in LAUNCH_EXPIRES:
            raise DoorOpError(400, 'Invalid expires')
        flags += ['--expires', expires]
    if rules is not None:
        if not isinstance(rules, dict):
            raise DoorOpError(400, 'Invalid rules')
        pw = rules.get('password')
        if pw is not None:
            if not isinstance(pw, str) or not 6 <= len(pw) <= 1024:
                raise DoorOpError(400, 'Password must be 6 to 1024 characters')
            flags.append('--password')
            password = pw
        guest = rules.get('guest', False)
        if not isinstance(guest, bool):
            raise DoorOpError(400, 'Invalid guest')
        if guest:
            flags.append('--guest-link')
        mo = rules.get('max_opens')
        if mo is not None:
            if not isinstance(mo, int) or isinstance(mo, bool) \
                    or not 1 <= mo <= door_state.MAX_OPENS:
                raise DoorOpError(400, 'Invalid max_opens')
            flags += ['--max-opens', str(mo)]
    return flags, password


def launch_plan(state_dir, rtype, name, content='', view_only=False, expires=None,
                rules=None, *, repo_root=None):
    """The LaunchPlan for a name-only tool (the panel's Launch). `expires`
    and `rules` (Pocket only) add allowlisted door flags; the password goes
    to the launcher in env PORCH_DOOR_PASSWORD, never argv."""
    if rtype not in LAUNCHABLE_TYPES:
        raise DoorOpError(400, 'Invalid type')
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise DoorOpError(400, 'Invalid name')
    # Strict boolean: "false", 0 or null are refused rather than coerced.
    if not isinstance(view_only, bool):
        raise DoorOpError(400, 'Invalid view_only')
    flags, password = _door_flags(expires, rules)

    tname = tunnel_name_for(rtype, name)
    if tname != name and not NAME_RE.match(tname):
        raise DoorOpError(400, 'Invalid name')
    if (Path(state_dir) / f"{tname}.json").is_file():
        raise DoorOpError(409, f'{tname} is already running')

    root = _root(repo_root)
    argv = [str(root / 'bin' / rtype), name, '--bg']
    if rtype == 'media' and view_only:
        argv.append('--view-only')
    argv += flags
    stdin = None
    if rtype == 'paste':
        stdin = (content if isinstance(content, str) else '').encode('utf-8')
    # The panel's launches (no door flags) inherit the environment as they
    # always have; a launch with door flags gets the scrubbed one.
    env = launcher_env(password) if (expires is not None or rules is not None) else None
    return LaunchPlan(argv, str(root), tname, rtype, stdin, env, tool_log_path(tname, root), 25)


def log_tail(log_path):
    if not log_path:
        return ''
    try:
        with open(log_path, 'r') as f:
            data = f.read()
        return data.strip()[-800:]
    except OSError:
        return ''


def run_launch(plan, runner=subprocess.run, *, domain=None, log=log):
    """Run a LaunchPlan. {'status': 'ok', 'url', 'name'[, 'type']}, or
    DoorOpError(500) with the launcher's stderr / log tail."""
    name, rtype = plan.name, plan.rtype
    try:
        kw = {'cwd': plan.cwd, 'shell': False, 'input': plan.stdin,
              'capture_output': True, 'timeout': plan.timeout}
        if plan.env is not None:
            kw['env'] = plan.env
        result = runner(plan.argv, **kw)
    except subprocess.TimeoutExpired:
        tail = log_tail(plan.log_path)
        msg = 'Launch timed out'
        if tail:
            msg += f': {tail}'
        log(f"Launch of '{name}' ({rtype}) timed out")
        raise DoorOpError(500, msg) from None
    except (OSError, ValueError) as e:
        log(f"Launch of '{name}' ({rtype}) failed: {e}")
        raise DoorOpError(500, f'Launch failed: {e}') from None

    if result.returncode == 0:
        url = tunnel_url(name, domain)
        if rtype == 'secure-entry':
            # The form lives under a random path token; the bare host
            # 404s. Hand back the launcher's own URL, never a guess.
            url = secure_entry_url(
                (result.stdout or b'').decode('utf-8', 'replace'), name, domain)
            if not url:
                log(f"Launch of '{name}' (secure-entry): no URL in launcher output")
                raise DoorOpError(500, 'secure-entry started but printed no entry URL')
        resp = {'status': 'ok', 'url': url, 'name': name}
        if rtype:
            resp['type'] = rtype
        log(f"Launched '{name}' ({rtype})")
        return resp

    stderr = (result.stderr or b'').decode('utf-8', 'replace').strip()
    tail = stderr or log_tail(plan.log_path)
    msg = f'Launch failed (exit {result.returncode})'
    if tail:
        msg += f': {tail[-800:]}'
    log(f"Launch of '{name}' ({rtype}) exited {result.returncode}")
    raise DoorOpError(500, msg)


# ---- share rules ---------------------------------------------------------------

def _alive(pid):
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def has_proxy(state):
    p = state.get('proxy')
    return isinstance(p, dict) and _alive(p.get('pid'))


def is_our_tunnel(pid, name, proc='/proc'):
    """pid is a live bin/tunnel for this door (not a recycled pid)."""
    if not _alive(pid):
        return False
    try:
        with open(os.path.join(proc, str(pid), 'cmdline'), 'rb') as f:
            argv = [a.decode('utf-8', 'replace') for a in f.read().split(b'\0') if a]
    except OSError:
        return False
    return (any(os.path.basename(a) == 'tunnel' for a in argv[:2])
            and name in argv)


def relaunch_command(name, extra_flags, history=None):
    """The shell command that relaunches door `name` with extra flags, from
    the newest start line of data/history.jsonl (argv + cwd); None if absent."""
    history = history or os.environ.get('CUSH_HISTORY_FILE') or os.path.join(
        str(REPO_ROOT), 'data', 'history.jsonl')
    entry = None
    try:
        with open(history, 'rb') as f:
            for line in f:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if isinstance(e, dict) and e.get('event') == 'start' and e.get('name') == name \
                        and isinstance(e.get('cmd'), list) and e['cmd']:
                    entry = e
    except OSError:
        return None
    if entry is None:
        return None
    argv = [str(a) for a in entry['cmd']]
    if os.path.basename(argv[0]) in ('bash', 'sh') and len(argv) > 1:
        argv = argv[1:]
    argv = [a for a in argv if a != '--bg'] + list(extra_flags) + ['--bg']
    cmd = ' '.join(shlex.quote(a) for a in argv)
    cwd = entry.get('cwd')
    return f'cd {shlex.quote(cwd)} && {cmd}' if isinstance(cwd, str) and cwd else cmd


def wait_for_proxy(path, since_pid=None, wait=None):
    deadline = time.time() + (PROXY_WAIT if wait is None else wait)
    while time.time() < deadline:
        try:
            s = door_state.read_state(path)
        except (OSError, ValueError):
            return False
        if has_proxy(s) and s['proxy'].get('pid') != since_pid:
            return True
        time.sleep(0.2)
    return False


def apply_rules(rules, password_hash=KEEP, guest=KEEP, max_opens=KEEP):
    """Apply a change to a clean rules dict (in place) and return it: None
    removes a key, KEEP leaves it, a value sets it."""
    for key, val in (('password', password_hash), ('guest', guest), ('max_opens', max_opens)):
        if val is KEEP:
            continue
        if val is None:
            rules.pop(key, None)
        else:
            rules[key] = val
    return rules


def rule_flags(password=KEEP, guest=KEEP, max_opens=KEEP):
    """The launcher flags that add these rules at a relaunch."""
    f = []
    if password is not KEEP and password is not None:
        f.append('--password')
    if guest == 'new':
        f.append('--guest-link')
    if max_opens is not KEEP and max_opens is not None:
        f += ['--max-opens', str(max_opens)]
    return f


def set_rules(state_dir, name, *, password=KEEP, guest=KEEP, max_opens=KEEP,
              signal_wait=None, relaunch_flags=None, tunnel_base=None, history=None):
    """Change a running door's share rules. KEEP leaves a rule as it is,
    None removes it; `password` is the plaintext (or a callable returning it,
    called only once the change is known to be possible, so a CLI prompt
    never runs for nothing), `guest` 'new' mints a fresh link, `max_opens`
    an int.

    A first rule on a door without a proxy is switched live: the rules are
    written, its bin/tunnel gets SIGUSR1 and has `signal_wait` seconds to
    record a live proxy, else the rules are rolled back
    (DoorOpError(502, code='switch_failed')). Doors that can't switch
    (tcp/udp, or started before bin/tunnel recorded its pid) raise
    DoorOpError(409, code='relaunch_needed', why=..., command=...).

    Returns {'rules': public rules, 'summary', 'guest_url' (or None),
    'minted' (a new guest link), 'live_switch'}."""
    path = str(_state_file(state_dir, name))
    try:
        current = door_state.read_state(path)
    except FileNotFoundError:
        raise DoorOpError(404, 'Tunnel not found') from None
    except (OSError, ValueError, UnicodeDecodeError):
        raise DoorOpError(409, 'Tunnel state file is unreadable') from None
    if max_opens is not KEEP and max_opens is not None and (
            not isinstance(max_opens, int) or isinstance(max_opens, bool)
            or not 1 <= max_opens <= door_state.MAX_OPENS):
        raise DoorOpError(400, 'Invalid max_opens')
    if guest not in (KEEP, None, 'new'):
        raise DoorOpError(400, 'Invalid guest')
    if password is not KEEP and password is not None and not callable(password) \
            and (not isinstance(password, str) or not 6 <= len(password) <= 1024):
        raise DoorOpError(400, 'Password must be 6 to 1024 characters')

    preview = apply_rules(door_state.clean_rules(current.get('rules')),
                          'x' if password not in (KEEP, None) else password,
                          'x' if guest == 'new' else guest, max_opens)
    live_switch = bool(preview) and not has_proxy(current)
    if live_switch:
        tpid = current.get('tunnel_pid')
        proto = current.get('proto') or 'http'
        if proto != 'http' or not is_our_tunnel(tpid, name):
            why = (f"it is a {proto} tunnel (share rules need http)" if proto != 'http' else
                   "it was started before doors could switch live")
            flags = list(relaunch_flags) if relaunch_flags is not None else \
                rule_flags(password, guest, max_opens)
            cmd = relaunch_command(name, flags, history) or (
                f"bin/{current.get('type') or 'serve'} ... {name} " + ' '.join(flags) + ' --bg')
            raise DoorOpError(409, f"{name} has no door proxy in front of it and {why}, so the "
                              "rule can't be added live", code='relaunch_needed',
                              why=why, command=cmd)
    if callable(password):
        password = password()
    pw_hash = door_state.hash_password(password) if password not in (KEEP, None) else password
    token = door_state.new_guest_token() if guest == 'new' else guest
    before = {}

    def fn(s):
        before['rules'] = s.get('rules')
        s['rules'] = apply_rules(door_state.clean_rules(s.get('rules')), pw_hash, token,
                                 max_opens)
    try:
        new = door_state.update_state(path, fn)
    except FileNotFoundError:
        raise DoorOpError(404, 'Tunnel not found') from None
    rules = door_state.clean_rules(new.get('rules'))
    if live_switch:
        try:
            os.kill(current['tunnel_pid'], signal.SIGUSR1)
            ok = wait_for_proxy(path, wait=signal_wait)
        except OSError:
            ok = False
        if not ok:
            def undo(s):
                s['rules'] = before.get('rules') or {}
            try:
                door_state.update_state(path, undo)
            except (OSError, ValueError):
                pass
            raise DoorOpError(502, f"{name}: the door proxy did not come up, so the rules were "
                              "rolled back (the door is unchanged)", code='switch_failed')
    return {
        'rules': door_state.public_rules(rules),
        'summary': door_state.rules_summary(rules),
        'guest_url': door_state.guest_url(name, rules['guest'], tunnel_base)
        if 'guest' in rules else None,
        'minted': guest == 'new',
        'live_switch': live_switch,
    }


# ---- inspector -----------------------------------------------------------------

def inspect_store_for(state_dir, name, base=None):
    """The store path of an open, inspected door."""
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise DoorOpError(400, 'Invalid name')
    try:
        st = read_state(Path(state_dir) / f'{name}.json')
    except (OSError, ValueError):
        raise DoorOpError(404, 'Tunnel not found') from None
    if not isinstance(st, dict) or not (door_state.clean_inspect(st.get('inspect'))
                                        or isinstance(st.get('capture'), dict)):
        raise DoorOpError(404, 'This door is not inspected (relaunch it with --inspect)')
    try:
        return inspect_store.store_path(name, base)
    except (inspect_store.InspectError, OSError) as e:
        raise DoorOpError(500, f'Inspector unavailable: {e}') from None


def requests_page(store, since=0, limit=REQUESTS_PAGE):
    limit = max(1, min(inspect_store.RING, limit))
    recs = inspect_store.read_records(store, since)
    more = len(recs) > limit
    # since= pages forward (oldest first); without it, the newest page.
    recs = recs[:limit] if since else recs[-limit:]
    return {
        'records': [inspect_store.summary(r) for r in recs],
        'last': recs[-1]['id'] if recs else since,
        'more': more,
        'body_cap': inspect_store.BODY_CAP,
    }


def request_detail(store, rid):
    rec = inspect_store.get_record(store, rid)
    if rec is None:
        raise DoorOpError(404, 'No such request')
    return rec


def replay(name, store, rid, base=None):
    try:
        reply = inspect_store.request_replay(name, rid, base)
    except inspect_store.InspectError as e:
        raise DoorOpError(409, str(e)) from None
    rec = inspect_store.get_record(store, reply.get('id'))
    reply['record'] = inspect_store.summary(rec) if rec else None
    reply['status'] = 'ok'
    reply['http_status'] = rec.get('status') if rec else None
    return reply

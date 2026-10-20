#!/usr/bin/env python3
"""Launch recipes: what it takes to open a closed door again, under its name.

Every reopenable launcher (view, seal, serve, paste, media, photos, music,
drop) writes data/doors/<name>.json (0600, in a 0700 dir) as it starts: the
door's type, its canonical inputs (a resolved path, the flags that change
what it serves, files it owns) and its share rules (password HASH, guest
token, max_opens, inspector), plus the door proxy's cookie key so a reopened
door keeps its visitors' sessions. A recipe is written by a launcher (or
updated by trusted local code: the close paths, porch share's staging) and
never from a request; launch history (data/history.jsonl) is not trusted
and is never read here.

    {"v": 1, "name", "type", "pid", "created", "launched", "reopens",
     "inputs": {"path", "flags": [...], "owned": [...], "owned_dir"},
     "rules": {...}, "inspect": {...}, "secret": "<hex>", "pocket": {...},
     "staged": [...], "closed": epoch|null, "reason": null|expired|closed|used-up|burned}

Closing. Whoever closes a door records why first (mark_closed): the
watchdog `expired`, bin/status close / the panel's Stop / Pocket's Close
`closed`, the door proxy at max_opens `used-up`, sealserver at its download
limit `burned`. The launcher's exit trap then asks release(): a door that
expired or was closed by its owner keeps its owned files (stdin copies,
sealed ciphertext, paste captures, porch share's media/music copies) for
RETAIN seconds (7 days) so it can be reopened; a used-up or burned door is
shredded at once (owned files and recipe), which is what --burn promises.
No recipe (or an unknown reason that is not a burn) = the old behaviour.

Reopening = reopen(name, expires): validate the recipe again (name, type,
the path still there, owned files still in their private dirs, not shredded,
inside retention), build argv from it (never from history) and run the
launcher with --reopen, which makes lib/door-flags.sh take the rules from the
recipe (spec_for_reopen) instead of the command line: same password, same
guest link, same inspector; opens start from zero.

prune() deletes recipes (and their owned files) RETAIN seconds after the
door closed, and notices doors that died without a trap.

CLI (lib/door-flags.sh, lib/tunnel-state.sh, bin/status, the launchers):
    door_recipe.py write --name N --type T --pid P [--path F] [--flag F]...
                         [--owned F]... [--owned-dir D]     (spec in $_PORCH_DOOR_SPEC)
    door_recipe.py launched <name> <pid>     (tunnel_state_register: drop a stale
                                              recipe, install the door's cookie key)
    door_recipe.py closed <name> <reason> [--state-file F]
    door_recipe.py release <name>            (prints keep | shred)
    door_recipe.py spec <name> --expires W   (the spec a --reopen launch uses)
    door_recipe.py reopen <name> [--expires W]
    door_recipe.py prune
"""

import errno
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import door_state  # noqa: E402

REPO_DIR = os.path.dirname(_HERE)
BIN_DIR = os.path.join(REPO_DIR, 'bin')
RETAIN = 7 * 86400                 # owned files of an expired/closed door are kept this long
REOPEN_TIMEOUT = 90                # s a launcher may take
MAX_RECIPE = 64 * 1024

TYPES = ('view', 'seal', 'serve', 'paste', 'media', 'photos', 'music', 'drop')
REASONS = ('expired', 'closed', 'used-up', 'burned')
SHRED_REASONS = ('used-up', 'burned')
# The flags a type may carry in its recipe; anything else is dropped (write)
# or refused (reopen). Value flags take the next item.
FLAGS = {
    'view': {'--follow': None, '--as': ('markdown', 'code', 'text', 'pdf', 'csv', 'tsv', 'json',
                                        'zip', 'diff', 'image', 'video', 'audio', 'other')},
    'serve': {'--list': None, '--allow-scripts': None},
    'media': {'--view-only': None, '--no-guest-upload': None},
}
# Names whose directory lives in $HOME (media/music staging and the apps' own dirs).
HOME_DIRS = {'media': 'media', 'photos': 'photos', 'music': 'music', 'drop': 'drops'}
# Launcher env vars that must never reach a launcher we start.
ENV_DROP = ('_CUSH_DAEMONIZED', 'CUSH_LOG_FILE', '_PORCH_DOOR_SPEC', 'TUNNEL_NO_STATE',
            'PORCH_DOOR_PASSWORD')

_SECRET_RE = re.compile(r'^[0-9a-f]{64}$')


class RecipeError(ValueError):
    """The recipe can't be used to reopen the door; the message is user-facing."""


# ---- where things live ----------------------------------------------------------

def doors_dir(path=None):
    """data/doors (PORCH_DOORS_DIR overrides; bin/test points it at a temp dir).
    Created 0700 and verified to be ours."""
    d = path or os.environ.get('PORCH_DOORS_DIR') or os.path.join(REPO_DIR, 'data', 'doors')
    try:
        os.makedirs(d, mode=0o700, exist_ok=True)
    except OSError:
        pass
    st = os.lstat(d)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
        raise OSError(errno.EPERM, f'{d} is not a private directory of ours')
    if st.st_mode & 0o077:
        os.chmod(d, 0o700)
    return d


def recipe_path(name, ddir=None):
    if not door_state.NAME_RE.match(name or ''):
        raise RecipeError(f'invalid door name: {name!r}')
    return os.path.join(doors_dir(ddir), f'{name}.json')


def _read_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_size > MAX_RECIPE:
            raise OSError(errno.EPERM, f'refusing {path}')
        with os.fdopen(fd, 'rb') as f:
            fd = None
            data = json.loads(f.read().decode('utf-8'))
    finally:
        if fd is not None:
            os.close(fd)
    if not isinstance(data, dict):
        raise ValueError('recipe is not an object')
    return data


def load(name, ddir=None):
    """The recipe dict, or None (no recipe, unreadable, or not ours)."""
    try:
        r = _read_json(recipe_path(name, ddir))
    except (OSError, ValueError, RecipeError):
        return None
    return r if r.get('name') == name else None


def _write(name, data, ddir=None):
    path = recipe_path(name, ddir)
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=f'.{name}.', suffix='.tmp', dir=d)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _update(name, fn, ddir=None):
    """Locked read-modify-write of a recipe; returns the new dict or None
    (no recipe). fn returns False to write nothing, or a dict to replace."""
    path = recipe_path(name, ddir)
    lock = os.path.join(os.path.dirname(path), f'.{name}.lock')
    import fcntl
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        r = load(name, ddir)
        if r is None:
            return None
        new = fn(r)
        if new is False:
            return r
        if isinstance(new, dict):
            r = new
        _write(name, r, ddir)
        return r
    finally:
        os.close(fd)


def remove(name, ddir=None):
    try:
        d = doors_dir(ddir)
    except OSError:
        return
    for p in (f'{name}.json', f'.{name}.lock'):
        try:
            os.unlink(os.path.join(d, p))
        except OSError:
            pass


# ---- private dirs an owned file may live in ---------------------------------------

def _rundir(tool):
    try:
        import rundir
        return os.path.realpath(rundir.tool_dir(tool))
    except Exception:  # noqa: BLE001
        return None


def _owned_dir_ok(d):
    """bin/seal's --owned-dir rule: ours, a directory, not group/world
    writable, not / or $HOME."""
    try:
        real = os.path.realpath(d)
        st = os.stat(real)
    except (OSError, TypeError, ValueError):
        return None
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o022:
        return None
    if real in ('/', os.path.realpath(os.path.expanduser('~'))):
        return None
    return real


def owned_ok(rtype, name, path, owned_dir=None):
    """True when `path` is a file this door may own and delete: directly in
    the share run dir (view, seal), in --owned-dir (seal: Pocket's sealed
    uploads), or a paste capture (paste-<name>-* in the paste run dir)."""
    if not isinstance(path, str) or not os.path.isabs(path):
        return False
    real = os.path.realpath(path)
    if real != os.path.normpath(path):
        return False                   # a symlink somewhere on the way: never
    parent = os.path.dirname(real)
    if rtype in ('view', 'seal') and parent == _rundir('share'):
        return True
    if rtype == 'seal' and owned_dir and parent == _owned_dir_ok(owned_dir):
        return True
    if rtype == 'paste' and parent == _rundir('paste') \
            and os.path.basename(real).startswith(f'paste-{name}-'):
        return True
    return False


def staged_ok(name, path):
    """porch share's copy: directly in ~/media/<name>/ or ~/music/<name>/."""
    if not isinstance(path, str) or not os.path.isabs(path):
        return False
    real = os.path.realpath(path)
    if real != os.path.normpath(path):
        return False
    home = os.path.realpath(os.path.expanduser('~'))
    return os.path.dirname(real) in (os.path.join(home, 'media', name),
                                     os.path.join(home, 'music', name))


def _unlink_file(path):
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode):
        return False
    try:
        os.unlink(path)
        return True
    except OSError:
        return False


def shred(r, ddir=None):
    """Delete a recipe's owned and staged files (each re-checked against its
    private dir first: a hand-edited recipe can't name anything else), then
    the recipe."""
    name = r.get('name')
    rtype = r.get('type')
    inputs = r.get('inputs') if isinstance(r.get('inputs'), dict) else {}
    for p in inputs.get('owned') or []:
        if owned_ok(rtype, name, p, inputs.get('owned_dir')):
            _unlink_file(p)
    for p in r.get('staged') or []:
        if staged_ok(name, p):
            _unlink_file(p)
            try:
                os.rmdir(os.path.dirname(p))       # only when it is empty now
            except OSError:
                pass
    if isinstance(name, str) and door_state.NAME_RE.match(name):
        remove(name, ddir)


# ---- writing (launchers) ------------------------------------------------------------

def _clean_flags(rtype, flags):
    allowed = FLAGS.get(rtype, {})
    out, i = [], 0
    flags = list(flags or [])
    while i < len(flags):
        f = flags[i]
        if f in allowed:
            vals = allowed[f]
            if vals is None:
                out.append(f)
            elif i + 1 < len(flags) and flags[i + 1] in vals:
                out += [f, flags[i + 1]]
                i += 1
        i += 1
    return out


def write(name, rtype, pid, spec=None, path=None, flags=(), owned=(), owned_dir=None,
          ddir=None, now=None):
    """Called by a launcher as it starts (before tunnel_state_register). A
    reopen (spec['reopen']) carries the old recipe's created time, cookie
    key, Pocket tag and staged files over."""
    now = int(time.time() if now is None else now)
    if rtype not in TYPES:
        raise RecipeError(f'type {rtype!r} has no recipe')
    if not door_state.NAME_RE.match(name or ''):
        raise RecipeError(f'invalid door name: {name!r}')
    spec = spec if isinstance(spec, dict) else {}
    old = load(name, ddir) if spec.get('reopen') else None
    secret = old.get('secret') if old and _SECRET_RE.match(str(old.get('secret'))) else \
        secrets.token_hex(32)
    exp = spec.get('expires') if spec else now + door_state.DEFAULT_TTL
    inputs = {'flags': _clean_flags(rtype, flags)}
    if path:
        inputs['path'] = os.path.realpath(path)
    owned = [os.path.realpath(p) for p in owned or () if p]
    if owned:
        inputs['owned'] = owned
    if owned_dir:
        inputs['owned_dir'] = os.path.realpath(owned_dir)
    r = {
        'v': 1, 'name': name, 'type': rtype, 'pid': int(pid),
        'created': int(old.get('created') or now) if old else now,
        'launched': now,
        'reopens': (int(old.get('reopens') or 0) + 1) if old else 0,
        'inputs': inputs,
        'rules': door_state.clean_rules(spec.get('rules')),
        'ttl': None if exp is None else max(0, int(exp) - now),
        'secret': secret,
        'closed': None, 'reason': None,
    }
    ins = door_state.clean_inspect(spec.get('inspect'))
    if ins:
        r['inspect'] = ins
    if old:
        if isinstance(old.get('pocket'), dict):
            r['pocket'] = old['pocket']
        if isinstance(old.get('staged'), list):
            r['staged'] = [p for p in old['staged'] if staged_ok(name, p)]
    _write(name, r, ddir)
    return r


def launched(name, pid, state_dir=None, ddir=None):
    """tunnel_state_register: this launch's recipe (same pid) gets its cookie
    key installed as <state dir>/.<name>.secret, so a reopened door's
    sessions stay valid. A recipe left by another door under this name is
    stale (that door can't be reopened once the name is reused): shredded."""
    r = load(name, ddir)
    if r is None:
        return
    if r.get('pid') != int(pid):
        shred(r, ddir)
        return
    key = r.get('secret')
    if not isinstance(key, str) or not _SECRET_RE.match(key):
        return
    p = os.path.join(state_dir or door_state.STATE_DIR, f'.{name}.secret')
    try:
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        return                       # one is there already: the door proxy's own
    with os.fdopen(fd, 'w') as f:
        f.write(key)


def add_staged(name, path, ddir=None):
    """porch share: the media/music copy it staged for this door."""
    if not staged_ok(name, path):
        return None

    def fn(r):
        st = [p for p in (r.get('staged') or []) if isinstance(p, str)]
        if path not in st:
            st.append(os.path.realpath(path))
        r['staged'] = st
    return _update(name, fn, ddir)


# ---- closing -----------------------------------------------------------------------

def mark_closed(name, reason, state=None, ddir=None, now=None):
    """Record why a door closed (first reason wins, except that a burn or
    use-up always wins over a plain close). With the door's live state, its
    current rules (porch door rules may have changed them) and Pocket tag
    are kept for the reopen."""
    if reason not in REASONS or not door_state.NAME_RE.match(name or ''):
        return None
    now = int(time.time() if now is None else now)

    def fn(r):
        cur = r.get('reason')
        if cur in SHRED_REASONS or (cur and reason not in SHRED_REASONS):
            return False
        r['reason'] = reason
        r['closed'] = r.get('closed') or now
        if isinstance(state, dict) and state.get('name') == name:
            if 'rules' in state:
                r['rules'] = door_state.clean_rules(state.get('rules'))
            if isinstance(state.get('pocket'), dict):
                r['pocket'] = state['pocket']
    return _update(name, fn, ddir)


def release(name, ddir=None, now=None):
    """The launcher's exit trap. 'keep' = its owned files stay (an expired or
    closed door, reopenable for RETAIN); 'shred' = delete them (no recipe,
    or burned / used up: the recipe and owned files are gone already)."""
    r = load(name, ddir)
    if r is None:
        return 'shred'
    if not r.get('reason'):
        r = mark_closed(name, 'closed', ddir=ddir, now=now) or r
    if r.get('reason') in SHRED_REASONS:
        shred(r, ddir)
        return 'shred'
    return 'keep'


def _alive(pid):
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        return False
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def is_open(name, state_dir=None):
    try:
        st = door_state.read_state(door_state.state_path(name, state_dir))
    except (OSError, ValueError, door_state.DoorError):
        return False
    return _alive(st.get('pid'))


def prune(ddir=None, state_dir=None, now=None):
    """Shred recipes RETAIN after their door closed (and burned/used-up ones
    at once); a door that died without its trap gets closed = now. Returns
    the number removed."""
    now = int(time.time() if now is None else now)
    try:
        d = doors_dir(ddir)
        names = os.listdir(d)
    except OSError:
        return 0
    gone = 0
    for fn in names:
        if not fn.endswith('.json') or fn.startswith('.'):
            continue
        name = fn[:-5]
        r = load(name, ddir)
        if r is None:
            if door_state.NAME_RE.match(name):
                remove(name, ddir)
                gone += 1
            continue
        if is_open(name, state_dir) or _alive(r.get('pid')):
            continue
        if r.get('reason') in SHRED_REASONS:
            shred(r, ddir)
            gone += 1
            continue
        closed = r.get('closed')
        if not isinstance(closed, int):
            mark_closed(name, 'closed', ddir=ddir, now=now)
            continue
        if now - closed > RETAIN:
            shred(r, ddir)
            gone += 1
    return gone


def retained_files(ddir=None):
    """Real paths of every owned/staged file a recipe still holds (Pocket's
    sealed-upload sweep must not take them)."""
    out = set()
    try:
        names = os.listdir(doors_dir(ddir))
    except OSError:
        return out
    for fn in names:
        if fn.endswith('.json') and not fn.startswith('.'):
            r = load(fn[:-5], ddir)
            if r is None:
                continue
            inputs = r.get('inputs') if isinstance(r.get('inputs'), dict) else {}
            for p in list(inputs.get('owned') or []) + list(r.get('staged') or []) \
                    + [inputs.get('path')]:
                if isinstance(p, str):
                    out.add(os.path.realpath(p))
    return out


# ---- reopening --------------------------------------------------------------------

def check(name, ddir=None, state_dir=None, now=None):
    """The validated recipe of a door that can be reopened now, or
    RecipeError saying why not."""
    now = int(time.time() if now is None else now)
    r = load(name, ddir)
    if r is None:
        raise RecipeError(f'{name} has no launch recipe (only doors opened since reopen '
                          'existed, by view/seal/serve/paste/media/photos/music/drop, can reopen)')
    rtype = r.get('type')
    if rtype not in TYPES:
        raise RecipeError(f'{name}: unknown type {rtype!r}')
    if is_open(name, state_dir):
        raise RecipeError(f'{name} is open already')
    if r.get('reason') in SHRED_REASONS:
        raise RecipeError(f'{name} was {r["reason"]}: its files are gone and it stays closed')
    closed = r.get('closed')
    if isinstance(closed, int) and now - closed > RETAIN:
        raise RecipeError(f'{name} closed more than 7 days ago')
    inputs = r.get('inputs') if isinstance(r.get('inputs'), dict) else {}
    flags = inputs.get('flags') or []
    if not isinstance(flags, list) or _clean_flags(rtype, flags) != flags:
        raise RecipeError(f'{name}: the recipe has flags it should not')
    path = inputs.get('path')
    owned = inputs.get('owned') or []
    if not isinstance(owned, list):
        raise RecipeError(f'{name}: bad recipe')
    for p in owned:
        if not owned_ok(rtype, name, p, inputs.get('owned_dir')):
            raise RecipeError(f'{name}: an owned file is outside its private directory')
    if rtype in ('view', 'seal', 'paste'):
        if not isinstance(path, str) or not os.path.isabs(path):
            raise RecipeError(f'{name}: the recipe names no file')
        if os.path.realpath(path) != path or not os.path.isfile(path):
            raise RecipeError(f'{name}: {path} is gone')
        if rtype in ('seal', 'paste') or owned:
            if owned and owned != [path]:
                raise RecipeError(f'{name}: bad recipe')
    elif rtype == 'serve':
        if not isinstance(path, str) or os.path.realpath(path) != path or not os.path.isdir(path):
            raise RecipeError(f'{name}: the folder is gone')
    if rtype == 'seal' and inputs.get('owned_dir') and not _owned_dir_ok(inputs['owned_dir']):
        raise RecipeError(f'{name}: its owned dir is not private any more')
    return r


def argv_for(r, expires):
    """The launcher argv for a checked recipe: only allowlisted pieces."""
    name, rtype = r['name'], r['type']
    inputs = r.get('inputs') or {}
    flags = list(inputs.get('flags') or [])
    path = inputs.get('path')
    owned = bool(inputs.get('owned'))
    launcher = os.path.join(BIN_DIR, rtype)
    if rtype == 'view':
        argv = [launcher, path, name] + flags + (['--owned-file'] if owned else [])
    elif rtype == 'seal':
        argv = [launcher, path, name]
        if owned:
            argv.append('--owned-file')
            if inputs.get('owned_dir'):
                argv += ['--owned-dir', inputs['owned_dir']]
    elif rtype == 'serve':
        argv = [launcher, path, name] + flags
    elif rtype == 'paste':
        argv = [launcher, name, path]
    else:
        argv = [launcher, name] + flags
    return argv + ['--reopen', '--expires', expires, '--bg']


def spec_for_reopen(name, expires, ddir=None, now=None):
    """The door spec a launcher run with --reopen uses: the recipe's rules
    and inspector, the new expiry. Refused for a door that can't reopen."""
    now = int(time.time() if now is None else now)
    r = check(name, ddir, now=now)
    spec = {'expires': door_state.parse_expires(expires, now), 'rules': door_state.clean_rules(
        r.get('rules')), 'reopen': True}
    ins = door_state.clean_inspect(r.get('inspect'))
    if ins:
        spec['inspect'] = ins
    return spec


def _env():
    return {k: v for k, v in os.environ.items() if k not in ENV_DROP}


def run_launcher(argv, timeout=REOPEN_TIMEOUT):
    """argv in its own session, no shell; (returncode, stdout, stderr)."""
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=_env(), cwd=REPO_DIR,
                            start_new_session=True)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, 9)
        except OSError:
            pass
        proc.communicate()
        return 124, '', 'timed out'
    return proc.returncode, out.decode('utf-8', 'replace'), err.decode('utf-8', 'replace')


def _last_line(text):
    lines = [ln.strip() for ln in (text or '').splitlines() if ln.strip()]
    line = lines[-1] if lines else ''
    return re.sub(r'\x1b\[[0-9;]*m', '', ''.join(c if c.isprintable() else ' ' for c in line))[:300]


def reopen(name, expires='1h', ddir=None, state_dir=None, runner=None, now=None,
           ok_if_open=False):
    """Relaunch door `name` from its recipe, open until `expires` (1h, 24h,
    ...). Returns the new state dict. RecipeError when it can't. With
    ok_if_open, a door that is open already (someone reopened it first)
    counts as done."""
    now = int(time.time() if now is None else now)
    if ok_if_open and is_open(name, state_dir):
        return door_state.read_state(door_state.state_path(name, state_dir))
    try:
        door_state.parse_expires(expires, now)
    except door_state.DoorError as e:
        raise RecipeError(str(e)) from None
    r = check(name, ddir, state_dir, now)
    argv = argv_for(r, expires)
    rc, out, err = (runner or run_launcher)(argv)
    if rc != 0:
        raise RecipeError(f'{name} did not reopen: {_last_line(err) or _last_line(out) or f"exit {rc}"}')
    spath = door_state.state_path(name, state_dir)
    tag = r.get('pocket')
    try:
        if isinstance(tag, dict):
            def fn(s):
                s['pocket'] = tag
            return door_state.update_state(spath, fn)
        return door_state.read_state(spath)
    except (OSError, ValueError):
        return {'name': name, 'type': r['type']}


# ---- CLI ------------------------------------------------------------------------

def _opt(rest, flag, many=False):
    vals, out, i = [], [], 0
    while i < len(rest):
        if rest[i] == flag and i + 1 < len(rest):
            vals.append(rest[i + 1])
            i += 2
            continue
        out.append(rest[i])
        i += 1
    rest[:] = out
    return vals if many else (vals[-1] if vals else None)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(__doc__.split('CLI', 1)[1], file=sys.stderr)
        return 2
    cmd, rest = argv[0], argv[1:]
    try:
        if cmd == 'write':
            name, rtype, pid = _opt(rest, '--name'), _opt(rest, '--type'), _opt(rest, '--pid')
            path, owned_dir = _opt(rest, '--path'), _opt(rest, '--owned-dir')
            flags, owned = _opt(rest, '--flag', True), _opt(rest, '--owned', True)
            try:
                spec = json.loads(os.environ.get('_PORCH_DOOR_SPEC') or '{}')
            except ValueError:
                spec = {}
            write(name, rtype, int(pid or 0), spec, path, flags, owned, owned_dir)
            return 0
        if cmd == 'launched' and len(rest) == 2:
            launched(rest[0], int(rest[1]))
            return 0
        if cmd == 'closed' and len(rest) >= 2:
            sf = _opt(rest, '--state-file')
            state = None
            if sf:
                try:
                    state = door_state.read_state(sf)
                except (OSError, ValueError):
                    state = None
            mark_closed(rest[0], rest[1], state)
            return 0
        if cmd == 'release' and len(rest) == 1:
            print(release(rest[0]))
            return 0
        if cmd == 'spec' and len(rest) >= 1:
            exp = _opt(rest, '--expires') or '1h'
            print(json.dumps(spec_for_reopen(rest[0], exp)))
            return 0
        if cmd == 'reopen' and len(rest) >= 1:
            exp = _opt(rest, '--expires') or '1h'
            st = reopen(rest[0], exp)
            print(f'{rest[0]}: open again, expires {door_state.fmt_expires(st)}')
            return 0
        if cmd == 'prune' and not rest:
            print(prune())
            return 0
    except (RecipeError, door_state.DoorError) as e:
        print(f'Error: {e}', file=sys.stderr)
        return 2
    except (OSError, ValueError) as e:
        print(f'Error: {e}', file=sys.stderr)
        return 1
    print(f'door_recipe.py: bad usage: {" ".join(argv)}', file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main())

"""Make link (lib/pocketserver.py): turn an inbox file, a clipboard entry or a
sealed upload into its own door, and list the doors this pocket made."""

import os
import re
import secrets
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import door_state  # noqa: E402

from pocket_core import clean_label  # noqa: E402

REPO_DIR = os.path.dirname(_HERE)


# ---- links: doors made from Pocket -------------------------------------------
#
# "Make link" turns an inbox file, a clipboard entry or a sealed (end-to-end
# encrypted) upload into its own door: `porch share` for the first two, bin/seal
# for the last, run via argv (never a shell) with the door flags the sheet
# picked. The password goes to the launcher in PORCH_DOOR_PASSWORD only. Every
# such door is named pk-<slug>-<hex> and tagged in its state file
# (/tmp/tunnel-state/<name>.json) with {"pocket": {"name", "kind", "label"}},
# which is what the links panel lists and the only doors its actions touch.

LINK_EXPIRY = ('1h', '24h', '7d', 'never')
MAX_LINKS = 20                         # live doors one pocket may have made
LINK_TIMEOUT = 90                      # s a launcher may take (media copies the file)
MAX_LINK_OPENS = 1000
_LINK_NAME = re.compile(r'^pk-[a-z0-9](?:[a-z0-9-]{0,36}[a-z0-9])?$')
# Never handed to a launcher: they would make it think it is already a
# daemon (it would then run in the foreground), or carry another door's spec.
LAUNCHER_ENV_DROP = ('_CUSH_DAEMONIZED', 'PORCH_LOG_FILE', 'CUSH_LOG_FILE', '_PORCH_DOOR_SPEC',
                     'TUNNEL_NO_STATE', 'PORCH_DOOR_PASSWORD')


class LinkError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.message = message
        self.status = status


class LinkTimeout(Exception):
    pass


def link_slug(text, max_len=20):
    s = re.sub(r'[^a-z0-9]+', '-', (text or '').lower()).strip('-')
    return s[:max_len].strip('-') or 'item'


def new_link_name(label):
    return f'pk-{link_slug(os.path.splitext(label or "")[0])}-{secrets.token_hex(2)}'


def parse_link_rules(rules):
    """The sheet's rules -> (door flags, password or None). LinkError when a
    field is unknown or out of range."""
    if rules is None:
        rules = {}
    if not isinstance(rules, dict):
        raise LinkError('rules must be an object')
    unknown = set(rules) - {'expires', 'password', 'burn', 'max_opens', 'guest'}
    if unknown:
        raise LinkError(f'unknown rule {sorted(unknown)[0]!r}')
    expires = rules.get('expires', '24h')
    if expires not in LINK_EXPIRY:
        raise LinkError('expires must be one of ' + ', '.join(LINK_EXPIRY))
    flags = ['--expires', expires]
    password = rules.get('password')
    if password in (None, ''):
        password = None
    elif (not isinstance(password, str)
          or not door_state.MIN_PASSWORD <= len(password) <= door_state.MAX_PASSWORD
          or '\x00' in password):
        raise LinkError(f'the password needs {door_state.MIN_PASSWORD} to '
                        f'{door_state.MAX_PASSWORD} characters')
    else:
        flags.append('--password')
    burn = rules.get('burn', False)
    max_opens = rules.get('max_opens')
    if not isinstance(burn, bool):
        raise LinkError('burn must be true or false')
    if max_opens is not None and (isinstance(max_opens, bool) or not isinstance(max_opens, int)
                                  or not 1 <= max_opens <= MAX_LINK_OPENS):
        raise LinkError(f'max_opens must be a whole number from 1 to {MAX_LINK_OPENS}')
    if burn:
        flags.append('--burn')
    elif max_opens is not None:
        flags += ['--max-opens', str(max_opens)]
    guest = rules.get('guest', False)
    if not isinstance(guest, bool):
        raise LinkError('guest must be true or false')
    if guest:
        flags.append('--guest-link')
    return flags, password


def launcher_env(password=None, base=None):
    env = {k: v for k, v in (os.environ if base is None else base).items()
           if k not in LAUNCHER_ENV_DROP}
    if password:
        env['PORCH_DOOR_PASSWORD'] = password
    return env


def run_launcher(argv, env, data, timeout):
    """Run a door launcher (it daemonizes the door itself with --bg) in its
    own session. (returncode, stdout, stderr); LinkTimeout after `timeout`
    seconds, with the launcher's process group killed."""
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                            cwd=REPO_DIR, start_new_session=True)
    try:
        out, err = proc.communicate(data, timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, 9)
        except OSError:
            pass
        try:
            proc.communicate(timeout=5)
        except Exception:  # noqa: BLE001
            pass
        raise LinkTimeout()
    return proc.returncode, out.decode('utf-8', 'replace'), err.decode('utf-8', 'replace')


def close_door(name):
    """bin/status close <name> (argv, never a shell)."""
    try:
        subprocess.run([os.path.join(REPO_DIR, 'bin', 'status'), 'close', name],
                       env=launcher_env(), cwd=REPO_DIR, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=30, start_new_session=True)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _pid_alive(pid):
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        return False
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def _clean_line(text, cap=300):
    """The last meaningful line of a launcher's output, safe to show."""
    lines = [ln.strip() for ln in (text or '').splitlines() if ln.strip()]
    if not lines:
        return ''
    line = ''.join(ch if ch.isprintable() else ' ' for ch in lines[-1])
    return re.sub(r'\x1b\[[0-9;]*m', '', line)[:cap]


def pocket_links(state_dir, pocket_name):
    """State dicts of the doors this pocket made (tagged, pk- names)."""
    out = []
    try:
        names = os.listdir(state_dir)
    except OSError:
        return out
    for fn in sorted(names):
        if not (fn.startswith('pk-') and fn.endswith('.json')) or not _LINK_NAME.match(fn[:-5]):
            continue
        try:
            st = door_state.read_state(os.path.join(state_dir, fn))
        except (OSError, ValueError):
            continue
        tag = st.get('pocket')
        if isinstance(tag, dict) and tag.get('name') == pocket_name and st.get('name') == fn[:-5]:
            out.append(st)
    return out


def links_sig(state_dir):
    """Changes whenever a pk- state file is added, removed or rewritten."""
    sig = []
    try:
        names = os.listdir(state_dir)
    except OSError:
        return None
    for fn in sorted(names):
        if fn.startswith('pk-') and fn.endswith('.json'):
            try:
                sig.append((fn, os.stat(os.path.join(state_dir, fn)).st_mtime_ns))
            except OSError:
                pass
    return tuple(sig)


def tunnel_url(name):
    # An invalid config raises porch_config.ConfigError: never a guessed domain.
    import porch_config
    return porch_config.get().tunnel_url(name, '/')


def public_link(st):
    tag = st.get('pocket') if isinstance(st.get('pocket'), dict) else {}
    rules = door_state.clean_rules(st.get('rules'))
    name = st.get('name')
    return {
        'name': name,
        'url': tunnel_url(name),
        'type': st.get('type') if isinstance(st.get('type'), str) else '',
        'kind': tag.get('kind') if isinstance(tag.get('kind'), str) else '',
        'label': clean_label(tag.get('label')) if isinstance(tag.get('label'), str) else '',
        'opens': st.get('opens') if isinstance(st.get('opens'), int) else 0,
        'last_open': st.get('last_open') if isinstance(st.get('last_open'), (int, float)) else None,
        'started': st.get('started') if isinstance(st.get('started'), (int, float)) else None,
        'expires': door_state.expires_of(st),
        'rules': door_state.public_rules(rules),
        'guest_url': door_state.guest_url(name, rules['guest']) if 'guest' in rules else None,
        'alive': _pid_alive(st.get('pid')),
    }

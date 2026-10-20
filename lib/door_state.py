#!/usr/bin/env python3
"""Door state: expiry parsing, share rules, locked state-file updates.

A "door" is one running tool behind a tunnel; its state lives in
/tmp/tunnel-state/<name>.json (written by tunnel_state_register in
lib/tunnel-state.sh). This module owns the fields the door proxy, the
watchdog, bin/status, `porch door` and the status API share:

    expires     epoch seconds, or null = never (keep_alive is an alias)
    rules       {"password": "scrypt$...", "guest": "<token>", "max_opens": N}
                (each key optional; only a salted scrypt hash is ever stored)
    opens       page views counted by the door proxy
    last_open   epoch of the latest counted open, or null
    proxy       {"port": P, "pid": X} when bin/tunnel put lib/doorproxy.py in front
    tunnel_pid  bin/tunnel's own pid (it restarts frpc behind a new proxy on
                SIGUSR1), with `proto` (http/https/tcp/udp)
    inspect     {"raw": bool} when the door records its requests (--inspect,
                --inspect-raw; lib/inspect_store.py); absent otherwise
    capture     {"status", "content_type", "body", "max_body_mb"}: a bin/hook
                webhook door (no app; the proxy answers every request)
    opens_by    "app" when the app counts opens itself (bin/seal: a complete
                ciphertext download is an open). The door proxy then counts
                nothing and never closes the door for max_opens; the app calls
                count_open() and stop_door(). Absent = the proxy counts.

Every read-modify-write goes through update_state(), which holds an flock on
<state dir>/.<name>.lock, so the proxy's open counter and a panel/CLI edit
cannot lose each other's writes.

CLI (used by lib/door-flags.sh and bin/status):
    door_state.py spec [--expires W] [--password] [--guest-link] [--max-opens N] [--burn]
                       [--inspect | --inspect-raw]
    door_state.py summary <name>            (spec JSON from $_PORCH_DOOR_SPEC)
    door_state.py expire <state-file> <when|never>
    door_state.py keep <state-file>
    door_state.py extend <state-file> <minutes>
    door_state.py describe <state-file>     (bin/status: "expires|opens|rules")
    door_state.py has-rules <state-file>    (exit 0 when the door has share rules)
    door_state.py needs-proxy <state-file>  (exit 0: rules, inspector or capture)
    door_state.py proxy-args <state-file>   (doorproxy flags, one per line)
    door_state.py set-capture <state-file> <status> <content-type> [max-body-mb]
                                            (response body on stdin, bin/hook)
    door_state.py set-tunnel <state-file> <pid> <proto>
                                            (bin/tunnel: whom `porch door rules`
                                            signals to put a proxy in front live)
    door_state.py set-opens-by <state-file> app|proxy
                                            (bin/seal: the app counts opens)
    door_state.py parse-expires <when>      (prints epoch or "never")
"""

import base64
import errno
import fcntl
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import signal
import stat
import sys
import tempfile
import time
from datetime import datetime, timezone

STATE_DIR = '/tmp/tunnel-state'
DEFAULT_TTL = 3600
MAX_TTL = 366 * 86400          # an absolute expiry further out than this is a typo
MIN_PASSWORD = 6
MAX_PASSWORD = 1024
MAX_OPENS = 1_000_000
CAPTURE_MAX_BODY_MB = 10        # default request body cap of a bin/hook door
CAPTURE_BODY_MAX = 64 * 1024    # the configured response body

# scrypt cost: ~16MB and a few tens of ms per check. The proxy rate-limits
# wrong guesses per IP and runs at most a couple of checks at once.
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1
SCRYPT_MAXMEM = 64 * 1024 * 1024

NAME_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')


class DoorError(ValueError):
    """Bad user input (an expiry, a rule); the message is user-facing."""


# ---- expiry ------------------------------------------------------------------

_REL_RE = re.compile(r'^\+?([0-9]{1,6})\s*(s|m|min|h|d|w)?$', re.I)
_UNIT = {'s': 1, 'm': 60, 'min': 60, 'h': 3600, 'd': 86400, 'w': 7 * 86400}


def parse_expires(text, now=None):
    """`30m`, `2h`, `1d`, `+90m`, an ISO-8601 time (naive = local time, `Z`
    or an offset allowed) or `never` -> epoch int, or None for never.
    A bare number is minutes. Past times, zero and anything over a year
    are refused with DoorError."""
    now = int(time.time() if now is None else now)
    if not isinstance(text, str) or not text.strip():
        raise DoorError('expiry is empty')
    t = text.strip()
    if t.lower() in ('never', 'none', 'forever', 'inf'):
        return None
    m = _REL_RE.match(t)
    if m:
        n = int(m.group(1))
        secs = n * _UNIT[(m.group(2) or 'm').lower()]
        if secs <= 0:
            raise DoorError(f'expiry must be in the future: {text}')
        at = now + secs
    else:
        iso = t[:-1] + '+00:00' if t.endswith(('Z', 'z')) else t
        try:
            dt = datetime.fromisoformat(iso)
        except ValueError:
            raise DoorError(f"can't read expiry {text!r}: use 30m, 2h, 1d, "
                            "an ISO-8601 time (2026-10-20T18:00) or never") from None
        at = int(dt.timestamp())  # naive -> local time
        if at <= now:
            raise DoorError(f'expiry is in the past: {text}')
    if at - now > MAX_TTL:
        raise DoorError(f'expiry is more than a year out: {text} (use never)')
    return at


def coerce_expires(value, now=None):
    """API form: an epoch number, "never"/None, or a parse_expires string."""
    now = int(time.time() if now is None else now)
    if value is None:
        return None
    if isinstance(value, bool):
        raise DoorError('invalid expiry')
    if isinstance(value, (int, float)):
        at = int(value)
        if at <= now:
            raise DoorError('expiry is in the past')
        if at - now > MAX_TTL:
            raise DoorError('expiry is more than a year out (use never)')
        return at
    if isinstance(value, str):
        return parse_expires(value, now)
    raise DoorError('invalid expiry')


def expires_of(state):
    """The effective expiry of a state dict: None = never (keep_alive or a
    null/absent `expires` on a door that has a `rules` key), else an int."""
    if state.get('keep_alive'):
        return None
    exp = state.get('expires')
    if exp is None:
        return None
    try:
        return int(exp)
    except (TypeError, ValueError):
        return 0


def fmt_expires(state, now=None):
    exp = expires_of(state)
    if exp is None:
        return 'never'
    now = int(time.time() if now is None else now)
    left = exp - now
    when = datetime.fromtimestamp(exp).strftime('%Y-%m-%d %H:%M')
    if left <= 0:
        return f'expired ({when})'
    h, m = divmod(left // 60, 60)
    return f'{when} (in {h}h {m}m)' if h else f'{when} (in {max(m, 1)}m)'


# ---- passwords ---------------------------------------------------------------

def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')


def _unb64(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def hash_password(password):
    """scrypt$N$r$p$<salt>$<key>, salt 16 random bytes. Never the password."""
    if not isinstance(password, str) or len(password) < MIN_PASSWORD:
        raise DoorError(f'password must be at least {MIN_PASSWORD} characters')
    if len(password) > MAX_PASSWORD:
        raise DoorError('password is too long')
    salt = secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                         p=SCRYPT_P, maxmem=SCRYPT_MAXMEM, dklen=32)
    return f'scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(key)}'


def verify_password(password, stored):
    """Constant-time check of `password` against a hash_password() string."""
    try:
        kind, n, r, p, salt, key = stored.split('$')
        n, r, p = int(n), int(r), int(p)
        if kind != 'scrypt' or n > 2 ** 20 or r > 32 or p > 4:
            return False
        want = _unb64(key)
        got = hashlib.scrypt(password.encode('utf-8')[:MAX_PASSWORD * 4], salt=_unb64(salt),
                             n=n, r=r, p=p, maxmem=SCRYPT_MAXMEM, dklen=len(want))
    except (AttributeError, ValueError, TypeError):
        return False
    return hmac.compare_digest(got, want)


def is_password_hash(v):
    return isinstance(v, str) and v.startswith('scrypt$') and v.count('$') == 5


def new_guest_token():
    return secrets.token_urlsafe(24)


def read_password(env=None, confirm=True):
    """PORCH_DOOR_PASSWORD, else a prompt on the controlling terminal (never
    argv, never stdin: paste/exchange read their content from stdin)."""
    env = os.environ if env is None else env
    pw = env.get('PORCH_DOOR_PASSWORD')
    if pw:
        return pw
    try:
        tty = open('/dev/tty', 'r+')
    except OSError:
        raise DoorError('--password needs PORCH_DOOR_PASSWORD or a terminal to prompt on') from None
    with tty:
        pw = getpass.getpass('Door password: ', stream=tty)
        if confirm and getpass.getpass('Again: ', stream=tty) != pw:
            raise DoorError('passwords do not match')
    return pw


# ---- rules -------------------------------------------------------------------

def clean_rules(rules):
    """Keep only well-formed rule keys (a hand-edited or hostile state file
    must not crash the proxy or the API)."""
    out = {}
    if not isinstance(rules, dict):
        return out
    if is_password_hash(rules.get('password')):
        out['password'] = rules['password']
    g = rules.get('guest')
    if isinstance(g, str) and 16 <= len(g) <= 128 and re.fullmatch(r'[A-Za-z0-9_-]+', g):
        out['guest'] = g
    mo = rules.get('max_opens')
    if isinstance(mo, int) and not isinstance(mo, bool) and 1 <= mo <= MAX_OPENS:
        out['max_opens'] = mo
    return out


def public_rules(rules):
    """What an API/listing may show: which rules are on, never a hash or token."""
    r = clean_rules(rules)
    return {'password': 'password' in r, 'guest_link': 'guest' in r,
            'max_opens': r.get('max_opens')}


def rules_summary(rules):
    r = clean_rules(rules)
    parts = []
    if 'password' in r:
        parts.append('password')
    if 'guest' in r:
        parts.append('guest link')
    mo = r.get('max_opens')
    if mo == 1:
        parts.append('burn after 1 open')
    elif mo:
        parts.append(f'max {mo} opens')
    return ', '.join(parts) or 'none'


def clean_inspect(v):
    """{"raw": bool} for an inspected door, else None."""
    if isinstance(v, dict):
        return {'raw': v.get('raw') is True}
    return None


def clean_capture(v):
    if not isinstance(v, dict):
        return None
    st = v.get('status')
    if not isinstance(st, int) or isinstance(st, bool) or not 200 <= st <= 599:
        st = 200
    ct = v.get('content_type')
    if not isinstance(ct, str) or not ct or len(ct) > 200 or any(c in ct for c in '\r\n'):
        ct = 'text/plain; charset=utf-8'
    body = v.get('body')
    if not isinstance(body, str):
        body = 'ok\n'
    return {'status': st, 'content_type': ct, 'body': body[:CAPTURE_BODY_MAX],
            'max_body_mb': capture_max_body(v) // (1024 * 1024)}


def capture_max_body(capture):
    """The request body cap of a capture door, in bytes."""
    mb = (capture or {}).get('max_body_mb') if isinstance(capture, dict) else None
    if not isinstance(mb, int) or isinstance(mb, bool) or not 1 <= mb <= 1024:
        mb = CAPTURE_MAX_BODY_MB
    return mb * 1024 * 1024


def needs_proxy(state):
    return bool(clean_rules(state.get('rules')) or clean_inspect(state.get('inspect'))
                or isinstance(state.get('capture'), dict))


def app_counts_opens(state):
    return state.get('opens_by') == 'app'


def count_open(path, now=None):
    """An app that counts its own opens (opens_by = app) records one. Returns
    (opens, max_opens or None) after the write; FileNotFoundError when the
    door is gone. The limit is read from the live rules, so `porch door
    rules --burn` on a running door applies to the next open."""
    now = int(time.time() if now is None else now)
    out = {}

    def fn(s):
        try:
            opens = int(s.get('opens') or 0)
        except (TypeError, ValueError):
            opens = 0
        s['opens'] = opens + 1
        s['last_open'] = now
        out['opens'] = opens + 1
        out['max'] = clean_rules(s.get('rules')).get('max_opens')
    update_state(path, fn)
    return out['opens'], out['max']


def proxy_args(state):
    out = []
    ins = clean_inspect(state.get('inspect'))
    if ins:
        out.append('--inspect-raw' if ins['raw'] else '--inspect')
    if isinstance(state.get('capture'), dict):
        out.append('--capture')
    return out


def build_spec(expires=None, password=False, guest_link=False, max_opens=None, burn=False,
               now=None, env=None, inspect=False, inspect_raw=False):
    """The launch-time door spec a launcher hands tunnel_state_register (via
    $_PORCH_DOOR_SPEC): {"expires": epoch|None, "rules": {...}}. `expires`
    is a parse_expires string, or None for the default hour."""
    now = int(time.time() if now is None else now)
    spec = {'expires': now + DEFAULT_TTL if expires is None else parse_expires(expires, now),
            'rules': {}}
    if burn and max_opens is not None:
        raise DoorError('--burn and --max-opens go separately (burn = --max-opens 1)')
    if burn:
        max_opens = 1
    if max_opens is not None:
        try:
            max_opens = int(max_opens)
        except (TypeError, ValueError):
            raise DoorError(f'--max-opens needs a number (got {max_opens!r})') from None
        if not 1 <= max_opens <= MAX_OPENS:
            raise DoorError('--max-opens must be at least 1')
        spec['rules']['max_opens'] = max_opens
    if password:
        spec['rules']['password'] = hash_password(read_password(env))
    if guest_link:
        spec['rules']['guest'] = new_guest_token()
    if inspect or inspect_raw:
        spec['inspect'] = {'raw': bool(inspect_raw)}
    return spec


def guest_url(name, token, tunnel_base=None):
    if tunnel_base is None:
        # An invalid config raises porch_config.ConfigError: never a guessed domain.
        import porch_config
        tunnel_base = porch_config.get().tunnel_base
    return f'https://{name}.{tunnel_base}/?k={token}'


# ---- state files -------------------------------------------------------------

def state_path(name, state_dir=None):
    if not NAME_RE.match(name or ''):
        raise DoorError(f'invalid door name: {name!r}')
    return os.path.join(state_dir or STATE_DIR, f'{name}.json')


def read_state(path):
    with open(path, 'r') as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError('state file is not an object')
    return data


def write_state_atomic(path, data):
    """Unique 0600 temp file in the same dir, fsync, rename. The temp name
    does not end in .json, so a listing never picks it up. 0600 because a
    door's state carries its rules (a password hash, a guest token)."""
    d, base = os.path.split(os.path.abspath(path))
    stem = base[:-5] if base.endswith('.json') else base
    fd, tmp = tempfile.mkstemp(prefix=f'.{stem}.', suffix='.tmp', dir=d)
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


def _open_private(path, flags):
    """Open a file we own in the shared state dir, refusing symlinks and
    files owned by someone else."""
    fd = os.open(path, flags | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0), 0o600)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
        os.close(fd)
        raise OSError(errno.EPERM, f'refusing {path}: not a regular file of ours')
    return fd


def lock_path(path):
    d, base = os.path.split(os.path.abspath(path))
    stem = base[:-5] if base.endswith('.json') else base
    return os.path.join(d, f'.{stem}.lock')


def update_state(path, fn):
    """Read-modify-write a state file under its lock file. `fn(state)` edits
    the dict in place (or returns a replacement, or False to write nothing).
    Returns the resulting state.
    FileNotFoundError if the door is gone (never recreated here)."""
    fd = _open_private(lock_path(path), os.O_RDWR | os.O_CREAT)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        state = read_state(path)
        new = fn(state)
        if new is False:        # fn decided nothing changes: skip the write
            return state
        if new is not None:
            state = new
        write_state_atomic(path, state)
        return state
    finally:
        os.close(fd)


def load_or_create_secret(state_dir, name):
    """The door's 32-byte cookie-signing key, <state dir>/.<name>.secret
    (0600, created once per door; removed with the state file)."""
    path = os.path.join(state_dir, f'.{name}.secret')
    try:
        fd = _open_private(path, os.O_RDWR | os.O_CREAT | os.O_EXCL)
        try:
            key = secrets.token_bytes(32)
            os.write(fd, key.hex().encode('ascii'))
            return key
        finally:
            os.close(fd)
    except FileExistsError:
        pass
    fd = _open_private(path, os.O_RDONLY)
    try:
        raw = os.read(fd, 256).decode('ascii', 'replace').strip()
    finally:
        os.close(fd)
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        key = b''
    if len(key) < 32:
        raise OSError(errno.EINVAL, f'{path} is not a door secret')
    return key


# ---- edits shared by bin/status, porch door and the status API -----------------

def set_expiry(path, at):
    """at: epoch int or None (never). Never also sets keep_alive, so older
    readers that only know keep_alive agree."""
    def fn(s):
        s['expires'] = at
        s['keep_alive'] = at is None
    return update_state(path, fn)


def extend(path, seconds, now=None):
    now = int(time.time() if now is None else now)

    def fn(s):
        cur = expires_of(s)
        if cur is None:
            return
        s['expires'] = max(cur, now) + seconds
    return update_state(path, fn)


# ---- stopping a door (the statusserver stop path) -----------------------------

FRPC_CONF_SUFFIX_RE = re.compile(r'^[A-Za-z0-9]+\.toml$')


def frpc_pids_for(name, proc='/proc'):
    """PIDs of real frpc processes running THIS tunnel's generated config,
    /tmp/frpc-<name>-<alnum>.toml (the same rule as tunnel_kill_frpc in
    lib/tunnel-state.sh). Matching the exact filename shape means stopping
    `c` never touches `chat`'s frpc, and an editor that merely mentions the
    path is never returned (its executable is not frpc)."""
    prefix = f'/tmp/frpc-{name}-'
    pids = []
    try:
        entries = os.listdir(proc)
    except OSError:
        return pids
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(os.path.join(proc, entry, 'cmdline'), 'rb') as f:
                argv = [a.decode('utf-8', 'replace') for a in f.read().split(b'\0') if a]
        except OSError:
            continue
        if not argv or os.path.basename(argv[0]) != 'frpc':
            continue
        for a in argv[1:]:
            if a.startswith(prefix) and FRPC_CONF_SUFFIX_RE.match(a[len(prefix):]):
                pids.append(int(entry))
                break
    return pids


def kill_frpc_for(name):
    killed = 0
    for pid in frpc_pids_for(name):
        try:
            os.kill(pid, signal.SIGTERM)
            killed += 1
        except OSError:
            pass
    return killed


def stop_door(name, state_dir=None, reason='closed'):
    """SIGTERM the launcher pid recorded in the state file, kill the frpc
    running this door's exact config, remove the state file: what the status
    API's Stop does. The launcher's EXIT trap takes the app server and the
    door proxy down with it. `reason` goes in the door's launch recipe first
    (lib/door_recipe.py): `closed` keeps it reopenable, `used-up` / `burned`
    shred its files."""
    path = state_path(name, state_dir)
    try:
        st = read_state(path)
    except (OSError, ValueError):
        st = {}
    record_close(name, reason, st)
    pid = st.get('pid')
    if isinstance(pid, int) and not isinstance(pid, bool) and pid > 1 and pid != os.getpid():
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    kill_frpc_for(name)
    cleanup_files(name, state_dir)
    if reason in ('used-up', 'burned'):
        # Shred its files now: the launcher's exit trap may never run (bin/status
        # follows TERM with KILL), and a burn has to hold regardless.
        try:
            import door_recipe
            door_recipe.release(name)
        except Exception:  # noqa: BLE001
            pass


def record_close(name, reason, state=None):
    """Why the door closed, into its launch recipe (never fails a stop)."""
    try:
        import door_recipe
        door_recipe.mark_closed(name, reason, state)
    except Exception:  # noqa: BLE001
        pass


def cleanup_files(name, state_dir=None):
    d = state_dir or STATE_DIR
    for p in (f'{name}.json', f'.{name}.lock', f'.{name}.secret'):
        try:
            os.unlink(os.path.join(d, p))
        except OSError:
            pass
    # The inspector's records go with the door (the proxy also removes them
    # on its way out).
    try:
        import inspect_store
        inspect_store.remove_store(name)
    except Exception:  # noqa: BLE001
        pass


# ---- CLI -----------------------------------------------------------------------

def _cli_spec(args):
    import argparse
    p = argparse.ArgumentParser(prog='door_state.py spec')
    p.add_argument('--expires')
    p.add_argument('--password', action='store_true')
    p.add_argument('--guest-link', action='store_true')
    p.add_argument('--max-opens')
    p.add_argument('--burn', action='store_true')
    p.add_argument('--inspect', action='store_true')
    p.add_argument('--inspect-raw', action='store_true')
    a = p.parse_args(args)
    spec = build_spec(a.expires, a.password, a.guest_link, a.max_opens, a.burn,
                      inspect=a.inspect, inspect_raw=a.inspect_raw)
    print(json.dumps(spec))
    return 0


def _cli_summary(name, show_token=True):
    raw = os.environ.get('_PORCH_DOOR_SPEC') or ''
    try:
        spec = json.loads(raw) if raw else {}
    except ValueError:
        spec = {}
    rules = clean_rules(spec.get('rules'))
    state = {'expires': spec.get('expires', None) if spec else int(time.time()) + DEFAULT_TTL}
    print(f'Expires: {fmt_expires(state)}')
    if rules:
        print(f'Rules: {rules_summary(rules)}')
    if 'guest' in rules:
        if show_token:
            print(f'Guest link: {guest_url(name, rules["guest"])}')
        else:
            print('Guest link: (printed by the launcher; also `porch door ls`)')
    ins = clean_inspect(spec.get('inspect')) if spec else None
    if ins:
        print(f'Inspector: on ({"RAW: secrets recorded unmasked" if ins["raw"] else "secret headers masked"})'
              f'; watch with: porch inspect {name} --follow')
        if ins['raw'] and show_token:
            print('Warning: --inspect-raw records Authorization, Cookie and token headers unmasked, '
                  'as sent (in your private run dir, deleted when the door closes).',
                  file=sys.stderr)
    return 0


def _cli_set_capture(path, status, ctype, max_mb=None):
    try:
        st = int(status)
    except ValueError:
        raise DoorError(f'--status must be a number (got {status!r})') from None
    if not 200 <= st <= 599:
        raise DoorError('--status must be 200-599')
    if not ctype or len(ctype) > 200 or not re.fullmatch(r'[\x20-\x7e]+', ctype) \
            or '/' not in ctype:
        raise DoorError(f'bad --content-type: {ctype!r}')
    body = sys.stdin.buffer.read(CAPTURE_BODY_MAX + 1)
    if len(body) > CAPTURE_BODY_MAX:
        raise DoorError('--body is limited to 64KB')
    cap = {'status': st, 'content_type': ctype, 'body': body.decode('utf-8', 'replace')}
    if max_mb is not None:
        try:
            mb = int(max_mb)
        except ValueError:
            raise DoorError('--max-body-mb must be a whole number') from None
        if not 1 <= mb <= 1024:
            raise DoorError('--max-body-mb must be 1-1024')
        cap['max_body_mb'] = mb

    def fn(s):
        s['capture'] = clean_capture(cap)
    update_state(path, fn)
    return 0


def _cli_describe(path):
    try:
        s = read_state(path)
    except (OSError, ValueError):
        return 1
    print('|'.join([fmt_expires(s), str(s.get('opens', 0) or 0),
                    rules_summary(s.get('rules'))]))
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print(__doc__.split('CLI', 1)[1], file=sys.stderr)
        return 2
    cmd, rest = argv[0], argv[1:]
    try:
        if cmd == 'spec':
            return _cli_spec(rest)
        if cmd == 'summary' and len(rest) >= 1:
            return _cli_summary(rest[0], show_token='--no-token' not in rest[1:])
        if cmd == 'parse-expires' and len(rest) == 1:
            at = parse_expires(rest[0])
            print('never' if at is None else at)
            return 0
        if cmd == 'expire' and len(rest) == 2:
            s = set_expiry(rest[0], parse_expires(rest[1]))
            print(f'expires: {fmt_expires(s)}')
            return 0
        if cmd == 'keep' and len(rest) == 1:
            set_expiry(rest[0], None)
            print('expires: never')
            return 0
        if cmd == 'extend' and len(rest) == 2:
            s = extend(rest[0], int(rest[1]) * 60)
            print(f'expires: {fmt_expires(s)}')
            return 0
        if cmd == 'describe' and len(rest) == 1:
            return _cli_describe(rest[0])
        if cmd == 'needs-proxy' and len(rest) == 1:
            try:
                return 0 if needs_proxy(read_state(rest[0])) else 1
            except (OSError, ValueError):
                return 1
        if cmd == 'proxy-args' and len(rest) == 1:
            try:
                print('\n'.join(proxy_args(read_state(rest[0]))))
            except (OSError, ValueError):
                return 1
            return 0
        if cmd == 'set-tunnel' and len(rest) == 3:
            pid = int(rest[1]) if rest[1].isdigit() else 0
            proto = rest[2] if rest[2] in ('http', 'https', 'tcp', 'udp') else ''
            if pid <= 1 or not proto:
                raise DoorError('set-tunnel needs a pid and http|https|tcp|udp')

            def fn(s):
                s['tunnel_pid'] = pid
                s['proto'] = proto
            update_state(rest[0], fn)
            return 0
        if cmd == 'set-opens-by' and len(rest) == 2:
            if rest[1] not in ('app', 'proxy'):
                raise DoorError('set-opens-by needs app or proxy')

            def fn(s):
                if rest[1] == 'app':
                    s['opens_by'] = 'app'
                else:
                    s.pop('opens_by', None)
            update_state(rest[0], fn)
            return 0
        if cmd == 'set-capture' and len(rest) in (3, 4):
            return _cli_set_capture(*rest)
        if cmd == 'has-rules' and len(rest) == 1:
            try:
                return 0 if clean_rules(read_state(rest[0]).get('rules')) else 1
            except (OSError, ValueError):
                return 1
    except DoorError as e:
        print(f'Error: {e}', file=sys.stderr)
        return 2
    except FileNotFoundError:
        print('Error: no such door (is it still running?)', file=sys.stderr)
        return 1
    except ValueError as e:
        import porch_config
        if isinstance(e, porch_config.ConfigError):
            print(f'Error: invalid Porch config: {e}', file=sys.stderr)
            return 1
        raise
    print(f'door_state.py: bad usage: {" ".join(argv)}', file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main())

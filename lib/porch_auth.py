"""porch_auth: the one owner/identity check every Porch app uses.

Credentials, both checked against the authserver's devices.json:

  * porch_host (preferred). A HOST-ONLY cookie minted by the authserver's
    /__porch/ handoff for exactly one host. Valid when it belongs to a
    browser device that is not revoked and not past its expires_at, through
    a host_tokens entry {sha256, host, expires_at} whose sha256 is
    sha256(cookie) (compared in constant time), whose host equals the
    request's Host, and whose expires_at is in the future. The device is the
    OWNER when its role is "admin". find_host_token_device() below is the
    reference validator; lib/authserver.py imports it from here, so the
    authserver and the apps cannot drift.

  * cush_auth (legacy, domain-wide). Accepted while the migration runs, when
    PORCH_ACCEPT_LEGACY_COOKIE is on (the default): a non-revoked, unexpired
    admin browser device whose token_sha256 matches. A devices.json that
    predates roles falls back to the old rule (a browser scoped ["*"]).
    Turn it off (PORCH_ACCEPT_LEGACY_COOKIE=0) once HAProxy strips cush_auth
    on tunnel hosts.

Never X-Cush-Role or any other header: the apps are reachable around HAProxy.

The parsed devices.json is cached by (mtime, size, inode); expiry is compared
against the clock on every call, so a device or token lapses on time even if
the file never changes. A missing, unreadable or corrupt devices.json means
nobody is the owner (fail closed).
"""

import datetime
import hashlib
import hmac
import json
import os
import re
import threading
import time
import urllib.parse

GATE_COOKIE = 'cush_auth'
HOST_COOKIE = 'porch_host'
LEGACY_ENV = 'PORCH_ACCEPT_LEGACY_COOKIE'
START_PATH = '/__porch/start'

# Overridable by tests/callers; None means "read the environment".
ACCEPT_LEGACY = None


def accept_legacy():
    """Is the domain-wide cush_auth cookie still accepted? Default on."""
    if ACCEPT_LEGACY is not None:
        return bool(ACCEPT_LEGACY)
    v = os.environ.get(LEGACY_ENV, '').strip().lower()
    return v not in ('0', 'false', 'no', 'off')


# ---- time + device rules (shared with lib/authserver.py) ---------------------

def epoch_from_iso(s):
    """ISO8601 'Z' timestamp -> epoch seconds. 0 for falsy/invalid."""
    if not s:
        return 0
    if isinstance(s, (int, float)):
        return float(s)  # tolerate legacy epoch values on disk
    try:
        dt = datetime.datetime.strptime(s, '%Y-%m-%dT%H:%M:%SZ').replace(
            tzinfo=datetime.timezone.utc)
        return dt.timestamp()
    except (ValueError, TypeError):
        return 0


def device_expired(d, now):
    """True once a device's `expires_at` has passed. No field = permanent;
    a value that is present but unreadable counts as expired (fail closed)."""
    exp = d.get('expires_at')
    if not exp:
        return False
    return epoch_from_iso(exp) <= now


def host_token_entry(d, token_sha, host, now):
    """The device's live host_tokens entry for (sha256 of a porch_host cookie,
    host), or None. Every entry is compared with compare_digest."""
    found = None
    for e in d.get('host_tokens') or []:
        if not isinstance(e, dict):
            continue
        s = e.get('sha256')
        if (isinstance(s, str) and hmac.compare_digest(s.lower(), token_sha)
                and e.get('host') == host
                and epoch_from_iso(e.get('expires_at')) > now):
            found = e
    return found


def find_host_token_device(devices, token, host, now=None):
    """Reference validator for the porch_host cookie.

    The device that owns `token` on `host`: a non-revoked, unexpired BROWSER
    device with a host_tokens entry whose sha256 is sha256(token) hex, whose
    host is exactly the request host, and whose expires_at is in the future.
    Revoking (or expiring) the device kills all of its host tokens at once.
    """
    if not token or not host or not isinstance(token, str):
        return None
    now = time.time() if now is None else now
    sha = hashlib.sha256(token.encode('utf-8')).hexdigest()
    host = host.strip().lower()
    found = None
    for d in devices or []:
        if (not isinstance(d, dict) or d.get('revoked')
                or d.get('type') != 'browser' or device_expired(d, now)):
            continue
        if host_token_entry(d, sha, host, now) is not None:
            found = d
    return found


def is_admin_device(d):
    """An owner: a browser device with role "admin". A record that predates
    roles counts when it is a browser scoped ["*"] (the authserver's own
    migration rule). Revocation/expiry are checked by the callers."""
    if not isinstance(d, dict) or d.get('type') != 'browser':
        return False
    if 'role' in d:
        return d.get('role') == 'admin'
    apps = d.get('apps')
    if not isinstance(apps, list) or not apps:
        apps = ['*']
    return apps == ['*']


# ---- devices.json cache ------------------------------------------------------

_lock = threading.Lock()
_cache = {'path': None, 'key': None, 'devices': None}


def reset_cache():
    with _lock:
        _cache.update(path=None, key=None, devices=None)


def load_devices(devices_path):
    """The device list from devices.json, or None (missing/corrupt: fail
    closed). Cached by (path, mtime_ns, size, inode)."""
    if not devices_path:
        return None
    try:
        st = os.stat(devices_path)
    except OSError:
        reset_cache()
        return None
    key = (st.st_mtime_ns, st.st_size, st.st_ino)
    with _lock:
        if _cache['path'] == devices_path and _cache['key'] == key:
            return _cache['devices']
    devices = None
    try:
        with open(devices_path) as f:
            data = json.load(f)
        raw = data.get('devices') if isinstance(data, dict) else None
        if isinstance(raw, list):
            devices = [d for d in raw if isinstance(d, dict)]
    except (OSError, ValueError, UnicodeDecodeError):
        devices = None
    with _lock:
        _cache.update(path=devices_path, key=key, devices=devices)
    return devices


def _live_owner(d, now):
    return (is_admin_device(d) and not d.get('revoked')
            and not device_expired(d, now))


def legacy_owner_device(devices, token, now=None):
    """The live admin device whose cush_auth token is `token`, or None."""
    if not token or not devices or not isinstance(token, str):
        return None
    now = time.time() if now is None else now
    digest = hashlib.sha256(token.encode('utf-8')).hexdigest()
    found = None
    for d in devices:
        tsh = d.get('token_sha256')
        if not isinstance(tsh, str) or not tsh:
            continue
        if hmac.compare_digest(digest, tsh.lower()) and _live_owner(d, now):
            found = d
    return found


def is_owner_token(token, devices_path, now=None):
    """Legacy check: does cush_auth `token` belong to a live owner device?
    (Ignores the legacy flag; request-level callers go through owner_cookie.)"""
    return legacy_owner_device(load_devices(devices_path), token, now) is not None


def auth_configured(devices_path, now=None):
    """True iff at least one live owner device exists (so signing in can work)."""
    devices = load_devices(devices_path)
    if not devices:
        return False
    now = time.time() if now is None else now
    return any(_live_owner(d, now) for d in devices)


# ---- request level -----------------------------------------------------------

def request_host(handler):
    """Lowercase host the request was addressed to, port stripped. If an
    X-Forwarded-Host disagrees with Host, "" (no host token can match).
    Same rule as authserver's _request_host."""
    def norm(v):
        v = (v or '').split(',')[0].strip().lower()
        if v.startswith('['):
            return v
        return v.rsplit(':', 1)[0] if ':' in v else v
    host = norm(handler.headers.get('Host'))
    xfh = handler.headers.get('X-Forwarded-Host')
    if xfh is not None and norm(xfh) != host:
        return ''
    return host


def _cookies(handler):
    out = {}
    raw = handler.headers.get('Cookie', '') if handler.headers is not None else ''
    for part in (raw or '').split(';'):
        k, _, v = part.strip().partition('=')
        if k:
            out[k] = v
    return out


def owner_credential(handler, devices_path, now=None):
    """(cookie_name, cookie_value, device) for the owner credential this
    request carries, or None. porch_host is tried first; cush_auth only
    while the legacy flag is on."""
    devices = load_devices(devices_path)
    if not devices:
        return None
    now = time.time() if now is None else now
    cookies = _cookies(handler)
    htok = cookies.get(HOST_COOKIE, '')
    if htok:
        host = request_host(handler)
        d = find_host_token_device(devices, htok, host, now) if host else None
        if d is not None and is_admin_device(d):
            return HOST_COOKIE, htok, d
    if accept_legacy():
        tok = cookies.get(GATE_COOKIE, '')
        d = legacy_owner_device(devices, tok, now)
        if d is not None:
            return GATE_COOKIE, tok, d
    return None


def owner_cookie(handler, devices_path, now=None):
    """The cookie value that makes this request an owner's, or ''."""
    cred = owner_credential(handler, devices_path, now)
    return cred[1] if cred else ''


def request_is_owner(handler, devices_path, now=None):
    return owner_credential(handler, devices_path, now) is not None


# ---- sign-in handoff ---------------------------------------------------------

_HOST_RE = re.compile(
    r'^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
    r'(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z][a-z0-9-]*[a-z0-9]$')
# What authserver's RD_PATH_RE accepts for the path+query of an rd.
_RD_PATH_RE = re.compile(r"^/(?!/)[^\s\"'<>\\`]*$")


def start_url(handler, path=None):
    """https://<host>/__porch/start?rd=<current url>, the URL that sends an
    un-authed owner through the authserver handoff and back here with a
    porch_host cookie. None when the request has no usable public host
    (an IP, localhost, a mismatched X-Forwarded-Host)."""
    host = request_host(handler)
    if not host or not _HOST_RE.match(host):
        return None
    rd_path = handler.path if path is None else path
    if not isinstance(rd_path, str) or not _RD_PATH_RE.match(rd_path) or len(rd_path) > 1024:
        rd_path = '/'
    rd = f'https://{host}{rd_path}'
    return f'https://{host}{START_PATH}?rd={urllib.parse.quote(rd, safe="")}'


def signin_url(handler, devices_path, path=None):
    """start_url() for a visitor who is not the owner, when signing in can
    work (a registry with a live owner). None otherwise: no link to show."""
    if not devices_path or not auth_configured(devices_path):
        return None
    if request_is_owner(handler, devices_path):
        return None
    return start_url(handler, path)

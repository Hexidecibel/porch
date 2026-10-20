#!/usr/bin/env python3
"""Door proxy: a streaming reverse proxy in front of one door's app.

bin/tunnel starts it (on its own loopback port, killed with the door) and
points frpc at it instead of the app, but only when the door has share rules
(rules in /tmp/tunnel-state/<name>.json, see lib/door_state.py). Plain doors
keep the direct frpc -> app path.

    frpc -> doorproxy (127.0.0.1:P) -> app (127.0.0.1:upstream)

Passthrough: request and response bodies are streamed (Content-Length and
chunked both work, chunked is re-framed), Range and Host pass unchanged,
X-Forwarded-For gets the peer appended like an edge would (so the app's
porch_http.client_ip still finds the real client), hop-by-hop headers are
dropped, our own door cookie never reaches the app, and an Upgrade
(WebSocket) is relayed as raw bytes after the 101.

Rules (re-read whenever the state file changes, so `porch door rules` and the
panel apply live):
    password    scrypt hash; a porch-styled gate page with a password form.
                Success sets __Host-porch_door: an HMAC under a per-door secret
                (<state dir>/.<name>.secret, 0600), never the password.
                Wrong passwords are limited per client IP (5/min).
    guest       ?k=<token> on any URL sets the same cookie and redirects to the
                URL without k. Password and guest link may both be set.
    max_opens   (burn = 1) counts an "open" per page view by a non-owner: a
                top-level document GET (Sec-Fetch-Dest: document, or Accept
                text/html without Sec-Fetch-Dest), plus, on an ungated door, any
                request without a door session (so curl can't read a burn link
                for free). Assets, XHR and Range requests of an admitted session
                don't count. When the limit is reached, admitted sessions get
                GRACE seconds to finish loading, new opens get a 410 "closed"
                page, then the door is stopped like the status API's Stop.
                A door whose state says opens_by = "app" (bin/seal: a complete
                ciphertext download is the open) is never counted or closed
                here; the app counts and stops the door itself.
The owner (porch_auth.request_is_owner against --devices) always passes and
is never counted. Upstream responses are not rewritten (except that an app's
Set-Cookie for our own cookie is dropped).

Inspector and capture mode (lib/inspect_store.py): --inspect / --inspect-raw
add a Recorder observer (every exchange -> <run dir>/inspect/<name>.jsonl,
header secrets masked unless raw) and its replay control socket; bin/tunnel
starts the proxy for an inspected door even without rules. --capture (bin/hook)
runs with no upstream at all: a CaptureResponder intercept answers every
admitted request with the status/body from the state file's `capture`, and
request bodies are capped (capture.max_body_mb, default 10MB, 413 past it).

Observers: Door.add_observer(obs) with any of these methods (DoorObserver has no-op
defaults); an observer that raises is logged and skipped, never breaks a
request:
    intercept(exch) -> None | (status, [(name, value)], body_bytes)
        After the gate admitted the request. A tuple answers it without
        contacting the app (the request body is still read and tapped).
    on_request(exch)                   before the upstream request is sent
    on_request_body(exch, chunk)       each decoded request body chunk
    on_response(exch)                  upstream status + headers are in
    on_response_body(exch, chunk)      each decoded response body chunk
    on_exchange(exch)                  always, last (gate pages too; exch.error
                                       is set when the exchange failed)
"""

import argparse
import atexit
import hashlib
import hmac
import itertools
import os
import re
import signal
import socket
import sys
import threading
import time
import urllib.parse
from html import escape as html_escape
from http.client import parse_headers
from http.server import BaseHTTPRequestHandler

_LIB = os.path.dirname(os.path.abspath(__file__))
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
import door_state  # noqa: E402
import inspect_store  # noqa: E402
import porch_auth  # noqa: E402
from porch_http import (  # noqa: E402
    BoundedThreadingHTTPServer, HardenedHandlerMixin, client_ip, content_length,
    csp_nonce, is_asset_path, make_server, parse_cookies, porch_css_tag, porch_mark,
    porch_style_src, same_origin, security_headers, serve_asset,
)

COOKIE = '__Host-porch_door'
CTRL_PREFIX = '/__porch-door/'      # not /__porch/: HAProxy sends that to the auth server
LOGIN_PATH = CTRL_PREFIX + 'login'
SESSION_TTL = 7 * 86400
GRACE = 60                           # s an exhausted door keeps serving admitted sessions
FAIL_LIMIT = 5                       # wrong passwords per client IP ...
FAIL_WINDOW = 60                     # ... per this many seconds
MAX_LOGIN_BODY = 8 * 1024
CONNECT_TIMEOUT = 10
UPSTREAM_TIMEOUT = 300               # per read from the app (thumbnails, ffmpeg)
TUNNEL_IDLE = 900                    # per read on an upgraded (WebSocket) connection
CHUNK = 64 * 1024
MAX_TRAILERS = 64

# RFC 9110 7.6.1 plus the ones a proxy must not pass on. Content-Length is
# dropped too: we frame the body ourselves.
HOP_BY_HOP = frozenset({
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'expect',
    'content-length',
})
# Set by send_response(); the app's copies would be duplicates.
OWN_RESPONSE_HEADERS = frozenset({'server', 'date'})

APP_FOR_TYPE = {'serve': 'serve', 'paste': 'paste', 'exchange': 'exchange', 'drop': 'drop',
                'seal': 'secret',
                'media': 'media', 'photos': 'media', 'music': 'music', 'chat': 'chat',
                'form': 'form'}

_HEX = re.compile(rb'^[0-9A-Fa-f]{1,8}$')
_NEXT_RE = re.compile(r'^/(?!/)[^\s\\]{0,2000}$')
_ids = itertools.count(1)


def log(msg):
    sys.stderr.write(f'[doorproxy] {msg}\n')


class BadRequest(Exception):
    pass


class TooLarge(BadRequest):
    pass


def strip_door_cookie(value):
    kept = [p.strip() for p in value.split(';')
            if p.strip() and p.strip().partition('=')[0] != COOKIE]
    return '; '.join(kept)


def sets_door_cookie(set_cookie_value):
    """True for an app's Set-Cookie that would overwrite our session cookie
    (it can't forge one, but it could log every visitor out)."""
    return set_cookie_value.split('=', 1)[0].strip() == COOKIE


# ---- observers ---------------------------------------------------------------

class DoorObserver:
    """No-op base for Door observers; override what you need."""

    def intercept(self, exch):
        return None

    def on_request(self, exch):
        pass

    def on_request_body(self, exch, chunk):
        pass

    def on_response(self, exch):
        pass

    def on_response_body(self, exch, chunk):
        pass

    def on_exchange(self, exch):
        pass


class Exchange:
    """One request through the door, as observers see it."""

    def __init__(self, handler, now):
        self.id = next(_ids)
        self.started = now
        self.ended = None
        self.method = handler.command
        self.target = handler.path
        split = urllib.parse.urlsplit(handler.path)
        self.path = split.path
        self.query = split.query
        self.version = handler.request_version
        self.client_ip = client_ip(handler)
        # As received (door cookie removed); replaced by the upstream copy
        # once the request is forwarded or intercepted.
        self.request_headers = []
        for k, v in handler.headers.items():
            if k.lower() == 'cookie':
                v = strip_door_cookie(v)
                if not v:
                    continue
            self.request_headers.append((k, v))
        self.owner = False
        self.admitted = None           # owner | session | open | None
        self.counted = False
        self.handled_by = None         # upstream | gate | intercept | asset
        self.status = None
        self.response_headers = []
        self.req_bytes = 0
        self.resp_bytes = 0
        self.upgraded = False
        self.error = None

    def as_dict(self):
        return {k: v for k, v in self.__dict__.items()}


# ---- the door ----------------------------------------------------------------

class Door:
    """Shared, thread-safe state of one door: its rules (live from the state
    file), the cookie key, the open counter and the wrong-password limiter."""

    def __init__(self, name, state_dir, upstream_port, devices_path=None,
                 upstream_host='127.0.0.1', grace=GRACE, closer=None, secret=None,
                 clock=time.time):
        self.name = name
        self.state_dir = state_dir
        self.state_path = door_state.state_path(name, state_dir)
        # None = capture-only (bin/hook): nothing behind the door.
        self.upstream = None if upstream_port is None else (upstream_host, int(upstream_port))
        self.max_body = None           # request body cap in bytes (capture mode)
        self.devices_path = devices_path
        self.grace = grace
        self.clock = clock
        self.secret = secret or door_state.load_or_create_secret(state_dir, name)
        self.closer = closer or (lambda: door_state.stop_door(name, state_dir, 'used-up'))
        self.observers = []
        self._lock = threading.Lock()
        self._sig = None
        self._rules = {}
        self.type = ''
        self.opens = 0
        self.app_counts = False         # opens_by = app: the app counts, we don't
        self.expires = None
        self.closed = False
        self._grace_timer = None
        self._fails = {}
        self._scrypt = threading.BoundedSemaphore(2)

    # observers
    def add_observer(self, obs):
        self.observers.append(obs)

    def notify(self, method, *args):
        result = None
        for obs in list(self.observers):
            fn = getattr(obs, method, None)
            if fn is None:
                continue
            try:
                r = fn(*args)
            except Exception as e:  # noqa: BLE001
                log(f'observer {type(obs).__name__}.{method} failed: {e!r}')
                continue
            if method == 'intercept' and r is not None and result is None:
                result = r
        return result

    # rules
    def rules(self):
        """Current rules, re-read when the state file changed (mtime, size,
        inode). A vanished file keeps the last rules: the door is stopping."""
        try:
            st = os.stat(self.state_path)
        except OSError:
            return self._rules
        sig = (st.st_mtime_ns, st.st_size, st.st_ino)
        with self._lock:
            if sig == self._sig:
                return self._rules
            try:
                s = door_state.read_state(self.state_path)
            except (OSError, ValueError):
                return self._rules
            self._sig = sig
            self._rules = door_state.clean_rules(s.get('rules'))
            self.type = s.get('type') if isinstance(s.get('type'), str) else ''
            try:
                self.opens = int(s.get('opens') or 0)
            except (TypeError, ValueError):
                self.opens = 0
            self.expires = door_state.expires_of(s)
            self.app_counts = door_state.app_counts_opens(s)
            mo = self._rules.get('max_opens')
            if self._grace_timer is not None and not (mo and self.opens >= mo):
                # The limit was raised or lifted during the grace: stay open.
                self._grace_timer.cancel()
                self._grace_timer = None
            return self._rules

    def gated(self, rules):
        return 'password' in rules or 'guest' in rules

    def exhausted(self, rules):
        mo = rules.get('max_opens')
        return bool(mo) and self.opens >= mo

    def expired(self, now):
        return self.expires is not None and now > self.expires

    # cookies
    def _fingerprint(self, rules):
        raw = f"{rules.get('password', '')}|{rules.get('guest', '')}".encode('utf-8')
        return hashlib.sha256(raw).hexdigest()

    def _sign(self, ts, rules, pending=False):
        msg = f'{self.name}|{ts}|{self._fingerprint(rules)}' + ('|pending' if pending else '')
        return hmac.new(self.secret, msg.encode('utf-8'), hashlib.sha256).hexdigest()

    def make_cookie(self, rules, now, pending=False):
        """A session cookie. `pending` = minted by the gate (password, guest
        link) and not counted as an open yet: on a door with max_opens its
        first request counts whatever it looks like, and the answer swaps it
        for a counted one. So a session always costs at least one open."""
        ts = int(now)
        return f'{"v1p" if pending else "v1"}.{ts}.{self._sign(ts, rules, pending)}'

    def cookie_state(self, value, rules, now):
        """'counted' / 'pending' for a door session minted under the current
        credentials (changing the password or guest link invalidates every
        session) and < SESSION_TTL old; None otherwise."""
        if not value or len(value) > 200:
            return None
        parts = value.split('.')
        if len(parts) != 3 or parts[0] not in ('v1', 'v1p') or not parts[1].isdigit() \
                or len(parts[1]) > 12:
            return None
        ts = int(parts[1])
        if not (now - SESSION_TTL <= ts <= now + 60):
            return None
        pending = parts[0] == 'v1p'
        if not hmac.compare_digest(parts[2], self._sign(ts, rules, pending)):
            return None
        return 'pending' if pending else 'counted'

    def cookie_ok(self, value, rules, now):
        return self.cookie_state(value, rules, now) is not None

    def cookie_header(self, value, now):
        max_age = SESSION_TTL
        if self.expires is not None:
            max_age = max(60, min(max_age, int(self.expires - now)))
        return (f'{COOKIE}={value}; Path=/; Max-Age={max_age}; Secure; HttpOnly; '
                'SameSite=Lax')

    # passwords
    def too_many_fails(self, ip, now):
        with self._lock:
            hits = [t for t in self._fails.get(ip, ()) if now - t < FAIL_WINDOW]
            if hits:
                self._fails[ip] = hits
            else:
                self._fails.pop(ip, None)
            return len(hits) >= FAIL_LIMIT

    def note_fail(self, ip, now):
        with self._lock:
            self._fails.setdefault(ip, []).append(now)
            if len(self._fails) > 10000:      # bounded memory under a spray
                self._fails.clear()

    def check_password(self, password, stored):
        with self._scrypt:
            return door_state.verify_password(password, stored)

    # opens
    def try_open(self, rules, now):
        """Count one open. False if the limit is already reached (nothing is
        written). Starts the grace timer on the open that reaches the limit."""
        mo = rules.get('max_opens')
        result = {'ok': True}

        def fn(s):
            try:
                opens = int(s.get('opens') or 0)
            except (TypeError, ValueError):
                opens = 0
            if mo and opens >= mo:
                result['ok'] = False
                result['opens'] = opens
                return False
            s['opens'] = opens + 1
            s['last_open'] = int(now)
            result['opens'] = opens + 1
        try:
            door_state.update_state(self.state_path, fn)
        except FileNotFoundError:
            return not mo           # the door is going away
        except (OSError, ValueError) as e:
            log(f'could not record an open: {e}')
            return not mo
        with self._lock:
            self.opens = result['opens']
        if mo and result['ok'] and result['opens'] >= mo:
            self._start_grace()
        return result['ok']

    def _start_grace(self):
        with self._lock:
            if self._grace_timer is not None or self.closed:
                return
            log(f"'{self.name}' used its last open; closing in {self.grace}s")
            t = threading.Timer(self.grace, self._grace_over)
            t.daemon = True
            self._grace_timer = t
        t.start()

    def _grace_over(self):
        rules = self.rules()
        with self._lock:
            if self._grace_timer is None:
                return              # cancelled by a rule change
            self._grace_timer = None
            if not self.exhausted(rules):
                return
            self.closed = True
        log(f"closing '{self.name}': open limit reached")
        try:
            self.closer()
        except Exception as e:  # noqa: BLE001
            log(f'close failed: {e!r}')

    def is_owner(self, handler):
        if not self.devices_path:
            return False
        try:
            return porch_auth.request_is_owner(handler, self.devices_path)
        except Exception:  # noqa: BLE001
            return False


# ---- pages -------------------------------------------------------------------

PAGE = """<!DOCTYPE html>
<html lang="en"__APP__>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>__TITLE__</title>
__PORCH_CSS__
<style nonce="__NONCE__">
.gate{display:flex;flex-direction:column;gap:16px}
.gate-alt{font-size:14px;color:var(--muted);text-align:center}
</style>
</head>
<body>
<main class="p-shell p-shell--narrow">
  <header class="p-head">
    <div class="p-kicker">__MARK__<span class="p-label--mono">__NAME__</span></div>
    <h1 class="p-title">__TITLE__</h1>
    <p class="p-lede">__LEDE__</p>
  </header>
__BODY__
  <footer class="p-foot">a porch door</footer>
</main>
__SIGNIN__
</body>
</html>"""

LOGIN_FORM = """  <form class="p-card gate" method="post" action="__ACTION__">
__NOTICE__    <input type="hidden" name="next" value="__NEXT__">
    <div class="p-field">
      <label class="p-label" for="pw">Password</label>
      <input class="p-input" id="pw" name="password" type="password" autocomplete="current-password" required autofocus>
    </div>
    <button class="p-btn p-btn--lg p-btn--block" type="submit">Open</button>
  </form>
__ALT__"""


def is_document(headers):
    dest = (headers.get('Sec-Fetch-Dest') or '').strip().lower()
    if dest:
        return dest == 'document'
    return 'text/html' in (headers.get('Accept') or '').lower()


def safe_next(raw):
    if isinstance(raw, str) and _NEXT_RE.match(raw) and not raw.startswith(CTRL_PREFIX):
        return raw
    return '/'


# ---- the handler -------------------------------------------------------------

class DoorHandler(HardenedHandlerMixin, BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, format, *args):
        method = args[0] if args else ''
        if isinstance(method, str) and method.startswith(('GET', 'HEAD')):
            return
        sys.stderr.write(f'[doorproxy] {self.address_string()} - {format % args}\n')

    def do_GET(self):
        self._handle()

    do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_GET

    # ---- entry ---------------------------------------------------------------

    def _handle(self):
        door = self.server.door
        now = door.clock()
        exch = Exchange(self, now)
        self._body_done = False
        try:
            self._serve(door, exch, now)
        except TooLarge as e:
            exch.error = str(e)
            self.close_connection = True
            if exch.status is None:
                self._plain(exch, 413, 'request body too large\n')
        except BadRequest as e:
            exch.error = str(e)
            if exch.status is None:
                self._plain(exch, 400, 'bad request\n')
            self.close_connection = True
        except (OSError, socket.timeout) as e:
            exch.error = repr(e)
            self.close_connection = True
        finally:
            exch.ended = door.clock()
            door.notify('on_exchange', exch)

    def _has_body(self):
        return bool(self.headers.get('Transfer-Encoding')) or content_length(self) > 0

    def _serve(self, door, exch, now):
        if not (self.path.startswith('/') or (self.path == '*' and self.command == 'OPTIONS')):
            raise BadRequest('request target must be origin-form')
        # http.client's header parser stops quietly at a malformed line
        # ("Bad Header: 1", "Transfer-Encoding : chunked") and drops every
        # header after it, Content-Length included: the body would then be
        # parsed as a second request (smuggling). Refuse instead of guessing.
        if getattr(self.headers, 'defects', None):
            raise BadRequest('malformed request headers')
        if len(self.headers.get_all('Transfer-Encoding') or []) > 1:
            raise BadRequest('several Transfer-Encoding headers')
        rules = door.rules()
        split = urllib.parse.urlsplit(self.path)
        path = split.path
        exch.owner = owner = door.is_owner(self)
        cookies = parse_cookies(self.headers.get('Cookie', ''))
        session = door.cookie_state(cookies.get(COOKIE, ''), rules, now)

        # Guest link: a matching ?k= mints a session and drops k from the URL.
        if 'guest' in rules and self.command in ('GET', 'HEAD') and split.query:
            q = urllib.parse.parse_qsl(split.query, keep_blank_values=True)
            keys = [v for k, v in q if k == 'k']
            want = rules['guest'].encode('utf-8')
            if any(hmac.compare_digest(v.encode('utf-8', 'replace'), want) for v in keys):
                rest = urllib.parse.urlencode([(k, v) for k, v in q if k != 'k'])
                exch.admitted = 'guest'
                # safe_next: never `/\\evil` or `//evil` (browsers read both
                # as another host).
                return self._redirect(exch, safe_next(path + ('?' + rest if rest else '')),
                                      door.make_cookie(rules, now, pending=True))

        if path.startswith(CTRL_PREFIX):
            return self._control(exch, door, rules, path, now)

        if owner:
            exch.admitted = 'owner'
        elif session:
            exch.admitted = 'session'
        elif not door.gated(rules):
            exch.admitted = 'open'

        # porch.css and its fonts: whoever is refused below still gets them,
        # or the gate and closed pages would render unstyled.
        asset = is_asset_path(path) and self.command in ('GET', 'HEAD')

        if not owner and (door.closed or door.expired(now)):
            if asset:
                return self._asset(exch)
            return self._page(exch, 410, 'This door is closed',
                              'It has expired or was stopped.', door)

        if exch.admitted is None:
            if asset:
                return self._asset(exch)
            return self._gate(exch, door, rules, None)

        set_cookie = None
        if not owner and not door.app_counts:
            # Without max_opens an ungated door (an inspected one) counts page
            # views only, not every request.
            # A gate-minted session that was never counted counts now,
            # whatever the request looks like (no free reads of a burn door).
            first = session == 'pending' and bool(rules.get('max_opens'))
            counts = ((self.command == 'GET' and 'Range' not in self.headers
                       and is_document(self.headers))
                      or (exch.admitted == 'open' and bool(rules.get('max_opens')))
                      or first)
            if rules.get('max_opens') and door.exhausted(rules):
                if counts or exch.admitted != 'session':
                    return self._asset(exch) if asset else self._closed(exch, door)
            elif counts and asset and exch.admitted == 'open':
                # an asset is never an open, even on an ungated burn door
                return self._asset(exch)
            elif counts:
                if not door.try_open(rules, now):
                    return self._asset(exch) if asset else self._closed(exch, door)
                exch.counted = True
                if (exch.admitted == 'open' and rules.get('max_opens')) or first:
                    # Lets this visitor's assets through the grace period.
                    set_cookie = door.make_cookie(rules, now)
        self._forward(exch, door, set_cookie, now)

    # ---- our own responses ---------------------------------------------------

    def _finish_own(self):
        # A body we never read must not be parsed as the next request.
        if self._has_body() and not self._body_done:
            self.close_connection = True

    def _plain(self, exch, status, text, headers=()):
        body = text.encode('utf-8')
        exch.status = status
        exch.handled_by = exch.handled_by or 'gate'
        self.send_response(status)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Security-Policy', "default-src 'none'; sandbox")
        security_headers(self)
        for k, v in headers:
            self.send_header(k, v)
        self._finish_own()
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def _redirect(self, exch, location, cookie_value):
        door = self.server.door
        exch.status = 303
        exch.handled_by = 'gate'
        self.send_response(303)
        self.send_header('Location', location)
        self.send_header('Set-Cookie', door.cookie_header(cookie_value, door.clock()))
        self.send_header('Content-Length', '0')
        self.send_header('Cache-Control', 'no-store')
        security_headers(self)
        self._finish_own()
        self.end_headers()

    def _page(self, exch, status, title, lede, door, body='', headers=()):
        nonce = csp_nonce()
        app = APP_FOR_TYPE.get(door.type)
        signin = ''
        try:
            url = porch_auth.signin_url(self, door.devices_path) if door.devices_path else None
        except Exception:  # noqa: BLE001
            url = None
        if url:
            signin = (f'<a class="porch-signin" href="{html_escape(url, quote=True)}" '
                      'rel="nofollow">Owner? Sign in</a>')
        html = (PAGE.replace('__APP__', f' data-app="{app}"' if app else '')
                .replace('__PORCH_CSS__', porch_css_tag())
                .replace('__MARK__', porch_mark(18))
                .replace('__NAME__', html_escape(door.name))
                .replace('__TITLE__', html_escape(title))
                .replace('__LEDE__', html_escape(lede))
                .replace('__SIGNIN__', signin)
                .replace('__BODY__', body)
                .replace('__NONCE__', nonce))
        data = html.encode('utf-8')
        exch.status = status
        exch.handled_by = 'gate'
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Vary', 'Cookie')
        self.send_header('Content-Security-Policy', (
            "default-src 'none'; "
            f"{porch_style_src(nonce)}; "
            "img-src data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"))
        security_headers(self)
        for k, v in headers:
            self.send_header(k, v)
        self._finish_own()
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(data)

    def _gate(self, exch, door, rules, error, status=None, headers=()):
        if 'password' not in rules:
            return self._page(exch, status or 403, 'This door needs its link',
                              'Open the exact link you were sent: it carries the key.', door,
                              headers=headers)
        notice = ''
        if error:
            notice = (f'    <div class="p-notice p-notice--error" role="alert">'
                      f'{html_escape(error)}</div>\n')
        nxt = self.path if self.command == 'GET' else '/'
        alt = ('  <p class="gate-alt">Or open the guest link you were sent.</p>\n'
               if 'guest' in rules else '')
        body = (LOGIN_FORM.replace('__ACTION__', LOGIN_PATH)
                .replace('__NOTICE__', notice)
                .replace('__NEXT__', html_escape(safe_next(nxt), quote=True))
                .replace('__ALT__', alt))
        return self._page(exch, status or 401, 'This door is locked',
                          'Enter the password to open it.', door, body=body, headers=headers)

    def _asset(self, exch):
        exch.handled_by = 'asset'
        serve_asset(self, head=self.command == 'HEAD')
        exch.status = 200

    def _closed(self, exch, door):
        return self._page(exch, 410, 'This door is closed',
                          'It could only be opened a set number of times, and that is used up.',
                          door)

    def _control(self, exch, door, rules, path, now):
        if path != LOGIN_PATH or self.command != 'POST' or 'password' not in rules:
            return self._plain(exch, 404, 'not found\n')
        if not same_origin(self):
            return self._plain(exch, 403, 'cross-site login refused\n')
        ip = client_ip(self)
        if door.too_many_fails(ip, now):
            return self._gate(exch, door, rules,
                              'Too many wrong passwords. Wait a minute and try again.',
                              status=429, headers=(('Retry-After', str(FAIL_WINDOW)),))
        length = content_length(self)
        if length < 0 or length > MAX_LOGIN_BODY or self.headers.get('Transfer-Encoding'):
            return self._plain(exch, 413, 'too large\n')
        raw = self.rfile.read(length) if length else b''
        self._body_done = True
        exch.req_bytes = len(raw)
        fields = urllib.parse.parse_qs(raw.decode('utf-8', 'replace'), max_num_fields=8)
        password = (fields.get('password') or [''])[0]
        nxt = safe_next((fields.get('next') or ['/'])[0])
        if password and door.check_password(password, rules['password']):
            exch.admitted = 'password'
            return self._redirect(exch, nxt, door.make_cookie(rules, now, pending=True))
        door.note_fail(ip, now)
        log(f"wrong password for '{door.name}' from {ip}")
        return self._gate(exch, door, rules, 'That password is not right.')

    # ---- forwarding ----------------------------------------------------------

    def _upgrade_token(self):
        conn = [t.strip().lower() for t in (self.headers.get('Connection') or '').split(',')]
        up = (self.headers.get('Upgrade') or '').strip()
        if 'upgrade' in conn and up and re.fullmatch(r'[A-Za-z0-9._/-]{1,64}', up):
            return up
        return None

    def _upstream_headers(self, upgrade, chunked, length):
        listed = {t.strip().lower()
                  for v in (self.headers.get_all('Connection') or [])
                  for t in v.split(',') if t.strip()}
        out = []
        xff = []
        proto = None
        for k, v in self.headers.items():
            lk = k.lower()
            if lk in HOP_BY_HOP or lk in listed:
                continue
            v = v.replace('\r', ' ').replace('\n', ' ')
            if lk == 'cookie':
                kept = strip_door_cookie(v)
                if kept:
                    out.append(('Cookie', kept))
                continue
            if lk == 'x-forwarded-for':
                xff.append(v.strip())
                continue
            if lk == 'x-forwarded-proto':
                proto = proto or v.strip()
                continue
            out.append((k, v))
        peer = str(self.client_address[0])
        out.append(('X-Forwarded-For', ', '.join([x for x in xff if x] + [peer])))
        out.append(('X-Forwarded-Proto', proto or 'https'))
        if chunked:
            out.append(('Transfer-Encoding', 'chunked'))
        elif length > 0:
            out.append(('Content-Length', str(length)))
        if upgrade:
            out.append(('Connection', 'Upgrade'))
            out.append(('Upgrade', upgrade))
        else:
            out.append(('Connection', 'close'))
        return out

    def _request_body(self, exch, chunked, length):
        """Yield the decoded request body in chunks (and tap it)."""
        door = self.server.door
        rf = self.rfile
        cap = door.max_body
        if chunked:
            while True:
                line = rf.readline(1026)
                if not line.endswith(b'\n'):
                    raise BadRequest('bad chunk size line')
                size_s = line.split(b';', 1)[0].strip()
                if not _HEX.match(size_s):
                    raise BadRequest('bad chunk size')
                size = int(size_s, 16)
                if size == 0:
                    for _ in range(MAX_TRAILERS):
                        t = rf.readline(8192)
                        if t in (b'\r\n', b'\n', b''):
                            break
                    else:
                        raise BadRequest('too many trailers')
                    break
                if cap and exch.req_bytes + size > cap:
                    raise TooLarge('request body too large')
                left = size
                while left:
                    data = rf.read(min(left, CHUNK))
                    if not data:
                        raise BadRequest('body ended early')
                    left -= len(data)
                    self.transferred(len(data))
                    exch.req_bytes += len(data)
                    door.notify('on_request_body', exch, data)
                    yield data
                if rf.readline(3) not in (b'\r\n', b'\n'):
                    raise BadRequest('bad chunk end')
        else:
            left = length
            while left > 0:
                data = rf.read1(min(left, CHUNK)) if hasattr(rf, 'read1') else rf.read(min(left, CHUNK))
                if not data:
                    raise BadRequest('body ended early')
                left -= len(data)
                self.transferred(len(data))
                exch.req_bytes += len(data)
                door.notify('on_request_body', exch, data)
                yield data
        self._body_done = True

    def _forward(self, exch, door, set_cookie, now):
        te = self.headers.get('Transfer-Encoding')
        length = content_length(self)
        if te is not None:
            if te.strip().lower() != 'chunked' or self.headers.get('Content-Length') is not None:
                raise BadRequest('unsupported Transfer-Encoding')
        if length < 0:
            raise BadRequest('bad Content-Length')
        chunked = te is not None
        upgrade = self._upgrade_token()
        exch.request_headers = self._upstream_headers(upgrade, chunked, length)
        if door.max_body and length > door.max_body:
            return self._plain(exch, 413, 'request body too large\n')

        answer = door.notify('intercept', exch)
        if answer is not None:
            for _ in self._request_body(exch, chunked, length):
                pass
            return self._send_intercepted(exch, answer, set_cookie)

        if door.upstream is None:
            exch.error = 'no app behind this door'
            return self._page(exch, 502, 'Nothing behind this door',
                              'This door has no app to answer.', door)
        door.notify('on_request', exch)
        try:
            up = socket.create_connection(door.upstream, timeout=CONNECT_TIMEOUT)
        except OSError as e:
            exch.error = f'upstream: {e}'
            return self._page(exch, 502, "The app isn't answering",
                              'The door is open but the app behind it is not responding. '
                              'Try again in a moment.', door)
        try:
            up.settimeout(UPSTREAM_TIMEOUT)
            head = [f'{self.command} {self.path} HTTP/1.1']
            head += [f'{k}: {v}' for k, v in exch.request_headers]
            up.sendall(('\r\n'.join(head) + '\r\n\r\n').encode('latin-1', 'replace'))
            for data in self._request_body(exch, chunked, length):
                up.sendall(b'%x\r\n%s\r\n' % (len(data), data) if chunked else data)
            if chunked:
                up.sendall(b'0\r\n\r\n')
            self._body_done = True
            exch.handled_by = 'upstream'
            self._relay_response(exch, door, up, upgrade, set_cookie)
        finally:
            try:
                up.close()
            except OSError:
                pass

    def _send_intercepted(self, exch, answer, set_cookie):
        status, headers, body = answer
        body = body or b''
        exch.status = int(status)
        exch.handled_by = 'intercept'
        exch.response_headers = [(k, str(v)) for k, v in headers]
        door = self.server.door
        door.notify('on_response', exch)
        if body and self.command != 'HEAD':
            door.notify('on_response_body', exch, body)
        self.send_response(exch.status)
        for k, v in headers:
            if k.lower() not in HOP_BY_HOP and k.lower() not in OWN_RESPONSE_HEADERS:
                self.send_header(k, str(v).replace('\r', ' ').replace('\n', ' '))
        if set_cookie:
            self.send_header('Set-Cookie', self.server.door.cookie_header(set_cookie, exch.started))
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)
            exch.resp_bytes = len(body)

    def _relay_response(self, exch, door, up, upgrade, set_cookie):
        upf = up.makefile('rb')
        while True:
            line = upf.readline(65537)
            if not line:
                raise OSError('upstream closed before responding')
            parts = line.decode('latin-1').rstrip('\r\n').split(' ', 2)
            if len(parts) < 2 or not parts[0].startswith('HTTP/') or not parts[1].isdigit():
                raise OSError('upstream sent a malformed status line')
            code = int(parts[1])
            reason = parts[2] if len(parts) > 2 else ''
            reason = re.sub(r'[\x00-\x1f\x7f]', ' ', reason)[:200]
            hdrs = parse_headers(upf)
            if 100 <= code < 200 and code != 101:
                continue            # interim (we never sent Expect upstream)
            break
        exch.status = code
        exch.response_headers = [(k, v) for k, v in hdrs.items()]
        door.notify('on_response', exch)

        if code == 101 and upgrade:
            return self._tunnel(exch, door, up, upf, hdrs, reason)

        listed = {t.strip().lower() for v in (hdrs.get_all('Connection') or [])
                  for t in v.split(',') if t.strip()}
        te = (hdrs.get('Transfer-Encoding') or '').strip().lower()
        no_body = self.command == 'HEAD' or code in (204, 304) or 100 <= code < 200
        cl = None
        if not no_body and not te:
            vals = {v.strip() for v in (hdrs.get_all('Content-Length') or [])}
            if len(vals) == 1:
                v = vals.pop()
                if v.isdigit() and len(v) <= 15:
                    cl = int(v)
            elif len(vals) > 1:
                raise OSError('upstream sent conflicting Content-Length')

        self.send_response(code, reason or None)
        for k, v in hdrs.items():
            lk = k.lower()
            if lk in HOP_BY_HOP or lk in listed or lk in OWN_RESPONSE_HEADERS:
                continue
            if lk == 'set-cookie' and sets_door_cookie(v):
                continue
            self.send_header(k, v.replace('\r', ' ').replace('\n', ' '))
        if set_cookie:
            self.send_header('Set-Cookie', door.cookie_header(set_cookie, exch.started))

        mode = 'none'
        if no_body:
            if self.command == 'HEAD' and hdrs.get('Content-Length', '').strip().isdigit():
                self.send_header('Content-Length', hdrs['Content-Length'].strip())
        elif te == 'chunked':
            mode = 'chunked-in'
        elif te:
            raise OSError(f'upstream sent Transfer-Encoding {te!r}')
        elif cl is not None:
            mode = 'length'
            self.send_header('Content-Length', str(cl))
        else:
            mode = 'eof'
        # Re-frame chunked / read-to-EOF bodies as chunked for HTTP/1.1
        # clients (keeps the connection reusable); HTTP/1.0 gets a close.
        out_chunked = mode in ('chunked-in', 'eof') and self.request_version == 'HTTP/1.1'
        if out_chunked:
            self.send_header('Transfer-Encoding', 'chunked')
        elif mode in ('chunked-in', 'eof'):
            self.close_connection = True
        if self.close_connection:
            self.send_header('Connection', 'close')
        self.end_headers()

        def emit(data):
            exch.resp_bytes += len(data)
            door.notify('on_response_body', exch, data)
            self.wfile.write(b'%x\r\n%s\r\n' % (len(data), data) if out_chunked else data)

        if mode == 'length':
            left = cl
            while left > 0:
                data = upf.read1(min(left, CHUNK))
                if not data:
                    self.close_connection = True
                    raise OSError('upstream body ended early')
                left -= len(data)
                emit(data)
        elif mode == 'chunked-in':
            for data in self._read_chunked_response(upf):
                emit(data)
        elif mode == 'eof':
            while True:
                data = upf.read1(CHUNK)
                if not data:
                    break
                emit(data)
        if out_chunked:
            self.wfile.write(b'0\r\n\r\n')

    @staticmethod
    def _read_chunked_response(upf):
        while True:
            line = upf.readline(1026)
            size_s = line.split(b';', 1)[0].strip()
            if not line.endswith(b'\n') or not _HEX.match(size_s):
                raise OSError('upstream sent a bad chunk')
            size = int(size_s, 16)
            if size == 0:
                for _ in range(MAX_TRAILERS):
                    if upf.readline(8192) in (b'\r\n', b'\n', b''):
                        break
                return
            left = size
            while left:
                data = upf.read1(min(left, CHUNK))
                if not data:
                    raise OSError('upstream chunk ended early')
                left -= len(data)
                yield data
            upf.readline(3)

    def _tunnel(self, exch, door, up, upf, hdrs, reason):
        """101 Switching Protocols: pass the head on, then relay raw bytes
        both ways until either side closes. Bytes already buffered on either
        side (rfile / upf) are drained first via read1()."""
        exch.upgraded = True
        self.send_response(101, reason or None)
        for k, v in hdrs.items():
            if k.lower() in OWN_RESPONSE_HEADERS:
                continue
            if k.lower() == 'set-cookie' and sets_door_cookie(v):
                continue
            self.send_header(k, v.replace('\r', ' ').replace('\n', ' '))
        self.end_headers()
        self.wfile.flush()
        self.close_connection = True
        client = self.connection
        client.settimeout(TUNNEL_IDLE)
        up.settimeout(TUNNEL_IDLE)

        def pump(src, dst_sock, count):
            try:
                while True:
                    data = src.read1(CHUNK)
                    if not data:
                        break
                    dst_sock.sendall(data)
                    count(len(data))
            except (OSError, ValueError):
                pass
            finally:
                for s in (dst_sock,):
                    try:
                        s.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass

        def up_count(n):
            exch.resp_bytes += n

        def down_count(n):
            exch.req_bytes += n
        t = threading.Thread(target=pump, args=(self.rfile, up, down_count), daemon=True)
        t.start()
        pump(upf, client, up_count)
        t.join(TUNNEL_IDLE)


class DoorServer(BoundedThreadingHTTPServer):
    allow_reuse_address = True
    door = None


def build_server(door, port=0, bind='127.0.0.1'):
    server = make_server(DoorHandler, port, bind, tag='doorproxy', server_class=DoorServer)
    server.door = door
    return server


_cleanups = []


def _run_cleanups():
    while _cleanups:
        fn = _cleanups.pop()
        try:
            fn()
        except Exception:  # noqa: BLE001
            pass


def _watch_parent(ppid, server):
    """Exit with the bin/tunnel that started us, even after a kill -9."""
    while True:
        time.sleep(5)
        if os.getppid() != ppid:
            log('parent is gone; exiting')
            _run_cleanups()
            os._exit(0)


def _on_term(signum, frame):
    _run_cleanups()
    os._exit(0)


def main(argv=None):
    p = argparse.ArgumentParser(description='Porch door proxy (share rules in front of an app)')
    p.add_argument('--name', required=True)
    p.add_argument('--upstream-port', type=int, default=None)
    p.add_argument('--port', type=int, required=True)
    p.add_argument('--bind', default='127.0.0.1')
    p.add_argument('--state-dir', default=door_state.STATE_DIR)
    p.add_argument('--devices', default=None, help='cush-auth devices.json (owner passes)')
    p.add_argument('--grace', type=float, default=GRACE)
    p.add_argument('--inspect', action='store_true', help='record exchanges (masked)')
    p.add_argument('--inspect-raw', action='store_true', help='record exchanges unmasked')
    p.add_argument('--capture', action='store_true',
                   help='no upstream: answer from the state file\'s capture config (bin/hook)')
    a = p.parse_args(argv)
    if a.upstream_port is None and not a.capture:
        p.error('--upstream-port is required (or --capture)')
    upstream = None if a.capture else a.upstream_port
    door = Door(a.name, a.state_dir, upstream, devices_path=a.devices, grace=a.grace)
    capture = {}
    if a.capture:
        try:
            capture = door_state.read_state(door.state_path).get('capture') or {}
        except (OSError, ValueError):
            capture = {}
        responder = inspect_store.CaptureResponder.from_state(capture)
        door.max_body = door_state.capture_max_body(capture)
    recorder = None
    if a.inspect or a.inspect_raw or a.capture:
        recorder = inspect_store.Recorder(door, raw=a.inspect_raw)
        recorder.store.reset()          # a new door under this name starts empty
        recorder.start_control()
        door.add_observer(recorder)
        _cleanups.append(recorder.close)
        if a.inspect_raw:
            log('WARNING: --inspect-raw: Authorization, Cookie and token headers are '
                f'recorded unmasked in {recorder.store.path}')
    if a.capture:
        door.add_observer(responder)
    server = build_server(door, a.port, a.bind)
    atexit.register(_run_cleanups)
    signal.signal(signal.SIGTERM, _on_term)

    def note(s):
        s['proxy'] = {'port': server.server_address[1], 'pid': os.getpid()}
    try:
        door_state.update_state(door.state_path, note)
    except (OSError, ValueError) as e:
        log(f'could not record the proxy in the state file: {e}')
    threading.Thread(target=_watch_parent, args=(os.getppid(), server), daemon=True).start()
    behind = (f'capture (answers {responder.status})' if a.capture
              else f'127.0.0.1:{a.upstream_port}')
    extra = ''
    if recorder:
        extra = f', inspector: {"raw" if a.inspect_raw else "masked"}'
    log(f"'{a.name}' on {a.bind}:{server.server_address[1]} -> {behind} "
        f"(rules: {door_state.rules_summary(door.rules())}{extra})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        _run_cleanups()


if __name__ == '__main__':
    main()

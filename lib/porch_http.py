"""porch_http: the HTTP core every Porch app server shares.

Lifted from the "shared hardening block" that used to be copied byte for
byte into lib/mediaserver.py, lib/musicserver.py and lib/dropserver.py, plus
the bits the other servers hand-rolled. Stdlib only. What is here:

  * client_ip()            who to log / rate-limit (X-Forwarded-For believed
                           only from a loopback peer, i.e. frpc; right-most
                           non-loopback hop)
  * BoundedThreadingHTTPServer + HardenedHandlerMixin
                           connection cap (503 over it), daemon threads,
                           request-head deadline, minimum transfer rate while
                           the request is read (off once the response starts)
  * make_server()          bind (127.0.0.1 by default, a warning otherwise)
  * content_length()       strict Content-Length parsing
  * same_origin()          CSRF check for writes: Origin/Referer vs Host
  * security_headers(), csp_nonce(), page_csp(), SANDBOX_CSP
  * serve_asset(), porch_css_tag(), porch_style_src()
                           the design system (lib/porch.css + fonts) at
                           /__porch-assets/, content-hashed and immutable
  * MultipartStreamer      streaming multipart/form-data parser
  * safe_stem(), sanitize_filename(), name_candidates()
  * parse_range(), stream_file()   single byte range, clamped, 416
  * atomic_write_bytes(), atomic_write_json(), place_unique()
  * Quota / UploadSlots    shared running totals + concurrent upload cap
  * temp-file registry, SIGTERM cleanup, stale .part sweep
  * limit_child() / JobGate  resource-limited helpers, one job per key

The owner/identity check lives next door in lib/porch_auth.py.

Module-level knobs (HEADER_DEADLINE, REQUEST_DEADLINE, MIN_TRANSFER_RATE) are
read at call time, so tests can patch them on this module.
"""

import base64
import hashlib
import json
import os
import re
import resource
import secrets
import shutil
import signal
import socket
import stat
import sys
import threading
import time
import urllib.parse
from http.server import ThreadingHTTPServer

TRUSTED_PROXY_PEERS = frozenset({'127.0.0.1', '::1', '::ffff:127.0.0.1'})
_IP_CHARS = re.compile(r'^[0-9A-Fa-f:.]{1,45}$')

HEADER_DEADLINE = 20          # s to deliver request line + headers (and idle keep-alive)
REQUEST_DEADLINE = 120        # s of banked time a request may run ahead of its bytes
MIN_TRANSFER_RATE = 8 * 1024  # bytes/s a body or response must average to stay alive
DEFAULT_MAX_CONNECTIONS = 64
DEFAULT_MIN_FREE_MB = 1024    # refuse uploads that would leave less than this free


def client_ip(handler):
    """The client address to log and rate-limit by.

    X-Forwarded-For is believed only when the TCP peer is loopback, which is
    how frpc (on this box) reaches us; anyone else gets their socket address.
    The rightmost non-loopback hop is used: hops to its left were written by
    the client and are forgeable.
    """
    addr = getattr(handler, 'client_address', None) or ('',)
    peer = str(addr[0])
    if peer not in TRUSTED_PROXY_PEERS:
        return peer
    headers = getattr(handler, 'headers', None)
    xff = headers.get('X-Forwarded-For', '') if headers is not None else ''
    for hop in reversed(xff.split(',')):
        hop = hop.strip()
        if hop and hop not in TRUSTED_PROXY_PEERS and _IP_CHARS.match(hop):
            return hop
    return peer


class _DeadlineReaper:
    """One thread that hangs up connections whose deadline has passed.

    The per-read socket timeout alone lets a client hold a thread forever by
    trickling a byte every few seconds; a deadline that only moves forward as
    bytes actually move (see HardenedHandlerMixin) closes that hole.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._conns = {}
        self._reaped = set()
        self._thread = None

    def arm(self, sock, seconds):
        with self._lock:
            self._conns[id(sock)] = (sock, time.monotonic() + seconds)
            if self._thread is None:
                self._thread = threading.Thread(
                    target=self._run, name='deadline-reaper', daemon=True)
                self._thread.start()

    def credit(self, sock, seconds, cap):
        """Push a deadline out by `seconds`, never past now + cap."""
        with self._lock:
            ent = self._conns.get(id(sock))
            if ent is not None:
                limit = time.monotonic() + cap
                self._conns[id(sock)] = (sock, min(ent[1] + seconds, limit))

    def disarm(self, sock):
        with self._lock:
            self._conns.pop(id(sock), None)
            self._reaped.discard(id(sock))

    def reaped(self, sock):
        with self._lock:
            return id(sock) in self._reaped

    def _run(self):
        while True:
            time.sleep(1)
            now = time.monotonic()
            with self._lock:
                late = [k for k, (_, d) in self._conns.items() if d <= now]
                socks = [self._conns.pop(k)[0] for k in late]
                self._reaped.update(late)
            for s in socks:
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass


_reaper = _DeadlineReaper()


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a hard cap on concurrent connections.

    Over the cap a connection gets an immediate 503 and is closed instead of
    a thread, so a flood can't grow the process without bound.
    """

    daemon_threads = True
    request_queue_size = 32
    max_connections = DEFAULT_MAX_CONNECTIONS

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._conn_slots = threading.BoundedSemaphore(self.max_connections)

    def process_request(self, request, client_address):
        if not self._conn_slots.acquire(blocking=False):
            try:
                request.settimeout(1)
                request.sendall(b'HTTP/1.1 503 Service Unavailable\r\n'
                                b'Content-Length: 0\r\nRetry-After: 5\r\n'
                                b'Connection: close\r\n\r\n')
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._conn_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._conn_slots.release()

    def handle_error(self, request, client_address):
        # A client hanging up (or being reaped) mid-response is routine on a
        # public link; only log a traceback for real errors.
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError, socket.timeout)):
            return
        super().handle_error(request, client_address)


class HardenedHandlerMixin:
    """Deadlines + logging identity for a BaseHTTPRequestHandler subclass.

    List it before BaseHTTPRequestHandler. Request line and headers must
    arrive within HEADER_DEADLINE; after that a request may only stay alive by
    moving bytes: transferred() banks n / MIN_TRANSFER_RATE seconds, capped at
    REQUEST_DEADLINE ahead, so a slow-but-real upload lives and a trickle dies.
    The deadline covers reading the request only: send_response() disarms it.
    """

    timeout = 60                  # per-read socket timeout, on top of the deadline
    server_version = 'porch'
    sys_version = ''

    def handle_one_request(self):
        _reaper.arm(self.connection, HEADER_DEADLINE)
        super().handle_one_request()

    def parse_request(self):
        ok = super().parse_request()
        if ok and _reaper.reaped(self.connection):
            # The header deadline fired mid-headers; EOF made the header
            # parser stop early, so what we have is not a real request.
            self.close_connection = True
            return False
        if ok:
            _reaper.arm(self.connection, REQUEST_DEADLINE)
        return ok

    def transferred(self, nbytes):
        _reaper.credit(self.connection, nbytes / MIN_TRANSFER_RATE, REQUEST_DEADLINE)

    def send_response(self, code, message=None):
        # The request head and body are in by the time a (final) response
        # starts, and the deadline exists to stop slow *requests*. A client
        # that pauses reading a long response (a paused video, a backgrounded
        # tab) is bounded by the per-send socket timeout instead; the deadline
        # is re-armed by the next handle_one_request on a kept-alive socket.
        # (100-continue goes through send_response_only, so it does not
        # disarm before the body is read.)
        _reaper.disarm(self.connection)
        super().send_response(code, message)

    def finish(self):
        try:
            super().finish()
        finally:
            _reaper.disarm(self.connection)

    def address_string(self):
        return client_ip(self)


# ---- quota -------------------------------------------------------------------

class Quota:
    """Running byte and item totals for one directory, shared by all requests.

    An upload takes an item slot with begin() before writing anything and
    reserves bytes with add() as they arrive; both are checked against the
    caps under one lock, so N concurrent uploads can't each see the same room
    left and overshoot it together. end(kept=False) hands everything back.
    The totals are re-read from disk whenever nothing is in flight, so files
    added or removed out of band are picked up.
    """

    DISK_CHECK_EVERY = 1024 * 1024

    def __init__(self, directory, scan, max_bytes, max_items,
                 min_free=DEFAULT_MIN_FREE_MB * 1024 * 1024, label='collection',
                 item_word='items'):
        self.directory = directory
        self.scan = scan              # () -> (bytes_on_disk, items_on_disk)
        self.max_bytes = max_bytes
        self.max_items = max_items
        self.min_free = min_free
        self.label = label
        self.item_word = item_word
        self._lock = threading.Lock()
        self.used = 0
        self.items = 0
        self.inflight = 0
        self._gen = 0                 # bumped by begin/end; see resync()
        self._since_disk = 0
        self.resync()

    def resync(self):
        # The scan runs unlocked, so an upload can begin and end while it
        # runs; its result is only applied if nothing began or ended meanwhile
        # (self._gen), else a stale scan would forget that upload.
        with self._lock:
            if self.inflight:
                return
            gen = self._gen
        used, items = self.scan()
        with self._lock:
            if not self.inflight and self._gen == gen:
                self.used, self.items = used, items

    def _disk_low(self, extra):
        try:
            free = shutil.disk_usage(self.directory).free
        except OSError:
            return False
        return free - extra < self.min_free

    def begin(self):
        """Reserve an item slot. Returns None, or the reason it is refused."""
        self.resync()
        with self._lock:
            if self.items >= self.max_items:
                return f'{self.label} is full ({self.max_items} {self.item_word})'
            if self.used >= self.max_bytes:
                return f'{self.label} is full ({human_size(self.max_bytes)})'
            if self._disk_low(0):
                return 'the server is low on disk space'
            self.items += 1
            self.inflight += 1
            self._gen += 1
        return None

    def add(self, nbytes):
        """Reserve nbytes more for an in-flight upload. None or a reason."""
        with self._lock:
            if self.used + nbytes > self.max_bytes:
                return f'{self.label} is full ({human_size(self.max_bytes)})'
            self._since_disk += nbytes
            if self._since_disk >= self.DISK_CHECK_EVERY:
                self._since_disk = 0
                if self._disk_low(nbytes):
                    return 'the server is low on disk space'
            self.used += nbytes
        return None

    def end(self, reserved, kept):
        with self._lock:
            self.inflight = max(0, self.inflight - 1)
            self._gen += 1
            if not kept:
                self.used = max(0, self.used - reserved)
                self.items = max(0, self.items - 1)

    def removed(self, nbytes):
        with self._lock:
            self._gen += 1
            self.used = max(0, self.used - nbytes)
            self.items = max(0, self.items - 1)


class UploadSlots:
    """Cap on concurrent uploads, overall and per client address."""

    def __init__(self, total=4, per_ip=2):
        self.total = total
        self.per_ip = per_ip
        self._lock = threading.Lock()
        self._n = 0
        self._by_ip = {}

    def acquire(self, ip):
        with self._lock:
            if self._n >= self.total or self._by_ip.get(ip, 0) >= self.per_ip:
                return False
            self._n += 1
            self._by_ip[ip] = self._by_ip.get(ip, 0) + 1
            return True

    def release(self, ip):
        with self._lock:
            self._n = max(0, self._n - 1)
            left = self._by_ip.get(ip, 0) - 1
            if left > 0:
                self._by_ip[ip] = left
            else:
                self._by_ip.pop(ip, None)


# ---- placement, temp files, shutdown -----------------------------------------

_place_lock = threading.Lock()
_inflight_lock = threading.Lock()
_inflight_tmp = set()


def new_tmp(directory):
    """A fresh upload temp path, registered for SIGTERM cleanup."""
    p = directory / ('.upload-' + secrets.token_hex(8) + '.part')
    with _inflight_lock:
        _inflight_tmp.add(str(p))
    return p


def drop_tmp(path):
    """Unregister (and remove, if it is still there) a temp path."""
    with _inflight_lock:
        _inflight_tmp.discard(str(path))
    try:
        os.unlink(path)
    except OSError:
        pass


def place_unique(tmp, directory, candidates):
    """Move tmp into directory under the first free name; return that name.

    os.link refuses to overwrite, so the check and the claim are one atomic
    step: two uploads can never both land on the same name, even from two
    processes. The global lock covers the fallback for filesystems without
    hard links.
    """
    with _place_lock:
        for name in candidates:
            final = directory / name
            # Self-heal: a stale directory where a file should go (the
            # mergerfs/docker bind-mount shadowing failure mode).
            if final.is_dir() and not final.is_symlink():
                shutil.rmtree(final)
            try:
                os.link(tmp, final)
            except FileExistsError:
                continue
            except OSError:
                if os.path.lexists(final):
                    continue
                os.replace(tmp, final)
                return name
            drop_tmp(tmp)
            return name
    raise OSError('no free name for upload')


def install_sigterm_cleanup(tag):
    """On SIGTERM, delete in-flight upload temp files before exiting."""
    def _on_term(signum, frame):
        with _inflight_lock:
            paths = list(_inflight_tmp)
            _inflight_tmp.clear()
        for p in paths:
            try:
                os.unlink(p)
            except OSError:
                pass
        sys.stderr.write(f"[{tag}] SIGTERM: removed {len(paths)} partial upload(s), exiting\n")
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, _on_term)


def sweep_stale_parts(directory, subdirs=(), max_age=300):
    """Remove .part leftovers from a previous run (crash, SIGKILL).

    Only files older than max_age go: a live upload keeps its temp file's
    mtime fresh, so a second instance on the same directory is left alone.
    """
    now = time.time()
    removed = 0
    for d in [directory] + [directory / s for s in subdirs]:
        try:
            entries = list(d.iterdir())
        except OSError:
            continue
        for e in entries:
            if not e.name.endswith('.part'):
                continue
            if d == directory and not e.name.startswith('.upload-'):
                continue
            try:
                st = e.lstat()
                if stat.S_ISREG(st.st_mode) and now - st.st_mtime > max_age:
                    e.unlink()
                    removed += 1
            except OSError:
                pass
    return removed


# ---- resource-limited helpers ------------------------------------------------

CHILD_CPU_SECONDS = 30
CHILD_MEM_BYTES = 1024 * 1024 * 1024
CHILD_FSIZE_BYTES = 64 * 1024 * 1024


def limit_child():
    """preexec_fn for media helpers (ffmpeg): low priority, bounded CPU/RAM."""
    try:
        os.nice(10)
    except OSError:
        pass
    for res, val in ((resource.RLIMIT_CPU, CHILD_CPU_SECONDS),
                     (resource.RLIMIT_AS, CHILD_MEM_BYTES),
                     (resource.RLIMIT_FSIZE, CHILD_FSIZE_BYTES),
                     (resource.RLIMIT_CORE, 0)):
        try:
            resource.setrlimit(res, (val, val))
        except (ValueError, OSError):
            pass


def child_limits(cpu_seconds, fsize_bytes, mem_bytes=CHILD_MEM_BYTES, niceness=10):
    """A preexec_fn like limit_child() with the caller's own limits, for
    helpers that legitimately need more than a poster frame (a transcode)."""
    def _apply():
        try:
            os.nice(niceness)
        except OSError:
            pass
        for res, val in ((resource.RLIMIT_CPU, int(cpu_seconds)),
                         (resource.RLIMIT_AS, int(mem_bytes)),
                         (resource.RLIMIT_FSIZE, int(fsize_bytes)),
                         (resource.RLIMIT_CORE, 0)):
            try:
                resource.setrlimit(res, (val, val))
            except (ValueError, OSError):
                pass
    return _apply


class JobGate:
    """At most one job per key, and at most max_jobs jobs overall.

    run() returns fn()'s result, or JobGate.BUSY when no global slot came free
    within `wait` seconds. fn should re-check its cache first: a caller that
    waited on the per-key lock usually finds the work already done.
    """

    BUSY = object()

    def __init__(self, max_jobs=2):
        self._sem = threading.BoundedSemaphore(max_jobs)
        self._lock = threading.Lock()
        self._keys = {}

    def run(self, key, fn, wait=15):
        with self._lock:
            ent = self._keys.setdefault(key, [threading.Lock(), 0])
            ent[1] += 1
        try:
            if not ent[0].acquire(timeout=wait):
                return self.BUSY
            try:
                if not self._sem.acquire(timeout=wait):
                    return self.BUSY
                try:
                    return fn()
                finally:
                    self._sem.release()
            finally:
                ent[0].release()
        finally:
            with self._lock:
                ent[1] -= 1
                if ent[1] <= 0:
                    self._keys.pop(key, None)


def touch_marker(path):
    """Write an empty failure marker (its mtime records when it failed)."""
    try:
        with open(path, 'w'):
            pass
    except OSError:
        pass


def fresh_against(cache, source):
    """True iff cache exists and is at least as new as source."""
    try:
        return cache.stat().st_mtime >= source.stat().st_mtime
    except OSError:
        return False



# ---- binding -----------------------------------------------------------------

LOOPBACK_BINDS = frozenset({'127.0.0.1', '::1', 'localhost'})


def make_server(handler, port, bind='127.0.0.1', tag='porch', max_connections=None,
                server_class=None):
    """A BoundedThreadingHTTPServer on (bind, port) for `handler`.

    Loopback is the default and the expected bind: frpc reaches us on
    127.0.0.1, and nothing else on the LAN should reach an app around the
    tunnel. Anything else gets a warning on stderr. max_connections, when
    given, applies to this server only (a subclass carries it).
    """
    cls = server_class or BoundedThreadingHTTPServer
    attrs = {}
    if max_connections:
        attrs['max_connections'] = max(1, int(max_connections))
    if ':' in bind:
        attrs['address_family'] = socket.AF_INET6
    if attrs:
        cls = type(cls.__name__, (cls,), attrs)
    if bind not in LOOPBACK_BINDS:
        sys.stderr.write(f"[{tag}] WARNING: binding {bind}, not loopback; this server "
                         "expects to be reached only through the tunnel\n")
    return cls((bind, port), handler)


# ---- request bodies ----------------------------------------------------------

_CL_RE = re.compile(r'[0-9]{1,15}')


def content_length(handler):
    """The request's Content-Length: an int >= 0, 0 when absent, -1 if bad.

    Strict: only a plain run of digits (no sign, underscore, or 10k-digit
    number for int() to choke on), and several Content-Length headers that
    disagree are refused rather than guessed between (request smuggling).
    """
    headers = getattr(handler, 'headers', None)
    if headers is None:
        return 0
    values = headers.get_all('Content-Length') or []
    if not values:
        return 0
    vals = {v.strip() for v in values}
    if len(vals) != 1:
        return -1
    v = vals.pop()
    if v == '':
        return 0
    if not _CL_RE.fullmatch(v):
        return -1
    return int(v)


def read_json_body(handler, cap):
    """Read a small JSON-object body. {} when empty, None if bad or over cap."""
    length = content_length(handler)
    if length < 0 or length > cap:
        return None
    raw = handler.rfile.read(length) if length else b''
    if not raw:
        return {}
    try:
        data = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


# ---- same-origin (CSRF) ------------------------------------------------------

def same_origin(handler):
    """CSRF check for state-changing requests.

    Requires Origin (or, for older clients, Referer) to name the same host
    the request was addressed to (the Host header, port included). Absent
    both, or 'null' (sandboxed iframe / file:// page), the request is refused.
    This, not the cookie, is what pins a write to the app's own page: a
    SameSite=Lax cookie still rides along from a sibling host of the site.
    """
    host = (handler.headers.get('Host') or '').strip().lower()
    if not host:
        return False
    for header in ('Origin', 'Referer'):
        raw = handler.headers.get(header)
        if not raw:
            continue
        if raw == 'null':
            return False
        try:
            netloc = urllib.parse.urlsplit(raw.strip()).netloc.lower()
        except ValueError:
            return False
        return bool(netloc) and netloc == host
    return False


# ---- response headers --------------------------------------------------------

# Anything served from user content: executes nothing, loads nothing.
SANDBOX_CSP = "default-src 'none'; sandbox"


def security_headers(handler, referrer='no-referrer', frame='DENY'):
    """Headers every response carries.

    nosniff is the important one: it stops a browser from re-deciding that
    something we labelled image/png or text/plain is really HTML and running
    it on this origin. Pass referrer=None / frame=None to leave one out.
    """
    handler.send_header('X-Content-Type-Options', 'nosniff')
    if referrer:
        handler.send_header('Referrer-Policy', referrer)
    if frame:
        handler.send_header('X-Frame-Options', frame)


def csp_nonce():
    """A fresh per-response nonce for the page's inline <style>/<script>."""
    return secrets.token_urlsafe(16)


def page_csp(nonce, sources="img-src 'self' data:; connect-src 'self'"):
    """Lockdown CSP for an inline page: nonced script/style (plus porch.css
    and its fonts from 'self'), `sources` for the rest, and 'none' for forms,
    <base> and framing."""
    return ("default-src 'none'; "
            f"script-src 'nonce-{nonce}'; {porch_style_src(nonce)}; "
            f"{sources}; "
            "form-action 'none'; base-uri 'none'; frame-ancestors 'none'")


# ---- design-system assets (/__porch-assets/) ---------------------------------
#
# lib/porch.css and the fonts in lib/vendor/fonts/ are served by every app at
# content-hashed paths under ASSET_PREFIX, with a one-year immutable cache. The
# prefix is deliberately not /__porch/: HAProxy sends /__porch/ on every host to
# the auth server. A request is looked up by exact path in a table built once at
# import, so nothing from the URL ever reaches the filesystem (no traversal), and
# a stale or unhashed name is a plain 404.

ASSET_PREFIX = '/__porch-assets/'
_LIB_DIR = os.path.dirname(os.path.abspath(__file__))
PORCH_CSS_FILE = os.path.join(_LIB_DIR, 'porch.css')
FONT_DIR = os.path.join(_LIB_DIR, 'vendor', 'fonts')
ASSET_CACHE_CONTROL = 'public, max-age=31536000, immutable'
_FONT_URL = re.compile(r'url\("fonts/([a-z0-9-]+)\.woff2"\)')


def _hash8(data):
    return hashlib.sha256(data).hexdigest()[:12]


def _build_assets():
    """{path: (bytes, content_type)} plus the stylesheet's public path."""
    table = {}
    font_paths = {}
    try:
        names = sorted(os.listdir(FONT_DIR))
    except OSError:
        names = []
    for name in names:
        if not name.endswith('.woff2'):
            continue
        with open(os.path.join(FONT_DIR, name), 'rb') as f:
            data = f.read()
        stem = name[:-len('.woff2')]
        rel = f'fonts/{stem}.{_hash8(data)}.woff2'
        table[ASSET_PREFIX + rel] = (data, 'font/woff2')
        font_paths[stem] = rel
    try:
        with open(PORCH_CSS_FILE, 'rb') as f:
            css = f.read().decode('utf-8')
    except OSError:
        return table, None

    # Relative to the stylesheet, so the pair also works under a path prefix
    # (secure-entry serves everything below its /<token>/).
    def _font(m):
        target = font_paths.get(m.group(1))
        return f'url("{target}")' if target else m.group(0)
    css = _FONT_URL.sub(_font, css).encode('utf-8')
    css_path = f'{ASSET_PREFIX}porch.{_hash8(css)}.css'
    table[css_path] = (css, 'text/css; charset=utf-8')
    return table, css_path


ASSETS, PORCH_CSS_PATH = _build_assets()


def font_face_rules(url_prefix):
    """porch.css's @font-face rules with the (hashed) font URLs under
    `url_prefix`, for a stylesheet built elsewhere (bin/auth-css)."""
    if not PORCH_CSS_PATH:
        return ''
    css = ASSETS[PORCH_CSS_PATH][0].decode('utf-8')
    rules = re.findall(r'@font-face\{[^}]*\}', css)
    return '\n'.join(r.replace('url("fonts/', f'url("{url_prefix}') for r in rules)


def inline_font_faces(names=('bricolage-700', 'geist-400', 'geist-500', 'geist-mono-400')):
    """@font-face rules for the named fonts with the woff2 inlined as data:
    URIs, for a page that cannot fetch /__porch-assets/ (the closed-door page
    frps serves on a dead host)."""
    with open(PORCH_CSS_FILE, encoding='utf-8') as f:
        css = f.read()
    out = []
    for name in names:
        rule = re.search(r'@font-face\{[^}]*url\("fonts/' + re.escape(name) + r'\.woff2"\)[^}]*\}',
                         css)
        if not rule:
            raise ValueError(f'porch.css has no @font-face for {name}')
        with open(os.path.join(FONT_DIR, name + '.woff2'), 'rb') as f:
            data = base64.b64encode(f.read()).decode('ascii')
        out.append(rule.group(0).replace(f'url("fonts/{name}.woff2")',
                                         f'url("data:font/woff2;base64,{data}")'))
    return '\n'.join(out)


def porch_css_tag(base=''):
    """The <link> every page puts in its <head> (empty if porch.css is
    missing, so a broken checkout degrades to unstyled, not to an error).
    `base` is a path prefix the app serves everything under (no trailing
    slash), matching serve_asset(base=...)."""
    if not PORCH_CSS_PATH:
        return ''
    return f'<link rel="stylesheet" href="{base}{PORCH_CSS_PATH}">'


def porch_style_src(nonce=None):
    """CSP directives that let a page use porch.css: the stylesheet and its
    fonts from this origin, plus the page's own nonced <style> if any. Only
    style-src and font-src are widened; nothing else changes."""
    nonce_src = f" 'nonce-{nonce}'" if nonce else ''
    return f"style-src 'self'{nonce_src}; font-src 'self'"


def porch_mark(size=16, label=None):
    """The porch mark (house outline, a light in the door) as inline SVG. The
    outline takes currentColor, the light takes the page's --accent."""
    a11y = (f'role="img" aria-label="{label}"' if label else 'aria-hidden="true"')
    return (f'<svg class="p-mark" width="{size}" height="{size}" viewBox="0 0 64 64" {a11y}>'
            '<path class="p-mark-line" d="M8 30 L32 10 L56 30" stroke-width="5"/>'
            '<path class="p-mark-line" d="M16 28 V54 H48 V28" stroke-width="5"/>'
            '<circle class="p-mark-light" cx="32" cy="22" r="5.5"/></svg>')


def is_asset_path(path):
    return path.startswith(ASSET_PREFIX)


def serve_asset(handler, head=False, base=''):
    """Answer a GET/HEAD for [base]/__porch-assets/...; False if the path is
    not ours (the caller carries on routing). Unknown asset names are a 404.
    `base` is a fixed path prefix the caller has already authorised (e.g.
    secure-entry's /<token>); it is compared exactly, never interpreted."""
    path = handler.path.split('?', 1)[0].split('#', 1)[0]
    if not path.startswith(base + ASSET_PREFIX):
        return False
    path = path[len(base):]
    entry = ASSETS.get(path)
    if entry is None:
        body = b'not found\n'
        handler.send_response(404)
        handler.send_header('Content-Type', 'text/plain; charset=utf-8')
        handler.send_header('Content-Length', str(len(body)))
        handler.send_header('Cache-Control', 'no-store')
        handler.send_header('Content-Security-Policy', SANDBOX_CSP)
        security_headers(handler)
        handler.end_headers()
        if not head:
            handler.wfile.write(body)
        return True
    data, ctype = entry
    etag = '"' + path.rsplit('.', 2)[-2] + '"'
    if handler.headers.get('If-None-Match') == etag:
        handler.send_response(304)
        handler.send_header('ETag', etag)
        handler.send_header('Cache-Control', ASSET_CACHE_CONTROL)
        handler.end_headers()
        return True
    handler.send_response(200)
    handler.send_header('Content-Type', ctype)
    handler.send_header('Content-Length', str(len(data)))
    handler.send_header('Cache-Control', ASSET_CACHE_CONTROL)
    handler.send_header('ETag', etag)
    handler.send_header('Content-Security-Policy', SANDBOX_CSP)
    handler.send_header('Cross-Origin-Resource-Policy', 'same-origin')
    security_headers(handler)
    handler.end_headers()
    if not head:
        handler.wfile.write(data)
    return True


def parse_cookies(cookie_header):
    """Cookie header -> {name: value}. A repeated name keeps the last value."""
    out = {}
    if not cookie_header:
        return out
    for part in cookie_header.split(';'):
        k, _, v = part.strip().partition('=')
        if k:
            out[k] = v
    return out


# ---- streaming multipart parser ---------------------------------------------

MAX_PART_HEADERS = 16 * 1024   # a part's header block; anything bigger is an attack
MAX_BOUNDARY = 200


class MultipartError(Exception):
    pass


class UploadRejected(Exception):
    """A part blew a hard limit; abandon the whole request.

    Raised instead of draining the rest of the body: once we know the client
    is over the per-file or per-collection cap there is no reason to keep
    reading (and paying for) bytes we are going to discard.
    """

    def __init__(self, reason, status=413):
        super().__init__(reason)
        self.reason = reason
        self.status = status


def multipart_boundary(content_type):
    """(boundary_bytes, None) for a multipart/form-data Content-Type, else
    (None, (message, status))."""
    ctype = content_type or ''
    m = re.search(r'boundary="?([^";,]+)"?', ctype, re.I)
    if not ctype.lower().startswith('multipart/form-data') or not m:
        return None, ('Expected multipart/form-data', 400)
    boundary = m.group(1).strip().encode('latin-1', 'replace')
    if not boundary or len(boundary) > MAX_BOUNDARY:
        return None, ('Bad multipart boundary', 400)
    return boundary, None


class MultipartStreamer:
    """Incremental multipart/form-data reader.

    Reads at most `limit` bytes (the declared Content-Length) and hands each
    part's body to the caller as a chunk iterator, so an upload spools
    straight to disk and its size is checked *as it arrives*, rather than
    after `rfile.read(length)` has made the box allocate the whole body.
    """

    CHUNK = 64 * 1024

    def __init__(self, rfile, boundary, limit, on_bytes=None,
                 max_part_headers=MAX_PART_HEADERS):
        self.rfile = rfile
        self.limit = limit                       # bytes still allowed off the wire
        self.on_bytes = on_bytes                 # deadline credit per chunk read
        self.max_part_headers = max_part_headers
        self.delim = b'\r\n--' + boundary
        # A synthetic leading CRLF lets the first boundary match the same
        # "\r\n--boundary" shape as every subsequent one.
        self.buf = b'\r\n'
        self.eof = False

    def _fill(self):
        """Pull one more chunk from the socket. False once the body is done."""
        if self.eof or self.limit <= 0:
            self.eof = True
            return False
        data = self.rfile.read(min(self.CHUNK, self.limit))
        if not data:
            self.eof = True
            return False
        self.limit -= len(data)
        self.buf += data
        if self.on_bytes:
            self.on_bytes(len(data))
        return True

    def _read_until(self, sep, maxlen):
        """Consume up to and including `sep`; return what preceded it."""
        while True:
            i = self.buf.find(sep)
            if i >= 0:
                out = self.buf[:i]
                self.buf = self.buf[i + len(sep):]
                return out
            if len(self.buf) > maxlen:
                raise MultipartError('multipart header too long')
            if not self._fill():
                raise MultipartError('truncated multipart stream')

    def _peek(self, n):
        while len(self.buf) < n:
            if not self._fill():
                break
        return self.buf[:n]

    def _skip_to_first_delim(self):
        while self.buf.find(self.delim) < 0:
            if len(self.buf) > self.CHUNK * 2:
                # Preamble before the first boundary is normally empty; a huge
                # one is a client trying to make us buffer.
                raise MultipartError('multipart preamble too long')
            if not self._fill():
                return False
        i = self.buf.find(self.delim)
        self.buf = self.buf[i + len(self.delim):]
        return True

    def _iter_part_body(self):
        d = self.delim
        n = len(d)
        while True:
            i = self.buf.find(d)
            if i >= 0:
                if i:
                    yield self.buf[:i]
                self.buf = self.buf[i + n:]
                return
            # Hold back the last n-1 bytes: the delimiter may straddle chunks.
            if len(self.buf) >= n:
                cut = len(self.buf) - (n - 1)
                chunk = self.buf[:cut]
                self.buf = self.buf[cut:]
                if chunk:
                    yield chunk
            if not self._fill():
                raise MultipartError('truncated multipart body')

    def parts(self):
        """Yield (filename_or_None, chunk_iterator) per part, in order.

        The caller must exhaust each iterator before advancing — that is what
        leaves the buffer positioned on the next delimiter.
        """
        if not self._skip_to_first_delim():
            return
        while True:
            # After a delimiter comes either "--" (final boundary) or CRLF and
            # then the part headers. Transport padding before the CRLF is legal.
            # The final boundary is checked by peeking, because a client is
            # allowed to end the body right after the trailing "--".
            if self._peek(2) == b'--':
                return
            line = self._read_until(b'\r\n', 1024)
            if line.startswith(b'--'):
                return
            raw_headers = self._read_until(b'\r\n\r\n', self.max_part_headers)
            headers = raw_headers.decode('utf-8', 'replace')
            m = re.search(r'filename\*?=("([^"]*)"|([^;\r\n]*))', headers, re.I)
            filename = None
            if m:
                filename = (m.group(2) if m.group(2) is not None else m.group(3) or '').strip()
            yield filename, self._iter_part_body()


# ---- filenames ---------------------------------------------------------------

MAX_NAME_STEM = 60          # chars of the client's stem we keep


def safe_stem(raw, max_stem=MAX_NAME_STEM):
    """Reduce a client-supplied filename to a harmless stem.

    Drops every directory component (both separators — a Windows client will
    happily send "..\\..\\etc\\passwd"), strips NULs, then keeps only
    characters that can't mean anything to a path, a shell, or an HTTP
    header. A leading '.' or '-' is removed so the result can never be a
    dotfile or look like a command-line flag to a helper such as ffmpeg.
    """
    name = str(raw).replace('\\', '/').split('/')[-1]
    stem = os.path.splitext(name)[0]
    stem = stem.replace('\x00', '')
    stem = re.sub(r'[^A-Za-z0-9._-]', '_', stem)
    stem = re.sub(r'_{3,}', '__', stem).strip('_')
    stem = stem[:max_stem]
    while stem[:1] in ('.', '-'):
        stem = stem[1:]
    return stem or 'upload'


def sanitize_filename(name, max_len=255):
    """Reduce a filename to something that can only be a file in one dir.

    Same character policy as safe_stem, with the extension kept: used both on
    lookup paths where the client echoes a stored name back, and (drop) as
    the stored name itself. A leading '.' or '-' becomes 'upload_'.
    """
    name = str(name).replace('\\', '/').split('/')[-1]
    name = name.replace('\x00', '')
    name = re.sub(r'[^A-Za-z0-9._-]', '_', name)
    while name[:1] in ('.', '-'):
        name = 'upload_' + name[1:]
    return name[:max_len] or 'upload'


def name_candidates(stem, ext):
    """Names to try for an upload: '<stem><ext>', then random suffixes.

    place_unique() claims the first free one atomically (os.link refuses to
    overwrite), so two simultaneous uploads of the same filename can't both
    win and clobber each other.
    """
    yield stem + ext
    for _ in range(8):
        yield f"{stem}-{secrets.token_hex(3)}{ext}"
    for _ in range(8):
        yield f"{stem}-{secrets.token_hex(8)}{ext}"


def human_size(size):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if size < 1024:
            return f"{size:.1f} {unit}" if unit != 'B' else f"{size} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def safe_child(base, raw, sanitize=sanitize_filename):
    """(resolved_path, name) for a client-supplied name inside `base`, or
    (None, name) if it is a symlink or resolves outside.

    The symlink test runs on the unresolved path: after resolve() a link has
    already been followed, so checking is_symlink() there could never fire.
    resolve()+containment then guarantees we never touch anything outside.
    """
    name = sanitize(raw)
    candidate = base / name
    try:
        if candidate.is_symlink():
            return None, name
        target = candidate.resolve()
        target.relative_to(base.resolve())
    except (ValueError, OSError):
        return None, name
    return target, name


# ---- byte ranges -------------------------------------------------------------

def parse_range(header, size):
    """Parse a single byte range against a file of `size` bytes.

    Returns (start, end) inclusive, 'unsatisfiable', or None (= ignore the
    header and send the whole file). Range headers arrive straight from the
    network, so this refuses anything it does not fully understand rather
    than passing numbers through to a seek():
      * only the 'bytes' unit, only one range (multipart/byteranges is
        answered with a plain 200 instead)
      * digit runs are length-capped, so no 10k-digit int to parse (which on
        Python 3.11+ raises out of int())
      * everything is clamped into [0, size-1] and start<=end is enforced
    """
    if not header or size <= 0:
        return None
    header = header.strip()
    if len(header) > 128 or not header.lower().startswith('bytes='):
        return None
    spec = header[6:].strip()
    if ',' in spec:
        return None                      # multi-range: fall back to 200
    m = re.fullmatch(r'(\d{0,15})-(\d{0,15})', spec)
    if not m:
        return None
    first, last = m.group(1), m.group(2)
    if first == '' and last == '':
        return None
    if first == '':
        # Suffix form 'bytes=-N': the final N bytes. N==0 is unsatisfiable.
        n = int(last)
        if n == 0:
            return 'unsatisfiable'
        start = max(0, size - n)
        end = size - 1
    else:
        start = int(first)
        end = int(last) if last != '' else size - 1
        if start >= size:
            return 'unsatisfiable'
        end = min(end, size - 1)
        if end < start:
            return 'unsatisfiable'
    return start, end


def stream_file(handler, target, size, ctype, disposition, name,
                cache='private, max-age=300', ranges=True, headers_fn=None):
    """Send a stored file, honouring a single Range when `ranges`.

    `name` must already be header-safe (sanitize_filename output). Every
    response gets the sandbox CSP, so even something unexpected served
    inline executes and loads nothing. headers_fn(handler) adds the app's
    security headers (default: security_headers). Bytes written are credited
    to the handler's transfer deadline when it has one.
    """
    add_headers = headers_fn or security_headers
    rng = parse_range(handler.headers.get('Range'), size) if ranges else None
    if rng == 'unsatisfiable':
        handler.send_response(416)
        handler.send_header('Content-Range', f'bytes */{size}')
        handler.send_header('Content-Length', '0')
        add_headers(handler)
        handler.end_headers()
        return
    start, end = rng if rng else (0, size - 1)
    length = end - start + 1 if size > 0 else 0

    handler.send_response(206 if rng else 200)
    handler.send_header('Content-Type', ctype)
    if ranges:
        handler.send_header('Accept-Ranges', 'bytes')
    handler.send_header('Content-Length', str(length))
    if rng:
        handler.send_header('Content-Range', f'bytes {start}-{end}/{size}')
    handler.send_header('Content-Disposition', f'{disposition}; filename="{name}"')
    handler.send_header('Cache-Control', cache)
    handler.send_header('Content-Security-Policy', SANDBOX_CSP)
    add_headers(handler)
    handler.end_headers()
    if handler.command == 'HEAD':
        return
    credit = getattr(handler, 'transferred', None)
    remaining = length
    with open(target, 'rb') as f:
        f.seek(start)
        while remaining > 0:
            chunk = f.read(min(65536, remaining))
            if not chunk:
                break
            try:
                handler.wfile.write(chunk)
            except (BrokenPipeError, ConnectionResetError):
                handler.close_connection = True
                return
            if credit:
                credit(len(chunk))
            remaining -= len(chunk)


# ---- atomic writes -----------------------------------------------------------

def atomic_write_bytes(path, data, mode=None):
    """Write `data` to `path` via a unique temp file in the same directory
    and os.replace, so readers see the old file or the new one, never half.
    The temp name starts with '.' so directory listings skip it."""
    path = os.fspath(path)
    d, base = os.path.split(path)
    tmp = os.path.join(d or '.', f'.{base}.{secrets.token_hex(6)}.tmp')
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0),
                     0o600 if mode is None else mode)
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def atomic_write_json(path, obj, mode=0o644):
    atomic_write_bytes(path, json.dumps(obj).encode('utf-8'), mode=mode)


def export_assets(dest):
    """Write every /__porch-assets/ file under `dest` (same relative paths),
    for a static host such as the landing page (bin/deploy). Returns the
    paths written."""
    written = []
    for path, (data, _ctype) in ASSETS.items():
        target = os.path.join(dest, path.lstrip('/'))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, 'wb') as f:
            f.write(data)
        written.append(target)
    return written


if __name__ == '__main__':
    # python3 lib/porch_http.py --export DIR   write the assets under DIR
    # python3 lib/porch_http.py --css-tag      print porch.css's <link> tag
    if sys.argv[1:2] == ['--export'] and len(sys.argv) == 3:
        for p in export_assets(sys.argv[2]):
            print(p)
    elif sys.argv[1:] == ['--css-tag']:
        print(porch_css_tag())
    elif sys.argv[1:2] == ['--inline-fonts'] and len(sys.argv) == 2:
        print(inline_font_faces())
    else:
        sys.exit('usage: porch_http.py --export DIR | --css-tag | --inline-fonts')

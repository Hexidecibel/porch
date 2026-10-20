#!/usr/bin/env python3
"""
cush-tools auth server.

Provides per-device auth for frp:
  - /verify?op=Login       frps webhook; approves/rejects based on metas.device_token
  - /auth/pair/start       bootstrap POSTs here; gets a pairing code + poll_token
  - /auth/pair/status/...  bootstrap long-polls; gets issued token on approval
  - /auth/                 admin UI (single HTML page)
  - /auth/admin/*          session-gated endpoints used by the UI
  - /auth/static/auth.css  the pages' stylesheet (public; built by bin/auth-css)
  - /login                 gate page: private / not on your pass / pass ran out,
                           with Ask for access; ?owner=1 (or no rd) = admin-password enroll
  - /auth/access-requests  Ask for access (public POST; GET /<id>?t= polls)
  - /i/<token>             invite landing page; POST /i/<token>/accept enrolls

Binds 127.0.0.1 only. Reload state from disk on SIGHUP. See CLAUDE.md for context.
"""

import argparse
import base64
import fcntl
import hashlib
import hmac
import json
import ipaddress
import os
import queue
import random
import secrets
import signal
import string
import tempfile
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, quote

_LIB = os.path.dirname(os.path.abspath(__file__))
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
import porch_http  # noqa: E402  (Porch fonts at /auth/__porch-assets/, see bin/auth-css)
import porch_auth  # noqa: E402  (porch_host validator + device-expiry rules, shared with the apps)
import porch_config  # noqa: E402  (domain config: config/porch.toml, PORCH_* env)
from porch_auth import epoch_from_iso, host_token_entry  # noqa: E402,F401
from porch_auth import device_expired as _device_expired  # noqa: E402
import access_requests  # noqa: E402  (Ask for access: the gate pages' asks, memory only)
import gate_pages  # noqa: E402  (the gate pages: private / not on your pass / ran out)

# --- Configuration / global state ---------------------------------------------------

DATA_DIR = ""
DEVICES_PATH = ""
STATE_LOCK = threading.Lock()
STATE = {
    "devices": [],
    "pairings": [],
    "admin": None,
    "server": {},           # set by configure_domain()
    "protected_apps": [],   # set by configure_domain()
    "public_paths": [],     # see validate_public_path()
    "invites": [],
}

# --- Forward-auth gate (web apps behind HAProxy) ------------------------------------
GATE_COOKIE = "cush_auth"
GATE_TTL = 90 * 86400  # 90 days
COOKIE_DOMAIN = ""  # set by configure_domain(), e.g. ".cush.rocks"
MAPS_DIR = "/etc/haproxy/maps"
DEVICES_MAP = ""   # set in main() from MAPS_DIR
PROTECTED_MAP = ""  # set in main() from MAPS_DIR
GRANTS_MAP = ""     # set in main() from MAPS_DIR
IDENTITY_MAP = ""   # set in main() from MAPS_DIR
PUBLIC_MAP = ""     # set in main() from MAPS_DIR (public prefixes, map_beg)
PUBLIC_EXACT_MAP = ""  # set in main() from MAPS_DIR (exact public paths, map_str)
HAPROXY_SOCK = "/run/haproxy/admin.sock"

# Default protected apps if none on disk (config auth.protected_apps).
DEFAULT_PROTECTED_APPS = []

# Known *.<root> app hostnames the panel offers protect toggles for (config
# auth.known_apps). Private tools that are reasonable cush-auth targets (have an
# HAProxy backend + cert, no strong auth of their own). Shown as protect-toggles
# in the admin panel and as per-device scope checkboxes.
KNOWN_HOSTS = []

# rate limit: ip -> list[epoch_seconds] for POST /i/<token>/accept
INVITE_ACCEPT_ATTEMPTS = {}
INVITE_ACCEPT_ATTEMPTS_LOCK = threading.Lock()

# Invite links: bounds on what the admin can create, and how long finished
# (expired / used up / revoked) invites linger in the panel before the sweeper
# drops them from disk.
INVITE_MAX_HOURS = 720
INVITE_MAX_USES = 50
# A standing invite (a link left up in public, e.g. on a portfolio) reuses
# max_uses as a cap on LIVE passes rather than lifetime uses, so it gets a
# higher ceiling. Devices it mints must expire: 1 minute to 30 days.
INVITE_MAX_LIVE = 500
INVITE_STANDING_DEFAULT_LIVE = 20
DEVICE_TTL_MAX_MINUTES = 30 * 24 * 60
# Statuses in which an invite is still in service. "full" is a standing invite
# whose passes are all in use; it reopens by itself as they expire.
INVITE_OPEN = ("active", "full")
INVITE_KEEP_SECS = 7 * 86400
INVITE_MAX_RECORDS = 500
INVITE_BASE_URL = ""  # set by configure_domain(): https://<auth_host>/i/

# Browser-device roles. `admin` is the owner's own browsers; `guest` is
# everyone else. Role is independent of scope: a guest can hold ["*"].
ROLES = ("admin", "guest")

import re
# One label under the root domain (configure_domain() rebuilds it).
HOST_RE = None
# Shapes that are safe to emit as a whitespace-separated HAProxy map line and
# as an argument to the runtime API's `add map` command. Anything containing a
# space or a newline could forge an extra map entry (a free auth grant) or
# smuggle a second socket command, so unexpected values are dropped, not
# escaped. Both are generated internally today; this guards against a
# hand-edited or CLI-written devices.json.
TOKEN_SHA_RE = re.compile(r"^[0-9a-fA-F]{64}$")
DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
# Value of a cush-identity.map line: "<device_id>|<role>|<percent-encoded name>".
# Percent-encoding keeps spaces out; this regex is the backstop, same as above.
IDENTITY_VALUE_RE = re.compile(r"^[A-Za-z0-9_.~%:|-]{1,200}$")
# Plaintext invite tokens are secrets.token_urlsafe(32) (43 chars). Anything
# else in /i/<token> is refused before it is hashed or looked up.
INVITE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,128}$")
INVITE_ID_RE = re.compile(r"^inv_[0-9a-f]{8}$")
# The path part deliberately excludes quotes, angle brackets, backslash and
# backtick: `rd` is echoed into the /login page's JS, and `</script>` inside
# it would close the script element (XSS) even though it needs no quotes.
RD_RE = None       # https://<one label under root>[path], set by configure_domain()
RD_PATH_CHARS = r"[^\s\"'<>\\`]*"
DEFAULT_RD = ""    # config auth.default_rd

# Public paths: a few URLs on a gated host that anyone may open (share links,
# webhooks). One entry is {id, host, path, app, why, created_at, created_by,
# enabled}. A path ending in "/" is a prefix, anything else is exact. The
# rules (validate_public_path) keep an entry from ever opening a whole site.
PUBLIC_PATH_MAX = 100
PUBLIC_PATH_MAX_LEN = 128
PUBLIC_PATH_CHARS_RE = re.compile(r"[A-Za-z0-9._~/-]+")
PUBLIC_PATH_ID_RE = re.compile(r"^pp_[0-9a-f]{8}$")
PUBLIC_APP_MAX = 40
PUBLIC_WHY_MAX = 120
PUBLIC_BY = ("cli", "pocket", "admin-ui")

# The auth host itself must never be a gated/granted target.
AUTH_HOST = ""     # config domain.auth_host
DOMAIN_ROOT = ""   # config domain.root
TUNNEL_BASE = ""   # config domain.tunnel_base

# Local CLI credential (bin/auth-admin). A fresh random token is written to
# DATA_DIR/.admin-cli-token (0600) on every start and accepted in place of an
# admin session, but only on requests that did not come through a proxy: both
# front doors stamp every request they forward. HAProxy's www-https frontend
# sets X-Forwarded-For/-Host/-Proto/-Port with `http-request set-header`, and
# nginx's tunnel.cush.rocks /auth/ location sets X-Forwarded-For with
# `proxy_set_header`, so a client cannot strip them. Their presence means the
# request came from the network, and the token is then ignored even if right.
CLI_TOKEN_FILE = ".admin-cli-token"

# The home box's own frpc (bin/tunnel, every launcher) authenticates like any
# paired machine, with a tunnel_admin device whose token lives in
# DATA_DIR/.home-frpc-token (0600). ensure_home_device() mints it on start.
# The old rule "a Login from 127.0.0.1 needs no token" is unsafe once a relay
# forwards remote frpc connections in through a loopback frpc, so it is only
# kept when LOCALHOST_BYPASS is on: PORCH_LOCALHOST_BYPASS=1 (0 forces it off),
# else config [adopt] localhost_bypass (an adopted install; default off).
HOME_TOKEN_FILE = ".home-frpc-token"
HOME_DEVICE_NAME = "home"


def localhost_bypass_enabled(cfg, env=None):
    env = os.environ if env is None else env
    v = (env.get("PORCH_LOCALHOST_BYPASS") or "").strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return bool(getattr(cfg, "localhost_bypass", False))


LOCALHOST_BYPASS = False  # set by configure_domain()
CLI_TOKEN_HEADER = "X-Cush-CLI-Token"
CLI_TOKEN = ""
PROXY_HEADERS = (
    "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
    "X-Forwarded-Port", "X-Real-IP", "Forwarded", "Via",
)

# One lock for every read-modify-write of devices.json, shared with
# bin/auth-admin's offline fallback. A sidecar file rather than devices.json
# itself (which is replaced by rename, so its inode changes under a lock) or
# the data directory. Readers take it shared, writers exclusive.
DEVICES_LOCK_FILE = ".devices.lock"
# Held exclusively for the whole life of a running server. bin/auth-admin
# probes it: if it cannot take it, the server is up and every mutation must go
# through the HTTP API, never straight to the file the server will overwrite.
SERVER_LOCK_FILE = ".authserver.lock"
_SERVER_LOCK_FD = None

# First-run admin setup. While no admin exists, a one-time token is minted at
# start, written 0600 to DATA_DIR/.admin-setup-token and logged; the setup
# endpoint refuses without it, so the first visitor can't claim the console.
SETUP_TOKEN_FILE = ".admin-setup-token"
SETUP_TOKEN = ""
PASSWORD_MIN = 12

# scrypt (n=2**15) costs ~32MB and tens of ms. Never under STATE_LOCK, and at
# most this many at once; a caller that can't get a slot soon gets a 503.
SCRYPT_SLOTS = threading.BoundedSemaphore(2)
SCRYPT_WAIT = 10

# Shared limiter for everything that checks the admin password (login,
# /auth/enroll, setup, set-password): 5 attempts/min per IP in ONE table, plus
# a global SLOWDOWN once GLOBAL_FAIL_MAX wrong passwords arrive inside the
# window from any mix of IPs. It is a delay, never a hard stop: a hard stop
# let anyone lock the owner out by spraying 30 wrong passwords a minute. Each
# failure past the threshold adds GLOBAL_DELAY_STEP seconds to every password
# check, capped at GLOBAL_DELAY_MAX, so a spread-out guesser is still throttled
# (combined with SCRYPT_SLOTS, to a handful of guesses a second at most).
AUTH_ATTEMPTS = {}
AUTH_ATTEMPTS_LOCK = threading.Lock()
AUTH_PER_IP_MAX = 5
AUTH_WINDOW = 60
GLOBAL_FAILS = []
GLOBAL_FAIL_MAX = 30
GLOBAL_DELAY_STEP = 0.25
GLOBAL_DELAY_MAX = 5.0
_sleep = time.sleep  # patched by tests

# --- Per-host session handoff ("porch_host") -----------------------------------------
# cush_auth is Domain=.cush.rocks, so every app (and every tunnel) receives it.
# The handoff gives each host its own HOST-ONLY cookie instead:
#   0. app sends an un-authed browser to https://<its host>/__porch/start?rd=..
#      which sets a random state in a __Host-porch_state cookie ON THAT HOST
#      and bounces to
#   1. https://auth.cush.rocks/auth/handoff?host=<its host>&rd=<url>&state=<s>
#   2. authserver (seeing cush_auth on the auth host) mints a 60s single-use
#      code bound to <host> AND <state>, redirects to https://<host>/__porch/auth?code=..
#   3. HAProxy routes /__porch/ on every host to authserver, which redeems the
#      code only if the browser's __Host-porch_state cookie equals the code's
#      state, records sha256 of a fresh token on the device (host_tokens) and
#      sets porch_host=<token> without a Domain attribute.
# The state binds the code to the browser that started the flow: without it
# an attacker could mint a code for THEIR device and send a victim to
# /__porch/auth?code=<it>, logging the victim into the attacker's identity.
# The __Host- prefix makes browsers refuse that cookie from any Set-Cookie
# with a Domain attribute, so a sibling *.cush.rocks host cannot toss one in.
HOST_COOKIE = "porch_host"
STATE_COOKIE = "__Host-porch_state"
HANDOFF_STATE_TTL = 600
HOST_TOKEN_TTL = 30 * 86400
HOST_TOKENS_PER_DEVICE = 50
HANDOFF_TTL = 60
HANDOFF_MAX = 1000
HANDOFF_CODES = {}   # sha256(code) -> {device_id, host, rd, expires}
HANDOFF_LOCK = threading.Lock()

# Ask for access (lib/access_requests.py): the gate pages' asks, in memory.
# Tests swap ACCESS for a Store with their own clock.
ACCESS = access_requests.Store()
ACCESS_LIMIT = access_requests.RateLimit(*access_requests.PER_IP)
ACCESS_PATH = "/auth/access-requests"
HANDOFF_CODE_RE = re.compile(r"^[A-Za-z0-9_-]{20,128}$")
# One DNS label under the root domain or under the tunnel base (by default
# cush.rocks / tunnel.cush.rocks). Set by configure_domain().
HANDOFF_HOST_RE = None
# Path + query of an rd. Same character rules as RD_RE: rd lands in a Location
# header and, via /login, in page JS.
RD_PATH_RE = re.compile(r"^/(?!/)[^\s\"'<>\\`]*$")


def configure_domain(cfg):
    """Point every domain-dependent global at `cfg` (a porch_config.Config).
    Called at import with porch_config.get(); tests call it with another
    domain and restore the default after. Every pattern is built from
    re.escape()d, already-validated hostnames and anchored at both ends."""
    global COOKIE_DOMAIN, DEFAULT_PROTECTED_APPS, KNOWN_HOSTS, INVITE_BASE_URL
    global HOST_RE, RD_RE, DEFAULT_RD, AUTH_HOST, DOMAIN_ROOT, TUNNEL_BASE
    global HANDOFF_HOST_RE, DEFAULT_SERVER, DOMAIN_CFG, LOCALHOST_BYPASS
    DOMAIN_CFG = cfg
    LOCALHOST_BYPASS = localhost_bypass_enabled(cfg)
    DOMAIN_ROOT = cfg.root
    TUNNEL_BASE = cfg.tunnel_base
    AUTH_HOST = cfg.auth_host
    COOKIE_DOMAIN = cfg.cookie_domain
    DEFAULT_PROTECTED_APPS = list(cfg.protected_apps)
    KNOWN_HOSTS = list(cfg.known_apps)
    INVITE_BASE_URL = f"https://{cfg.auth_host}/i/"
    DEFAULT_RD = cfg.default_rd
    DEFAULT_SERVER = {"addr": cfg.frp_addr, "port": cfg.frp_port}
    root = re.escape(cfg.root)
    HOST_RE = re.compile(r"^[a-z0-9-]+\." + root + r"\Z")
    RD_RE = re.compile(
        r"^https://[a-z0-9-]+\." + root + r"(/" + RD_PATH_CHARS + r")?\Z", re.IGNORECASE)
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\."
    bases = sorted({re.escape(cfg.root), re.escape(cfg.tunnel_base)})
    HANDOFF_HOST_RE = re.compile(r"^" + label + r"(?:" + "|".join(bases) + r")\Z")
    STATE["server"] = dict(DEFAULT_SERVER)
    STATE["protected_apps"] = list(DEFAULT_PROTECTED_APPS)


DEFAULT_SERVER = {}
DOMAIN_CFG = None
configure_domain(porch_config.get())


def _domain_html(html):
    """Fill the domain placeholders in one of the inline page templates.
    Runs on the template before any request data is spliced in."""
    return (html.replace("__PORCH_ROOT_RE__", porch_config.js_regex_escape(DOMAIN_ROOT))
                .replace("__PORCH_ROOT__", DOMAIN_ROOT)
                .replace("__PORCH_AUTH_HOST__", AUTH_HOST)
                .replace("__PORCH_DEFAULT_RD__", DEFAULT_RD))

# frps NewProxy rules for tunnel devices that are not tunnel_admin. `entry-` is
# what secure-entry forms use: a squatter there could phish secrets.
# The owner's own tool names are reserved too (music*, media*, ...): a remote
# device that grabs a name the owner's links point at would serve its page
# under the owner's URL. So is every name the owner's localhost tunnels use
# now (OWNER_STATE_DIR) or have used (DATA_DIR/history.jsonl).
RESERVED_SUBDOMAIN_PREFIXES = ("entry-", "music", "media", "photos", "drop")
RESERVED_SUBDOMAINS = frozenset({"auth", "www", "api", "admin", "panel", "status", "grab"})
OPEN_PROXY_TYPES = ("http", "https")
OWNER_STATE_DIR = "/tmp/tunnel-state"
HISTORY_FILE = "history.jsonl"
_OWNER_NAMES_CACHE = {"key": None, "names": frozenset()}
_OWNER_NAMES_LOCK = threading.Lock()


def owner_tunnel_names():
    """Names the owner's own (localhost) tunnels have used: every `name` in
    DATA_DIR/history.jsonl plus every <name>.json in OWNER_STATE_DIR.
    The history parse is cached on (mtime, size)."""
    names = set()
    try:
        for fn in os.listdir(OWNER_STATE_DIR):
            if fn.endswith(".json"):
                names.add(fn[:-5].lower())
    except OSError:
        pass
    path = os.path.join(DATA_DIR, HISTORY_FILE) if DATA_DIR else ""
    try:
        st = os.stat(path)
        key = (path, st.st_mtime_ns, st.st_size)
    except OSError:
        key = None
    with _OWNER_NAMES_LOCK:
        if key is not None and _OWNER_NAMES_CACHE["key"] == key:
            return frozenset(names | _OWNER_NAMES_CACHE["names"])
    hist = set()
    if key is not None:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    n = rec.get("name") if isinstance(rec, dict) else None
                    if isinstance(n, str) and n:
                        hist.add(n.strip().lower())
        except OSError:
            pass
    with _OWNER_NAMES_LOCK:
        _OWNER_NAMES_CACHE["key"] = key
        _OWNER_NAMES_CACHE["names"] = frozenset(hist)
    return frozenset(names | hist)

# Per-connection socket timeout (seconds) for both read and write.
REQUEST_TIMEOUT = 60


def normalize_apps(apps):
    """Validate + normalize a device-scope `apps` value.

    Accepts ["*"] (all gated apps) or a list of *.cush.rocks hostnames.
    Returns the normalized list (["*"] or a sorted, de-duped, lowercased list
    of valid hosts). Raises ValueError on any invalid/forbidden entry.
    """
    if not isinstance(apps, list) or len(apps) == 0:
        raise ValueError("apps must be a non-empty list")
    if apps == ["*"]:
        return ["*"]
    if "*" in apps:
        raise ValueError("apps cannot mix '*' with specific hosts")
    out = set()
    for h in apps:
        if not isinstance(h, str):
            raise ValueError("apps entries must be strings")
        h = h.strip().lower()
        if not HOST_RE.match(h):
            raise ValueError(f"invalid host: {h}")
        if h == AUTH_HOST:
            raise ValueError("cannot grant the auth host")
        out.add(h)
    if not out:
        raise ValueError("apps must contain at least one valid host")
    return sorted(out)


def poll_token_match(stored, given):
    """Constant-time comparison for pairing poll tokens.

    poll_token is a bearer secret — the only thing standing between a caller
    and someone else's freshly-issued device token — so it gets compare_digest
    rather than `==`, which short-circuits on the first differing byte.
    """
    if not stored or not given:
        return False
    if not isinstance(stored, str) or not isinstance(given, str):
        return False
    return hmac.compare_digest(stored, given)


def device_perm_apps(d):
    """A browser device's PERMANENT scope (its stored `apps`), defaulting
    old/missing records to ['*']. This is what the panel shows and edits, and
    the only thing a scope merge may write back; see device_apps for what the
    device can actually reach right now."""
    apps = d.get("apps")
    if not isinstance(apps, list) or not apps:
        return ["*"]
    return apps


def _live_pass(d, now):
    """The device's `pass` record if it is still running, else None.

    A pass is time-limited extra scope on a browser that was already enrolled
    when it accepted a TTL invite: {invite_id, apps, expires_at}.
    """
    p = d.get("pass")
    if not isinstance(p, dict) or epoch_from_iso(p.get("expires_at")) <= now:
        return None
    return p


def device_apps(d, now=None):
    """What a browser device can reach right now: its permanent scope plus
    the apps of a live pass. A pass can never contribute '*'."""
    apps = device_perm_apps(d)
    if apps == ["*"]:
        return apps
    p = _live_pass(d, time.time() if now is None else now)
    if p is None:
        return apps
    extra = [
        h for h in (p.get("apps") or []) if isinstance(h, str) and h != "*"
    ]
    return sorted(set(apps) | set(extra))


def find_host_token_device(devices, token, host, now=None):
    """Reference validator for the porch_host cookie: porch_auth's, so the
    apps and this server apply exactly the same rule. `now` defaults to this
    module's clock (tests swap `time`)."""
    return porch_auth.find_host_token_device(
        devices, token, host, time.time() if now is None else now)


def handoff_allowed(d, host, now):
    """May this browser device get a porch_host token for `host`? Admins and
    ['*'] devices anywhere; otherwise only for hosts in its current scope."""
    if d.get("role") == "admin":
        return True
    apps = device_apps(d, now)
    return apps == ["*"] or host in apps


# token_sha256 -> (device_id, type) (hot path for /verify and /auth/me).
# The type is cached alongside the id so /verify can refuse browser gate
# cookies without an O(n) scan of the device list.
TOKEN_CACHE = {}

# The pages' stylesheet: lib/auth.css, generated by bin/auth-css and committed.
# Read once by load_auth_css(); under /auth/ so nginx's /auth/ proxy on
# tunnel.cush.rocks reaches it too.
AUTH_CSS_PATH = "/auth/static/auth.css"
# auth.css's fonts live at AUTH_ASSET_BASE + /__porch-assets/fonts/<name>.<hash>.woff2
AUTH_ASSET_BASE = "/auth"
AUTH_CSS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "auth.css")
AUTH_CSS = None       # bytes, or None if the file could not be read
AUTH_CSS_ETAG = ""

# async write queue for /verify last_seen / run_id updates
UPDATE_QUEUE = queue.Queue(maxsize=10000)

# rate limit: ip -> list[epoch_seconds] for /auth/pair/start
PAIR_START_ATTEMPTS = {}
PAIR_START_ATTEMPTS_LOCK = threading.Lock()

# Cap to prevent unbounded rate-limit dict growth under flood attacks.
RATE_LIMIT_MAX_KEYS = 10000

# Fix #5: in-memory issued tokens keyed by poll_token.
# poll_token -> (issued_token_plaintext, expires_at_epoch)
PENDING_TOKENS = {}
PENDING_TOKENS_LOCK = threading.Lock()

# Fix #3: cap on simultaneously-pending pairings (not counting approved/expired).
MAX_PENDING_PAIRINGS = 100

# Throttled logger state: msg -> last_logged_epoch
_LOG_ONCE_STATE = {}
_LOG_ONCE_LOCK = threading.Lock()


def _log_once_per_sec(msg):
    now = time.time()
    with _LOG_ONCE_LOCK:
        last = _LOG_ONCE_STATE.get(msg, 0)
        if now - last < 1.0:
            return
        _LOG_ONCE_STATE[msg] = now
    log(msg)


def _rate_limit_check(table, table_lock, ip, window, max_attempts):
    """Generic per-IP rate limiter.

    Prunes old timestamps, evicts empty keys, caps total key count. Returns
    True if the request is allowed (and records the attempt), False if denied.
    """
    now = time.time()
    with table_lock:
        attempts = [t for t in table.get(ip, []) if now - t < window]
        if attempts:
            table[ip] = attempts
        elif ip in table:
            del table[ip]
        if len(attempts) >= max_attempts:
            # Still counts as an attempt — keep the entry fresh so the window holds.
            attempts.append(now)
            table[ip] = attempts
            return False
        # Cap total keys — if we're at the limit, evict an arbitrary key.
        if ip not in table and len(table) >= RATE_LIMIT_MAX_KEYS:
            try:
                victim = next(iter(table))
                del table[victim]
            except StopIteration:
                pass
        attempts.append(now)
        table[ip] = attempts
        return True


def global_password_delay():
    """Seconds every password check waits while the global slowdown is on
    (0 below GLOBAL_FAIL_MAX recent failures)."""
    now = time.time()
    with AUTH_ATTEMPTS_LOCK:
        GLOBAL_FAILS[:] = [t for t in GLOBAL_FAILS if now - t < AUTH_WINDOW]
        excess = len(GLOBAL_FAILS) - GLOBAL_FAIL_MAX + 1
    if excess <= 0:
        return 0.0
    return min(GLOBAL_DELAY_MAX, GLOBAL_DELAY_STEP * excess)


def password_attempt_allowed(ip):
    """Gate for every admin-password check. False only while THIS IP has used
    its AUTH_PER_IP_MAX attempts in the window. Many failures from everyone
    combined slow every check down (global_password_delay) but never refuse
    it outright, so a password spray cannot lock the owner out."""
    if not _rate_limit_check(
        AUTH_ATTEMPTS, AUTH_ATTEMPTS_LOCK, ip, AUTH_WINDOW, AUTH_PER_IP_MAX
    ):
        return False
    delay = global_password_delay()
    if delay > 0:
        _log_once_per_sec(f"auth: global password slowdown active ({delay:.2f}s)")
        _sleep(delay)
    return True


def record_password_failure():
    with AUTH_ATTEMPTS_LOCK:
        GLOBAL_FAILS.append(time.time())
        if len(GLOBAL_FAILS) > GLOBAL_FAIL_MAX * 4:
            del GLOBAL_FAILS[: len(GLOBAL_FAILS) - GLOBAL_FAIL_MAX * 4]


def _is_loopback(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a.is_loopback


def client_ip_from(peer, xff_values):
    """The real client IP for per-IP limits.

    X-Forwarded-For is trusted only when the TCP peer is loopback (the
    proxies on this box). Then the right-most hop that is not loopback is the
    client: HAProxy sets XFF to the client's address, and nginx's
    $proxy_add_x_forwarded_for appends HAProxy's own 127.0.0.1 after it.
    Anything to the left of that is client-supplied and ignored. Taking the
    first token (as before) let a client pick its own rate-limit key, and an
    nginx using $remote_addr made every visitor 127.0.0.1.
    """
    if not _is_loopback(peer):
        return peer
    hops = [h.strip() for v in xff_values for h in v.split(",") if h.strip()]
    for hop in reversed(hops):
        if _is_loopback(hop):
            continue
        try:
            return str(ipaddress.ip_address(hop))
        except ValueError:
            return "unparseable:" + hop[:64]
    return peer


class ScryptBusy(Exception):
    """No scrypt slot came free within SCRYPT_WAIT seconds."""


def scrypt_limited(password, salt):
    """scrypt_hash behind SCRYPT_SLOTS. Never call with STATE_LOCK held."""
    if not SCRYPT_SLOTS.acquire(timeout=SCRYPT_WAIT):
        raise ScryptBusy()
    try:
        return scrypt_hash(password, salt)
    finally:
        SCRYPT_SLOTS.release()

# Unambiguous alphabet for pairing codes — no 0/O/1/I/L.
CODE_ALPHA = "ABCDEFGHJKMNPQRSTUVWXYZ"
CODE_DIGIT = "23456789"

SESSION_COOKIE = "cush_auth_session"
SESSION_TTL = 86400  # 24h
PAIRING_TTL = 600  # 10 min
POLL_TIMEOUT = 30  # seconds
POLL_INTERVAL = 0.5


# --- Logging ------------------------------------------------------------------------

def log(msg):
    sys.stderr.write(f"[authserver] {msg}\n")
    sys.stderr.flush()


# --- Atomic JSON persistence --------------------------------------------------------

class devices_lock:
    """flock on DATA_DIR/.devices.lock (next to `path`). Exclusive for writers,
    shared for readers. bin/auth-admin's offline fallback takes the same lock
    exclusively across its whole read-modify-write."""

    def __init__(self, path=None, exclusive=True):
        d = os.path.dirname(path or DEVICES_PATH) or "."
        self.lock_path = os.path.join(d, DEVICES_LOCK_FILE)
        self.mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        self.fd = None

    def __enter__(self):
        self.fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(self.fd, self.mode)
        return self

    def __exit__(self, *exc):
        try:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
        finally:
            os.close(self.fd)
        return False


def _atomic_write(path, data):
    """Write JSON to `path` via a unique 0600 temp file, fsync, rename, all
    under the exclusive devices lock."""
    d = os.path.dirname(path) or "."
    with devices_lock(path, exclusive=True):
        fd, tmp = tempfile.mkstemp(prefix=".devices.", suffix=".tmp", dir=d)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


def _write_secret_file(path, value):
    """Publish a secret at `path`: a 0600 temp file (created 0600 before
    anything is written), fsync, rename. Never readable by another user and
    never seen half-written."""
    fd, tmp = tempfile.mkstemp(
        prefix="." + os.path.basename(path) + ".", suffix=".tmp",
        dir=os.path.dirname(path) or ".",
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(value + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_cli_token():
    """Mint this run's CLI token and publish it at DATA_DIR/.admin-cli-token.
    A restart invalidates the old one."""
    global CLI_TOKEN
    token = secrets.token_urlsafe(32)
    _write_secret_file(os.path.join(DATA_DIR, CLI_TOKEN_FILE), token)
    CLI_TOKEN = token


def ensure_setup_token():
    """While no admin exists, keep a one-time setup token on disk (0600) and
    in the log; once an admin exists, forget it and remove the file."""
    global SETUP_TOKEN
    path = os.path.join(DATA_DIR, SETUP_TOKEN_FILE)
    with STATE_LOCK:
        needs = not STATE.get("admin")
    if not needs:
        SETUP_TOKEN = ""
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except OSError as e:
            log(f"could not remove {path}: {e}")
        return
    if SETUP_TOKEN:
        return
    token = secrets.token_urlsafe(18)
    _write_secret_file(path, token)
    SETUP_TOKEN = token
    log(f"No admin configured. Setup token: {token} (also in {path}); "
        f"enter it at /auth/ or run bin/auth-admin set-password")


def acquire_server_lock():
    """Hold DATA_DIR/.authserver.lock for the life of the process. Exits if
    another authserver already holds it: two servers would overwrite each
    other's devices.json."""
    global _SERVER_LOCK_FD
    path = os.path.join(DATA_DIR, SERVER_LOCK_FILE)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        log(f"FATAL: another authserver holds {path}")
        sys.exit(1)
    os.ftruncate(fd, 0)
    os.write(fd, f"{os.getpid()}\n".encode())
    _SERVER_LOCK_FD = fd


class StateError(ValueError):
    """devices.json is unreadable or has the wrong shape."""


def validate_state(data):
    """Raise StateError with a precise message if `data` is not a usable
    devices.json. Missing keys are filled in by load_state; wrong TYPES are not
    guessed at."""
    if not isinstance(data, dict):
        raise StateError("top level must be a JSON object")
    for key in ("devices", "pairings", "invites", "protected_apps", "app_hosts",
                "public_paths"):
        if key in data and data[key] is not None and not isinstance(data[key], list):
            raise StateError(f"'{key}' must be a list")
    for i, d in enumerate(data.get("devices") or []):
        if not isinstance(d, dict):
            raise StateError(f"devices[{i}] must be an object")
        if not isinstance(d.get("id"), str) or not d["id"]:
            raise StateError(f"devices[{i}] has no string 'id'")
        ht = d.get("host_tokens")
        if ht is not None and not isinstance(ht, list):
            raise StateError(f"devices[{i}].host_tokens must be a list")
    for i, p in enumerate(data.get("pairings") or []):
        if not isinstance(p, dict) or not isinstance(p.get("code"), str):
            raise StateError(f"pairings[{i}] must be an object with a string 'code'")
    for i, inv in enumerate(data.get("invites") or []):
        if not isinstance(inv, dict):
            raise StateError(f"invites[{i}] must be an object")
    for i, pp in enumerate(data.get("public_paths") or []):
        if not isinstance(pp, dict):
            raise StateError(f"public_paths[{i}] must be an object")
    admin = data.get("admin")
    if admin is not None:
        if not isinstance(admin, dict):
            raise StateError("'admin' must be an object or null")
        for k in ("password_scrypt", "salt", "session_secret"):
            if k in admin and not isinstance(admin[k], str):
                raise StateError(f"admin.{k} must be a string")
    if "server" in data and not isinstance(data["server"], dict):
        raise StateError("'server' must be an object")


def load_state(fatal=True):
    """Load devices.json from disk. If missing, create a fresh one.

    A file that can't be parsed or has the wrong shape is reported with the
    path and the exact problem. At start (fatal=True) that ends the process;
    on a SIGHUP reload it raises StateError and the in-memory state is kept.

    The read and the swap of STATE both happen under STATE_LOCK. Reading
    first and locking only for the swap lost any change a request saved in
    between: the reload then put the older file contents back in memory.
    Lock order is STATE_LOCK, then the devices.json file lock, the same as
    every save.
    """
    with STATE_LOCK:
        _load_state_holding_lock(fatal)


def _load_state_holding_lock(fatal):
    """load_state's body. Caller holds STATE_LOCK."""
    global STATE, TOKEN_CACHE
    if not os.path.exists(DEVICES_PATH):
        fresh = {
            "devices": [],
            "pairings": [],
            "admin": None,
            "server": dict(DEFAULT_SERVER),
            "protected_apps": list(DEFAULT_PROTECTED_APPS),
            "public_paths": [],
            "invites": [],
        }
        os.makedirs(os.path.dirname(DEVICES_PATH), exist_ok=True)
        _atomic_write(DEVICES_PATH, fresh)
        log(f"Created fresh {DEVICES_PATH}")
    # Shared lock while reading, so an offline bin/auth-admin write is never
    # observed half-done.
    try:
        with devices_lock(DEVICES_PATH, exclusive=False):
            with open(DEVICES_PATH, "r") as f:
                data = json.load(f)
        validate_state(data)
    except (OSError, ValueError) as e:
        what = "is not valid JSON" if isinstance(e, json.JSONDecodeError) else "is unusable"
        msg = (f"{DEVICES_PATH} {what}: {e}. Fix it by hand or restore a "
               f"backup (bin/auth-deploy keeps data/backups/devices.json.bak-*).")
        if fatal:
            log("FATAL: " + msg)
            sys.exit(1)
        raise StateError(msg)
    # fill in missing defaults
    data.setdefault("devices", [])
    data.setdefault("pairings", [])
    data.setdefault("admin", None)
    data.setdefault("server", dict(DEFAULT_SERVER))
    if not isinstance(data.get("invites"), list):
        data["invites"] = []
    if not isinstance(data.get("public_paths"), list):
        data["public_paths"] = []
    # Seed protected_apps; default if absent. Normalize device "type" — any
    # device lacking a type predates the browser gate and is a tunnel device.
    if not data.get("protected_apps"):
        data["protected_apps"] = list(DEFAULT_PROTECTED_APPS)
    # app_hosts remembers every host that has ever been protected, so turning
    # protection off in the panel leaves a toggle behind to turn it back on.
    if not isinstance(data.get("app_hosts"), list):
        data["app_hosts"] = []
    data["app_hosts"] = sorted(set(data["app_hosts"]) | set(data["protected_apps"]))
    # Role migration. Browser devices that predate roles were owners exactly
    # when they held ["*"] (that was the rule the status/music/media servers
    # used), so they become admin and everything else becomes guest — no
    # behavior change on the day roles land. A role value that isn't one we
    # know is coerced to guest (fail closed). Tunnel devices carry no role.
    migrated = False
    for d in data.get("devices", []):
        d.setdefault("type", "tunnel")
        if d["type"] != "browser":
            continue
        if "role" not in d:
            d["role"] = "admin" if device_perm_apps(d) == ["*"] else "guest"
            migrated = True
        elif d["role"] not in ROLES:
            d["role"] = "guest"
            migrated = True
    # Session epoch: monotonically-increasing counter on the admin record.
    # Every cookie stamps its issued_at; verification rejects any cookie
    # whose issued_at predates the current epoch. Logout bumps the epoch,
    # invalidating all outstanding cookies server-side — not just the one
    # the browser is sending back. Missing on disk => initialize to 0
    # (backward-compat for installs that predate this field).
    if isinstance(data.get("admin"), dict):
        data["admin"].setdefault("epoch", 0)
    # Migration for Fix #5: any legacy issued_token on disk is dead state;
    # the Mac has already pulled its token or the pairing is unreachable.
    for p in data.get("pairings", []):
        if p.get("issued_token"):
            p["issued_token"] = None
    now = time.time()
    STATE = data
    TOKEN_CACHE = {
        d["token_sha256"]: (d["id"], d.get("type", "tunnel"))
        for d in STATE["devices"]
        if not d.get("revoked") and d.get("token_sha256")
        and not _device_expired(d, now)
    }
    # Persist the role migration right away: the status/music/media
    # servers read devices.json directly and switch to the role rule as
    # soon as they see a `role` key.
    if migrated:
        save_state_locked()
        log("Migrated browser device roles")
    log(f"Loaded {len(STATE['devices'])} devices, {len(STATE['pairings'])} pairings")


def save_state_locked():
    """Caller must hold STATE_LOCK."""
    _atomic_write(DEVICES_PATH, STATE)


def ensure_home_device():
    """Make sure DATA_DIR/.home-frpc-token exists and names a live tunnel_admin
    device ("home"). Mints both on first start. A revoked home device is not
    resurrected: delete the token file and restart to rotate. Returns the
    device dict (or None when revoked)."""
    path = os.path.join(DATA_DIR, HOME_TOKEN_FILE)
    token = ""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "r") as f:
            token = f.read().strip()
        if os.stat(path).st_mode & 0o077:
            os.chmod(path, 0o600)
    except FileNotFoundError:
        pass
    minted = False
    if not token:
        token = b64url(secrets.token_bytes(32))
        _write_secret_file(path, token)
        minted = True
    sha = sha256_hex(token)
    with STATE_LOCK:
        dev = next((d for d in STATE["devices"] if d.get("token_sha256") == sha), None)
        if dev is not None:
            if dev.get("revoked"):
                log(f"WARNING: the home frpc token ({HOME_TOKEN_FILE}) belongs to revoked "
                    f"device {dev.get('id')}; home tunnels will be refused. Delete "
                    f"{path} and restart to mint a new one.")
                return None
            if dev.get("type") != "tunnel" or dev.get("tunnel_admin") is not True:
                dev["type"], dev["tunnel_admin"], dev["apps"] = "tunnel", True, None
                save_state_locked()
            TOKEN_CACHE[sha] = (dev["id"], "tunnel")
            return dev
        device_id = "dev_" + secrets.token_hex(4)
        while any(d.get("id") == device_id for d in STATE["devices"]):
            device_id = "dev_" + secrets.token_hex(4)
        dev = {
            "id": device_id, "name": HOME_DEVICE_NAME, "type": "tunnel", "apps": None,
            "token_sha256": sha, "created_at": iso_from_epoch(time.time()),
            "last_seen": None, "revoked": False, "run_id_history": [],
            "tunnel_admin": True, "home": True,
        }
        STATE["devices"].append(dev)
        TOKEN_CACHE[sha] = (device_id, "tunnel")
        save_state_locked()
    log(f"home frpc device {device_id} registered"
        + (f" (new token in {HOME_TOKEN_FILE})" if minted else ""))
    return dev


RELOAD_EVENT = threading.Event()


def handle_sighup(signum, frame):
    # Only flag the reload here. A second SIGHUP can interrupt the handler of
    # the first on the same thread, and the locks load_state and
    # sync_haproxy_maps take are not re-entrant.
    RELOAD_EVENT.set()


def reload_worker():
    """Reload devices.json and force a full map push on each SIGHUP."""
    while True:
        RELOAD_EVENT.wait()
        RELOAD_EVENT.clear()
        log("SIGHUP received, reloading state")
        try:
            load_state(fatal=False)
            ensure_setup_token()
            sync_haproxy_maps(force=True)
        except Exception as e:
            log(f"reload failed, keeping the in-memory state: {e}")


# --- HAProxy forward-auth map sync --------------------------------------------------

import socket as _socket


def _atomic_write_text(path, text):
    """Atomic text write mirroring _atomic_write's dir-lock + fsync + rename."""
    lock_dir = os.path.dirname(path) or "."
    lock_fd = os.open(lock_dir, os.O_RDONLY)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(tmp, 0o644)
        except OSError:
            pass
        os.replace(tmp, path)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def _haproxy_socket_cmd(cmd):
    """Send one command to HAProxy's runtime API over its UNIX admin socket.

    Returns the reply text, or None if the socket is unavailable (not running,
    no permission, etc.). Never raises — map FILES are authoritative on reload,
    so a socket failure is non-fatal: the next HAProxy reload picks up the file.
    """
    try:
        s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(HAPROXY_SOCK)
        if not cmd.endswith("\n"):
            cmd = cmd + "\n"
        s.sendall(cmd.encode("utf-8"))
        chunks = []
        while True:
            buf = s.recv(4096)
            if not buf:
                break
            chunks.append(buf)
        s.close()
        return b"".join(chunks).decode("utf-8", "replace")
    except Exception as e:
        _log_once_per_sec(f"haproxy socket unavailable: {e}")
        return None


# Runtime-API replies, as HAProxy 2.8 sends them. A command that worked answers
# with an empty line; anything else is an error message.
_MAP_VERSION_RE = re.compile(r"^New version created: (\d+)$")
_MAP_UNKNOWN_REPLY = "Unknown map identifier"
_UNKNOWN_MAPS_LOGGED = set()


def _haproxy_swap_map(path, pairs):
    """Replace one live HAProxy map with `pairs` in a single atomic step.

    `prepare map` opens a new version that no request can see, the entries are
    added to it, and `commit map` switches lookups over in one go. If anything
    fails before the commit, nothing is committed and the old live map keeps
    serving: stale beats empty, since an empty protected map un-gates every app.

    Returns True when the map is live (or HAProxy does not load this map at
    all, so there is nothing to push), False when the push failed, and None
    when the socket could not be reached.
    """
    reply = _haproxy_socket_cmd(f"prepare map {path}")
    if reply is None:
        return None
    reply = reply.strip()
    if reply.startswith(_MAP_UNKNOWN_REPLY):
        # A map no haproxy.cfg rule references is never loaded. Say so once.
        if path not in _UNKNOWN_MAPS_LOGGED:
            _UNKNOWN_MAPS_LOGGED.add(path)
            log(f"haproxy does not load {path}; writing the file only")
        return True
    m = _MAP_VERSION_RE.match(reply)
    if not m:
        log(f"haproxy map swap {path}: prepare failed: {reply!r}")
        return False
    ver = m.group(1)
    for key, value in pairs:
        reply = _haproxy_socket_cmd(f"add map @{ver} {path} {key} {value}")
        if reply is None or reply.strip():
            log(f"haproxy map swap {path}: add {key!r} failed: {reply!r}; "
                f"keeping the old map")
            # Entries of an abandoned version stay in memory until a later
            # commit purges them; drop them now.
            _haproxy_socket_cmd(f"clear map @{ver} {path}")
            return False
    reply = _haproxy_socket_cmd(f"commit map @{ver} {path}")
    if reply is None or reply.strip():
        log(f"haproxy map swap {path}: commit failed: {reply!r}; "
            f"keeping the old map")
        _haproxy_socket_cmd(f"clear map @{ver} {path}")
        return False
    return True


# Serialises whole syncs, so the last state snapshot taken is also the last one
# written and pushed. Always taken before STATE_LOCK, never while holding it.
_SYNC_LOCK = threading.Lock()
# map path -> text this process last pushed to HAProxy successfully.
_PUSHED_TEXT = {}


def _identity_value(device_id, role, name):
    """Build the cush-identity.map value for one browser device, or None.

    "<device_id>|<role>|<name_pct>". An unknown role reads as guest. Long
    names are shortened one character at a time until the encoded form fits,
    so a percent escape is never cut in half. The result must pass
    IDENTITY_VALUE_RE, the same drop-don't-escape rule the other maps use.
    """
    role = role if role in ROLES else "guest"
    name = name if isinstance(name, str) else ""
    name_pct = quote(name, safe="")
    while len(name_pct) > 120 and name:
        name = name[:-1]
        name_pct = quote(name, safe="")
    value = f"{device_id}|{role}|{name_pct}"
    if not IDENTITY_VALUE_RE.match(value):
        return None
    return value


def validate_public_path(host, path):
    """Check one public path; return (host, path) normalised, else raise
    ValueError with a message fit for the caller.

    The host must be one label under the root (HOST_RE) and not the auth host;
    whether it is gated is the caller's question. The path starts with "/", is
    not "/" itself, uses only [A-Za-z0-9._~/-], holds no "..", "//" (and so no
    "*", "?", "#" or "%"), does not start with "/__porch" (Porch's own
    /__porch/ and /__porch-assets/) and is at most PUBLIC_PATH_MAX_LEN long.
    A trailing "/" makes it a prefix; anything else is exact. The map lines
    built from it are "<host><path> <id>": no space can reach them.
    """
    if not isinstance(host, str) or not isinstance(path, str):
        raise ValueError("host and path must be strings")
    host = host.strip().lower()
    if not HOST_RE or not HOST_RE.match(host):
        raise ValueError("invalid host")
    if host == AUTH_HOST:
        raise ValueError("the auth host has no public paths")
    if not path.startswith("/"):
        raise ValueError("path must start with /")
    if path == "/":
        raise ValueError("a public path cannot be the whole site (/)")
    if len(path) > PUBLIC_PATH_MAX_LEN:
        raise ValueError(f"path is longer than {PUBLIC_PATH_MAX_LEN} characters")
    for bad in ("..", "//", "*", "?", "#", "%"):
        if bad in path:
            raise ValueError(f"path may not contain {bad!r}")
    if not PUBLIC_PATH_CHARS_RE.fullmatch(path):
        raise ValueError("path may only use letters, digits and . _ ~ / -")
    if path.lower().startswith("/__porch"):
        raise ValueError("paths under /__porch belong to Porch")
    return host, path


def public_path_is_prefix(path):
    return path.endswith("/")


def public_path_view(entry, protected):
    """The admin view of one stored entry: the record plus `kind`, `active`
    (enabled and its host still gated) and, when it is not, why."""
    host = entry.get("host") or ""
    path = entry.get("path") or ""
    enabled = entry.get("enabled") is not False
    gated = host in protected
    if not enabled:
        why_not = "switched off"
    elif not gated:
        why_not = "host not gated"
    else:
        why_not = None
    return {
        "id": entry.get("id"),
        "host": host,
        "path": path,
        "kind": "prefix" if public_path_is_prefix(path) else "exact",
        "app": entry.get("app") or "",
        "why": entry.get("why") or "",
        "created_at": epoch_from_iso(entry.get("created_at")),
        "created_by": entry.get("created_by") or "",
        "enabled": enabled,
        "active": why_not is None,
        "inactive": why_not,
    }


def public_map_pairs(entries, protected):
    """(prefix pairs, exact pairs) of (key, id) for the public maps. Only
    enabled entries on a host that is still gated, and only ones that still
    pass validate_public_path (a hand-edited devices.json gets dropped, not
    escaped, like every other map line)."""
    prefix, exact = [], []
    for e in entries:
        if not isinstance(e, dict) or e.get("enabled") is False:
            continue
        pid = e.get("id")
        if not isinstance(pid, str) or not PUBLIC_PATH_ID_RE.match(pid):
            continue
        try:
            host, path = validate_public_path(e.get("host"), e.get("path"))
        except ValueError:
            log(f"sync_haproxy_maps: skipping public path {pid}: invalid")
            continue
        if host not in protected:
            continue
        (prefix if public_path_is_prefix(path) else exact).append((host + path, pid))
    prefix.sort()
    exact.sort()
    return prefix, exact


def sync_haproxy_maps(force=False, now=None):
    """Write the device + protected-host maps and push them live to HAProxy.

    File side (authoritative across reloads):
      - DEVICES_MAP:   "<token_sha256> <device_id>" per non-revoked device that
                       has a gate token. HAProxy computes sha2(256),hex of the
                       cush_auth cookie and looks the result up here.
      - PROTECTED_MAP: "<host> 1" per protected hostname.
      - GRANTS_MAP:    per-app device scoping. Keys are "<token_sha256>:<scope>"
                       where scope is either "*" (all gated apps) or a specific
                       lowercase host. Value is the device_id. HAProxy builds the
                       key from sha2(256),hex,lower of the cush_auth cookie + the
                       requested host (and also probes the ":*" key). Only
                       non-revoked BROWSER devices appear here; tunnel devices
                       (frp) never do. A live pass adds its hosts.
      - IDENTITY_MAP:  "<token_sha256> <device_id>|<role>|<name_pct>" per
                       non-revoked BROWSER device. HAProxy looks the cookie hash
                       up here and splits the value into the X-Cush-Device /
                       X-Cush-Role / X-Cush-Device-Name request headers. The
                       name is percent-encoded so the value holds no spaces.
      - PUBLIC_MAP:    "<host><path> <id>" per enabled public prefix (path
                       ends in "/") on a host still in protected_apps; HAProxy
                       matches "<lowercased host><path>" with map_beg.
      - PUBLIC_EXACT_MAP: the same for exact public paths, matched with
                       map_str. Both are optional (unset: not written).

    A device whose `expires_at` has passed is left out of every map, whether
    or not the sweeper has dropped its row yet.

    Socket side (live, best-effort): each map is swapped in whole by
    _haproxy_swap_map, so a lookup sees the old map or the new one and never a
    half-filled one. A map whose text matches what this process last pushed is
    skipped; the first sync after start pushes everything, and so does
    force=True (SIGHUP), which repairs a live map changed behind our back. Any
    socket failure is logged — the files are the source of truth on reload.

    Returns "ok", "skipped" (maps not configured: tests, a bare import) or
    "failed: <why>", which the admin endpoints pass back as `haproxy` so a
    revoke that did not reach the edge is visible instead of silent.
    """
    if not DEVICES_MAP or not PROTECTED_MAP or not GRANTS_MAP or not IDENTITY_MAP:
        return "skipped"
    with _SYNC_LOCK:
        return _sync_haproxy_maps_locked(force, time.time() if now is None else now)


def _sync_haproxy_maps_locked(force, now):
    """Body of sync_haproxy_maps. Caller must hold _SYNC_LOCK."""
    # Best-effort create of MAPS_DIR; deploy normally pre-creates it.
    try:
        os.makedirs(MAPS_DIR, exist_ok=True)
    except PermissionError:
        pass
    except OSError as e:
        log(f"sync_haproxy_maps: makedirs {MAPS_DIR}: {e}")

    with STATE_LOCK:
        dev_lines = []
        grant_lines = []  # (key, device_id) where key = "<token_sha256>:<scope>"
        ident_lines = []  # (token_sha256, "<device_id>|<role>|<name_pct>")
        for d in STATE.get("devices", []):
            if d.get("revoked") or _device_expired(d, now):
                continue
            tsh = d.get("token_sha256")
            did = d.get("id") or ""
            if not tsh:
                continue
            # Drop anything that isn't a bare sha256 hex digest / plain device
            # id — see TOKEN_SHA_RE above.
            if not isinstance(tsh, str) or not TOKEN_SHA_RE.match(tsh):
                log(f"sync_haproxy_maps: skipping device {did!r}: bad token_sha256")
                continue
            if not isinstance(did, str) or not DEVICE_ID_RE.match(did):
                log(f"sync_haproxy_maps: skipping device with bad id {did!r}")
                continue
            dev_lines.append((tsh, did))
            # Only browser devices get per-app grants. Tunnel (frp) devices use
            # /verify, not the web gate, and must never appear in the grants map.
            if d.get("type", "tunnel") != "browser":
                continue
            tsh_l = tsh.lower()
            ident = _identity_value(did, d.get("role"), d.get("name"))
            if ident is None:
                log(f"sync_haproxy_maps: no identity line for {did!r}: bad value")
            else:
                ident_lines.append((tsh_l, ident))
            apps = device_apps(d, now)
            if apps == ["*"]:
                grant_lines.append((f"{tsh_l}:*", did))
            else:
                for h in apps:
                    if not isinstance(h, str):
                        continue
                    h = h.lower()
                    if not HOST_RE.match(h) or h == AUTH_HOST:
                        continue
                    grant_lines.append((f"{tsh_l}:{h}", did))
        # Same reasoning as the device lines: only well-formed hostnames become
        # map keys, so a bad protected_apps entry can't inject a line.
        hosts = [
            h for h in STATE.get("protected_apps", [])
            if isinstance(h, str) and HOST_RE.match(h.lower())
        ]
        pub_prefix, pub_exact = public_map_pairs(
            list(STATE.get("public_paths") or []), set(hosts))

    # Deterministic ordering so reconciles are stable across runs.
    grant_lines.sort()
    ident_lines.sort()

    dev_text = "".join(f"{tsh} {did}\n" for tsh, did in dev_lines)
    host_text = "".join(f"{h} 1\n" for h in hosts)
    grant_text = "".join(f"{k} {did}\n" for k, did in grant_lines)
    ident_text = "".join(f"{k} {v}\n" for k, v in ident_lines)
    pub_text = "".join(f"{k} {v}\n" for k, v in pub_prefix)
    pub_exact_text = "".join(f"{k} {v}\n" for k, v in pub_exact)
    public_maps = [(m, t, pairs) for m, t, pairs in (
        (PUBLIC_MAP, pub_text, pub_prefix),
        (PUBLIC_EXACT_MAP, pub_exact_text, pub_exact),
    ) if m]

    files_ok = True
    problems = []
    try:
        _atomic_write_text(DEVICES_MAP, dev_text)
        _atomic_write_text(PROTECTED_MAP, host_text)
        _atomic_write_text(GRANTS_MAP, grant_text)
        _atomic_write_text(IDENTITY_MAP, ident_text)
        for m, t, _pairs in public_maps:
            _atomic_write_text(m, t)
    except PermissionError as e:
        files_ok = False
        problems.append("map files not written (permission)")
        log(f"sync_haproxy_maps: cannot write maps (permission): {e}")
    except OSError as e:
        files_ok = False
        problems.append("map files not written")
        log(f"sync_haproxy_maps: cannot write maps: {e}")

    # Live push over the runtime API, best-effort. Grants and identity go
    # before protected, so a host that has just become protected never meets a
    # grants map that predates it. The public maps go after protected: a
    # path opens only once its host's gate is live. If the socket can't be
    # reached, stop and report it (the helper already logged once).
    pushes = [
        (GRANTS_MAP, grant_text, grant_lines),
        (IDENTITY_MAP, ident_text, ident_lines),
        (PROTECTED_MAP, host_text, [(h, "1") for h in hosts]),
        *public_maps,
        (DEVICES_MAP, dev_text, dev_lines),
    ]
    for path, text, pairs in pushes:
        # With a stale file on disk an HAProxy reload would bring old entries
        # back, so only trust the skip when the files were written.
        if files_ok and not force and _PUSHED_TEXT.get(path) == text:
            continue
        pushed = _haproxy_swap_map(path, pairs)
        if pushed is None:
            problems.append("haproxy socket unavailable")
            break
        if pushed:
            _PUSHED_TEXT[path] = text
        else:
            _PUSHED_TEXT.pop(path, None)
            problems.append(f"push of {os.path.basename(path)} failed")
    if problems:
        return "failed: " + "; ".join(problems)
    return "ok"


# --- Crypto helpers -----------------------------------------------------------------

def sha256_hex(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _js_string(value):
    """Encode a Python string as a JS string literal safe to inline in HTML.

    json.dumps handles quotes/backslashes; the extra escapes stop `</script>`
    (and HTML-entity tricks) from terminating the surrounding <script> block.
    """
    return (
        json.dumps(value)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )


def scrypt_hash(password, salt):
    """Match the spec: n=2**15, r=8, p=1, maxmem=67108864, dklen=32."""
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2 ** 15,
        r=8,
        p=1,
        maxmem=67108864,
        dklen=32,
    )


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64url_decode(s):
    s = s.encode("ascii") if isinstance(s, str) else s
    pad = b"=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def b64_std(b):
    """Standard base64 encode with padding — matches auth-admin for password_scrypt/salt."""
    return base64.b64encode(b).decode("ascii")


def b64_std_decode(s):
    """Accept either standard or urlsafe base64, with or without padding."""
    if isinstance(s, str):
        s = s.encode("ascii")
    pad = b"=" * (-len(s) % 4)
    # Try standard first, then urlsafe — both are written by tools in this repo.
    try:
        return base64.b64decode(s + pad, validate=False)
    except Exception:
        return base64.urlsafe_b64decode(s + pad)


# --- ISO8601 timestamps (matching auth-admin's format) ------------------------------

def iso_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_from_epoch(ts):
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_pairing_code():
    alpha = "".join(secrets.choice(CODE_ALPHA) for _ in range(4))
    digit = "".join(secrets.choice(CODE_DIGIT) for _ in range(4))
    return f"{alpha}-{digit}"


# --- Session cookie -----------------------------------------------------------------

def make_session_cookie(session_secret_b64):
    # Sub-second resolution: the logout epoch is compared against this, and a
    # whole-second stamp let a cookie minted in the same second as a logout
    # survive that logout.
    payload = json.dumps({"issued_at": round(time.time(), 3)}, separators=(",", ":"))
    payload_b = payload.encode("utf-8")
    key = b64url_decode(session_secret_b64)
    mac = hmac.new(key, payload_b, hashlib.sha256).digest()
    return f"{b64url(payload_b)}.{b64url(mac)}"


def verify_session_cookie(cookie, session_secret_b64, min_issued_at=0):
    """Verify HMAC + TTL + epoch freshness.

    min_issued_at enforces the admin session epoch: any cookie stamped
    BEFORE the current epoch was invalidated (typically by a logout).
    Returns True iff the cookie is authentic, unexpired, and at-or-after
    the provided epoch.
    """
    if not cookie or "." not in cookie:
        return False
    try:
        payload_b64, mac_b64 = cookie.split(".", 1)
        payload_b = b64url_decode(payload_b64)
        mac = b64url_decode(mac_b64)
    except Exception:
        return False
    key = b64url_decode(session_secret_b64)
    expected = hmac.new(key, payload_b, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        return False
    try:
        payload = json.loads(payload_b.decode("utf-8"))
        issued_at = float(payload.get("issued_at", 0))
    except Exception:
        return False
    if time.time() - issued_at > SESSION_TTL:
        return False
    # Epoch check: logout bumps admin.epoch, stamping every prior cookie dead.
    if issued_at < float(min_issued_at or 0):
        return False
    return True


# --- Invite helpers -----------------------------------------------------------------

def _invite_device_ttl(inv):
    """Seconds a device minted from this invite lives, or None for permanent.
    An unreadable value on disk reads as the shortest pass, not as permanent."""
    minutes = inv.get("device_ttl_minutes")
    if minutes is None:
        return None
    try:
        minutes = int(minutes)
    except (TypeError, ValueError):
        return 60
    return max(1, min(minutes, DEVICE_TTL_MAX_MINUTES)) * 60


def _invite_live_count(inv, now):
    """How many devices hold access from this invite right now: non-revoked,
    unexpired devices it minted, plus enrolled browsers with a live pass from
    it. Caller holds STATE_LOCK."""
    invite_id = inv.get("id")
    if not invite_id:
        return 0
    count = 0
    for d in STATE.get("devices", []):
        if d.get("revoked") or _device_expired(d, now):
            continue
        p = _live_pass(d, now)
        if d.get("invite_id") == invite_id or (
            p is not None and p.get("invite_id") == invite_id
        ):
            count += 1
    return count


def _invite_status(inv, now):
    """active | revoked | expired | used | full, in that precedence.

    An ordinary invite is used up for good once `uses` reaches `max_uses`. A
    standing invite compares the cap with the number of LIVE devices instead
    (_invite_live_count), so "full" clears as passes expire, and its
    `expires_at` may be null, meaning the link itself never expires. Null on
    any other invite still reads as expired. Caller holds STATE_LOCK.
    """
    if inv.get("revoked"):
        return "revoked"
    standing = bool(inv.get("standing"))
    exp = inv.get("expires_at")
    if not (standing and exp is None) and epoch_from_iso(exp) <= now:
        return "expired"
    try:
        cap = int(inv.get("max_uses", 1))
        if standing:
            if _invite_live_count(inv, now) >= cap:
                return "full"
        elif int(inv.get("uses", 0)) >= cap:
            return "used"
    except (TypeError, ValueError):
        return "used"
    return "active"


def _invite_ended_at(inv, now):
    """When an invite stopped working (epoch), for the 7-day keep window.

    Revoked: revocation time. Used up: the last use. Otherwise expiry, which
    is in the future for an active invite. Falls back to created_at for
    hand-edited records that lack the timestamp. Only meaningful once the
    status is not in INVITE_OPEN: an open standing invite has no expiry, and
    callers must not age it out by its created_at.
    """
    status = _invite_status(inv, now)
    if status == "revoked":
        ts = epoch_from_iso(inv.get("revoked_at"))
    elif status == "used":
        ts = epoch_from_iso(inv.get("last_used_at"))
    else:
        ts = epoch_from_iso(inv.get("expires_at"))
    return ts or epoch_from_iso(inv.get("created_at"))


def _find_invite_locked(token_sha):
    """Look an invite up by the sha256 of its plaintext token. Caller holds
    STATE_LOCK. Every record is compared with compare_digest, so the scan
    takes the same time whether or not (and wherever) it matches."""
    found = None
    for inv in STATE.get("invites", []):
        stored = inv.get("token_sha256")
        if isinstance(stored, str) and hmac.compare_digest(stored, token_sha):
            found = inv
    return found


# --- Background writer for /verify updates ------------------------------------------

def writer_worker():
    """Coalesce last_seen + run_id history updates so /verify stays O(1)."""
    while True:
        item = UPDATE_QUEUE.get()
        if item is None:
            return
        # Drain any additional pending items to batch writes.
        batch = [item]
        try:
            while True:
                batch.append(UPDATE_QUEUE.get_nowait())
        except queue.Empty:
            pass
        dirty = False
        with STATE_LOCK:
            for device_id, run_id, ts in batch:
                ts_iso = iso_from_epoch(ts)
                for d in STATE["devices"]:
                    if d["id"] == device_id:
                        d["last_seen"] = ts_iso
                        hist = d.setdefault("run_id_history", [])
                        if run_id:
                            hist.append({"run_id": run_id, "at": ts_iso})
                            if len(hist) > 20:
                                del hist[: len(hist) - 20]
                        dirty = True
                        break
            if dirty:
                try:
                    save_state_locked()
                except Exception as e:
                    log(f"writer_worker save failed: {e}")


# --- Sweeper: pairing, pass and invite expiry ---------------------------------------

SWEEP_INTERVAL = 30


def sweep_once(now=None):
    """One sweeper pass. Returns how many seconds to wait before the next.

    Expires pairings, drops expired guest devices and passes, and GCs old
    pairings and invites. `now` is injectable for tests.
    """
    now = time.time() if now is None else now
    changed = False
    resync = False
    with STATE_LOCK:
        for p in STATE["pairings"]:
            exp = epoch_from_iso(p.get("expires_at"))
            if p.get("status") == "pending" and exp < now:
                p["status"] = "expired"
                p["issued_token"] = None
                changed = True
            elif (p.get("status") == "approved" and exp < now
                    and p.get("issued_token") is not None):
                # Approved pairings still clear after expiry if never polled.
                # Only when there is something to clear: this used to mark the
                # state dirty, and rewrite devices.json, on every tick.
                p["issued_token"] = None
                changed = True
        # GC ancient pairings (>24h old) regardless of status. Approved
        # pairings handed their issued_token via PENDING_TOKENS long ago;
        # expired/rejected are dead state; pending>24h should have been
        # expired in the pass above — all safe to drop from disk.
        cutoff = now - 24 * 3600
        before = len(STATE["pairings"])
        STATE["pairings"] = [
            p for p in STATE["pairings"]
            if epoch_from_iso(p.get("created_at")) >= cutoff
        ]
        deleted = before - len(STATE["pairings"])
        if deleted > 0:
            changed = True
            print(
                f"[authserver] sweeper: deleted {deleted} ancient pairings",
                file=sys.stderr,
                flush=True,
            )
        # Expired passes. A device row goes only if it carries an expires_at
        # that has passed (_device_expired); permanent devices are never
        # touched. The maps and /auth/me already ignore an expired device, so
        # this is cleanup plus the resync that takes its lines out of HAProxy.
        invites = STATE.setdefault("invites", [])
        kept_devices = []
        dropped = []
        for d in STATE["devices"]:
            if _device_expired(d, now):
                dropped.append(d)
                continue
            if "pass" in d and _live_pass(d, now) is None:
                del d["pass"]
                changed = resync = True
            hts = d.get("host_tokens")
            if isinstance(hts, list) and hts:
                live = [e for e in hts if isinstance(e, dict)
                        and epoch_from_iso(e.get("expires_at")) > now]
                if len(live) != len(hts):
                    d["host_tokens"] = live
                    changed = True
            kept_devices.append(d)
        if dropped:
            STATE["devices"] = kept_devices
            gone = set()
            for d in dropped:
                gone.add(d.get("id"))
                TOKEN_CACHE.pop(d.get("token_sha256"), None)
            # Keep a long-lived standing invite's device list from growing
            # by one id per visitor forever.
            for inv in invites:
                ids = inv.get("device_ids")
                if isinstance(ids, list) and gone.intersection(ids):
                    inv["device_ids"] = [i for i in ids if i not in gone]
            log(f"sweeper: dropped {len(dropped)} expired guest devices")
            changed = resync = True
        # GC invites that finished (expired / used up / revoked) more than
        # INVITE_KEEP_SECS ago. Open invites are never dropped.
        kept = [
            inv for inv in invites
            if _invite_status(inv, now) in INVITE_OPEN
            or _invite_ended_at(inv, now) >= now - INVITE_KEEP_SECS
        ]
        if len(kept) != len(invites):
            log(f"sweeper: deleted {len(invites) - len(kept)} old invites")
            STATE["invites"] = kept
            changed = True
        if changed:
            try:
                save_state_locked()
            except Exception as e:
                log(f"sweeper save failed: {e}")
        # Wake for the next expiry instead of up to 30s after it, so a pass
        # stops working at HAProxy when it says it does.
        upcoming = []
        for d in STATE["devices"]:
            if d.get("revoked"):
                continue
            if d.get("expires_at"):
                upcoming.append(epoch_from_iso(d.get("expires_at")))
            p = _live_pass(d, now)
            if p is not None:
                upcoming.append(epoch_from_iso(p.get("expires_at")))
    # sync_haproxy_maps takes STATE_LOCK itself; the lock is not re-entrant.
    if resync:
        sync_haproxy_maps(now=now)
    # Fix #5: clean expired PENDING_TOKENS entries.
    with PENDING_TOKENS_LOCK:
        dead = [k for k, (_, exp) in PENDING_TOKENS.items() if exp < now]
        for k in dead:
            del PENDING_TOKENS[k]
    with HANDOFF_LOCK:
        for k in [k for k, v in HANDOFF_CODES.items() if v["expires"] < now]:
            del HANDOFF_CODES[k]
    if not upcoming:
        return SWEEP_INTERVAL
    return max(0.25, min(SWEEP_INTERVAL, min(upcoming) - now + 0.05))


def sweeper_worker():
    delay = SWEEP_INTERVAL
    while True:
        time.sleep(delay)
        try:
            delay = sweep_once()
        except Exception as e:
            # Expiry enforcement lives here; one bad record must not end it.
            log(f"sweeper failed: {e}")
            delay = SWEEP_INTERVAL


# --- HTTP handler -------------------------------------------------------------------

def json_bytes(obj):
    return json.dumps(obj).encode("utf-8")


def _create_invite_locked(note, apps, landing, max_uses, expires_hours, device_ttl,
                          standing, now):
    """Append a new invite to STATE (caller holds STATE_LOCK, saves after).
    Arguments are already validated. Returns (invite, token_plain); the
    plaintext token exists only in the return value. OverflowError when
    INVITE_MAX_RECORDS invites are already kept."""
    invites = STATE.setdefault("invites", [])
    if len(invites) >= INVITE_MAX_RECORDS:
        raise OverflowError("too many invites")
    token_plain = secrets.token_urlsafe(32)
    existing = {i.get("id") for i in invites}
    invite_id = "inv_" + secrets.token_hex(4)
    while invite_id in existing:
        invite_id = "inv_" + secrets.token_hex(4)
    invite = {
        "id": invite_id,
        "token_sha256": sha256_hex(token_plain),
        "note": note,
        "apps": apps,
        "landing": landing,
        "max_uses": max_uses,
        "uses": 0,
        "standing": standing,
        "device_ttl_minutes": device_ttl,
        "expires_at": (
            iso_from_epoch(now + expires_hours * 3600)
            if expires_hours is not None else None
        ),
        "created_at": iso_from_epoch(now),
        "revoked": False,
        "revoked_at": None,
        "last_used_at": None,
        "device_ids": [],
    }
    invites.append(invite)
    return invite, token_plain


class AuthHandler(BaseHTTPRequestHandler):

    # Socket timeout per connection: a client that stops sending (or reading)
    # frees its thread instead of holding it forever.
    timeout = REQUEST_TIMEOUT
    server_version = "cush-auth"
    sys_version = ""

    def log_message(self, format, *args):
        # Quiet GET logs (like shortenerserver). Keep POST/errors.
        msg = format % args
        if msg.startswith("\"GET "):
            return
        sys.stderr.write(f"[authserver] {self.address_string()} - {msg}\n")

    # ---- helpers -------------------------------------------------------------------

    def _emit_extra_headers(self, extra_headers):
        # Accept either a dict {k: v} or a list of (k, v) tuples. The list form
        # allows multiple headers with the same name (e.g. two Set-Cookie).
        if not extra_headers:
            return
        items = extra_headers.items() if isinstance(extra_headers, dict) else extra_headers
        for k, v in items:
            self.send_header(k, v)

    def _send_json(self, code, payload, extra_headers=None):
        body = json_bytes(payload)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self._emit_extra_headers(extra_headers)
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, code, html, extra_headers=None, referrer="same-origin"):
        """Serve one of the inline pages with the same lockdown header set as
        lib/statusserver.py. Each page's single inline <style> and <script>
        carry nonce="__NONCE__", replaced per response; inline event handlers
        and style attributes are therefore refused by the browser, and the
        pages use neither. auth.css is the only other resource ('self')."""
        nonce = secrets.token_hex(16)
        if isinstance(html, str):
            html = html.replace("__NONCE__", nonce)
            body = html.encode("utf-8")
        else:
            body = html.replace(b"__NONCE__", nonce.encode())
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", (
            "default-src 'none'; "
            f"style-src 'self' 'nonce-{nonce}'; "
            "font-src 'self'; "
            f"script-src 'nonce-{nonce}'; "
            "connect-src 'self'; "
            "img-src 'self' data:; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        ))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", referrer)
        self.send_header("Cache-Control", "no-store")
        self._emit_extra_headers(extra_headers)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location, extra_headers=None):
        """302 with no body. no-referrer: handoff URLs carry a one-time code."""
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self._emit_extra_headers(extra_headers)
        self.end_headers()

    def _request_host(self):
        """Lowercase host this request was addressed to, port stripped. If a
        proxy's X-Forwarded-Host disagrees with Host, returns "" (no match)."""
        def norm(v):
            v = (v or "").split(",")[0].strip().lower()
            if v.startswith("["):
                return v
            return v.rsplit(":", 1)[0] if ":" in v else v
        host = norm(self.headers.get("Host"))
        xfh = self.headers.get("X-Forwarded-Host")
        if xfh is not None and norm(xfh) != host:
            return ""
        return host

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except (ValueError, TypeError):
            raise ValueError("invalid Content-Length")
        if length < 0:
            raise ValueError("invalid Content-Length")
        if length == 0:
            return {}
        if length > 1024 * 1024:
            raise ValueError("body too large")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            raise ValueError("invalid JSON body")
        # Every handler does body.get(...): a list, string or number would
        # be an AttributeError and a dropped connection instead of a 400.
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object")
        return data

    def _client_ip(self):
        return client_ip_from(self.client_address[0],
                              self.headers.get_all("X-Forwarded-For") or [])

    def _origin_ok(self):
        """Reject cross-origin state-changing POSTs.

        cush_auth_session is SameSite=Strict, but every *.cush.rocks name —
        each gated app, and every user-created *.tunnel.cush.rocks host — is
        the SAME site, so Strict does not stop a cross-SUBDOMAIN forgery. And
        a text/plain body makes the forged POST a CORS "simple request", so
        there is no preflight to block it either. Requiring Origin to match
        the host being addressed closes that hole. Non-browser callers (curl,
        the bootstrap poller, frps) send no Origin and are unaffected.
        """
        origin = self.headers.get("Origin")
        if not origin:
            return True
        try:
            netloc = urlparse(origin).netloc.strip().lower()
        except ValueError:
            return False
        if not netloc:
            return False
        hosts = {
            (self.headers.get("Host") or "").strip().lower(),
            (self.headers.get("X-Forwarded-Host") or "").strip().lower(),
        }
        return netloc in (hosts - {""})

    def _session_cookie(self):
        cookie_hdr = self.headers.get("Cookie", "")
        if not cookie_hdr:
            return None
        for part in cookie_hdr.split(";"):
            k, _, v = part.strip().partition("=")
            if k == SESSION_COOKIE:
                return v
        return None

    def _cli_token_ok(self):
        """True iff this request carries the local CLI token and came straight
        from this box rather than through HAProxy or nginx.

        See CLI_TOKEN above for why the forwarded headers are a reliable
        tell. A browser always sends Origin on a POST and bin/auth-admin never
        does, so an Origin header disqualifies the request too: the CLI path
        cannot be driven from a page, and _origin_ok() keeps guarding the
        cookie path unchanged.
        """
        given = self.headers.get(CLI_TOKEN_HEADER)
        if not given or not CLI_TOKEN:
            return False
        if self.client_address[0] not in ("127.0.0.1", "::1"):
            return False
        if self.headers.get("Origin") is not None or any(
            self.headers.get(h) is not None for h in PROXY_HEADERS
        ):
            _log_once_per_sec("CLI token presented on a proxied request; ignored")
            return False
        return hmac.compare_digest(
            given.encode("utf-8"), CLI_TOKEN.encode("utf-8")
        )

    def _require_session(self):
        if self._cli_token_ok():
            return True
        with STATE_LOCK:
            admin = STATE.get("admin")
            # Snapshot epoch inside the lock so a concurrent logout that bumps
            # it can't race past this check.
            epoch = float(admin.get("epoch", 0) or 0) if admin else 0
        if not admin or not admin.get("session_secret"):
            self._send_json(401, {"error": "no admin configured"})
            return False
        cookie = self._session_cookie()
        if not cookie or not verify_session_cookie(
            cookie, admin["session_secret"], min_issued_at=epoch
        ):
            self._send_json(401, {"error": "unauthorized"})
            return False
        return True

    def _set_session_cookie(self, session_secret_b64):
        cookie = make_session_cookie(session_secret_b64)
        return {
            "Set-Cookie": (
                f"{SESSION_COOKIE}={cookie}; HttpOnly; Secure; "
                f"SameSite=Strict; Path=/; Max-Age={SESSION_TTL}"
            )
        }

    def _clear_session_cookie(self):
        return {
            "Set-Cookie": (
                f"{SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Strict; "
                f"Path=/; Max-Age=0"
            )
        }

    def _read_cookie(self, name):
        cookie_hdr = self.headers.get("Cookie", "")
        if not cookie_hdr:
            return None
        for part in cookie_hdr.split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return None

    def _gate_cookie_header(self, token_plain, max_age=GATE_TTL):
        # The cross-app device cookie HAProxy hashes and looks up in the device
        # map. Domain-wide (.cush.rocks), 90-day, HttpOnly so JS can't read it.
        # A pass device passes its remaining lifetime as max_age, so the
        # browser forgets the cookie when the server forgets the device.
        return (
            "Set-Cookie",
            f"{GATE_COOKIE}={token_plain}; Domain={COOKIE_DOMAIN}; Path=/; "
            f"Secure; HttpOnly; SameSite=Lax; Max-Age={int(max_age)}",
        )

    # ---- routing -------------------------------------------------------------------

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/auth" or path == "/auth/":
            return self._handle_admin_ui()
        if path == "/login":
            return self._handle_login_page(parsed.query)
        if path == "/auth/me":
            return self._handle_auth_me()
        if path.startswith("/auth/pair/status/"):
            token = path[len("/auth/pair/status/"):]
            return self._handle_pair_status(token)
        if path.startswith("/auth/web-pair/status/"):
            token = path[len("/auth/web-pair/status/"):]
            return self._handle_web_pair_status(token)
        if path == "/auth/admin/state":
            return self._handle_admin_state()
        if path == "/auth/admin/public-paths":
            return self._handle_admin_public_paths_list()
        if path == "/auth/admin/access-requests":
            return self._handle_admin_access_list()
        if path.startswith(ACCESS_PATH + "/"):
            return self._handle_access_status(path[len(ACCESS_PATH) + 1:], parsed.query)
        if path.startswith("/i/"):
            return self._handle_invite_page(path[len("/i/"):])
        if path == AUTH_CSS_PATH:
            return self._handle_auth_css()
        if path.startswith(AUTH_ASSET_BASE + porch_http.ASSET_PREFIX):
            # The Porch fonts auth.css names (hashed, immutable; exact-path
            # table in porch_http, so nothing here touches the filesystem).
            porch_http.serve_asset(self, base=AUTH_ASSET_BASE)
            return None
        if path == "/auth/handoff":
            return self._handle_handoff_start(parsed.query)
        if path == "/__porch/start":
            return self._handle_porch_start(parsed.query)
        if path == "/__porch/auth":
            return self._handle_handoff_redeem(parsed.query)
        if path == "/__porch/me":
            return self._handle_porch_me()
        if path == "/healthz":
            return self._send_json(200, {"ok": True})
        self._send_json(404, {"error": "not found"})

    def _handle_auth_css(self):
        """The one static file. Public (the login and invite pages need it
        before anyone is signed in) and matched by exact path, so there is no
        filename to traverse with. `no-cache` plus an ETag means a browser
        revalidates every load and picks up a deploy's new CSS at once."""
        if AUTH_CSS is None:
            return self._send_json(404, {"error": "not found"})
        if self.headers.get("If-None-Match") == AUTH_CSS_ETAG:
            self.send_response(304)
            self.send_header("ETag", AUTH_CSS_ETAG)
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/css; charset=utf-8")
        self.send_header("Content-Length", str(len(AUTH_CSS)))
        self.send_header("ETag", AUTH_CSS_ETAG)
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(AUTH_CSS)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        # CSRF guard for everything that acts on the admin session or mints a
        # device from the admin password. /verify and the pairing endpoints are
        # exempt: they carry no ambient credential, and their callers (frps,
        # bin/bootstrap) are not browsers. /i/ is here because accepting an
        # invite rides the visitor's ambient cush_auth cookie (it merges scope
        # into an enrolled browser), so it must not be forgeable cross-site.
        if (path.startswith("/auth/admin/") or path == "/auth/enroll"
                or path.startswith("/i/") or path == ACCESS_PATH):
            if not self._origin_ok():
                log(f"rejected cross-origin POST {path} origin={self.headers.get('Origin')!r}")
                return self._send_json(403, {"error": "cross-origin request rejected"})

        if path == "/verify":
            op = qs.get("op", [""])[0]
            return self._handle_verify(op)
        if path == "/auth/pair/start":
            return self._handle_pair_start()
        if path == "/auth/web-pair/start":
            return self._handle_web_pair_start()
        if path == "/auth/admin/setup":
            return self._handle_admin_setup()
        if path == "/auth/admin/login":
            return self._handle_admin_login()
        if path == "/auth/admin/logout":
            return self._handle_admin_logout()
        if path == "/auth/admin/approve":
            return self._handle_admin_approve()
        if path == "/auth/admin/reject":
            return self._handle_admin_reject()
        if path == "/auth/admin/revoke":
            return self._handle_admin_revoke()
        if path == "/auth/admin/set-password":
            return self._handle_admin_set_password()
        if path == "/auth/enroll":
            return self._handle_enroll()
        if path == "/auth/admin/enroll-self":
            return self._handle_enroll_self()
        if path == "/auth/admin/apps":
            return self._handle_admin_apps()
        if path == "/auth/admin/public-paths":
            return self._handle_admin_public_paths()
        if path == "/auth/admin/device-apps":
            return self._handle_admin_device_apps()
        if path == "/auth/admin/device-role":
            return self._handle_admin_device_role()
        if path == "/auth/admin/device-rename":
            return self._handle_admin_device_rename()
        if path == "/auth/admin/verify-password":
            return self._handle_admin_verify_password()
        if path == "/auth/admin/invites":
            return self._handle_admin_invite_create()
        if path == "/auth/admin/invite-revoke":
            return self._handle_admin_invite_revoke()
        if path == "/auth/admin/server":
            return self._handle_admin_server()
        if path == ACCESS_PATH:
            return self._handle_access_ask()
        if path == "/auth/admin/access-requests/decide":
            return self._handle_admin_access_decide()
        if path.startswith("/i/") and path.endswith("/accept"):
            return self._handle_invite_accept(path[len("/i/"):-len("/accept")])
        self._send_json(404, {"error": "not found"})

    # ---- /verify (frp webhook) -----------------------------------------------------

    def _handle_verify(self, op):
        """frps HTTP-plugin webhook. Ops (config/frps.toml.example):

        Login        device_token must be a live tunnel device (or the client
                     is on localhost).
        NewProxy     what a device may open; see _verify_new_proxy.
        NewWorkConn  every new connection a proxy serves. Re-checks the token,
        Ping         and the heartbeat: a revoked device stops carrying
                     traffic at once, and (if its frpc sends heartbeats) gets
                     its session closed. See the revoke note in the docs.

        A session with no device_token got past Login only through the
        localhost bypass (Login refuses a remote client without one), so the
        later ops let it through while LOCALHOST_BYPASS is on, and refuse it
        when it is off (a session left over from before the switch-over is
        cut at its next heartbeat).
        """
        try:
            body = self._read_json()
        except ValueError as e:
            return self._send_json(400, {"reject": True, "reject_reason": str(e)})

        body_op = body.get("op") or op
        content = body.get("content", {}) or {}
        if not isinstance(content, dict):
            return self._send_json(200, {"reject": True, "reject_reason": "bad content"})
        if body_op == "Login":
            return self._verify_login(content)
        if body_op in ("NewProxy", "NewWorkConn", "Ping"):
            user = content.get("user") or {}
            metas = (user.get("metas") if isinstance(user, dict) else None) or {}
            token = metas.get("device_token") if isinstance(metas, dict) else ""
            if not token:
                # Only a localhost-bypass Login yields a tokenless session.
                if LOCALHOST_BYPASS:
                    return self._send_json(200, {"unchange": True, "reject": False})
                _log_once_per_sec(f"verify {body_op}: session without device_token refused")
                return self._send_json(
                    200, {"reject": True, "reject_reason": "missing device_token"})
            entry = TOKEN_CACHE.get(sha256_hex(str(token)))
            if not entry or entry[1] != "tunnel":
                _log_once_per_sec(f"verify {body_op}: revoked or unknown device refused")
                return self._send_json(
                    200, {"reject": True, "reject_reason": "device revoked"}
                )
            if body_op == "NewProxy":
                return self._verify_new_proxy(entry[0], content)
            return self._send_json(200, {"unchange": True, "reject": False})
        return self._send_json(200, {"unchange": True, "reject": False})

    def _verify_new_proxy(self, device_id, content):
        """Remote tunnel devices may open http/https proxies on a plain
        *.tunnel.cush.rocks subdomain. A device with tunnel_admin=true (set
        with `bin/auth-admin role <device> admin`) may also open tcp/udp/
        stcp/xtcp/tcpmux proxies (remote ports on the box), use
        custom_domains, and take reserved subdomains."""
        with STATE_LOCK:
            dev = next((d for d in STATE["devices"] if d.get("id") == device_id), None)
            admin = bool(dev and dev.get("tunnel_admin") is True)
        ptype = str(content.get("proxy_type") or "").lower()
        name = content.get("proxy_name") or ""

        def reject(why):
            log(f"verify NewProxy: device={device_id} proxy={name!r} refused: {why}")
            return self._send_json(200, {"reject": True, "reject_reason": why})

        if admin:
            return self._send_json(200, {"unchange": True, "reject": False})
        if ptype not in OPEN_PROXY_TYPES:
            return reject(f"proxy type {ptype or '?'} needs a tunnel_admin device")
        if content.get("custom_domains"):
            return reject("custom_domains needs a tunnel_admin device")
        # Routing knobs that would let a proxy share or hijack a vhost route
        # (path locations, per-user routing, load-balancing groups) or forge
        # the Host the backend sees: admin only.
        for key in ("locations", "http_user", "route_by_http_user", "group",
                    "host_header_rewrite"):
            if content.get(key):
                return reject(f"{key} needs a tunnel_admin device")
        hdrs = content.get("headers")
        if hdrs:
            if not isinstance(hdrs, dict) or any(
                    str(k).strip().lower() == "host" for k in hdrs):
                return reject("a Host header rewrite needs a tunnel_admin device")
        sub = str(content.get("subdomain") or "").strip().lower()
        if not sub:
            return reject("a subdomain is required")
        if sub in RESERVED_SUBDOMAINS or any(
            sub.startswith(p) for p in RESERVED_SUBDOMAIN_PREFIXES
        ):
            return reject(f"subdomain {sub!r} is reserved")
        if sub in owner_tunnel_names():
            return reject(f"subdomain {sub!r} is reserved for the owner's tunnels")
        return self._send_json(200, {"unchange": True, "reject": False})

    def _verify_login(self, content):
        client_address = content.get("client_address", "") or ""
        run_id = content.get("run_id", "") or ""
        metas = content.get("metas", {}) or {}
        device_token = (metas.get("device_token", "") if isinstance(metas, dict) else "") or ""

        is_local = (client_address.startswith("127.0.0.1:")
                    or client_address.startswith("[::1]:"))

        def bypass(why):
            # Adopted installs only (LOCALHOST_BYPASS). The log line is how the
            # owner checks every home frpc carries the home token before
            # switching the bypass off: "localhost bypass" must stop appearing.
            log(f"verify: localhost bypass ({why}) client={client_address} run_id={run_id}")
            return self._send_json(200, {"unchange": True, "reject": False})

        if not device_token:
            if is_local and LOCALHOST_BYPASS:
                return bypass("no device_token")
            log(f"verify: missing device_token client={client_address}")
            return self._send_json(200, {"reject": True, "reject_reason": "missing device_token"})

        token_hash = sha256_hex(str(device_token))
        entry = TOKEN_CACHE.get(token_hash)
        if not entry:
            if is_local and LOCALHOST_BYPASS:
                return bypass("unknown or revoked token")
            log(f"verify: unknown or revoked token client={client_address}")
            return self._send_json(
                200,
                {"reject": True, "reject_reason": "unknown or revoked device token"},
            )
        device_id, dev_type = entry
        # Browser devices are web-gate identities only. Without this check a
        # guest could read their own cush_auth cookie and replay it as an frpc
        # metas.device_token, turning app-scoped web access into full tunnel
        # access (the grants map already excludes tunnel devices, so the reverse
        # was never possible).
        if dev_type != "tunnel":
            log(f"verify: non-tunnel device {device_id} rejected client={client_address}")
            return self._send_json(
                200,
                {"reject": True, "reject_reason": "device is not a tunnel device"},
            )

        # Update last_seen / run_id history asynchronously. Never block /verify
        # on queue pressure — drop writes with a throttled warning instead.
        try:
            UPDATE_QUEUE.put_nowait((device_id, run_id, time.time()))
        except queue.Full:
            _log_once_per_sec("queue full; dropping verify update")
        log(f"verify: ok device={device_id} client={client_address} run_id={run_id}")
        return self._send_json(200, {"unchange": True, "reject": False})

    # ---- /auth/pair/start ----------------------------------------------------------

    def _handle_pair_start(self):
        ip = self._client_ip()
        # 10 requests/minute/IP — keeps an attacker from ballooning pairings state.
        if not _rate_limit_check(
            PAIR_START_ATTEMPTS, PAIR_START_ATTEMPTS_LOCK, ip, 60, 10
        ):
            return self._send_json(
                429,
                {"error": "too many requests"},
                extra_headers={"Retry-After": "60"},
            )
        try:
            body = self._read_json()
        except ValueError as e:
            return self._send_json(400, {"error": str(e)})
        device_name = (body.get("device_name") or "").strip()
        if not device_name:
            return self._send_json(400, {"error": "device_name required"})
        if len(device_name) > 64:
            return self._send_json(400, {"error": "device_name too long"})

        now = time.time()
        # Avoid collisions with any currently-active pairing code, and enforce
        # a global cap on currently-pending pairings.
        with STATE_LOCK:
            pending = [
                p for p in STATE["pairings"]
                if p.get("status") == "pending"
                and epoch_from_iso(p.get("expires_at")) > now
            ]
            if len(pending) >= MAX_PENDING_PAIRINGS:
                return self._send_json(
                    503,
                    {"error": "too many pending pairings; try again later"},
                )
            active_codes = {p["code"] for p in pending}
        for _ in range(16):
            code = new_pairing_code()
            if code not in active_codes:
                break
        poll_token = b64url(secrets.token_bytes(24))
        expires_at = now + PAIRING_TTL

        pairing = {
            "code": code,
            "poll_token": poll_token,
            "device_name": device_name,
            "status": "pending",
            "kind": "tunnel",
            "issued_token": None,
            "created_at": iso_from_epoch(now),
            "expires_at": iso_from_epoch(expires_at),
        }
        with STATE_LOCK:
            STATE["pairings"].append(pairing)
            save_state_locked()

        log(f"pair/start name={device_name} code={code}")
        return self._send_json(
            200,
            {"code": code, "poll_token": poll_token, "expires_at": expires_at},
        )

    # ---- /auth/pair/status/<poll_token> --------------------------------------------

    def _handle_pair_status(self, poll_token):
        if not poll_token:
            return self._send_json(404, {"error": "not found"})

        deadline = time.time() + POLL_TIMEOUT
        while True:
            with STATE_LOCK:
                pairing = next(
                    (
                        p for p in STATE["pairings"]
                        if poll_token_match(p.get("poll_token"), poll_token)
                    ),
                    None,
                )
                if pairing is None:
                    return self._send_json(404, {"error": "not found"})

                status = pairing.get("status", "pending")

                # Expire inline if the sweeper hasn't gotten to it yet.
                if status == "pending" and epoch_from_iso(pairing.get("expires_at")) < time.time():
                    pairing["status"] = "expired"
                    pairing["issued_token"] = None
                    save_state_locked()
                    status = "expired"

                if status == "approved":
                    # Fix #5: pull the plaintext token from in-memory PENDING_TOKENS.
                    # If it's missing (server restarted, sweeper expired it), the
                    # token is unreachable — treat the pairing as expired.
                    server = STATE.get("server", {})
                    server_addr = os.environ.get(
                        "CUSH_SERVER_ADDR", server.get("addr", DEFAULT_SERVER["addr"])
                    )
                    server_port = int(server.get("port", DEFAULT_SERVER["port"]))
                    with PENDING_TOKENS_LOCK:
                        entry = PENDING_TOKENS.pop(poll_token, None)
                    if entry is None or entry[1] < time.time():
                        return self._send_json(200, {"status": "expired"})
                    token = entry[0]
                    return self._send_json(
                        200,
                        {
                            "status": "approved",
                            "token": token,
                            "server_addr": server_addr,
                            "server_port": server_port,
                            # bin/bootstrap writes config/porch.toml from it.
                            "domain": {
                                "root": DOMAIN_ROOT,
                                "tunnel_base": TUNNEL_BASE,
                                "auth_host": AUTH_HOST,
                                "panel_host": DOMAIN_CFG.panel_host,
                                "landing_host": DOMAIN_CFG.landing_host,
                                "cookie_domain": COOKIE_DOMAIN,
                            },
                        },
                    )
                if status == "rejected":
                    return self._send_json(200, {"status": "rejected"})
                if status == "expired":
                    return self._send_json(200, {"status": "expired"})

            if time.time() >= deadline:
                return self._send_json(200, {"status": "pending"})
            time.sleep(POLL_INTERVAL)

    # ---- /auth/web-pair/start ------------------------------------------------------

    def _handle_web_pair_start(self):
        """Self-service browser pairing: a buddy requests web access to apps
        without the admin password. Mints a `kind:"web"` pairing (no device yet);
        the owner approves + scopes it in the admin panel, which mints a browser
        device. Shares the same code/poll-token/expiry machinery as the frp flow.
        """
        ip = self._client_ip()
        # Reuse the frp pair/start limiter — same anti-flood budget applies.
        if not _rate_limit_check(
            PAIR_START_ATTEMPTS, PAIR_START_ATTEMPTS_LOCK, ip, 60, 10
        ):
            return self._send_json(
                429,
                {"error": "too many requests"},
                extra_headers={"Retry-After": "60"},
            )
        try:
            body = self._read_json()
        except ValueError as e:
            return self._send_json(400, {"error": str(e)})
        device_name = (body.get("device_name") or "").strip() or "Browser"
        if len(device_name) > 64:
            device_name = device_name[:64]
        # Where to send the buddy after approval; validated/clamped to a
        # *.cush.rocks target. Defaults to the grab landing page.
        rd = self._sanitize_rd((body.get("rd") or "").strip())

        now = time.time()
        with STATE_LOCK:
            pending = [
                p for p in STATE["pairings"]
                if p.get("status") == "pending"
                and epoch_from_iso(p.get("expires_at")) > now
            ]
            if len(pending) >= MAX_PENDING_PAIRINGS:
                return self._send_json(
                    503,
                    {"error": "too many pending pairings; try again later"},
                )
            active_codes = {p["code"] for p in pending}
        for _ in range(16):
            code = new_pairing_code()
            if code not in active_codes:
                break
        poll_token = b64url(secrets.token_bytes(24))
        expires_at = now + PAIRING_TTL

        pairing = {
            "code": code,
            "poll_token": poll_token,
            "device_name": device_name,
            "status": "pending",
            "kind": "web",
            "rd": rd,
            "issued_token": None,
            "created_at": iso_from_epoch(now),
            "expires_at": iso_from_epoch(expires_at),
        }
        with STATE_LOCK:
            STATE["pairings"].append(pairing)
            save_state_locked()

        log(f"web-pair/start name={device_name} code={code}")
        return self._send_json(
            200,
            {"code": code, "poll_token": poll_token, "expires_at": expires_at},
        )

    # ---- /auth/web-pair/status/<poll_token> ----------------------------------------

    def _handle_web_pair_status(self, poll_token):
        """Buddy's browser polls here. On approval, THIS response sets the
        cross-app cush_auth cookie (one-time plaintext delivery from
        PENDING_TOKENS) and returns the pairing's sanitized rd so the page can
        redirect. The cookie is only ever issued for an APPROVED web pairing —
        approval is the session-gated admin action, so a buddy cannot
        self-approve. Non-blocking-friendly: returns immediately (no long-poll).
        """
        if not poll_token:
            return self._send_json(404, {"error": "not found"})

        with STATE_LOCK:
            pairing = next(
                (
                    p for p in STATE["pairings"]
                    if poll_token_match(p.get("poll_token"), poll_token)
                ),
                None,
            )
            if pairing is None:
                return self._send_json(404, {"error": "not found"})
            if pairing.get("kind") != "web":
                # Wrong flow for this endpoint; don't leak frp tokens here.
                return self._send_json(404, {"error": "not found"})

            status = pairing.get("status", "pending")
            rd = self._sanitize_rd(pairing.get("rd") or "")

            # Expire inline if the sweeper hasn't gotten to it yet.
            if status == "pending" and epoch_from_iso(pairing.get("expires_at")) < time.time():
                pairing["status"] = "expired"
                pairing["issued_token"] = None
                save_state_locked()
                status = "expired"

        if status == "pending":
            return self._send_json(200, {"status": "pending"})
        if status == "rejected":
            return self._send_json(200, {"status": "rejected"})
        if status == "expired":
            return self._send_json(200, {"status": "expired"})
        if status == "approved":
            with PENDING_TOKENS_LOCK:
                entry = PENDING_TOKENS.pop(poll_token, None)
            # If already consumed (reload after redirect) or expired, still
            # report approved + rd so a reload doesn't error — just no cookie.
            if entry is None or entry[1] < time.time():
                return self._send_json(200, {"status": "approved", "rd": rd})
            token = entry[0]
            return self._send_json(
                200,
                {"status": "approved", "rd": rd},
                extra_headers=[self._gate_cookie_header(token)],
            )
        return self._send_json(200, {"status": status})

    # ---- /auth/ (admin UI) ---------------------------------------------------------

    def _handle_admin_ui(self):
        return self._send_html(200, _domain_html(ADMIN_HTML))

    # ---- /auth/admin/setup ---------------------------------------------------------

    def _too_many(self):
        return self._send_json(
            429, {"ok": False, "error": "too many attempts"},
            extra_headers={"Retry-After": str(AUTH_WINDOW)},
        )

    def _busy(self):
        return self._send_json(
            503, {"ok": False, "error": "server busy; try again"},
            extra_headers={"Retry-After": "5"},
        )

    def _handle_admin_setup(self):
        """First-run setup. Needs the one-time setup token minted at start
        (DATA_DIR/.admin-setup-token, also in the log), so whoever reaches
        /auth/ first cannot claim the console."""
        ip = self._client_ip()
        if not password_attempt_allowed(ip):
            return self._too_many()
        try:
            body = self._read_json()
        except ValueError as e:
            return self._send_json(400, {"error": str(e)})
        with STATE_LOCK:
            if STATE.get("admin"):
                return self._send_json(409, {"error": "admin already configured"})
        given = body.get("setup_token")
        if (not isinstance(given, str) or not SETUP_TOKEN
                or not hmac.compare_digest(given.strip().encode("utf-8"),
                                           SETUP_TOKEN.encode("utf-8"))):
            record_password_failure()
            log(f"admin setup refused ip={ip}: bad setup token")
            return self._send_json(403, {"error": "setup token required (see the server log "
                                                  "or data/.admin-setup-token)"})
        password = body.get("password") or ""
        if not isinstance(password, str) or len(password) < PASSWORD_MIN:
            return self._send_json(
                400, {"error": f"password must be at least {PASSWORD_MIN} characters"}
            )
        salt = secrets.token_bytes(16)
        try:
            digest = scrypt_limited(password, salt)
        except ScryptBusy:
            return self._busy()
        with STATE_LOCK:
            if STATE.get("admin"):
                return self._send_json(409, {"error": "admin already configured"})
            STATE["admin"] = {
                "password_scrypt": b64_std(digest),
                "salt": b64_std(salt),
                "session_secret": b64url(secrets.token_bytes(32)),
                "epoch": 0,
            }
            save_state_locked()
            cookie_headers = self._set_session_cookie(STATE["admin"]["session_secret"])
        ensure_setup_token()
        log("admin setup complete")
        return self._send_json(200, {"ok": True}, extra_headers=cookie_headers)

    # ---- /auth/admin/login ---------------------------------------------------------

    def _password_ok(self, password):
        """(ok, snapshot) for the admin password. ok is None when no admin is
        configured. Snapshots the hash under STATE_LOCK, runs scrypt outside
        it. Raises ScryptBusy. `snapshot` is the stored hash the check ran
        against; callers that then act on the admin record confirm it is
        unchanged (a concurrent password change wins)."""
        with STATE_LOCK:
            admin = STATE.get("admin")
            if not admin:
                return None, None
            snap = admin.get("password_scrypt")
            if not admin.get("salt") or not snap:
                return False, snap
            salt = b64_std_decode(admin["salt"])
            expected = b64_std_decode(snap)
        if not isinstance(password, str):
            password = ""
        actual = scrypt_limited(password, salt)
        return hmac.compare_digest(actual, expected), snap

    def _handle_admin_login(self):
        ip = self._client_ip()
        if not password_attempt_allowed(ip):
            return self._too_many()
        try:
            body = self._read_json()
        except ValueError as e:
            return self._send_json(400, {"error": str(e)})
        try:
            ok, snap = self._password_ok(body.get("password") or "")
        except ScryptBusy:
            return self._busy()
        if ok is None:
            return self._send_json(400, {"error": "no admin configured"})
        if not ok:
            record_password_failure()
            log(f"admin login failed ip={ip}")
            return self._send_json(401, {"error": "invalid password"})
        with STATE_LOCK:
            admin = STATE.get("admin")
            if not admin or admin.get("password_scrypt") != snap:
                return self._send_json(409, {"error": "password changed; try again"})
            cookie_headers = self._set_session_cookie(admin["session_secret"])

        log(f"admin login ok ip={ip}")
        return self._send_json(200, {"ok": True}, extra_headers=cookie_headers)

    # ---- /auth/admin/logout --------------------------------------------------------

    def _handle_admin_logout(self):
        # Bumping admin.epoch invalidates ALL outstanding cookies server-side,
        # not just the one this browser is returning. For a single-admin tool
        # this is the right semantics: logging out means "end every session."
        with STATE_LOCK:
            admin = STATE.get("admin")
            if admin:
                # Stamp the epoch with wall-clock seconds, NOT a counter: cookies
                # carry a unix-timestamp issued_at, and verify_session_cookie
                # rejects issued_at < epoch. A counter (1, 2, 3...) is always far
                # below any timestamp, so incrementing it invalidated nothing and
                # logout was a no-op server-side.
                admin["epoch"] = round(time.time(), 3)
                try:
                    save_state_locked()
                except Exception as e:
                    log(f"logout save failed: {e}")
        return self._send_json(200, {"ok": True}, extra_headers=self._clear_session_cookie())

    # ---- /auth/admin/state ---------------------------------------------------------

    def _handle_admin_state(self):
        # Allow reading setup status even without a session so the UI can branch.
        with STATE_LOCK:
            admin_set = bool(STATE.get("admin"))
        if not admin_set:
            return self._send_json(200, {"needs_setup": True})

        if not self._require_session():
            return  # _require_session already responded

        with STATE_LOCK:
            pairings = [
                {
                    "code": p["code"],
                    "device_name": p.get("device_name", ""),
                    "kind": p.get("kind", "tunnel"),
                    "expires_at": epoch_from_iso(p.get("expires_at")),
                    "created_at": epoch_from_iso(p.get("created_at")),
                }
                for p in STATE["pairings"]
                if p.get("status") == "pending"
                and epoch_from_iso(p.get("expires_at")) > time.time()
            ]
            now = time.time()
            devices = []
            for d in STATE["devices"]:
                # Already dead at the gate; the sweeper drops the row shortly.
                if _device_expired(d, now):
                    continue
                hist = d.get("run_id_history", [])[-5:]
                is_browser = d.get("type") == "browser"
                live_pass = _live_pass(d, now) if is_browser else None
                devices.append(
                    {
                        "id": d["id"],
                        "name": d.get("name", ""),
                        "type": d.get("type", "tunnel"),
                        # The PERMANENT scope only: the panel's scope editor
                        # posts this list back to device-apps, and pass apps
                        # must never be saved into it.
                        "apps": device_perm_apps(d) if is_browser else None,
                        "pass": {
                            "apps": [
                                h for h in (live_pass.get("apps") or [])
                                if isinstance(h, str)
                            ],
                            "expires_at": epoch_from_iso(live_pass.get("expires_at")),
                            "invite_id": live_pass.get("invite_id"),
                        } if live_pass is not None else None,
                        "role": d.get("role") if is_browser else None,
                        "tunnel_admin": (d.get("tunnel_admin") is True)
                        if not is_browser else None,
                        "revoked": bool(d.get("revoked")),
                        "created_at": epoch_from_iso(d.get("created_at")),
                        "expires_at": epoch_from_iso(d.get("expires_at")) or None,
                        "invite_id": d.get("invite_id"),
                        "last_seen": epoch_from_iso(d.get("last_seen")) or None,
                        "run_id_history": hist,
                    }
                )
            protected = list(STATE.get("protected_apps", []))
            protected_set = set(protected)
            # Union of the static known-host hints and anything already
            # protected, so custom hosts still surface a toggle.
            host_names = list(KNOWN_HOSTS)
            for h in STATE.get("app_hosts", []) + protected:
                if h not in host_names:
                    host_names.append(h)
            known_hosts = [
                {"host": h, "protected": h in protected_set}
                for h in host_names
            ]
            # Invites: open ones plus anything that finished in the last
            # INVITE_KEEP_SECS. token_sha256 never leaves the server.
            names = {d["id"]: d.get("name", "") for d in STATE["devices"]}
            invites = []
            for inv in STATE.get("invites", []):
                status = _invite_status(inv, now)
                if (status not in INVITE_OPEN
                        and _invite_ended_at(inv, now) < now - INVITE_KEEP_SECS):
                    continue
                invites.append(
                    {
                        "id": inv.get("id"),
                        "note": inv.get("note", ""),
                        "apps": inv.get("apps") or [],
                        "landing": inv.get("landing"),
                        # `uses` is lifetime accepts. For a standing invite
                        # max_uses caps `live`, not `uses`.
                        "uses": inv.get("uses", 0),
                        "max_uses": inv.get("max_uses", 1),
                        "live": _invite_live_count(inv, now),
                        "standing": bool(inv.get("standing")),
                        "device_ttl_minutes": inv.get("device_ttl_minutes"),
                        "status": status,
                        # null: a standing invite that never expires.
                        "expires_at": epoch_from_iso(inv.get("expires_at")) or None,
                        "created_at": epoch_from_iso(inv.get("created_at")),
                        "devices": [
                            {"id": did, "name": names[did]}
                            for did in inv.get("device_ids", [])
                            if did in names
                        ],
                    }
                )
            invites.sort(key=lambda i: i["created_at"], reverse=True)
            public_paths = [
                public_path_view(e, protected_set)
                for e in STATE.get("public_paths") or [] if isinstance(e, dict)
            ]
        return self._send_json(
            200,
            {
                "needs_setup": False,
                "pairings": pairings,
                "devices": devices,
                "protected_apps": protected,
                "known_hosts": known_hosts,
                "invites": invites,
                "public_paths": public_paths,
                "access_requests": ACCESS.recent(),
            },
        )

    # ---- /auth/admin/approve -------------------------------------------------------

    def _handle_admin_approve(self):
        if not self._require_session():
            return
        try:
            body = self._read_json()
        except ValueError as e:
            return self._send_json(400, {"error": str(e)})
        code = (body.get("code") or "").strip().upper()
        if not code:
            return self._send_json(400, {"error": "code required"})
        # Scope for a web pairing's browser device. Required, never defaulted:
        # an approve that forgot to say which apps must not hand out ["*"].
        # Validated up front so a bad scope fails before we mint anything.
        # Tunnel pairings ignore it (the grants map excludes tunnel devices).
        apps = None
        if "apps" in body:
            try:
                apps = normalize_apps(body.get("apps"))
            except ValueError as e:
                return self._send_json(400, {"error": str(e)})

        token_plain = secrets.token_urlsafe(32)
        token_hash = sha256_hex(token_plain)
        device_id = "dev_" + secrets.token_hex(4)
        now = time.time()

        with STATE_LOCK:
            pairing = next(
                (p for p in STATE["pairings"] if p["code"] == code),
                None,
            )
            if pairing is None:
                return self._send_json(404, {"error": "code not found"})
            if pairing.get("status") != "pending":
                return self._send_json(
                    409,
                    {"error": f"pairing is {pairing.get('status')}"},
                )
            if epoch_from_iso(pairing.get("expires_at")) < now:
                pairing["status"] = "expired"
                pairing["issued_token"] = None
                save_state_locked()
                return self._send_json(410, {"error": "pairing expired"})

            if pairing.get("kind") == "web" and apps is None:
                return self._send_json(
                    400, {"error": "a web pairing needs an explicit apps scope "
                                   "(['*'] or a list of hosts)"}
                )
            # Web pairings (self-service buddy access) mint a BROWSER device so
            # the token lands in cush-grants.map and the cush_auth cookie works
            # at the HAProxy web gate. Tunnel (frp) pairings keep minting tunnel
            # devices, which use /verify and never appear in the grants map.
            dev_type = "browser" if pairing.get("kind") == "web" else "tunnel"
            device = {
                "id": device_id,
                "name": pairing.get("device_name", ""),
                "type": dev_type,
                # `apps` is a WEB-gate scope and must stay null on tunnel (frp)
                # devices. Downstream servers read devices.json directly and
                # treat apps == ["*"] as "owner"; stamping that onto a tunnel
                # device would let an frpc device_token double as an owner
                # cush_auth cookie in those apps.
                "apps": apps if dev_type == "browser" else None,
                "token_sha256": token_hash,
                "created_at": iso_from_epoch(now),
                "last_seen": None,
                "revoked": False,
                "run_id_history": [],
            }
            # A buddy approved from the pairing queue is a guest, even with
            # ["*"]; tunnel devices carry no role.
            if dev_type == "browser":
                device["role"] = "guest"
            STATE["devices"].append(device)
            TOKEN_CACHE[token_hash] = (device_id, dev_type)

            pairing["status"] = "approved"
            # Fix #5: never persist the plaintext token to disk. The long-poll
            # will read it from the in-memory PENDING_TOKENS table.
            pairing["issued_token"] = None
            poll_token = pairing.get("poll_token")
            token_expires_at = epoch_from_iso(pairing.get("expires_at")) or (now + PAIRING_TTL)
            save_state_locked()

        if poll_token:
            with PENDING_TOKENS_LOCK:
                PENDING_TOKENS[poll_token] = (token_plain, token_expires_at)

        hap = sync_haproxy_maps()
        log(f"admin approve code={code} device={device_id} haproxy={hap}")
        return self._send_json(200, {"ok": True, "device_id": device_id,
                                     "type": dev_type, "haproxy": hap})

    # ---- /auth/admin/reject --------------------------------------------------------

    def _handle_admin_reject(self):
        if not self._require_session():
            return
        try:
            body = self._read_json()
        except ValueError as e:
            return self._send_json(400, {"error": str(e)})
        code = (body.get("code") or "").strip().upper()
        if not code:
            return self._send_json(400, {"error": "code required"})

        with STATE_LOCK:
            pairing = next(
                (p for p in STATE["pairings"] if p["code"] == code),
                None,
            )
            if pairing is None:
                return self._send_json(404, {"error": "code not found"})
            pairing["status"] = "rejected"
            pairing["issued_token"] = None
            save_state_locked()

        log(f"admin reject code={code}")
        return self._send_json(200, {"ok": True})

    # ---- /auth/admin/revoke --------------------------------------------------------

    def _handle_admin_revoke(self):
        if not self._require_session():
            return
        try:
            body = self._read_json()
        except ValueError as e:
            return self._send_json(400, {"error": str(e)})
        device_id = (body.get("device_id") or "").strip()
        if not device_id:
            return self._send_json(400, {"error": "device_id required"})

        with STATE_LOCK:
            device = next(
                (d for d in STATE["devices"] if d["id"] == device_id),
                None,
            )
            if device is None:
                return self._send_json(404, {"error": "device not found"})
            device["revoked"] = True
            device["revoked_at"] = iso_now()
            # Every per-host porch_host token dies with the device (apps check
            # `revoked` anyway; clearing the list is belt and braces).
            device["host_tokens"] = []
            dev_type = device.get("type", "tunnel")
            # Drop from hot cache: /verify Login, NewProxy, NewWorkConn and
            # Ping all refuse the token from here on.
            tsh = device.get("token_sha256")
            if tsh and tsh in TOKEN_CACHE:
                del TOKEN_CACHE[tsh]
            save_state_locked()

        hap = sync_haproxy_maps()
        log(f"admin revoke device={device_id} haproxy={hap}")
        reply = {"ok": True, "device_id": device_id, "haproxy": hap}
        if dev_type == "tunnel":
            # frps has no API to drop a live client session. What a revoke
            # does to a connected frpc: new proxies and new work connections
            # (i.e. every new visitor connection) are refused right away, and
            # its next heartbeat Ping, if its frpc sends them, ends the session.
            reply["tunnel"] = ("new proxies and connections refused; an open "
                               "session ends at its next heartbeat, or on frps restart")
        return self._send_json(200, reply)

    # ---- /auth/admin/set-password --------------------------------------------------

    def _handle_admin_set_password(self):
        """Body {current, new}. The local CLI (CLI token) may leave `current`
        out, and may set the first password when no admin exists: it already
        holds the data directory. Hashing happens outside STATE_LOCK; the
        record is only replaced if nobody changed it meanwhile."""
        cli = self._cli_token_ok()
        if not cli and not self._require_session():
            return
        ip = self._client_ip()
        if not cli and not password_attempt_allowed(ip):
            return self._too_many()
        try:
            body = self._read_json()
        except ValueError as e:
            return self._send_json(400, {"error": str(e)})
        new_pw = body.get("new") or ""
        if not isinstance(new_pw, str) or len(new_pw) < PASSWORD_MIN:
            return self._send_json(
                400, {"error": f"new password must be at least {PASSWORD_MIN} characters"}
            )
        with STATE_LOCK:
            admin = STATE.get("admin")
            snap = admin.get("password_scrypt") if admin else None
        if admin is None and not cli:
            return self._send_json(400, {"error": "no admin configured"})
        try:
            if not cli:
                ok, snap = self._password_ok(body.get("current") or "")
                if not ok:
                    record_password_failure()
                    return self._send_json(401, {"error": "current password incorrect"})
            new_salt = secrets.token_bytes(16)
            new_hash = scrypt_limited(new_pw, new_salt)
        except ScryptBusy:
            return self._busy()

        with STATE_LOCK:
            admin = STATE.get("admin")
            if (admin.get("password_scrypt") if admin else None) != snap:
                return self._send_json(409, {"error": "password changed meanwhile; try again"})
            if admin is None:
                admin = STATE["admin"] = {}
            admin["salt"] = b64_std(new_salt)
            admin["password_scrypt"] = b64_std(new_hash)
            # Rotate session_secret too: a password change invalidates every
            # existing session (the usual motivation is a suspected session
            # compromise). Epoch is bumped as well, wall-clock stamped (see
            # _handle_admin_logout), so the two mechanisms stay in sync.
            admin["session_secret"] = b64url(secrets.token_bytes(32))
            admin["epoch"] = round(time.time(), 3)
            save_state_locked()
            # Mint a fresh cookie for THIS browser so it isn't booted from the
            # UI right after changing its own password. Not for the CLI.
            cookie_headers = None if cli else self._set_session_cookie(admin["session_secret"])
        ensure_setup_token()
        log(f"admin password changed{' (cli)' if cli else ''}; session_secret rotated")
        return self._send_json(200, {"ok": True}, extra_headers=cookie_headers)

    # ---- /auth/admin/server (session-gated) ----------------------------------------

    def _handle_admin_server(self):
        """Set the frps address/port handed to pairing clients. Body {addr, port?}."""
        if not self._require_session():
            return
        try:
            body = self._read_json()
        except ValueError as e:
            return self._send_json(400, {"error": str(e)})
        addr = body.get("addr")
        if not isinstance(addr, str) or not re.match(r"^[A-Za-z0-9.:-]{1,253}$", addr.strip()):
            return self._send_json(400, {"error": "invalid addr"})
        with STATE_LOCK:
            port = body.get("port", STATE.get("server", {}).get("port", 7000))
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                return self._send_json(400, {"error": "port must be 1-65535"})
            STATE["server"] = {"addr": addr.strip(), "port": port}
            save_state_locked()
        log(f"admin server -> {addr.strip()}:{port}")
        return self._send_json(200, {"ok": True, "server": {"addr": addr.strip(), "port": port}})

    # ---- gate: helpers -------------------------------------------------------------

    def _sanitize_rd(self, rd):
        if rd and RD_RE.match(rd):
            return rd
        return DEFAULT_RD

    def _verify_admin_password(self, password):
        """True/False for the admin password, None if no admin is configured.
        Raises ScryptBusy. Caller must NOT hold STATE_LOCK."""
        return self._password_ok(password)[0]

    def _mint_browser_device_locked(self, device_name, apps=None, role="guest",
                                    expires_at=None):
        """Create a browser device in STATE; caller holds STATE_LOCK.

        Returns (device, token_plain). Does NOT save or sync maps — the caller
        does both (saving under the lock, syncing after releasing it, since
        sync_haproxy_maps takes STATE_LOCK itself and the lock is not
        re-entrant). `apps` is an already-validated scope, default ['*'].
        `expires_at` (epoch) makes it a pass device that stops working then;
        the key is left off permanent devices altogether.
        """
        token_plain = secrets.token_urlsafe(32)
        token_hash = sha256_hex(token_plain)
        existing = {d.get("id") for d in STATE["devices"]}
        device_id = "dev_" + secrets.token_hex(4)
        while device_id in existing:
            device_id = "dev_" + secrets.token_hex(4)
        now = time.time()
        device = {
            "id": device_id,
            "name": (device_name or "Browser").strip()[:64] or "Browser",
            "type": "browser",
            "apps": apps if apps else ["*"],
            "role": role if role in ROLES else "guest",
            "token_sha256": token_hash,
            "created_at": iso_from_epoch(now),
            "last_seen": None,
            "revoked": False,
            "run_id_history": [],
        }
        if expires_at is not None:
            device["expires_at"] = iso_from_epoch(expires_at)
        STATE["devices"].append(device)
        TOKEN_CACHE[token_hash] = (device_id, "browser")
        return device, token_plain

    def _mint_browser_device(self, device_name, apps=None, role="guest"):
        """Create + persist a browser device, return (device_id, token_plain).
        Updates TOKEN_CACHE and syncs HAProxy maps. `apps` is the device scope
        (already-validated ['*'] or list of hosts); defaults to ['*']."""
        with STATE_LOCK:
            device, token_plain = self._mint_browser_device_locked(
                device_name, apps, role
            )
            save_state_locked()
        sync_haproxy_maps()
        return device["id"], token_plain

    # ---- /login (gate enroll page) -------------------------------------------------

    def _handle_login_page(self, query):
        """GET /login?rd=<url>: where HAProxy sends a browser without a grant
        for a gated app. With a valid rd on a gated host, the visitor gets the
        gate page for what their cush_auth cookie says (private / not on your
        pass / pass ran out / on the list after all), with Ask for access.
        ?owner=1, no rd, an rd on the auth host (the porch_host handoff) or on
        a host that is not gated: the admin-password enroll page, as before."""
        qs = parse_qs(query)
        raw_rd = (qs.get("rd", [""])[0] or "").strip()
        rd = self._sanitize_rd(raw_rd)
        if qs.get("owner", [""])[0] != "1" and raw_rd and rd == raw_rd:
            host = (urlparse(rd).hostname or "").lower()
            if host and host != AUTH_HOST:
                now = time.time()
                with STATE_LOCK:
                    gated = host in STATE.get("protected_apps", [])
                    state, dev = self._gate_state_locked(host, now) if gated else (None, None)
                if gated:
                    return self._send_gate(state, host, rd, dev)
        return self._send_login_page(rd)

    def _send_login_page(self, rd):
        # Embed rd as a JSON string literal with <, > and & escaped as \uXXXX.
        # Stripping quotes alone did NOT stop `</script>` from breaking out of
        # the script element; RD_RE now rejects those characters too, so this
        # is belt-and-braces against an XSS on the host that holds the admin UI.
        html = _domain_html(LOGIN_HTML).replace('"__RD__"', _js_string(rd))
        return self._send_html(200, html)

    # ---- gate pages + Ask for access (lib/gate_pages.py, lib/access_requests.py) ----

    def _gate_state_locked(self, host, now):
        """(state, device) for the gate page on `host`, from this request's
        cush_auth cookie. Caller holds STATE_LOCK. state: private (no
        cookie, or one no device has), expired (revoked, run out, or a pass
        that held this host ran out), in (it can open the host after all),
        scope (a live device without the host)."""
        token = self._read_cookie(GATE_COOKIE)
        if not token:
            return "private", None
        sha = sha256_hex(token)
        d = next((x for x in STATE["devices"]
                  if x.get("token_sha256") == sha and x.get("type") == "browser"), None)
        if d is None:
            return "private", None
        if d.get("revoked") or _device_expired(d, now):
            return "expired", d
        if self._covers(d, [host], now):
            return "in", d
        p = d.get("pass")
        if (isinstance(p, dict) and host in (p.get("apps") or [])
                and epoch_from_iso(p.get("expires_at")) <= now):
            return "expired", d
        return "scope", d

    @staticmethod
    def _askable_locked(host):
        """Can Ask for access be granted for `host`? A gated app under the
        root (a device scope or an invite can name it). Caller holds STATE_LOCK."""
        return (isinstance(host, str) and bool(HOST_RE.match(host)) and host != AUTH_HOST
                and host in STATE.get("protected_apps", []))

    def _send_gate(self, state, host, rd, dev):
        """One of the gate pages (403; 200 for `in`)."""
        with STATE_LOCK:
            can_ask = self._askable_locked(host)
        view = {
            "state": state, "host": host, "rd": rd,
            "device": ((dev or {}).get("name") or None) if state == "scope" else None,
            "owner_url": "/login?owner=1&rd=" + quote(rd, safe=""),
            "api": ACCESS_PATH, "can_ask": can_ask,
        }
        brand = getattr(DOMAIN_CFG, "brand", None) or "Porch"
        html = gate_pages.render(view, _js_string, brand)
        return self._send_html(200 if state == "in" else 403, html, extra_headers=[
            ("X-Robots-Tag", "noindex, nofollow")])

    def _handle_access_ask(self):
        """POST /auth/access-requests {host, note?, rd?} from a gate page.
        Public. 201 {id, token, poll} for anything that passes the limits,
        real or not (a host that is not gated is stored and runs out quietly),
        so the answer never tells which hosts exist."""
        if self._request_host() != AUTH_HOST:
            return self._send_json(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            n = -1
        if n < 0 or n > access_requests.BODY_MAX:
            return self._send_json(413, {"error": "body too large"})
        try:
            body = self._read_json()
        except ValueError as e:
            return self._send_json(400, {"error": str(e)})
        host, note, rd_in = body.get("host"), body.get("note", ""), body.get("rd", "")
        if not isinstance(host, str) or not host.strip() or len(host) > 253 \
                or not isinstance(note, str) or not isinstance(rd_in, str):
            return self._send_json(400, {"error": "host (and note, rd) must be strings"})
        host = host.strip().lower().rstrip(".")
        ip = self._client_ip()
        if not ACCESS_LIMIT.hit(ip):
            return self._send_json(429, {"error": "too many asks; try again later"},
                                   extra_headers={"Retry-After": "600"})
        now = time.time()
        with STATE_LOCK:
            askable = self._askable_locked(host)
            state, dev = self._gate_state_locked(host, now) if askable else ("private", None)
        kind = {"scope": "device", "expired": "expired"}.get(state, "stranger")
        real = askable and state != "in"
        device = dev if kind == "device" else None
        rd = self._handoff_rd(host, rd_in) if askable else None
        try:
            rid, token, _rec, joined = ACCESS.ask(
                host, note, ip, real, kind=kind,
                device_id=device["id"] if device else None,
                device_name=device.get("name", "") if device else None, rd=rd)
        except access_requests.Refused as e:
            return self._send_json(e.status, {"error": e.message},
                                   extra_headers={"Retry-After": "600"})
        if real and not joined:
            # The note stays in the record; it is never logged.
            log(f"access ask {rid} host={host} kind={kind} "
                f"device={device['id'] if device else '-'} ip={ip}")
        return self._send_json(201, {"id": rid, "token": token, "poll": access_requests.POLL})

    def _handle_access_status(self, rid, query):
        """GET /auth/access-requests/<id>?t=<token>: the visitor's poll.
        404 for an unknown id or a wrong token (the same answer)."""
        token = (parse_qs(query or "").get("t", [""])[0] or "")
        out = ACCESS.status(rid, token)
        if out is None:
            return self._send_json(404, {"error": "not found"})
        out["poll"] = access_requests.POLL
        return self._send_json(200, out, extra_headers={"Referrer-Policy": "no-referrer"})

    def _handle_admin_access_list(self):
        """GET /auth/admin/access-requests: pending + recently decided asks
        (never tokens or invite links)."""
        if not self._require_session():
            return
        return self._send_json(200, {"requests": ACCESS.recent()})

    def _grant_access(self, rec, device_ttl):
        """Allow one ask: a live device gets the host added to its scope;
        anyone else gets a single-use invite for exactly that host (its URL
        goes only to the visitor's poll). Raises RuntimeError to refuse."""
        host = rec["host"]
        now = time.time()
        with STATE_LOCK:
            if not self._askable_locked(host):
                raise RuntimeError(f"{host} is not a gated app any more")
            d = None
            if rec.get("kind") == "device" and rec.get("device_id"):
                d = next((x for x in STATE["devices"] if x.get("id") == rec["device_id"]
                          and x.get("type") == "browser" and not x.get("revoked")
                          and not _device_expired(x, now)), None)
            if d is not None:
                cur = device_perm_apps(d)
                if cur != ["*"] and host not in cur:
                    d["apps"] = sorted(set(cur) | {host})
                save_state_locked()
                out = {"how": "device"}
            else:
                note = rec.get("note") or ""
                inv, token_plain = _create_invite_locked(
                    ("Asked for access" + (f": {note}" if note else ""))[:80],
                    normalize_apps([host]), host, 1, access_requests.INVITE_HOURS,
                    device_ttl, False, now)
                save_state_locked()
                out = {"how": "invite", "invite_id": inv["id"],
                       "invite_url": INVITE_BASE_URL + token_plain}
        if out["how"] == "device":
            sync_haproxy_maps()
        return out

    def _handle_admin_access_decide(self):
        """POST /auth/admin/access-requests/decide {id, decision: allow|deny,
        device_ttl_minutes?}. device_ttl_minutes (a stranger's invite only)
        makes the device it mints a pass that lasts that long."""
        if not self._require_session():
            return
        try:
            body = self._read_json()
        except ValueError as e:
            return self._send_json(400, {"error": str(e)})
        rid, decision = body.get("id"), body.get("decision")
        if not access_requests.valid_id(rid):
            return self._send_json(400, {"error": "invalid id"})
        ttl = body.get("device_ttl_minutes")
        if ttl is not None and (isinstance(ttl, bool) or not isinstance(ttl, int)
                                or not 1 <= ttl <= DEVICE_TTL_MAX_MINUTES):
            return self._send_json(
                400, {"error": f"device_ttl_minutes must be 1-{DEVICE_TTL_MAX_MINUTES} or null"})
        try:
            rec = ACCESS.decide(rid, decision, grant=lambda r: self._grant_access(r, ttl))
        except ValueError as e:
            return self._send_json(400, {"error": str(e)})
        except LookupError as e:
            return self._send_json(404, {"error": str(e)})
        except RuntimeError as e:
            return self._send_json(409, {"error": str(e)})
        log(f"admin access {decision} {rid} host={rec.get('host')} how={rec.get('how') or '-'} "
            f"device={rec.get('device_id') or '-'} invite={rec.get('invite_id') or '-'}")
        return self._send_json(200, {"ok": True, "request": rec})

    # ---- /auth/me ------------------------------------------------------------------

    def _handle_auth_me(self):
        token = self._read_cookie(GATE_COOKIE)
        if not token:
            return self._send_json(200, {"authenticated": False, "device": None})
        entry = TOKEN_CACHE.get(sha256_hex(token))
        if not entry:
            return self._send_json(200, {"authenticated": False, "device": None})
        device_id = entry[0]
        # Refresh last_seen cheaply via the same async writer as /verify; the
        # writer coalesces and only persists when dirty. No per-request disk I/O.
        try:
            UPDATE_QUEUE.put_nowait((device_id, "", time.time()))
        except queue.Full:
            pass
        with STATE_LOCK:
            d = next((x for x in STATE["devices"] if x["id"] == device_id), None)
            dev = None
            # An expired pass device is signed out here at once, not when the
            # sweeper next runs.
            if d is not None and not _device_expired(d, time.time()):
                dev = {
                    "id": d["id"],
                    "name": d.get("name", ""),
                    "type": d.get("type", "tunnel"),
                    "last_seen": epoch_from_iso(d.get("last_seen")) or None,
                }
        return self._send_json(200, {"authenticated": dev is not None, "device": dev})

    # ---- /auth/enroll (no session; password-gated) ---------------------------------

    def _handle_enroll(self):
        ip = self._client_ip()
        # Same limiter as /auth/admin/login: one per-IP table + global backoff.
        if not password_attempt_allowed(ip):
            return self._too_many()
        try:
            body = self._read_json()
        except ValueError as e:
            return self._send_json(400, {"ok": False, "error": str(e)})
        password = body.get("password") or ""
        device_name = (body.get("device_name") or "").strip()
        rd = self._sanitize_rd((body.get("rd") or "").strip())
        # Optional scope override; default full access (['*']).
        apps = ["*"]
        if "apps" in body:
            try:
                apps = normalize_apps(body.get("apps"))
            except ValueError as e:
                return self._send_json(400, {"ok": False, "error": str(e)})

        try:
            ok = self._verify_admin_password(password)
        except ScryptBusy:
            return self._busy()
        if ok is None:
            return self._send_json(400, {"ok": False, "error": "no admin configured"})
        if not ok:
            record_password_failure()
            log(f"enroll failed ip={ip}")
            return self._send_json(401, {"ok": False})

        # Knowing the admin password makes this browser the owner's.
        device_id, token_plain = self._mint_browser_device(device_name, apps, "admin")
        log(f"enroll ok device={device_id} ip={ip}")
        return self._send_json(
            200, {"ok": True, "rd": rd},
            extra_headers=[self._gate_cookie_header(token_plain)],
        )

    # ---- /auth/admin/enroll-self (session-gated; no password re-entry) -------------

    def _handle_enroll_self(self):
        if not self._require_session():
            return
        try:
            body = self._read_json()
        except ValueError:
            body = {}
        device_name = (body.get("device_name") or "Browser").strip()
        # Owner enrolling their own browser defaults to full access; allow an
        # optional scope override.
        apps = ["*"]
        if "apps" in body:
            try:
                apps = normalize_apps(body.get("apps"))
            except ValueError as e:
                return self._send_json(400, {"ok": False, "error": str(e)})
        # Holding an admin session makes this browser the owner's.
        device_id, token_plain = self._mint_browser_device(device_name, apps, "admin")
        log(f"enroll-self device={device_id}")
        return self._send_json(
            200, {"ok": True, "device_id": device_id},
            extra_headers=[self._gate_cookie_header(token_plain)],
        )

    # ---- /auth/admin/apps (session-gated) ------------------------------------------

    def _handle_admin_apps(self):
        if not self._require_session():
            return
        try:
            body = self._read_json()
        except ValueError as e:
            return self._send_json(400, {"error": str(e)})
        host = (body.get("host") or "").strip().lower()
        action = (body.get("action") or "").strip()
        if not HOST_RE.match(host):
            return self._send_json(400, {"error": "invalid host"})
        if host == AUTH_HOST:
            return self._send_json(400, {"error": "cannot gate the auth host"})
        if action not in ("protect", "unprotect", "forget"):
            return self._send_json(
                400, {"error": "action must be protect|unprotect|forget"}
            )

        if action == "forget":
            # Drop a host from the remembered list so its toggle disappears.
            # Only for hosts that are neither protected nor a built-in hint;
            # app_hosts is not in any map, so there is nothing to sync.
            with STATE_LOCK:
                if host in STATE.get("protected_apps", []):
                    return self._send_json(
                        409, {"error": "host is still protected; unprotect it first"}
                    )
                if host in KNOWN_HOSTS:
                    return self._send_json(
                        409, {"error": "host is a built-in entry and cannot be forgotten"}
                    )
                hosts = STATE.get("app_hosts", [])
                if host not in hosts:
                    return self._send_json(404, {"error": "host not found"})
                STATE["app_hosts"] = sorted(set(hosts) - {host})
                save_state_locked()
            log(f"admin apps forget {host}")
            return self._send_json(200, {"ok": True})

        with STATE_LOCK:
            apps = STATE.setdefault("protected_apps", [])
            if action == "protect" and host not in apps:
                apps.append(host)
            elif action == "unprotect" and host in apps:
                apps.remove(host)
            STATE["protected_apps"] = sorted(set(apps))
            STATE["app_hosts"] = sorted(set(STATE.get("app_hosts", [])) | {host})
            updated = list(STATE["protected_apps"])
            save_state_locked()
        hap = sync_haproxy_maps()
        log(f"admin apps {action} {host} haproxy={hap}")
        return self._send_json(200, {"ok": True, "protected_apps": updated, "haproxy": hap})

    # ---- /auth/admin/public-paths (session or CLI token) ---------------------------

    def _public_paths_snapshot(self):
        """Caller holds STATE_LOCK."""
        protected = set(STATE.get("protected_apps", []))
        return [public_path_view(e, protected)
                for e in STATE.get("public_paths") or [] if isinstance(e, dict)]

    def _handle_admin_public_paths_list(self):
        if not self._require_session():
            return
        with STATE_LOCK:
            items = self._public_paths_snapshot()
        return self._send_json(200, {"public_paths": items, "max": PUBLIC_PATH_MAX})

    def _handle_admin_public_paths(self):
        """Body: {action: add, host, path, app, why[, by]} or
        {action: enable|disable|remove, id}. `by` (cli|pocket) is believed
        only from the CLI token; a session is the admin UI. Answers the entry
        (null after remove), the whole list and the map sync status."""
        if not self._require_session():
            return
        try:
            body = self._read_json()
        except ValueError as e:
            return self._send_json(400, {"error": str(e)})
        action = body.get("action")
        if action not in ("add", "enable", "disable", "remove"):
            return self._send_json(
                400, {"error": "action must be add|enable|disable|remove"})
        if self._cli_token_ok():
            by = body.get("by") if body.get("by") in ("cli", "pocket") else "cli"
        else:
            by = "admin-ui"

        if action == "add":
            try:
                host, path = validate_public_path(body.get("host"), body.get("path"))
            except ValueError as e:
                return self._send_json(400, {"error": str(e)})
            app = body.get("app")
            app = app.strip() if isinstance(app, str) else ""
            if not app or len(app) > PUBLIC_APP_MAX or not app.isprintable():
                return self._send_json(
                    400, {"error": f"app must be 1-{PUBLIC_APP_MAX} printable characters"})
            why = body.get("why", "")
            why = why.strip() if isinstance(why, str) else None
            if why is None or len(why) > PUBLIC_WHY_MAX or not why.isprintable():
                return self._send_json(
                    400, {"error": f"why must be at most {PUBLIC_WHY_MAX} printable characters"})
            with STATE_LOCK:
                if host not in STATE.get("protected_apps", []):
                    return self._send_json(
                        409, {"error": "host is not gated; public paths are only for protected apps"})
                entries = STATE.setdefault("public_paths", [])
                if any(e.get("host") == host and e.get("path") == path
                       for e in entries if isinstance(e, dict)):
                    return self._send_json(409, {"error": "that path is already listed"})
                if len(entries) >= PUBLIC_PATH_MAX:
                    return self._send_json(
                        409, {"error": f"at most {PUBLIC_PATH_MAX} public paths"})
                ids = {e.get("id") for e in entries if isinstance(e, dict)}
                pid = "pp_" + secrets.token_hex(4)
                while pid in ids:
                    pid = "pp_" + secrets.token_hex(4)
                entry = {
                    "id": pid, "host": host, "path": path, "app": app, "why": why,
                    "created_at": iso_now(), "created_by": by, "enabled": True,
                }
                entries.append(entry)
                save_state_locked()
        else:
            pid = body.get("id")
            if not isinstance(pid, str) or not PUBLIC_PATH_ID_RE.match(pid):
                return self._send_json(400, {"error": "invalid id"})
            with STATE_LOCK:
                entries = STATE.setdefault("public_paths", [])
                entry = next((e for e in entries
                              if isinstance(e, dict) and e.get("id") == pid), None)
                if entry is None:
                    return self._send_json(404, {"error": "public path not found"})
                if action == "remove":
                    entries.remove(entry)
                else:
                    entry["enabled"] = action == "enable"
                save_state_locked()
            host, path, app = entry.get("host"), entry.get("path"), entry.get("app")
        with STATE_LOCK:
            protected = set(STATE.get("protected_apps", []))
            items = self._public_paths_snapshot()
        hap = sync_haproxy_maps()
        log(f"public path {action} id={entry['id']} host={host} path={path} "
            f"app={app!r} by={by} haproxy={hap}")
        view = None if action == "remove" else public_path_view(entry, protected)
        return self._send_json(200, {"ok": True, "entry": view,
                                     "public_paths": items, "haproxy": hap})

    # ---- /auth/admin/device-apps (session-gated) -----------------------------------

    def _handle_admin_device_apps(self):
        """Edit a browser device's per-app scope after the fact.

        Body: {device_id, apps} where apps is ['*'] or a list of valid
        *.cush.rocks hosts (auth.cush.rocks rejected). 404 if the device is
        missing or is not a browser device.
        """
        if not self._require_session():
            return
        try:
            body = self._read_json()
        except ValueError as e:
            return self._send_json(400, {"error": str(e)})
        device_id = (body.get("device_id") or "").strip()
        if not device_id:
            return self._send_json(400, {"error": "device_id required"})
        try:
            apps = normalize_apps(body.get("apps"))
        except ValueError as e:
            return self._send_json(400, {"error": str(e)})

        with STATE_LOCK:
            device = next(
                (d for d in STATE["devices"] if d["id"] == device_id),
                None,
            )
            if device is None:
                return self._send_json(404, {"error": "device not found"})
            if device.get("type", "tunnel") != "browser":
                return self._send_json(404, {"error": "not a browser device"})
            device["apps"] = apps
            save_state_locked()
            updated = {
                "id": device["id"],
                "name": device.get("name", ""),
                "type": device.get("type", "browser"),
                "apps": list(apps),
                "revoked": bool(device.get("revoked")),
            }

        hap = sync_haproxy_maps()
        log(f"admin device-apps {device_id} -> {apps} haproxy={hap}")
        return self._send_json(200, {"ok": True, "device": updated, "haproxy": hap})


    # ---- /auth/admin/device-role (session-gated) -----------------------------------

    def _handle_admin_device_role(self):
        """Set a device's role. Body: {device_id, role} where role is
        admin|guest. Browser devices: `role` (independent of scope; never
        touches `apps`). Tunnel devices: the `tunnel_admin` flag."""
        if not self._require_session():
            return
        try:
            body = self._read_json()
        except ValueError as e:
            return self._send_json(400, {"error": str(e)})
        device_id = (body.get("device_id") or "").strip()
        role = body.get("role")
        if not device_id:
            return self._send_json(400, {"error": "device_id required"})
        if not isinstance(role, str) or role not in ROLES:
            return self._send_json(400, {"error": "role must be admin|guest"})

        with STATE_LOCK:
            device = next(
                (d for d in STATE["devices"] if d["id"] == device_id),
                None,
            )
            if device is None:
                return self._send_json(404, {"error": "device not found"})
            if device.get("type", "tunnel") != "browser":
                # A tunnel device's "role" is the separate tunnel_admin flag
                # (raw tcp/udp ports, custom domains, reserved subdomains; see
                # _verify_new_proxy). It is never written as `role`: other
                # servers read role=admin as "owner" and a tunnel token must
                # never double as an owner cookie.
                device["tunnel_admin"] = (role == "admin")
                device.pop("role", None)
                save_state_locked()
                log(f"admin device-role {device_id} tunnel_admin={role == 'admin'}")
                return self._send_json(200, {"ok": True, "device_id": device_id,
                                             "role": role, "tunnel_admin": role == "admin"})
            device["role"] = role
            save_state_locked()

        hap = sync_haproxy_maps()
        log(f"admin device-role {device_id} -> {role} haproxy={hap}")
        return self._send_json(200, {"ok": True, "device_id": device_id, "role": role,
                                     "haproxy": hap})

    # ---- /auth/admin/device-rename (session-gated) ---------------------------------

    def _handle_admin_device_rename(self):
        """Rename a device. Body: {device_id, name}; name is 1-64 printable
        characters after trimming. A browser device's name is part of the
        identity map, so that map is re-synced."""
        if not self._require_session():
            return
        try:
            body = self._read_json()
        except ValueError as e:
            return self._send_json(400, {"error": str(e)})
        device_id = body.get("device_id")
        name = body.get("name")
        if not isinstance(device_id, str) or not device_id.strip():
            return self._send_json(400, {"error": "device_id required"})
        device_id = device_id.strip()
        name = name.strip() if isinstance(name, str) else ""
        if not name or len(name) > 64 or not name.isprintable():
            return self._send_json(400, {"error": "name must be 1-64 printable characters"})
        with STATE_LOCK:
            device = next((d for d in STATE["devices"] if d["id"] == device_id), None)
            if device is None:
                return self._send_json(404, {"error": "device not found"})
            device["name"] = name
            browser = device.get("type", "tunnel") == "browser"
            save_state_locked()
        reply = {"ok": True, "device_id": device_id, "name": name}
        if browser:
            reply["haproxy"] = sync_haproxy_maps()
        log(f"admin device-rename {device_id}")
        return self._send_json(200, reply)

    # ---- /auth/admin/verify-password (CLI token only) ------------------------------

    def _handle_admin_verify_password(self):
        """Check the admin password for a local caller (Pocket's step-up).
        Body {password, ip}: `ip` is the end user's address, the key for the
        same per-IP budget and global slowdown the login page uses ("pocket"
        when it is not an IP literal). CLI token only, never a session; no
        cookie, no session is made. 200 {ok: true}, 401 for a wrong password."""
        if not self._cli_token_ok():
            return self._send_json(403, {"error": "CLI token required"})
        try:
            body = self._read_json()
        except ValueError as e:
            return self._send_json(400, {"error": str(e)})
        ip = body.get("ip")
        try:
            ip = str(ipaddress.ip_address(ip)) if isinstance(ip, str) else "pocket"
        except ValueError:
            ip = "pocket"
        if not password_attempt_allowed(ip):
            return self._too_many()
        password = body.get("password")
        try:
            ok, _snap = self._password_ok(password if isinstance(password, str) else "")
        except ScryptBusy:
            return self._busy()
        if ok is None:
            return self._send_json(400, {"error": "no admin configured"})
        if not ok:
            record_password_failure()
            log(f"step-up password failed ip={ip}")
            return self._send_json(401, {"error": "invalid password"})
        log(f"step-up password ok ip={ip}")
        return self._send_json(200, {"ok": True})

    # ---- /auth/admin/invites + invite-revoke (session-gated) -----------------------

    def _handle_admin_invite_create(self):
        """Create an invite link. Body: {note, apps, landing?, expires_hours,
        max_uses, device_ttl_minutes?, standing?}. The plaintext token is in
        this response and nowhere else — only its sha256 is stored, so the
        link cannot be shown again.

        device_ttl_minutes (null = permanent) is how long each device minted
        from the link lives. standing=true is a link meant to stay up: it
        needs a device TTL, max_uses becomes a cap on LIVE passes (up to
        INVITE_MAX_LIVE) and expires_hours may be null for a link that never
        expires.
        """
        if not self._require_session():
            return
        try:
            body = self._read_json()
        except ValueError as e:
            return self._send_json(400, {"error": str(e)})
        note = body.get("note") or ""
        if not isinstance(note, str):
            return self._send_json(400, {"error": "note must be a string"})
        note = note.strip()[:80]
        try:
            apps = normalize_apps(body.get("apps"))
        except ValueError as e:
            return self._send_json(400, {"error": str(e)})
        # Invites only ever mint guests, and a guest link must name its apps.
        if apps == ["*"]:
            return self._send_json(
                400, {"error": "an invite cannot grant all apps; list the hosts"}
            )
        standing = body.get("standing", False)
        if not isinstance(standing, bool):
            return self._send_json(400, {"error": "standing must be true or false"})
        device_ttl = body.get("device_ttl_minutes")
        if device_ttl is not None:
            # bool is an int in Python; `true` is not a number of minutes.
            if isinstance(device_ttl, bool) or not isinstance(device_ttl, int):
                return self._send_json(
                    400, {"error": "device_ttl_minutes must be an integer or null"}
                )
            if not 1 <= device_ttl <= DEVICE_TTL_MAX_MINUTES:
                return self._send_json(
                    400,
                    {"error": f"device_ttl_minutes must be 1-{DEVICE_TTL_MAX_MINUTES}"},
                )
        if standing and device_ttl is None:
            return self._send_json(
                400, {"error": "a standing invite needs device_ttl_minutes"}
            )
        max_cap = INVITE_MAX_LIVE if standing else INVITE_MAX_USES
        try:
            # A standing link may leave expires_hours out (or null): no expiry.
            expires_hours = body.get("expires_hours", None if standing else 24)
            if expires_hours is not None:
                expires_hours = int(expires_hours)
            max_uses = int(body.get(
                "max_uses", INVITE_STANDING_DEFAULT_LIVE if standing else 1
            ))
        except (TypeError, ValueError):
            return self._send_json(400, {"error": "expires_hours and max_uses must be integers"})
        if expires_hours is None and not standing:
            return self._send_json(400, {"error": "expires_hours is required"})
        if expires_hours is not None and not 1 <= expires_hours <= INVITE_MAX_HOURS:
            return self._send_json(400, {"error": f"expires_hours must be 1-{INVITE_MAX_HOURS}"})
        if not 1 <= max_uses <= max_cap:
            return self._send_json(400, {"error": f"max_uses must be 1-{max_cap}"})
        # Where Accept sends the guest. Must be one of the invite's apps.
        # Default: the first app.
        landing = body.get("landing") or None
        if landing is not None:
            if not isinstance(landing, str):
                return self._send_json(400, {"error": "invalid landing"})
            landing = landing.strip().lower()
            if landing not in apps:
                return self._send_json(400, {"error": "landing must be one of the apps"})
        else:
            landing = apps[0]

        now = time.time()
        with STATE_LOCK:
            try:
                invite, token_plain = _create_invite_locked(
                    note, apps, landing, max_uses, expires_hours, device_ttl, standing, now)
            except OverflowError:
                return self._send_json(409, {"error": "too many invites; revoke some first"})
            invite_id = invite["id"]
            save_state_locked()
            public = {k: v for k, v in invite.items() if k != "token_sha256"}
            public["status"] = "active"
            public["live"] = 0
            public["expires_at"] = epoch_from_iso(invite["expires_at"]) or None
            public["created_at"] = epoch_from_iso(invite["created_at"])

        log(f"admin invite create {invite_id} apps={apps} uses={max_uses} "
            f"hours={expires_hours} standing={standing} device_ttl_min={device_ttl}")
        return self._send_json(
            200, {"ok": True, "invite": public, "url": INVITE_BASE_URL + token_plain}
        )

    def _handle_admin_invite_revoke(self):
        """Revoke an invite. Body: {id, revoke_devices?}.

        The link stops working either way. With revoke_devices=true the
        devices it minted are revoked too and passes it put on already
        enrolled browsers are cleared; without it they keep working until
        they expire or are revoked one by one. Works on an invite that is
        already revoked, so its devices can still be cut off afterwards.
        """
        if not self._require_session():
            return
        try:
            body = self._read_json()
        except ValueError as e:
            return self._send_json(400, {"error": str(e)})
        invite_id = body.get("id")
        if not isinstance(invite_id, str) or not INVITE_ID_RE.match(invite_id):
            return self._send_json(400, {"error": "invalid id"})
        revoke_devices = body.get("revoke_devices", False)
        if not isinstance(revoke_devices, bool):
            return self._send_json(400, {"error": "revoke_devices must be true or false"})
        cut = 0
        with STATE_LOCK:
            inv = next(
                (i for i in STATE.get("invites", []) if i.get("id") == invite_id),
                None,
            )
            if inv is None:
                return self._send_json(404, {"error": "invite not found"})
            changed = False
            if not inv.get("revoked"):
                inv["revoked"] = True
                inv["revoked_at"] = iso_now()
                changed = True
            if revoke_devices:
                for d in STATE["devices"]:
                    # A pass rides on a device the invite did not create, so
                    # only the pass goes; the device keeps its own scope.
                    p = d.get("pass")
                    if isinstance(p, dict) and p.get("invite_id") == invite_id:
                        del d["pass"]
                        cut += 1
                    if d.get("invite_id") == invite_id and not d.get("revoked"):
                        d["revoked"] = True
                        d["host_tokens"] = []
                        TOKEN_CACHE.pop(d.get("token_sha256"), None)
                        cut += 1
            if changed or cut:
                save_state_locked()
        hap = sync_haproxy_maps() if cut else "ok"
        log(f"admin invite revoke {invite_id} revoke_devices={revoke_devices} cut={cut} haproxy={hap}")
        return self._send_json(200, {"ok": True, "devices_revoked": cut, "haproxy": hap})

    # ---- per-host handoff: /auth/handoff, /__porch/auth, /__porch/me ---------------

    @staticmethod
    def _handoff_rd(host, rd):
        """rd clamped to `host`: an absolute https URL on exactly that host,
        or a path on it. Anything else (another host, //evil, a scheme
        trick, CR/LF, quotes) becomes https://<host>/. This is the
        open-redirect guard for both legs of the handoff."""
        default = f"https://{host}/"
        if not isinstance(rd, str) or not rd or len(rd) > 2048:
            return default
        if rd.startswith("/"):
            return f"https://{host}{rd}" if RD_PATH_RE.match(rd) else default
        try:
            u = urlparse(rd)
        except ValueError:
            return default
        if u.scheme != "https" or (u.hostname or "") != host or u.port is not None:
            return default
        if u.username is not None or u.password is not None:
            return default
        rest = rd[len(f"https://{u.netloc}"):] or "/"
        if u.netloc.lower() != host or not RD_PATH_RE.match(rest):
            return default
        return f"https://{host}{rest}"

    def _handle_porch_start(self, query):
        """GET https://<host>/__porch/start?rd=<url on that host>.

        Step 0 of the handoff, on the APP host: set a fresh random state as a
        host-only __Host-porch_state cookie, then go to the auth host's
        /auth/handoff carrying the same state."""
        host = self._request_host()
        if not HANDOFF_HOST_RE.match(host or "") or host == AUTH_HOST:
            return self._send_json(400, {"error": "invalid host"})
        qs = parse_qs(query or "")
        rd = self._handoff_rd(host, qs.get("rd", [""])[0])
        state = secrets.token_urlsafe(24)
        return self._redirect(
            f"https://{AUTH_HOST}/auth/handoff?host={quote(host, safe='')}"
            f"&rd={quote(rd, safe='')}&state={state}",
            extra_headers=[("Set-Cookie",
                            f"{STATE_COOKIE}={state}; Path=/; Secure; HttpOnly; "
                            f"SameSite=Lax; Max-Age={HANDOFF_STATE_TTL}")])

    def _handle_handoff_start(self, query):
        """GET /auth/handoff?host=<app host>&rd=<url on that host>&state=<s>.

        Without a valid state the browser is first sent to
        https://<host>/__porch/start, which sets the state cookie on <host>
        and comes back here with it.

        Only on the auth host, where the domain cush_auth cookie is the
        credential. A browser without one is sent to /login, which comes back
        here. Otherwise a 60s single-use code bound to (device, host) is
        minted and the browser goes to https://<host>/__porch/auth?code=..&rd=..
        """
        if self._request_host() != AUTH_HOST:
            return self._send_json(404, {"error": "not found"})
        qs = parse_qs(query)
        host = (qs.get("host", [""])[0] or "").strip().lower()
        if not HANDOFF_HOST_RE.match(host) or host == AUTH_HOST:
            return self._send_json(400, {"error": "invalid host"})
        rd = self._handoff_rd(host, qs.get("rd", [""])[0])
        state = qs.get("state", [""])[0]
        if not HANDOFF_CODE_RE.match(state or ""):
            return self._redirect(
                f"https://{host}/__porch/start?rd={quote(rd, safe='')}")
        now = time.time()
        with STATE_LOCK:
            dev = self._gate_device_locked(now)
            allowed = dev is not None and handoff_allowed(dev, host, now)
            device_id = dev["id"] if dev is not None else None
            dev_view = {"name": dev.get("name", "")} if dev is not None else None
        if dev is None:
            back = (f"https://{AUTH_HOST}/auth/handoff?host={quote(host, safe='')}"
                    f"&rd={quote(rd, safe='')}&state={state}")
            return self._redirect("/login?rd=" + quote(back, safe=""))
        if not allowed:
            log(f"handoff refused device={device_id} host={host}: out of scope")
            return self._send_gate("scope", host, rd, dev_view)
        code = secrets.token_urlsafe(32)
        with HANDOFF_LOCK:
            if len(HANDOFF_CODES) >= HANDOFF_MAX:
                for k in [k for k, v in HANDOFF_CODES.items() if v["expires"] < now]:
                    del HANDOFF_CODES[k]
                if len(HANDOFF_CODES) >= HANDOFF_MAX:
                    return self._busy()
            HANDOFF_CODES[sha256_hex(code)] = {
                "device_id": device_id, "host": host, "rd": rd,
                "state": state, "expires": now + HANDOFF_TTL,
            }
        return self._redirect(
            f"https://{host}/__porch/auth?code={code}&rd={quote(rd, safe='')}"
        )

    def _handle_handoff_redeem(self, query):
        """GET https://<host>/__porch/auth?code=..&rd=.. (HAProxy routes
        /__porch/ on every host here). Spends the code, checks it was minted
        for THIS host and that the device is still good, records a fresh
        host token on the device and sets it as a host-only cookie."""
        host = self._request_host()
        qs = parse_qs(self.path.partition("?")[2] if query is None else query)
        code = qs.get("code", [""])[0]
        if not host or not HANDOFF_CODE_RE.match(code or ""):
            return self._send_json(400, {"error": "invalid handoff"})
        now = time.time()
        with HANDOFF_LOCK:
            rec = HANDOFF_CODES.pop(sha256_hex(code), None)   # single use
        if rec is None or rec["expires"] < now or rec["host"] != host:
            if rec is not None:
                log(f"handoff redeem refused host={host}: "
                    f"{'expired' if rec['expires'] < now else 'wrong host'}")
            return self._send_json(400, {"error": "handoff expired or invalid; reload the app"})
        # The code is only good in the browser that started the flow.
        got = self._read_cookie(STATE_COOKIE) or ""
        if not rec.get("state") or not hmac.compare_digest(
                got.encode("utf-8", "replace"), rec["state"].encode("utf-8")):
            log(f"handoff redeem refused host={host}: state cookie missing or wrong")
            return self._send_json(400, {"error": "handoff was started in another browser; reload the app"})
        token = secrets.token_urlsafe(32)
        with STATE_LOCK:
            d = next((x for x in STATE["devices"] if x.get("id") == rec["device_id"]), None)
            if (d is None or d.get("revoked") or d.get("type") != "browser"
                    or _device_expired(d, now) or not handoff_allowed(d, host, now)):
                return self._send_json(403, {"error": "device no longer allowed"})
            expires = now + HOST_TOKEN_TTL
            if d.get("expires_at"):
                expires = min(expires, epoch_from_iso(d["expires_at"]))
            hts = [e for e in (d.get("host_tokens") or [])
                   if isinstance(e, dict) and epoch_from_iso(e.get("expires_at")) > now]
            hts.append({
                "sha256": sha256_hex(token),
                "host": host,
                "created_at": iso_from_epoch(now),
                "expires_at": iso_from_epoch(expires),
            })
            d["host_tokens"] = hts[-HOST_TOKENS_PER_DEVICE:]
            save_state_locked()
            stored_exp = epoch_from_iso(d["host_tokens"][-1]["expires_at"])
        max_age = max(1, int(stored_exp - now))
        rd = self._handoff_rd(host, qs.get("rd", [""])[0] or rec["rd"])
        log(f"handoff ok device={rec['device_id']} host={host}")
        return self._redirect(rd, extra_headers=[(
            "Set-Cookie",
            f"{HOST_COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Lax; "
            f"Max-Age={max_age}",
        ), (
            "Set-Cookie",
            f"{STATE_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",
        )])

    def _handle_porch_me(self):
        """GET https://<host>/__porch/me: who the porch_host cookie is on this
        host. {authenticated, host, device: {id, name, role} | null}."""
        host = self._request_host()
        token = self._read_cookie(HOST_COOKIE)
        now = time.time()
        dev = None
        with STATE_LOCK:
            d = find_host_token_device(STATE["devices"], token, host, now) if host else None
            if d is not None:
                dev = {"id": d["id"], "name": d.get("name", ""),
                       "role": d.get("role") if d.get("role") in ROLES else "guest"}
        return self._send_json(200, {"authenticated": dev is not None,
                                     "host": host, "device": dev})

    # ---- /i/<token> (public invite landing) ----------------------------------------

    def _gate_device_locked(self, now=None):
        """The non-revoked, unexpired browser device this request's cush_auth
        cookie belongs to, or None. Caller holds STATE_LOCK."""
        token = self._read_cookie(GATE_COOKIE)
        if not token:
            return None
        entry = TOKEN_CACHE.get(sha256_hex(token))
        if not entry or entry[1] != "browser":
            return None
        now = time.time() if now is None else now
        return next(
            (
                d for d in STATE["devices"]
                if d.get("id") == entry[0] and not d.get("revoked")
                and not _device_expired(d, now)
            ),
            None,
        )

    def _invite_rd(self, inv):
        landing = inv.get("landing")
        if isinstance(landing, str) and landing:
            return self._sanitize_rd(f"https://{landing}/")
        return DEFAULT_RD

    def _covers(self, dev, apps, now):
        """True iff the device can already reach every one of `apps` right
        now (permanent scope plus any live pass)."""
        cur = device_apps(dev, now)
        if cur == ["*"]:
            return True
        return isinstance(apps, list) and set(apps) <= set(cur)

    def _handle_invite_page(self, token):
        """Render the invite card. GET NEVER consumes a use: chat apps
        (iMessage, Slack, Discord) fetch links for previews, and a one-time
        invite must survive being pasted into a conversation."""
        now = time.time()
        view = {"status": "invalid", "apps": [], "enrolled": None, "rd": DEFAULT_RD}
        code = 404
        if INVITE_TOKEN_RE.match(token or ""):
            with STATE_LOCK:
                inv = _find_invite_locked(sha256_hex(token))
                if inv is not None:
                    dev = self._gate_device_locked(now)
                    status = _invite_status(inv, now)
                    ttl = _invite_device_ttl(inv)
                    # A browser that already accepted this invite (e.g. hitting
                    # Back after the redirect) gets a way on, not "used up".
                    # For a pass that only holds while the pass is running:
                    # once it has expired the visitor must be able to accept
                    # again.
                    if dev is not None and dev["id"] in inv.get("device_ids", []):
                        if ttl is None or self._covers(dev, inv.get("apps"), now):
                            status = "accepted"
                    view = {
                        "status": status,
                        "apps": list(inv.get("apps") or []),
                        "enrolled": dev.get("name", "") if dev is not None else None,
                        # null: no expiry (standing invite).
                        "expires_at": epoch_from_iso(inv.get("expires_at")) or None,
                        # Minutes each pass lasts; null for permanent access.
                        "ttl_minutes": ttl // 60 if ttl is not None else None,
                        "rd": self._invite_rd(inv),
                    }
                    code = 200
        # _js_string json-encodes any value, so the whole view object gets the
        # same </script>-proof escaping a string would.
        html = _domain_html(INVITE_HTML).replace('"__INVITE__"', _js_string(view))
        return self._send_html(
            code, html,
            extra_headers=[
                ("Referrer-Policy", "no-referrer"),
                ("X-Robots-Tag", "noindex, nofollow"),
            ],
        )

    def _handle_invite_accept(self, token):
        """Accept an invite. Body: {device_name}.

        Not enrolled: a guest device is minted with the invite's scope and the
        cush_auth cookie is set. If the invite has a device TTL the device
        carries expires_at and the cookie lasts exactly as long.

        Already enrolled (the browser keeps its device, cookie and role):
          - permanent invite: the invite's apps are merged into the device's
            permanent scope.
          - TTL invite: nothing permanent changes. The device gets a `pass`
            {invite_id, apps, expires_at} that device_apps() adds to its scope
            until it runs out. One pass per device; a newer one replaces it.
            A device that already reaches every app of the invite is left
            alone and nothing is consumed.
          - permanent invite on a pass device (one that itself expires): the
            device is promoted in place. It becomes permanent with the
            invite's scope, and what it held before lives on as a pass until
            its original expiry.

        Validity is re-checked and the use is consumed under one STATE_LOCK
        hold, so two racing accepts cannot both spend the last use (or the
        last free pass of a standing invite).
        """
        ip = self._client_ip()
        if not _rate_limit_check(
            INVITE_ACCEPT_ATTEMPTS, INVITE_ACCEPT_ATTEMPTS_LOCK, ip, 60, 10
        ):
            return self._send_json(
                429, {"ok": False, "error": "too many attempts"},
                extra_headers={"Retry-After": "60"},
            )
        try:
            body = self._read_json()
        except ValueError as e:
            return self._send_json(400, {"ok": False, "error": str(e)})
        device_name = body.get("device_name") or ""
        if not isinstance(device_name, str):
            device_name = ""
        if not INVITE_TOKEN_RE.match(token or ""):
            return self._send_json(404, {"ok": False, "error": "invalid invite"})

        now = time.time()
        token_plain = None
        max_age = GATE_TTL
        with STATE_LOCK:
            inv = _find_invite_locked(sha256_hex(token))
            if inv is None:
                return self._send_json(404, {"ok": False, "error": "invalid invite"})
            status = _invite_status(inv, now)
            if status not in INVITE_OPEN:
                return self._send_json(410, {"ok": False, "error": f"invite {status}"})
            inv_apps = inv.get("apps")
            try:
                inv_apps = normalize_apps(inv_apps)
            except ValueError:
                return self._send_json(410, {"ok": False, "error": "invite invalid"})
            # Creation refuses ["*"]; this covers a record written before that
            # rule or by hand.
            if inv_apps == ["*"]:
                return self._send_json(410, {"ok": False, "error": "invite invalid"})
            ttl = _invite_device_ttl(inv)
            rd = self._invite_rd(inv)
            invite_id = inv.get("id")

            dev = self._gate_device_locked(now)
            if dev is not None and ttl is not None and self._covers(dev, inv_apps, now):
                # Nothing to add: no use spent, no pass taken, and it works
                # even while a standing invite is full.
                return self._send_json(
                    200, {"ok": True, "rd": rd, "merged": True, "noop": True}
                )
            if status == "full":
                return self._send_json(
                    503,
                    {
                        "ok": False, "full": True,
                        "error": "All guest passes are in use right now. "
                                 "Please try again later.",
                    },
                    extra_headers={"Retry-After": "600"},
                )

            expires_at = now + ttl if ttl is not None else None
            if dev is not None and ttl is not None:
                dev["pass"] = {
                    "invite_id": invite_id,
                    "apps": list(inv_apps),
                    "expires_at": iso_from_epoch(expires_at),
                }
                device_id = dev["id"]
                merged = True
            elif dev is not None and dev.get("expires_at"):
                # Promote a pass device: merging into a device that is about
                # to be dropped would spend the use and then lose the grant.
                old_apps = device_perm_apps(dev)
                if not set(old_apps) <= set(inv_apps):
                    dev["pass"] = {
                        "invite_id": dev.get("invite_id"),
                        "apps": list(old_apps),
                        "expires_at": dev["expires_at"],
                    }
                else:
                    dev.pop("pass", None)
                dev["apps"] = list(inv_apps)
                dev["invite_id"] = invite_id
                del dev["expires_at"]
                # Its cookie was issued to die with the pass; reissue it.
                token_plain = self._read_cookie(GATE_COOKIE)
                device_id = dev["id"]
                merged = True
            elif dev is not None:
                # Already enrolled: widen this browser's scope, keep its role
                # and cookie. Testing your own invite on your phone must not
                # swap an admin cookie for a guest one. Permanent scope only:
                # a live pass's apps must not be written into `apps`.
                cur = device_perm_apps(dev)
                if cur != ["*"]:
                    dev["apps"] = sorted(set(cur) | set(inv_apps))
                device_id = dev["id"]
                merged = True
            else:
                device, token_plain = self._mint_browser_device_locked(
                    device_name, list(inv_apps), "guest", expires_at
                )
                device["invite_id"] = invite_id
                device_id = device["id"]
                merged = False
                if expires_at is not None:
                    # From the stored (whole-second) stamp, so the cookie never
                    # outlives the device.
                    max_age = max(
                        1, int(epoch_from_iso(device["expires_at"]) - now)
                    )
            inv["uses"] = int(inv.get("uses", 0)) + 1
            inv["last_used_at"] = iso_from_epoch(now)
            ids = inv.setdefault("device_ids", [])
            if device_id not in ids:
                ids.append(device_id)
            save_state_locked()

        sync_haproxy_maps()
        log(f"invite accept {invite_id} device={device_id} merged={merged} "
            f"ttl={ttl} ip={ip}")
        reply = {"ok": True, "rd": rd, "merged": merged}
        if expires_at is not None:
            reply["expires_at"] = int(expires_at)
        return self._send_json(
            200, reply,
            extra_headers=(
                [self._gate_cookie_header(token_plain, max_age)]
                if token_plain else None
            ),
        )


# --- Modern admin console (Tailwind utilities, vanilla JS) --------------------------
#
# All three pages below are styled by lib/auth.css, built from the class names
# in this file by bin/auth-css and served at AUTH_CSS_PATH. A class name has to
# appear whole in the source to get a rule: do not assemble one from fragments.
# After adding or changing classes, run bin/auth-css and commit the result
# (bin/auth-deploy refuses a stale file). The <link> sits after each page's own
# <style>, the order the CDN build used to inject its sheet in.

ADMIN_HTML = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>porch · access</title>
<style nonce="__NONCE__">
  body{background:#121014;}
  .glass{background:#1B181E;}
  .pulse-dot{box-shadow:0 0 0 0 rgba(92,203,138,.6);animation:pd 2s infinite}
  @keyframes pd{70%{box-shadow:0 0 0 8px rgba(92,203,138,0)}100%{box-shadow:0 0 0 0 rgba(92,203,138,0)}}
  .toggle{transition:background .15s ease}
  .knob{transition:transform .15s ease}
  .knob-on{transform:translateX(20px)}
  ::-webkit-scrollbar{width:10px;height:10px}
  ::-webkit-scrollbar-thumb{background:#2E2830;border-radius:6px}
</style>
<link rel="stylesheet" href="/auth/static/auth.css">
</head>
<body class="text-slate-200 min-h-screen">
<div class="max-w-4xl mx-auto px-5 py-10">

  <!-- header -->
  <header class="flex items-center justify-between mb-8">
    <div class="flex items-center gap-3">
      <div class="w-11 h-11 rounded-xl bg-gradient-to-br from-blue-500/30 to-indigo-600/20 border border-blue-400/30 flex items-center justify-center">
        <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6 text-blue-300" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
      </div>
      <div>
        <h1 class="font-display text-2xl font-bold tracking-tight">porch</h1>
        <p class="text-xs text-slate-400">front door &middot; devices &amp; access</p>
      </div>
    </div>
    <div id="header-right" class="flex items-center gap-3"></div>
  </header>

  <!-- setup / login card -->
  <div id="auth-card" class="hidden glass border border-edge rounded-2xl p-7 max-w-md mx-auto mt-10">
    <div id="auth-icon" class="w-12 h-12 rounded-xl bg-blue-500/15 border border-blue-400/30 flex items-center justify-center mb-5">
      <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6 text-blue-300" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
    </div>
    <h2 id="auth-title" class="font-display text-xl font-bold tracking-tight mb-1">Sign in</h2>
    <p id="auth-sub" class="text-sm text-slate-400 mb-5">Enter the admin password.</p>
    <input id="auth-setup" type="text" autocomplete="off"
      class="hidden w-full bg-base border border-edge rounded-lg px-3 py-2.5 text-sm outline-none focus:border-blue-400 mb-3" placeholder="Setup token (server log or data/.admin-setup-token)">
    <input id="auth-pw" type="password" autocomplete="current-password"
      class="w-full bg-base border border-edge rounded-lg px-3 py-2.5 text-sm outline-none focus:border-blue-400 mb-3" placeholder="Password" autofocus>
    <button id="auth-btn" class="w-full bg-blue-500 hover:bg-blue-400 text-slate-950 font-semibold transition rounded-lg py-2.5 text-sm font-medium">Continue</button>
    <p id="auth-msg" class="text-sm text-rose-400 mt-3 min-h-[1.25rem]"></p>
  </div>

  <!-- dashboard -->
  <main id="dash" class="hidden space-y-6">
    <p id="hap-msg" class="hidden text-sm text-rose-400 rounded-xl border border-edge bg-base/40 px-4 py-3"></p>
    <div id="act-msg" role="alert" class="hidden flex items-start justify-between gap-3 text-sm text-rose-300 rounded-xl border border-rose-400/40 bg-rose-950/30 px-4 py-3"><span id="act-text"></span><button id="act-close" type="button" class="shrink-0 text-xs text-slate-300 hover:text-slate-100" aria-label="Dismiss">Dismiss</button></div>

    <!-- devices -->
    <section class="glass border border-edge rounded-2xl p-6">
      <div class="flex items-center justify-between mb-4">
        <h2 class="font-display text-lg font-bold tracking-tight text-slate-100 flex items-center gap-2">
          <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>
          Devices
        </h2>
        <button id="btn-enroll" class="text-xs bg-emerald-600/90 hover:bg-emerald-500 transition rounded-lg px-3 py-1.5 font-medium flex items-center gap-1.5">
          <svg xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>
          Enroll this browser
        </button>
      </div>
      <div id="devices" class="space-y-2"></div>
    </section>

    <!-- invites -->
    <section class="glass border border-edge rounded-2xl p-6">
      <div class="flex items-center justify-between mb-4">
        <h2 class="font-display text-lg font-bold tracking-tight text-slate-100 flex items-center gap-2">
          <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
          Invites
        </h2>
        <button id="btn-invite-new" class="text-xs bg-emerald-600/90 hover:bg-emerald-500 transition rounded-lg px-3 py-1.5 font-medium flex items-center gap-1.5">
          <svg xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>
          New invite
        </button>
      </div>

      <div id="inv-form" class="inv-form hidden rounded-xl border border-edge bg-base/40 px-4 py-4 mb-4">
        <p class="text-xs text-slate-500 mb-3">Anyone with the link can enroll a browser as a <span class="text-slate-300">guest</span> with this scope. Opening the link doesn't use it up; pressing Accept does.</p>
        <input id="inv-note" type="text" maxlength="80" placeholder="Note (who is this for?)"
          class="w-full bg-base border border-edge rounded-lg px-3 py-2 text-sm outline-none focus:border-blue-400 mb-3">
        <div id="inv-hosts" class="grid grid-cols-1 sm:grid-cols-2 gap-1.5 mb-3"></div>
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-2 mb-3">
          <label class="text-xs text-slate-400">Land on
            <select id="inv-landing" class="mt-1 w-full bg-base border border-edge rounded-lg px-2 py-1.5 text-sm outline-none focus:border-blue-400"><option value="">First app</option></select></label>
          <label class="text-xs text-slate-400">Expires in
            <select id="inv-expiry" class="mt-1 w-full bg-base border border-edge rounded-lg px-2 py-1.5 text-sm outline-none focus:border-blue-400">
              <option value="1">1 hour</option><option value="24" selected>24 hours</option><option value="168">7 days</option><option value="720">30 days</option><option id="inv-never" value="" hidden disabled>Never</option></select></label>
          <label id="inv-uses-wrap" class="text-xs text-slate-400">Uses
            <select id="inv-uses" class="mt-1 w-full bg-base border border-edge rounded-lg px-2 py-1.5 text-sm outline-none focus:border-blue-400">
              <option value="1" selected>1</option><option value="5">5</option><option value="25">25</option></select></label>
          <label id="inv-live-wrap" class="hidden text-xs text-slate-400">Passes live at once
            <input id="inv-live" type="number" min="1" max="500" value="20" class="mt-1 w-full bg-base border border-edge rounded-lg px-2 py-1.5 text-sm outline-none focus:border-blue-400"></label>
        </div>
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-2 mb-3">
          <label class="text-xs text-slate-400">Device lasts
            <select id="inv-ttl" class="mt-1 w-full bg-base border border-edge rounded-lg px-2 py-1.5 text-sm outline-none focus:border-blue-400">
              <option value="" selected>Permanent</option><option value="60">1 hour</option><option value="1440">24 hours</option><option value="4320">72 hours</option><option value="10080">7 days</option></select></label>
          <label class="sm:col-span-2 flex items-center gap-2 text-xs sm:mt-5">
            <input id="inv-standing" type="checkbox" class="accent-emerald-500">
            <span><span class="font-medium">Standing link</span> <span class="text-slate-500">stays up; each visitor gets a pass that expires, and the cap counts passes in use</span></span></label>
        </div>
        <div class="flex gap-2">
          <button id="inv-create" class="text-xs bg-blue-500 hover:bg-blue-400 text-slate-950 font-semibold transition rounded-lg px-3 py-1.5">Create link</button>
          <button id="inv-cancel" class="text-xs bg-slate-700/60 hover:bg-slate-600 transition rounded-lg px-3 py-1.5">Cancel</button>
        </div>
        <p id="inv-msg" class="text-sm text-rose-400 mt-2 min-h-[1.25rem]"></p>
      </div>

      <div id="inv-created" class="hidden rounded-xl border border-emerald-400/30 bg-emerald-950/20 px-4 py-4 mb-4">
        <p class="text-xs text-emerald-300 mb-2">Invite link created. Copy it now: it can't be shown again.</p>
        <input id="inv-url" type="text" readonly
          class="w-full font-mono bg-base border border-edge rounded-lg px-3 py-2 text-xs outline-none mb-3">
        <div class="flex gap-2">
          <button id="inv-copy" class="text-xs bg-blue-500 hover:bg-blue-400 text-slate-950 font-semibold transition rounded-lg px-3 py-1.5">Copy</button>
          <button id="inv-share" class="hidden text-xs bg-slate-700/60 hover:bg-slate-600 transition rounded-lg px-3 py-1.5">Share</button>
          <button id="inv-done" class="text-xs bg-slate-700/60 hover:bg-slate-600 transition rounded-lg px-3 py-1.5">Done</button>
        </div>
      </div>

      <div id="invites" class="space-y-2"></div>
    </section>

    <!-- pending pairings -->
    <section class="glass border border-edge rounded-2xl p-6">
      <h2 class="font-display text-lg font-bold tracking-tight text-slate-100 mb-4 flex items-center gap-2">
        <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
        Pending pairings
      </h2>
      <div id="pairings" class="space-y-2"></div>
    </section>

    <!-- protected apps -->
    <section class="glass border border-edge rounded-2xl p-6">
      <h2 class="font-display text-lg font-bold tracking-tight text-slate-100 mb-4 flex items-center gap-2">
        <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        Protected apps
      </h2>
      <p class="text-xs text-slate-500 mb-4">Toggle which <span class="font-mono">*.__PORCH_ROOT__</span> apps require a device cookie at the HAProxy edge.</p>
      <div id="apps" class="grid grid-cols-1 sm:grid-cols-2 gap-2"></div>
      <div id="public-paths-wrap" class="hidden">
        <p class="text-xs text-slate-500 mt-4 mb-2">Public paths: open to anyone on a gated app. Manage with <span class="font-mono">porch public</span> or the Porch app.</p>
        <div id="public-paths" class="space-y-2"></div>
      </div>
    </section>

    <!-- change password -->
    <details class="glass border border-edge rounded-2xl p-6">
      <summary class="cursor-pointer text-sm text-slate-400 hover:text-slate-200 select-none">Change admin password</summary>
      <div class="mt-4 space-y-3 max-w-sm">
        <input id="cp-current" type="password" autocomplete="current-password" placeholder="Current password"
          class="w-full bg-base border border-edge rounded-lg px-3 py-2 text-sm outline-none focus:border-blue-400">
        <input id="cp-new" type="password" autocomplete="new-password" placeholder="New password"
          class="w-full bg-base border border-edge rounded-lg px-3 py-2 text-sm outline-none focus:border-blue-400">
        <button id="btn-chpw" class="bg-blue-500 hover:bg-blue-400 text-slate-950 font-semibold transition rounded-lg px-4 py-2 text-sm font-medium">Update password</button>
        <p id="chpw-msg" class="text-sm min-h-[1.25rem]"></p>
      </div>
    </details>
  </main>
</div>

<script nonce="__NONCE__">
(function(){
  var MODE = "admin";  // "admin" full console
  var el = function(id){return document.getElementById(id);};
  var state = "login"; // login | setup | dash

  function esc(s){return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");}

  function jreq(method,url,body){
    var opts={method:method,credentials:"include",headers:{}};
    if(body!==undefined){opts.headers["Content-Type"]="application/json";opts.body=JSON.stringify(body);}
    return fetch(url,opts).then(function(r){
      return r.json().then(function(j){return {ok:r.ok,status:r.status,body:j};})
        .catch(function(){return {ok:r.ok,status:r.status,body:{}};});
    });
  }

  // Admin actions answer with haproxy: "ok" | "skipped" | "failed: ...".
  // A failure means the change is saved but not live at the edge yet.
  // Inline error banner instead of alert(): stays until dismissed or the
  // next action succeeds.
  function showErr(msg){
    var m=el("act-msg");
    el("act-text").textContent=msg;
    m.classList.remove("hidden");
    m.scrollIntoView({block:"nearest"});
  }
  function clearErr(){ el("act-msg").classList.add("hidden"); }
  function hapNote(res){
    var h=res&&res.body&&res.body.haproxy, m=el("hap-msg");
    if(typeof h==="string" && h.indexOf("failed")===0){
      m.textContent="Saved, but HAProxy was not updated ("+h+"). The change is not live at the gate until the maps are pushed (SIGHUP cush-auth or reload HAProxy).";
      m.classList.remove("hidden");
    } else if(h==="ok"){ m.classList.add("hidden"); }
    return res;
  }

  function rel(ts){
    if(!ts) return "never";
    var d=(Date.now()-ts*1000)/1000;
    if(d<60) return Math.floor(d)+"s ago";
    if(d<3600) return Math.floor(d/60)+"m ago";
    if(d<86400) return Math.floor(d/3600)+"h ago";
    if(d<2592000) return Math.floor(d/86400)+"d ago";
    return new Date(ts*1000).toLocaleDateString();
  }
  function expLeft(ts){
    var r=Math.max(0,Math.floor(ts-Date.now()/1000));
    return Math.floor(r/60)+"m "+(r%60)+"s left";
  }

  function setView(v){
    state=v;
    el("auth-card").classList.toggle("hidden", v==="dash");
    el("dash").classList.toggle("hidden", v!=="dash");
    el("header-right").innerHTML = (v==="dash")
      ? '<span class="flex items-center gap-2 text-xs text-emerald-400"><span class="w-2 h-2 rounded-full bg-emerald-400 pulse-dot"></span>online</span>'
        + '<button id="btn-logout" class="text-xs bg-slate-700/60 hover:bg-slate-600 transition rounded-lg px-3 py-1.5">Sign out</button>'
      : '';
    var lo=el("btn-logout"); if(lo) lo.onclick=function(){jreq("POST","/auth/admin/logout").then(function(){setView("login");});};
    if(v==="setup"){
      el("auth-title").textContent="Set admin password";
      el("auth-sub").textContent="No admin configured yet. Enter the setup token from the server log, then choose a password (12+ characters).";
      el("auth-setup").classList.remove("hidden");
      el("auth-pw").setAttribute("autocomplete","new-password");
    } else if(v==="login"){
      el("auth-title").textContent="Sign in";
      el("auth-sub").textContent="Enter the admin password.";
      el("auth-setup").classList.add("hidden");
      el("auth-pw").setAttribute("autocomplete","current-password");
    }
  }

  function roleBadge(role){
    if(role==="admin") return '<span class="text-[10px] uppercase tracking-wide px-2 py-0.5 rounded-full bg-amber-500/15 text-amber-300 border border-amber-400/30">Admin</span>';
    return '<span class="text-[10px] uppercase tracking-wide px-2 py-0.5 rounded-full bg-slate-600/30 text-slate-300 border border-slate-500/40">Guest</span>';
  }

  function badge(type){
    if(type==="browser") return '<span class="text-[10px] uppercase tracking-wide px-2 py-0.5 rounded-full bg-blue-500/15 text-blue-300 border border-blue-400/30">Browser</span>';
    return '<span class="text-[10px] uppercase tracking-wide px-2 py-0.5 rounded-full bg-violet-500/15 text-violet-300 border border-violet-400/30">Tunnel</span>';
  }

  // Hosts available for scope checkboxes (KNOWN_HOSTS minus the auth host).
  var SCOPE_HOSTS = [];

  function scopeSummary(d){
    if(d.type!=="browser") return "";
    var apps=d.apps||["*"];
    if(apps.length===1 && apps[0]==="*"){
      return '<span class="text-[10px] uppercase tracking-wide px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-400/30">All apps</span>';
    }
    return apps.map(function(h){
      return '<span class="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-700/40 text-slate-300 border border-edge">'+esc(h)+'</span>';
    }).join(" ");
  }

  // Time-limited extras on a device row: when the whole device expires, and
  // the apps a pass lends it. Pass apps are shown apart from the permanent
  // scope because the scope editor only ever edits the permanent one.
  function expiryBadge(d){
    if(!d.expires_at) return "";
    return '<span class="text-[10px] uppercase tracking-wide px-2 py-0.5 rounded-full bg-amber-500/15 text-amber-300 border border-amber-400/30">Pass &middot; '+leftText(d.expires_at)+'</span>';
  }
  function passSummary(d){
    if(!d.pass) return "";
    return (d.pass.apps||[]).map(function(h){
      return '<span class="text-[10px] font-mono px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-300 border border-amber-400/30">'+esc(h)+' &middot; '+leftText(d.pass.expires_at)+'</span>';
    }).join(" ");
  }

  function scopeEditor(d){
    var apps=d.apps||["*"];
    var all=(apps.length===1 && apps[0]==="*");
    var set={}; apps.forEach(function(h){set[h]=1;});
    var boxes=SCOPE_HOSTS.map(function(h){
      var ck=(!all && set[h])?"checked":"";
      return '<label class="flex items-center gap-2 text-xs '+(all?'opacity-40':'')+'">'
        +'<input type="checkbox" class="dev-host accent-blue-500" value="'+esc(h)+'" '+ck+(all?' disabled':'')+'>'
        +'<span class="font-mono">'+esc(h)+'</span></label>';
    }).join("");
    return '<div class="dev-scope hidden mt-3 pt-3 border-t border-edge" data-id="'+esc(d.id)+'">'
      +'<label class="flex items-center gap-2 text-xs mb-2">'
        +'<input type="checkbox" class="dev-all accent-emerald-500" '+(all?"checked":"")+'>'
        +'<span class="font-medium">All apps</span></label>'
      +'<div class="dev-hosts grid grid-cols-1 sm:grid-cols-2 gap-1.5 mb-3">'+boxes+'</div>'
      +'<div class="flex gap-2">'
        +'<button class="text-xs bg-blue-500 hover:bg-blue-400 text-slate-950 font-semibold transition rounded-lg px-3 py-1.5" data-action="save-scope" data-id="'+esc(d.id)+'">Save scope</button>'
        +'<button class="text-xs bg-slate-700/60 hover:bg-slate-600 transition rounded-lg px-3 py-1.5" data-action="cancel-scope" data-id="'+esc(d.id)+'">Cancel</button>'
      +'</div></div>';
  }

  function renderDevices(list){
    var c=el("devices");
    if(!list.length){c.innerHTML='<div class="text-sm text-slate-500 text-center py-6">No devices yet</div>';return;}
    c.innerHTML=list.map(function(d){
      var rev=d.revoked;
      var isBrowser=(d.type==="browser");
      return '<div class="rounded-xl border '
        +(rev?'border-rose-900/40 bg-rose-950/20 opacity-60':'border-edge bg-base/40')
        +' px-4 py-3">'
        +'<div class="flex items-center justify-between">'
          +'<div class="min-w-0">'
            +'<div class="flex items-center gap-2 flex-wrap">'
              +'<span class="font-medium truncate">'+esc(d.name||d.id)+'</span>'
              +badge(d.type)
              +(isBrowser?roleBadge(d.role):'')
              +(rev?'':expiryBadge(d))
              +(rev?'<span class="text-[10px] uppercase px-2 py-0.5 rounded-full bg-rose-500/15 text-rose-300 border border-rose-400/30">Revoked</span>':'')
            +'</div>'
            +'<div class="text-xs text-slate-500 mt-0.5">'+esc(d.id)+' &middot; seen '+rel(d.last_seen)+' &middot; added '+rel(d.created_at)+'</div>'
            +(isBrowser && !rev?'<div class="flex items-center gap-1.5 flex-wrap mt-1.5">'+scopeSummary(d)+(d.pass?' '+passSummary(d):'')+'</div>':'')
          +'</div>'
          +'<div class="flex gap-2 shrink-0">'
            +((isBrowser && !rev)?'<button class="text-xs bg-slate-700/60 hover:bg-slate-600 transition rounded-lg px-3 py-1.5" data-action="set-role" data-role="'+(d.role==="admin"?'guest':'admin')+'" data-id="'+esc(d.id)+'">'+(d.role==="admin"?'Make guest':'Make admin')+'</button>':'')
            +((isBrowser && !rev)?'<button class="text-xs bg-slate-700/60 hover:bg-slate-600 transition rounded-lg px-3 py-1.5" data-action="edit-scope" data-id="'+esc(d.id)+'">Scope</button>':'')
            +(rev?'':'<button class="text-xs bg-rose-600/80 hover:bg-rose-500 transition rounded-lg px-3 py-1.5" data-action="revoke" data-id="'+esc(d.id)+'">Revoke</button>')
          +'</div>'
        +'</div>'
        +((isBrowser && !rev)?scopeEditor(d):'')
      +'</div>';
    }).join("");
  }

  function approveScope(code){
    var boxes=SCOPE_HOSTS.map(function(h){
      return '<label class="flex items-center gap-2 text-xs opacity-40">'
        +'<input type="checkbox" class="pair-host accent-blue-500" value="'+esc(h)+'" disabled>'
        +'<span class="font-mono">'+esc(h)+'</span></label>';
    }).join("");
    return '<div class="pair-scope hidden w-full mt-3 pt-3 border-t border-edge" data-code="'+code+'">'
      +'<p class="text-xs text-slate-500 mb-2">Scope this device. Uncheck "All apps" to limit to specific apps.</p>'
      +'<label class="flex items-center gap-2 text-xs mb-2">'
        +'<input type="checkbox" class="pair-all accent-emerald-500" checked>'
        +'<span class="font-medium">All apps</span></label>'
      +'<div class="pair-hosts grid grid-cols-1 sm:grid-cols-2 gap-1.5 mb-3">'+boxes+'</div>'
      +'<div class="flex gap-2">'
        +'<button class="text-xs bg-emerald-600/90 hover:bg-emerald-500 transition rounded-lg px-3 py-1.5" data-action="approve-confirm" data-code="'+code+'">Confirm approve</button>'
        +'<button class="text-xs bg-slate-700/60 hover:bg-slate-600 transition rounded-lg px-3 py-1.5" data-action="approve-cancel" data-code="'+code+'">Cancel</button>'
      +'</div></div>';
  }

  function pairKindBadge(kind){
    if(kind==="web") return '<span class="text-[10px] uppercase tracking-wide px-2 py-0.5 rounded-full bg-blue-500/15 text-blue-300 border border-blue-400/30">Web (browser)</span>';
    return '<span class="text-[10px] uppercase tracking-wide px-2 py-0.5 rounded-full bg-violet-500/15 text-violet-300 border border-violet-400/30">Tunnel</span>';
  }

  function renderPairings(list){
    var c=el("pairings");
    if(!list.length){c.innerHTML='<div class="text-sm text-slate-500 text-center py-6">No pending pairings</div>';return;}
    c.innerHTML=list.map(function(p){
      var code=String(p.code).replace(/[^A-Z0-9-]/g,"");
      var isWeb=(p.kind==="web");
      return '<div class="rounded-xl border border-edge bg-base/40 px-4 py-3">'
        +'<div class="flex items-center justify-between flex-wrap gap-3">'
          +'<div><div class="font-mono text-2xl tracking-widest text-blue-300">'+esc(p.code)+'</div>'
            +'<div class="text-xs text-slate-500 mt-0.5 flex items-center gap-2 flex-wrap">'+pairKindBadge(p.kind)+'<span>'+esc(p.device_name)+' &middot; '+expLeft(p.expires_at)+'</span></div></div>'
          +'<div class="flex gap-2">'
            +'<button class="text-xs bg-emerald-600/90 hover:bg-emerald-500 transition rounded-lg px-3 py-1.5" data-action="'+(isWeb?'approve':'approve-tunnel')+'" data-code="'+code+'">Approve</button>'
            +'<button class="text-xs bg-rose-600/80 hover:bg-rose-500 transition rounded-lg px-3 py-1.5" data-action="reject" data-code="'+code+'">Reject</button>'
          +'</div>'
        +'</div>'
        // Scope chooser only for web (browser) pairings; tunnel pairings
        // approve directly without a per-app scope (the grants map ignores them).
        +(isWeb?approveScope(code):'')
      +'</div>';
    }).join("");
  }

  // Collect the chosen scope from an editor container (.dev-scope or .pair-scope).
  function collectScope(box, allSel, hostSel){
    var all=box.querySelector(allSel);
    if(all && all.checked) return ["*"];
    var hosts=[];
    box.querySelectorAll(hostSel).forEach(function(cb){ if(cb.checked) hosts.push(cb.value); });
    return hosts;
  }

  function inviteStatusBadge(st){
    var cls={active:"bg-emerald-500/15 text-emerald-300 border-emerald-400/30",
      used:"bg-slate-600/30 text-slate-300 border-slate-500/40",
      expired:"bg-slate-600/30 text-slate-400 border-slate-500/40",
      full:"bg-amber-500/15 text-amber-300 border-amber-400/30",
      revoked:"bg-rose-500/15 text-rose-300 border-rose-400/30"}[st]||"bg-slate-600/30 text-slate-400 border-slate-500/40";
    var label={active:"Active",used:"Used up",expired:"Expired",revoked:"Revoked",full:"Full"}[st]||st;
    return '<span class="text-[10px] uppercase tracking-wide px-2 py-0.5 rounded-full border '+cls+'">'+esc(label)+'</span>';
  }

  function leftText(ts){
    var d=Math.max(0,ts-Date.now()/1000);
    if(d<3600) return Math.max(1,Math.ceil(d/60))+"m left";
    if(d<172800) return Math.floor(d/3600)+"h left";
    return Math.floor(d/86400)+"d left";
  }
  function ttlText(m){
    if(m<60) return m+"m";
    if(m<2880) return Math.round(m/60)+"h";
    return Math.round(m/1440)+"d";
  }

  function untilText(ts){
    if(!ts) return "no expiry";
    var d=ts-Date.now()/1000;
    if(d<=0) return "expired "+rel(ts);
    if(d<3600) return "expires in "+Math.max(1,Math.floor(d/60))+"m";
    if(d<172800) return "expires in "+Math.floor(d/3600)+"h";
    return "expires in "+Math.floor(d/86400)+"d";
  }

  function renderInvites(list){
    var c=el("invites");
    if(!list.length){c.innerHTML='<div class="text-sm text-slate-500 text-center py-6">No invites</div>';return;}
    c.innerHTML=list.map(function(i){
      var active=(i.status==="active" || i.status==="full");
      var devs=(i.devices||[]).map(function(d){return esc(d.name||d.id);}).join(", ");
      var live=i.live||0;
      // A standing invite's cap is on passes in use right now, so that is the
      // number to show against it; lifetime accepts follow.
      var count=i.standing
        ? esc(live)+'/'+esc(i.max_uses)+' live &middot; '+esc(i.uses)+' total'
        : esc(i.uses)+'/'+esc(i.max_uses)+' used'+(i.device_ttl_minutes?' &middot; '+esc(live)+' live':'');
      var kind=(i.standing?'<span class="text-[10px] uppercase tracking-wide px-2 py-0.5 rounded-full bg-blue-500/15 text-blue-300 border border-blue-400/30">Standing</span>':'')
        +(i.device_ttl_minutes?'<span class="text-[10px] uppercase tracking-wide px-2 py-0.5 rounded-full bg-amber-500/15 text-amber-300 border border-amber-400/30">'+esc(ttlText(i.device_ttl_minutes))+' passes</span>':'');
      return '<div class="rounded-xl border border-edge bg-base/40 px-4 py-3 '+(active?'':'opacity-70')+'">'
        +'<div class="flex items-center justify-between gap-3">'
          +'<div class="min-w-0">'
            +'<div class="flex items-center gap-2 flex-wrap">'
              +'<span class="font-medium truncate">'+(i.note?esc(i.note):'<span class="text-slate-500">(no note)</span>')+'</span>'
              +inviteStatusBadge(i.status)
              +kind
            +'</div>'
            +'<div class="text-xs text-slate-500 mt-0.5">'+esc(i.id)+' &middot; '+count+' &middot; '+untilText(i.expires_at)+' &middot; created '+rel(i.created_at)+'</div>'
            +'<div class="flex items-center gap-1.5 flex-wrap mt-1.5">'+scopeSummary({type:"browser",apps:i.apps||[]})+'</div>'
            +(devs?'<div class="text-xs text-slate-400 mt-1.5">Devices: '+devs+'</div>':'')
          +'</div>'
          +(active?'<button class="shrink-0 text-xs bg-rose-600/80 hover:bg-rose-500 transition rounded-lg px-3 py-1.5" data-action="invite-revoke" data-id="'+esc(i.id)+'" data-live="'+esc(live)+'">Revoke</button>':'')
        +'</div>'
      +'</div>';
    }).join("");
  }

  // Host checkboxes for the invite form. Only rebuilt while the form is
  // closed, so a refresh never clears a half-filled form.
  function renderInviteHosts(){
    if(!el("inv-form").classList.contains("hidden")) return;
    el("inv-hosts").innerHTML=SCOPE_HOSTS.map(function(h){
      return '<label class="flex items-center gap-2 text-xs">'
        +'<input type="checkbox" class="inv-host accent-blue-500" value="'+esc(h)+'">'
        +'<span class="font-mono">'+esc(h)+'</span></label>';
    }).join("");
    syncInviteLanding();
  }

  // The landing choice must be one of the chosen apps. An invite always
  // names its apps: there is no "All apps" box here (the server refuses
  // it), so collectScope is given a selector that matches nothing.
  function syncInviteLanding(){
    var form=el("inv-form"), sel=el("inv-landing"), prev=sel.value;
    var hosts=collectScope(form,".inv-none",".inv-host");
    sel.innerHTML='<option value="">First app</option>'
      +hosts.map(function(h){return '<option value="'+esc(h)+'">'+esc(h)+'</option>';}).join("");
    if(hosts.indexOf(prev)>=0) sel.value=prev;
  }

  // Standing link: the cap becomes "passes live at once", the link may never
  // expire, and the devices it mints must (default 24 hours).
  function syncInviteStanding(){
    var on=el("inv-standing").checked, never=el("inv-never"), exp=el("inv-expiry"), ttl=el("inv-ttl");
    el("inv-uses-wrap").classList.toggle("hidden", on);
    el("inv-live-wrap").classList.toggle("hidden", !on);
    never.hidden=!on; never.disabled=!on;
    ttl.options[0].disabled=on;
    if(on){
      exp.value="";
      if(!ttl.value) ttl.value="1440";
    } else if(exp.value===""){
      exp.value="24";
    }
  }

  function renderApps(list){
    var c=el("apps");
    c.innerHTML=list.map(function(a){
      var locked=(a.host==="__PORCH_AUTH_HOST__");
      var on=a.protected;
      return '<div class="flex items-center justify-between rounded-xl border border-edge bg-base/40 px-4 py-2.5">'
        +'<span class="font-mono text-sm '+(on?'text-slate-100':'text-slate-400')+'">'+esc(a.host)+'</span>'
        +(locked
          ? '<span class="text-[10px] uppercase text-slate-500">locked</span>'
          : '<button data-action="toggle-app" data-host="'+esc(a.host)+'" data-on="'+(on?'1':'0')+'" '
            +'class="toggle relative w-11 h-6 rounded-full '+(on?'bg-emerald-500':'bg-slate-700')+'">'
            +'<span class="knob absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white'+(on?' knob-on':'')+'"></span>'
          +'</button>')
      +'</div>';
    }).join("");
  }

  function renderPublicPaths(list){
    var c=el("public-paths");
    el("public-paths-wrap").classList.toggle("hidden",!list.length);
    c.textContent="";
    list.forEach(function(p){
      var row=document.createElement("div");
      row.className="flex items-center justify-between rounded-xl border border-edge bg-base/40 px-4 py-2.5";
      var name=document.createElement("span");
      name.className="font-mono text-sm "+(p.active?"text-slate-100":"text-slate-400");
      name.textContent=p.host+p.path+(p.kind==="prefix"?"*":"");
      var note=document.createElement("span");
      note.className="text-xs text-slate-500";
      note.textContent=p.app+(p.active?"":" \u00b7 "+p.inactive);
      row.appendChild(name); row.appendChild(note); c.appendChild(row);
    });
  }

  function refresh(){
    return jreq("GET","/auth/admin/state").then(function(res){
      if(res.status===401){setView("login");return;}
      if(res.body && res.body.needs_setup){setView("setup");return;}
      setView("dash");
      SCOPE_HOSTS=(res.body.known_hosts||[]).map(function(a){return a.host;})
        .filter(function(h){return h!=="__PORCH_AUTH_HOST__";});
      renderDevices(res.body.devices||[]);
      renderPairings(res.body.pairings||[]);
      renderInvites(res.body.invites||[]);
      renderInviteHosts();
      renderApps(res.body.known_hosts||[]);
      renderPublicPaths(res.body.public_paths||[]);
    });
  }

  el("auth-btn").addEventListener("click",function(){
    var pw=el("auth-pw").value, msg=el("auth-msg"); msg.textContent="";
    if(!pw){msg.textContent="Enter a password.";return;}
    var url=(state==="setup")?"/auth/admin/setup":"/auth/admin/login";
    var body={password:pw};
    if(state==="setup") body.setup_token=el("auth-setup").value.trim();
    jreq("POST",url,body).then(function(res){
      if(res.ok){el("auth-pw").value="";refresh();}
      else if(res.status===429){msg.textContent="Too many attempts. Wait a minute.";}
      else{msg.textContent=(res.body&&res.body.error)||"Failed";}
    });
  });
  el("auth-pw").addEventListener("keydown",function(e){if(e.key==="Enter")el("auth-btn").click();});
  el("act-close").addEventListener("click",clearErr);

  el("btn-enroll").addEventListener("click",function(){
    var name=prompt("Name this browser device:","Browser");
    if(name===null) return;
    jreq("POST","/auth/admin/enroll-self",{device_name:name}).then(function(res){
      if(res.ok){refresh();}
      else{showErr((res.body&&res.body.error)||"Enroll failed");}
    });
  });

  el("btn-chpw").addEventListener("click",function(){
    var cur=el("cp-current").value, nw=el("cp-new").value, msg=el("chpw-msg"); msg.textContent="";
    jreq("POST","/auth/admin/set-password",{current:cur,new:nw}).then(function(res){
      if(res.ok){msg.className="text-sm text-emerald-400 min-h-[1.25rem]";msg.textContent="Password updated";el("cp-current").value="";el("cp-new").value="";}
      else{msg.className="text-sm text-rose-400 min-h-[1.25rem]";msg.textContent=(res.body&&res.body.error)||"Update failed";}
    });
  });

  // Pause auto-refresh while any inline scope editor is open so it isn't
  // clobbered mid-edit.
  function editorOpen(){ return !!document.querySelector(".dev-scope:not(.hidden), .pair-scope:not(.hidden), .inv-form:not(.hidden)"); }

  // ---- invites ----
  el("btn-invite-new").addEventListener("click",function(){
    renderInviteHosts();
    el("inv-msg").textContent="";
    el("inv-standing").checked=false;
    el("inv-ttl").value="";
    syncInviteStanding();
    el("inv-form").classList.remove("hidden");
    el("inv-note").focus();
  });
  el("inv-cancel").addEventListener("click",function(){ el("inv-form").classList.add("hidden"); });
  el("inv-create").addEventListener("click",function(){
    var form=el("inv-form"), msg=el("inv-msg"); msg.textContent="";
    var apps=collectScope(form,".inv-none",".inv-host");
    if(apps.length===0){msg.textContent="Pick at least one app.";return;}
    var standing=el("inv-standing").checked;
    var body={note:el("inv-note").value,apps:apps,standing:standing,
      expires_hours:el("inv-expiry").value?parseInt(el("inv-expiry").value,10):null,
      max_uses:parseInt(el(standing?"inv-live":"inv-uses").value,10),
      device_ttl_minutes:el("inv-ttl").value?parseInt(el("inv-ttl").value,10):null};
    if(isNaN(body.max_uses)){msg.textContent="Enter how many passes can be live at once.";return;}
    if(el("inv-landing").value) body.landing=el("inv-landing").value;
    jreq("POST","/auth/admin/invites",body).then(function(res){
      if(!res.ok || !res.body.url){msg.textContent=(res.body&&res.body.error)||"Create failed";return;}
      form.classList.add("hidden");
      el("inv-note").value="";
      el("inv-url").value=res.body.url;
      el("inv-share").classList.toggle("hidden", !navigator.share);
      el("inv-created").classList.remove("hidden");
      el("inv-url").select();
      refresh();
    });
  });
  el("inv-copy").addEventListener("click",function(){
    var u=el("inv-url"), b=el("inv-copy");
    function done(){b.textContent="Copied";setTimeout(function(){b.textContent="Copy";},1500);}
    if(navigator.clipboard && navigator.clipboard.writeText){
      navigator.clipboard.writeText(u.value).then(done,function(){u.select();document.execCommand("copy");done();});
    } else { u.select(); document.execCommand("copy"); done(); }
  });
  el("inv-share").addEventListener("click",function(){
    if(!navigator.share) return;
    navigator.share({title:"cush invite",url:el("inv-url").value}).catch(function(){});
  });
  el("inv-done").addEventListener("click",function(){
    // Drop the one-time link from the DOM once the admin is done with it.
    el("inv-url").value="";
    el("inv-created").classList.add("hidden");
  });

  document.addEventListener("click",function(e){
    var t=e.target.closest("[data-action]"); if(!t) return;
    var a=t.dataset.action;
    if(a==="approve"){
      // Web pairing: reveal the scope chooser instead of approving immediately.
      var ps=document.querySelector('.pair-scope[data-code="'+t.dataset.code+'"]');
      if(ps) ps.classList.remove("hidden");
    }
    else if(a==="approve-tunnel"){
      // Tunnel (frp) pairing: approve directly, no scope chooser.
      jreq("POST","/auth/admin/approve",{code:t.dataset.code}).then(hapNote).then(function(res){
        if(!res.ok){showErr((res.body&&res.body.error)||"Approve failed");}
        refresh();
      });
    }
    else if(a==="approve-cancel"){
      var ps2=t.closest(".pair-scope"); if(ps2) ps2.classList.add("hidden");
    }
    else if(a==="approve-confirm"){
      var box=t.closest(".pair-scope");
      var apps=collectScope(box,".pair-all",".pair-host");
      if(apps.length===0){showErr("Pick at least one app or choose All apps.");return;}
      jreq("POST","/auth/admin/approve",{code:t.dataset.code,apps:apps}).then(hapNote).then(function(res){
        if(!res.ok){showErr((res.body&&res.body.error)||"Approve failed");}
        refresh();
      });
    }
    else if(a==="reject"){jreq("POST","/auth/admin/reject",{code:t.dataset.code}).then(refresh);}
    else if(a==="revoke"){if(confirm("Revoke this device?"))jreq("POST","/auth/admin/revoke",{device_id:t.dataset.id}).then(hapNote).then(refresh);}
    else if(a==="set-role"){
      var toAdmin=(t.dataset.role==="admin");
      if(toAdmin && !confirm("Make this device an admin? Admins own the status panel, music and media servers.")) return;
      jreq("POST","/auth/admin/device-role",{device_id:t.dataset.id,role:t.dataset.role}).then(hapNote).then(function(res){
        if(!res.ok){showErr((res.body&&res.body.error)||"Role change failed");}
        refresh();
      });
    }
    else if(a==="invite-revoke"){
      if(!confirm("Revoke this invite? The link stops working.")) return;
      // Asked every time there is something to cut off: OK revokes the
      // devices and passes the invite handed out, Cancel leaves them working.
      var n=parseInt(t.dataset.live,10)||0, also=false;
      if(n>0) also=confirm("Also revoke the "+n+" device"+(n===1?"":"s")+" it created?\n\nOK: revoke "+(n===1?"it":"them")+" too.\nCancel: keep "+(n===1?"it":"them")+" working.");
      jreq("POST","/auth/admin/invite-revoke",{id:t.dataset.id,revoke_devices:also}).then(hapNote).then(function(res){
        if(!res.ok){showErr((res.body&&res.body.error)||"Revoke failed");}
        refresh();
      });
    }
    else if(a==="toggle-app"){
      var on=(t.dataset.on==="1");
      if(on && !confirm("Stop protecting "+t.dataset.host+"? It becomes reachable without the gate.")) return;
      jreq("POST","/auth/admin/apps",{host:t.dataset.host,action:on?"unprotect":"protect"}).then(hapNote).then(function(res){
        if(!res.ok){showErr((res.body&&res.body.error)||"Toggle failed");}
        refresh();
      });
    }
    else if(a==="edit-scope"){
      var sc=document.querySelector('.dev-scope[data-id="'+t.dataset.id+'"]');
      if(sc) sc.classList.toggle("hidden");
    }
    else if(a==="cancel-scope"){
      var sc2=t.closest(".dev-scope"); if(sc2) sc2.classList.add("hidden");
    }
    else if(a==="save-scope"){
      var dbox=t.closest(".dev-scope");
      var dapps=collectScope(dbox,".dev-all",".dev-host");
      if(dapps.length===0){showErr("Pick at least one app or choose All apps.");return;}
      jreq("POST","/auth/admin/device-apps",{device_id:t.dataset.id,apps:dapps}).then(hapNote).then(function(res){
        if(!res.ok){showErr((res.body&&res.body.error)||"Save failed");}
        refresh();
      });
    }
  });

  // Toggle the host checkboxes' enabled state when "All apps" is flipped.
  document.addEventListener("change",function(e){
    var cb=e.target;
    if(cb.classList.contains("dev-all")){
      var box=cb.closest(".dev-scope");
      box.querySelectorAll(".dev-host").forEach(function(h){h.disabled=cb.checked;});
      box.querySelectorAll(".dev-host").forEach(function(h){h.closest("label").classList.toggle("opacity-40",cb.checked);});
    } else if(cb.id==="inv-standing"){
      syncInviteStanding();
    } else if(cb.classList.contains("inv-host")){
      syncInviteLanding();
    } else if(cb.classList.contains("pair-all")){
      var pbox=cb.closest(".pair-scope");
      pbox.querySelectorAll(".pair-host").forEach(function(h){h.disabled=cb.checked;});
      pbox.querySelectorAll(".pair-host").forEach(function(h){h.closest("label").classList.toggle("opacity-40",cb.checked);});
    }
  });

  refresh();
  setInterval(function(){if(state==="dash" && !editorOpen())refresh();},5000);
})();
</script>
</body>
</html>
"""


# --- Trimmed enroll page served at /login -------------------------------------------

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>porch &middot; sign in</title>
<style nonce="__NONCE__">
  body{background:#121014;}
  .glass{background:#1B181E;}
</style>
<link rel="stylesheet" href="/auth/static/auth.css">
</head>
<body class="min-h-screen flex items-center justify-center text-slate-200 px-5">
<div class="glass border border-edge rounded-2xl p-8 w-full max-w-sm">
  <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-blue-500/30 to-indigo-600/20 border border-blue-400/30 flex items-center justify-center mb-5">
    <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6 text-blue-300" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
  </div>
  <h1 class="font-display text-2xl font-bold tracking-tight mb-1">Enroll this browser</h1>
  <p class="text-sm text-slate-400 mb-6">Enter the admin password to grant this browser access to protected apps.</p>

  <!-- password enroll (owner) -->
  <div id="pw-pane">
    <label class="block text-xs font-medium text-slate-300 mb-1.5">Password</label>
    <input id="pw" type="password" autocomplete="current-password" autofocus
      class="w-full bg-base border border-edge rounded-lg px-3 py-2.5 text-sm outline-none focus:border-blue-400 mb-3">

    <label class="block text-xs font-medium text-slate-300 mb-1.5">Device name <span class="text-slate-500 normal-case">(optional)</span></label>
    <input id="name" type="text" placeholder="Browser"
      class="w-full bg-base border border-edge rounded-lg px-3 py-2.5 text-sm outline-none focus:border-blue-400 mb-4">

    <button id="go" class="w-full bg-blue-500 hover:bg-blue-400 text-slate-950 font-semibold transition rounded-lg py-2.5 text-sm font-medium">Enroll &amp; continue</button>
    <p id="msg" class="text-sm text-rose-400 mt-3 min-h-[1.25rem]"></p>

    <div class="flex items-center gap-3 my-5">
      <div class="flex-1 h-px bg-edge"></div>
      <span class="text-[10px] uppercase tracking-wide text-slate-500">no password?</span>
      <div class="flex-1 h-px bg-edge"></div>
    </div>

    <button id="req" class="w-full bg-slate-700/60 hover:bg-slate-600 transition rounded-lg py-2.5 text-sm font-medium border border-edge">Request access (no password)</button>
    <p class="text-xs text-slate-500 mt-2 text-center">Ask the owner to approve you. No password needed.</p>
  </div>

  <!-- waiting-for-approval pane -->
  <div id="wait-pane" class="hidden text-center">
    <p class="text-sm text-slate-400 mb-4">Share this code with the owner. They'll approve you and pick which apps you can use.</p>
    <div id="wait-code" class="font-mono text-4xl tracking-widest text-blue-300 mb-5">--------</div>
    <div id="wait-status" class="flex items-center justify-center gap-2 text-sm text-slate-400 mb-4">
      <span class="inline-block w-2 h-2 rounded-full bg-amber-400 animate-pulse"></span>
      <span>Waiting for approval…</span>
    </div>
    <p id="wait-msg" class="text-sm min-h-[1.25rem] mb-3"></p>
    <button id="wait-retry" class="hidden w-full bg-blue-500 hover:bg-blue-400 text-slate-950 font-semibold transition rounded-lg py-2.5 text-sm font-medium">Try again</button>
    <button id="wait-cancel" class="w-full mt-2 text-xs text-slate-500 hover:text-slate-300 transition">Cancel</button>
  </div>
</div>
<script nonce="__NONCE__">
(function(){
  var RD = "__RD__";
  var el=function(id){return document.getElementById(id);};
  // One enrollment at a time: the password check is slow (scrypt), and every
  // extra tap or Enter while it runs used to mint another device (5 at once).
  var busy=false, goLabel=el("go").textContent;
  function done(){ busy=false; el("go").disabled=false; el("go").textContent=goLabel; }
  function enroll(){
    if(busy) return;
    var pw=el("pw").value, name=el("name").value, msg=el("msg"); msg.textContent="";
    if(!pw){msg.textContent="Enter the password.";return;}
    busy=true; el("go").disabled=true; el("go").textContent="Enrolling\u2026";
    fetch("/auth/enroll",{method:"POST",credentials:"include",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({password:pw,device_name:name,rd:RD})})
      .then(function(r){return r.json().then(function(j){return {ok:r.ok,status:r.status,body:j};});})
      .then(function(res){
        if(res.ok && res.body.ok){ window.location.href = res.body.rd || RD; return; }
        done();
        if(res.status===429){ msg.textContent="Too many attempts. Wait a minute."; }
        else{ msg.textContent="Invalid password"; }
      })
      .catch(function(){ done(); msg.textContent="Network error"; });
  }
  el("go").addEventListener("click",enroll);
  el("pw").addEventListener("keydown",function(e){if(e.key==="Enter")enroll();});
  el("name").addEventListener("keydown",function(e){if(e.key==="Enter")enroll();});

  // ---- self-service "Request access" (no password) ----
  var pollTimer=null, pollToken=null;

  function showWait(){ el("pw-pane").classList.add("hidden"); el("wait-pane").classList.remove("hidden"); }
  function showLogin(){
    if(pollTimer){clearTimeout(pollTimer);pollTimer=null;}
    pollToken=null;
    el("wait-pane").classList.add("hidden"); el("pw-pane").classList.remove("hidden");
  }
  function setStatus(html){ el("wait-status").innerHTML=html; }

  function poll(){
    if(!pollToken) return;
    fetch("/auth/web-pair/status/"+encodeURIComponent(pollToken),{credentials:"include"})
      .then(function(r){return r.json().then(function(j){return {ok:r.ok,status:r.status,body:j};});})
      .then(function(res){
        var b=res.body||{};
        if(res.status===404){ failWait("This request is no longer valid."); return; }
        if(b.status==="approved"){
          // The status response set the cush_auth cookie. Redirect to the app.
          setStatus('<span class="inline-block w-2 h-2 rounded-full bg-emerald-400"></span><span>Approved! Redirecting…</span>');
          window.location.href = b.rd || RD;
          return;
        }
        if(b.status==="rejected"){ failWait("The owner declined this request."); return; }
        if(b.status==="expired"){ failWait("This request expired. Please try again."); return; }
        // still pending
        pollTimer=setTimeout(poll,2500);
      })
      .catch(function(){ pollTimer=setTimeout(poll,3000); });
  }

  function failWait(text){
    if(pollTimer){clearTimeout(pollTimer);pollTimer=null;}
    pollToken=null;
    setStatus('<span class="inline-block w-2 h-2 rounded-full bg-rose-400"></span><span>Not approved</span>');
    var m=el("wait-msg"); m.className="text-sm text-rose-400 min-h-[1.25rem] mb-3"; m.textContent=text;
    el("wait-retry").classList.remove("hidden");
  }

  function requestAccess(){
    showWait();
    el("wait-retry").classList.add("hidden");
    el("wait-msg").textContent="";
    el("wait-code").textContent="--------";
    setStatus('<span class="inline-block w-2 h-2 rounded-full bg-amber-400 animate-pulse"></span><span>Requesting…</span>');
    fetch("/auth/web-pair/start",{method:"POST",credentials:"include",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({device_name:el("name").value,rd:RD})})
      .then(function(r){return r.json().then(function(j){return {ok:r.ok,status:r.status,body:j};});})
      .then(function(res){
        if(!res.ok || !res.body.code){
          failWait((res.body&&res.body.error)||"Could not start a request.");
          return;
        }
        pollToken=res.body.poll_token;
        el("wait-code").textContent=res.body.code;
        setStatus('<span class="inline-block w-2 h-2 rounded-full bg-amber-400 animate-pulse"></span><span>Waiting for approval…</span>');
        pollTimer=setTimeout(poll,2500);
      })
      .catch(function(){ failWait("Network error."); });
  }

  el("req").addEventListener("click",requestAccess);
  el("wait-retry").addEventListener("click",requestAccess);
  el("wait-cancel").addEventListener("click",showLogin);
})();
</script>
</body>
</html>
"""


# --- Invite landing page served at /i/<token> --------------------------------------

INVITE_HTML = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow">
<title>porch &middot; invite</title>
<style nonce="__NONCE__">
  body{background:#121014;}
  .glass{background:#1B181E;}
</style>
<link rel="stylesheet" href="/auth/static/auth.css">
</head>
<body class="min-h-screen flex items-center justify-center text-slate-200 px-5">
<div class="glass border border-edge rounded-2xl p-8 w-full max-w-sm">
  <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-blue-500/30 to-indigo-600/20 border border-blue-400/30 flex items-center justify-center mb-5">
    <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6 text-blue-300" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M19 8v6M22 11h-6"/></svg>
  </div>

  <!-- valid invite -->
  <div id="ok-pane" class="hidden">
    <h1 class="font-display text-2xl font-bold tracking-tight mb-1">You're invited</h1>
    <p class="text-sm text-slate-400 mb-4">Accept to give this browser access to:</p>
    <div id="apps" class="flex flex-wrap gap-1.5 mb-5"></div>
    <p id="ttl" class="hidden text-xs text-slate-400 mb-4"></p>
    <p id="enrolled" class="hidden text-xs text-amber-300/90 bg-amber-500/10 border border-amber-400/30 rounded-lg px-3 py-2 mb-4"></p>
    <div id="name-wrap">
      <label class="block text-xs font-medium text-slate-300 mb-1.5">Name this device <span class="text-slate-500 normal-case">(optional)</span></label>
      <input id="name" type="text" maxlength="64" placeholder="e.g. Sam's phone"
        class="w-full bg-base border border-edge rounded-lg px-3 py-2.5 text-sm outline-none focus:border-blue-400 mb-4">
    </div>
    <button id="go" class="w-full bg-blue-500 hover:bg-blue-400 text-slate-950 font-semibold transition rounded-lg py-2.5 text-sm font-medium">Accept invite</button>
    <p id="msg" class="text-sm text-rose-400 mt-3 min-h-[1.25rem]"></p>
  </div>

  <!-- already accepted by this browser -->
  <div id="done-pane" class="hidden">
    <h1 class="font-display text-2xl font-bold tracking-tight mb-1">Already accepted</h1>
    <p class="text-sm text-slate-400 mb-5">This browser already accepted this invite.</p>
    <a id="continue" href="#" class="block text-center w-full bg-blue-500 hover:bg-blue-400 text-slate-950 font-semibold transition rounded-lg py-2.5 text-sm font-medium">Continue</a>
  </div>

  <!-- invalid / expired / used / revoked -->
  <div id="bad-pane" class="hidden">
    <h1 id="bad-title" class="font-display text-2xl font-bold tracking-tight mb-1">Invite not valid</h1>
    <p id="bad-sub" class="text-sm text-slate-400">Ask the person who sent it for a new link.</p>
  </div>
</div>
<script nonce="__NONCE__">
(function(){
  var INV = "__INVITE__";
  var el=function(id){return document.getElementById(id);};
  function esc(s){return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");}
  // Only ever navigate to an https *.__PORCH_ROOT__ URL (the server already
  // sanitizes rd; this is belt-and-braces against a javascript: URL).
  function safeRd(u){return /^https:\/\/[a-z0-9-]+\.__PORCH_ROOT_RE__(\/|$)/i.test(u||"") ? u : "__PORCH_DEFAULT_RD__";}

  if(INV.status==="active"){
    el("ok-pane").classList.remove("hidden");
    var apps=INV.apps||[];
    el("apps").innerHTML=(apps.length===1&&apps[0]==="*")
      ? '<span class="text-xs px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-400/30">All protected apps</span>'
      : apps.map(function(h){return '<span class="text-xs font-mono px-2 py-0.5 rounded-full bg-slate-700/40 text-slate-300 border border-edge">'+esc(h)+'</span>';}).join("");
    var span="";
    if(INV.ttl_minutes){
      var m=INV.ttl_minutes;
      span=(m<60)?(m+" minute"+(m===1?"":"s")):(m<2880)?(Math.round(m/60)+" hour"+(Math.round(m/60)===1?"":"s")):(Math.round(m/1440)+" days");
      el("ttl").textContent="This is a guest pass: access lasts "+span+" from when you accept.";
      el("ttl").classList.remove("hidden");
    }
    if(INV.enrolled!==null && INV.enrolled!==undefined){
      var en=el("enrolled");
      en.textContent="This browser is already enrolled as “"+(INV.enrolled||"Browser")+"”. Accepting adds these apps to it"+(span?" for "+span:"")+".";
      en.classList.remove("hidden");
      el("name-wrap").classList.add("hidden");
    }
  } else if(INV.status==="accepted"){
    el("done-pane").classList.remove("hidden");
    el("continue").href=safeRd(INV.rd);
  } else {
    el("bad-pane").classList.remove("hidden");
    var titles={expired:"Invite expired",used:"Invite already used",revoked:"Invite revoked",full:"All passes are in use"};
    el("bad-title").textContent=titles[INV.status]||"Invite not valid";
    // A full standing link is not dead: passes free up as they expire.
    if(INV.status==="full") el("bad-sub").textContent="Every guest pass is in use right now. Please try again later.";
  }

  var busy=false;
  function accept(){
    if(busy) return;
    var msg=el("msg"); msg.textContent="";
    var tok=location.pathname.replace(/^\/i\//,"").replace(/\/+$/,"");
    busy=true; el("go").disabled=true; el("go").textContent="Accepting…";
    fetch("/i/"+encodeURIComponent(tok)+"/accept",{method:"POST",credentials:"include",
      headers:{"Content-Type":"application/json"},body:JSON.stringify({device_name:el("name").value})})
      .then(function(r){return r.json().then(function(j){return {ok:r.ok,status:r.status,body:j};})
        .catch(function(){return {ok:r.ok,status:r.status,body:{}};});})
      .then(function(res){
        if(res.ok && res.body.ok){ window.location.href=safeRd(res.body.rd); return; }
        busy=false; el("go").disabled=false; el("go").textContent="Accept invite";
        if(res.status===429){ msg.textContent="Too many attempts. Wait a minute."; }
        else if(res.body&&res.body.full){ msg.textContent="All guest passes are in use right now. Please try again later."; }
        else if(res.status===410||res.status===404){ msg.textContent="This invite is no longer valid."; }
        else{ msg.textContent=(res.body&&res.body.error)||"Could not accept the invite."; }
      })
      .catch(function(){ busy=false; el("go").disabled=false; el("go").textContent="Accept invite"; msg.textContent="Network error"; });
  }
  el("go").addEventListener("click",accept);
  el("name").addEventListener("keydown",function(e){if(e.key==="Enter")accept();});
})();
</script>
</body>
</html>
"""


def load_auth_css():
    """Read lib/auth.css into memory. A missing file is logged, not fatal: the
    gate matters more than its styling, and bin/auth-deploy checks the file
    before it restarts anything."""
    global AUTH_CSS, AUTH_CSS_ETAG
    try:
        with open(AUTH_CSS_FILE, "rb") as f:
            AUTH_CSS = f.read()
    except OSError as e:
        AUTH_CSS, AUTH_CSS_ETAG = None, ""
        log(f"WARNING: cannot read {AUTH_CSS_FILE} ({e}); pages will be unstyled. Run bin/auth-css.")
        return
    AUTH_CSS_ETAG = '"' + hashlib.sha256(AUTH_CSS).hexdigest()[:32] + '"'


class AuthServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# --- main ---------------------------------------------------------------------------

def configure_maps(maps_dir):
    """Point the map globals at maps_dir, or switch the HAProxy map sync off
    (None: porch's fresh profile renders no edge gate, so HAProxy loads no
    maps and the porch user is deliberately not in the haproxy group)."""
    global MAPS_DIR, DEVICES_MAP, PROTECTED_MAP, GRANTS_MAP, IDENTITY_MAP
    global PUBLIC_MAP, PUBLIC_EXACT_MAP
    if maps_dir is None:
        MAPS_DIR = DEVICES_MAP = PROTECTED_MAP = GRANTS_MAP = IDENTITY_MAP = None
        PUBLIC_MAP = PUBLIC_EXACT_MAP = None
        return
    MAPS_DIR = os.path.abspath(maps_dir)
    DEVICES_MAP = os.path.join(MAPS_DIR, "cush-devices.map")
    PROTECTED_MAP = os.path.join(MAPS_DIR, "cush-protected.map")
    GRANTS_MAP = os.path.join(MAPS_DIR, "cush-grants.map")
    IDENTITY_MAP = os.path.join(MAPS_DIR, "cush-identity.map")
    PUBLIC_MAP = os.path.join(MAPS_DIR, "cush-public.map")
    PUBLIC_EXACT_MAP = os.path.join(MAPS_DIR, "cush-public-exact.map")


def initial_map_sync():
    hap = sync_haproxy_maps()
    if hap == "skipped":
        log("HAProxy map sync: off (no edge gate; --no-maps)")
    elif hap != "ok":
        log(f"WARNING: initial HAProxy map push: {hap}")
    return hap


def main():
    global DATA_DIR, DEVICES_PATH

    parser = argparse.ArgumentParser(description="cush-tools auth server")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--data", type=str, required=True, help="Data directory")
    parser.add_argument("--bind", type=str, default="127.0.0.1",
                        help="Listen address (default 127.0.0.1; keep it loopback)")
    parser.add_argument(
        "--maps-dir", type=str, default="/etc/haproxy/maps",
        help="Directory for HAProxy forward-auth map files",
    )
    parser.add_argument(
        "--no-maps", action="store_true",
        help="HAProxy has no edge gate (porch's fresh profile): write no map files and "
             "never touch its admin socket",
    )
    args = parser.parse_args()

    DATA_DIR = os.path.abspath(args.data)
    os.makedirs(DATA_DIR, exist_ok=True)
    DEVICES_PATH = os.path.join(DATA_DIR, "devices.json")

    configure_maps(None if args.no_maps else args.maps_dir)

    acquire_server_lock()
    load_state()
    load_auth_css()
    write_cli_token()
    ensure_home_device()
    log("localhost frpc bypass: " + ("ON (adopted install; see CLAUDE.md "
        "'Home frpc token' to switch it off)" if LOCALHOST_BYPASS else "off"))
    ensure_setup_token()
    initial_map_sync()
    signal.signal(signal.SIGHUP, handle_sighup)

    # background workers
    threading.Thread(target=reload_worker, daemon=True).start()
    threading.Thread(target=writer_worker, daemon=True).start()
    threading.Thread(target=sweeper_worker, daemon=True).start()

    if args.bind not in ("127.0.0.1", "::1", "localhost"):
        log(f"WARNING: binding {args.bind}; the CLI token and /verify assume loopback")
    AuthServer.address_family = _socket.AF_INET6 if ":" in args.bind else _socket.AF_INET
    server = AuthServer((args.bind, args.port), AuthHandler)
    log(f"Listening on {args.bind}:{args.port} (data={DATA_DIR})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("Shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()

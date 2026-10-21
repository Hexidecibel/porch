#!/usr/bin/env python3

"""Pocket server (used by bin/pocket): a phone share target + clipboard handoff.

One owner-only page at https://<name>.<tunnel_base>/ that does two things:

  * Inbox. Installed as a PWA on Android, Pocket shows up in the system share
    sheet (Web Share Target): sharing a photo, a file or a link POSTs it to
    /share, files land in ~/pocket/<name>/inbox/ and text/links become a
    clipboard entry. The page can also upload (resumable, lib/porch_tus.py,
    mounted at /tus/) and lists, downloads and deletes what is there.
  * Clipboard. One shared slot plus the last 20 entries. Copy on the phone,
    tap "Paste from this device", and it is one tap away on the desktop (or
    `porch clip` in a terminal), and back. Every change is pushed to open
    pages over Server-Sent Events (/api/events).

Access:

  * Everything except the PWA manifest, its icons, the service worker and
    the design-system assets is the owner's: a browser porch_auth accepts
    (porch_host for this host, or the legacy cush_auth cookie) as a live
    admin device in --devices. No registry, or no match: nobody gets in
    (fail closed). A visitor gets a small page with "Owner? Sign in" and
    nothing else.
  * Every write needs a same-origin Origin/Referer, with one exception:
    POST /share also accepts a request with no Origin/Referer (or Origin
    'null') when it carries Sec-Fetch-Site: none, which is what a
    browser-initiated share-target navigation looks like. No page can forge
    that header, and the owner cookie still has to be on the request.
  * `porch clip` (lib/porch_setup/cmd_clip.py) uses a local token instead of
    a cookie. A fresh one is written 0600 at start to the private run dir
    (lib/rundir.py: <run dir>/pocket/<name>.token) and is accepted only from
    a loopback peer addressed as 127.0.0.1/localhost, and only when the
    request carries none of X-Forwarded-*, Forwarded, X-Real-IP, Via, Origin
    or Referer. HAProxy stamps X-Forwarded-For on every request it passes
    to the tunnel, so the token never works from the network.

Data: inbox files in <dir>/inbox/ (partials in inbox/.tus/), the clipboard in
<dir>/.clip.json (0600; <dir> is made 0700). It may hold anything the owner
copied, so it never leaves this box except through the owner's own page.
"""

import argparse
import hmac
import html
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import door_recipe  # noqa: E402  (launch recipes: reopen a door; retained files)
import door_state  # noqa: E402  (door state files: Make link / the links panel)
import porch_auth  # noqa: E402  (the one owner check: porch_host + legacy cush_auth)
import porch_tus  # noqa: E402  (resumable uploads at /tus/)
import reopen_requests  # noqa: E402  (asks to reopen a closed door, from its closed page)
import rundir  # noqa: E402  (private run dir for the CLI token)
from porch_http import (  # noqa: E402  (shared HTTP core)
    DEFAULT_MAX_CONNECTIONS, DEFAULT_MIN_FREE_MB, HardenedHandlerMixin,
    MultipartError, Quota, UploadRejected, UploadSlots,
    TRUSTED_PROXY_PEERS, atomic_write_bytes, client_ip, content_length,
    csp_nonce, drop_tmp, human_size, install_sigterm_cleanup, make_server,
    multipart_boundary, new_tmp, page_csp, place_unique, porch_css_tag,
    porch_mark, read_json_body, safe_child, same_origin, security_headers,
    serve_asset, stream_file, sweep_stale_parts,
)
from porch_http import BoundedThreadingHTTPServer  # noqa: E402,F401  (re-exported)
# Pocket's stores, Make link and the asset table live in their own modules
# (lib/pocket_core.py, lib/pocket_links.py, lib/pocket_assets.py); every name
# the handler and the tests use is re-exported here.
from pocket_core import (  # noqa: E402,F401  (moved; re-exported)
    CLI_TOKEN_HEADER, ClipStore, DEFAULT_MAX_TOTAL_MB, FieldStreamer, Hub, INLINE_TYPES,
    KEY_FAIL_RATE, KEY_RATE, KeyStore, MAX_CLIP_BYTES, MAX_FIELD_BYTES, MAX_FILES,
    MAX_FILE_SIZE, MAX_HISTORY, NOT_LOCAL_HEADERS, RateLimit, SHARE_KEY_HEADER, SSE_HEARTBEAT,
    SEALED_ORPHAN_AGE, SSE_MAX_AGE, SSE_MAX_TOTAL, _CLIP_ID, _SEALED_NAME, _KEY_ID, _LOCAL_HOST, _dir_sig, clean_label,
    cli_token_path, device_hint, inbox_usage, list_inbox, name_candidates, sanitize_filename,
    sealed_create, sealed_files, sealed_head, sealed_usage,
    MAX_KEY_LABEL, MAX_NAME, MAX_SHARE_KEYS, SEAL_DATA_START, SEAL_MAGIC, SEAL_RECORD,
    SHARE_KEY_PREFIX, SSE_MAX_PER_CLIENT, _FIELDNAME, _FILENAME, _PHONE_UA, _SHARE_KEY,
    _hash_key, sealed_length_ok,
)
from pocket_links import (  # noqa: E402,F401  (moved; re-exported)
    LAUNCHER_ENV_DROP, LINK_TIMEOUT, LinkError, LinkTimeout, MAX_LINKS,
    _LINK_NAME, _clean_line, _pid_alive, close_door, launcher_env, links_sig,
    new_link_name, parse_link_rules, pocket_links, public_link, run_launcher, tunnel_url,
    LINK_EXPIRY, MAX_LINK_OPENS, link_slug,
)
import pocket_assets  # noqa: E402  (hashed /static/ table)
import auth_client  # noqa: E402  (porch-auth's CLI-token API)
import door_ops  # noqa: E402  (the door control plane, shared with statusserver)
from door_ops import DoorOpError  # noqa: E402
from pocket_audit import AuditLog  # noqa: E402,F401
from pocket_doors import DoorsMixin, doors_sig, history_sig, parse_query, HISTORY_MIN_INTERVAL  # noqa: E402,F401
from pocket_people import AuthOpError, AuthWatcher, PeopleMixin, access_view, pairings_view, people_view  # noqa: E402,F401
from pocket_stepup import (  # noqa: E402,F401
    ChallengeStore, PasskeyStore, STEPUP_COOKIE, StepUpMixin, StepUpStore,
)
from pocket_assets import (  # noqa: E402,F401  (moved; re-exported)
    GROUND, ICONS, ICON_DIR, LINKS_CLIENT_JS, PAGE_HTML, QR_CLIENT_JS, SERVICE_WORKER_JS,
    STATIC_JS, build_icons, manifest, ACCENT, TEXT, icon_svg, _load_icons,
)


# ---- pages -------------------------------------------------------------------

HEAD_HTML = """<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="__GROUND__">
<link rel="icon" href="/icon.svg" type="image/svg+xml">
__PORCH_CSS__"""

REFUSE_HTML = """<!DOCTYPE html>
<html lang="en" data-app="exchange">
<head>
__HEAD__
<title>Porch</title>
</head>
<body>
<main class="p-shell p-shell--narrow">
  <header class="p-head">
    <div class="p-kicker">__MARK__<span>a private pocket</span></div>
    <h1 class="p-title">__HEADING__</h1>
    <p class="p-lede">__TEXT__</p>
  </header>
  __ACTION__
</main>
</body>
</html>"""

# /reopen/<id>: one ask to reopen, opened from its notification (a tap on
# iOS, or anywhere but the Allow buttons on Android). Owner-only, like the rest.
REOPEN_HTML = r"""<!DOCTYPE html>
<html lang="en" data-app="exchange">
<head>
__HEAD__
<title>Reopen? · Porch</title>
<style nonce="__NONCE__">
.facts{margin:0;display:flex;flex-direction:column}
.facts div{display:grid;grid-template-columns:6.5em minmax(0,1fr);gap:12px;padding:12px 0;border-bottom:1px solid var(--line)}
.facts div:last-child{border-bottom:0;padding-bottom:0}
.facts div:first-child{padding-top:0}
.facts dt{font-size:13px;color:var(--muted)}
.facts dd{margin:0;font-size:15px;color:var(--text);overflow-wrap:anywhere}
.facts .mono{font-family:var(--font-mono);font-size:14px;color:var(--accent-ink)}
.decide{display:flex;flex-direction:column;gap:10px}
.state{display:flex;gap:10px;align-items:center}
.small{font-size:13px;color:var(--muted);margin:0}
.back{align-self:flex-start}
main{display:flex;flex-direction:column;gap:18px;padding-bottom:max(24px,env(safe-area-inset-bottom))}
</style>
</head>
<body>
<main class="p-shell p-shell--narrow">
  <header class="p-head">
    <div class="p-kicker">__MARK__<span>asked to reopen</span></div>
    <h1 class="p-title" id="title"></h1>
    <p class="p-lede" id="lede"></p>
  </header>
  <div class="p-card">
    <dl class="facts">
      <div><dt>Who</dt><dd id="who"></dd></div>
      <div><dt>Asked</dt><dd id="asked"></dd></div>
      <div><dt>Door</dt><dd class="mono" id="door"></dd></div>
      <div id="closedRow"><dt>Closed</dt><dd id="closed"></dd></div>
    </dl>
  </div>
  <div class="p-notice" id="notice" role="status" aria-live="polite" hidden></div>
  <div class="decide" id="decide">
    <button type="button" class="p-btn p-btn--lg p-btn--block" data-d="allow" data-e="1h">Allow 1 hour</button>
    <button type="button" class="p-btn p-btn--ghost p-btn--lg p-btn--block" data-d="allow" data-e="24h">Allow 24 hours</button>
    <button type="button" class="p-btn p-btn--quiet p-btn--lg p-btn--block" data-d="deny">Deny</button>
    <p class="small">Allowing opens it again exactly as it was: the same link, password and guest link. Their page comes in by itself.</p>
  </div>
  <a class="p-btn p-btn--quiet back" href="/" id="back">Open your pocket</a>
</main>
<script type="application/json" id="data">__DATA_JSON__</script>
<script nonce="__NONCE__">
"use strict";
const R = JSON.parse(document.getElementById('data').textContent);
const $ = (id) => document.getElementById(id);
function ago(ts){
  const s = Math.max(0, Date.now()/1000 - ts);
  if(s < 60) return 'just now';
  if(s < 3600) return Math.round(s/60) + ' min ago';
  if(s < 86400) return Math.round(s/3600) + ' h ago';
  return Math.round(s/86400) + ' d ago';
}
function show(state, extra){
  const n = $('notice');
  const open = state === 'pending';
  $('decide').hidden = !open;
  $('title').textContent = state === 'approved' ? '\u201c' + R.name + '\u201d is open again'
    : state === 'denied' ? 'You said not now' : state === 'expired' ? 'This ask ran out'
    : 'Reopen \u201c' + R.name + '\u201d?';
  $('lede').textContent = state === 'approved' ? 'Open ' + (R.expires === '24h' ? 'for 24 hours' : 'for an hour') + '. Their page reloads into it by itself.'
    : state === 'denied' ? 'They see \u201cThe owner said not now.\u201d'
    : state === 'expired' ? 'Asks wait 30 minutes. They can ask again from the same link.'
    : 'Someone opened this link after it closed and asked you to open it again.';
  if(extra){ n.textContent = extra.text; n.className = 'p-notice p-notice--' + extra.kind; n.hidden = false; }
  else n.hidden = true;
}
$('who').textContent = R.note || 'No name given';
$('asked').textContent = ago(R.created) + (R.ip ? ' \u00b7 from ' + R.ip : '') + (R.waiting > 1 ? ' \u00b7 ' + R.waiting + ' people waiting' : '');
$('door').textContent = R.url.replace(/^https:\/\//, '').replace(/\/$/, '') + (R.type ? ' \u00b7 ' + R.type : '');
if(R.closed) $('closed').textContent = (R.reason === 'expired' ? 'Expired ' : 'Closed ') + ago(R.closed);
else $('closedRow').hidden = true;
show(R.state === 'opening' ? 'pending' : R.state);
document.querySelectorAll('#decide button').forEach((b)=>{
  b.addEventListener('click', ()=>{
    const body = {decision: b.dataset.d};
    if(b.dataset.e) body.expires = b.dataset.e;
    document.querySelectorAll('#decide button').forEach((x)=>{ x.disabled = true; });
    b.textContent = b.dataset.d === 'deny' ? 'Telling them\u2026' : 'Opening\u2026';
    fetch('/api/reopen/' + encodeURIComponent(R.id), {method: 'POST', credentials: 'same-origin',
      headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)})
      .then((r)=>r.json().catch(()=>({})).then((j)=>{
        if(!r.ok) throw new Error(j.message || ('HTTP ' + r.status));
        Object.assign(R, j.request || {});
        show(R.state, R.state === 'approved' ? {kind: 'ok', text: 'Done. ' + R.url} : null);
      }))
      .catch((err)=>{
        show('pending', {kind: 'error', text: err.message});
        document.querySelectorAll('#decide button').forEach((x)=>{ x.disabled = false; });
        b.textContent = b.dataset.d === 'deny' ? 'Deny' : (b.dataset.e === '1h' ? 'Allow 1 hour' : 'Allow 24 hours');
      });
  });
});
</script>
</body>
</html>"""


# ---- the control-plane route table -------------------------------------------
#
# Every route here is the owner's (porch_auth: porch_host or the legacy
# cush_auth cookie); the `porch clip` CLI token never counts. A POST needs a
# same-origin Origin/Referer AND Content-Type: application/json (so a
# cross-origin attempt needs a CORS preflight), and a JSON object body no
# larger than `cap`. `stepup`: True = always needs a fresh step-up (★);
# 'cond' = the handler decides (rules that widen access, invite revoke with
# its devices, passkey register); False = never.

_N = r'([a-z0-9][a-z0-9-]{0,40})'
_ID = r'([A-Za-z0-9_-]{1,64})'
_PK = r'([A-Za-z0-9_-]{16,1400})'
_CODE = r'([A-Z]{4}-[0-9]{4})'
_RID = r'([0-9]{1,12})'
CAP = 8 * 1024

ROUTES = [
    # method, path regex, handler, stepup, body cap
    ('GET', r'/api/app', 'api_app', False, 0),
    ('GET', r'/api/activity', 'api_activity', False, 0),
    ('GET', r'/api/doors', 'api_doors', False, 0),
    ('GET', r'/api/doors/history', 'api_doors_history', False, 0),
    ('GET', rf'/api/doors/{_N}/requests', 'api_door_requests', False, 0),
    ('GET', rf'/api/doors/{_N}/requests/events', 'api_door_request_events', False, 0),
    ('GET', rf'/api/doors/{_N}/requests/{_RID}', 'api_door_request', False, 0),
    ('GET', r'/api/requests', 'api_requests', False, 0),
    ('GET', r'/api/people', 'api_people', False, 0),
    ('GET', r'/api/people/public-paths', 'api_public_paths', False, 0),
    ('GET', r'/api/passkeys', 'api_passkeys', False, 0),

    ('POST', r'/api/doors/stop-all', 'api_doors_stop_all', True, CAP),
    ('POST', r'/api/doors/launch', 'api_doors_launch', False, 2 * 1024 * 1024),
    ('POST', rf'/api/doors/history/{_N}/reopen', 'api_history_reopen', False, CAP),
    ('POST', rf'/api/doors/history/{_N}/revive', 'api_history_revive', False, CAP),
    ('POST', rf'/api/doors/history/{_N}/forget', 'api_history_forget', False, CAP),
    ('POST', rf'/api/doors/{_N}/extend', 'api_door_extend', False, CAP),
    ('POST', rf'/api/doors/{_N}/expire', 'api_door_expire', False, CAP),
    ('POST', rf'/api/doors/{_N}/stop', 'api_door_stop', False, CAP),
    ('POST', rf'/api/doors/{_N}/rules', 'api_door_rules', 'cond', CAP),
    ('POST', rf'/api/doors/{_N}/requests/{_RID}/replay', 'api_door_replay', False, CAP),

    ('POST', rf'/api/requests/pairings/{_CODE}/approve', 'api_pairing_approve', True, CAP),
    ('POST', rf'/api/requests/pairings/{_CODE}/reject', 'api_pairing_reject', False, CAP),
    ('POST', rf'/api/requests/access/{_ID}/allow', 'api_access_allow', True, CAP),
    ('POST', rf'/api/requests/access/{_ID}/deny', 'api_access_deny', False, CAP),

    ('POST', rf'/api/people/devices/{_ID}/revoke', 'api_device_revoke', True, CAP),
    ('POST', rf'/api/people/devices/{_ID}/role', 'api_device_role', True, CAP),
    ('POST', rf'/api/people/devices/{_ID}/apps', 'api_device_apps', True, CAP),
    ('POST', rf'/api/people/devices/{_ID}/rename', 'api_device_rename', False, CAP),
    ('POST', r'/api/people/invites', 'api_invite_create', True, CAP),
    ('POST', rf'/api/people/invites/{_ID}/revoke', 'api_invite_revoke', 'cond', CAP),
    ('POST', r'/api/people/apps', 'api_apps', True, CAP),
    ('POST', r'/api/people/public-paths', 'api_public_path_add', True, CAP),
    ('POST', rf'/api/people/public-paths/{_ID}/on', 'api_public_path_on', True, CAP),
    ('POST', rf'/api/people/public-paths/{_ID}/off', 'api_public_path_off', False, CAP),
    ('POST', rf'/api/people/public-paths/{_ID}/remove', 'api_public_path_remove', False, CAP),
    ('POST', r'/api/people/password', 'api_password', True, CAP),

    ('POST', r'/api/stepup/options', 'api_stepup_options', False, CAP),
    ('POST', r'/api/stepup/passkey', 'api_stepup_passkey', False, 64 * 1024),
    ('POST', r'/api/stepup/password', 'api_stepup_password', False, CAP),
    ('POST', r'/api/stepup/end', 'api_stepup_end', False, CAP),
    ('POST', r'/api/passkeys/register/options', 'api_passkey_register_options', True, CAP),
    ('POST', r'/api/passkeys/register', 'api_passkey_register', 'cond', 160 * 1024),
    ('POST', rf'/api/passkeys/{_PK}/rename', 'api_passkey_rename', False, CAP),
    ('POST', rf'/api/passkeys/{_PK}/delete', 'api_passkey_delete', True, CAP),

    ('POST', r'/api/push/topics', 'api_push_topics', False, CAP),
]
_ROUTES = [(m, re.compile(p), h, s, c) for m, p, h, s, c in ROUTES]
DEFAULT_CODES = {404: 'not_found', 409: 'conflict', 429: 'rate_limited', 503: 'auth_down'}

def shell_csp(nonce):
    """The app shell's CSP (plan 1.3): scripts and styles from this origin
    (hashed files, /static/seal.js, porch.css) plus the nonced config block;
    blob: images for previews; nothing inline, no forms, no framing."""
    return ("default-src 'none'; "
            f"script-src 'self' 'nonce-{nonce}'; style-src 'self' 'nonce-{nonce}'; "
            "font-src 'self'; img-src 'self' data: blob:; connect-src 'self'; "
            "manifest-src 'self'; worker-src 'self'; "
            "form-action 'none'; base-uri 'none'; frame-ancestors 'none'")


def _git_version():
    """The checkout's short commit hash (shown under You > About), read once
    at import; None outside a git checkout."""
    try:
        out = subprocess.run(['git', '-C', os.path.dirname(_HERE), 'rev-parse', '--short', 'HEAD'],
                             capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    v = out.stdout.strip()
    return v if out.returncode == 0 and re.fullmatch(r'[0-9a-f]{4,40}', v) else None


APP_VERSION = _git_version()

PERMISSIONS_POLICY = ('publickey-credentials-get=(self), publickey-credentials-create=(self), '
                      'camera=(), microphone=(), geolocation=()')


def _is_json(handler):
    ctype = (handler.headers.get('Content-Type') or '').split(';', 1)[0].strip().lower()
    return ctype == 'application/json'


# ---- handler -----------------------------------------------------------------

class PocketHandler(StepUpMixin, DoorsMixin, PeopleMixin, HardenedHandlerMixin,
                    BaseHTTPRequestHandler):

    protocol_version = 'HTTP/1.1'

    base_dir = Path('.')
    inbox_dir = Path('inbox')
    devices_path = ''
    title = 'Porch'
    cli_token = ''              # '' = the CLI token path is off
    store = None                # ClipStore
    hub = None                  # Hub
    keys = None                 # KeyStore (device share keys); None = off
    key_rate = None             # RateLimit per key id
    key_fail = None             # RateLimit of wrong keys per client address
    max_file = MAX_FILE_SIZE
    max_total = DEFAULT_MAX_TOTAL_MB * 1024 * 1024
    max_files = MAX_FILES
    min_free = DEFAULT_MIN_FREE_MB * 1024 * 1024
    upload_slots = UploadSlots(total=4, per_ip=2)
    sse_heartbeat = SSE_HEARTBEAT
    sse_max_age = SSE_MAX_AGE
    pocket_name = 'pocket'      # tags the doors Make link opens
    state_dir = door_state.STATE_DIR
    sealed_dir = None           # end-to-end encrypted uploads; None = <base_dir>/sealed
    link_runner = staticmethod(run_launcher)
    link_closer = staticmethod(close_door)
    link_timeout = LINK_TIMEOUT
    max_links = MAX_LINKS
    link_lock = threading.Lock()
    reopen_store = None         # reopen_requests.Store; None = the run dir's (tests override)
    reopener = None             # (name, expires) -> state; None = door_recipe.reopen
    push_claim = None           # VAPID sub; None = https://<landing host>/
    audit = None                # AuditLog; None = <base_dir>/.audit.jsonl
    pocket_host = ''            # the public host (/api/app); '' = rp_id
    tunnel_base = ''            # <name>.<tunnel_base> doors (the page links only those)

    _quota = None
    _quota_lock = threading.Lock()
    _tus = None
    _tus_lock = threading.Lock()
    _sealed_tus = None

    @classmethod
    def quota(cls):
        """The inbox's shared Quota; unfinished tus uploads count as landed."""
        with cls._quota_lock:
            q = cls.__dict__.get('_quota')
            if q is None:
                def scan():
                    # Sealed uploads count too: one quota for everything here.
                    used, files = inbox_usage(cls.inbox_dir)
                    s_used, s_files = sealed_usage(cls.sealed_root())
                    p_used, p_files = cls.tus().pending_usage()
                    q_used, q_files = cls.sealed_tus().pending_usage()
                    return used + s_used + p_used + q_used, files + s_files + p_files + q_files
                q = Quota(cls.inbox_dir, scan, cls.max_total, cls.max_files, cls.min_free,
                          label='pocket', item_word='files')
                cls._quota = q
            return q

    @classmethod
    def tus(cls):
        with cls._tus_lock:
            t = cls.__dict__.get('_tus')
            if t is None:
                t = porch_tus.TusServer(cls.inbox_dir, quota=cls.quota, max_size=cls.max_file,
                                        finalize=cls._tus_finalize, tag='pocketserver')
                cls._tus = t
            return t

    @classmethod
    def sealed_root(cls):
        return Path(cls.sealed_dir) if cls.sealed_dir else Path(cls.base_dir) / 'sealed'

    @classmethod
    def sealed_tus(cls):
        """/tus-sealed/: ciphertext from the page's Sealer. Only the porch-seal
        magic is checked (on_head); the rest is never sniffed or verified."""
        with cls._tus_lock:
            t = cls.__dict__.get('_sealed_tus')
            if t is None:
                cls.sealed_root().mkdir(mode=0o700, exist_ok=True)
                t = porch_tus.TusServer(cls.sealed_root(), quota=cls.quota, max_size=cls.max_file,
                                        finalize=cls._sealed_finalize, on_head=sealed_head,
                                        on_create=sealed_create, prefix='/tus-sealed/',
                                        tag='pocketserver')
                cls._sealed_tus = t
            return t

    @classmethod
    def _sealed_finalize(cls, part, up, handler):
        os.chmod(part, 0o600)
        name = place_unique(part, cls.sealed_root(),
                            (secrets.token_urlsafe(16) + '.pseal' for _ in range(16)))
        os.chmod(cls.sealed_root() / name, 0o600)
        return name

    @classmethod
    def _tus_finalize(cls, part, up, handler):
        name = place_unique(part, cls.inbox_dir,
                            name_candidates(sanitize_filename(up.metadata.get('filename') or 'upload')))
        if cls.hub:
            cls.hub.bump('inbox')
        return name

    def log_message(self, format, *args):
        method = args[0] if args else ''
        if isinstance(method, str) and method.startswith('GET'):
            return
        sys.stderr.write(f"[pocketserver] {self.address_string()} - {format % args}\n")

    # ---- identity ----

    def _is_owner(self):
        return porch_auth.request_is_owner(self, self.devices_path)

    def _cli_ok(self):
        """The local CLI token, from this box only (see the module docstring)."""
        given = self.headers.get(CLI_TOKEN_HEADER)
        if not given or not self.cli_token:
            return False
        if self.client_address[0] not in TRUSTED_PROXY_PEERS:
            return False
        if any(self.headers.get(h) is not None for h in NOT_LOCAL_HEADERS):
            sys.stderr.write("[pocketserver] CLI token on a forwarded/page request; ignored\n")
            return False
        if not _LOCAL_HOST.match((self.headers.get('Host') or '').strip().lower()):
            return False
        return hmac.compare_digest(given.encode('utf-8'), self.cli_token.encode('utf-8'))

    def _presented_key(self):
        """The device share key on this request (Authorization: Bearer, or
        X-Porch-Share-Key), or None. Never logged."""
        auth = (self.headers.get('Authorization') or '').strip()
        if auth[:7].lower() == 'bearer ':
            return auth[7:].strip()
        key = self.headers.get(SHARE_KEY_HEADER)
        return key.strip() if key is not None else None

    def _share_origin_ok(self):
        """same_origin(), or a browser-initiated share-target navigation:
        no Origin/Referer (or Origin 'null') with Sec-Fetch-Site: none."""
        if same_origin(self):
            return True
        origin = self.headers.get('Origin')
        if self.headers.get('Referer') or (origin is not None and origin != 'null'):
            return False
        return (self.headers.get('Sec-Fetch-Site') or '').strip().lower() == 'none'

    # ---- responses ----

    def send_json(self, data, status=200, headers=None):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if self.close_connection:
            self.send_header('Connection', 'close')
        security_headers(self)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def _drain(self, cap=64 * 1024):
        """Read and discard a small body the route has no use for (the page
        sends {} with a delete), so a kept-alive connection stays in step."""
        n = content_length(self)
        if 0 < n <= cap:
            self.rfile.read(n)
        elif n != 0:
            self.close_connection = True

    def _refuse_json(self, status, message):
        if self.command in ('POST', 'PATCH', 'PUT', 'DELETE') and content_length(self) != 0:
            self.close_connection = True
        self.send_json({'status': 'error', 'message': message}, status)

    def _send_bytes(self, status, body, ctype, cache='no-store', csp=None, extra=None):
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', cache)
        if csp:
            self.send_header('Content-Security-Policy', csp)
        if ctype.startswith('text/html'):
            self.send_header('Permissions-Policy', PERMISSIONS_POLICY)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        if self.close_connection:
            self.send_header('Connection', 'close')
        security_headers(self)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def _api_error(self, status, message, code=None, headers=None, **extra):
        out = {'status': 'error', 'message': message}
        code = code or DEFAULT_CODES.get(status)
        if code:
            out['code'] = code
        out.update(extra)
        if self.command in ('POST', 'PATCH', 'PUT', 'DELETE') and content_length(self) != 0 \
                and not getattr(self, '_body_read', False):
            self.close_connection = True
        self.send_json(out, status, headers)

    def _audit_log(self):
        if self.audit is None:
            type(self).audit = AuditLog(Path(self.base_dir) / '.audit.jsonl')
        return self.audit

    def _audit(self, action, target='', result='ok', code='', detail='', method=None):
        if method is None:
            method = self.stepup_status().get('method') or ''
        if action.startswith('door.') and self.hub is not None:
            self.hub.bump('doors')          # open pages hear it now, not at the next ping
        self._audit_log().append(action, target, method, client_ip(self), result, code, detail)

    # ---- the route table ----

    def _route(self, method):
        """Serve a control-plane route (ROUTES). False when the path is not
        one of them (the legacy routes go on as before)."""
        path = self._path()
        for m, rx, name, stepup, cap in _ROUTES:
            if m != method:
                continue
            match = rx.fullmatch(path)
            if match:
                break
        else:
            return False
        self._body_read = False
        if not self._is_owner():                # never the CLI token
            self._deny(True)
            return True
        if method == 'POST':
            if not same_origin(self):
                self._api_error(403, 'Cross-origin request refused', 'csrf')
                return True
            if not _is_json(self):
                self._api_error(415, 'Send application/json', 'bad_content_type')
                return True
            n = content_length(self)
            if n > cap or n < 0:
                self._api_error(413, 'Request body too large', 'too_large')
                return True
            data = read_json_body(self, cap)
            self._body_read = True
            if data is None:
                self._api_error(400, 'Expected a JSON object', 'bad_request')
                return True
        else:
            data = parse_query(urllib.parse.urlparse(self.path).query)
        if stepup is True and not self.require_stepup():
            return True
        try:
            getattr(self, name)(data, *match.groups())
        except (DoorOpError, AuthOpError) as e:
            self._api_error(e.status, e.message, e.code, **e.extra)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f"[pocketserver] {method} {path} failed: {e.__class__.__name__}\n")
            self.close_connection = True
            try:
                self._api_error(500, 'Server error', 'server_error')
            except OSError:
                pass
        return True

    # ---- app + activity + push topics ----

    def api_app(self, query):
        import porch_push
        ctx = self.owner_ctx() or {}
        try:
            n_doors = sum(1 for d in door_ops.list_doors(self.state_dir, unmanaged=False,
                                                         cleanup=False, log=lambda m: None)
                          if not self._is_self_door(d))
        except OSError:
            n_doors = 0
        pending = sum(1 for r in self._requests() if r.get('state') in ('pending', 'opening'))
        w = self.watcher
        snap = w.current() if w is not None else None
        pending += len(pairings_view(snap or {}))
        pending += sum(1 for a in access_view(snap or {}) if a['state'] == 'pending')
        public = sum(1 for p in people_view(snap or {})['public_paths'] if p['active'])
        st = self.stepup_status()
        store = self._passkey_store()
        host = self.pocket_host or self.rp_id
        self.send_json({
            'status': 'ok', 'now': int(time.time()),
            'pocket': {'name': self.pocket_name, 'title': self.title, 'host': host,
                       'origin': self.rp_origin},
            'me': {'device_id': ctx.get('device_id'), 'device_name': ctx.get('device_name')},
            'stepup': st,
            'passkeys': {'count': len(store.usable()), 'unusable': len(store.credentials()) -
                         len(store.usable()), 'rp_id': self.rp_id},
            'push': {'supported': porch_push.available()},
            'auth': self.auth_info(),
            'counts': {'doors': n_doors, 'requests': pending, 'public_paths': public},
        })

    def api_activity(self, query):
        try:
            limit = int(query.get('limit', '100'))
        except ValueError:
            limit = 100
        self.send_json(self._audit_log().recent(limit))

    def api_push_topics(self, data):
        import porch_push
        store = self._push_store()
        ep = data.get('endpoint')
        if not isinstance(ep, str) and isinstance(data.get('id'), str):
            ep = next((s['endpoint'] for s in store.load()
                       if porch_push.sub_id(s['endpoint']) == data['id']), None)
        if not isinstance(ep, str):
            self._api_error(400, 'endpoint (or id) is required')
            return
        try:
            topics = store.set_topics(ep, data.get('topics'))
        except ValueError as e:
            self._api_error(400, str(e))
            return
        if topics is None:
            self._api_error(404, 'No such subscription')
            return
        self.send_json({'status': 'ok', 'topics': topics, 'subscriptions': store.public()})

    def _head_html(self):
        return HEAD_HTML.replace('__PORCH_CSS__', porch_css_tag()).replace('__GROUND__', GROUND)

    def _message_page(self, status, heading, text, action=''):
        nonce = csp_nonce()
        body = (REFUSE_HTML.replace('__HEAD__', self._head_html())
                .replace('__MARK__', porch_mark(16))
                .replace('__HEADING__', html.escape(heading))
                .replace('__TEXT__', html.escape(text))
                .replace('__ACTION__', action)).encode()
        if self.command in ('POST', 'PATCH', 'PUT', 'DELETE') and content_length(self) != 0:
            self.close_connection = True
        self._send_bytes(status, body, 'text/html; charset=utf-8', csp=page_csp(nonce, "img-src 'self'"))

    def _refuse_page(self):
        """What a visitor who is not the owner gets: a sign-in link, nothing else."""
        url = porch_auth.signin_url(self, self.devices_path, path='/')
        action = ''
        if url:
            action = (f'<a class="p-btn p-btn--lg" href="{html.escape(url, quote=True)}" '
                      'rel="nofollow">Owner? Sign in</a>')
        self._message_page(403, 'This pocket is private',
                           'Only its owner can open it.', action)

    def _deny(self, api):
        if api:
            self._refuse_json(403, 'Only the owner can use this pocket')
        else:
            self._refuse_page()

    def _serve_page(self):
        """The Porch app shell (lib/pocket_static/app.html): every script and
        the stylesheet are hashed same-origin files, the config is a nonced
        JSON block, nothing inline runs."""
        ua = self.headers.get('User-Agent', '')
        ios = bool(re.search(r'iPhone|iPad|iPod', ua)) or (
            'Macintosh' in ua and 'Mobile' in ua)
        cfg = {'maxFile': self.max_file, 'ios': ios, 'title': self.title,
               'tunnel_base': self.tunnel_base}
        if APP_VERSION:
            cfg['version'] = APP_VERSION
        nonce = csp_nonce()
        body = pocket_assets.render_shell(
            self._head_html(), html.escape(self.title), nonce,
            json.dumps(cfg).replace('<', '\\u003c')).encode()
        self._send_bytes(200, body, 'text/html; charset=utf-8', csp=shell_csp(nonce))

    # ---- public routes ----

    def _serve_public(self, path):
        """Manifest, service worker and icons: needed before (and without)
        any cookie, and they say nothing about the pocket's contents."""
        if path == '/manifest.webmanifest':
            body = json.dumps(manifest(self.title)).encode()
            self._send_bytes(200, body, 'application/manifest+json', cache='no-cache')
            return True
        if path == '/sw.js':
            self._send_bytes(200, SERVICE_WORKER_JS.encode(), 'text/javascript; charset=utf-8',
                             cache='no-cache', csp="default-src 'self'")
            return True
        if path in ICONS:
            data, ctype = ICONS[path]
            self._send_bytes(200, data, ctype, cache='public, max-age=86400',
                             csp="default-src 'none'; style-src 'unsafe-inline'; sandbox")
            return True
        return False

    # ---- dispatch ----

    def _path(self):
        return urllib.parse.urlparse(self.path).path

    def _tus_path(self):
        path = self._path()
        return self.tus().owns(path) or self.sealed_tus().owns(path)

    def do_HEAD(self):
        if self._tus_path():
            self._tus_request()
            return
        self.do_GET()

    def do_OPTIONS(self):
        if self._tus_path():
            self._tus_request()
            return
        self.send_json({'status': 'error', 'message': 'Not found'}, 404)

    def do_PATCH(self):
        if self._tus_path():
            self._tus_request()
            return
        self._refuse_json(404, 'Not found')

    def do_GET(self):
        if serve_asset(self, head=self.command == 'HEAD'):
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if self._serve_public(path):
            return
        if self._route('GET'):
            return
        api = path.startswith('/api/')
        cli = api and self._cli_ok()
        if not cli and not self._is_owner():
            self._deny(api)
            return

        if path.startswith('/reopen/') or path.startswith('/api/reopen') \
                or path.startswith('/api/push'):
            if not self._is_owner():          # the owner's browser, never the CLI token
                self._deny(api)
            elif path.startswith('/reopen/'):
                self._reopen_page(path[len('/reopen/'):])
            elif path == '/api/reopen':
                self.send_json(self._requests())
            elif path == '/api/push':
                self.send_json(self._push_info())
            else:
                self.send_json({'status': 'error', 'message': 'Not found'}, 404)
            return
        if path == '/':
            self._serve_page()
        elif path == '/api/clip':
            self.send_json(self.store.snapshot())
        elif path == '/api/inbox':
            self.send_json(list_inbox(self.inbox_dir))
        elif path == '/api/events':
            self._events()
        elif path == '/api/keys':
            if not self._is_owner():          # minted in the page, not by the CLI
                self._deny(True)
            else:
                self.send_json(self.keys.listing() if self.keys else [])
        elif path == '/api/links':
            if not self._is_owner():          # the owner's page only, not the CLI token
                self._deny(True)
            else:
                self.send_json(self._links_listing())
        elif path in STATIC_JS:
            self._serve_static_js(path)
        elif pocket_assets.lookup(path):
            data, ctype = pocket_assets.lookup(path)
            self._send_bytes(200, data, ctype, cache=pocket_assets.IMMUTABLE,
                             csp="default-src 'none'")
        elif path.startswith('/inbox/'):
            self._serve_file(urllib.parse.unquote(path[len('/inbox/'):]),
                             'dl=1' in parsed.query.split('&'))
        elif api:
            self.send_json({'status': 'error', 'message': 'Not found'}, 404)
        else:
            self._message_page(404, 'Not here', 'There is nothing at this address.',
                               '<a class="p-btn p-btn--ghost" href="/">Open your pocket</a>')

    def _write_gate(self, path):
        """Owner (or CLI token) + same-origin for a write. True when it may go
        ahead; otherwise the refusal has been sent."""
        api = path.startswith('/api/')
        if api and self._cli_ok():
            return True
        if not self._is_owner():
            self._deny(api or self._tus_path())
            return False
        ok = self._share_origin_ok() if path == '/share' else same_origin(self)
        if not ok:
            self._refuse_json(403, 'Cross-origin request refused')
            return False
        return True

    def do_POST(self):
        path = self._path()
        if self._tus_path():
            self._tus_request()
            return
        if self._route('POST'):
            return
        if path == '/share' and self._presented_key() is not None:
            # A device key (iOS Shortcut): it decides alone, cookie or not,
            # and it is worth nothing on any other route.
            self._share_with_key()
            return
        if not self._write_gate(path):
            return
        if path == '/share':
            self._share()
            return
        if path == '/api/clip':
            self._clip_set()
            return
        if path == '/api/keys' or path.startswith('/api/keys/'):
            self._keys_post(path)
            return
        if path == '/api/links' or path.startswith('/api/links/'):
            self._links_post(path)
            return
        if path.startswith('/api/reopen/') or path.startswith('/api/push/'):
            if not self._is_owner():
                self._refuse_json(403, 'Only the owner can do that')
                return
            if path.startswith('/api/reopen/'):
                self._reopen_decide(path[len('/api/reopen/'):])
            else:
                self._push_post(path[len('/api/push/'):])
            return
        self._drain()
        m = re.fullmatch(r'/api/clip/([^/]+)/delete', path)
        if m:
            self._clip_delete(m.group(1))
            return
        m = re.fullmatch(r'/api/inbox/([^/]+)/delete', path)
        if m:
            self._inbox_delete(urllib.parse.unquote(m.group(1)))
            return
        self._refuse_json(404, 'Not found')

    def do_DELETE(self):
        path = self._path()
        if self._tus_path():
            self._tus_request()
            return
        if not self._write_gate(path):
            return
        if path.startswith('/api/keys/'):
            self._keys_post(path + '/delete')
            return
        self._drain()
        m = re.fullmatch(r'/api/clip/([^/]+)', path)
        if m:
            self._clip_delete(m.group(1))
            return
        m = re.fullmatch(r'/api/inbox/([^/]+)', path)
        if m:
            self._inbox_delete(urllib.parse.unquote(m.group(1)))
            return
        self._refuse_json(404, 'Not found')

    # ---- tus ----

    def _tus_request(self):
        """/tus/: owner first (OPTIONS too), same-origin on writes, then an
        upload slot for each request that carries bytes."""
        method = self.command
        if not self._is_owner():
            self._refuse_json(403, 'Only the owner can use this pocket')
            return
        if method in ('POST', 'PATCH', 'DELETE') and not same_origin(self):
            self._refuse_json(403, 'Cross-origin request refused')
            return
        ip = None
        if method in ('POST', 'PATCH'):
            ip = client_ip(self)
            if not self.upload_slots.acquire(ip):
                self.close_connection = True
                self.send_json({'status': 'error',
                                'message': 'Too many uploads in progress, try again shortly'},
                               503, {'Retry-After': '5'})
                return
        try:
            path = self._path()
            (self.sealed_tus() if self.sealed_tus().owns(path) else self.tus()).handle(self)
        except Exception as e:
            sys.stderr.write(f"[pocketserver] tus {method} failed: {e}\n")
            self.close_connection = True
            try:
                self.send_json({'status': 'error', 'message': 'Server error'}, 500)
            except Exception:
                pass
        finally:
            if ip is not None:
                self.upload_slots.release(ip)

    # ---- clipboard ----

    def _source(self):
        if self.headers.get(CLI_TOKEN_HEADER) and self._cli_ok():
            return 'cli'
        return device_hint(self.headers.get('User-Agent', ''))

    def _clip_set(self):
        data = read_json_body(self, MAX_CLIP_BYTES * 6 + 1024)
        if data is None:
            self._refuse_json(400, 'Expected a JSON object no larger than the clip limit')
            return
        text = data.get('text')
        if not isinstance(text, str) or not text.strip():
            self.send_json({'status': 'error', 'message': 'text must be a non-empty string'}, 400)
            return
        if len(text.encode('utf-8')) > MAX_CLIP_BYTES:
            self.send_json({'status': 'error',
                            'message': f'over the {human_size(MAX_CLIP_BYTES)} clip limit'}, 413)
            return
        self.store.add(text, self._source())
        self.hub.bump('clip')
        self.send_json(self.store.snapshot())

    def _clip_delete(self, eid):
        if not _CLIP_ID.match(eid) or not self.store.delete(eid):
            self.send_json({'status': 'error', 'message': 'No such entry'}, 404)
            return
        self.hub.bump('clip')
        self.send_json(self.store.snapshot())

    # ---- inbox ----

    def _serve_file(self, raw, download):
        target, name = safe_child(self.inbox_dir, raw, sanitize_filename)
        if target is None or not target.is_file():
            self.send_json({'status': 'error', 'message': 'Not found'}, 404)
            return
        try:
            size = target.stat().st_size
        except OSError:
            self.send_json({'status': 'error', 'message': 'Not found'}, 404)
            return
        ctype = None if download else INLINE_TYPES.get(os.path.splitext(name)[1].lower())
        if ctype is None:
            stream_file(self, target, size, 'application/octet-stream', 'attachment',
                        name, cache='private, no-store', ranges=False)
        else:
            stream_file(self, target, size, ctype, 'inline', name, cache='private, no-store')

    def _inbox_delete(self, raw):
        target, _name = safe_child(self.inbox_dir, raw, sanitize_filename)
        if target is None or not target.is_file():
            self.send_json({'status': 'error', 'message': 'Not found'}, 404)
            return
        try:
            size = target.stat().st_size
            target.unlink()
        except OSError:
            self.send_json({'status': 'error', 'message': 'Could not delete'}, 500)
            return
        self.quota().removed(size)
        self.hub.bump('inbox')
        self.send_json(list_inbox(self.inbox_dir))

    # ---- share target ----

    def _share(self, source=None):
        fetch_mode = source is not None or self.headers.get('X-Porch-Fetch') == '1'
        ip = client_ip(self)
        if not self.upload_slots.acquire(ip):
            self.close_connection = True
            self.send_json({'status': 'error',
                            'message': 'Too many uploads in progress, try again shortly'},
                           503, {'Retry-After': '5'})
            return
        try:
            self._handle_share(fetch_mode, source)
        except MultipartError as e:
            sys.stderr.write(f"[pocketserver] malformed share: {e}\n")
            self._share_failed(fetch_mode, 400, 'That share arrived malformed.')
        except Exception as e:
            sys.stderr.write(f"[pocketserver] share failed: {e}\n")
            self._share_failed(fetch_mode, 500, 'Something went wrong on the server.')
        finally:
            self.upload_slots.release(ip)

    def _share_failed(self, fetch_mode, status, message, saved=0):
        self.close_connection = True
        if saved:
            message += f' {saved} file(s) made it in before that.'
        try:
            if fetch_mode:
                self.send_json({'status': 'error', 'message': message}, status)
            else:
                self._message_page(status, 'Share did not go through', message,
                                   '<a class="p-btn p-btn--ghost" href="/">Back to your pocket</a>')
        except Exception:
            pass

    def _handle_share(self, fetch_mode, source=None):
        boundary, bad = multipart_boundary(self.headers.get('Content-Type', ''))
        if bad:
            self._share_failed(fetch_mode, bad[1], bad[0])
            return
        length = content_length(self)
        if length <= 0:
            self._share_failed(fetch_mode, 411, 'Content-Length required.')
            return
        max_request = min(self.max_file * 8, self.max_total) + 4 * MAX_FIELD_BYTES
        if length > max_request:
            self._share_failed(fetch_mode, 413,
                               f'That share is larger than the {human_size(max_request)} limit.')
            return

        quota = self.quota()
        streamer = FieldStreamer(self.rfile, boundary, length, self.transferred)
        fields = {}
        saved = []
        try:
            for name, filename, chunks in streamer.fields():
                if filename is not None:
                    if not filename:
                        for _ in chunks:      # an empty file input
                            pass
                        continue
                    res = self._spool(filename, chunks, quota)
                    if res:
                        saved.append(res)
                    continue
                buf = bytearray()
                for chunk in chunks:
                    if len(buf) + len(chunk) > MAX_FIELD_BYTES:
                        raise UploadRejected(f'a text field is over the {human_size(MAX_FIELD_BYTES)} limit')
                    buf += chunk
                if name in ('title', 'text', 'url'):
                    fields[name] = buf.decode('utf-8', 'replace').strip()
        except UploadRejected as e:
            if saved:
                self.hub.bump('inbox')
            self._share_failed(fetch_mode, e.status, e.reason[:1].upper() + e.reason[1:] + '.',
                               saved=len(saved))
            return

        # Android often puts the link in `text` and leaves `url` empty, or
        # repeats it; keep each distinct value once, title first.
        parts = []
        for key in ('title', 'text', 'url'):
            v = fields.get(key, '')
            if v and v not in parts and not any(v in p for p in parts):
                parts.append(v)
        text = '\n'.join(parts)
        clip = 0
        clip_id = None
        if text:
            raw = text.encode('utf-8')[:MAX_CLIP_BYTES]
            clip_id = self.store.add(raw.decode('utf-8', 'ignore'),
                                     source or device_hint(self.headers.get('User-Agent', '')))['id']
            self.hub.bump('clip')
            clip = 1
        if saved:
            self.hub.bump('inbox')
            for s in saved:
                sys.stderr.write(f"[pocketserver] Saved: {s['name']} ({human_size(s['size'])})\n")
        if fetch_mode:
            bits = []
            if saved:
                bits.append(f"{len(saved)} file{'' if len(saved) == 1 else 's'}")
            if clip:
                bits.append('a clip')
            message = ('Got ' + ' and '.join(bits) + '.') if bits else 'Nothing came through.'
            self.send_json({'status': 'ok', 'files': saved, 'clip': bool(clip),
                            'message': message})
            return
        # The page offers "Make a link?" for what just came in (up to five).
        location = f'/?shared=1&files={len(saved)}&text={clip}'
        for s in saved[:5]:
            location += '&f=' + urllib.parse.quote(s['name'], safe='')
        if clip_id:
            location += '&c=' + clip_id
        self.send_response(303)
        self.send_header('Location', location)
        self.send_header('Content-Length', '0')
        self.send_header('Cache-Control', 'no-store')
        security_headers(self)
        self.end_headers()

    def _spool(self, filename, chunks, quota):
        """One file part into the inbox, every cap enforced as it arrives
        (the dropserver pattern). Returns {'name','size'} or None if empty."""
        refusal = quota.begin()
        if refusal:
            raise UploadRejected(refusal)
        tmp = None
        written = 0
        kept = False
        try:
            tmp = new_tmp(self.inbox_dir)
            with open(tmp, 'wb') as out:
                for chunk in chunks:
                    if written + len(chunk) > self.max_file:
                        raise UploadRejected(f'over the {human_size(self.max_file)} per-file limit')
                    refusal = quota.add(len(chunk))
                    if refusal:
                        raise UploadRejected(refusal)
                    written += len(chunk)
                    out.write(chunk)
            if written == 0:
                return None
            name = place_unique(tmp, self.inbox_dir, name_candidates(sanitize_filename(filename)))
            kept = True
            return {'name': name, 'size': written}
        finally:
            quota.end(written, kept)
            if not kept and tmp is not None:
                drop_tmp(tmp)

    # ---- device share keys ----

    def _share_with_key(self):
        """POST /share authorised by a device key. Rate-limited per key, and
        wrong keys per client address; answers JSON (a Shortcut reads it)."""
        ip = client_ip(self)
        fail = self.key_fail
        if fail is not None and fail.blocked(ip):
            self._refuse_json(429, 'Too many wrong device keys; wait a few minutes')
            return
        entry = self.keys.match(self._presented_key()) if self.keys else None
        if entry is None:
            if fail is not None:
                fail.hit(ip)
            sys.stderr.write(f"[pocketserver] share refused: unknown or revoked device key "
                             f"from {ip}\n")
            if self.command in ('POST',) and content_length(self) != 0:
                self.close_connection = True
            self.send_json({'status': 'error', 'message': 'Unknown or revoked device key'},
                           401, {'WWW-Authenticate': 'Bearer realm="pocket"'})
            return
        if self.key_rate is not None and not self.key_rate.hit(entry['id']):
            self.close_connection = True
            self.send_json({'status': 'error',
                            'message': 'This device key is sharing too fast; try again shortly'},
                           429, {'Retry-After': '60'})
            return
        self.keys.used(entry['id'])
        sys.stderr.write(f"[pocketserver] share via device key {entry['label']!r} from {ip}\n")
        self._share(source=entry['label'][:16])

    def _keys_post(self, path):
        """Create / rotate / revoke device keys: the owner's browser only."""
        if not self._is_owner() or self.keys is None:
            self._refuse_json(403, 'Only the owner can manage device keys')
            return
        if path == '/api/keys':
            data = read_json_body(self, 4096)
            if data is None:
                self._refuse_json(400, 'Expected a small JSON object')
                return
            entry, reason = self.keys.create(data.get('label'))
            if entry is None:
                self.send_json({'status': 'error', 'message': reason}, 409)
                return
            sys.stderr.write(f"[pocketserver] device key {entry['label']!r} created\n")
            self.send_json(entry, 201)
            return
        self._drain()
        m = re.fullmatch(r'/api/keys/([^/]+)/(rotate|delete)', path)
        if not m or not _KEY_ID.match(m.group(1)):
            self._refuse_json(404, 'No such device key')
            return
        kid, action = m.groups()
        if action == 'rotate':
            entry = self.keys.rotate(kid)
            if entry is None:
                self._refuse_json(404, 'No such device key')
                return
            sys.stderr.write(f"[pocketserver] device key {entry['label']!r} rotated\n")
            self.send_json(entry)
            return
        if not self.keys.revoke(kid):
            self._refuse_json(404, 'No such device key')
            return
        sys.stderr.write("[pocketserver] device key revoked\n")
        self.send_json(self.keys.listing())

    # ---- links (Make link + the links panel) ----

    def _links_listing(self):
        self._sweep_sealed()
        return [public_link(st) for st in pocket_links(self.state_dir, self.pocket_name)]

    def _sweep_sealed(self):
        """Delete sealed uploads no live door of ours owns, once they are
        SEALED_ORPHAN_AGE old (a Make link that never came, or failed)."""
        files = sealed_files(self.sealed_root())
        if not files:
            return
        owned = set()
        # A closed door's sealed file is kept for a reopen (lib/door_recipe.py).
        try:
            retained = door_recipe.retained_files()
        except OSError:
            retained = set()
        for name, size, mtime in files:
            if os.path.realpath(self.sealed_root() / name) in retained:
                owned.add(name)
        for st in pocket_links(self.state_dir, self.pocket_name):
            tag = st['pocket']
            if tag.get('kind') == 'sealed' and isinstance(tag.get('item'), str):
                owned.add(tag['item'])
        now = time.time()
        for name, size, mtime in files:
            if name in owned or now - mtime < SEALED_ORPHAN_AGE:
                continue
            try:
                os.unlink(self.sealed_root() / name)
            except OSError:
                continue
            self.quota().removed(size)
            sys.stderr.write("[pocketserver] removed an unlinked sealed upload\n")

    def _links_post(self, path):
        """POST /api/links (make one) and /api/links/<name>/extend|never|close.
        The owner's page only: cookie + same-origin (already checked by
        _write_gate), never the CLI token."""
        if not self._is_owner():
            self._refuse_json(403, 'Only the owner can make links')
            return
        if path == '/api/links':
            data = read_json_body(self, 16 * 1024)
            if data is None:
                self._refuse_json(400, 'Expected a small JSON object')
                return
            try:
                self.send_json(self._link_create(data), 201)
            except LinkError as e:
                self.send_json({'status': 'error', 'message': e.message}, e.status)
            return
        self._drain()
        m = re.fullmatch(r'/api/links/([^/]+)/(extend|never|close)', path)
        if not m or not _LINK_NAME.match(m.group(1)):
            self._refuse_json(404, 'No such link')
            return
        name, action = m.groups()
        mine = {st['name']: st for st in pocket_links(self.state_dir, self.pocket_name)}
        if name not in mine:
            self._refuse_json(404, 'No such link')
            return
        spath = door_state.state_path(name, self.state_dir)
        try:
            if action == 'extend':
                door_state.extend(spath, 3600)
            elif action == 'never':
                door_state.set_expiry(spath, None)
            else:
                self.link_closer(name)
                if os.path.exists(spath) and not _pid_alive(mine[name].get('pid')):
                    door_state.cleanup_files(name, self.state_dir)   # a stale record
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as e:
            sys.stderr.write(f"[pocketserver] link {name} {action} failed: {e}\n")
            self._refuse_json(500, 'Could not change that link')
            return
        sys.stderr.write(f"[pocketserver] link {name}: {action}\n")
        self.hub.bump('links')
        self.send_json(self._links_listing())

    def _link_target(self, kind, item):
        """(argv after the launcher, stdin bytes or None, label, launcher)."""
        if not isinstance(item, str) or not item or len(item) > 512:
            raise LinkError('id must be a non-empty string')
        if kind == 'inbox':
            target, fname = safe_child(self.inbox_dir, item, sanitize_filename)
            if target is None or target.is_symlink() or not target.is_file():
                raise LinkError('No such inbox file', 404)
            return [str(target)], None, fname, 'share'
        if kind == 'clip':
            if not _CLIP_ID.match(item):
                raise LinkError('No such clipboard entry', 404)
            entry = self.store.get(item)
            if entry is None:
                raise LinkError('No such clipboard entry', 404)
            first = ' '.join(entry['text'].split())[:24]
            return ['-'], entry['text'].encode('utf-8'), 'clip ' + first, 'share'
        if kind == 'sealed':
            if not _SEALED_NAME.match(item):
                raise LinkError('No such sealed upload', 404)
            target = self.sealed_root() / item
            if target.is_symlink() or not target.is_file():
                raise LinkError('No such sealed upload', 404)
            return [str(target)], None, 'sealed file', 'seal'
        raise LinkError('kind must be inbox, clip or sealed')

    def _link_create(self, data):
        kind, item = data.get('kind'), data.get('id')
        args, stdin, label, launcher = self._link_target(kind, item)
        flags, password = parse_link_rules(data.get('rules'))
        name = data.get('name')
        if name in (None, ''):
            name = new_link_name('file' if kind == 'sealed' else
                                 ('clip' if kind == 'clip' else label))
        elif not isinstance(name, str) or not _LINK_NAME.match(name):
            raise LinkError('name must look like pk-<letters, digits, dashes>')
        if launcher == 'seal':
            argv = [os.path.join(REPO_DIR, 'bin', 'seal'), args[0], name] + flags + \
                ['--owned-file', '--owned-dir', str(self.sealed_root()), '--bg']
        else:
            argv = [os.path.join(REPO_DIR, 'bin', 'porch'), 'share', args[0], '--name', name] + \
                flags + ['--bg']
        spath = door_state.state_path(name, self.state_dir)
        with self.link_lock:
            live = [st for st in pocket_links(self.state_dir, self.pocket_name)
                    if _pid_alive(st.get('pid'))]
            if len(live) >= self.max_links:
                raise LinkError(f'at most {self.max_links} live links; close one first', 409)
            if os.path.exists(spath):
                raise LinkError('a door with that name is already open', 409)
            try:
                rc, out, err = self.link_runner(argv, launcher_env(password), stdin,
                                                self.link_timeout)
            except LinkTimeout:
                sys.stderr.write(f"[pocketserver] link {name}: launcher timed out; closing\n")
                self.link_closer(name)
                raise LinkError('Opening the link took too long; nothing was left open', 504)
            except OSError as e:
                sys.stderr.write(f"[pocketserver] link {name}: could not run the launcher: {e}\n")
                raise LinkError('Could not start the door', 500)
            if rc != 0:
                if os.path.exists(spath):
                    self.link_closer(name)
                why = _clean_line(err) or _clean_line(out) or f'exit {rc}'
                sys.stderr.write(f"[pocketserver] link {name}: launcher failed ({rc})\n")
                raise LinkError(f'The door did not open: {why}', 502)

            def tag(st):
                st['pocket'] = {'name': self.pocket_name, 'kind': kind,
                                'label': clean_label(label),
                                **({'item': item} if kind == 'sealed' else {})}
            try:
                st = door_state.update_state(spath, tag)
            except (OSError, ValueError):
                sys.stderr.write(f"[pocketserver] link {name}: no door state after launch\n")
                self.link_closer(name)
                raise LinkError('The door did not come up', 502)
        sys.stderr.write(f"[pocketserver] link {name} made for a {kind} item\n")
        self.hub.bump('links')
        link = public_link(st)
        return {'name': name, 'url': link['url'], 'guest_url': link['guest_url'],
                'expires': link['expires'], 'type': link['type'], 'kind': kind}

    # ---- ask to reopen + push notifications ----

    def _rstore(self):
        if self.reopen_store is None:
            type(self).reopen_store = reopen_requests.Store()
        return self.reopen_store

    def _requests_sig(self):
        try:
            return self._rstore().sig()
        except OSError:
            return None

    def _requests(self):
        """Real asks to reopen still answered (pending + recently decided)."""
        try:
            return self._rstore().recent()
        except OSError:
            return []

    def _reopen_decide(self, rid):
        """POST /api/reopen/<id> {decision: allow|deny, expires: 1h|24h}: from
        the page, the /reopen/<id> page, or the service worker's Allow button."""
        data = read_json_body(self, 4096)
        if data is None or not reopen_requests.valid_id(rid):
            self._refuse_json(400, 'Expected {decision, expires}')
            return
        reopen = self.reopener or (lambda name, exp: door_recipe.reopen(
            name, exp, state_dir=self.state_dir, ok_if_open=True))
        try:
            rec = self._rstore().decide(rid, data.get('decision'), data.get('expires'), reopen)
        except ValueError as e:
            self.send_json({'status': 'error', 'message': str(e)}, 400)
            return
        except LookupError as e:
            self.send_json({'status': 'error', 'message': str(e)}, 409)
            return
        except RuntimeError as e:
            self.send_json({'status': 'error', 'message': str(e)}, 502)
            return
        except OSError:
            self.send_json({'status': 'error', 'message': 'The request store is unavailable'}, 503)
            return
        sys.stderr.write(f"[pocketserver] reopen request for {rec.get('name')}: {rec.get('state')}\n")
        self.hub.bump('links')
        self.send_json({'status': 'ok', 'request': rec,
                        'url': tunnel_url(rec['name']) if rec.get('state') == 'approved' else None})

    def _vapid_path(self):
        return Path(self.base_dir) / '.vapid.pem'

    def _push_store(self):
        import porch_push
        return porch_push.SubStore(Path(self.base_dir) / '.push.json')

    def _push_claim(self):
        if self.push_claim:
            return self.push_claim
        # main() already refused to start on an invalid config, and get() is
        # cached; a ConfigError here is loud on purpose (no silent fallback).
        import porch_config
        return f'https://{porch_config.get().landing_host}/'

    def _push_info(self):
        import porch_push
        if not porch_push.available():
            return {'supported': False, 'why': f'Push needs python3-cryptography on this box '
                                               f'({porch_push.APT_HINT}).', 'subscriptions': []}
        key = porch_push.load_or_create_vapid(str(self._vapid_path()))
        return {'supported': True, 'public_key': porch_push.b64u(porch_push.public_bytes(key)),
                'subscriptions': self._push_store().public(),
                # The page finds its own subscription by hashing its endpoint
                # (porch_push.sub_id); the server never guesses which it is.
                'this_endpoint_hint': None}

    def _push_post(self, action):
        import porch_push
        data = read_json_body(self, 8192)
        if data is None:
            self._refuse_json(400, 'Expected a small JSON object')
            return
        if not porch_push.available():
            self.send_json({'status': 'error', 'message': 'Push needs python3-cryptography '
                            f'on this box ({porch_push.APT_HINT})'}, 501)
            return
        store = self._push_store()
        if action == 'subscribe':
            porch_push.load_or_create_vapid(str(self._vapid_path()))
            try:
                store.add(data.get('subscription'), device_hint(self.headers.get('User-Agent', '')))
            except ValueError as e:
                self.send_json({'status': 'error', 'message': str(e)}, 400)
                return
            sys.stderr.write("[pocketserver] push: a device subscribed\n")
        elif action == 'unsubscribe':
            ep = data.get('endpoint')
            if isinstance(ep, str):
                store.remove(ep)
            sys.stderr.write("[pocketserver] push: a device unsubscribed\n")
        elif action == 'test':
            out = porch_push.deliver(str(self.base_dir), {
                't': 'test', 'title': 'Porch notifications work',
                'body': 'You will hear here when someone asks to reopen one of your doors.'},
                self._push_claim(), ttl=600,
                log=lambda m: sys.stderr.write(f"[pocketserver] {m}\n"))
            self.send_json({'status': 'ok', **out, 'subscriptions': store.public()})
            return
        else:
            self._refuse_json(404, 'Not found')
            return
        self.send_json({'status': 'ok', 'subscriptions': store.public()})

    def _reopen_page(self, rid):
        rec = None
        if reopen_requests.valid_id(rid):
            try:
                rec = self._rstore().get(rid)
            except OSError:
                rec = None
        if rec is None:
            self._message_page(404, 'No such request',
                               'It may have run out (asks wait 30 minutes) or been answered.',
                               '<a class="p-btn p-btn--ghost" href="/">Open your pocket</a>')
            return
        nonce = csp_nonce()
        data = dict(rec, url=tunnel_url(rec['name']))
        body = (REOPEN_HTML.replace('__HEAD__', self._head_html())
                .replace('__MARK__', porch_mark(16))
                .replace('__DATA_JSON__', json.dumps(data).replace('<', '\\u003c'))
                .replace('__NONCE__', nonce)).encode()
        self._send_bytes(200, body, 'text/html; charset=utf-8',
                         csp=page_csp(nonce, "img-src 'self' data:; connect-src 'self'"))

    def _serve_static_js(self, path):
        try:
            body = Path(STATIC_JS[path]).read_bytes()
        except OSError:
            self.send_json({'status': 'error', 'message': 'Not found'}, 404)
            return
        self._send_bytes(200, body, 'text/javascript; charset=utf-8', cache='private, no-cache',
                         csp="default-src 'none'")

    # ---- events ----

    def _events(self):
        ip = client_ip(self)
        if not self.hub.acquire(ip):
            self.send_json({'status': 'error', 'message': 'Too many live connections'},
                           429, {'Retry-After': '10'})
            return
        try:
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Accel-Buffering', 'no')
            self.send_header('Connection', 'close')
            security_headers(self)
            self.end_headers()
            self.close_connection = True
            seen = dict(self.hub.versions)
            inbox_sig = _dir_sig(self.inbox_dir)
            lsig = links_sig(self.state_dir)
            rsig = self._requests_sig()
            dsig = doors_sig(self.state_dir)
            hsig = history_sig(self.history_path, self.doors_dir)
            hist_at = time.monotonic()
            hist_due = False
            # The control-plane events are the owner's page only, never
            # the `porch clip` CLI token's.
            owner = self.owner_ctx() is not None
            stepup = self._stream_stepup()
            self._sse('clip', self.store.snapshot())
            self._sse('inbox', list_inbox(self.inbox_dir), retry=3000)
            self._sse('links', self._links_listing())
            self._sse('requests', self._requests())
            if owner:
                self._sse('doors', self.doors_reply())
                self._sse('history', self._history_event())
                self._sse('people', self.people_event())
                self._sse('stepup', stepup)
            started = time.monotonic()
            while time.monotonic() - started < self.sse_max_age:
                wait = self.sse_heartbeat
                if stepup['active']:
                    # Wake when the step-up runs out, so the page hears it ends.
                    wait = max(0.2, min(wait, stepup['expires_at'] - self.stepups.clock() + 0.2))
                now = self.hub.wait(seen, wait)
                sent = False
                if now['clip'] != seen['clip']:
                    self._sse('clip', self.store.snapshot())
                    sent = True
                sig = _dir_sig(self.inbox_dir)
                if now['inbox'] != seen['inbox'] or sig != inbox_sig:
                    self._sse('inbox', list_inbox(self.inbox_dir))
                    sent = True
                # Opens and expiry change in the door's state file (the door
                # proxy, bin/status), so the files are watched as well.
                ls = links_sig(self.state_dir)
                if now['links'] != seen['links'] or ls != lsig:
                    self._sse('links', self._links_listing())
                    sent = True
                ds = doors_sig(self.state_dir)
                if owner and (now['doors'] != seen['doors'] or ds != dsig):
                    self._sse('doors', self.doors_reply())
                    sent = True
                # Asks to reopen arrive through statusserver, in the shared store.
                rs = self._requests_sig()
                if rs != rsig:
                    self._sse('requests', self._requests())
                    sent = True
                hs = history_sig(self.history_path, self.doors_dir)
                if hs != hsig or ds != dsig:
                    hist_due = True
                if owner and hist_due and time.monotonic() - hist_at >= HISTORY_MIN_INTERVAL:
                    self._sse('history', self._history_event())
                    hist_at, hist_due = time.monotonic(), False
                    sent = True
                if owner and now['people'] != seen['people']:
                    self._sse('people', self.people_event())
                    sent = True
                su = self._stream_stepup()
                if owner and su != stepup:
                    self._sse('stepup', su)
                    stepup = su
                    sent = True
                seen, inbox_sig, lsig, rsig, dsig, hsig = now, sig, ls, rs, ds, hs
                if not sent:
                    self.wfile.write(b': ping\n\n')
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.hub.release(ip)

    def _stream_stepup(self):
        """{active, expires_at, method} of this stream's owner device."""
        ctx = self.owner_ctx()
        if ctx is None:
            return {'active': False, 'expires_at': None, 'method': None}
        return self.stepups.status(ctx['device_id'], ctx['owner_sha'])

    def _history_event(self):
        try:
            return self.history_listing()
        except (OSError, DoorOpError):
            return []

    def _sse(self, event, data, retry=None):
        msg = f'event: {event}\n'
        if retry:
            msg = f'retry: {retry}\n' + msg
        msg += 'data: ' + json.dumps(data) + '\n\n'
        self.wfile.write(msg.encode('utf-8'))
        self.wfile.flush()


# ---- systemd user service ---------------------------------------------------

REPO_DIR = os.path.dirname(_HERE)
UNIT_TEMPLATE = os.path.join(REPO_DIR, 'config', 'templates', 'systemd', 'porch-pocket@.service.tmpl')
UNIT_FILE = 'porch-pocket@.service'
_POCKET_NAME = re.compile(r'^[a-z0-9][a-z0-9-]{0,40}$')


def unit_name(name):
    if not _POCKET_NAME.match(name or ''):
        raise ValueError(f'invalid pocket name {name!r}')
    return f'porch-pocket@{name}.service'


def user_unit_dir(env=None):
    env = os.environ if env is None else env
    base = env.get('XDG_CONFIG_HOME') or os.path.join(env.get('HOME') or os.path.expanduser('~'),
                                                      '.config')
    return os.path.join(base, 'systemd', 'user')


def render_service_unit(repo_dir=REPO_DIR, brand=None, template=UNIT_TEMPLATE):
    """The porch-pocket@.service template unit for this checkout."""
    import string
    if brand is None:
        try:
            import porch_config
            brand = porch_config.get().brand
        except Exception:
            brand = 'Porch'
    if any(c in repo_dir for c in ' \n\t%$\\"\''):
        raise ValueError(f'repo path {repo_dir!r} cannot go into a unit file as-is')
    with open(template, encoding='utf-8') as f:
        text = f.read()
    return string.Template(text).substitute(
        repo_dir=repo_dir, brand=(clean_label(brand) or 'Porch').replace('%', '%%'))


def _systemctl(*args, check=True):
    proc = subprocess.run(['systemctl', '--user', *args], capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise SystemExit(f"systemctl --user {' '.join(args)} failed: "
                         f"{(proc.stderr or proc.stdout).strip()}")
    return proc


def install_service(name, start=True):
    """Write the template unit, enable porch-pocket@<name> and start it."""
    unit = unit_name(name)
    d = user_unit_dir()
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, UNIT_FILE)
    body = render_service_unit()
    try:
        same = open(path, encoding='utf-8').read() == body
    except OSError:
        same = False
    if not same:
        atomic_write_bytes(Path(path), body.encode('utf-8'), mode=0o644)
        print(f'wrote {path}')
    _systemctl('daemon-reload')
    _systemctl('enable', unit)
    if start:
        _systemctl('restart', unit)
    linger = subprocess.run(['loginctl', 'show-user', os.environ.get('USER', ''), '-p', 'Linger'],
                            capture_output=True, text=True).stdout.strip()
    print(f'enabled {unit}' + (' and started it' if start else ''))
    if linger != 'Linger=yes':
        print('warning: linger is off, so it only runs while you are logged in. '
              'Fix: loginctl enable-linger $USER', file=sys.stderr)
    return unit


def uninstall_service(name):
    """Stop and disable porch-pocket@<name>; drop the template when no
    other instance is enabled."""
    unit = unit_name(name)
    _systemctl('disable', '--now', unit, check=False)
    d = user_unit_dir()
    wants = os.path.join(d, 'default.target.wants')
    try:
        others = [n for n in os.listdir(wants) if n.startswith('porch-pocket@')]
    except OSError:
        others = []
    if not others:
        try:
            os.unlink(os.path.join(d, UNIT_FILE))
            print(f'removed {os.path.join(d, UNIT_FILE)}')
        except OSError:
            pass
    _systemctl('daemon-reload', check=False)
    print(f'stopped and disabled {unit}')


def service_main(argv):
    """--install-service NAME | --uninstall-service NAME | --render-unit"""
    try:
        if argv[0] == '--render-unit':
            sys.stdout.write(render_service_unit())
        elif argv[0] == '--install-service':
            install_service(argv[1] if len(argv) > 1 else 'pocket')
        elif argv[0] == '--uninstall-service':
            uninstall_service(argv[1] if len(argv) > 1 else 'pocket')
    except ValueError as e:
        raise SystemExit(f'pocket: {e}')


def make_watcher(H, base):
    """The AuthWatcher for a pocket: bumps the hub, pushes pairings and
    invite accepts to this pocket's subscriptions (per topic)."""
    def push(payload, topic):
        import porch_push
        if not porch_push.available():
            return
        claim = H.push_claim or H._push_claim(H)
        porch_push.deliver(str(base), payload, claim, ttl=600, topic=topic,
                           log=lambda m: sys.stderr.write(f"[pocketserver] {m}\n"))
    return AuthWatcher(H.auth, bump=lambda: H.hub.bump('people'), push=push)


def main():
    if sys.argv[1:2] == ['--build-icons']:
        build_icons(sys.argv[2] if len(sys.argv) > 2 else ICON_DIR)
        return
    if sys.argv[1:2] and sys.argv[1] in ('--install-service', '--uninstall-service',
                                         '--render-unit'):
        service_main(sys.argv[1:])
        return
    parser = argparse.ArgumentParser(description='Pocket: share target + clipboard')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--dir', type=str, required=True, help='~/pocket/<name>')
    parser.add_argument('--name', type=str, default='pocket',
                        help='door name (CLI token file, page title)')
    parser.add_argument('--bind', type=str, default='127.0.0.1')
    parser.add_argument('--devices', type=str, default='',
                        help='porch-auth devices.json (without it nobody can open the pocket)')
    parser.add_argument('--no-cli-token', action='store_true',
                        help='do not write a token for `porch clip`')
    parser.add_argument('--max-file-mb', type=int, default=MAX_FILE_SIZE // (1024 * 1024))
    parser.add_argument('--max-total-mb', type=int, default=DEFAULT_MAX_TOTAL_MB)
    parser.add_argument('--max-files', type=int, default=MAX_FILES)
    parser.add_argument('--min-free-mb', type=int, default=DEFAULT_MIN_FREE_MB)
    parser.add_argument('--max-connections', type=int, default=DEFAULT_MAX_CONNECTIONS)
    parser.add_argument('--history', type=str,
                        default=os.path.join(REPO_DIR, 'data', 'history.jsonl'),
                        help='launch history (data/history.jsonl, like statusserver)')
    parser.add_argument('--rp-id', type=str, default='',
                        help='WebAuthn rpId (default: the configured pocket host)')
    parser.add_argument('--rp-origin', type=str, default='',
                        help='WebAuthn origin (default: https://<rp-id>)')
    parser.add_argument('--no-auth-watcher', action='store_true',
                        help='do not poll porch-auth (no pairing/invite notifications)')
    args = parser.parse_args()

    base = Path(args.dir).resolve()
    base.mkdir(parents=True, exist_ok=True)
    os.chmod(base, 0o700)
    inbox = base / 'inbox'
    inbox.mkdir(exist_ok=True)

    H = PocketHandler
    H.base_dir = base
    H.inbox_dir = inbox
    H.sealed_dir = base / 'sealed'
    H.sealed_dir.mkdir(mode=0o700, exist_ok=True)
    H.pocket_name = args.name
    H.devices_path = os.path.abspath(args.devices) if args.devices else ''
    H.title = 'Porch' if args.name == 'pocket' else f'Porch · {args.name}'
    H.max_file = max(1, args.max_file_mb) * 1024 * 1024
    H.max_total = max(1, args.max_total_mb) * 1024 * 1024
    H.max_files = max(1, args.max_files)
    H.min_free = max(0, args.min_free_mb) * 1024 * 1024
    H.store = ClipStore(base / '.clip.json')
    H.hub = Hub()
    H.keys = KeyStore(base / '.share-keys.json')
    H.key_rate = RateLimit(*KEY_RATE)
    H.key_fail = RateLimit(*KEY_FAIL_RATE)
    H.history_path = str(Path(args.history).resolve())
    H.audit = AuditLog(base / '.audit.jsonl')
    import porch_config
    try:
        cfg = porch_config.get()
    except porch_config.ConfigError as e:
        # The passkey rpId, push claim and links all come from the config:
        # never guess a domain (CLAUDE.md "Domain config": servers refuse to start).
        sys.exit(f'pocket: invalid Porch config: {e}')
    host, brand, tbase = f'{args.name}.{cfg.tunnel_base}', cfg.brand, cfg.tunnel_base
    rp_id = args.rp_id or host
    H.pocket_host = host
    H.tunnel_base = tbase
    H.brand = brand
    H.init_stepup(base, rp_id, (args.rp_origin or f'https://{rp_id}').rstrip('/'))
    if H.devices_path:
        # The CLI token porch-auth writes next to devices.json (data/.admin-cli-token).
        H.auth = auth_client.Client(os.path.dirname(H.devices_path))
        if not args.no_auth_watcher:
            H.watcher = make_watcher(H, base)
            H.watcher.start()

    token_file = None
    if not args.no_cli_token:
        token_file = cli_token_path(args.name)
        H.cli_token = secrets.token_urlsafe(32)
        rundir.write_private(token_file, H.cli_token)

    swept = sweep_stale_parts(inbox)
    if swept:
        sys.stderr.write(f"[pocketserver] removed {swept} stale partial upload(s)\n")
    H.tus().pending_count()
    H.sealed_tus().pending_count()
    install_sigterm_cleanup('pocketserver')

    server = make_server(H, args.port, args.bind, tag='pocketserver',
                         max_connections=max(SSE_MAX_TOTAL + 8, args.max_connections))
    sys.stderr.write(f"[pocketserver] Listening on {args.bind}:{args.port}, pocket at {base} "
                     f"[{'owner via porch-auth' if args.devices else 'no --devices: nobody can open it'}]\n")
    try:
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        sys.stderr.write("\n[pocketserver] Shutting down.\n")
    finally:
        server.server_close()
        if H.watcher is not None:
            H.watcher.stop()
        if token_file:
            try:
                os.unlink(token_file)
            except OSError:
                pass


if __name__ == '__main__':
    main()

#!/usr/bin/env python3

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
import tempfile
import threading
import time
import urllib.parse
from html import escape as html_escape
from http.server import BaseHTTPRequestHandler
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent

_LIB = str(Path(__file__).resolve().parent)
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
import door_ops  # noqa: E402  (the door control plane: shared with Pocket + porch door)
import door_recipe  # noqa: E402  (launch recipes: reopen a closed door under its name)
import door_state  # noqa: E402  (door expiry/rules, locked state-file edits, stop)
import inspect_store  # noqa: E402  (request inspector records + replay socket)
import porch_auth  # noqa: E402  (the one owner check, shared with every app)
import porch_config  # noqa: E402  (domain config: config/porch.toml, PORCH_* env)
import reopen_requests  # noqa: E402  ("ask to reopen" from the closed-door page)
from porch_auth import GATE_COOKIE, HOST_COOKIE  # noqa: E402
from porch_http import (  # noqa: E402
    BoundedThreadingHTTPServer, client_ip, content_length, make_server, parse_cookies,
    porch_css_tag, porch_mark, porch_style_src, serve_asset,
)

# Owner = what lib/porch_auth.py says: a porch_host cookie minted for this host
# by a live admin browser device, or (while PORCH_ACCEPT_LEGACY_COOKIE is on)
# a live admin device's domain-wide cush_auth cookie.

# The door logic lives in lib/door_ops.py (shared with Pocket and `porch
# door`); the handlers below are thin wrappers. The module-level names stay
# here as aliases, and the wrappers read REPO_ROOT and DOMAIN from this module
# at call time, so tests can still re-point them.
LAUNCHABLE_TYPES = door_ops.LAUNCHABLE_TYPES
NAME_RE = door_ops.NAME_RE
REVIVE_FLAGS = door_ops.REVIVE_FLAGS
REVIVABLE_TYPES = door_ops.REVIVABLE_TYPES

# Every POST here carries a small JSON object; nothing legitimate is bigger.
MAX_BODY = 256 * 1024


class BodyTooLarge(Exception):
    """Declared Content-Length is past MAX_BODY; refuse before allocating."""

# Per-process CSRF key. Tokens are an HMAC of the caller's own gate cookie, so
# they're stateless, unguessable, and useless in another browser. A restart
# invalidates outstanding tokens — the Origin check below still covers those.
_CSRF_SECRET = secrets.token_bytes(32)

# Launch history: only the newest HISTORY_KEEP records survive a compaction,
# which runs once the file passes HISTORY_MAX records.
HISTORY_MAX = door_ops.HISTORY_MAX
HISTORY_KEEP = door_ops.HISTORY_KEEP

# Per-connection socket timeout (seconds).
REQUEST_TIMEOUT = 60

# Request inspector (GET /api/tunnels/<name>/requests/events): at most this many
# live SSE streams at once, a comment heartbeat every SSE_HEARTBEAT seconds,
# and each stream ends after SSE_MAX_SECONDS (EventSource reconnects with
# Last-Event-ID, so nothing is missed).
SSE_MAX_STREAMS = 4
SSE_HEARTBEAT = 15
SSE_MAX_SECONDS = 300
SSE_POLL = 0.5
_sse_slots = threading.BoundedSemaphore(SSE_MAX_STREAMS)
REQUESTS_PAGE = door_ops.REQUESTS_PAGE

# "Ask to reopen" (POST /api/reopen-requests): the closed-door page on a dead
# tunnel host asks; Pocket's push notification (and the panel) answers.
REOPEN_EXPIRES = door_ops.REOPEN_EXPIRES  # what an approval may open a door for
REOPEN_POLL = 4                         # s between the visitor page's polls


def reopen_origin(origin):
    """The CORS origin to echo for the public reopen endpoints: exactly
    https://<door label>.<tunnel base>, nothing else (no port, no path)."""
    if not isinstance(origin, str) or not origin.startswith('https://'):
        return None
    host = origin[len('https://'):]
    if reopen_requests.door_for_host(host, DOMAIN.tunnel_base) is None or host != host.lower():
        return None
    return origin


def push_reopen(rec, root=None):
    """Tell the owner's browsers (every Pocket's push subscriptions). Runs in
    a thread: the visitor's answer never waits for it, or depends on it."""
    try:
        import porch_push
        out = porch_push.notify_all(reopen_requests.push_payload(rec),
                                    f'https://{DOMAIN.landing_host}/', root=root, log=log)
        log(f"Reopen request for '{rec.get('name')}': push sent {out['sent']}, "
            f"failed {out['failed']}, dropped {out['dropped']}")
    except Exception as e:  # noqa: BLE001
        log(f"Reopen push failed: {e.__class__.__name__}")

def csrf_token_for(cookie_value):
    """Return the CSRF token bound to a given gate cookie value."""
    return hmac.new(_CSRF_SECRET, cookie_value.encode('utf-8'),
                    hashlib.sha256).hexdigest()


is_alive = door_ops.is_alive
read_state = door_ops.read_state


def write_state_atomic(path, data):
    """Unique temp file in the same dir (never <name>.json.tmp, which the
    launcher itself uses), fsync, rename. The temp name does not end in
    .json, so a listing never picks it up."""
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix=f'.{path.stem}.', suffix='.tmp', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# frpc matching + kill live in lib/door_state.py (the door proxy's burn path
# stops a door the same way); re-exported here.
FRPC_CONF_SUFFIX_RE = door_state.FRPC_CONF_SUFFIX_RE
frpc_pids_for = door_state.frpc_pids_for
kill_frpc_for = door_ops.kill_frpc_for


def log(msg):
    sys.stderr.write(f"[status-api] {msg}\n")


# The domain config (a porch_config.Config). Read at call time, so tests can
# swap it for another domain.
DOMAIN = porch_config.get()


def tunnel_url(name):
    return door_ops.tunnel_url(name, DOMAIN)


def domain_html(html):
    """Fill the domain placeholders in a page template (before any request
    data is spliced in). Values are validated hostnames: no markup."""
    return (html.replace('__PORCH_TUNNEL_BASE__', DOMAIN.tunnel_base)
                .replace('__PORCH_AUTH_HOST__', DOMAIN.auth_host))


tunnel_name_for = door_ops.tunnel_name_for


def secure_entry_url(stdout, tunnel_name):
    return door_ops.secure_entry_url(stdout, tunnel_name, DOMAIN)


def enrich(tunnel):
    return door_ops.enrich(tunnel, DOMAIN)


def find_unmanaged_frpc(state_dir):
    return door_ops.find_unmanaged_frpc(state_dir, DOMAIN)


_history_lock = door_ops._history_lock
_history_cache = door_ops._history_cache


def ensure_private_file(path):
    """Create `path` 0600 if missing; tighten it to 0600 if it exists."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.close(fd)
        os.chmod(str(p), 0o600)
    except OSError as e:
        log(f"could not secure {p}: {e}")


write_history = door_ops.write_history
latest_start_by_name = door_ops.latest_start_by_name


def read_history(history_path):
    return door_ops.read_history(history_path, log)


def revive_argv(rec, name):
    return door_ops.revive_argv(rec, name, REPO_ROOT)


def tool_log_path(name):
    return door_ops.tool_log_path(name, REPO_ROOT)

# ---------------------------------------------------------------------------
# Management console (GET /)
# ---------------------------------------------------------------------------
# Single page, no external resources: the CSP below is `default-src 'none'`
# with a per-response nonce for the one inline <style> and <script>, so there
# is nothing left for an injected string to load. __CSRF_TOKEN__ and __NONCE__
# are substituted server-side (both are hex, so no escaping is needed).

CONSOLE_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="light dark">
<title>Porch · tunnel control</title>
__PORCH_CSS__
<style nonce="__NONCE__">
/* ---- palette -------------------------------------------------------------
   Every colour comes from porch.css (night/day, porch-light accent); these
   are the console's own names for those tokens. */
:root{
  --bg:var(--ground);
  --surface-2:var(--ground);
  --surface-hover:var(--veil);
  --border:var(--line);
  --border-strong:var(--line-strong);
  --text-soft:var(--muted);
  --dim:var(--muted);
  --crit:var(--danger);
  --crit-soft:var(--danger-soft);
  --focus:var(--accent);
  --radius:var(--r-xl);
}

*{margin:0;padding:0;box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{
  background:var(--ground);
  color:var(--text);
  min-height:100vh;
  padding:24px 16px calc(64px + env(safe-area-inset-bottom));
  line-height:1.45;
}
.container{max-width:860px;width:100%;margin:0 auto}

/* ---- typography ---- */
h1{font-size:32px}
.subtitle{color:var(--muted);font-size:14px;margin-top:6px}
.lbl{font-size:13px;color:var(--muted);font-weight:500}
.sec-head .lbl:first-child{font:700 22px/1.2 var(--font-display);letter-spacing:-.02em;color:var(--text)}
.field .lbl{color:var(--text)}
.num{font-variant-numeric:tabular-nums;font-feature-settings:"tnum" 1}

/* ---- head ---- */
.head{margin-bottom:8px}
.head .p-bar{margin-bottom:24px}
.summary{
  margin-top:12px;font-size:13px;color:var(--text-soft);
  min-height:1.3em;
}
.summary .pill{
  display:inline-flex;align-items:center;gap:7px;
  border:1px solid var(--border);background:var(--surface-2);
  border-radius:999px;padding:5px 13px;
}
.dot{width:7px;height:7px;border-radius:50%;background:var(--ok);flex:0 0 7px}
.dot.stale{background:var(--warn)}
.dot.off{background:var(--crit)}

/* ---- cards / sections ---- */
section{margin-top:26px}
.sec-head{
  display:flex;align-items:baseline;justify-content:space-between;
  gap:12px;margin:0 4px 12px;
}
.card{
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:var(--radius);
}
.card + .card{margin-top:12px}

/* ---- tunnel card ---- */
.tunnel{
  --state:var(--accent);
  --state-soft:var(--accent-soft);
  position:relative;overflow:hidden;
  padding:16px 16px 14px 19px;
}
.tunnel::before{
  content:"";position:absolute;left:0;top:0;bottom:0;width:4px;
  background:var(--state);
}
.tunnel[data-urgency="warn"]{--state:var(--warn);--state-soft:var(--warn-soft)}
.tunnel[data-urgency="crit"]{--state:var(--crit);--state-soft:var(--crit-soft)}
.tunnel[data-urgency="warn"],.tunnel[data-urgency="crit"]{
  border-color:var(--state);
  background:linear-gradient(90deg,var(--state-soft),transparent 55%),var(--surface);
}
.t-top{display:flex;align-items:flex-start;gap:10px;flex-wrap:wrap}
.t-name{font-size:16px;font-weight:600;word-break:break-all}
.badge{
  display:inline-flex;align-items:center;min-height:24px;border-radius:999px;padding:0 10px;
  font-size:12px;font-weight:500;color:var(--accent-ink);
  background:var(--accent-soft);white-space:nowrap;
}
.badge.unmanaged{color:var(--warn);border-color:var(--warn);background:var(--warn-soft)}
.t-age{margin-left:auto;font-size:.72rem;color:var(--dim);white-space:nowrap}
.t-rules{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}
.t-rules[hidden]{display:none}
.badge.rule{color:var(--text);background:var(--veil);border:1px solid var(--border)}
.badge.opens{color:var(--text-soft);background:transparent;border:1px solid var(--border)}
.t-exp{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:12px}
.t-exp[hidden]{display:none}
.t-exp select,.t-exp input{width:auto;min-height:40px;padding:6px 10px;font-size:14px}
.t-exp input[hidden]{display:none}

/* url row: the copy button is the primary action, so it is the big target */
.t-url{
  display:flex;align-items:stretch;gap:8px;margin-top:12px;
  border:1px solid var(--border);border-radius:11px;
  background:var(--surface-2);overflow:hidden;
}
.t-url a{
  flex:1;min-width:0;display:block;
  padding:10px 12px;color:var(--accent);text-decoration:none;
  font:400 13.5px/1.35 var(--font-mono);
}
.t-url a{display:flex;align-items:center;white-space:nowrap;overflow:hidden}
.t-url a[hidden]{display:none}
/* a long name (63 chars, or an unmanaged frpc's) ellipsizes; the domain stays */
.t-url a .u-name{white-space:nowrap;font-weight:600;min-width:0;overflow:hidden;text-overflow:ellipsis}
.t-url a .u-rest{white-space:nowrap;color:var(--dim);flex:0 0 auto}
.t-top{min-width:0}
.t-name{min-width:0;overflow-wrap:anywhere}
.t-url a:hover{text-decoration:underline}
.t-url span.plain{
  flex:1;min-width:0;display:flex;align-items:center;padding:10px 12px;
  color:var(--dim);font-size:.86rem;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
}
.copy{
  flex:0 0 auto;display:flex;align-items:center;gap:7px;
  min-height:44px;padding:0 14px;border:none;border-left:1px solid var(--border);
  background:var(--surface-2);color:var(--text-soft);cursor:pointer;
  font-size:13px;font-weight:500;
  transition:background .15s,color .15s;
  -webkit-tap-highlight-color:transparent;
}
.copy:hover{background:var(--surface-hover);color:var(--text)}
.copy.done{color:var(--ok)}
.copy svg{width:15px;height:15px;fill:currentColor;flex:0 0 15px}

/* countdown + meter */
.t-time{
  display:flex;align-items:baseline;gap:10px;margin-top:14px;
}
.cd{
  font:500 22px/1.1 var(--font-mono);color:var(--state);
}
.cd.kept{font-size:1.02rem;font-weight:500;color:var(--ok)}
.cd.none{font-size:.95rem;font-weight:400;color:var(--dim)}
.cd.kept,.cd.none{font-family:var(--font-ui)}
.cd-sub{font-size:13px;color:var(--dim)}
.meter{
  height:4px;border-radius:2px;margin-top:9px;overflow:hidden;
  background:var(--border);
}
.meter i{
  display:block;height:100%;width:0;border-radius:2px;
  background:var(--state);transition:width .9s linear;
}
.tunnel[data-urgency="crit"] .cd{animation:pulse 1.6s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.45}}

/* ---- buttons ---- */
.actions{display:flex;gap:8px;margin-top:14px;flex-wrap:wrap}
.btn{
  min-height:40px;padding:0 15px;border-radius:10px;cursor:pointer;
  border:1px solid var(--border-strong);background:var(--accent-soft);
  color:var(--text);font-size:14px;font-weight:500;
  font-family:inherit;
  display:inline-flex;align-items:center;justify-content:center;gap:7px;
  transition:background .15s,border-color .15s,color .15s,opacity .15s;
  -webkit-tap-highlight-color:transparent;
}
.btn:hover{background:var(--surface-hover);border-color:var(--accent)}
.btn:disabled{opacity:.4;cursor:default}
.btn:disabled:hover{background:var(--accent-soft);border-color:var(--border-strong)}
.btn.ghost{background:transparent;border-color:var(--border);color:var(--text-soft)}
.btn.ghost:hover{background:var(--surface-hover);color:var(--text)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--on-accent);font-weight:600}
.btn.primary:hover{opacity:.88;background:var(--accent)}
.btn.danger{color:var(--crit);border-color:var(--crit);background:var(--crit-soft)}
.btn.danger:hover{background:var(--crit);color:#fff;border-color:var(--crit)}
.btn[aria-pressed="true"]{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}
.btn svg{width:14px;height:14px;fill:currentColor}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px;border-radius:6px}

/* ---- launch form ---- */
.form{padding:16px}
.field{margin-bottom:12px}
.field label{display:block;margin-bottom:6px}
input[type=text],select,textarea{
  width:100%;min-height:44px;padding:10px 12px;
  border:1px solid var(--border-strong);border-radius:var(--r-md);
  background:var(--surface-2);color:var(--text);
  font-family:inherit;font-size:15px;
}
input[type=text]{font-family:var(--font-mono)}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.check{display:flex;align-items:center;gap:10px;min-height:44px;cursor:pointer;font-size:.88rem}
.check input{width:18px;height:18px;accent-color:var(--accent);flex:0 0 18px}
textarea{min-height:110px;resize:vertical;font-family:var(--font-mono);font-size:14px}
input::placeholder,textarea::placeholder{color:var(--dim)}
input:hover,select:hover,textarea:hover{border-color:var(--border-strong)}
.hint{font-size:.72rem;color:var(--dim);margin-top:6px}
.form-row{display:flex;gap:10px;flex-wrap:wrap}
.form-row .field{flex:1 1 180px;margin-bottom:12px}
.msg{font-size:.82rem;margin-top:4px;min-height:1.2em;color:var(--dim)}
.msg.error{color:var(--crit)}
.msg.ok{color:var(--ok)}

/* ---- history ---- */
.hrow{
  display:flex;align-items:center;gap:10px;flex-wrap:wrap;
  padding:12px 16px;border-bottom:1px solid var(--border);
}
.hrow:last-child{border-bottom:none}
.hrow .t-name{font-size:.92rem;font-weight:500}
.hrow .h-age{font-size:.72rem;color:var(--dim)}
.hrow .h-act{margin-left:auto;display:flex;gap:8px}
.hrow .btn{min-height:36px;font-size:.76rem;padding:0 12px}

.empty{
  text-align:center;color:var(--dim);padding:32px 16px;font-size:14px;
}
.badge.why{color:var(--text-soft);background:transparent;border:1px solid var(--border)}
.badge.why.burned{color:var(--crit);border-color:var(--crit);background:var(--crit-soft)}

/* ---- asked to reopen ---- */
.card.asks{border-color:var(--accent)}
.arow{display:flex;flex-direction:column;gap:10px;padding:14px 16px;border-bottom:1px solid var(--border)}
.arow:last-child{border-bottom:none}
.arow .a-top{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap}
.arow .a-note{font-size:.95rem;color:var(--text);overflow-wrap:anywhere}
.arow .a-meta{font-size:.74rem;color:var(--dim);overflow-wrap:anywhere}
.arow .a-act{display:flex;gap:8px;flex-wrap:wrap}
.arow .btn{min-height:40px;font-size:.8rem}

/* ---- request inspector ---- */
.badge.inspb{color:var(--accent-ink);background:var(--accent-soft);border:1px solid var(--accent)}
.badge.raw{color:var(--warn);background:var(--warn-soft);border:1px solid var(--warn)}
.insp-live{font-size:13px;color:var(--dim);display:inline-flex;align-items:center;gap:7px;margin-left:auto}
.card.insp{display:grid;grid-template-columns:minmax(0,2fr) minmax(0,3fr);overflow:hidden;min-height:320px}
.insp-list{border-right:1px solid var(--border);max-height:70vh;overflow-y:auto}
.irow{
  display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:4px 10px;align-items:baseline;
  width:100%;padding:10px 14px;border:none;border-bottom:1px solid var(--border);
  background:transparent;color:var(--text);text-align:left;cursor:pointer;font:inherit;
}
.irow:hover{background:var(--surface-hover)}
.irow[aria-selected="true"]{background:var(--accent-soft)}
.irow .i-m{font:600 12px/1.4 var(--font-mono)}
.irow .i-p{font:400 13px/1.4 var(--font-mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.irow .i-s{font:600 12px/1.4 var(--font-mono)}
.irow .i-s.s2{color:var(--ok)}.irow .i-s.s3{color:var(--accent-ink)}
.irow .i-s.s4{color:var(--warn)}.irow .i-s.s5,.irow .i-s.s0{color:var(--crit)}
.irow .i-meta{grid-column:2 / 4;font-size:12px;color:var(--dim)}
.insp-detail{padding:16px;max-height:70vh;overflow-y:auto;min-width:0}
.insp-detail h3{font:600 14px/1.3 var(--font-ui);margin:18px 0 8px;color:var(--text)}
.insp-detail .d-head{font:500 14px/1.4 var(--font-mono);word-break:break-all}
.insp-detail .d-sub{font-size:13px;color:var(--dim);margin-top:4px}
.hdrs{display:grid;grid-template-columns:minmax(90px,max-content) minmax(0,1fr);gap:3px 12px;
  font:400 12.5px/1.45 var(--font-mono)}
.hdrs dt{color:var(--muted)}
.hdrs dd{word-break:break-all}
pre.body{font:400 12.5px/1.5 var(--font-mono);background:var(--ground);border:1px solid var(--border);
  border-radius:var(--r-md);padding:10px 12px;white-space:pre-wrap;word-break:break-all;
  max-height:420px;overflow:auto}
.insp-detail .note{font-size:12.5px;color:var(--dim);margin-top:6px}

/* ---- toasts ---- */
.toasts{
  position:fixed;left:50%;transform:translateX(-50%);
  bottom:calc(18px + env(safe-area-inset-bottom));
  display:flex;flex-direction:column;gap:8px;align-items:center;
  z-index:40;pointer-events:none;width:calc(100% - 32px);max-width:420px;
}
.toast{
  background:var(--surface);border:1px solid var(--border-strong);
  border-radius:var(--r-lg);padding:12px 16px;font-size:14px;color:var(--text);
  box-shadow:var(--shadow);
  animation:rise .22s ease-out;width:100%;text-align:center;
}
.toast.error{border-color:var(--crit);color:var(--crit)}
.toast.ok{border-color:var(--ok)}
@keyframes rise{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}

/* ---- confirm dialog ---- */
dialog{
  border:1px solid var(--border-strong);border-radius:var(--radius);
  background:var(--surface);color:var(--text);padding:22px;
  max-width:380px;width:calc(100% - 32px);box-shadow:var(--shadow);
}
dialog::backdrop{background:rgba(12,10,14,.6)}
dialog h2{font-size:20px;margin-bottom:8px}
dialog p{font-size:.86rem;color:var(--text-soft);margin-bottom:18px}
dialog .actions{margin-top:0;justify-content:flex-end}

/* ---- wall (non-owner / auth lost mid-session) ---- */
.wall{padding:44px 22px;text-align:center}
.wall h2{font-size:22px;margin-bottom:10px}
.wall p{color:var(--dim);font-size:.86rem;margin-bottom:18px}
.wall a{color:var(--accent)}

.sr-only{
  position:absolute;width:1px;height:1px;padding:0;margin:-1px;
  overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;border:0;
}

@media (max-width:720px){
  .card.insp{grid-template-columns:minmax(0,1fr)}
  .insp-list{border-right:none;border-bottom:1px solid var(--border);max-height:40vh}
  .insp-detail{max-height:none}
}

@media (max-width:520px){
  body{padding-top:24px}
  h1{font-size:28px}
  .t-age{margin-left:0;width:100%}
  .actions .btn{flex:1 1 auto}
  .copy span{display:none}
  .copy{padding:0 16px}
  /* 44px is the touch minimum (Apple HIG / WCAG 2.5.5). The desktop 40px is
     fine with a pointer, but this console is used one-handed on a phone to
     launch a tunnel and copy the link, so every control gets the full target
     at the mobile breakpoint. Measured at 390px: Launch and Refresh were the
     only two under 44. */
  .btn,.hrow .btn{min-height:44px}
  .t-url a{font-size:.82rem}
  .hrow .h-act{margin-left:0;width:100%}
  .hrow .h-act .btn{flex:1}
  .arow .btn{min-height:44px;flex:1 1 auto}
}

@media (prefers-reduced-motion: reduce){
  *,*::before,*::after{
    animation-duration:.001ms !important;animation-iteration-count:1 !important;
    transition-duration:.001ms !important;
  }
}
</style>
</head>
<body>
<div class="container">

  <header class="head">
    <div class="p-bar">
      <div class="p-brand">__MARK__porch<small>tunnel control</small></div>
    </div>
    <h1>Open now</h1>
    <div class="subtitle">Doors close after an hour unless you keep them open.</div>
    <div class="summary" id="summary" role="status" aria-live="polite"></div>
  </header>

  <!-- shown instead of everything else if the owner cookie stops validating -->
  <div class="card wall" id="wall" hidden>
    <h2>This browser isn&rsquo;t enrolled</h2>
    <p>Tunnel Control is limited to enrolled browsers.</p>
    <p><a href="https://__PORCH_AUTH_HOST__/auth/">Enrol this browser</a></p>
  </div>

  <div id="app">
    <section aria-labelledby="askHead" id="askSection" hidden>
      <div class="sec-head">
        <span class="lbl" id="askHead">Asked to reopen</span>
        <span class="lbl num" id="askCount"></span>
      </div>
      <div class="card asks" id="askList"></div>
    </section>

    <section aria-labelledby="activeHead">
      <div class="sec-head">
        <span class="lbl" id="activeHead">Active doors</span>
        <span class="lbl num" id="activeCount"></span>
      </div>
      <div id="tunnelList"></div>
    </section>

    <section id="inspView" aria-labelledby="inspHead" hidden>
      <div class="sec-head">
        <span class="lbl" id="inspHead">Inspect</span>
        <span class="insp-live" id="inspLive" role="status" aria-live="polite"></span>
        <button class="btn ghost" id="inspClose" type="button">Close</button>
      </div>
      <div class="card insp">
        <div class="insp-list" id="inspList" aria-label="Requests"></div>
        <div class="insp-detail" id="inspDetail"></div>
      </div>
    </section>

    <section aria-labelledby="launchHead">
      <div class="sec-head"><span class="lbl" id="launchHead">Open a new door</span></div>
      <div class="card form">
        <div class="form-row">
          <div class="field">
            <label class="lbl" for="launchType">Type</label>
            <select class="p-select" id="launchType">
              <option value="drop">drop &mdash; receive files</option>
              <option value="photos">photos &mdash; gallery</option>
              <option value="media">media &mdash; photos + video</option>
              <option value="music">music &mdash; player</option>
              <option value="exchange">exchange &mdash; text in/out</option>
              <option value="secure-entry">secure-entry &mdash; secret form</option>
              <option value="paste">paste &mdash; share text</option>
            </select>
          </div>
          <div class="field">
            <label class="lbl" for="launchName">Name</label>
            <input type="text" id="launchName" placeholder="my-tunnel" autocomplete="off"
                   autocapitalize="none" spellcheck="false" maxlength="41"
                   pattern="[a-z0-9][a-z0-9-]{0,40}" aria-describedby="nameHint">
            <div class="hint" id="nameHint">Lowercase letters, digits and dashes &mdash; becomes &lt;name&gt;.__PORCH_TUNNEL_BASE__</div>
          </div>
        </div>
        <div class="field" id="viewOnlyField" hidden>
          <label class="check" for="launchViewOnly">
            <input type="checkbox" id="launchViewOnly">
            View only (guests can watch, not upload/download)
          </label>
        </div>
        <div class="field" id="contentField" hidden>
          <label class="lbl" for="launchContent">Paste content</label>
          <textarea id="launchContent" placeholder="Text to publish&hellip;" spellcheck="false"></textarea>
        </div>
        <div class="actions">
          <button class="btn primary" id="launchBtn" type="button">Launch tunnel</button>
        </div>
        <div class="msg" id="launchMsg" role="status" aria-live="polite"></div>
      </div>
    </section>

    <section aria-labelledby="histHead">
      <div class="sec-head">
        <span class="lbl" id="histHead">Recently closed</span>
        <button class="btn ghost" id="histRefresh" type="button">Refresh</button>
      </div>
      <div class="card" id="historyList"></div>
    </section>
  </div>
</div>

<div class="toasts" id="toasts" role="status" aria-live="polite" aria-atomic="false"></div>

<dialog id="confirmDlg" aria-labelledby="confirmTitle">
  <h2 id="confirmTitle">Stop tunnel?</h2>
  <p id="confirmBody"></p>
  <div class="actions">
    <button class="btn ghost" id="confirmNo" type="button">Cancel</button>
    <button class="btn danger" id="confirmYes" type="button">Stop it</button>
  </div>
</dialog>

<script nonce="__NONCE__">
(function(){
'use strict';

// Substituted server-side; an HMAC of this browser's owner cookie.
var CSRF = '__CSRF_TOKEN__';

var POLL_MS = 5000;          // active-tunnel refresh
var HIST_MS = 30000;         // history refresh
var HOST_SUFFIX = '.__PORCH_TUNNEL_BASE__';
var WARN_S = 600;            // under 10m: "share this now" territory
var CRIT_S = 120;            // under 2m: about to drop
var FULL_TTL = 3600;         // one launch window, for the meter

var skew = 0;                // serverNow - clientNow, from /api/tunnels
var cards = Object.create(null);   // name -> {node, refs, data}
var lastOk = 0;
var offline = false;
var summaryKey = '';
var pollTimer = null, histTimer = null, tickTimer = null;

var listEl = document.getElementById('tunnelList');
var histEl = document.getElementById('historyList');
var summaryEl = document.getElementById('summary');
var countEl = document.getElementById('activeCount');
var toastEl = document.getElementById('toasts');
var appEl = document.getElementById('app');
var wallEl = document.getElementById('wall');

// ---- tiny DOM helpers ---------------------------------------------------
// Everything user-controlled goes in via textContent; no data ever reaches
// innerHTML. The only markup built from strings is the static icon path set.

function el(tag, cls, text){
  var n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = text;
  return n;
}

var ICONS = {
  copy: 'M16 1H4a2 2 0 0 0-2 2v14h2V3h12V1zm3 4H8a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2zm0 16H8V7h11v14z',
  check: 'M9 16.17 4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z'
};

function icon(name){
  var ns = 'http://www.w3.org/2000/svg';
  var svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  var p = document.createElementNS(ns, 'path');
  p.setAttribute('d', ICONS[name] || '');
  svg.appendChild(p);
  return svg;
}

function clear(node){ while (node.firstChild) node.removeChild(node.firstChild); }

// ---- formatting ---------------------------------------------------------

function pad(n){ return n < 10 ? '0' + n : String(n); }
function serverNow(){ return Date.now() / 1000 + skew; }

function fmtCountdown(sec){
  if (sec <= 0) return 'expired';
  var h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = Math.floor(sec % 60);
  return h > 0 ? h + ':' + pad(m) + ':' + pad(s) : m + ':' + pad(s);
}

// Screen-reader friendly version — digits-with-colons reads badly.
function fmtSpoken(sec){
  if (sec <= 0) return 'expired';
  var h = Math.floor(sec / 3600), m = Math.round((sec % 3600) / 60);
  if (h > 0) return h + ' hour' + (h === 1 ? '' : 's') + ' ' + m + ' minute' + (m === 1 ? '' : 's') + ' remaining';
  if (sec < 60) return 'under a minute remaining';
  return m + ' minute' + (m === 1 ? '' : 's') + ' remaining';
}

function fmtAge(started){
  if (!started) return '';
  var sec = Math.max(0, serverNow() - started);
  if (sec < 60) return 'just now';
  var m = Math.floor(sec / 60);
  if (m < 60) return m + 'm ago';
  var h = Math.floor(m / 60);
  if (h < 24) return h + 'h ' + (m % 60) + 'm ago';
  return Math.floor(h / 24) + 'd ago';
}

function urgency(sec){
  if (sec === null) return 'none';
  if (sec <= CRIT_S) return 'crit';
  if (sec <= WARN_S) return 'warn';
  return 'ok';
}

// Only accept URLs we generated ourselves: https on the tunnel domain. Keeps a
// hostile state file from turning into a javascript: or data: link.
function safeUrl(u){
  if (typeof u !== 'string') return null;
  var p;
  try { p = new URL(u); } catch (e) { return null; }
  if (p.protocol !== 'https:') return null;
  if (p.hostname !== HOST_SUFFIX.slice(1) && p.hostname.slice(-HOST_SUFFIX.length) !== HOST_SUFFIX) return null;
  return p.href;
}

// ---- toasts -------------------------------------------------------------

function toast(msg, kind){
  var t = el('div', 'toast' + (kind ? ' ' + kind : ''), msg);
  toastEl.appendChild(t);
  setTimeout(function(){ if (t.parentNode) t.parentNode.removeChild(t); }, 3600);
}

// ---- API ----------------------------------------------------------------

function api(path, method, body){
  var opts = {
    method: method || 'GET',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { 'X-CSRF-Token': CSRF }
  };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  return fetch(path, opts).then(function(r){
    if (r.status === 403) { showWall(); throw new Error('forbidden'); }
    return r.json().catch(function(){ return null; }).then(function(data){
      if (!r.ok) {
        throw new Error((data && data.message) ? data.message : 'Request failed (' + r.status + ')');
      }
      return data;
    });
  });
}

function showWall(){
  stopTimers();
  appEl.hidden = true;
  wallEl.hidden = false;
  summaryEl.textContent = '';
  countEl.textContent = '';
}

// ---- active tunnels -----------------------------------------------------

function buildCard(t){
  var node = el('article', 'card tunnel');
  node.setAttribute('data-name', t.name);

  var top = el('div', 't-top');
  var name = el('span', 't-name');
  var badge = el('span', 'badge');
  var age = el('span', 't-age');
  top.appendChild(name); top.appendChild(badge); top.appendChild(age);

  var urlRow = el('div', 't-url');
  var link = el('a');
  link.target = '_blank';
  link.rel = 'noopener noreferrer';
  var uName = el('span', 'u-name');
  var uRest = el('span', 'u-rest');
  link.appendChild(uName); link.appendChild(uRest);
  var plain = el('span', 'plain');
  plain.hidden = true;
  var copyBtn = el('button', 'copy');
  copyBtn.type = 'button';
  copyBtn.appendChild(icon('copy'));
  copyBtn.appendChild(el('span', null, 'Copy'));
  copyBtn.setAttribute('aria-label', 'Copy tunnel URL');
  urlRow.appendChild(link); urlRow.appendChild(plain); urlRow.appendChild(copyBtn);

  var rulesRow = el('div', 't-rules');
  rulesRow.hidden = true;

  var timeRow = el('div', 't-time');
  var cd = el('span', 'cd num');
  cd.setAttribute('role', 'timer');
  var cdSub = el('span', 'cd-sub');
  timeRow.appendChild(cd); timeRow.appendChild(cdSub);

  var meter = el('div', 'meter');
  var fill = document.createElement('i');
  meter.appendChild(fill);

  var actions = el('div', 'actions');
  var extend = el('button', 'btn', '+1 hour');
  extend.type = 'button';
  var keep = el('button', 'btn', 'Keep alive');
  keep.type = 'button';
  keep.setAttribute('aria-pressed', 'false');
  var expBtn = el('button', 'btn ghost', 'Set expiry');
  expBtn.type = 'button';
  expBtn.setAttribute('aria-expanded', 'false');
  var stop = el('button', 'btn danger', 'Stop');
  stop.type = 'button';
  var inspBtn = el('button', 'btn ghost', 'Inspect');
  inspBtn.type = 'button';
  inspBtn.hidden = true;
  actions.appendChild(extend); actions.appendChild(keep); actions.appendChild(expBtn);
  actions.appendChild(inspBtn); actions.appendChild(stop);

  // Exact expiry: a preset, a local date/time, or never.
  var expRow = el('div', 't-exp');
  expRow.hidden = true;
  var expSel = el('select');
  expSel.setAttribute('aria-label', 'Expire');
  [['+30m', 'in 30 minutes'], ['+1h', 'in 1 hour'], ['+2h', 'in 2 hours'], ['+6h', 'in 6 hours'],
   ['+1d', 'in 1 day'], ['+7d', 'in 7 days'], ['never', 'never'], ['at', 'at a time…']]
    .forEach(function(o){ var op = el('option', null, o[1]); op.value = o[0]; expSel.appendChild(op); });
  var expAt = el('input');
  expAt.type = 'datetime-local';
  expAt.setAttribute('aria-label', 'Expiry date and time');
  expAt.hidden = true;
  var expSet = el('button', 'btn primary', 'Set');
  expSet.type = 'button';
  expRow.appendChild(expSel); expRow.appendChild(expAt); expRow.appendChild(expSet);

  node.appendChild(top); node.appendChild(urlRow); node.appendChild(rulesRow);
  node.appendChild(timeRow); node.appendChild(meter); node.appendChild(actions);
  node.appendChild(expRow);

  var entry = {
    node: node,
    name: name, badge: badge, age: age,
    link: link, uName: uName, uRest: uRest, plain: plain, copy: copyBtn,
    cd: cd, cdSub: cdSub, meter: meter, fill: fill, rules: rulesRow,
    extend: extend, keep: keep, stop: stop, insp: inspBtn,
    expBtn: expBtn, expRow: expRow, expSel: expSel, expAt: expAt, expSet: expSet,
    data: t
  };

  copyBtn.addEventListener('click', function(){ copyUrl(entry); });
  extend.addEventListener('click', function(){ doExtend(entry); });
  keep.addEventListener('click', function(){ doKeepAlive(entry); });
  stop.addEventListener('click', function(){ askStop(entry); });
  inspBtn.addEventListener('click', function(){ openInspect(entry.data); });
  expBtn.addEventListener('click', function(){
    expRow.hidden = !expRow.hidden;
    expBtn.setAttribute('aria-expanded', expRow.hidden ? 'false' : 'true');
    if (!expRow.hidden) expSel.focus();
  });
  expSel.addEventListener('change', function(){ expAt.hidden = expSel.value !== 'at'; });
  expSet.addEventListener('click', function(){ doExpire(entry); });

  return entry;
}

function fillCard(entry, t){
  entry.data = t;
  entry.name.textContent = t.name;
  entry.badge.textContent = t.type || 'tunnel';
  entry.badge.className = 'badge' + (t.type === 'unmanaged' ? ' unmanaged' : '');
  entry.age.textContent = t.started ? 'started ' + fmtAge(t.started) : '';

  var url = safeUrl(t.url);
  if (url) {
    entry.link.hidden = false;
    entry.plain.hidden = true;
    entry.link.href = url;
    entry.link.title = url;
    // Split at the shared suffix so the subdomain — the only part that varies —
    // stays whole and legible when the line has to wrap.
    var host = url.replace(/^https:\/\//, '').replace(/\/$/, '');
    if (host.slice(-HOST_SUFFIX.length) === HOST_SUFFIX) {
      entry.uName.textContent = host.slice(0, -HOST_SUFFIX.length);
      entry.uRest.textContent = HOST_SUFFIX;
    } else {
      entry.uName.textContent = host;
      entry.uRest.textContent = '';
    }
    entry.copy.disabled = false;
  } else {
    // Unparseable name (an unmanaged frpc we couldn't read cleanly). Show it,
    // but never as a clickable link.
    entry.link.hidden = true;
    entry.plain.hidden = false;
    entry.plain.textContent = String(t.url || 'no url');
    entry.copy.disabled = true;
  }

  var managed = t.type !== 'unmanaged' && (t.never || typeof t.expires === 'number');
  entry.extend.disabled = !managed || !!t.never;
  entry.keep.disabled = !managed;
  entry.expBtn.disabled = !managed;
  if (!managed) { entry.expRow.hidden = true; }
  entry.keep.setAttribute('aria-pressed', t.never ? 'true' : 'false');
  entry.keep.textContent = t.never ? 'Never expires' : 'Keep alive';
  entry.insp.hidden = !t.inspect;
  fillRules(entry, t);

  tickCard(entry);
}

// Share rules + open count as small badges (names only, from the API's
// booleans; never a hash or token).
function fillRules(entry, t){
  var r = t.rules || {};
  clear(entry.rules);
  var any = false;
  function add(text, cls){ entry.rules.appendChild(el('span', 'badge ' + cls, text)); any = true; }
  if (r.password) add('password', 'rule');
  if (r.guest_link) add('guest link', 'rule');
  if (typeof r.max_opens === 'number') add(r.max_opens === 1 ? 'burn after 1 open' : 'max ' + r.max_opens + ' opens', 'rule');
  if (t.capture) add('webhook', 'inspb');
  else if (t.inspect) add('inspecting', 'inspb');
  if (t.inspect_raw) add('raw: unmasked', 'raw');
  var opens = typeof t.opens === 'number' ? t.opens : 0;
  if (any || opens > 0) {
    var o = opens + (opens === 1 ? ' open' : ' opens');
    if (typeof t.last_open === 'number') o += ' · last ' + fmtAge(t.last_open);
    add(o, 'opens');
  }
  entry.rules.hidden = !any;
}

// Exact local time of an epoch, e.g. "Mon 19 Oct, 15:45".
function fmtWhen(epoch){
  var d = new Date(epoch * 1000);
  return d.toLocaleString(undefined, {weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit'});
}

// Countdown repaint — runs once a second, no network.
function tickCard(entry){
  var t = entry.data;
  if (t.never || t.keep_alive) {
    entry.cd.textContent = '∞';
    entry.cd.className = 'cd kept';
    entry.cd.setAttribute('aria-label', 'never expires');
    entry.cdSub.textContent = 'never expires';
    entry.meter.hidden = false;
    entry.fill.style.width = '100%';
    entry.node.setAttribute('data-urgency', 'none');
    return;
  }
  if (t.expires === null || t.expires === undefined) {
    entry.cd.textContent = 'no timer';
    entry.cd.className = 'cd none';
    entry.cd.setAttribute('aria-label', 'no expiry tracked');
    entry.cdSub.textContent = 'not started by Porch';
    entry.meter.hidden = true;
    entry.node.setAttribute('data-urgency', 'none');
    return;
  }
  var left = Math.max(0, t.expires - serverNow());
  entry.cd.className = 'cd num';
  entry.cd.textContent = fmtCountdown(left);
  entry.meter.hidden = false;
  entry.cd.setAttribute('aria-label', fmtSpoken(left));
  entry.cdSub.textContent = left <= 0 ? 'gone' : ((left <= WARN_S ? 'expiring soon · ' : 'until ') + fmtWhen(t.expires));
  entry.fill.style.width = Math.min(100, (left / FULL_TTL) * 100) + '%';
  entry.node.setAttribute('data-urgency', urgency(left));
}

function renderTunnels(list){
  var seen = Object.create(null);
  var frag = document.createDocumentFragment();

  list.forEach(function(t){
    if (!t || typeof t.name !== 'string') return;
    seen[t.name] = true;
    var entry = cards[t.name];
    if (!entry) {
      entry = cards[t.name] = buildCard(t);
    }
    fillCard(entry, t);
    frag.appendChild(entry.node);
  });

  Object.keys(cards).forEach(function(name){
    if (!seen[name]) {
      if (insp.name === name) inspClosed();
      var n = cards[name].node;
      if (n.parentNode) n.parentNode.removeChild(n);
      delete cards[name];
    }
  });

  // Re-appending in order is cheap and keeps the DOM order == server order.
  listEl.appendChild(frag);

  if (!list.length) {
    if (!listEl.querySelector('.empty')) {
      clear(listEl);
      listEl.appendChild(el('div', 'card empty', 'No active tunnels. Launch one below.'));
    }
  } else {
    var e = listEl.querySelector('.empty');
    if (e) e.parentNode.removeChild(e);
  }
}

function updateSummary(list){
  var live = list.filter(function(t){ return !t.keep_alive && !t.never && typeof t.expires === 'number'; });
  var soonest = null;
  live.forEach(function(t){
    var left = Math.max(0, t.expires - serverNow());
    if (soonest === null || left < soonest) soonest = left;
  });

  countEl.textContent = list.length ? list.length + (list.length === 1 ? ' tunnel' : ' tunnels') : '';

  // Coarse key so the live region only speaks when something meaningful moved:
  // per-minute once something is close to expiry, 15-minute steps otherwise.
  var bucket;
  if (offline) bucket = 'offline';
  else if (soonest === null) bucket = 'none';
  else if (soonest <= 0) bucket = 'expired';
  else if (soonest <= WARN_S) bucket = 'm' + Math.ceil(soonest / 60);
  else bucket = 'q' + Math.ceil(soonest / 900);
  var key = list.length + '|' + bucket;
  if (key === summaryKey) return;
  summaryKey = key;

  clear(summaryEl);
  var pill = el('span', 'pill');
  var dot = el('span', 'dot' + (offline ? ' off' : ''));
  pill.appendChild(dot);
  var text;
  if (offline) {
    text = 'Lost contact with the status API';
  } else if (!list.length) {
    text = 'Nothing running';
  } else if (soonest === null) {
    text = list.length + ' active, none expiring';
  } else if (soonest <= 0) {
    text = list.length + ' active · one has expired';
  } else if (soonest <= WARN_S) {
    text = list.length + ' active · one expires in under ' + Math.ceil(soonest / 60) + ' min';
  } else {
    // Matches the 15-minute key bucket, so the line can never read stale.
    text = list.length + ' active · next expires in under ' + (Math.ceil(soonest / 900) * 15) + ' min';
  }
  pill.appendChild(el('span', null, text));
  summaryEl.appendChild(pill);
}

function fetchTunnels(){
  return api('api/tunnels').then(function(data){
    var list = Array.isArray(data) ? data : [];
    // Trust the server's clock, not the phone's.
    list.some(function(t){
      if (t && !t.never && typeof t.expires === 'number' && typeof t.time_remaining === 'number') {
        skew = (t.expires - t.time_remaining) - Date.now() / 1000;
        return true;
      }
      return false;
    });
    lastOk = Date.now();
    if (offline) { offline = false; summaryKey = ''; }
    renderTunnels(list);
    updateSummary(list);
  }).catch(function(err){
    if (err && err.message === 'forbidden') return;
    if (Date.now() - lastOk > 12000 && !offline) { offline = true; summaryKey = ''; updateSummary(currentList()); }
  });
}

function currentList(){
  return Object.keys(cards).map(function(n){ return cards[n].data; });
}

function tick(){
  Object.keys(cards).forEach(function(n){ tickCard(cards[n]); });
  updateSummary(currentList());
}

// ---- actions ------------------------------------------------------------

function copyUrl(entry){
  var url = safeUrl(entry.data.url);
  if (!url) return;
  var done = function(){
    entry.copy.classList.add('done');
    clear(entry.copy);
    entry.copy.appendChild(icon('check'));
    entry.copy.appendChild(el('span', null, 'Copied'));
    setTimeout(function(){
      entry.copy.classList.remove('done');
      clear(entry.copy);
      entry.copy.appendChild(icon('copy'));
      entry.copy.appendChild(el('span', null, 'Copy'));
    }, 1600);
  };
  var fallback = function(){
    var ta = document.createElement('textarea');
    ta.value = url;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    document.body.removeChild(ta);
    if (ok) done(); else toast('Copy failed — long-press the link instead', 'error');
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(url).then(done, fallback);
  } else {
    fallback();
  }
}

function copyText(text, done){
  var fallback = function(){
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    document.body.removeChild(ta);
    if (ok) done(); else toast('Copy failed', 'error');
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done, fallback);
  } else {
    fallback();
  }
}

function busy(btn, on){
  btn.disabled = !!on;
  btn.setAttribute('aria-busy', on ? 'true' : 'false');
}

function doExtend(entry){
  var name = entry.data.name;
  busy(entry.extend, true);
  api('api/tunnels/' + encodeURIComponent(name) + '/extend', 'POST')
    .then(function(res){
      if (res && typeof res.expires === 'number') {
        entry.data.expires = res.expires;
        tickCard(entry);
      }
      toast(name + ' extended by an hour', 'ok');
      summaryKey = '';
      fetchTunnels();
    })
    .catch(function(err){ if (err.message !== 'forbidden') toast(err.message, 'error'); })
    .then(function(){ busy(entry.extend, false); });
}

function applyExpiry(entry, res){
  if (!res) return;
  entry.data.never = !!res.never;
  entry.data.keep_alive = !!res.keep_alive;
  entry.data.expires = res.expires;
  if (typeof res.time_remaining === 'number' && typeof res.expires === 'number') {
    skew = (res.expires - res.time_remaining) - Date.now() / 1000;
  }
  fillCard(entry, entry.data);
}

function doKeepAlive(entry){
  var name = entry.data.name;
  busy(entry.keep, true);
  api('api/tunnels/' + encodeURIComponent(name) + '/keep-alive', 'POST')
    .then(function(res){
      applyExpiry(entry, res);
      toast(name + (entry.data.never ? ' will never expire' : ' is back on a timer'), 'ok');
      summaryKey = '';
    })
    .catch(function(err){ if (err.message !== 'forbidden') toast(err.message, 'error'); })
    .then(function(){ busy(entry.keep, false); });
}

function doExpire(entry){
  var name = entry.data.name;
  var v = entry.expSel.value;
  var at = v;
  if (v === 'at') {
    var ms = entry.expAt.value ? new Date(entry.expAt.value).getTime() : NaN;
    if (!isFinite(ms)) { toast('Pick a date and time first', 'error'); return; }
    at = Math.round(ms / 1000);
  }
  busy(entry.expSet, true);
  api('api/tunnels/' + encodeURIComponent(name) + '/expire', 'POST', {at: at})
    .then(function(res){
      applyExpiry(entry, res);
      toast(name + (entry.data.never ? ' will never expire' : ' expires ' + fmtWhen(entry.data.expires)), 'ok');
      entry.expRow.hidden = true;
      entry.expBtn.setAttribute('aria-expanded', 'false');
      summaryKey = '';
    })
    .catch(function(err){ if (err.message !== 'forbidden') toast(err.message, 'error'); })
    .then(function(){ busy(entry.expSet, false); });
}

// ---- stop (destructive → confirm) --------------------------------------

var dlg = document.getElementById('confirmDlg');
var dlgBody = document.getElementById('confirmBody');
var dlgYes = document.getElementById('confirmYes');
var dlgNo = document.getElementById('confirmNo');
var pendingStop = null;
var lastFocus = null;

function askStop(entry){
  pendingStop = entry;
  dlgBody.textContent = 'Stopping "' + entry.data.name + '" kills the process and the link dies immediately. There is no undo.';
  lastFocus = document.activeElement;
  if (typeof dlg.showModal === 'function') {
    dlg.showModal();
    dlgNo.focus();
  } else if (window.confirm('Stop "' + entry.data.name + '"? The link dies immediately.')) {
    doStop(entry);
  }
}

function closeDlg(){
  if (dlg.open) dlg.close();
  pendingStop = null;
  if (lastFocus && lastFocus.focus) lastFocus.focus();
}

dlgNo.addEventListener('click', closeDlg);
dlg.addEventListener('cancel', function(){
  pendingStop = null;
  if (lastFocus && lastFocus.focus) lastFocus.focus();
});
dlgYes.addEventListener('click', function(){
  var entry = pendingStop;
  closeDlg();
  if (entry) doStop(entry);
});

function doStop(entry){
  var name = entry.data.name;
  busy(entry.stop, true);
  api('api/tunnels/' + encodeURIComponent(name) + '/stop', 'POST')
    .then(function(){
      toast(name + ' stopped', 'ok');
      summaryKey = '';
      fetchTunnels();
      fetchHistory();
    })
    .catch(function(err){
      if (err.message !== 'forbidden') toast(err.message, 'error');
      busy(entry.stop, false);
    });
}

// ---- history ------------------------------------------------------------

function renderHistory(items){
  clear(histEl);
  if (!items.length) {
    histEl.appendChild(el('div', 'empty', 'Nothing in the launch history yet.'));
    return;
  }
  items.forEach(function(h){
    if (!h || typeof h.name !== 'string') return;
    var row = el('div', 'hrow');
    row.appendChild(el('span', 't-name', h.name));
    row.appendChild(el('span', 'badge', h.type || 'tunnel'));
    row.appendChild(el('span', 'h-age', h.started ? fmtAge(h.started) : ''));

    if (h.reason) {
      row.appendChild(el('span', 'badge why' + (h.reason === 'burned' || h.reason === 'used-up' ? ' burned' : ''),
                         h.reason === 'used-up' ? 'used up' : h.reason));
    }

    var acts = el('div', 'h-act');
    var revive = el('button', 'btn', 'Revive');
    revive.type = 'button';
    revive.disabled = !h.revivable;
    if (!h.revivable) revive.title = h.reopen_why || 'This tool type cannot be revived';
    var forget = el('button', 'btn ghost', 'Forget');
    forget.type = 'button';
    if (h.reopenable) {
      // A launch recipe brings it back as it was: same file, rules and links.
      ['1h', '24h'].forEach(function(exp){
        var b = el('button', 'btn' + (exp === '1h' ? ' primary' : ''), 'Reopen ' + exp);
        b.type = 'button';
        b.setAttribute('aria-label', 'Reopen ' + h.name + ' for ' + (exp === '1h' ? 'an hour' : '24 hours'));
        b.addEventListener('click', function(){
          busy(b, true);
          api('api/history/' + encodeURIComponent(h.name) + '/reopen', 'POST', {expires: exp})
            .then(function(){ toast(h.name + ' is open again for ' + exp, 'ok'); fetchTunnels(); fetchHistory(); })
            .catch(function(err){
              if (err.message !== 'forbidden') toast(err.message, 'error');
              busy(b, false);
            });
        });
        acts.appendChild(b);
      });
    } else {
      acts.appendChild(revive);
    }
    acts.appendChild(forget);
    row.appendChild(acts);

    revive.addEventListener('click', function(){
      busy(revive, true);
      api('api/history/' + encodeURIComponent(h.name) + '/revive', 'POST')
        .then(function(){ toast(h.name + ' revived', 'ok'); fetchTunnels(); fetchHistory(); })
        .catch(function(err){
          if (err.message !== 'forbidden') toast(err.message, 'error');
          busy(revive, false);
        });
    });
    forget.addEventListener('click', function(){
      busy(forget, true);
      api('api/history/' + encodeURIComponent(h.name) + '/forget', 'POST')
        .then(function(){ fetchHistory(); })
        .catch(function(err){
          if (err.message !== 'forbidden') toast(err.message, 'error');
          busy(forget, false);
        });
    });

    histEl.appendChild(row);
  });
}

// ---- asked to reopen -----------------------------------------------------

var askSection = document.getElementById('askSection');
var askList = document.getElementById('askList');
function renderAsks(list){
  var pending = list.filter(function(r){ return r && r.state === 'pending' && r.until > serverNow(); });
  askSection.hidden = pending.length === 0;
  document.getElementById('askCount').textContent = pending.length ? String(pending.length) : '';
  clear(askList);
  pending.forEach(function(r){
    var row = el('div', 'arow');
    var top = el('div', 'a-top');
    top.appendChild(el('span', 't-name', r.name));
    if (r.type) top.appendChild(el('span', 'badge', r.type));
    row.appendChild(top);
    row.appendChild(el('div', 'a-note', r.note ? '\u201c' + r.note + '\u201d' : 'No name given'));
    var bits = ['asked ' + fmtAge(r.created)];
    if (r.ip) bits.push('from ' + r.ip);
    if (r.waiting > 1) bits.push(r.waiting + ' people waiting');
    if (r.closed) bits.push((r.reason === 'expired' ? 'expired ' : 'closed ') + fmtAge(r.closed));
    row.appendChild(el('div', 'a-meta', bits.join(' \u00b7 ')));
    var acts = el('div', 'a-act');
    [['allow', '1h', 'Allow 1h', 'btn primary'], ['allow', '24h', 'Allow 24h', 'btn'],
     ['deny', null, 'Deny', 'btn ghost']].forEach(function(d){
      var b = el('button', d[3], d[2]);
      b.type = 'button';
      b.addEventListener('click', function(){
        busy(b, true);
        api('api/reopen-requests/' + encodeURIComponent(r.id) + '/decide', 'POST',
            d[1] ? {decision: d[0], expires: d[1]} : {decision: d[0]})
          .then(function(){
            toast(d[0] === 'deny' ? 'Told them not now' : r.name + ' is open again for ' + d[1], 'ok');
            fetchAsks(); fetchTunnels(); fetchHistory();
          })
          .catch(function(err){
            if (err.message !== 'forbidden') toast(err.message, 'error');
            busy(b, false);
          });
      });
      acts.appendChild(b);
    });
    row.appendChild(acts);
    askList.appendChild(row);
  });
}
function fetchAsks(){
  return api('api/reopen-requests').then(function(data){
    renderAsks(Array.isArray(data) ? data : []);
  }).catch(function(){});
}

function fetchHistory(){
  return api('api/history').then(function(data){
    renderHistory(Array.isArray(data) ? data : []);
  }).catch(function(){});
}

// ---- launch -------------------------------------------------------------

var typeSel = document.getElementById('launchType');
var nameInput = document.getElementById('launchName');
var contentField = document.getElementById('contentField');
var contentInput = document.getElementById('launchContent');
var viewOnlyField = document.getElementById('viewOnlyField');
var viewOnlyInput = document.getElementById('launchViewOnly');
var launchBtn = document.getElementById('launchBtn');
var launchMsg = document.getElementById('launchMsg');
var NAME_RE = /^[a-z0-9][a-z0-9-]{0,40}$/;

typeSel.addEventListener('change', function(){
  contentField.hidden = (typeSel.value !== 'paste');
  viewOnlyField.hidden = (typeSel.value !== 'media');
});

nameInput.addEventListener('keydown', function(e){
  if (e.key === 'Enter') { e.preventDefault(); launch(); }
});

function launch(){
  launchMsg.className = 'msg';
  launchMsg.textContent = '';
  var name = nameInput.value.trim().toLowerCase();
  if (!NAME_RE.test(name)) {
    launchMsg.className = 'msg error';
    launchMsg.textContent = 'Names are lowercase letters, digits and dashes (max 41 chars).';
    nameInput.focus();
    return;
  }
  var body = { type: typeSel.value, name: name };
  if (typeSel.value === 'paste') body.content = contentInput.value;
  if (typeSel.value === 'media') body.view_only = viewOnlyInput.checked;

  busy(launchBtn, true);
  launchMsg.textContent = 'Launching ' + name + '…';
  api('api/launch', 'POST', body)
    .then(function(res){
      nameInput.value = '';
      contentInput.value = '';
      viewOnlyInput.checked = false;
      launchMsg.className = 'msg ok';
      launchMsg.textContent = (res && res.url) ? res.url + ' is live' : name + ' is live';
      toast(name + ' launched', 'ok');
      summaryKey = '';
      fetchTunnels();
      fetchHistory();
    })
    .catch(function(err){
      if (err.message === 'forbidden') return;
      launchMsg.className = 'msg error';
      launchMsg.textContent = err.message;
    })
    .then(function(){ busy(launchBtn, false); });
}

launchBtn.addEventListener('click', launch);
document.getElementById('histRefresh').addEventListener('click', fetchHistory);

// ---- request inspector -------------------------------------------------
// Live list from an EventSource on api/tunnels/<name>/requests/events (polls
// ?since= where EventSource is missing), detail from .../requests/<id>.
// Header values arrive already masked unless the door is raw; everything
// goes into the DOM as textContent.

var inspView = document.getElementById('inspView');
var inspHead = document.getElementById('inspHead');
var inspLive = document.getElementById('inspLive');
var inspList = document.getElementById('inspList');
var inspDetail = document.getElementById('inspDetail');
var INSP_ROWS = 500;
var insp = {name: null, door: null, es: null, poll: null, rows: Object.create(null),
            order: [], last: 0, selected: null};
var CURL_SKIP = /^(host|connection|content-length|transfer-encoding|keep-alive|x-forwarded-for|x-forwarded-proto|x-porch-replay)$/i;

function inspBase(){ return 'api/tunnels/' + encodeURIComponent(insp.name) + '/requests'; }

function setLive(text, kind){
  clear(inspLive);
  inspLive.appendChild(el('span', 'dot' + (kind ? ' ' + kind : '')));
  inspLive.appendChild(el('span', null, text));
}

function fmtBytes(n){
  n = +n || 0;
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(1) + ' MB';
}

function openInspect(t){
  closeInspect();
  insp.name = t.name;
  insp.door = t;
  inspHead.textContent = (t.capture ? 'Webhook · ' : 'Inspect · ') + t.name;
  clear(inspList);
  inspList.appendChild(el('div', 'empty', 'No requests yet. They appear here as they arrive.'));
  showDetailEmpty();
  inspView.hidden = false;
  setLive('loading…', 'stale');
  api(inspBase()).then(function(data){
    (data && Array.isArray(data.records) ? data.records : []).forEach(addInspRow);
    insp.last = (data && typeof data.last === 'number') ? data.last : 0;
    startInspStream();
  }).catch(function(err){
    if (err.message !== 'forbidden') { setLive(err.message, 'off'); }
  });
  inspView.scrollIntoView({behavior: 'smooth', block: 'start'});
}

function stopInspStream(){
  if (insp.es) { insp.es.close(); insp.es = null; }
  if (insp.poll) { clearInterval(insp.poll); insp.poll = null; }
}

function closeInspect(){
  stopInspStream();
  insp.name = null; insp.door = null; insp.rows = Object.create(null); insp.order = [];
  insp.selected = null; insp.last = 0;
  inspView.hidden = true;
}

function inspClosed(){
  stopInspStream();
  setLive('door closed', 'off');
}

function startInspStream(){
  var name = insp.name;
  if (window.EventSource) {
    var es = new EventSource(inspBase() + '/events?since=' + insp.last);
    insp.es = es;
    es.onopen = function(){ if (insp.name === name) setLive('live'); };
    es.addEventListener('request', function(e){
      if (insp.name !== name) return;
      try { addInspRow(JSON.parse(e.data)); } catch (x) { /* ignore a bad event */ }
    });
    es.addEventListener('closed', function(){ if (insp.name === name) inspClosed(); });
    es.onerror = function(){ if (insp.name === name && insp.es) setLive('reconnecting…', 'stale'); };
  } else {
    setLive('live (polling)');
    insp.poll = setInterval(function(){
      if (insp.name !== name) return;
      api(inspBase() + '?since=' + insp.last).then(function(data){
        (data && Array.isArray(data.records) ? data.records : []).forEach(addInspRow);
      }).catch(function(){ setLive('reconnecting…', 'stale'); });
    }, 3000);
  }
}

function statusClass(st){
  if (typeof st !== 'number') return 's0';
  return 's' + Math.min(5, Math.max(1, Math.floor(st / 100)));
}

function addInspRow(r){
  if (!r || typeof r.id !== 'number' || insp.rows[r.id]) return;
  if (r.id > insp.last) insp.last = r.id;
  var e = inspList.querySelector('.empty');
  if (e) e.parentNode.removeChild(e);
  var row = el('button', 'irow');
  row.type = 'button';
  row.setAttribute('aria-selected', 'false');
  row.appendChild(el('span', 'i-m', String(r.method || '?')));
  row.appendChild(el('span', 'i-p', String(r.target || '')));
  row.appendChild(el('span', 'i-s ' + statusClass(r.status), r.status ? String(r.status) : '—'));
  var meta = '#' + r.id + ' · ' + new Date((r.ts || 0) * 1000).toLocaleTimeString() + ' · ' +
             (typeof r.ms === 'number' ? Math.round(r.ms) + ' ms' : '–') + ' · ' + fmtBytes(r.resp_bytes);
  if (r.replay_of) meta += ' · replay of #' + r.replay_of;
  else if (r.upgraded) meta += ' · websocket';
  else if (r.handled_by === 'gate') meta += ' · gate';
  if (r.error) meta += ' · ' + r.error;
  row.appendChild(el('span', 'i-meta', meta));
  row.addEventListener('click', function(){ selectInsp(r.id); });
  insp.rows[r.id] = row;
  insp.order.push(r.id);
  inspList.insertBefore(row, inspList.firstChild);
  while (insp.order.length > INSP_ROWS) {
    var old = insp.order.shift();
    var n = insp.rows[old];
    if (n && n.parentNode) n.parentNode.removeChild(n);
    delete insp.rows[old];
  }
}

function showDetailEmpty(){
  clear(inspDetail);
  inspDetail.appendChild(el('div', 'empty', 'Pick a request to see its headers and body.'));
}

function selectInsp(id){
  if (insp.selected && insp.rows[insp.selected]) insp.rows[insp.selected].setAttribute('aria-selected', 'false');
  insp.selected = id;
  if (insp.rows[id]) insp.rows[id].setAttribute('aria-selected', 'true');
  var name = insp.name;
  api(inspBase() + '/' + id).then(function(rec){
    if (insp.name === name && insp.selected === id) renderInspDetail(rec);
  }).catch(function(err){ if (err.message !== 'forbidden') toast(err.message, 'error'); });
}

function headerList(h){
  var dl = el('dl', 'hdrs');
  (Array.isArray(h) ? h : []).forEach(function(kv){
    if (!Array.isArray(kv)) return;
    dl.appendChild(el('dt', null, String(kv[0])));
    dl.appendChild(el('dd', null, String(kv[1])));
  });
  if (!dl.firstChild) dl.appendChild(el('dd', null, '(none)'));
  return dl;
}

function bodyBlock(b){
  var wrap = el('div');
  b = b || {};
  if (!b.kind || b.kind === 'none') {
    wrap.appendChild(el('div', 'note', b.websocket ? 'WebSocket: recorded as metadata only.' : '(no body)'));
    return wrap;
  }
  var info = fmtBytes(b.size) + (b.type ? ' · ' + b.type : '');
  if (b.decoded) info += ' · decoded from ' + b.decoded;
  if (b.kind === 'binary') {
    wrap.appendChild(el('div', 'note', info + ' · binary: not stored'));
    wrap.appendChild(el('pre', 'body', 'first bytes: ' + (b.hex || '').replace(/(..)/g, '$1 ').trim()));
    return wrap;
  }
  var text = String(b.data || '');
  if (/json/i.test(b.type || '') && !b.truncated) {
    try { text = JSON.stringify(JSON.parse(text), null, 2); } catch (e) { /* show as is */ }
  }
  wrap.appendChild(el('pre', 'body', text));
  if (b.truncated) wrap.appendChild(el('div', 'note', 'Truncated: only the first 64 KB was kept (' + info + ').'));
  else wrap.appendChild(el('div', 'note', info));
  return wrap;
}

function shq(s){ return "'" + String(s).replace(/'/g, "'\\''") + "'"; }

function curlFor(rec){
  var url = 'https://' + insp.name + HOST_SUFFIX + (rec.target || '/');
  var parts = ['curl'];
  if (rec.method && rec.method !== 'GET') parts.push('-X ' + rec.method);
  parts.push(shq(url));
  (rec.req_headers || []).forEach(function(kv){
    if (Array.isArray(kv) && !CURL_SKIP.test(kv[0])) parts.push('-H ' + shq(kv[0] + ': ' + kv[1]));
  });
  var b = rec.req_body || {};
  if (b.kind === 'text') parts.push('--data-raw ' + shq(b.data || ''));
  return parts.join(' \\\n  ');
}

function replayable(rec){
  if (!insp.door || insp.door.capture) return 'A webhook door has no app to replay to.';
  if (rec.upgraded) return 'WebSocket exchanges cannot be replayed.';
  if (rec.handled_by !== 'upstream' && rec.handled_by !== 'replay') return 'The door answered this itself.';
  var b = rec.req_body || {};
  if (b.truncated) return 'The request body was truncated.';
  if (b.kind === 'binary' || b.decoded) return 'The request body was not stored in full.';
  return '';
}

function renderInspDetail(rec){
  clear(inspDetail);
  inspDetail.appendChild(el('div', 'd-head', (rec.method || '?') + ' ' + (rec.target || '')));
  var sub = (rec.status ? rec.status : 'no answer') + ' · ' +
            (typeof rec.ms === 'number' ? Math.round(rec.ms) + ' ms' : '') + ' · from ' + (rec.client_ip || '?') +
            ' · ' + new Date((rec.ts || 0) * 1000).toLocaleString();
  if (rec.replay_of) sub += ' · replay of #' + rec.replay_of;
  inspDetail.appendChild(el('div', 'd-sub', sub));
  if (rec.error) inspDetail.appendChild(el('div', 'note', 'Error: ' + rec.error));
  if (rec.raw) inspDetail.appendChild(el('div', 'note', 'Raw capture: header values are not masked.'));

  var acts = el('div', 'actions');
  var cp = el('button', 'btn ghost', 'Copy as curl');
  cp.type = 'button';
  var rp = el('button', 'btn', 'Replay');
  rp.type = 'button';
  var why = replayable(rec);
  if (why) { rp.disabled = true; rp.title = why; }
  acts.appendChild(cp); acts.appendChild(rp);
  inspDetail.appendChild(acts);
  if (why) inspDetail.appendChild(el('div', 'note', 'Replay: ' + why));
  cp.addEventListener('click', function(){
    copyText(curlFor(rec), function(){ toast('curl command copied (masked values stay masked)', 'ok'); });
  });
  rp.addEventListener('click', function(){
    busy(rp, true);
    api(inspBase() + '/' + rec.id + '/replay', 'POST').then(function(res){
      if (res && res.record) addInspRow(res.record);
      var msg = 'Replayed as #' + (res && res.id) + ' → ' + ((res && res.http_status) || 'no answer');
      if (res && res.dropped && res.dropped.length) msg += ' (dropped ' + res.dropped.join(', ') + ')';
      toast(msg, 'ok');
    }).catch(function(err){
      if (err.message !== 'forbidden') toast(err.message, 'error');
    }).then(function(){ busy(rp, false); });
  });

  inspDetail.appendChild(el('h3', null, 'Request headers'));
  inspDetail.appendChild(headerList(rec.req_headers));
  inspDetail.appendChild(el('h3', null, 'Request body'));
  inspDetail.appendChild(bodyBlock(rec.req_body));
  inspDetail.appendChild(el('h3', null, 'Response headers'));
  inspDetail.appendChild(headerList(rec.resp_headers));
  inspDetail.appendChild(el('h3', null, 'Response body'));
  inspDetail.appendChild(bodyBlock(rec.resp_body));
}

document.getElementById('inspClose').addEventListener('click', closeInspect);

// ---- timers -------------------------------------------------------------

function startTimers(){
  stopTimers();
  pollTimer = setInterval(function(){ fetchTunnels(); fetchAsks(); }, POLL_MS);
  histTimer = setInterval(fetchHistory, HIST_MS);
  tickTimer = setInterval(tick, 1000);
}

function stopTimers(){
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  if (histTimer) { clearInterval(histTimer); histTimer = null; }
  if (tickTimer) { clearInterval(tickTimer); tickTimer = null; }
}

// Don't poll a backgrounded tab; catch up the moment it comes back.
document.addEventListener('visibilitychange', function(){
  if (document.hidden) {
    stopTimers();
  } else if (wallEl.hidden) {
    fetchTunnels();
    fetchHistory();
    startTimers();
  }
});

fetchTunnels();
fetchHistory();
fetchAsks();
startTimers();

})();
</script>
</body>
</html>"""


# Served (403) to anyone whose cookie doesn't resolve to an owner device. It
# deliberately says nothing about paths, ports, or whether auth is configured.
DENIED_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Not enrolled</title>
__PORCH_CSS__
<style nonce="__NONCE__">
body{display:flex;align-items:center;justify-content:center;padding:24px var(--gutter)}
.box{max-width:420px;width:100%;display:flex;flex-direction:column;align-items:flex-start;gap:14px;padding:32px 24px}
.box p{color:var(--muted);font-size:15px;line-height:1.55}
</style>
</head>
<body>
<main class="p-card box">
  <div class="p-kicker">__MARK__<span>porch</span></div>
  <h1 class="p-title p-title--sm">Not enrolled</h1>
  <p>This browser isn&rsquo;t on the allow-list, so there&rsquo;s nothing to show here.</p>
  <p><a href="https://__PORCH_AUTH_HOST__/auth/">Enrol this browser</a></p>
  __SIGNIN__
</main>
</body>
</html>"""


class StatusHandler(BaseHTTPRequestHandler):

    state_dir = Path('.')
    devices_path = None
    history_path = None
    inspect_base = None          # None = lib/rundir.py's <run dir>/inspect (tests override)
    sse_max_seconds = SSE_MAX_SECONDS
    sse_heartbeat = SSE_HEARTBEAT
    reopen_store = None          # reopen_requests.Store; None = the run dir's (tests override)
    reopen_limit = reopen_requests.RateLimit(*reopen_requests.PER_IP)
    doors_dir = None             # launch recipes; None = door_recipe's data/doors
    pocket_root = None           # where Pocket keeps push subscriptions; None = ~/pocket
    notifier = staticmethod(push_reopen)
    reopener = None              # (name, expires) -> state; None = door_recipe.reopen

    # Don't advertise the Python version to unauthenticated callers.
    server_version = 'porch'
    sys_version = ''
    # A client that stops sending or reading frees its thread.
    timeout = REQUEST_TIMEOUT

    def log_message(self, format, *args):
        method = args[0] if args else ''
        if isinstance(method, str) and method.startswith('GET'):
            return
        sys.stderr.write(f"[status-api] {self.address_string()} - {format % args}\n")

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'same-origin')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html, status=200):
        """Serve one of the inline pages with a lockdown header set.

        The pages load nothing from anywhere, so the CSP can be
        `default-src 'none'` with a nonce for the single inline <style> and
        <script>; that also blocks inline event handlers outright.
        """
        nonce = secrets.token_hex(16)
        # Relative link: the console also works below a path prefix.
        css_tag = porch_css_tag().replace('href="/', 'href="', 1)
        body = (html.replace('__PORCH_CSS__', css_tag).replace('__MARK__', porch_mark(22))
                .replace('__NONCE__', nonce).encode('utf-8'))
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Content-Security-Policy', (
            "default-src 'none'; "
            f"{porch_style_src(nonce)}; "
            f"script-src 'nonce-{nonce}'; "
            "connect-src 'self'; "
            "img-src data:; "
            "base-uri 'none'; "
            "form-action 'none'; "
            "frame-ancestors 'none'"
        ))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'same-origin')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def send_cors_headers(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_OPTIONS(self):
        if urllib.parse.urlsplit(self.path).path.startswith('/api/reopen-requests'):
            self._reopen_json({}, 204)
            return
        self.send_cors_headers()

    # ---- auth helpers -------------------------------------------------------

    def _owner_cookie(self):
        """The cookie value that makes this request an owner's, or ''
        (porch_auth.owner_cookie: porch_host for this host, else the legacy
        cush_auth while that is still accepted)."""
        return porch_auth.owner_cookie(self, self.devices_path)

    def _is_owner(self):
        """True iff the request carries a live owner cookie."""
        return bool(self._owner_cookie())

    def _csrf_ok(self):
        """Guard the mutating routes against cross-site requests.

        Two independent ways to pass, either is sufficient:
          1. X-CSRF-Token matching the HMAC of this request's own gate cookie
             (what the console page sends), or
          2. an Origin/Referer whose host matches the Host this request came in
             on (what the landing-page panel at tunnel.cush.rocks sends — nginx
             forwards `Host $host`, so the two line up).
        A request with neither is rejected: browsers always send Origin on a
        cross-origin POST, so the only callers this turns away are hand-rolled
        ones, which can set either header.
        """
        token = self.headers.get('X-CSRF-Token', '')
        if token:
            cookies = parse_cookies(self.headers.get('Cookie', ''))
            for name in (GATE_COOKIE, HOST_COOKIE):
                cookie = cookies.get(name, '')
                if cookie and hmac.compare_digest(token, csrf_token_for(cookie)):
                    return True

        hosts = set()
        for hdr in ('Host', 'X-Forwarded-Host'):
            val = (self.headers.get(hdr) or '').split(',')[0].strip()
            if val:
                hosts.add(val.lower())
                hosts.add(val.split(':')[0].lower())
        if not hosts:
            return False

        for hdr in ('Origin', 'Referer'):
            val = self.headers.get(hdr)
            if not val:
                continue
            # 'null' (sandboxed/opaque origin) has no netloc and must not pass.
            try:
                parsed = urllib.parse.urlsplit(val)
            except ValueError:
                return False
            if not parsed.netloc:
                return False
            return parsed.netloc.lower() in hosts or (parsed.hostname or '').lower() in hosts

        return False

    def _forbid(self):
        self.send_json({
            'status': 'error',
            'message': f'Forbidden — enroll this browser at https://{DOMAIN.auth_host}/auth/',
        }, 403)

    def _read_body(self):
        """Read the request body, bounded.

        Every caller here posts a small JSON object. Reading an unbounded
        Content-Length would turn one POST into an allocation of that size —
        owner-gated, but there is no reason to leave it unbounded.
        """
        length = content_length(self)
        if length <= 0:
            return b''
        if length > MAX_BODY:
            self.close_connection = True
            raise BodyTooLarge()
        return self.rfile.read(length)

    def _read_json_body(self):
        try:
            raw = self._read_body()
        except BodyTooLarge:
            return None
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        if not isinstance(data, dict):
            return None
        return data

    # ---- routing ------------------------------------------------------------

    def do_GET(self):
        # porch.css + fonts: public, static, needed by the refusal page too.
        if serve_asset(self, head=self.command == 'HEAD'):
            return
        path = urllib.parse.urlsplit(self.path).path.rstrip('/')

        # The management console. Owner-gated exactly like the API routes: a
        # non-owner gets the standalone refusal page and nothing else.
        if path == '':
            cookie = self._owner_cookie()
            if not cookie:
                url = porch_auth.signin_url(self, self.devices_path)
                link = (f'<p><a href="{html_escape(url, quote=True)}" rel="nofollow">'
                        'Owner? Sign in on this host</a></p>') if url else ''
                self.send_html(domain_html(DENIED_HTML).replace('__SIGNIN__', link), 403)
                return
            self.send_html(domain_html(CONSOLE_HTML).replace('__CSRF_TOKEN__', csrf_token_for(cookie)))
            return

        if path == '/api/me':
            self._me()
            return

        # The visitor's poll: public, the token is the only key.
        if path.startswith('/api/reopen-requests/'):
            self._reopen_poll(path[len('/api/reopen-requests/'):])
            return
        if path == '/api/reopen-requests':
            if not self._is_owner():
                self._forbid()
                return
            self.send_json(self._reopen_store().recent())
            return

        if path == '/api/tunnels':
            if not self._is_owner():
                self._forbid()
                return
            self._list_tunnels()
            return

        if path == '/api/history':
            if not self._is_owner():
                self._forbid()
                return
            self._history()
            return

        # GET /api/tunnels/<name>/requests[/events|/<id>]
        parts = path.split('/')
        if len(parts) in (5, 6) and parts[1] == 'api' and parts[2] == 'tunnels' \
                and parts[4] == 'requests':
            if not self._is_owner():
                self._forbid()
                return
            store = self._inspect_store(parts[3])
            if store is None:
                return
            if len(parts) == 5:
                self._requests_list(store)
            elif parts[5] == 'events':
                self._requests_events(parts[3], store)
            elif parts[5].isdigit() and len(parts[5]) <= 12:
                self._request_detail(store, int(parts[5]))
            else:
                self.send_json({'status': 'error', 'message': 'Not found'}, 404)
            return

        self.send_json({'status': 'error', 'message': 'Not found'}, 404)

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path.rstrip('/')
        parts = path.split('/')

        # The closed-door page's ask: public and cross-origin by design (it is
        # served on the dead tunnel host), so it has its own origin rule and
        # limits instead of the owner gate. It reads no cookies.
        if path == '/api/reopen-requests':
            self._reopen_ask()
            return

        # Every route below mutates something, so the CSRF gate goes first —
        # ahead of even the owner check, so a cross-site probe learns nothing.
        if not self._csrf_ok():
            self.send_json({'status': 'error', 'message': 'Forbidden'}, 403)
            return

        # POST /api/launch
        if path == '/api/launch':
            if not self._is_owner():
                self._forbid()
                return
            self._launch()
            return

        # POST /api/tunnels/<name>/extend|expire|keep-alive|stop
        if len(parts) == 5 and parts[1] == 'api' and parts[2] == 'tunnels':
            if not self._is_owner():
                self._forbid()
                return
            name = parts[3]
            action = parts[4]
            # `name` is about to name a state file and an frpc config path
            # (/tmp/frpc-<name>-XXXXX.toml), so require the /api/launch shape.
            if not NAME_RE.match(name):
                self.send_json({'status': 'error', 'message': 'Invalid name'}, 400)
                return
            state_file = self.state_dir / f"{name}.json"

            if not state_file.is_file():
                if action == 'stop':
                    self._stop_unmanaged(name)
                else:
                    self.send_json({'status': 'error', 'message': 'Tunnel not found'}, 404)
                return

            if action == 'extend':
                self._extend(name, state_file)
            elif action == 'expire':
                self._expire(name, state_file)
            elif action == 'keep-alive':
                self._keep_alive(name, state_file)
            elif action == 'stop':
                self._stop(name, state_file)
            else:
                self.send_json({'status': 'error', 'message': 'Unknown action'}, 400)
            return

        # POST /api/tunnels/<name>/requests/<id>/replay
        if len(parts) == 7 and parts[1] == 'api' and parts[2] == 'tunnels' \
                and parts[4] == 'requests' and parts[6] == 'replay':
            if not self._is_owner():
                self._forbid()
                return
            if not (parts[5].isdigit() and len(parts[5]) <= 12):
                self.send_json({'status': 'error', 'message': 'Invalid request id'}, 400)
                return
            store = self._inspect_store(parts[3])
            if store is None:
                return
            self._replay(parts[3], store, int(parts[5]))
            return

        # POST /api/reopen-requests/<id>/decide {decision, expires}
        if len(parts) == 5 and parts[1] == 'api' and parts[2] == 'reopen-requests' \
                and parts[4] == 'decide':
            if not self._is_owner():
                self._forbid()
                return
            self._reopen_decide(parts[3])
            return

        # POST /api/history/<name>/revive|reopen|forget
        if len(parts) == 5 and parts[1] == 'api' and parts[2] == 'history':
            if not self._is_owner():
                self._forbid()
                return
            name = parts[3]
            action = parts[4]
            if not NAME_RE.match(name):
                self.send_json({'status': 'error', 'message': 'Invalid name'}, 400)
                return
            if action == 'revive':
                self._revive(name)
            elif action == 'reopen':
                self._reopen_door(name)
            elif action == 'forget':
                self._forget(name)
            else:
                self.send_json({'status': 'error', 'message': 'Unknown action'}, 400)
            return

        self.send_json({'status': 'error', 'message': 'Not found'}, 404)

    # ---- /api/me ------------------------------------------------------------

    def _me(self):
        self.send_json({
            'owner': self._is_owner(),
            'auth_configured': porch_auth.auth_configured(self.devices_path),
        })

    # ---- /api/tunnels -------------------------------------------------------

    def _list_tunnels(self):
        self.send_json(door_ops.list_doors(self.state_dir, domain=DOMAIN, log=log))

    def _door_op(self, fn, *args, **kw):
        """Run a door_ops call; its refusal becomes the JSON error reply.
        Returns the result, or None once an error has been answered."""
        try:
            return fn(*args, **kw)
        except door_ops.DoorOpError as e:
            self.send_json({'status': 'error', 'message': e.message}, e.status)
            return None

    def _extend(self, name, state_file):
        reply = self._door_op(door_ops.extend, self.state_dir, name, log=log)
        if reply is None:
            return
        self.send_json(reply)
        log(f"Extended tunnel '{name}' by 1 hour")

    def _expire(self, name, state_file):
        """POST {"at": epoch | "never" | "+2h" | "30m" | ISO-8601}."""
        data = self._read_json_body()
        if data is None or 'at' not in data:
            self.send_json({'status': 'error', 'message': 'Body must be {"at": ...}'}, 400)
            return
        reply = self._door_op(door_ops.set_expires, self.state_dir, name, data['at'], log=log)
        if reply is None:
            return
        self.send_json(reply)
        log(f"Set expiry of '{name}' to {'never' if reply['never'] else reply['expires']}")

    def _keep_alive(self, name, state_file):
        reply = self._door_op(door_ops.toggle_keep, self.state_dir, name, log=log)
        if reply is None:
            return
        self.send_json(reply)
        log(f"Toggled keep_alive for '{name}' to {reply['keep_alive']}")

    def _stop(self, name, state_file):
        reply = self._door_op(door_ops.stop, self.state_dir, name, log=log)
        if reply is not None:
            self.send_json(reply)

    def _stop_unmanaged(self, name):
        self._stop(name, None)

    # ---- /api/tunnels/<name>/requests (request inspector) -------------------

    def _inspect_store(self, name):
        """The store path of an open, inspected door, or None (reply sent)."""
        return self._door_op(door_ops.inspect_store_for, self.state_dir, name, self.inspect_base)

    def _query(self):
        return urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)

    def _int_param(self, q, key, default=0):
        v = (q.get(key) or [''])[0]
        return int(v) if v.isdigit() and len(v) <= 12 else default

    def _requests_list(self, store):
        q = self._query()
        self.send_json(door_ops.requests_page(store, self._int_param(q, 'since'),
                                              self._int_param(q, 'limit', REQUESTS_PAGE)))

    def _request_detail(self, store, rid):
        rec = self._door_op(door_ops.request_detail, store, rid)
        if rec is not None:
            self.send_json(rec)

    def _replay(self, name, store, rid):
        reply = self._door_op(door_ops.replay, name, store, rid, self.inspect_base)
        if reply is not None:
            self.send_json(reply)

    def _requests_events(self, name, store):
        """Server-sent events: one `request` event (a summary) per new record,
        a `: ping` comment every sse_heartbeat seconds, `closed` when the door
        goes away. Resumes from Last-Event-ID (EventSource sends it on reconnect)
        or ?since=."""
        if not _sse_slots.acquire(blocking=False):
            self.send_json({'status': 'error', 'message': 'Too many live streams'}, 429)
            return
        try:
            q = self._query()
            last = (self.headers.get('Last-Event-ID') or '').strip()
            since = int(last) if last.isdigit() and len(last) <= 12 else self._int_param(q, 'since')
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Accel-Buffering', 'no')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.close_connection = True
            w = self.wfile
            w.write(b'retry: 3000\n\n')
            w.flush()
            tail = inspect_store.Tail(store, since)
            state_file = self.state_dir / f'{name}.json'
            start = beat = time.monotonic()
            while time.monotonic() - start < self.sse_max_seconds:
                recs = tail.poll()
                for r in recs:
                    data = json.dumps(inspect_store.summary(r))
                    w.write(f'id: {r["id"]}\nevent: request\ndata: {data}\n\n'.encode('utf-8'))
                if recs:
                    w.flush()
                    beat = time.monotonic()
                elif time.monotonic() - beat >= self.sse_heartbeat:
                    w.write(b': ping\n\n')
                    w.flush()
                    beat = time.monotonic()
                if not state_file.exists():
                    w.write(b'event: closed\ndata: {}\n\n')
                    w.flush()
                    break
                time.sleep(SSE_POLL)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            _sse_slots.release()

    # ---- /api/history -------------------------------------------------------

    def _history(self):
        self.send_json(door_ops.history(self.history_path, self.state_dir, self.doors_dir,
                                        repo_root=REPO_ROOT, domain=DOMAIN, log=log))

    def _forget(self, name):
        reply = self._door_op(door_ops.forget, self.history_path, name, log=log)
        if reply is not None:
            self.send_json(reply)

    def _revive(self, name):
        plan = self._door_op(door_ops.revive_plan, self.history_path, self.state_dir, name,
                             repo_root=REPO_ROOT, log=log)
        if plan is None:
            return
        self._run_launch(plan.argv, plan.cwd, plan.name, plan.rtype,
                         log_path=plan.log_path, timeout=plan.timeout)

    # ---- ask to reopen -------------------------------------------------------

    def _reopen_store(self):
        if self.reopen_store is None:
            type(self).reopen_store = reopen_requests.Store()
        return self.reopen_store

    def _reopen_json(self, data, status=200):
        """A public reopen answer: CORS for the asking door's own origin only
        (https://<label>.<tunnel base>), never credentials."""
        body = b'' if status == 204 else json.dumps(data).encode()
        self.send_response(status)
        origin = reopen_origin(self.headers.get('Origin'))
        if origin:
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Access-Control-Allow-Methods', 'GET, POST')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type')
            self.send_header('Access-Control-Max-Age', '600')
        self.send_header('Vary', 'Origin')
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _reopen_ask(self):
        """POST {host, note} (text/plain JSON: no preflight). The answer,
        {id, token}, is the same for every valid door name, reopenable or
        not; only the owner ever learns which."""
        n = content_length(self)
        if n > reopen_requests.BODY_MAX:
            self.close_connection = True
            self._reopen_json({'error': 'too large'}, 413)
            return
        raw = self.rfile.read(n) if n > 0 else b''
        try:
            data = json.loads(raw.decode('utf-8')) if raw else None
        except (ValueError, UnicodeDecodeError):
            data = None
        if not isinstance(data, dict):
            self._reopen_json({'error': 'bad request'}, 400)
            return
        host = data.get('host')
        name = reopen_requests.door_for_host(host, DOMAIN.tunnel_base) \
            if isinstance(host, str) else None
        if name is None:
            self._reopen_json({'error': 'bad request'}, 400)
            return
        # Only the dead door's own page may ask for it (browsers always send
        # Origin on a cross-origin POST; another site can't forge it).
        if self.headers.get('Origin') != f'https://{host.strip().lower()}':
            self._reopen_json({'error': 'forbidden'}, 403)
            return
        ip = client_ip(self)
        if not self.reopen_limit.hit(ip):
            self._reopen_json({'error': 'Too many asks from here. Try again later.'}, 429)
            return
        try:
            r = door_recipe.check(name, self.doors_dir, str(self.state_dir))
            info = {'type': r.get('type'), 'closed': r.get('closed'), 'reason': r.get('reason')}
        except (door_recipe.RecipeError, OSError):
            r, info = None, None
        try:
            rid, token, rec, joined = self._reopen_store().ask(
                name, data.get('note'), ip, r is not None, info)
        except reopen_requests.Refused as e:
            self._reopen_json({'error': e.message}, e.status)
            return
        except OSError as e:
            log(f"Reopen store unavailable: {e}")
            self._reopen_json({'error': 'unavailable'}, 503)
            return
        if r is not None and not joined:
            threading.Thread(target=self.notifier, args=(rec, self.pocket_root),
                             daemon=True).start()
            log(f"Reopen requested for '{name}' from {ip}")
        self._reopen_json({'id': rid, 'token': token, 'poll': REOPEN_POLL}, 201)

    def _reopen_poll(self, rid):
        q = self._query()
        token = (q.get('t') or [''])[0]
        try:
            state = self._reopen_store().status(rid, token)
        except OSError:
            state = None
        if state is None:
            self._reopen_json({'state': 'unknown'}, 404)
            return
        self._reopen_json({'state': state, 'poll': REOPEN_POLL})

    def _reopen_fn(self):
        if self.reopener is not None:
            return self.reopener
        return lambda name, expires: door_recipe.reopen(name, expires, self.doors_dir,
                                                        str(self.state_dir), ok_if_open=True)

    def _reopen_decide(self, rid):
        data = self._read_json_body()
        if data is None or not reopen_requests.valid_id(rid):
            self.send_json({'status': 'error', 'message': 'Invalid request'}, 400)
            return
        try:
            rec = self._reopen_store().decide(rid, data.get('decision'), data.get('expires'),
                                              self._reopen_fn())
        except ValueError as e:
            self.send_json({'status': 'error', 'message': str(e)}, 400)
            return
        except LookupError as e:
            self.send_json({'status': 'error', 'message': str(e)}, 409)
            return
        except RuntimeError as e:
            self.send_json({'status': 'error', 'message': str(e)}, 502)
            return
        log(f"Reopen request for '{rec.get('name')}': {rec.get('state')}")
        self.send_json({'status': 'ok', 'request': rec})

    def _reopen_door(self, name):
        data = self._read_json_body()
        expires = (data or {}).get('expires', '1h')
        reply = self._door_op(door_ops.reopen, name, expires, reopener=self._reopen_fn(),
                              domain=DOMAIN, log=log)
        if reply is not None:
            self.send_json(reply)

    # ---- /api/launch --------------------------------------------------------

    def _launch(self):
        data = self._read_json_body()
        if data is None:
            self.send_json({'status': 'error', 'message': 'Invalid JSON body'}, 400)
            return
        plan = self._door_op(door_ops.launch_plan, self.state_dir, data.get('type', ''),
                             data.get('name', ''), data.get('content', ''),
                             data.get('view_only', False), repo_root=REPO_ROOT)
        if plan is None:
            return
        self._run_launch(plan.argv, plan.cwd, plan.name, plan.rtype, stdin=plan.stdin,
                         log_path=plan.log_path, timeout=plan.timeout)

    # ---- shared launch runner ----------------------------------------------

    def _run_launch(self, argv, cwd, name, rtype, stdin=None, log_path=None, timeout=20):
        plan = door_ops.LaunchPlan(argv, cwd, name, rtype, stdin, None, log_path, timeout)
        reply = self._door_op(door_ops.run_launch, plan, domain=DOMAIN, log=log)
        if reply is not None:
            self.send_json(reply)


class StatusServer(BoundedThreadingHTTPServer):
    """porch_http's bounded server (connection cap, daemon threads)."""
    allow_reuse_address = True


def main():
    parser = argparse.ArgumentParser(description='Tunnel status API server')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--state-dir', type=str, required=True)
    parser.add_argument('--devices', type=str, default=str(REPO_ROOT / 'data' / 'devices.json'))
    parser.add_argument('--history', type=str, default=str(REPO_ROOT / 'data' / 'history.jsonl'))
    parser.add_argument('--bind', type=str, default='127.0.0.1',
                        help='Listen address (default 127.0.0.1; keep it loopback)')
    args = parser.parse_args()

    state_dir = Path(args.state_dir).resolve()
    state_dir.mkdir(parents=True, exist_ok=True)
    StatusHandler.state_dir = state_dir
    StatusHandler.devices_path = str(Path(args.devices).resolve())
    StatusHandler.history_path = str(Path(args.history).resolve())
    # The history holds argv and cwd of every launch: owner-only.
    ensure_private_file(StatusHandler.history_path)

    # make_server warns on a non-loopback bind: this API trusts loopback-only exposure.
    server = make_server(StatusHandler, args.port, args.bind, tag='statusserver',
                         server_class=StatusServer)
    log(f"Listening on {args.bind}:{args.port}, state dir: {state_dir}, "
        f"devices: {StatusHandler.devices_path}, history: {StatusHandler.history_path}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("Shutting down.")
        server.shutdown()


if __name__ == '__main__':
    main()

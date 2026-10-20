#!/usr/bin/env python3

import argparse
import base64
import cgi
import hmac
import html
import io
import json
import os
import re
import secrets
import shutil
import socket
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler
from pathlib import Path

# `lib/` is not a package — make sibling modules importable.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import rundir  # noqa: E402  (per-user private dirs + atomic 0600 writes)
from porch_http import (  # noqa: E402  (shared HTTP core)
    content_length, make_server, porch_css_tag, porch_style_src, same_origin, serve_asset,
)

# Secrets-backend imports are deferred to _persist() so disk-only mode never
# touches the 1Password / Infisical layers. This keeps the existing
# /tmp/secure-entry/<label> flow byte-identical when --save-to-secrets
# (a.k.a. legacy --save-to-op) isn't used.

# ── HTML templates ─────────────────────────────────────────────────────────
#
# Two templates are used:
#   - ENTRY_HTML: the single-field string form.
#   - MULTI_HTML: the new multi-field form. Renders a vertical stack of inputs
#     (one per --field), each typed string|file|ssh.
#
# Both templates are vanilla HTML/CSS styled by porch.css (secret accent),
# which is served below /<token>/__porch-assets/ like the page itself.
# They are served under a nonce-only CSP: every <style>/<script> carries
# nonce="CSP_NONCE" (substituted per response), and there are no inline event
# handlers or style="" attributes, which that CSP would block.

SE_HEAD = r"""<!DOCTYPE html>
<html lang="en" data-app="secret">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>A secret, please</title>
__PORCH_CSS__
<style nonce="CSP_NONCE">
.se-icon{width:56px;height:56px;border-radius:var(--r-xl);background:var(--accent-soft);color:var(--accent-ink);
  display:flex;align-items:center;justify-content:center}
.se-form{display:flex;flex-direction:column;gap:18px}
.se-form[hidden]{display:none}
.field-type{font:400 12px var(--font-ui);color:var(--muted);margin-left:8px}
.p-textarea.string{font-family:var(--font-mono)}
.p-textarea{min-height:96px}
#content{min-height:140px}
input[type=file].p-input{padding:10px 14px;height:auto}
.field.saved .p-textarea,.field.saved input[type=file]{opacity:.45}
.field.saved .field-type{color:var(--ok)}
.field.invalid .p-textarea,.field.invalid input[type=file]{border-color:var(--danger);box-shadow:0 0 0 3px var(--danger-soft)}
.confirmation ul{list-style:none;margin:8px 0 0;padding:0;font:13px/1.7 var(--font-mono)}
.p-notice b{display:block}
.p-notice .sub{color:var(--muted);font-size:14px}
</style>
</head>
<body>
<main class="p-shell p-shell--narrow">
  <div class="se-icon" aria-hidden="true"><svg width="26" height="26" viewBox="0 0 26 26" fill="none"><rect x="5" y="11" width="16" height="11" rx="3" stroke="currentColor" stroke-width="2"/><path d="M8.5 11 V8 a4.5 4.5 0 0 1 9 0 V11" stroke="currentColor" stroke-width="2"/><circle cx="13" cy="16.5" r="1.6" fill="currentColor"/></svg></div>
  <header class="p-head">
    <h1 class="p-title">You've been asked for a secret</h1>
    <p class="p-lede">It goes straight to whoever sent you this link. This page keeps no copy, and it works only once.</p>
  </header>
"""

SE_SEND_BTN = ('<button class="p-btn p-btn--lg p-btn--block btn" id="submitBtn" type="button">'
               '<svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden="true">'
               '<rect x="3.5" y="8" width="11" height="7.5" rx="2" stroke="currentColor" stroke-width="1.7"/>'
               '<path d="M6 8 V6 a3 3 0 0 1 6 0 V8" stroke="currentColor" stroke-width="1.7"/></svg>'
               '<span id="submitText">Send securely</span></button>')

SE_FOOT = r"""  <div class="p-notice" role="note">
    <svg class="p-notice-icon" width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden="true"><circle cx="9" cy="9" r="7" stroke="currentColor" stroke-width="1.6"/><path d="M9 8 V12.5 M9 5.6 V5.8" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>
    <div class="p-muted">Spellcheck and autocomplete are off on these fields, so your browser won't send them anywhere either.</div>
  </div>
  <footer class="p-foot">sealed by porch</footer>
</main>
"""

# Shared by both forms: a status banner instead of alert(), and the submit
# button's busy/idle text.
SE_COMMON_JS = r"""function showStatus(msg){
  const st = document.getElementById('status');
  st.textContent = msg;
  st.hidden = !msg;
}
function setBusy(busy, label){
  const btn = document.getElementById('submitBtn');
  btn.disabled = busy;
  document.getElementById('submitText').textContent = label;
}
"""

ENTRY_HTML = SE_HEAD + r"""  <div id="status" class="p-notice p-notice--error banner error" role="alert" hidden></div>
  <div id="form" class="se-form">
    <div class="p-field">
      <label class="p-label p-label--mono" for="content">ENTRY_LABEL</label>
      <textarea id="content" class="p-textarea p-textarea--mono" placeholder="Paste it here" spellcheck="false" autocomplete="off" autocorrect="off" autocapitalize="off"></textarea>
    </div>
    """ + SE_SEND_BTN + r"""
  </div>
  <div id="done" class="p-notice p-notice--ok confirmation" role="status" hidden><div><b>Sent. It's been delivered.</b><span class="sub">You can close this tab.</span></div></div>
  <div id="already" class="p-notice already" role="status" hidden><div><b>Already received</b><span class="sub">This link has been used. Nothing more is needed.</span></div></div>
""" + SE_FOOT + r"""<script nonce="CSP_NONCE">
""" + SE_COMMON_JS + r"""async function submit(){
  const content = document.getElementById('content').value;
  if(!content.trim()){ showStatus('Paste the secret first.'); return; }
  showStatus('');
  setBusy(true, 'Sending…');
  try{
    // Relative on purpose: the page lives at /<token>/, so this resolves to
    // /<token>/submit. An absolute '/submit' would 404.
    const resp = await fetch('submit',{
      method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:'content='+encodeURIComponent(content)
    });
    let data = null;
    let rawText = '';
    try{ data = await resp.clone().json(); }catch(_){ rawText = await resp.text(); }
    if(data && data.status==='already_received'){
      document.getElementById('form').hidden=true;
      document.getElementById('already').hidden=false;
      return;
    }
    if(!resp.ok){
      const msg = (data && (data.error || data.message)) || rawText || ('HTTP '+resp.status);
      setBusy(false, 'Try again');
      showStatus("Couldn't send: "+msg);
      return;
    }
    if(data && data.status==='ok'){
      document.getElementById('form').hidden=true;
      document.getElementById('done').hidden=false;
    }else{
      setBusy(false, 'Try again');
      showStatus("Couldn't send: "+((data && (data.error||data.message)) || rawText || 'unknown error'));
    }
  }catch(e){
    setBusy(false, 'Try again');
    showStatus("Couldn't send: "+(e && e.message ? e.message : e));
  }
}
document.getElementById('submitBtn').addEventListener('click', submit);
</script>
</body>
</html>"""


# Multi-field form. Renders a stacked sequence of labeled inputs, then a
# single Submit button. JS uses FormData + fetch so we can mix file uploads
# with text fields without a page reload.
MULTI_HTML_HEAD = SE_HEAD


def _render_multi_html(label, field_specs, *, banner=None):
    """Render the multi-field form with the given fields.

    field_specs: list of (name, type) tuples — type ∈ {string, file, ssh}.
    banner: optional dict with {'kind': 'warn'|'error', 'message': str}.

    No inline event handlers and no style="" attributes: the page is served
    under a nonce-only CSP, which blocks both.
    """
    parts = [MULTI_HTML_HEAD]

    # Persistent banner: ssh-typed inputs get a warning, error states get
    # rendered inline. Server-side validation errors prepend an .error banner.
    has_ssh = any(t == 'ssh' for _, t in field_specs)
    if has_ssh:
        parts.append(
            '  <div class="p-notice p-notice--warn banner warn" role="note">'
            'SSH private key — do not paste a public key here.</div>\n'
        )

    if banner:
        kind = 'error' if banner.get('kind', 'error') == 'error' else 'warn'
        msg = html.escape(banner.get('message', ''))
        notice = 'p-notice--error' if kind == 'error' else 'p-notice--warn'
        parts.append(f'  <div class="p-notice {notice} banner {kind}">{msg}</div>\n')
    # Live status line for partial-save results (filled via textContent).
    parts.append('  <div id="status" class="p-notice p-notice--error banner error" role="alert" hidden></div>\n')

    parts.append('  <div id="form" class="se-form">\n')
    for name, ftype in field_specs:
        type_hint = {'string': 'text', 'file': 'file upload', 'ssh': 'ssh private key'}[ftype]
        parts.append(f'    <div class="p-field field" data-field="{html.escape(name)}" data-type="{ftype}">\n')
        parts.append(
            f'      <label class="p-label p-label--mono field-label" for="f-{html.escape(name)}">'
            f'{html.escape(name)}'
            f'<span class="field-type">[{ftype}]</span></label>\n'
        )
        if ftype == 'file':
            parts.append(
                f'      <input type="file" class="p-input" id="f-{html.escape(name)}" '
                f'name="{html.escape(name)}" title="{type_hint}">\n'
            )
        else:
            css_class = 'p-textarea p-textarea--mono ' + ('string' if ftype == 'string' else 'mono')
            placeholder = (
                'Paste it here' if ftype == 'string'
                else '-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----'
            )
            parts.append(
                f'      <textarea id="f-{html.escape(name)}" '
                f'name="{html.escape(name)}" class="{css_class}" '
                f'placeholder="{html.escape(placeholder)}" '
                f'spellcheck="false" autocomplete="off" autocorrect="off" '
                f'autocapitalize="off" '
                f'title="{type_hint}"></textarea>\n'
            )
        parts.append('    </div>\n')
    parts.append('    ' + SE_SEND_BTN + '\n')
    parts.append('  </div>\n')
    parts.append('  <div id="done" class="p-notice p-notice--ok confirmation" role="status" hidden></div>\n')
    parts.append('  <div id="already" class="p-notice already" role="status" hidden><div><b>Already received</b>'
                 '<span class="sub">This link has been used. Nothing more is needed.</span></div></div>\n')
    parts.append(SE_FOOT)

    # JS submission logic.
    parts.append('<script nonce="CSP_NONCE">\n' + SE_COMMON_JS)
    parts.append("""function fieldsList(){
  return Array.from(document.querySelectorAll('.field'));
}
function pendingFields(){
  return fieldsList().filter(el => !el.classList.contains('saved'));
}
function clearInvalid(){
  fieldsList().forEach(el => el.classList.remove('invalid'));
}
function markInvalid(names){
  const set = new Set(names);
  fieldsList().forEach(el => {
    if(set.has(el.dataset.field)) el.classList.add('invalid');
  });
}
function markSaved(names){
  const set = new Set(names || []);
  fieldsList().forEach(el => {
    if(!set.has(el.dataset.field)) return;
    el.classList.add('saved');
    const inp = el.querySelector('textarea, input');
    if(inp){ inp.disabled = true; if(inp.tagName === 'TEXTAREA') inp.value = ''; }
    const lbl = el.querySelector('.field-type');
    if(lbl) lbl.textContent = 'saved';
  });
}
async function submitAll(){
  clearInvalid();
  // Client-side: ensure every not-yet-saved field has a value (UX guard;
  // the server re-validates). Fields already saved on an earlier, partially
  // failed attempt are not sent again.
  const fd = new FormData();
  const empty = [];
  for(const el of pendingFields()){
    const name = el.dataset.field;
    const type = el.dataset.type;
    if(type === 'file'){
      const inp = el.querySelector('input[type=file]');
      if(!inp.files || inp.files.length === 0){ empty.push(name); continue; }
      fd.append(name, inp.files[0]);
    }else{
      const ta = el.querySelector('textarea');
      const v = ta.value || '';
      if(!v.trim()){ empty.push(name); continue; }
      fd.append(name, v);
    }
  }
  if(empty.length){
    markInvalid(empty);
    showStatus('Missing field' + (empty.length>1?'s':'') + ': ' + empty.join(', '));
    return;
  }
  showStatus('');
  setBusy(true, 'Sending…');
  try{
    const resp = await fetch('submit', { method:'POST', body: fd });
    let data = null;
    let rawText = '';
    try{ data = await resp.clone().json(); }catch(_){ rawText = await resp.text(); }
    if(data && data.status==='already_received'){
      document.getElementById('form').hidden = true;
      document.getElementById('already').hidden = false;
      return;
    }
    if(!resp.ok){
      setBusy(false, 'Try again');
      if(data && data.saved){ markSaved(data.saved); }
      if(data && data.invalid_fields){ markInvalid(data.invalid_fields); }
      if(data && data.failed){ markInvalid(data.failed); }
      const msg = (data && (data.error || data.message)) || rawText || ('HTTP '+resp.status);
      showStatus((data && data.saved && data.saved.length) ? msg : "Couldn't send: "+msg);
      return;
    }
    if(data && data.status==='ok'){
      const done = document.getElementById('done');
      const box = document.createElement('div');
      const head = document.createElement('b'); head.textContent = "Sent. It's been delivered.";
      const sub = document.createElement('span'); sub.className = 'sub'; sub.textContent = 'You can close this tab.';
      box.appendChild(head); box.appendChild(sub);
      const names = data.received || [];
      if(names.length){
        const ul = document.createElement('ul');
        for(const n of names){ const li = document.createElement('li'); li.textContent = n; ul.appendChild(li); }
        box.appendChild(ul);
      }
      done.replaceChildren(box);
      showStatus('');
      document.getElementById('form').hidden = true;
      done.hidden = false;
    }else if(data && data.status==='already_received'){
      document.getElementById('form').hidden = true;
      document.getElementById('already').hidden = false;
    }else{
      setBusy(false, 'Try again');
      showStatus("Couldn't send: "+((data && (data.error||data.message)) || rawText || 'unknown error'));
    }
  }catch(e){
    setBusy(false, 'Try again');
    showStatus("Couldn't send: "+(e && e.message ? e.message : e));
  }
}
document.getElementById('submitBtn').addEventListener('click', submitAll);
</script>
</body>
</html>""")
    return ''.join(parts)


def _render_single_form(label, *, field_type='string'):
    """Render the single-field form.

    For type='string' (and the default no-field-flag path), this returns the
    ENTRY_HTML form.

    For type='file' or type='ssh', a similarly-styled but type-aware form is
    used (built off the multi-field renderer with a single field).
    """
    if field_type == 'string':
        # Escape the label: it reaches this template from --label, which
        # callers (bin/inject) build from a secret ref, and it is interpolated
        # straight into the page. The multi-field renderer already escapes.
        return ENTRY_HTML.replace('ENTRY_LABEL', html.escape(label))
    # file / ssh — use the multi-field renderer with a synthetic single field
    # named `content` so the POST handler keeps its legacy `content` name.
    return _render_multi_html(label, [('content', field_type)])


# ── Server handler ─────────────────────────────────────────────────────────

# Request-body ceilings, checked against Content-Length before anything is
# read. A secret is a few KB; a file-typed field may be a cert bundle or key
# file. Nothing legitimate comes near these.
MAX_TEXT_BODY = 1024 * 1024            # string / ssh submissions
MAX_FILE_BODY = 16 * 1024 * 1024       # any form with a file field

# What the visitor sees when a backend (op / Infisical) or disk write fails.
# The real exception goes to the server log only: op/Infisical error text can
# carry vault/item names, account e-mails and local paths.
GENERIC_SAVE_ERROR = ('Could not save the secret. Nothing was stored; '
                      'please try again or tell the person who sent you this link.')

_TOKEN_OK = re.compile(r'^[A-Za-z0-9_-]{16,128}$')


def _redact(msg, *secrets):
    """Strip any submitted value out of an error string before logging it."""
    msg = str(msg)
    for s in secrets:
        if isinstance(s, bytes):
            try:
                s = s.decode('utf-8')
            except UnicodeDecodeError:
                continue
        if s and len(s) >= 4:
            msg = msg.replace(s, '[redacted]')
    return msg


class SecureEntryHandler(BaseHTTPRequestHandler):

    # Bound how long a slow or half-open connection can hold a thread.
    timeout = 60
    server_version = 'secure-entry'
    sys_version = ''

    output_file = Path('.')          # legacy single-field disk path
    output_dir = None                # multi-field disk dir (Path) or None
    label = 'secret'
    # Unguessable path prefix. The form lives at /<token>/ and everything else
    # 404s, so knowing the (guessable) subdomain is not enough to submit.
    token = ''
    received = False
    # Set while one submission is mid-persist (the backend write can take
    # seconds). A second POST in that window gets 409 instead of racing.
    claimed = False
    _lock = threading.Lock()
    # Multi-field: names already persisted to the backend by an earlier,
    # partially failed attempt. A retry only writes the rest.
    saved_fields = None
    server_ref = None
    # Phase 1 op-integration knobs.
    save_to_op = None       # op://Vault/Item/field for single-field, op://Vault/Item for multi
    keep_disk = False
    signal_file = None
    entry_type = 'string'   # single-field type override
    # Phase 4 multi-field state. fields is a list of (name, type) tuples; if
    # empty/None, single-field legacy mode is active.
    fields = None

    def log_message(self, format, *args):
        # Suppress all request logging: the request line carries the token.
        pass

    # ── response helpers ──────────────────────────────────────────────────

    def _security_headers(self, nonce=None):
        if nonce:
            csp = (f"default-src 'none'; script-src 'nonce-{nonce}'; "
                   f"{porch_style_src(nonce)}; connect-src 'self'; "
                   "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        else:
            csp = "default-src 'none'; frame-ancestors 'none'; sandbox"
        self.send_header('Content-Security-Policy', csp)
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        if self.close_connection:
            self.send_header('Connection', 'close')
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _not_found(self):
        body = b'Not found'
        self.send_response(404)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self._security_headers()
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def _route(self):
        """Return the sub-path after /<token>, or None if the token is wrong.

        '/<token>' -> '', '/<token>/' -> '/', '/<token>/submit' -> '/submit'.
        """
        path = urllib.parse.urlsplit(self.path).path
        if not path.startswith('/'):
            return None
        seg, sep, rest = path[1:].partition('/')
        tok = SecureEntryHandler.token
        if not tok or not hmac.compare_digest(seg.encode(), tok.encode()):
            return None
        return (sep + rest) if sep else ''

    def _same_origin(self):
        """True when the POST carries an Origin/Referer for this very host
        (porch_http.same_origin): a page on another site could otherwise POST
        first and win the one-shot with attacker-chosen text."""
        return same_origin(self)

    def _read_body(self, cap):
        """Read the request body under `cap`. Returns bytes, or None after
        having already sent the error response."""
        length = content_length(self)
        if length < 0:
            self.close_connection = True
            self.send_json({'status': 'error', 'message': 'Bad Content-Length'}, 400)
            return None
        if length > cap:
            self.close_connection = True
            self.send_json({'status': 'error', 'message': 'Submission too large'}, 413)
            return None
        if length == 0:
            # Chunked or missing: BaseHTTPRequestHandler does not de-chunk,
            # and an unbounded read is the thing being avoided.
            self.close_connection = True
            self.send_json({'status': 'error', 'message': 'Content-Length required'}, 411)
            return None
        try:
            body = self.rfile.read(length)
        except (socket.timeout, OSError):
            self.close_connection = True
            return None
        if len(body) != length:
            self.close_connection = True
            self.send_json({'status': 'error', 'message': 'Incomplete body'}, 400)
            return None
        return body

    # ── claim / release around the slow persist ────────────────────────────

    # Release BEFORE answering, on failure as on success: a client that gets
    # its 502 and retries at once must not find the claim still held by this
    # thread (409 already_received; seen as a flaky test). _release only
    # drops a claim this handler holds, so the later `finally` cannot clear
    # a newer request's claim.
    def _claim(self):
        cls = SecureEntryHandler
        with cls._lock:
            if cls.received or cls.claimed:
                return False
            cls.claimed = True
            self._holding = True
            return True

    def _release(self, *, success):
        cls = SecureEntryHandler
        with cls._lock:
            if not getattr(self, '_holding', False):
                return
            self._holding = False
            cls.claimed = False
            if success:
                cls.received = True

    # ── GET ────────────────────────────────────────────────────────────────

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        sub = self._route()
        if sub is None:
            self._not_found()
            return
        # porch.css + fonts, only below /<token>/ (the bare host stays a 404);
        # _route() has already checked the token in constant time.
        if serve_asset(self, head=self.command == 'HEAD', base=f'/{SecureEntryHandler.token}'):
            return
        if sub == '':
            # /<token> -> /<token>/ so the form's relative 'submit' resolves.
            self.send_response(301)
            self.send_header('Location', f'/{SecureEntryHandler.token}/')
            self.send_header('Content-Length', '0')
            self._security_headers()
            self.end_headers()
            return
        if sub != '/':
            self._not_found()
            return

        cls = SecureEntryHandler
        if cls.fields:
            html_text = _render_multi_html(cls.label, cls.fields)
        else:
            html_text = _render_single_form(cls.label, field_type=cls.entry_type)
        if cls.received:
            html_text = html_text.replace(
                '<div id="form" class="se-form">', '<div id="form" class="se-form" hidden>'
            ).replace(
                '<div id="already" class="p-notice already" role="status" hidden>',
                '<div id="already" class="p-notice already" role="status">'
            )
        elif cls.fields and cls.saved_fields:
            # Partial save from an earlier attempt: show which fields are done
            # (the page script greys them out and skips them on retry).
            done = ', '.join(n for n, _ in cls.fields if n in cls.saved_fields)
            html_text = html_text.replace(
                '<div id="status" class="p-notice p-notice--error banner error" role="alert" hidden></div>',
                '<div id="status" class="p-notice p-notice--warn banner error" role="alert">Already saved: '
                f'{html.escape(done)}. Fill in the remaining fields and submit again.</div>'
            )
            html_text = html_text.replace(
                "document.getElementById('submitBtn').addEventListener",
                f"markSaved({json.dumps(sorted(cls.saved_fields)).replace('<', chr(92) + 'u003c')});\n"
                "document.getElementById('submitBtn').addEventListener"
            )
        nonce = secrets.token_urlsafe(16)
        body = (html_text.replace('__PORCH_CSS__', porch_css_tag(base=f'/{cls.token}'))
                .replace('CSP_NONCE', nonce).encode())
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self._security_headers(nonce)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    # ── POST ───────────────────────────────────────────────────────────────

    def do_POST(self):
        if self._route() != '/submit':
            self.close_connection = True
            self._not_found()
            return

        # Before the body is read: a cross-site POST costs nothing and can
        # never win the one-shot.
        if not self._same_origin():
            self.close_connection = True
            self.send_json({'status': 'error',
                            'message': 'Cross-origin request refused'}, 403)
            return

        cls = SecureEntryHandler
        if cls.received:
            self.close_connection = True
            self.send_json({'status': 'already_received'}, 409)
            return

        ctype = self.headers.get('Content-Type', '')
        has_file = (cls.entry_type == 'file') if not cls.fields else \
            any(t == 'file' for _, t in cls.fields)
        body = self._read_body(MAX_FILE_BODY if has_file else MAX_TEXT_BODY)
        if body is None:
            return

        if cls.fields:
            saved = cls.saved_fields or set()
            expected = [f for f in cls.fields if f[0] not in saved]
            try:
                values, errors = self._parse_multi_post(
                    ctype, raw_body=body, expected=expected)
            except Exception as e:
                sys.stderr.write(f"[secure-entry] multipart parse failed: {type(e).__name__}\n")
                self.send_json({'status': 'error', 'message': 'Could not read the form data'}, 400)
                return
            if errors:
                self.send_json(
                    {'status': 'error',
                     'message': 'Missing required field(s): ' + ', '.join(errors),
                     'invalid_fields': errors},
                    400,
                )
                return
            if not self._claim():
                self.send_json({'status': 'already_received'}, 409)
                return
            ok = False
            try:
                ok = self._persist_multi(values)
            finally:
                self._release(success=ok)
            if ok:
                self._schedule_shutdown()
            return

        if cls.entry_type == 'file':
            # Single-field file: parse as multipart, look for 'content' field.
            try:
                values, errors = self._parse_multi_post(
                    ctype, raw_body=body, expected=[('content', 'file')]
                )
            except Exception as e:
                sys.stderr.write(f"[secure-entry] multipart parse failed: {type(e).__name__}\n")
                self.send_json({'status': 'error', 'message': 'Could not read the form data'}, 400)
                return
            if errors:
                self.send_json(
                    {'status': 'error', 'message': 'Empty content',
                     'invalid_fields': errors},
                    400,
                )
                return
            content = values['content']
        else:
            # type=string or type=ssh — urlencoded body with a 'content' key.
            try:
                params = urllib.parse.parse_qs(body.decode('utf-8'))
            except UnicodeDecodeError:
                self.send_json({'status': 'error', 'message': 'Invalid encoding'}, 400)
                return
            content = params.get('content', [''])[0]
            if not content.strip():
                self.send_json({'status': 'error', 'message': 'Empty content'}, 400)
                return

        if not self._claim():
            self.send_json({'status': 'already_received'}, 409)
            return
        ok = False
        try:
            ok = self._persist_single_value(content)
        finally:
            self._release(success=ok)
        if ok:
            self._schedule_shutdown()

    def _schedule_shutdown(self):
        cls = SecureEntryHandler
        if cls.server_ref:
            timer = threading.Timer(30, cls.server_ref.shutdown)
            timer.daemon = True
            timer.start()

    # ── Multipart parsing ──────────────────────────────────────────────────

    def _parse_multi_post(self, ctype, *, raw_body, expected=None):
        """Parse an already-read multipart body; return (values, missing).

        values: {field_name: payload}. For string/ssh fields, payload is the
        decoded text. For file fields, payload is the raw bytes (caller is
        responsible for base64-encoding for storage).

        Caller passes `expected` as a list of (name, type) tuples to constrain
        which fields to read. If None, uses cls.fields.
        """
        cls = SecureEntryHandler
        field_specs = expected if expected is not None else cls.fields

        # Use cgi.FieldStorage for multipart; it's stdlib and handles file
        # uploads cleanly. (cgi is deprecated in 3.13 but still works in 3.11/12;
        # rewriting to email.parser is a future cleanup.)
        env = {
            'REQUEST_METHOD': 'POST',
            'CONTENT_TYPE': ctype,
            'CONTENT_LENGTH': str(len(raw_body)),
        }
        fs = cgi.FieldStorage(
            fp=io.BytesIO(raw_body),
            headers=self.headers,
            environ=env,
            keep_blank_values=True,
        )

        values = {}
        missing = []
        for name, ftype in field_specs:
            if fs.list is None or name not in fs:
                missing.append(name)
                continue
            item = fs[name]
            # FieldStorage sometimes returns a list when multiple parts share
            # a name; we don't expect that, but guard.
            if isinstance(item, list):
                item = item[0]
            if ftype == 'file':
                if not getattr(item, 'filename', None):
                    missing.append(name)
                    continue
                data = item.file.read()
                if not data:
                    missing.append(name)
                    continue
                values[name] = data  # bytes
            else:
                # string / ssh: read the value as text.
                value = item.value if hasattr(item, 'value') else ''
                if isinstance(value, bytes):
                    try:
                        value = value.decode('utf-8')
                    except UnicodeDecodeError:
                        missing.append(name)
                        continue
                if not value or not value.strip():
                    missing.append(name)
                    continue
                values[name] = value
        return values, missing

    # ── Persistence: single-field path ─────────────────────────────────────

    def _persist_single_value(self, content):
        """Persist one submitted value. Sends the response; returns True on
        success (the caller then marks the entry received)."""
        cls = SecureEntryHandler
        op_target = cls.save_to_op
        write_disk = (op_target is None) or cls.keep_disk

        # Encode file payloads to base64 text so disk and op storage stay
        # printable.
        if cls.entry_type == 'file':
            raw = content if isinstance(content, bytes) else content.encode('utf-8')
            disk_payload = base64.b64encode(raw).decode('ascii')
            size_bytes = len(raw)
        else:
            disk_payload = content
            size_bytes = len(content.encode('utf-8'))

        # Step 1: secret-backend write (if requested). Routed through the
        # cush_secrets dispatch layer so op:// and inf:// refs both work.
        if op_target is not None:
            try:
                import cush_secrets
                cush_secrets.item_upsert(op_target, disk_payload, concealed=True)
            except Exception as e:
                sys.stderr.write(
                    f"[secure-entry] secrets write failed ({type(e).__name__}): "
                    f"{_redact(e, disk_payload, content)}\n")
                self._release(success=False)
                self.send_json({'status': 'error', 'message': GENERIC_SAVE_ERROR}, 502)
                return False

        # Step 2: disk write (atomic, 0600, never through a symlink).
        if write_disk:
            try:
                output_path = cls.output_file
                if output_path.is_dir() and not output_path.is_symlink():
                    shutil.rmtree(output_path)
                rundir.write_private(str(output_path), disk_payload)
            except Exception as e:
                sys.stderr.write(
                    f"[secure-entry] disk write failed ({type(e).__name__}): "
                    f"{_redact(e, disk_payload, content)}\n")
                self._release(success=False)
                self.send_json({'status': 'error', 'message': GENERIC_SAVE_ERROR}, 500)
                return False

        # Step 3: signal-file.
        self._touch_signal()

        # Step 4: success path.
        if op_target is not None and not write_disk:
            sys.stderr.write(f"[secure-entry] Secret received → {op_target}\n")
        elif op_target is not None:
            sys.stderr.write(
                f"[secure-entry] Secret received → {op_target} + {cls.output_file}\n"
            )
        else:
            sys.stderr.write(f"[secure-entry] Secret received → {cls.output_file}\n")

        if cls.entry_type == 'file':
            sys.stderr.write(f"[secure-entry] file payload {size_bytes} bytes (base64-encoded)\n")

        resp = {'status': 'ok', 'received': ['content']}
        if cls.entry_type == 'file':
            resp['size_bytes'] = size_bytes
        # Mark received *before* answering, so nobody can observe a 200
        # while the one-shot still looks open.
        self._release(success=True)
        self.send_json(resp)
        return True

    def _touch_signal(self):
        cls = SecureEntryHandler
        if cls.signal_file:
            try:
                sig = Path(cls.signal_file)
                sig.parent.mkdir(parents=True, exist_ok=True)
                sig.touch()
            except Exception as e:
                sys.stderr.write(f"[secure-entry] signal-file touch failed: {e}\n")

    # ── Persistence: multi-field path ──────────────────────────────────────

    def _persist_multi(self, values):
        """Persist a multi-field submission to disk and/or the backend.

        values: {name: str|bytes} for every field not already saved.

        Disk layout: <runtime-dir>/<label>/<field>, mode 600 per file, 700 on
        the directory. File-type fields are base64-encoded.

        Backend layout: --save-to-secrets op://Vault/Item (no trailing field),
        one upsert per field. If some upserts fail, the ones that succeeded
        are remembered in cls.saved_fields and reported back to the visitor;
        a retry writes only the remainder. Returns True on full success.
        """
        cls = SecureEntryHandler
        op_target = cls.save_to_op
        write_disk = (op_target is None) or cls.keep_disk
        if cls.saved_fields is None:
            cls.saved_fields = set()

        disk_payloads = {}   # name -> str (text for string/ssh, base64 for file)
        size_bytes = {}
        for name, ftype in cls.fields:
            if name not in values:
                continue
            raw = values[name]
            if ftype == 'file':
                rb = raw if isinstance(raw, bytes) else (raw or '').encode('utf-8')
                disk_payloads[name] = base64.b64encode(rb).decode('ascii')
                size_bytes[name] = len(rb)
            else:
                disk_payloads[name] = raw if isinstance(raw, str) else raw.decode('utf-8')
                size_bytes[name] = len(disk_payloads[name].encode('utf-8'))

        all_names = [n for n, _ in cls.fields]

        # Step 1: secret-backend writes, in declaration order.
        if op_target is not None:
            import cush_secrets  # noqa: WPS433 — deferred import
            failed = []
            for name in all_names:
                if name in cls.saved_fields or name not in disk_payloads:
                    continue
                per_field_ref = cush_secrets.join_multi_field_ref(op_target, name)
                payload = disk_payloads[name]
                try:
                    cush_secrets.item_upsert(per_field_ref, payload, concealed=True)
                except Exception as e:
                    failed.append(name)
                    sys.stderr.write(
                        f"[secure-entry] secrets write failed for field {name!r} "
                        f"({type(e).__name__}): {_redact(e, payload, values.get(name))}\n")
                    continue
                cls.saved_fields.add(name)
            if failed:
                saved = [n for n in all_names if n in cls.saved_fields]
                if saved:
                    msg = (f"Saved: {', '.join(saved)}. Could not save: "
                           f"{', '.join(failed)}. Press Retry to send only the "
                           f"fields that failed.")
                else:
                    msg = GENERIC_SAVE_ERROR
                self._release(success=False)
                self.send_json(
                    {'status': 'error', 'message': msg,
                     'saved': saved, 'failed': failed},
                    502,
                )
                return False

        # Step 2: disk write — directory-per-label layout. Only reached once
        # every field has a value in this request (backend-less mode never
        # records partial saves, so all fields were required).
        if write_disk:
            missing = [n for n in all_names if n not in disk_payloads]
            if missing and op_target is not None:
                # --keep-disk after a partial backend save: the earlier values
                # were not kept in memory, so they cannot be written to disk.
                sys.stderr.write(
                    "[secure-entry] --keep-disk: fields saved on an earlier attempt "
                    f"are not on disk: {', '.join(missing)}\n")
            try:
                outdir = cls.output_dir
                if outdir is None:
                    raise RuntimeError("multi-field disk path not configured")
                if outdir.is_symlink() or (outdir.exists() and not outdir.is_dir()):
                    outdir.unlink()
                rundir.ensure_private_subdir(str(outdir))
                for name in all_names:
                    if name not in disk_payloads:
                        continue
                    fp = outdir / name
                    if fp.is_dir() and not fp.is_symlink():
                        shutil.rmtree(fp)
                    rundir.write_private(str(fp), disk_payloads[name])
            except Exception as e:
                sys.stderr.write(
                    f"[secure-entry] disk write failed ({type(e).__name__}): "
                    f"{_redact(e, *disk_payloads.values())}\n")
                self._release(success=False)
                self.send_json({'status': 'error', 'message': GENERIC_SAVE_ERROR}, 500)
                return False

        # Step 3: signal-file.
        self._touch_signal()

        # Step 4: success.
        if op_target is not None and not write_disk:
            sys.stderr.write(
                f"[secure-entry] Secrets received ({len(all_names)} field(s)) → {op_target}\n"
            )
        elif op_target is not None:
            sys.stderr.write(
                f"[secure-entry] Secrets received ({len(all_names)} field(s)) → "
                f"{op_target} + {cls.output_dir}\n"
            )
        else:
            sys.stderr.write(
                f"[secure-entry] Secrets received ({len(all_names)} field(s)) → {cls.output_dir}\n"
            )

        self._release(success=True)     # before answering (see single-field)
        self.send_json({
            'status': 'ok',
            'received': all_names,
            'sizes': size_bytes,
        })
        return True


# ── argparse helpers ───────────────────────────────────────────────────────


_VALID_TYPES = ('string', 'file', 'ssh')


def _parse_field_arg(s):
    """Parse a --field argument: 'name' or 'name:type'.

    Returns (name, type). Type defaults to 'string'. Raises ValueError on
    malformed input or unknown type.
    """
    if ':' in s:
        name, ftype = s.split(':', 1)
    else:
        name, ftype = s, 'string'
    name = name.strip()
    ftype = ftype.strip()
    if not name:
        raise ValueError(f"--field: empty field name in {s!r}")
    # Validate name: keep it simple — printable ASCII, no slashes, no colons.
    for ch in name:
        if ch in '/\\:' or ord(ch) < 0x20:
            raise ValueError(f"--field: invalid character {ch!r} in field name {name!r}")
    if ftype not in _VALID_TYPES:
        raise ValueError(
            f"--field: type for {name!r} must be one of {_VALID_TYPES} (got {ftype!r})"
        )
    return name, ftype


def main():
    parser = argparse.ArgumentParser(description='Secure entry server')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--label', type=str, required=True)
    parser.add_argument('--output', type=str, required=True,
                        help='Disk path for the submitted secret. In single-'
                             'field mode this is a flat file path. In multi-'
                             'field mode this is treated as a directory and '
                             'each field is written to a child file.')
    parser.add_argument('--save-to-secrets', dest='save_to_secrets', type=str,
                        default=None,
                        help='Backend ref (op:// or inf://). Single-field: '
                             'op://Vault/Item/field or inf://env/path/KEY. '
                             'Multi-field: op://Vault/Item or inf://env/path '
                             '(no trailing key).')
    parser.add_argument('--save-to-op', dest='save_to_op_legacy', type=str,
                        default=None,
                        help='Deprecated alias for --save-to-secrets '
                             '(only accepts op:// refs historically; now '
                             'forwards to --save-to-secrets verbatim).')
    parser.add_argument('--keep-disk', action='store_true',
                        help='With --save-to-op, also write to disk.')
    parser.add_argument('--signal-file', type=str, default=None,
                        help='Path to touch after a successful persist.')
    parser.add_argument('--type', dest='entry_type', default='string',
                        choices=list(_VALID_TYPES),
                        help='Single-field: submission type. Ignored when '
                             '--field is specified (use name:type instead).')
    parser.add_argument('--field', dest='fields', action='append', default=[],
                        help='Multi-field mode: --field <name>[:<type>]. '
                             'Repeat for multiple fields. Type defaults to '
                             'string.')
    parser.add_argument('--bind', type=str, default='127.0.0.1',
                        help='Listen address (default 127.0.0.1; frpc '
                             'connects over loopback).')
    args = parser.parse_args()

    # The URL path token. Taken from the environment (not argv, which every
    # local user can read in ps/proc) so the launcher can print the full URL
    # before the server starts; generated here when not provided.
    token = os.environ.pop('SECURE_ENTRY_TOKEN', '')
    if not token:
        token = secrets.token_urlsafe(24)
        sys.stderr.write(f"[secure-entry] form path: /{token}/\n")
    if not _TOKEN_OK.match(token):
        sys.stderr.write("[secure-entry] SECURE_ENTRY_TOKEN must be 16-128 chars of [A-Za-z0-9_-]\n")
        sys.exit(2)
    SecureEntryHandler.token = token

    # Parse fields. Empty list -> single-field mode.
    fields = []
    for f in args.fields:
        try:
            fields.append(_parse_field_arg(f))
        except ValueError as e:
            sys.stderr.write(f"[secure-entry] {e}\n")
            sys.exit(2)

    # Reject duplicate field names.
    seen = set()
    for name, _ in fields:
        if name in seen:
            sys.stderr.write(f"[secure-entry] duplicate --field name: {name}\n")
            sys.exit(2)
        seen.add(name)

    multi_mode = len(fields) > 0

    # Reconcile --save-to-secrets / --save-to-op (deprecated alias). If both
    # are set, prefer --save-to-secrets; print a stderr nudge so the user
    # notices the conflict but the script keeps going.
    save_to = args.save_to_secrets
    if args.save_to_op_legacy is not None:
        sys.stderr.write(
            "[secure-entry] note: --save-to-op is deprecated; "
            "use --save-to-secrets (accepts op:// or inf://) instead.\n"
        )
        if save_to is None:
            save_to = args.save_to_op_legacy

    # Ref-shape validation against mode. Routed through cush_secrets so the
    # rules stay in one place and op:// + inf:// share a checker.
    if save_to is not None:
        try:
            import cush_secrets
            cush_secrets.validate_persist_ref_shape(save_to, multi_field=multi_mode)
        except Exception as e:
            sys.stderr.write(f"[secure-entry] {e}\n")
            sys.exit(2)

    output_path = Path(args.output).resolve()
    SecureEntryHandler.label = args.label
    SecureEntryHandler.save_to_op = save_to
    SecureEntryHandler.keep_disk = args.keep_disk
    SecureEntryHandler.signal_file = args.signal_file
    SecureEntryHandler.entry_type = args.entry_type
    SecureEntryHandler.fields = fields if multi_mode else None

    if multi_mode:
        SecureEntryHandler.output_dir = output_path
        SecureEntryHandler.output_file = output_path  # cosmetic
    else:
        SecureEntryHandler.output_file = output_path
        SecureEntryHandler.output_dir = None

    # Only create the output dir when we actually intend to write there.
    write_disk = (save_to is None) or args.keep_disk
    if write_disk:
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            rundir.ensure_private_subdir(str(output_path.parent))
            if multi_mode:
                if output_path.is_symlink() or (output_path.exists() and not output_path.is_dir()):
                    output_path.unlink()
                rundir.ensure_private_subdir(str(output_path))
        except (OSError, rundir.UnsafeDirError) as e:
            sys.stderr.write(f"[secure-entry] refusing unsafe output location: {e}\n")
            sys.exit(1)

    server = make_server(SecureEntryHandler, args.port, args.bind, tag='secure-entry')
    SecureEntryHandler.server_ref = server
    mode_bits = []
    if save_to:
        mode_bits.append(f"secrets={save_to}")
    if write_disk:
        if multi_mode:
            mode_bits.append(f"disk-dir={output_path}")
        else:
            mode_bits.append(f"disk={output_path}")
    if args.signal_file:
        mode_bits.append(f"signal={args.signal_file}")
    if multi_mode:
        mode_bits.append(f"fields={','.join(n for n, _ in fields)}")
    sys.stderr.write(
        f"[secure-entry] Listening on {args.bind}:{args.port}, label={args.label}"
        f"{' (' + ', '.join(mode_bits) + ')' if mode_bits else ''}\n"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n[secure-entry] Shutting down.\n")
        server.shutdown()


if __name__ == '__main__':
    main()

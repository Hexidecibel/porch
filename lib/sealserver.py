#!/usr/bin/env python3
"""Sealed-share door: serves one porch-seal v1 file (ciphertext only) and a
page that decrypts it in the browser.

Used by bin/seal (and `porch share --e2e`). The server never holds a key: the
link carries it in its #k= fragment, which browsers do not send, or the
recipient types a password that is stretched in the page (PBKDF2). What this
process sees is the same ciphertext the disk, the logs and the door inspector
see. Format and threat model: docs/porch-seal.md; crypto: lib/porch_seal.py
and lib/seal.js (served at /static/seal.js).

Endpoints:
    /                   the page (porch.css, data-app "secret": the green of
                        secure-entry, the other tool whose whole point is that
                        the box never sees the plaintext)
    /blob               the ciphertext, application/octet-stream, one Range
                        at a time, no-store, nosniff, attachment
    /static/seal.js     lib/seal.js
    /static/pdfjs/...   the viewer's vendored pdf.js table (lib/viewserver.py)

Opens and burn: the state file says opens_by = "app" (bin/seal sets it), so
the door proxy counts nothing. Here an open is a COMPLETE download of /blob by
one client (client_ip: the right-most non-loopback X-Forwarded-For hop from a
loopback peer): the bytes actually written to that client are tracked as
intervals across Range requests, and the open is counted when they cover the
whole file (then the client starts over, so a second full download counts
again). Partial downloads never count; neither does the owner
(porch_auth.request_is_owner against --devices). When the count reaches the
door's live max_opens (--burn = 1), /blob answers 410 from then on, an owned
file (--owned-file) is deleted at once, and the door is stopped
(door_state.stop_door) after GRACE seconds so a page that just finished can
still load pdf.js and its fonts.
"""

import argparse
import collections
import html
import json
import os
import re
import stat
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler

_HERE_LIB = os.path.dirname(os.path.abspath(__file__))
if _HERE_LIB not in sys.path:
    sys.path.insert(0, _HERE_LIB)
import door_state  # noqa: E402
import porch_auth  # noqa: E402
import porch_seal  # noqa: E402
from porch_http import (  # noqa: E402
    SANDBOX_CSP, HardenedHandlerMixin, client_ip, csp_nonce, human_size, make_server,
    parse_range, porch_css_tag, porch_mark, porch_style_src, security_headers, serve_asset,
)
from viewserver import STATIC_FILES as VIEW_STATIC, VENDOR_DIR  # noqa: E402

SEAL_JS = os.path.join(_HERE_LIB, 'seal.js')
_JS = 'text/javascript; charset=utf-8'
# pdf.js and its CMaps/standard fonts, exactly as the viewer serves them.
STATIC_FILES = {p: v for p, v in VIEW_STATIC.items() if p.startswith('/static/pdfjs/')}
_static_cache = {}

GRACE = 30                       # s between the last allowed download and closing the door
MAX_CLIENTS = 1024               # clients whose partial coverage we remember
CAP_DESKTOP = 1024 ** 3          # in-memory decrypt cap in the page (desktop)
CAP_IOS = 300 * 1024 ** 2        # ... and on iOS / iPadOS
CHUNK = 64 * 1024


class Coverage:
    """Merged half-open byte intervals [start, end)."""

    def __init__(self):
        self.spans = []

    def add(self, start, end):
        if end <= start:
            return
        out = []
        placed = False
        for s, e in self.spans:
            if e < start:
                out.append((s, e))
            elif end < s:
                if not placed:
                    out.append((start, end))
                    placed = True
                out.append((s, e))
            else:
                start, end = min(s, start), max(e, end)
        if not placed:
            out.append((start, end))
        out.sort()
        self.spans = out

    def covered(self):
        return sum(e - s for s, e in self.spans)


class Burner:
    """Counts complete downloads per client and closes the door at the limit."""

    def __init__(self, total, state_path=None, closer=None, on_exhausted=None, grace=GRACE,
                 max_clients=MAX_CLIENTS):
        self.total = total
        self.state_path = state_path
        self.closer = closer
        self.on_exhausted = on_exhausted
        self.grace = grace
        self.max_clients = max_clients
        self.clients = collections.OrderedDict()
        self.lock = threading.Lock()
        self.exhausted = False
        self.completed = 0               # complete non-owner downloads seen
        self._timer = None

    def served(self, client, start, end):
        """Credit bytes [start, end) written to `client`. True when this
        completed a download (and it was counted)."""
        with self.lock:
            cov = self.clients.get(client)
            if cov is None:
                cov = self.clients[client] = Coverage()
                while len(self.clients) > self.max_clients:
                    self.clients.popitem(last=False)
            else:
                self.clients.move_to_end(client)
            cov.add(start, end)
            if cov.covered() < self.total:
                return False
            del self.clients[client]     # a later full download counts again
            self.completed += 1
        self._count()
        return True

    def _count(self):
        opens, limit = None, None
        if self.state_path:
            try:
                opens, limit = door_state.count_open(self.state_path)
            except FileNotFoundError:
                return                    # the door is going away
            except (OSError, ValueError) as e:
                sys.stderr.write(f'[sealserver] could not record an open: {e}\n')
                return
        if limit and opens >= limit:
            self._exhaust()

    def _exhaust(self):
        with self.lock:
            if self.exhausted:
                return
            self.exhausted = True
        sys.stderr.write(f'[sealserver] download limit reached; closing in {self.grace}s\n')
        if self.on_exhausted:
            try:
                self.on_exhausted()
            except Exception as e:  # noqa: BLE001
                sys.stderr.write(f'[sealserver] cleanup failed: {e!r}\n')
        if self.closer:
            t = threading.Timer(self.grace, self._close)
            t.daemon = True
            self._timer = t
            t.start()

    def _close(self):
        try:
            self.closer()
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f'[sealserver] close failed: {e!r}\n')


PAGE_HTML = r"""<!DOCTYPE html>
<html lang="en" data-app="secret">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex">
<title>Sealed file</title>
__PORCH_CSS__
<style nonce="__NONCE__">
/* One left edge: the header, the file and the buttons all sit on the shell's gutter. */
.p-head{padding:0}
.p-kicker{flex-wrap:wrap;row-gap:6px}
.p-title{font-size:clamp(24px,7vw,32px);overflow-wrap:anywhere}
.bar{display:flex;flex-wrap:wrap;align-items:center;gap:8px}
.bar .meta{flex:none}
#notice:empty{display:none}
.meta{font:500 13px var(--font-mono);color:var(--muted);overflow-wrap:anywhere}
.status{display:flex;flex-direction:column;gap:10px}
.status-label{font-size:14px;color:var(--muted)}
.stage{display:flex;justify-content:center;background:var(--surface);border:1px solid var(--line);
  border-radius:var(--r-2xl);padding:12px;overflow:auto}
/* a photo or a video is its own card: no frame around it, flush with the text */
.stage--image,.stage--video{padding:0;background:none;border:0;overflow:visible}
.stage img,.stage video{display:block;max-width:100%;height:auto;max-height:70vh;max-height:70svh;border-radius:var(--r-lg)}
.stage--video video{width:100%;background:#000}
.stage audio{width:100%}
.stage canvas{max-width:100%;height:auto;background:#fff;border-radius:4px}
.text{margin:0;width:100%;white-space:pre-wrap;overflow-wrap:anywhere;font:400 13px/1.55 var(--font-mono);
  color:var(--text);max-height:65vh;max-height:65svh;overflow:auto}
@media (max-width:560px){.bar .dl{flex:1 1 100%}}
.pwform{display:flex;flex-direction:column;gap:14px}
.hint{font-size:13px;color:var(--muted)}
[hidden]{display:none!important}
</style>
</head>
<body>
<main class="p-shell">
  <header class="p-head">
    <div class="p-kicker">__MARK__<span>Sealed share</span><span class="p-badge p-badge--accent">end-to-end encrypted</span>__BURN__</div>
    <h1 class="p-title" id="title">A sealed file</h1>
    <p class="p-lede" id="lede">It is decrypted here, in your browser. This server only holds
      ciphertext and never sees the key.</p>
    <p class="meta" id="meta">__SIZE__</p>
  </header>
  <section class="p-card status" id="status">
    <div class="status-label" id="status-label">Opening…</div>
    <div class="p-progress" id="progress"><span id="progress-fill"></span></div>
  </section>
  <form class="p-card pwform" id="pwform" hidden>
    <div class="p-field">
      <label class="p-label" for="pw">Password</label>
      <input class="p-input" id="pw" type="password" autocomplete="off" required>
    </div>
    <p class="hint">The sender sealed this file with a password. It is checked in your
      browser; nothing you type is sent anywhere.</p>
    <button class="p-btn p-btn--lg p-btn--block" type="submit" id="pwbtn">Open</button>
  </form>
  <div id="notice"></div>
  <section id="view" hidden></section>
  <div class="bar" id="actions" hidden></div>
</main>
<script type="application/json" id="cfg">__CFG_JSON__</script>
<script src="/static/seal.js"></script>
<script nonce="__NONCE__">
(function () {
  'use strict';
  const cfg = JSON.parse(document.getElementById('cfg').textContent);
  const $ = function (id) { return document.getElementById(id); };
  const IOS = /iPad|iPhone|iPod/.test(navigator.userAgent)
    || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  const CAP = IOS ? cfg.capIOS : cfg.capDesktop;
  const IMAGES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/avif', 'image/bmp'];
  const TEXTY = ['application/json', 'application/xml', 'application/javascript', 'application/x-sh',
    'application/x-yaml', 'application/toml', 'application/x-ndjson', 'application/sql'];
  const TEXT_EXT = /\.(txt|md|markdown|log|csv|tsv|json|ndjson|ya?ml|toml|ini|conf|cfg|py|js|mjs|ts|sh|bash|c|h|cc|cpp|go|rs|java|rb|php|html?|css|xml|sql|diff|patch)$/i;
  const MAX_TEXT = 4 * 1024 * 1024;
  let urls = [];

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function human(n) {
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(n < 10 ? 1 : 0) : String(n)) + ' ' + u[i];
  }
  function status(text, frac) {
    $('status').hidden = false;
    $('status-label').textContent = text;
    $('progress').hidden = frac == null;
    if (frac != null) $('progress-fill').style.width = Math.round(Math.max(0, Math.min(1, frac)) * 100) + '%';
  }
  function notice(kind, title, text) {
    const box = $('notice');
    box.textContent = '';
    if (!title) return;
    const n = el('div', 'p-notice p-notice--' + kind);
    const body = el('div');
    body.appendChild(el('strong', null, title));
    if (text) { body.appendChild(document.createElement('br')); body.appendChild(document.createTextNode(text)); }
    n.appendChild(body);
    box.appendChild(n);
  }
  // The key lives in the address bar until the file opens: a reload or a
  // retry still works while something is wrong. After a successful decrypt
  // it is removed (history, screen shares, shoulder surfers); reloading then
  // needs the original link again.
  function stripKey() {
    if (location.hash) {
      try { history.replaceState(null, '', location.pathname + location.search); } catch (e) {}
    }
  }
  function kindOf(meta) {
    const t = String(meta.type || '').toLowerCase().split(';')[0].trim();
    if (IMAGES.indexOf(t) >= 0) return 'image';
    if (t.indexOf('video/') === 0) return 'video';
    if (t.indexOf('audio/') === 0) return 'audio';
    if (t === 'application/pdf') return 'pdf';
    if (t.indexOf('text/') === 0 || TEXTY.indexOf(t) >= 0 || TEXT_EXT.test(meta.name)) return 'text';
    return 'file';
  }
  let pdfLib = null;
  function loadPdf() {
    if (!pdfLib) {
      pdfLib = import('/static/pdfjs/pdf.min.mjs').then(function (lib) {
        lib.GlobalWorkerOptions.workerSrc = '/static/pdfjs/pdf.worker.min.mjs';
        return lib;
      });
    }
    return pdfLib;
  }

  function fail(e, mode) {
    $('status').hidden = true;
    const k = e && e.kind;
    if (k === 'key' && mode === 'password') {
      askPassword('Wrong password. Try again.');
      return;
    }
    if (k === 'key') {
      notice('error', 'This link’s key does not open the file',
        'The link may be cut short or mistyped. Ask the sender for the whole link, including everything after #.');
    } else if (k === 'tamper') {
      notice('error', 'This file was changed after it was sealed',
        'It failed the integrity check, so nothing from it is shown.');
    } else if (k === 'format') {
      notice('error', 'This sealed file is broken', 'It is not a file this page can open.');
    } else if (k === 'gone') {
      notice('warn', 'This share is gone', 'It was already opened (burn after reading), expired, or was closed by the sender.');
    } else if (k === 'network') {
      notice('error', 'The download failed', 'Check the connection and reload the page.');
    } else {
      notice('error', 'Something went wrong', String((e && e.message) || e));
    }
  }

  function askPassword(error) {
    $('status').hidden = true;
    notice(error ? 'error' : '', error || '');
    $('pwform').hidden = false;
    $('pwbtn').disabled = false;
    $('pw').value = '';
    $('pw').focus();
  }

  function downloadLink(blob, name, label) {
    const u = URL.createObjectURL(blob);
    urls.push(u);
    const a = el('a', 'p-btn p-btn--lg dl', label || 'Download');
    a.href = u;
    a.setAttribute('download', name || 'download');
    return a;
  }

  async function render(kind, parts, meta) {
    const view = $('view');
    view.textContent = '';
    const actions = $('actions');
    actions.textContent = '';
    // Only types that never run script get their real MIME type on the Blob;
    // everything else is octet-stream, so its blob: URL cannot become a page.
    const shown = (kind === 'image' || kind === 'video' || kind === 'audio' || kind === 'pdf')
      ? meta.type : 'application/octet-stream';
    const blob = new Blob(parts, {type: shown});
    const stage = el('div', 'stage stage--' + kind);
    view.appendChild(stage);          // in the layout first: the PDF is fitted to its width
    view.hidden = false;
    if (kind === 'image') {
      const img = el('img');
      img.alt = meta.name;
      img.src = URL.createObjectURL(blob);
      urls.push(img.src);
      stage.appendChild(img);
    } else if (kind === 'video' || kind === 'audio') {
      const m = el(kind);
      m.controls = true;
      m.setAttribute('playsinline', '');
      m.preload = 'metadata';
      m.src = URL.createObjectURL(blob);
      urls.push(m.src);
      stage.appendChild(m);
    } else if (kind === 'pdf') {
      await renderPdf(blob, stage, actions);
    } else if (kind === 'text' && blob.size <= MAX_TEXT) {
      const pre = el('pre', 'text');
      pre.textContent = new TextDecoder('utf-8').decode(await blob.arrayBuffer());
      stage.appendChild(pre);
    } else {
      const e = el('div', 'p-empty');
      e.appendChild(el('div', 'p-empty-title', kind === 'text' ? 'Too long to show here' : 'Ready to download'));
      e.appendChild(el('div', 'p-empty-text', human(meta.size) + ' · ' + (meta.type || 'file')));
      stage.appendChild(e);
    }
    actions.appendChild(downloadLink(blob, meta.name, 'Download'));
    actions.hidden = false;
  }

  async function renderPdf(blob, stage, actions) {
    const lib = await loadPdf();
    const data = new Uint8Array(await blob.arrayBuffer());
    const doc = await lib.getDocument({data: data, isEvalSupported: false, enableXfa: false,
      cMapPacked: true, cMapUrl: new URL('/static/pdfjs/cmaps/', location.href).href,
      standardFontDataUrl: new URL('/static/pdfjs/standard_fonts/', location.href).href}).promise;
    const canvas = el('canvas');
    stage.appendChild(canvas);
    let page = 1, task = null;
    const label = el('span', 'meta');
    const prev = el('button', 'p-btn p-btn--ghost p-btn--sm', 'Prev');
    const next = el('button', 'p-btn p-btn--ghost p-btn--sm', 'Next');
    prev.type = next.type = 'button';
    prev.addEventListener('click', function () { if (page > 1) { page--; draw(); } });
    next.addEventListener('click', function () { if (page < doc.numPages) { page++; draw(); } });
    if (doc.numPages > 1) actions.append(prev, label, next);
    async function draw() {
      if (task) { try { task.cancel(); } catch (e) {} }
      const p = await doc.getPage(page);
      const base = p.getViewport({scale: 1});
      const width = Math.max(200, stage.clientWidth - 24);
      const vp = p.getViewport({scale: width / base.width});
      const ratio = window.devicePixelRatio || 1;
      canvas.width = Math.floor(vp.width * ratio);
      canvas.height = Math.floor(vp.height * ratio);
      canvas.style.width = Math.floor(vp.width) + 'px';
      label.textContent = page + ' / ' + doc.numPages;
      task = p.render({canvasContext: canvas.getContext('2d'), viewport: vp,
        transform: ratio !== 1 ? [ratio, 0, 0, ratio, 0, 0] : null});
      try { await task.promise; } catch (e) { if (!e || e.name !== 'RenderingCancelledException') throw e; }
    }
    await draw();
  }

  async function collect(r) {
    const parts = [];
    let done = 0;
    for await (const c of r.chunks) {
      parts.push(c);
      done += c.length;
      status('Decrypting… ' + human(done) + ' of ' + human(r.meta.size), r.meta.size ? done / r.meta.size : 1);
    }
    return parts;
  }

  function offerBig(r) {
    $('status').hidden = true;
    notice('warn', 'Too big to open in the page on this device',
      human(r.meta.size) + '. It can still be decrypted straight into a download.');
    const btn = el('button', 'p-btn p-btn--lg', 'Decrypt and download');
    btn.type = 'button';
    btn.addEventListener('click', async function () {
      btn.disabled = true;
      let w = null;
      try {
        if (window.showSaveFilePicker) {
          const h = await window.showSaveFilePicker({suggestedName: r.meta.name});
          w = await h.createWritable();
          let done = 0;
          for await (const c of r.chunks) {
            await w.write(c);
            done += c.length;
            status('Decrypting… ' + human(done) + ' of ' + human(r.meta.size), done / r.meta.size);
          }
          await w.close();
          w = null;
          status('Saved.', null);
        } else {
          const parts = await collect(r);
          const a = downloadLink(new Blob(parts, {type: 'application/octet-stream'}), r.meta.name, 'Save file');
          $('actions').textContent = '';
          $('actions').appendChild(a);
          $('actions').hidden = false;
          status('Decrypted. Save the file:', null);
        }
        notice('', '');
        stripKey();
      } catch (e) {
        if (w) { try { await w.abort(); } catch (e2) {} }   // a partial file is never committed
        fail(e, r.mode);
      }
    });
    $('actions').textContent = '';
    $('actions').appendChild(btn);
    $('actions').hidden = false;
  }

  async function start(opts, mode) {
    notice('', '');
    status(mode === 'password' ? 'Checking the password…' : 'Opening…', null);
    let r;
    try {
      r = await PorchSeal.open('blob', opts);
    } catch (e) {
      return fail(e, mode);
    }
    $('pwform').hidden = true;
    const meta = r.meta;
    $('title').textContent = meta.name;
    document.title = meta.name;
    $('meta').textContent = human(meta.size) + ' · ' + (meta.type || 'file');
    const kind = kindOf(meta);
    if (meta.size > CAP) return offerBig(r);
    if (kind === 'pdf') loadPdf().catch(function () {});     // fetch pdf.js while decrypting
    let parts;
    try {
      parts = await collect(r);
    } catch (e) {
      return fail(e, mode);
    }
    status('Rendering…', 1);
    try {
      await render(kind, parts, meta);
    } catch (e) {
      notice('warn', 'Opened, but it cannot be shown here', 'Use Download instead.');
      $('view').hidden = true;
      $('actions').textContent = '';
      $('actions').appendChild(downloadLink(new Blob(parts, {type: 'application/octet-stream'}), meta.name));
      $('actions').hidden = false;
    }
    $('status').hidden = true;
    stripKey();
  }

  window.addEventListener('pagehide', function () { urls.forEach(function (u) { URL.revokeObjectURL(u); }); });
  $('pwform').addEventListener('submit', function (ev) {
    ev.preventDefault();
    const pw = $('pw').value;
    if (!pw) return;
    $('pwbtn').disabled = true;
    $('pw').value = '';
    start({password: pw}, 'password');
  });

  if (!window.PorchSeal || !window.crypto || !window.crypto.subtle) {
    fail({message: 'This browser cannot decrypt here (WebCrypto is missing).'});
  } else if (cfg.mode === 'password') {
    askPassword(null);
  } else {
    const key = PorchSeal.keyFromFragment(location.hash);
    if (!key) {
      $('status').hidden = true;
      notice('error', 'This link is missing its key',
        'A sealed link ends with #k=… . Ask the sender for the whole link.');
    } else {
      start({key: key}, 'key');
    }
  }
})();
</script>
</body>
</html>"""


class SealHandler(HardenedHandlerMixin, BaseHTTPRequestHandler):
    """Serves one sealed file. Configure a subclass with make_handler()."""

    protocol_version = 'HTTP/1.1'

    file_path = None
    name = 'seal'
    info = None                      # porch_seal.info() at start
    devices = None
    burner = None
    state_path = None

    def log_message(self, format, *args):
        method = args[0] if args else ''
        if isinstance(method, str) and method.startswith(('GET', 'HEAD')):
            return
        sys.stderr.write(f"[sealserver] {self.address_string()} - {format % args}\n")

    def _send(self, status, body, ctype, csp=SANDBOX_CSP, headers=(), cache='no-store'):
        if isinstance(body, str):
            body = body.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', cache)
        if csp:
            self.send_header('Content-Security-Policy', csp)
        for k, v in headers:
            self.send_header(k, v)
        security_headers(self)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def _not_found(self):
        self._send(404, 'Not found\n', 'text/plain; charset=utf-8')

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if serve_asset(self, head=self.command == 'HEAD'):
            return
        try:
            path = urllib.parse.urlsplit(self.path).path
        except ValueError:
            return self._not_found()
        if path == '/':
            return self._page()
        if path == '/blob':
            return self._blob()
        if path == '/static/seal.js':
            return self._static_file(SEAL_JS, _JS)
        if path in STATIC_FILES:
            fname, ctype = STATIC_FILES[path]
            return self._static_file(str(VENDOR_DIR / fname), ctype)
        return self._not_found()

    def _static_file(self, fpath, ctype):
        body = _static_cache.get(fpath)
        if body is None:
            try:
                with open(fpath, 'rb') as f:
                    body = f.read()
            except OSError:
                return self._not_found()
            _static_cache[fpath] = body
        self._send(200, body, ctype, csp=None, cache='public, max-age=86400')

    def _live_limit(self):
        if not self.state_path:
            return None
        try:
            return door_state.clean_rules(door_state.read_state(self.state_path).get('rules')).get('max_opens')
        except (OSError, ValueError):
            return None

    def _page(self):
        nonce = csp_nonce()
        cfg = {'name': self.name, 'mode': self.info['mode'],
               'ctSize': self.info['ciphertext_size'], 'plainSize': self.info['plaintext_size'],
               'capDesktop': CAP_DESKTOP, 'capIOS': CAP_IOS}
        limit = self._live_limit()
        burn = ''
        if limit == 1:
            burn = '<span class="p-badge p-badge--wait">burns after one download</span>'
        elif limit:
            burn = f'<span class="p-badge p-badge--wait">closes after {int(limit)} downloads</span>'
        fields = {
            '__PORCH_CSS__': porch_css_tag(),
            '__MARK__': porch_mark(16),
            '__BURN__': burn,
            '__SIZE__': html.escape(f"{human_size(self.info['plaintext_size'])} · porch-seal v1"),
            # '<' escaped so nothing can end the JSON <script> block.
            '__CFG_JSON__': json.dumps(cfg).replace('<', '\\u003c'),
            '__NONCE__': nonce,
        }
        page = re.sub(r'__(?:PORCH_CSS|MARK|BURN|SIZE|CFG_JSON|NONCE)__',
                      lambda m: fields[m.group(0)], PAGE_HTML)
        csp = ("default-src 'none'; "
               f"script-src 'self' 'nonce-{nonce}'; {porch_style_src(nonce)}; "
               "connect-src 'self'; worker-src 'self'; img-src 'self' blob:; "
               "media-src 'self' blob:; form-action 'none'; base-uri 'none'; "
               "frame-ancestors 'none'")
        self._send(200, page, 'text/html; charset=utf-8', csp=csp)

    def _gone(self):
        self._send(410, 'This sealed share is gone.\n', 'text/plain; charset=utf-8')

    def _blob(self):
        if self.burner is not None and self.burner.exhausted:
            return self._gone()
        try:
            fd = os.open(self.file_path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
                         | getattr(os, 'O_CLOEXEC', 0))
        except OSError:
            return self._gone()
        with os.fdopen(fd, 'rb') as f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode):
                return self._gone()
            size = st.st_size
            rng = parse_range(self.headers.get('Range'), size)
            if rng == 'unsatisfiable':
                self.send_response(416)
                self.send_header('Content-Range', f'bytes */{size}')
                self.send_header('Content-Length', '0')
                self.send_header('Cache-Control', 'no-store')
                security_headers(self)
                self.end_headers()
                return
            start, end = rng if rng else (0, size - 1)
            length = end - start + 1 if size > 0 else 0
            self.send_response(206 if rng else 200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Accept-Ranges', 'bytes')
            self.send_header('Content-Length', str(length))
            if rng:
                self.send_header('Content-Range', f'bytes {start}-{end}/{size}')
            self.send_header('Content-Disposition', 'attachment; filename="sealed.pseal"')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Security-Policy', SANDBOX_CSP)
            self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
            security_headers(self)
            self.end_headers()
            if self.command == 'HEAD' or length == 0:
                return
            owner = self._is_owner()
            who = client_ip(self)
            credit = getattr(self, 'transferred', None)
            f.seek(start)
            pos, remaining = start, length
            while remaining > 0:
                chunk = f.read(min(CHUNK, remaining))
                if not chunk:
                    break
                try:
                    self.wfile.write(chunk)
                except (BrokenPipeError, ConnectionResetError):
                    self.close_connection = True
                    return
                if credit:
                    credit(len(chunk))
                if self.burner is not None and not owner:
                    self.burner.served(who, pos, pos + len(chunk))
                pos += len(chunk)
                remaining -= len(chunk)

    def _is_owner(self):
        if not self.devices:
            return False
        try:
            return porch_auth.request_is_owner(self, self.devices)
        except Exception:  # noqa: BLE001
            return False


def make_handler(path, name='seal', state_dir=None, devices=None, owned=False, grace=GRACE,
                 closer=None):
    """A SealHandler subclass for one sealed file. state_dir=None: no door
    state (tests count completions on the Burner only)."""
    real = os.path.realpath(path)
    info = porch_seal.info(real)            # SealError if it is not a v1 file
    state_path = door_state.state_path(name, state_dir) if state_dir else None

    def shred():
        # Burned: the launch recipe (lib/door_recipe.py) must never reopen it.
        if state_dir:
            door_state.record_close(name, 'burned')
        if owned:
            try:
                os.unlink(real)
            except OSError:
                pass

    if closer is None and state_dir:
        def closer():
            door_state.stop_door(name, state_dir, 'burned')
    burner = Burner(info['ciphertext_size'], state_path=state_path, closer=closer,
                    on_exhausted=shred, grace=grace)
    return type('BoundSealHandler', (SealHandler,), {
        'file_path': real, 'name': name, 'info': info, 'devices': devices,
        'burner': burner, 'state_path': state_path,
    })


def main(argv=None):
    p = argparse.ArgumentParser(description='Sealed-share door (ciphertext only)')
    p.add_argument('--port', type=int, required=True)
    p.add_argument('--file', required=True)
    p.add_argument('--name', default='seal')
    p.add_argument('--state-dir', default=None, help='door state dir (counts opens, burn)')
    p.add_argument('--devices', default=None, help='devices.json: the owner is never counted')
    p.add_argument('--owned-file', action='store_true', help='delete the file when the limit is reached')
    p.add_argument('--grace', type=float, default=GRACE)
    p.add_argument('--bind', default='127.0.0.1')
    p.add_argument('--max-connections', type=int, default=None)
    args = p.parse_args(argv)
    try:
        handler = make_handler(args.file, args.name, args.state_dir, args.devices,
                               args.owned_file, args.grace)
    except (OSError, ValueError) as e:
        sys.stderr.write(f"[sealserver] {e}\n")
        return 2
    server = make_server(handler, args.port, args.bind, tag='sealserver',
                         max_connections=args.max_connections)
    sys.stderr.write(f"[sealserver] Listening on :{args.port}, "
                     f"{handler.info['mode']}-mode seal of {handler.info['plaintext_size']} bytes\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
    return 0


if __name__ == '__main__':
    sys.exit(main())

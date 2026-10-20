#!/usr/bin/env python3

"""File drop server (used by bin/drop).

Anyone the owner sends the link to can ADD a file. Only the owner — a browser
whose porch_host cookie (or, during the migration, legacy cush_auth cookie)
lib/porch_auth.py accepts as a live admin device in data/devices.json (same
rule as bin/media and bin/music) — can list the drop
or download from it. A guest's page only shows what that guest just sent.

Because adding is open to everyone, every other control has to hold:

  * Uploads stream to disk with the per-file cap enforced *during* the write,
    and every byte is reserved against a shared per-drop Quota (total bytes,
    file count, free-disk floor) under one lock, so concurrent uploads can't
    jointly overshoot it. Concurrent uploads are capped overall and per client.
  * The stored name is derived here, never taken from the client, and the
    final placement is an atomic no-clobber link. Every lookup re-checks for
    symlinks and containment.
  * Files go back out as `attachment` + `application/octet-stream` + nosniff,
    so an uploaded .html/.svg can never execute on this origin.
  * POST /upload requires a same-origin Origin/Referer, so a random web page
    can't push files through a visitor's browser.
  * /tus/ (resumable uploads, lib/porch_tus.py; the page's first choice) has
    the same gates: same-origin on every write, an upload slot per request
    that carries bytes, the same caps and blocklist. Partials live in
    .tus/ and never show up in the listing.
  * Binds 127.0.0.1 by default (frpc is the only intended client); bounded
    connections and transfer-rate deadlines keep slow clients from pinning
    threads. Partial uploads are removed on SIGTERM and swept on startup.
"""

import argparse
import html
import json
import os
import secrets
import sys
import urllib.parse
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import porch_auth  # noqa: E402  (the one owner check: porch_host + legacy cush_auth)
import porch_tus  # noqa: E402  (resumable uploads at /tus/)
from porch_http import (  # noqa: E402  (shared HTTP core)
    DEFAULT_MAX_CONNECTIONS, DEFAULT_MIN_FREE_MB, HardenedHandlerMixin,
    MultipartError, MultipartStreamer, Quota, UploadRejected, UploadSlots,
    client_ip, content_length, drop_tmp, human_size, install_sigterm_cleanup,
    make_server, multipart_boundary, new_tmp, place_unique, safe_child,
    same_origin, security_headers, stream_file, sweep_stale_parts,
    csp_nonce, porch_css_tag, porch_mark, porch_style_src, serve_asset,
)
from porch_http import sanitize_filename as _sanitize_filename  # noqa: E402
from porch_http import BoundedThreadingHTTPServer  # noqa: E402,F401  (re-exported)


MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024  # 2GB — raised to accept large manual zips
MAX_FILES = 5000              # per-drop file count ceiling
DEFAULT_MAX_TOTAL_MB = 20 * 1024  # per-drop total; --max-total-mb overrides
MAX_NAME = 120                # chars of the client's filename we keep

# Denylist, not an allowlist: a drop is supposed to take arbitrary files, so
# this only exists to stop a friend double-clicking something nasty out of the
# download folder. It is not a security boundary — everything served from
# /files/ goes out as an opaque attachment, which is the actual control.
BLOCKED_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.sh', '.com', '.scr', '.pif', '.msi',
    '.ps1', '.psm1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.cpl',
    '.dll', '.sys', '.hta', '.lnk', '.scf', '.reg', '.msc', '.jar',
    '.msp', '.gadget', '.appref-ms', '.inf', '.chm',
}


def sanitize_filename(name):
    """Reduce a client-supplied filename to something that can only be a file
    (porch_http.sanitize_filename), keeping at most MAX_NAME characters."""
    return _sanitize_filename(name, MAX_NAME)


def name_candidates(name):
    """Names to try for an upload, in order: as-is, counter, then random.

    place_unique() claims the first free one atomically, so two simultaneous
    uploads of the same filename can't both win or spin here forever.
    """
    yield name
    stem, suffix = os.path.splitext(name)
    for counter in range(1, 50):
        yield f"{stem}_{counter}{suffix}"
    for _ in range(16):
        yield f"{stem}_{secrets.token_hex(6)}{suffix}"


UPLOAD_HTML = r"""<!DOCTYPE html>
<html lang="en" data-app="drop">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Send files</title>
__PORCH_CSS__
<style nonce="__NONCE__">
.dropzone input{position:absolute;inset:auto auto 0 0;width:1px;height:1px;opacity:0;overflow:hidden}
.dropzone:has(:focus-visible){outline:2px solid var(--accent);outline-offset:2px}
.photo-pick{position:relative;gap:10px;margin-top:-8px}
.photo-pick input{position:absolute;inset:auto auto 0 0;width:1px;height:1px;opacity:0;overflow:hidden}
.photo-pick:has(:focus-visible){outline:2px solid var(--accent);outline-offset:2px}
.photo-pick svg{color:var(--accent-ink);flex:none}
.progress-wrap{display:none;flex-direction:column;gap:8px}
.progress-wrap.active{display:flex}
.progress-text{font-size:13px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.error-msg:empty{display:none}
.retry-wrap{display:flex;justify-content:center}
.file-list:empty{display:none}
.file-size{font-size:12px;color:var(--muted);white-space:nowrap}
.file-ok{color:var(--ok);display:inline-flex}
.list-label:empty{display:none}
</style>
</head>
<body>
<main class="p-shell p-shell--narrow">
  <header class="p-head">
    <div class="p-kicker">__MARK__<span id="subtitle">someone left the door open for you</span></div>
    <h1 class="p-title">Send files</h1>
    <p class="p-lede" id="lede">Only the person who sent you this link can see what you drop here.</p>
  </header>
  <!-- A <label> around a real file input: tapping anywhere on it is a native
       activation, which is what iOS Safari needs to offer Photo Library / Take
       Photo / Choose File. No JS forwards clicks to the input. -->
  <label class="p-drop dropzone" id="dropzone" for="fileInput">
    <svg class="p-drop-icon" width="40" height="40" viewBox="0 0 40 40" fill="none" aria-hidden="true"><path d="M20 26 V8 M12 15 L20 7 L28 15" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/><path d="M7 25 V32 H33 V25" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
    <div class="p-drop-title">Choose files</div>
    <div class="p-drop-hint" id="dropHint">or drop them here</div>
    <input type="file" id="fileInput" multiple aria-describedby="dropHint">
  </label>
  <!-- Android Chrome answers an input that accepts anything with a generic
       Camera / Camcorder / Files chooser; only an image/video-only input opens
       the system photo picker (the gallery). iOS offers Photo Library either way. -->
  <label class="p-btn p-btn--ghost p-btn--block p-btn--lg photo-pick" for="photoInput">
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" aria-hidden="true"><rect x="2.5" y="4" width="15" height="12" rx="2.5" stroke="currentColor" stroke-width="1.8"/><circle cx="7.5" cy="8.5" r="1.6" fill="currentColor"/><path d="M3 14.5 L8 10.5 L11.5 13 L14 11 L17.5 14" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round" stroke-linecap="round"/></svg>
    Photos &amp; videos
    <input type="file" id="photoInput" accept="image/*,video/*" multiple>
  </label>
  <div class="p-card p-card--tight progress-wrap" id="progressWrap">
    <div class="progress-text" id="progressText">0%</div>
    <div class="p-progress"><span class="progress-fill" id="progressFill"></span></div>
  </div>
  <div class="p-notice error-msg" id="errorMsg" role="status" aria-live="polite"></div>
  <div class="retry-wrap" id="retryWrap" hidden>
    <button type="button" class="p-btn p-btn--ghost p-btn--sm retry-btn" id="retryBtn">Retry failed uploads</button>
  </div>
  <div class="p-section-label list-label" id="listLabel"></div>
  <div class="p-list file-list" id="fileList"></div>
  <footer class="p-foot">sent through porch</footer>
</main>
<!-- Server-rendered config: a JSON block (never executed) with every '<'
     escaped server-side, so no value can close the tag. The blocklist comes
     from the server's own BLOCKED_EXTENSIONS, so the two can't drift. -->
<script type="application/json" id="cfg">__CFG_JSON__</script>
<script nonce="__NONCE__">
"use strict";
const CFG = JSON.parse(document.getElementById('cfg').textContent);
const OWNER = CFG.owner === true;   // the server re-checks /files on every request
const BLOCKED = new Set(CFG.blocked);
const dz = document.getElementById('dropzone');
const fi = document.getElementById('fileInput');
const pi = document.getElementById('photoInput');
const pw = document.getElementById('progressWrap');
const pf = document.getElementById('progressFill');
const pt = document.getElementById('progressText');
const em = document.getElementById('errorMsg');
const fl = document.getElementById('fileList');
const listLabel = document.getElementById('listLabel');
const retryWrap = document.getElementById('retryWrap');

function getExt(name){
  const i = name.lastIndexOf('.');
  return i > 0 ? name.slice(i).toLowerCase() : '';
}

function humanSize(b){
  if(b<1024) return b+' B';
  if(b<1048576) return (b/1024).toFixed(1)+' KB';
  if(b<1073741824) return (b/1048576).toFixed(1)+' MB';
  return (b/1073741824).toFixed(1)+' GB';
}

function showError(msg, ok){
  em.textContent=msg;
  em.className='p-notice error-msg '+(ok ? 'p-notice--ok' : 'p-notice--error');
  setTimeout(()=>{if(em.textContent===msg)em.textContent='';},8000);
}

/* One request per file, in order: each file gets its own progress, its own
   error message, and a retry — a single bad file no longer sinks the batch. */
const queue = [];
let failed = [];
let running = false, batchTotal = 0, batchIndex = 0, batchOk = 0;
const mine = [];   // this visitor's own uploads (all a guest ever sees)

function upload(fileList){
  em.textContent='';
  for(const f of fileList){
    const ext = getExt(f.name);
    if(BLOCKED.has(ext)){ failed.push({file:f, error:'file type '+ext+' is not allowed', retry:false}); continue; }
    if(f.size > CFG.maxFile){ failed.push({file:f, error:'larger than the '+humanSize(CFG.maxFile)+' per-file limit', retry:false}); continue; }
    queue.push(f); batchTotal++;
  }
  syncFailed();
  pump();
}

__TUS_JS__
function showProgress(f, sent, total){
  const pct = total ? Math.round(sent/total*100) : 0;
  pf.style.width=pct+'%';
  pt.textContent=(batchTotal>1 ? batchIndex+' of '+batchTotal+' · ' : '')+f.name+' · '+pct+'%';
}
/* Resumable (tus) first, so a phone that locks mid-upload resumes instead
   of starting over; the one-shot multipart POST is the fallback. */
function sendOne(f){
  return PorchTus.upload(f, {endpoint:'/tus/', onProgress:(s,t)=>showProgress(f, s, t)})
    .then(res=>{
      if(res.fallback) return sendMultipart(f);
      return res.ok ? {ok:true, saved:[{name:res.name, size:res.size}]} : res;
    })
    .catch(()=>sendMultipart(f));
}
function sendMultipart(f){
  return new Promise(resolve=>{
    const fd = new FormData();
    fd.append('file', f, f.name);
    const xhr = new XMLHttpRequest();
    xhr.upload.onprogress = function(e){
      if(!e.lengthComputable) return;
      showProgress(f, e.loaded, e.total);
    };
    xhr.onload = function(){
      let r = null;
      try{ r = JSON.parse(xhr.responseText); }catch(e){}
      const saved = r && Array.isArray(r.files) ? r.files : [];
      if(xhr.status >= 200 && xhr.status < 300 && saved.length){ resolve({ok:true, saved}); return; }
      const rej = r && Array.isArray(r.rejected) && r.rejected.length ? r.rejected[0].reason : null;
      resolve({ok:false, error: rej || (r && r.message) || ('HTTP '+xhr.status),
               retry: xhr.status === 503 || xhr.status >= 500 || xhr.status === 0});
    };
    xhr.onerror = function(){ resolve({ok:false, error:'network error', retry:true}); };
    xhr.open('POST','/upload');
    xhr.send(fd);
  });
}

function pump(){
  if(running) return;
  const f = queue.shift();
  if(!f){
    pw.classList.remove('active');
    if(batchTotal){
      const bad = batchTotal - batchOk;
      if(bad) showError(bad+' of '+batchTotal+' upload(s) failed');
      else showError('Sent '+batchOk+' file'+(batchOk===1?'':'s')+'.', true);
    }
    batchTotal = batchIndex = batchOk = 0;
    return;
  }
  running = true; batchIndex++;
  pw.classList.add('active'); pf.style.width='0%';
  pt.textContent=(batchTotal>1 ? batchIndex+' of '+batchTotal+' · ' : '')+f.name;
  sendOne(f).then(res=>{
    running = false;
    if(res.ok){
      batchOk++;
      for(const s of res.saved) mine.unshift({name:s.name, size:s.size});
    }else{
      failed.push({file:f, error:res.error, retry:res.retry !== false});
    }
    syncFailed();
    refreshFiles();
    pump();
  });
}

function syncFailed(){
  const retryable = failed.filter(x=>x.retry);
  retryWrap.hidden = retryable.length === 0;
  if(failed.length){
    const last = failed[failed.length-1];
    showError(last.file.name+': '+last.error);
  }
}
document.getElementById('retryBtn').addEventListener('click', ()=>{
  const again = failed.filter(x=>x.retry).map(x=>x.file);
  failed = failed.filter(x=>!x.retry);
  for(const f of again){ queue.push(f); batchTotal++; }
  syncFailed();
  pump();
});

function row(name, size, link){
  const r = document.createElement('div');
  r.className='p-row file-row';
  // textContent, not innerHTML: a file dropped into the directory out of
  // band is not name-sanitized, and a name must never be parsed as markup.
  const main = document.createElement('div'); main.className='p-row-main';
  const nm = document.createElement('div'); nm.className='p-row-name file-name'; nm.textContent=name; nm.title=name;
  const sz = document.createElement('div'); sz.className='p-row-meta file-size'; sz.textContent=humanSize(size)+(link?'':' · sent');
  main.appendChild(nm); main.appendChild(sz); r.appendChild(main);
  if(link){
    const dl = document.createElement('a'); dl.className='p-btn p-btn--ghost p-btn--sm file-dl';
    dl.href='/files/'+encodeURIComponent(name); dl.download=''; dl.textContent='Download';
    dl.setAttribute('aria-label','Download '+name);
    r.appendChild(dl);
  }else{
    const ok = document.createElementNS('http://www.w3.org/2000/svg','svg');
    ok.setAttribute('class','file-ok'); ok.setAttribute('width','20'); ok.setAttribute('height','20');
    ok.setAttribute('viewBox','0 0 20 20'); ok.setAttribute('role','img'); ok.setAttribute('aria-label','Uploaded');
    const pth = document.createElementNS('http://www.w3.org/2000/svg','path');
    pth.setAttribute('d','M4 10.5 L8 14 L16 6'); pth.setAttribute('fill','none'); pth.setAttribute('stroke','currentColor');
    pth.setAttribute('stroke-width','2'); pth.setAttribute('stroke-linecap','round'); pth.setAttribute('stroke-linejoin','round');
    ok.appendChild(pth); r.appendChild(ok);
  }
  return r;
}

function refreshFiles(){
  if(!OWNER){
    // Guests can't list the drop (the server refuses /files for them); they
    // only see what they themselves sent from this page.
    listLabel.textContent = mine.length ? 'Your uploads' : '';
    fl.replaceChildren(...mine.map(f=>row(f.name, f.size, false)));
    return;
  }
  fetch('/files', {credentials:'same-origin'}).then(r=>{
    if(!r.ok) throw new Error('HTTP '+r.status);
    return r.json();
  }).then(files=>{
    files.sort((a,b)=>b.modified-a.modified);
    listLabel.textContent = files.length ? files.length + ' file' + (files.length===1?'':'s') + ' in this drop' : 'Nothing dropped yet';
    fl.replaceChildren(...files.map(f=>row(f.name, f.size, true)));
  }).catch(e=>showError('Could not load the file list ('+e.message+')'));
}

fi.addEventListener('change', ()=>{if(fi.files.length)upload(fi.files);fi.value='';});
pi.addEventListener('change', ()=>{if(pi.files.length)upload(pi.files);pi.value='';});
dz.addEventListener('dragover', e=>{e.preventDefault();dz.classList.add('dragover');});
dz.addEventListener('dragleave', ()=>dz.classList.remove('dragover'));
dz.addEventListener('drop', e=>{e.preventDefault();dz.classList.remove('dragover');if(e.dataTransfer.files.length)upload(e.dataTransfer.files);});

document.getElementById('dropHint').textContent = 'or drop them here · up to '+humanSize(CFG.maxFile)+' each · executables are blocked';
if(OWNER){
  document.getElementById('subtitle').textContent = 'your drop';
  document.getElementById('lede').textContent = 'Everything people send lands here. Only you can see and download it.';
}
refreshFiles();
</script>
__SIGNIN__
</body>
</html>"""


class DropHandler(HardenedHandlerMixin, BaseHTTPRequestHandler):

    protocol_version = 'HTTP/1.1'

    upload_dir = Path('.')
    devices_path = ''           # cush-auth registry; owners may list + download
    max_file = MAX_FILE_SIZE
    max_total = DEFAULT_MAX_TOTAL_MB * 1024 * 1024
    max_files = MAX_FILES
    min_free = DEFAULT_MIN_FREE_MB * 1024 * 1024
    upload_slots = UploadSlots(total=4, per_ip=2)

    _quota = None
    _quota_lock = threading.Lock()
    _tus = None
    _tus_lock = threading.Lock()

    @classmethod
    def quota(cls):
        """The drop's shared Quota, created on first use (one per handler class).
        Unfinished resumable uploads count as if they had landed."""
        with cls._quota_lock:
            q = cls.__dict__.get('_quota')
            if q is None:
                def scan():
                    used, files = drop_usage(cls.upload_dir)
                    p_used, p_files = cls.tus().pending_usage()
                    return used + p_used, files + p_files
                q = Quota(cls.upload_dir, scan,
                          cls.max_total, cls.max_files, cls.min_free,
                          label='drop', item_word='files')
                cls._quota = q
            return q

    @classmethod
    def tus(cls):
        """The drop's resumable-upload endpoint (/tus/), one per handler class."""
        with cls._tus_lock:
            t = cls.__dict__.get('_tus')
            if t is None:
                t = porch_tus.TusServer(
                    cls.upload_dir, quota=cls.quota, max_size=cls.max_file,
                    finalize=cls._tus_finalize, on_create=cls._tus_on_create,
                    tag='dropserver')
                cls._tus = t
            return t

    @staticmethod
    def _tus_on_create(meta, length, handler):
        """The blocklist, decided from the filename before any byte is sent."""
        ext = _blocked_ext(meta.get('filename', ''))
        return f'file type {ext} is not allowed' if ext else None

    @classmethod
    def _tus_finalize(cls, part, up, handler):
        filename = up.metadata.get('filename') or 'upload'
        ext = _blocked_ext(filename)
        if ext:
            raise porch_tus.TusRejected(f'file type {ext} is not allowed')
        return place_unique(part, cls.upload_dir, name_candidates(sanitize_filename(filename)))

    def log_message(self, format, *args):
        method = args[0] if args else ''
        if isinstance(method, str) and method.startswith('GET'):
            return
        sys.stderr.write(f"[dropserver] {self.address_string()} - {format % args}\n")

    def _security_headers(self):
        """nosniff (an application/octet-stream file is never re-sniffed as
        HTML), no-referrer, DENY framing: porch_http.security_headers."""
        security_headers(self)

    def send_json(self, data, status=200, headers=None):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if self.close_connection:
            # We are answering without draining the request body (an upload we
            # refused), so the connection can't be reused — say so explicitly.
            self.send_header('Connection', 'close')
        self._security_headers()
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def _is_owner(self):
        """True iff this request may list and download the drop: porch_auth
        accepts its porch_host cookie for this host (or, during the
        migration, a legacy cush_auth cookie) as a live admin device.
        No registry => nobody.
        """
        return porch_auth.request_is_owner(self, self.devices_path)

    def _signin_html(self):
        """The small "Owner? Sign in" link for a visitor who is not the owner,
        pointing at this host's /__porch/start handoff. '' when the visitor
        is the owner or no owner registry is configured."""
        url = porch_auth.signin_url(self, self.devices_path)
        if not url:
            return ''
        return (f'<a class="porch-signin" href="{html.escape(url, quote=True)}" '
                'rel="nofollow">Owner? Sign in</a>')

    def _same_origin(self):
        """CSRF check for /upload (porch_http.same_origin): the drop has no
        login, so without it any page a visitor opens could POST files
        through their browser into this directory."""
        return same_origin(self)

    def _safe_target(self, raw):
        """Sanitized name + symlink-refusing containment check in upload_dir."""
        return safe_child(self.upload_dir, raw, sanitize_filename)

    def _serve_page(self):
        owner = self._is_owner()
        cfg = {
            'owner': owner,
            'blocked': sorted(BLOCKED_EXTENSIONS),
            'maxFile': self.max_file,
        }
        cfg_json = json.dumps(cfg).replace('<', '\\u003c')
        nonce = csp_nonce()
        body = (UPLOAD_HTML.replace('__TUS_JS__', porch_tus.TUS_CLIENT_JS)
                .replace('__PORCH_CSS__', porch_css_tag())
                .replace('__MARK__', porch_mark(16))
                .replace('__NONCE__', nonce)
                .replace('__CFG_JSON__', cfg_json)
                .replace('__SIGNIN__', self._signin_html())).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        # The page loads nothing but porch.css and its fonts from this origin
        # plus its own nonced inline style/script; 'none' everywhere else
        # kills base-tag and clickjacking tricks outright.
        self.send_header('Content-Security-Policy', (
            f"default-src 'none'; {porch_style_src(nonce)}; "
            f"script-src 'nonce-{nonce}'; connect-src 'self'; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        ))
        self._security_headers()
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

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
        self.close_connection = True
        self.send_json({'status': 'error', 'message': 'Not found'}, 404)

    def do_DELETE(self):
        if self._tus_path():
            self._tus_request()
            return
        self.send_json({'status': 'error', 'message': 'Not found'}, 404)

    def _tus_path(self):
        return self.tus().owns(urllib.parse.urlparse(self.path).path)

    def _tus_request(self):
        """/tus/: the same gates as /upload, in the same order: same-origin
        for writes, then an upload slot for each request carrying bytes."""
        method = self.command
        if method in ('POST', 'PATCH', 'DELETE') and not self._same_origin():
            self.close_connection = True
            self.send_json({'status': 'error',
                            'message': 'Cross-origin request refused'}, 403)
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
            self.tus().handle(self)
        except Exception as e:
            sys.stderr.write(f"[dropserver] tus {method} failed: {e}\n")
            self.close_connection = True
            try:
                self.send_json({'status': 'error', 'message': 'Server error'}, 500)
            except Exception:
                pass
        finally:
            if ip is not None:
                self.upload_slots.release(ip)

    def do_GET(self):
        if serve_asset(self, head=self.command == 'HEAD'):
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip('/')

        if path == '' or path == '/':
            self._serve_page()
            return

        if path == '/files' or path.startswith('/files/'):
            # Listing and download are the owner's. A guest's only power is to
            # add a file; it can't see or fetch anyone else's (or its own,
            # after the fact).
            if not self._is_owner():
                self.send_json({'status': 'error',
                                'message': 'Only the drop owner can list or download files'},
                               403)
                return

        if path == '/files':
            self.send_json(list_drop(self.upload_dir))
            return

        if path.startswith('/files/'):
            raw = urllib.parse.unquote(path[len('/files/'):])
            target, name = self._safe_target(raw)
            if target is None or not target.is_file():
                self.send_json({'status': 'error', 'message': 'Not found'}, 404)
                return
            try:
                size = target.stat().st_size
            except OSError:
                self.send_json({'status': 'error', 'message': 'Not found'}, 404)
                return
            # Always opaque, always an attachment, no ranges: an uploaded .html
            # or .svg must never render on this origin. `name` is
            # [a-zA-Z0-9._-] only (sanitize_filename): header-safe.
            stream_file(self, target, size, 'application/octet-stream', 'attachment',
                        name, cache='private, no-store', ranges=False)
            return

        self.send_json({'status': 'error', 'message': 'Not found'}, 404)

    def do_POST(self):
        if self._tus_path():
            self._tus_request()
            return
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.rstrip('/') != '/upload':
            self.send_json({'status': 'error', 'message': 'Not found'}, 404)
            return

        # Checked before anything reads the body, so a cross-site POST costs
        # us nothing.
        if not self._same_origin():
            self.close_connection = True
            self.send_json({'status': 'error',
                            'message': 'Cross-origin request refused'}, 403)
            return

        ip = client_ip(self)
        if not self.upload_slots.acquire(ip):
            self.close_connection = True
            self.send_json({'status': 'error',
                            'message': 'Too many uploads in progress, try again shortly'},
                           503, {'Retry-After': '5'})
            return
        try:
            self._handle_upload()
        except MultipartError as e:
            sys.stderr.write(f"[dropserver] malformed upload: {e}\n")
            self.close_connection = True
            try:
                self.send_json({'status': 'error', 'message': 'Malformed upload'}, 400)
            except Exception:
                pass
        except Exception as e:
            sys.stderr.write(f"[dropserver] upload failed: {e}\n")
            self.close_connection = True
            try:
                # Generic text only: internal exception strings carry filesystem
                # paths, and this endpoint answers anonymous callers.
                self.send_json({'status': 'error', 'message': 'Server error'}, 500)
            except Exception:
                pass
        finally:
            self.upload_slots.release(ip)

    def _handle_upload(self):
        boundary, bad = multipart_boundary(self.headers.get('Content-Type', ''))
        if bad:
            self.send_json({'status': 'error', 'message': bad[0]}, bad[1])
            return

        length = content_length(self)
        if length <= 0:
            # No Content-Length (e.g. chunked) — BaseHTTPRequestHandler does
            # not de-chunk, and reading an unbounded body is precisely the DoS
            # we are avoiding, so refuse it.
            self.send_json({'status': 'error', 'message': 'Content-Length required'}, 411)
            return
        # First cap: refuse an oversized body before reading a single byte.
        # A batch may hold several files, so the request ceiling is a small
        # multiple of the per-file cap (the page sends one file per request).
        max_request = min(self.max_file * 4, self.max_total) + 64 * 1024
        if length > max_request:
            self.close_connection = True
            self.send_json({'status': 'error',
                            'message': f'Upload request is larger than the '
                                       f'{human_size(max_request)} request limit'}, 413)
            return

        quota = self.quota()
        streamer = MultipartStreamer(self.rfile, boundary, length, self.transferred)
        saved, rejected = [], []
        aborted = None

        try:
            for filename, chunks in streamer.parts():
                if not filename:
                    # Non-file field: drain it so the parser lands on the next part.
                    for _ in chunks:
                        pass
                    continue
                result = self._spool_part(filename, chunks, quota)
                if result.get('ok'):
                    saved.append({'name': result['name'], 'size': result['size']})
                    sys.stderr.write(
                        f"[dropserver] Saved: {result['name']} "
                        f"({human_size(result['size'])}) from {client_ip(self)}\n")
                else:
                    rejected.append({'name': sanitize_filename(filename),
                                     'reason': result['reason']})
        except UploadRejected as e:
            # Stop reading the body entirely and hang up after replying.
            aborted = e
            self.close_connection = True
            rejected.append({'name': 'upload', 'reason': e.reason})

        if saved:
            status = aborted.status if aborted else 200
            self.send_json({'status': 'ok', 'files': saved, 'rejected': rejected}, status)
            return
        if not rejected:
            self.send_json({'status': 'error', 'message': 'No files found in upload'}, 400)
            return
        reason = rejected[0]['reason']
        status = aborted.status if aborted else (
            413 if ('limit' in reason or 'full' in reason) else 400)
        self.send_json({'status': 'error', 'message': reason,
                        'files': [], 'rejected': rejected}, status)

    def _spool_part(self, filename, chunks, quota):
        """Stream one uploaded part to disk with every cap enforced as it arrives.

        Returns {'ok': True, 'name', 'size'} or {'ok': False, 'reason'}. Bytes
        are reserved against the drop's shared Quota chunk by chunk, so
        concurrent uploads can't jointly overshoot the total or the free-space
        floor. A hard limit raises UploadRejected and abandons the request.
        """
        ext = _blocked_ext(filename)
        if ext:
            for _ in chunks:        # keep the parser in sync; nothing is stored
                pass
            return {'ok': False, 'reason': f'file type {ext} is not allowed'}

        refusal = quota.begin()
        if refusal:
            raise UploadRejected(refusal)
        # Everything after begin() runs inside the try, so every begin() has
        # its end(): new_tmp() raising used to leak the item slot for good.
        tmp = None
        written = 0                 # == bytes reserved against the quota
        kept = False
        try:
            tmp = new_tmp(self.upload_dir)
            with open(tmp, 'wb') as out:
                for chunk in chunks:
                    # Second cap, enforced mid-stream: a lying Content-Length
                    # buys no more disk than the per-file limit allows.
                    if written + len(chunk) > self.max_file:
                        raise UploadRejected(
                            f'over the {human_size(self.max_file)} per-file limit')
                    refusal = quota.add(len(chunk))
                    if refusal:
                        raise UploadRejected(refusal)
                    written += len(chunk)
                    out.write(chunk)
            if written == 0:
                return {'ok': False, 'reason': 'empty file'}

            name = place_unique(tmp, self.upload_dir,
                                name_candidates(sanitize_filename(filename)))
            kept = True
            return {'ok': True, 'name': name, 'size': written}
        finally:
            quota.end(written, kept)
            if not kept and tmp is not None:
                drop_tmp(tmp)


def _blocked_ext(filename):
    """The client filename's extension when it is on the blocklist, else ''."""
    base = str(filename).replace('\\', '/').split('/')[-1]
    # Windows drops trailing dots and spaces, so 'evil.exe.' saves as evil.exe.
    ext = os.path.splitext(base.rstrip('. '))[1].lower()
    return ext if ext in BLOCKED_EXTENSIONS else ''


def drop_usage(directory):
    """(bytes, files) currently stored in the drop (partials excluded)."""
    total = count = 0
    for f in list_drop(directory):
        total += f['size']
        count += 1
    return total, count


def list_drop(directory):
    files = []
    try:
        entries = list(directory.iterdir())
    except OSError:
        entries = []
    for entry in entries:
        # is_file() follows symlinks; a link planted here would be listed even
        # though _safe_target() refuses to serve it. Skip links outright so the
        # listing only names real files we own.
        if entry.is_symlink() or not entry.is_file():
            continue
        if entry.name.endswith('.part') or entry.name.startswith('.'):
            continue
        try:
            st = entry.stat()
        except OSError:
            continue
        files.append({'name': entry.name, 'size': st.st_size, 'modified': st.st_mtime})
    return files


def main():
    parser = argparse.ArgumentParser(description='File drop server')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--dir', type=str, required=True)
    # Loopback by default: frpc reaches us on 127.0.0.1, and nothing else
    # on the LAN should be able to talk to the drop around the tunnel.
    parser.add_argument('--bind', type=str, default='127.0.0.1')
    parser.add_argument('--devices', type=str, default='',
                        help='path to cush-auth devices.json; enrolled owner browsers '
                             'may list and download (nobody can without it)')
    parser.add_argument('--max-file-mb', type=int, default=MAX_FILE_SIZE // (1024 * 1024))
    parser.add_argument('--max-total-mb', type=int, default=DEFAULT_MAX_TOTAL_MB,
                        help='total bytes this drop may hold')
    parser.add_argument('--max-files', type=int, default=MAX_FILES)
    parser.add_argument('--min-free-mb', type=int, default=DEFAULT_MIN_FREE_MB,
                        help='refuse uploads that would leave less free disk than this')
    parser.add_argument('--max-uploads', type=int, default=4,
                        help='concurrent uploads (each client address gets at most 2)')
    parser.add_argument('--max-connections', type=int, default=DEFAULT_MAX_CONNECTIONS)
    args = parser.parse_args()

    upload_dir = Path(args.dir).resolve()
    upload_dir.mkdir(parents=True, exist_ok=True)
    DropHandler.upload_dir = upload_dir
    DropHandler.devices_path = os.path.abspath(args.devices) if args.devices else ''
    DropHandler.max_file = max(1, args.max_file_mb) * 1024 * 1024
    DropHandler.max_total = max(1, args.max_total_mb) * 1024 * 1024
    DropHandler.max_files = max(1, args.max_files)
    DropHandler.min_free = max(0, args.min_free_mb) * 1024 * 1024
    DropHandler.upload_slots = UploadSlots(total=max(1, args.max_uploads),
                                           per_ip=min(2, max(1, args.max_uploads)))

    swept = sweep_stale_parts(upload_dir)
    if swept:
        sys.stderr.write(f"[dropserver] removed {swept} stale partial upload(s)\n")
    # Reads unfinished resumable uploads back in (sweeping expired ones).
    pending = DropHandler.tus().pending_count()
    if pending:
        sys.stderr.write(f"[dropserver] {pending} resumable upload(s) waiting to be resumed\n")
    install_sigterm_cleanup('dropserver')

    server = make_server(DropHandler, args.port, args.bind, tag='dropserver',
                         max_connections=max(4, args.max_connections))
    owner = 'owner list/download via cush-auth' if args.devices else \
        'upload only (no --devices: nobody can list)'
    sys.stderr.write(f"[dropserver] Listening on {args.bind}:{args.port}, uploading to "
                     f"{upload_dir} [{owner}; cap {human_size(DropHandler.max_total)}]\n")
    try:
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        sys.stderr.write("\n[dropserver] Shutting down.\n")
    finally:
        server.server_close()


if __name__ == '__main__':
    main()

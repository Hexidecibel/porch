#!/usr/bin/env python3

"""Bidirectional text exchange (used by bin/exchange).

Two one-shot modes behind one tunnel URL:

  * send    -- show text the owner already has, plus /raw.
  * receive -- take one POST of text and write it to --output, then stop.

Both are public by design: the owner mails the link to whoever should read or
fill it. That is the contract, so there is no login — which is why the receive
side needs the rest to hold:

  * /submit caps the body *before* reading it. The old code did
    `self.rfile.read(Content-Length)` with no ceiling at all, so an anonymous
    POST declaring 4GB made the box allocate 4GB.
  * /submit requires a same-origin Origin/Referer. Without it, any page the
    owner visits could POST first and win the one-shot with attacker text —
    the owner then reads that as if it came from their correspondent.
  * Everything is served with nosniff and a lockdown CSP; the received text is
    never echoed back into a page.
"""

import argparse
import html
import json
import re
import shutil
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rundir  # noqa: E402  (atomic 0600 writes that never follow a symlink)
from porch_http import (  # noqa: E402  (shared HTTP core)
    content_length, csp_nonce, make_server, porch_css_tag, porch_mark, porch_style_src,
    same_origin, security_headers, serve_asset,
)

# The received text is a message a person types, not a file upload. 8MB is
# already absurdly generous for that, and it is what stops an anonymous POST
# from turning Content-Length into an allocation request.
MAX_SUBMIT_BODY = 8 * 1024 * 1024


# Both pages are built once at startup; NONCE_MARK is swapped for a fresh
# nonce on every response. It contains '<', which html.escape() turns into
# &lt;, so no escaped content or name can ever contain the marker.
NONCE_MARK = '<N>'

_HEAD = r"""<!DOCTYPE html>
<html lang="en" data-app="exchange">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Exchange</title>
__PORCH_CSS__
<style nonce="<N>">
.text-wrap{padding:0;overflow:hidden}
.toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 12px 10px 16px;
  border-bottom:1px solid var(--line)}
.toolbar .meta{font-size:13px;color:var(--muted)}
.toolbar .acts{display:flex;gap:8px}
.toolbar button.copied{color:var(--ok);border-color:var(--ok-line)}
.text-wrap textarea{border:0;border-radius:0;background:transparent;min-height:55vh;padding:16px;
  font:400 14px/1.6 var(--font-mono);resize:vertical}
.text-wrap textarea:focus{box-shadow:none}
#content{min-height:300px;font:400 14px/1.6 var(--font-mono)}
.ex-form{display:flex;flex-direction:column;gap:16px}
.ex-form[hidden]{display:none}
.p-notice b{display:block}
.p-notice .sub{color:var(--muted);font-size:14px}
</style>
</head>
<body>
"""

SEND_HTML = (_HEAD + r"""<main class="p-shell p-shell--wide">
  <header class="p-head">
    <div class="p-kicker">__MARK__<span>some text, left on the porch for you</span></div>
    <h1 class="p-title">EXCHANGE_NAME</h1>
  </header>
  <div class="p-card text-wrap">
    <div class="toolbar">
      <span class="meta">EXCHANGE_FOOTER</span>
      <span class="acts">
        <a class="p-btn p-btn--quiet p-btn--sm" href="/raw">Raw</a>
        <button type="button" class="p-btn p-btn--sm" id="copyBtn">Copy</button>
      </span>
    </div>
    <textarea class="p-textarea" readonly aria-label="Text">EXCHANGE_CONTENT</textarea>
  </div>
  <footer class="p-foot">sent through porch</footer>
</main>
<script nonce="<N>">
function copyContent(){
  const ta = document.querySelector('textarea');
  const btn = document.getElementById('copyBtn');
  navigator.clipboard.writeText(ta.value).then(()=>{
    btn.textContent='Copied';
    btn.classList.add('copied');
    setTimeout(()=>{btn.textContent='Copy';btn.classList.remove('copied');},2000);
  }, ()=>{ ta.focus(); ta.select(); btn.textContent='Press Ctrl+C'; });
}
document.getElementById('copyBtn').addEventListener('click', copyContent);
</script>
</body>
</html>""")


RECEIVE_HTML = (_HEAD + r"""<main class="p-shell">
  <header class="p-head">
    <div class="p-kicker">__MARK__<span>EXCHANGE_NAME</span></div>
    <h1 class="p-title">Send some text</h1>
    <p class="p-lede">Paste it below and send. It goes only to whoever sent you this link, and the box takes one reply.</p>
  </header>
  <div id="status" class="p-notice p-notice--error" role="alert" hidden></div>
  <div id="form" class="ex-form">
    <label class="sr-only" for="content">Text to send</label>
    <textarea id="content" class="p-textarea" placeholder="Paste your text here"></textarea>
    <button type="button" class="p-btn p-btn--lg p-btn--block btn" id="submitBtn">Send</button>
  </div>
  <div id="done" class="p-notice p-notice--ok confirmation" role="status" hidden><div><b>Sent.</b><span class="sub">You can close this tab.</span></div></div>
  <div id="already" class="p-notice already" role="status" hidden><div><b>Already received</b><span class="sub">This link has had its reply. Nothing more is needed.</span></div></div>
  <footer class="p-foot">sent through porch</footer>
</main>
<script nonce="<N>">
function showStatus(msg){
  const st = document.getElementById('status');
  st.textContent = msg; st.hidden = !msg;
}
async function submit(){
  const btn = document.getElementById('submitBtn');
  const content = document.getElementById('content').value;
  if(!content.trim()){ showStatus('Paste something first.'); return; }
  showStatus('');
  btn.disabled = true;
  btn.textContent = 'Sending…';
  try{
    const resp = await fetch('/submit',{
      method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:'content='+encodeURIComponent(content)
    });
    let data = null;
    let rawText = '';
    try{ data = await resp.clone().json(); }catch(_){ rawText = await resp.text(); }
    if(data && data.status==='already_received'){
      document.getElementById('form').hidden = true;
      document.getElementById('already').hidden = false;
      return;
    }
    if(!resp.ok){
      const msg = (data && (data.error || data.message)) || rawText || ('HTTP '+resp.status);
      btn.disabled = false;
      btn.textContent = 'Try again';
      showStatus("Couldn't send: "+msg);
      return;
    }
    if(data && data.status==='ok'){
      document.getElementById('form').hidden = true;
      document.getElementById('done').hidden = false;
    }else{
      btn.disabled = false;
      btn.textContent = 'Try again';
      showStatus("Couldn't send: "+((data && (data.error||data.message)) || rawText || 'unknown error'));
    }
  }catch(e){
    btn.disabled = false;
    btn.textContent = 'Try again';
    showStatus("Couldn't send: "+(e && e.message ? e.message : e));
  }
}
document.getElementById('submitBtn').addEventListener('click', submit);
</script>
</body>
</html>""")

# The stylesheet link and mark are fixed per process: fill them in once, before
# any user text is substituted.
SEND_HTML = SEND_HTML.replace('__PORCH_CSS__', porch_css_tag()).replace('__MARK__', porch_mark(16))
RECEIVE_HTML = RECEIVE_HTML.replace('__PORCH_CSS__', porch_css_tag()).replace('__MARK__', porch_mark(16))


def human_size(size):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if size < 1024:
            return f"{size:.1f} {unit}" if unit != 'B' else f"{size} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


class ExchangeHandler(BaseHTTPRequestHandler):

    protocol_version = 'HTTP/1.1'
    # Bound how long a half-open or slow-loris connection can hold a thread.
    timeout = 120
    # Don't advertise the Python version to anonymous callers.
    server_version = 'cush-tools'
    sys_version = ''

    # Guards the one-shot flag: without it two simultaneous POSTs both see
    # received==False and the second one overwrites the first.
    _submit_lock = threading.Lock()

    mode = 'send'
    name = ''
    content_raw = ''
    send_html = ''
    receive_html = ''
    output_file = Path('.')
    received = False
    server_ref = None

    def log_message(self, format, *args):
        method = args[0] if args else ''
        if isinstance(method, str) and method.startswith('GET'):
            return
        sys.stderr.write(f"[exchange] {self.address_string()} - {format % args}\n")

    def _security_headers(self):
        """Headers every response carries.

        nosniff stops a browser from re-deciding that the text/plain at /raw is
        really HTML and running it on this origin.
        """
        security_headers(self)

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        if self.close_connection:
            # Answering without draining the request body — say so explicitly
            # so the leftover bytes aren't parsed as the next request.
            self.send_header('Connection', 'close')
        self._security_headers()
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def _same_origin(self):
        """CSRF check for /submit (porch_http.same_origin). The exchange URL
        is public and unauthenticated, so without this any page the owner has
        open could POST first and burn the one-shot with text of the
        attacker's choosing."""
        return same_origin(self)

    def do_GET(self):
        if serve_asset(self, head=self.command == 'HEAD'):
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip('/')

        if path == '' or path == '/':
            if ExchangeHandler.mode == 'send':
                body = ExchangeHandler.send_html.encode()
            else:
                if ExchangeHandler.received:
                    h = ExchangeHandler.receive_html
                    h = h.replace(
                        '<div id="form" class="ex-form">',
                        '<div id="form" class="ex-form" hidden>'
                    ).replace(
                        '<div id="already" class="p-notice already" role="status" hidden>',
                        '<div id="already" class="p-notice already" role="status">'
                    )
                    body = h.encode()
                else:
                    body = ExchangeHandler.receive_html.encode()
            nonce = csp_nonce()
            body = body.replace(NONCE_MARK.encode(), nonce.encode())
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            # The page loads porch.css and its fonts from this origin and nothing
            # else, plus its own nonced inline style/script; 'none' everywhere
            # else kills base-tag and clickjacking tricks outright.
            self.send_header('Content-Security-Policy', (
                f"default-src 'none'; {porch_style_src(nonce)}; "
                f"script-src 'nonce-{nonce}'; connect-src 'self'; "
                "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
            ))
            self._security_headers()
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(body)
            return

        if path == '/raw' and ExchangeHandler.mode == 'send':
            body = ExchangeHandler.content_raw.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            # The pasted text is arbitrary; nosniff + a sandbox CSP mean that
            # even if a browser were minded to treat it as markup, it executes
            # nothing on this origin.
            self.send_header('Content-Security-Policy', "default-src 'none'; sandbox")
            self._security_headers()
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(body)
            return

        self.send_response(404)
        body = b'Not found'
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self._security_headers()
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def do_POST(self):
        try:
            if ExchangeHandler.mode != 'receive':
                self.send_json({'status': 'error', 'message': 'Not found'}, 404)
                return

            parsed = urllib.parse.urlparse(self.path)
            if parsed.path.rstrip('/') != '/submit':
                self.send_json({'status': 'error', 'message': 'Not found'}, 404)
                return

            # Checked before anything reads the body, so a cross-site POST
            # costs us nothing and cannot win the one-shot.
            if not self._same_origin():
                self.close_connection = True
                self.send_json({'status': 'error',
                                'message': 'Cross-origin request refused'}, 403)
                return

            if ExchangeHandler.received:
                self.send_json({'status': 'already_received'}, 409)
                return

            length = content_length(self)
            if length < 0:
                self.close_connection = True
                self.send_json({'status': 'error', 'message': 'Bad Content-Length'}, 400)
                return
            if length > MAX_SUBMIT_BODY:
                # Refused before a single byte is read: the declared size is
                # what an attacker would otherwise turn into an allocation.
                self.close_connection = True
                self.send_json({'status': 'error',
                                'message': f'Submission exceeds the '
                                           f'{human_size(MAX_SUBMIT_BODY)} limit'}, 413)
                return
            if length == 0:
                # No Content-Length (e.g. chunked): BaseHTTPRequestHandler does
                # not de-chunk, and reading an unbounded body is exactly the DoS
                # being avoided here.
                self.send_json({'status': 'error', 'message': 'Content-Length required'}, 411)
                return
            body = self.rfile.read(length)
            try:
                params = urllib.parse.parse_qs(body.decode('utf-8'))
            except UnicodeDecodeError:
                self.send_json({'status': 'error', 'message': 'Invalid encoding'}, 400)
                return
            content = params.get('content', [''])[0]

            if not content.strip():
                self.send_json({'status': 'error', 'message': 'Empty content'}, 400)
                return

            # One-shot, atomically: two simultaneous POSTs must not both write.
            with ExchangeHandler._submit_lock:
                if ExchangeHandler.received:
                    self.send_json({'status': 'already_received'}, 409)
                    return
                ExchangeHandler.received = True

            output_path = ExchangeHandler.output_file
            # Self-heal: if a stale directory exists where the file should go, remove it
            if output_path.is_dir() and not output_path.is_symlink():
                shutil.rmtree(output_path)
            # temp + rename, 0600: a symlink planted at the target is replaced,
            # never followed.
            try:
                rundir.write_private(str(output_path), content)
            except Exception:
                # Give the sender another go rather than a dead form.
                with ExchangeHandler._submit_lock:
                    ExchangeHandler.received = False
                raise

            size = len(content.encode('utf-8'))
            sys.stderr.write(f"[exchange] Text received -> {output_path} ({human_size(size)})\n")

            self.send_json({'status': 'ok', 'size': size})

            # Schedule server shutdown after 30 seconds
            if ExchangeHandler.server_ref:
                timer = threading.Timer(30, ExchangeHandler.server_ref.shutdown)
                timer.daemon = True
                timer.start()
        except Exception as e:
            sys.stderr.write(f"[exchange] submit failed: {e}\n")
            self.close_connection = True
            try:
                # Generic text only: internal exception strings carry filesystem
                # paths, and this used to echo str(e) straight to the caller.
                self.send_json({'status': 'error', 'message': 'Server error'}, 500)
            except Exception:
                pass
            return


def render_send_html(raw_content, name):
    """Fill SEND_HTML in one pass.

    The old code ran three sequential .replace() calls with the content
    substituted *first*, so text that happened to contain the literal
    EXCHANGE_NAME or EXCHANGE_FOOTER had that chunk rewritten by the later
    passes. re.sub with a callback never rescans what it inserted (same fix
    as paste/snap/qr).
    """
    line_count = raw_content.count('\n') + (1 if raw_content and not raw_content.endswith('\n') else 0)
    size = len(raw_content.encode('utf-8'))
    fields = {
        'EXCHANGE_CONTENT': html.escape(raw_content),
        'EXCHANGE_NAME': html.escape(name),
        'EXCHANGE_FOOTER': f"{human_size(size)} &middot; {line_count} lines",
    }
    return re.sub(r'EXCHANGE_(?:CONTENT|NAME|FOOTER)',
                  lambda m: fields[m.group(0)], SEND_HTML)


def main():
    parser = argparse.ArgumentParser(description='Exchange server')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--mode', type=str, required=True, choices=['send', 'receive'])
    parser.add_argument('--name', type=str, required=True)
    parser.add_argument('--file', type=str, default=None)
    parser.add_argument('--output', type=str, default=None)
    parser.add_argument('--bind', type=str, default='127.0.0.1')
    args = parser.parse_args()

    ExchangeHandler.mode = args.mode
    ExchangeHandler.name = args.name

    if args.mode == 'send':
        if not args.file:
            sys.stderr.write("[exchange] Error: --file is required in send mode\n")
            sys.exit(1)

        with open(args.file, 'r') as f:
            raw_content = f.read()

        ExchangeHandler.content_raw = raw_content

        ExchangeHandler.send_html = render_send_html(raw_content, args.name)

    else:
        if not args.output:
            sys.stderr.write("[exchange] Error: --output is required in receive mode\n")
            sys.exit(1)

        ExchangeHandler.output_file = Path(args.output).resolve()
        rendered = RECEIVE_HTML.replace('EXCHANGE_NAME', html.escape(args.name))
        ExchangeHandler.receive_html = rendered

    server = make_server(ExchangeHandler, args.port, args.bind, tag='exchange')
    ExchangeHandler.server_ref = server
    sys.stderr.write(f"[exchange] Listening on :{args.port}, mode={args.mode}, name='{args.name}'\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n[exchange] Shutting down.\n")
        server.shutdown()


if __name__ == '__main__':
    main()

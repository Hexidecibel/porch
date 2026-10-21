#!/usr/bin/env python3

import argparse
import html
import re
import secrets
import os
import sys
from http.server import BaseHTTPRequestHandler
from pathlib import Path

_HERE_LIB = os.path.dirname(os.path.abspath(__file__))
if _HERE_LIB not in sys.path:
    sys.path.insert(0, _HERE_LIB)
from porch_http import (  # noqa: E402  (shared HTTP core)
    make_server, porch_css_tag, porch_mark, porch_style_src, security_headers, serve_asset,
)

# highlight.js is vendored (lib/vendor/, see SOURCES there) and served from
# this server: the page CSP allows only 'self' + a per-response nonce, so the
# old cdnjs <script> was silently blocked and highlighting never ran.
VENDOR_DIR = Path(__file__).resolve().parent / 'vendor'
STATIC_FILES = {
    '/static/highlight.min.js': ('highlight.min.js', 'text/javascript; charset=utf-8'),
    '/static/atom-one-dark.min.css': ('atom-one-dark.min.css', 'text/css; charset=utf-8'),
}


PASTE_HTML = r"""<!DOCTYPE html>
<html lang="en" data-app="paste">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PASTE_NAME</title>
__PORCH_CSS__
<link rel="stylesheet" href="/static/atom-one-dark.min.css">
<style nonce="CSP_NONCE">
/* The code card is night in both themes: the vendored highlight theme is a
   dark one. */
.code-wrap{background:#1B181E;color:#F3ECE4;border:1px solid rgba(255,240,220,.10);border-radius:var(--r-2xl);overflow:hidden}
.toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 12px 10px 16px;
  border-bottom:1px solid rgba(255,240,220,.10)}
.toolbar .meta{font-size:13px;color:#A79E95}
.toolbar .acts{display:flex;gap:8px}
.toolbar .p-btn--quiet{color:#F3ECE4}
.toolbar .p-btn--quiet:hover{background:rgba(255,240,220,.06)}
.toolbar button.copied{filter:none;background:#5CCB8A;color:#0A1F12}
pre{margin:0;padding:16px;overflow-x:auto;background:transparent !important}
pre code{font:400 13.5px/1.65 var(--font-mono);background:transparent !important;color:#F3ECE4}
pre code.hljs{padding:0}
</style>
</head>
<body>
<main class="p-shell p-shell--wide">
  <header class="p-head">
    <div class="p-kicker">__MARK__<span>a paste on a porch</span></div>
    <h1 class="p-title">PASTE_NAME</h1>
  </header>
  <div class="code-wrap">
    <div class="toolbar">
      <span class="meta">PASTE_FOOTER</span>
      <span class="acts">
        <a class="p-btn p-btn--quiet p-btn--sm" href="/raw">Raw</a>
        <button class="p-btn p-btn--sm" id="copyBtn" type="button">Copy</button>
      </span>
    </div>
    <pre><code class="PASTE_LANG">PASTE_CONTENT</code></pre>
  </div>
  <footer class="p-foot">shared through porch</footer>
</main>
<script src="/static/highlight.min.js"></script>
<script nonce="CSP_NONCE">
if (window.hljs) hljs.highlightAll();
function copyPaste(){
  const code = document.querySelector('pre code');
  const btn = document.getElementById('copyBtn');
  navigator.clipboard.writeText(code.textContent).then(()=>{
    btn.textContent='Copied';
    btn.classList.add('copied');
    setTimeout(()=>{btn.textContent='Copy';btn.classList.remove('copied');},2000);
  }, ()=>{ btn.textContent='Select and copy'; });
}
document.getElementById('copyBtn').addEventListener('click', copyPaste);
</script>
</body>
</html>"""
# Fixed per process; filled in before any paste text is substituted.
PASTE_HTML = PASTE_HTML.replace('__PORCH_CSS__', porch_css_tag()).replace('__MARK__', porch_mark(16))


PASTE_CONTENT_RAW = ""


class PasteHandler(BaseHTTPRequestHandler):

    protocol_version = 'HTTP/1.1'
    # Bound how long a half-open or slow-loris connection can hold a thread.
    timeout = 120
    # Don't advertise the Python version to anonymous callers.
    server_version = 'porch'
    sys_version = ''

    paste_content = ""
    paste_name = ""
    paste_lang = ""
    paste_html = ""
    paste_parts = ()    # paste_html split at each nonce slot

    def log_message(self, format, *args):
        method = args[0] if args else ''
        if isinstance(method, str) and method.startswith('GET'):
            return
        sys.stderr.write(f"[pasteserver] {self.address_string()} - {format % args}\n")

    def _security_headers(self):
        """Headers every response carries.

        nosniff is the important one here: /raw serves arbitrary pasted text as
        text/plain, and without it a browser is free to decide that text is
        really HTML and run it on this origin.
        """
        security_headers(self)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if serve_asset(self, head=self.command == 'HEAD'):
            return
        path = self.path.split('?')[0].rstrip('/')

        if path == '' or path == '/':
            nonce = secrets.token_urlsafe(16)
            # Joined, not .replace()d: the paste body may itself contain the
            # text CSP_NONCE, and it must come through untouched.
            body = nonce.join(self.paste_parts).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            # Scripts/styles: this origin (the vendored highlight.js) plus the
            # page's own nonce'd inline block — nothing third-party, no inline
            # handlers. 'none' elsewhere kills base-tag and clickjacking tricks.
            self.send_header('Content-Security-Policy', (
                f"default-src 'none'; {porch_style_src(nonce)}; "
                f"script-src 'self' 'nonce-{nonce}'; base-uri 'none'; "
                "form-action 'none'; frame-ancestors 'none'"
            ))
            self._security_headers()
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(body)
            return

        if path in STATIC_FILES:
            fname, ctype = STATIC_FILES[path]
            try:
                body = (VENDOR_DIR / fname).read_bytes()
            except OSError:
                body = None
            if body is not None:
                self.send_response(200)
                self.send_header('Content-Type', ctype)
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Cache-Control', 'public, max-age=86400')
                self._security_headers()
                self.end_headers()
                if self.command != 'HEAD':
                    self.wfile.write(body)
                return

        if path == '/raw':
            body = PASTE_CONTENT_RAW.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            # Belt and braces with nosniff: even if a browser did treat this as
            # markup, a sandbox CSP means it executes nothing.
            self.send_header('Content-Security-Policy', "default-src 'none'; sandbox")
            self._security_headers()
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(body)
            return

        self.send_response(404)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        body = b'Not found'
        self.send_header('Content-Length', str(len(body)))
        self._security_headers()
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)


def human_size(size):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if size < 1024:
            return f"{size:.1f} {unit}" if unit != 'B' else f"{size} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def render_paste_parts(fields):
    """Render PASTE_HTML, returned as the pieces between nonce slots.

    The template is split at CSP_NONCE *before* anything is substituted, so a
    paste containing that literal text is never mistaken for a nonce slot.
    """
    return tuple(
        re.sub(r'PASTE_(?:CONTENT|NAME|LANG|FOOTER)',
               lambda m: fields[m.group(0)], piece)
        for piece in PASTE_HTML.split('CSP_NONCE')
    )


def main():
    global PASTE_CONTENT_RAW

    parser = argparse.ArgumentParser(description='Paste server')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--file', type=str, required=True)
    parser.add_argument('--name', type=str, required=True)
    parser.add_argument('--lang', type=str, default='')
    parser.add_argument('--bind', type=str, default='127.0.0.1')
    args = parser.parse_args()

    with open(args.file, 'r') as f:
        raw_content = f.read()

    PASTE_CONTENT_RAW = raw_content

    escaped_content = html.escape(raw_content)
    line_count = raw_content.count('\n') + (1 if raw_content and not raw_content.endswith('\n') else 0)
    size = len(raw_content.encode('utf-8'))
    footer = f"{human_size(size)} &middot; {line_count} lines"

    lang_class = f"language-{args.lang}" if args.lang else ""

    # One pass over the template, not four sequential .replace() calls. The old
    # order substituted the paste body first and then ran the remaining
    # replacements *over it*, so a paste that happened to contain the literal
    # text "PASTE_NAME" or "PASTE_LANG" had that chunk rewritten. Nothing
    # substituted in can be re-substituted here.
    fields = {
        'PASTE_CONTENT': escaped_content,
        'PASTE_NAME': html.escape(args.name),
        # Escaped as well: --lang is a command-line string landing in a
        # class="..." attribute, and an unescaped quote would break out of it.
        'PASTE_LANG': html.escape(lang_class),
        'PASTE_FOOTER': footer,
    }
    PasteHandler.paste_parts = render_paste_parts(fields)
    PasteHandler.paste_html = 'CSP_NONCE'.join(PasteHandler.paste_parts)

    server = make_server(PasteHandler, args.port, args.bind, tag='paste')
    sys.stderr.write(f"[pasteserver] Listening on :{args.port}, serving paste '{args.name}'\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n[pasteserver] Shutting down.\n")
        server.shutdown()


if __name__ == '__main__':
    main()

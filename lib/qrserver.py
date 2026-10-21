#!/usr/bin/env python3

import argparse
import base64
import io
import re
import os
import sys
from http.server import BaseHTTPRequestHandler

_HERE_LIB = os.path.dirname(os.path.abspath(__file__))
if _HERE_LIB not in sys.path:
    sys.path.insert(0, _HERE_LIB)
from porch_http import make_server, security_headers  # noqa: E402  (shared HTTP core)

try:
    import qrcode
    from qrcode.image.pil import PilImage
except ImportError:
    print("Missing dependency: pip install qrcode[pil]", file=sys.stderr)
    sys.exit(1)


QR_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>QR Code</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{
  background:#050008;
  font-family:'Segoe UI',system-ui,-apple-system,sans-serif;
  color:rgba(180,220,255,.88);
  min-height:100vh;
  display:flex;
  justify-content:center;
  padding:60px 20px;
}
.container{max-width:600px;width:100%;padding:40px 0;text-align:center}
h1{
  font-weight:300;
  letter-spacing:.15em;
  font-size:2.4rem;
  color:rgba(180,220,255,.88);
  text-shadow:0 0 30px rgba(100,200,255,.35),0 0 60px rgba(100,200,255,.15);
  margin-bottom:8px;
}
.subtitle{
  letter-spacing:.35em;
  text-transform:uppercase;
  color:rgba(180,200,255,.7);
  font-size:.75rem;
  margin-bottom:40px;
}
.qr-wrap{
  display:inline-block;
  padding:24px;
  background:rgba(255,255,255,.04);
  border:1px solid rgba(100,200,255,.15);
  border-radius:16px;
  margin-bottom:28px;
}
.qr-wrap img{
  display:block;
  width:280px;
  height:280px;
  image-rendering:pixelated;
  border-radius:4px;
}
.data-label{
  font-family:'Fira Code','Cascadia Code','JetBrains Mono',Consolas,monospace;
  font-size:.85rem;
  color:rgba(180,220,255,.65);
  word-break:break-all;
  padding:16px 20px;
  background:rgba(255,255,255,.03);
  border:1px solid rgba(100,200,255,.1);
  border-radius:10px;
  margin-bottom:20px;
  max-width:100%;
}
.actions{
  display:flex;
  justify-content:center;
  gap:12px;
  margin-bottom:24px;
}
.actions a,.actions button{
  background:none;
  border:1px solid rgba(100,200,255,.3);
  color:rgba(180,200,255,.7);
  padding:8px 20px;
  border-radius:6px;
  font-size:.8rem;
  letter-spacing:.05em;
  cursor:pointer;
  text-decoration:none;
  font-family:inherit;
  transition:all .2s ease;
}
.actions a:hover,.actions button:hover{
  border-color:rgba(100,200,255,.6);
  color:rgba(180,220,255,.95);
  background:rgba(100,200,255,.05);
}
.actions button.copied{
  border-color:rgba(100,255,150,.5);
  color:rgba(100,255,150,.8);
}
.footer{
  color:rgba(180,200,255,.3);
  font-size:.7rem;
  letter-spacing:.05em;
  margin-top:24px;
}
</style>
</head>
<body>
<div class="container">
  <h1>QR Code</h1>
  <div class="subtitle">QR_NAME</div>
  <div class="qr-wrap">
    <img src="data:image/png;base64,QR_IMAGE_B64" alt="QR Code">
  </div>
  <div class="data-label">QR_DATA</div>
  <div class="actions">
    <a href="/qr.png" download="qr.png">Download PNG</a>
    <button id="copyBtn" onclick="copyData()">Copy Data</button>
  </div>
  <div class="footer">QR_FOOTER</div>
</div>
<script>
function copyData(){
  navigator.clipboard.writeText(QR_DATA_JS).then(()=>{
    const btn=document.getElementById('copyBtn');
    btn.textContent='Copied';
    btn.classList.add('copied');
    setTimeout(()=>{btn.textContent='Copy Data';btn.classList.remove('copied');},2000);
  });
}
</script>
</body>
</html>"""


QR_PNG_BYTES = b""


class QRHandler(BaseHTTPRequestHandler):

    protocol_version = 'HTTP/1.1'
    # Bound how long a half-open or slow-loris connection can hold a thread.
    timeout = 120
    # Don't advertise the Python version to anonymous callers.
    server_version = 'porch'
    sys_version = ''

    qr_html = ""

    def log_message(self, format, *args):
        method = args[0] if args else ''
        if isinstance(method, str) and method.startswith('GET'):
            return
        sys.stderr.write(f"[qrserver] {self.address_string()} - {format % args}\n")

    def _security_headers(self):
        """Headers every response carries. nosniff stops a browser re-deciding
        that something we labelled image/png or text/plain is really HTML."""
        security_headers(self)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = self.path.split('?')[0].rstrip('/')

        if path == '' or path == '/':
            body = self.qr_html.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            # The page carries the QR as a data: URI and loads nothing else.
            self.send_header('Content-Security-Policy', (
                "default-src 'none'; style-src 'unsafe-inline'; "
                "script-src 'unsafe-inline'; img-src data:; "
                "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
            ))
            self._security_headers()
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(body)
            return

        if path == '/qr.png':
            self.send_response(200)
            self.send_header('Content-Type', 'image/png')
            self.send_header('Content-Length', str(len(QR_PNG_BYTES)))
            self.send_header('Content-Disposition', 'attachment; filename="qr.png"')
            self.send_header('Content-Security-Policy', "default-src 'none'; sandbox")
            self._security_headers()
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(QR_PNG_BYTES)
            return

        self.send_response(404)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        body = b'Not found'
        self.send_header('Content-Length', str(len(body)))
        self._security_headers()
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)


def main():
    global QR_PNG_BYTES

    parser = argparse.ArgumentParser(description='QR code server')
    parser.add_argument('--port', type=int, required=True)
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument('--data', type=str,
                     help='QR payload (visible in ps; prefer --data-file)')
    src.add_argument('--data-file', type=str,
                     help="Read the payload from this file, or '-' for stdin")
    parser.add_argument('--name', type=str, required=True)
    parser.add_argument('--bind', type=str, default='127.0.0.1')
    args = parser.parse_args()

    if args.data_file is not None:
        if args.data_file == '-':
            args.data = sys.stdin.read()
        else:
            with open(args.data_file, 'r', encoding='utf-8') as f:
                args.data = f.read()
        if not args.data:
            sys.stderr.write("[qrserver] Error: no data\n")
            sys.exit(1)

    # Generate QR code
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=2,
    )
    qr.add_data(args.data)
    qr.make(fit=True)

    img = qr.make_image(image_factory=PilImage)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    QR_PNG_BYTES = buf.getvalue()
    b64 = base64.b64encode(QR_PNG_BYTES).decode('ascii')

    # Escape data for HTML display and JS string
    import html as html_mod
    import json
    escaped_data = html_mod.escape(args.data)
    # json.dumps leaves '<' alone, so a payload containing '</script>' would
    # terminate the inline <script> block early and everything after it would
    # be parsed as markup. Escaping '<' keeps the value a JS string.
    js_data = json.dumps(args.data).replace('<', '\\u003c')

    data_len = len(args.data)
    footer = f"{data_len} character{'s' if data_len != 1 else ''}"

    # One pass over the template, longest placeholder first, not five
    # sequential .replace() calls. Sequential replacement ran each later
    # substitution *over* the text already inserted, so --data containing the
    # literal "QR_NAME" had that chunk rewritten, and QR_DATA_JS/QR_DATA
    # overlapped by prefix.
    fields = {
        'QR_IMAGE_B64': b64,
        'QR_DATA_JS': js_data,
        'QR_DATA': escaped_data,
        'QR_NAME': html_mod.escape(args.name),
        'QR_FOOTER': footer,
    }
    rendered = re.sub(r'QR_(?:IMAGE_B64|DATA_JS|DATA|NAME|FOOTER)',
                      lambda m: fields[m.group(0)], QR_HTML)

    QRHandler.qr_html = rendered

    server = make_server(QRHandler, args.port, args.bind, tag='qr')
    sys.stderr.write(f"[qrserver] Listening on :{args.port}, serving QR for '{args.name}'\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n[qrserver] Shutting down.\n")
        server.shutdown()


if __name__ == '__main__':
    main()

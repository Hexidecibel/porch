#!/usr/bin/env python3

"""Link shortener (used by bin/shorten, fronted by HAProxy at cush.rocks).

Every slug's target ends up verbatim in a Location: header, so link targets are
validated once at load time rather than trusted at redirect time — see
valid_target().
"""

import argparse
import json
import os
import re
import signal
import sys
from http.server import BaseHTTPRequestHandler

_HERE_LIB = os.path.dirname(os.path.abspath(__file__))
if _HERE_LIB not in sys.path:
    sys.path.insert(0, _HERE_LIB)
from porch_http import make_server, security_headers  # noqa: E402  (shared HTTP core)

LINKS = {}
DATA_PATH = ""

MAX_TARGET_LEN = 4096


def valid_target(target):
    """True if `target` is safe to put in a Location: header.

    Two things are being stopped here:

      * Response splitting. Python's send_header() does no CRLF validation at
        all — it formats "%s: %s\r\n" and encodes it — so a target containing
        a newline injects headers, or a whole second response, into every
        redirect for that slug. Anything with a control character is refused.
      * Non-http(s) schemes. A `javascript:` or `data:` target turns a
        cush.rocks short link into a payload delivery mechanism for whoever
        clicks it.
    """
    if not isinstance(target, str) or not target or len(target) > MAX_TARGET_LEN:
        return False
    if not target.lower().startswith(('http://', 'https://')):
        return False
    # No CR, LF, NUL, or any other C0/C1 control character.
    return not re.search(r'[\x00-\x1f\x7f-\x9f]', target)


def load_links():
    global LINKS
    try:
        with open(DATA_PATH, 'r') as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("expected a JSON object")
        # Filter at load time so a bad entry can never reach a Location header,
        # however it got into the file.
        clean = {k: v for k, v in data.items()
                 if isinstance(k, str) and valid_target(v)}
        dropped = len(data) - len(clean)
        LINKS = clean
        sys.stderr.write(f"[shortener] Loaded {len(LINKS)} links from {DATA_PATH}\n")
        if dropped:
            sys.stderr.write(f"[shortener] Refused {dropped} link(s) with an unsafe "
                             f"target (non-http(s) scheme or control characters)\n")
    except FileNotFoundError:
        sys.stderr.write(f"[shortener] Data file not found, starting with empty links\n")
        LINKS = {}
    except (json.JSONDecodeError, ValueError) as e:
        sys.stderr.write(f"[shortener] Error loading {DATA_PATH}: {e} — keeping old data\n")


def handle_sighup(signum, frame):
    sys.stderr.write(f"[shortener] SIGHUP received, reloading links\n")
    load_links()


INDEX_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>cush.rocks</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#050008;font-family:'Segoe UI',system-ui,sans-serif;
color:rgba(180,220,255,.88);min-height:100vh;display:flex;
justify-content:center;align-items:center;text-align:center}
h1{font-weight:300;letter-spacing:.15em;font-size:2.4rem;
text-shadow:0 0 30px rgba(100,200,255,.35),0 0 60px rgba(100,200,255,.15);
margin-bottom:12px}
p{color:rgba(180,200,255,.5);font-size:.85rem;letter-spacing:.05em}
</style></head><body>
<div><h1>cush.rocks</h1><p>link shortener &middot; LINK_COUNT active links</p></div>
</body></html>"""

NOT_FOUND_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Not Found</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#050008;font-family:'Segoe UI',system-ui,sans-serif;
color:rgba(180,220,255,.88);min-height:100vh;display:flex;
justify-content:center;align-items:center;text-align:center}
h1{font-weight:300;letter-spacing:.15em;font-size:2rem;
text-shadow:0 0 30px rgba(100,200,255,.35);margin-bottom:12px}
p{color:rgba(180,200,255,.5);font-size:.85rem}
</style></head><body>
<div><h1>Link not found</h1><p>This short link doesn't exist.</p></div>
</body></html>"""


class ShortenerHandler(BaseHTTPRequestHandler):

    protocol_version = 'HTTP/1.1'
    # Bound how long a half-open or slow-loris connection can hold a thread.
    timeout = 60
    # Don't advertise the Python version to anonymous callers.
    server_version = 'porch'
    sys_version = ''

    def _security_headers(self):
        security_headers(self, frame=None)

    def log_message(self, format, *args):
        method = args[0] if args else ''
        if isinstance(method, str) and method.startswith('GET'):
            return
        sys.stderr.write(f"[shortener] {self.address_string()} - {format % args}\n")

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = self.path.split('?')[0].rstrip('/')

        if path == '' or path == '/':
            body = INDEX_HTML.replace('LINK_COUNT', str(len(LINKS))).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Content-Security-Policy', (
                "default-src 'none'; style-src 'unsafe-inline'; "
                "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
            ))
            self._security_headers()
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(body)
            return

        slug = path.lstrip('/')
        target = LINKS.get(slug)
        # Re-checked at redirect time as well as at load: this value is the one
        # thing here that goes into a response header verbatim, and
        # send_header() will happily write a CRLF straight into the response.
        if target and valid_target(target):
            self.send_response(302)
            self.send_header('Location', target)
            self.send_header('Content-Length', '0')
            self._security_headers()
            self.end_headers()
            return

        body = NOT_FOUND_HTML.encode()
        self.send_response(404)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Content-Security-Policy', (
            "default-src 'none'; style-src 'unsafe-inline'; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        ))
        self._security_headers()
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)


def main():
    global DATA_PATH

    parser = argparse.ArgumentParser(description='Link shortener server')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--data', type=str, required=True)
    args = parser.parse_args()

    DATA_PATH = os.path.abspath(args.data)
    load_links()
    signal.signal(signal.SIGHUP, handle_sighup)

    server = make_server(ShortenerHandler, args.port, '127.0.0.1', tag='shortener')
    sys.stderr.write(f"[shortener] Listening on 127.0.0.1:{args.port}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n[shortener] Shutting down.\n")
        server.shutdown()


if __name__ == '__main__':
    main()

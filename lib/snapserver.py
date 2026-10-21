#!/usr/bin/env python3

import argparse
import base64
import html
import ipaddress
import os
import re
import socket
import sys
import urllib.parse
from datetime import datetime
from http.server import BaseHTTPRequestHandler

_HERE_LIB = os.path.dirname(os.path.abspath(__file__))
if _HERE_LIB not in sys.path:
    sys.path.insert(0, _HERE_LIB)
from porch_http import make_server, security_headers  # noqa: E402  (shared HTTP core)


SNAP_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Screenshot</title>
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
.container{max-width:1100px;width:100%;padding:40px 0}
h1{
  font-weight:300;
  letter-spacing:.15em;
  font-size:2.4rem;
  text-align:center;
  color:rgba(180,220,255,.88);
  text-shadow:0 0 30px rgba(100,200,255,.35),0 0 60px rgba(100,200,255,.15);
  margin-bottom:8px;
}
.subtitle{
  text-align:center;
  letter-spacing:.05em;
  color:rgba(180,200,255,.7);
  font-size:.8rem;
  margin-bottom:40px;
  word-break:break-all;
}
.subtitle a{
  color:rgba(180,200,255,.7);
  text-decoration:none;
  border-bottom:1px solid rgba(100,200,255,.2);
  transition:all .2s ease;
}
.subtitle a:hover{
  color:rgba(180,220,255,.95);
  border-color:rgba(100,200,255,.5);
}
.image-wrap{
  position:relative;
  border:1px solid rgba(100,200,255,.15);
  border-radius:12px;
  overflow:hidden;
}
.toolbar{
  display:flex;
  justify-content:flex-end;
  gap:12px;
  padding:8px 12px;
  background:rgba(255,255,255,.03);
  border-bottom:1px solid rgba(100,200,255,.1);
}
.toolbar a{
  background:none;
  border:1px solid rgba(100,200,255,.3);
  color:rgba(180,200,255,.7);
  padding:4px 12px;
  border-radius:6px;
  font-size:.75rem;
  letter-spacing:.05em;
  cursor:pointer;
  text-decoration:none;
  font-family:inherit;
  transition:all .2s ease;
}
.toolbar a:hover{
  border-color:rgba(100,200,255,.6);
  color:rgba(180,220,255,.95);
  background:rgba(100,200,255,.05);
}
.image-wrap img{
  display:block;
  width:100%;
  height:auto;
}
.footer{
  text-align:center;
  color:rgba(180,200,255,.3);
  font-size:.7rem;
  letter-spacing:.05em;
  margin-top:24px;
}
</style>
</head>
<body>
<div class="container">
  <h1>Screenshot</h1>
  <div class="subtitle"><a href="SNAP_URL" target="_blank" rel="noopener">SNAP_URL_DISPLAY</a></div>
  <div class="image-wrap">
    <div class="toolbar">
      <a href="/screenshot.png" download="SNAP_FILENAME">Download</a>
    </div>
    <a href="/screenshot.png" target="_blank"><img src="data:image/png;base64,SNAP_BASE64" alt="Screenshot of SNAP_URL_DISPLAY"></a>
  </div>
  <div class="footer">SNAP_FOOTER</div>
</div>
</body>
</html>"""


SCREENSHOT_DATA = b""


class SnapHandler(BaseHTTPRequestHandler):

    protocol_version = 'HTTP/1.1'
    # Bound how long a half-open or slow-loris connection can hold a thread.
    timeout = 120
    # Don't advertise the Python version to anonymous callers.
    server_version = 'porch'
    sys_version = ''

    snap_html = ""

    def log_message(self, format, *args):
        method = args[0] if args else ''
        if isinstance(method, str) and method.startswith('GET'):
            return
        sys.stderr.write(f"[snapserver] {self.address_string()} - {format % args}\n")

    def _security_headers(self):
        """Headers every response carries. nosniff stops a browser re-deciding
        that something we labelled image/png or text/plain is really HTML."""
        security_headers(self)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = self.path.split('?')[0].rstrip('/')

        if path == '' or path == '/':
            body = self.snap_html.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            # The page carries the screenshot as a data: URI and loads nothing
            # else. form-action/base-uri 'none' kill base-tag tricks; the page
            # links out to the captured URL, which is why no navigation policy
            # tighter than this one is applied.
            self.send_header('Content-Security-Policy', (
                "default-src 'none'; style-src 'unsafe-inline'; "
                "img-src 'self' data:; base-uri 'none'; "
                "form-action 'none'; frame-ancestors 'none'"
            ))
            self._security_headers()
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(body)
            return

        if path == '/screenshot.png':
            self.send_response(200)
            self.send_header('Content-Type', 'image/png')
            self.send_header('Content-Length', str(len(SCREENSHOT_DATA)))
            self.send_header('Content-Disposition', 'inline; filename="screenshot.png"')
            self.send_header('Content-Security-Policy', "default-src 'none'; sandbox")
            self._security_headers()
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(SCREENSHOT_DATA)
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


class UnsafeURLError(ValueError):
    pass


def _ip_is_public(ip):
    ip = ipaddress.ip_address(ip)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    # is_global is False for loopback, RFC1918, link-local (169.254/16 — the
    # cloud metadata address lives there), CGNAT 100.64/10, ULA fc00::/7,
    # unspecified, reserved and documentation ranges.
    return ip.is_global and not ip.is_multicast


def check_url(url, *, allow_private=False, resolver=socket.getaddrinfo):
    """Validate a URL for headless Chrome. Returns (host, ip_to_pin_or_None).

    Only http/https. Unless allow_private, every address the host resolves
    to must be public — a screenshot of http://127.0.0.1:9471/ or
    http://169.254.169.254/ would otherwise be published to a public URL.
    The returned IP is pinned into Chrome's resolver so a DNS answer that
    changes between this check and the fetch (rebinding) can't swap it.
    """
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError as e:
        raise UnsafeURLError(f"unparseable URL: {e}")
    if parts.scheme.lower() not in ('http', 'https'):
        raise UnsafeURLError(f"only http:// and https:// URLs are allowed (got {parts.scheme or 'none'}:)")
    host = parts.hostname
    if not host:
        raise UnsafeURLError("URL has no host")
    try:
        port = parts.port or (443 if parts.scheme.lower() == 'https' else 80)
    except ValueError:
        raise UnsafeURLError("bad port in URL")
    if allow_private:
        return host, None
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if not _ip_is_public(literal):
            raise UnsafeURLError(f"{host} is a private/loopback/link-local address (use --allow-private)")
        return host, None
    try:
        infos = resolver(host, port, 0, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise UnsafeURLError(f"cannot resolve {host}: {e}")
    ips = []
    for info in infos:
        ip = info[4][0].split('%', 1)[0]
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise UnsafeURLError(f"cannot resolve {host}")
    bad = [ip for ip in ips if not _ip_is_public(ip)]
    if bad:
        raise UnsafeURLError(
            f"{host} resolves to a private/loopback/link-local address ({', '.join(bad)}); "
            "use --allow-private if that is intended")
    # Prefer IPv4 for the pin: a v6-only pin breaks on boxes without v6 routes.
    v4 = [ip for ip in ips if ':' not in ip]
    return host, (v4 or ips)[0]


def _check_url_cli(argv):
    """`snapserver.py --check-url URL [--allow-private]` for bin/snap.

    Prints a Chrome --host-resolver-rules value (empty line when no pin is
    needed) on success; exits 2 with a reason on stderr otherwise.
    """
    allow = '--allow-private' in argv
    rest = [a for a in argv if a != '--allow-private']
    if len(rest) != 1:
        sys.stderr.write("usage: snapserver.py --check-url URL [--allow-private]\n")
        return 2
    try:
        host, ip = check_url(rest[0], allow_private=allow)
    except UnsafeURLError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 2
    if ip:
        target = f"[{ip}]" if ':' in ip else ip
        print(f"MAP {host} {target}")
    else:
        print("")
    return 0


def main():
    global SCREENSHOT_DATA

    parser = argparse.ArgumentParser(description='Screenshot server')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--file', type=str, required=True)
    parser.add_argument('--name', type=str, required=True)
    parser.add_argument('--url', type=str, required=True)
    parser.add_argument('--bind', type=str, default='127.0.0.1')
    args = parser.parse_args()

    with open(args.file, 'rb') as f:
        SCREENSHOT_DATA = f.read()

    b64 = base64.b64encode(SCREENSHOT_DATA).decode('ascii')
    size = len(SCREENSHOT_DATA)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    footer = f"{human_size(size)} &middot; captured {timestamp}"

    # The captured URL becomes an href. html.escape() keeps it inside the
    # attribute, but only an http(s) scheme keeps it from being a
    # javascript:/data: link that runs on this origin when clicked.
    safe_url = args.url if args.url.lower().startswith(('http://', 'https://')) else '#'
    url_escaped = html.escape(safe_url)
    # Truncate display URL if very long
    url_display = args.url
    if len(url_display) > 120:
        url_display = url_display[:117] + '...'
    url_display_escaped = html.escape(url_display)

    filename = f"screenshot-{args.name}.png"

    # One pass over the template, longest placeholder first, not five
    # sequential .replace() calls: sequential replacement ran each later
    # substitution *over* the text already inserted, and SNAP_URL_DISPLAY /
    # SNAP_URL overlap by prefix.
    fields = {
        'SNAP_BASE64': b64,
        'SNAP_URL_DISPLAY': url_display_escaped,
        'SNAP_URL': url_escaped,
        'SNAP_FILENAME': html.escape(filename),
        'SNAP_FOOTER': footer,
    }
    rendered = re.sub(r'SNAP_(?:BASE64|URL_DISPLAY|URL|FILENAME|FOOTER)',
                      lambda m: fields[m.group(0)], SNAP_HTML)

    SnapHandler.snap_html = rendered

    server = make_server(SnapHandler, args.port, args.bind, tag='snap')
    sys.stderr.write(f"[snapserver] Listening on :{args.port}, serving screenshot of '{args.url}'\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n[snapserver] Shutting down.\n")
        server.shutdown()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--check-url':
        sys.exit(_check_url_cli(sys.argv[2:]))
    main()

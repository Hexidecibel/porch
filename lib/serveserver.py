#!/usr/bin/env python3
"""Static file server for bin/serve.

bin/serve used to run a bare `python3 -m http.server`, which on a public
tunnel meant: listening on every interface, happily serving .env and .git/
(the whole repo history, credentials included), following symlinks anywhere
on disk, listing every directory, and letting any served HTML run script on
the tunnel's origin. This replaces it with a deliberately small server:

  * binds 127.0.0.1 (frpc reaches it over loopback);
  * GET/HEAD only;
  * any path segment starting with '.' is a 404 — .env, .git/config,
    .ssh/, .DS_Store, and '..' traversal alike — checked on the request path
    AND on the resolved path, so a symlink named "notes" pointing at .git
    is refused too;
  * every path is realpath()-resolved and must stay inside the root, so a
    symlink to /etc/passwd or ~/.ssh is a 404;
  * no directory listing unless --list (index.html is still served);
  * nosniff on everything, and a CSP sandbox (no script) on every type that
    can render as an active document (HTML, SVG, XML, unknown) unless
    --allow-scripts. Media, raster images, PDFs, fonts, CSS/JS and archives
    go without `sandbox`: WebKit's own media-document controls need script,
    so a sandboxed directly-linked .mp4 would not play on iOS Safari;
  * .gz/.tgz/.svgz/.bz2/.xz are served as the archive they are
    (application/gzip, ...), never with Content-Encoding, which made browsers
    silently unpack them (and an .svgz render as live SVG);
  * per-connection timeouts, daemon threads.
"""

import argparse
import html
import mimetypes
import os
import shutil
import stat
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler

_HERE_LIB = os.path.dirname(os.path.abspath(__file__))
if _HERE_LIB not in sys.path:
    sys.path.insert(0, _HERE_LIB)
from porch_http import (  # noqa: E402  (shared HTTP core)
    human_size, make_server, parse_range, porch_css_tag, porch_mark, porch_style_src, serve_asset,
)

# Sandboxed: no script, no plugins; forms/popups/downloads keep working so a
# plain static site still behaves. Sent on every type that can be an active
# document on this origin (HTML, SVG, XML, unknown/octet-stream); the passive
# types in PASSIVE_TYPES get CSP_SCRIPTS (no `sandbox`) instead.
CSP_SANDBOX = ("sandbox allow-forms allow-popups allow-popups-to-escape-sandbox "
               "allow-downloads; object-src 'none'; base-uri 'self'; "
               "frame-ancestors 'self'")
CSP_SCRIPTS = "object-src 'none'; base-uri 'self'; frame-ancestors 'self'"
# Our own directory listing: no script at all, porch.css + fonts from this
# origin. The sandbox keeps the origin (allow-same-origin, without
# allow-scripts that is harmless) so the stylesheet and fonts still load.
CSP_LISTING = (f"default-src 'none'; {porch_style_src()}; "
               "sandbox allow-same-origin allow-downloads allow-popups allow-popups-to-escape-sandbox; "
               "base-uri 'none'; form-action 'none'; frame-ancestors 'self'")

LISTING_STYLE_ICON = {
    'dir': ('<svg width="18" height="18" viewBox="0 0 20 20" fill="none" aria-hidden="true">'
            '<path d="M2.5 5.5 a1.5 1.5 0 0 1 1.5-1.5 H8 l2 2 h6 a1.5 1.5 0 0 1 1.5 1.5 V15 a1.5 1.5 0 0 1-1.5 1.5 H4 '
            'a1.5 1.5 0 0 1-1.5-1.5 Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>'),
    'file': ('<svg width="18" height="18" viewBox="0 0 20 20" fill="none" aria-hidden="true">'
             '<path d="M5 2.5 H11.5 L15.5 6.5 V17.5 H5 Z M11.5 2.5 V6.5 H15.5" stroke="currentColor" '
             'stroke-width="1.6" stroke-linejoin="round"/></svg>'),
}

# Types a browser never runs as a scripted document. An allowlist, so a type
# nobody thought about gets the sandbox.
PASSIVE_PREFIXES = ('video/', 'audio/', 'font/')
PASSIVE_TYPES = frozenset({
    'application/pdf', 'text/plain', 'text/css', 'text/csv', 'text/markdown',
    'text/javascript', 'application/javascript', 'application/json',
    'application/wasm', 'application/zip', 'application/gzip',
    'application/x-tar', 'application/x-bzip2', 'application/x-xz',
    'application/x-compress', 'application/x-7z-compressed',
    'application/vnd.ms-fontobject', 'application/font-woff',
})

# mimetypes reports .gz/.bz2/.xz as an *encoding* of the inner type. We serve
# the file itself, so it is the archive type and no Content-Encoding is sent.
ENCODING_TYPES = {
    'gzip': 'application/gzip', 'bzip2': 'application/x-bzip2',
    'xz': 'application/x-xz', 'compress': 'application/x-compress',
}


def needs_sandbox(ctype):
    base = (ctype or '').split(';', 1)[0].strip().lower()
    if base.startswith('image/'):
        return base == 'image/svg+xml'
    if base.startswith(PASSIVE_PREFIXES) or base in PASSIVE_TYPES:
        return False
    return True


TEXT_TYPES = ('text/', 'application/javascript', 'application/json',
              'application/xml', 'image/svg+xml')


class ServeHandler(BaseHTTPRequestHandler):

    protocol_version = 'HTTP/1.1'
    timeout = 30
    server_version = 'porch-serve'
    sys_version = ''

    root = '/nonexistent'      # realpath of the served directory
    allow_list = False
    allow_scripts = False

    # ── helpers ────────────────────────────────────────────────────────────

    def _common_headers(self, ctype=None):
        """ctype None (redirects, errors, listings) is treated as active."""
        sandbox = not self.allow_scripts and (ctype is None or needs_sandbox(ctype))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy',
                         CSP_SANDBOX if sandbox else CSP_SCRIPTS)
        self.send_header('Referrer-Policy', 'same-origin')
        self.send_header('Cache-Control', 'no-cache')

    def _simple(self, status, text, extra=None):
        body = text.encode()
        self.send_response(status)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self._common_headers()
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def _not_found(self):
        self._simple(404, 'Not found')

    def resolve(self, raw_path):
        """Map a request path to (real_path, is_dir) or None for 404.

        Pure function of the request path and the filesystem — exercised
        directly by the tests.
        """
        path = urllib.parse.urlsplit(raw_path).path
        try:
            path = urllib.parse.unquote(path, errors='strict')
        except UnicodeDecodeError:
            return None
        if '\x00' in path or '\\' in path:
            return None
        segments = [s for s in path.split('/') if s]
        # Dot-segments: '.', '..', and every dotfile / dot-directory.
        if any(s.startswith('.') for s in segments):
            return None
        candidate = os.path.join(self.root, *segments)
        real = os.path.realpath(candidate)
        if real != self.root and not real.startswith(self.root + os.sep):
            return None   # symlink (or anything) escaping the root
        rel = os.path.relpath(real, self.root)
        if rel != '.' and any(s.startswith('.') for s in rel.split(os.sep)):
            return None   # symlink landing on a dot-path inside the root
        try:
            st = os.stat(real)
        except OSError:
            return None
        if stat.S_ISDIR(st.st_mode):
            return real, True
        if stat.S_ISREG(st.st_mode):
            return real, False
        return None       # fifos, sockets, devices

    # ── methods ────────────────────────────────────────────────────────────

    def _method_not_allowed(self):
        self.close_connection = True
        self._simple(405, 'Method not allowed', {'Allow': 'GET, HEAD', 'Connection': 'close'})

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _method_not_allowed

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        # porch.css + fonts for the listing page. Dot-free, so they could
        # otherwise collide with a served path; a /__porch-assets/ directory
        # in the served root is shadowed.
        if serve_asset(self, head=self.command == 'HEAD'):
            return
        hit = self.resolve(self.path)
        if hit is None:
            self._not_found()
            return
        real, is_dir = hit
        if is_dir:
            # Collapse leading slashes: "//evil.com" must never become a
            # protocol-relative Location: //evil.com/.
            url_path = '/' + urllib.parse.urlsplit(self.path).path.lstrip('/')
            if not url_path.endswith('/'):
                self.send_response(301)
                self.send_header('Location', url_path + '/')
                self.send_header('Content-Length', '0')
                self._common_headers()
                self.end_headers()
                return
            index = self.resolve(url_path + 'index.html')
            if index is not None and not index[1]:
                self._send_file(index[0])
                return
            if self.allow_list:
                self._send_listing(real, url_path)
                return
            self._not_found()
            return
        self._send_file(real)

    def _send_file(self, real):
        ctype, enc = mimetypes.guess_type(real)
        if enc:
            ctype = ENCODING_TYPES.get(enc, 'application/octet-stream')
        if not ctype:
            ctype = 'application/octet-stream'
        if ctype.startswith(TEXT_TYPES) and 'charset' not in ctype:
            ctype += '; charset=utf-8'
        try:
            f = open(real, 'rb')
        except OSError:
            self._not_found()
            return
        with f:
            size = os.fstat(f.fileno()).st_size
            # Single byte ranges: iOS Safari will not play a video from a
            # server that answers Range with a plain 200.
            # porch_http.parse_range: one range, clamped, digit runs capped.
            start, end = 0, size - 1
            rng = parse_range(self.headers.get('Range'), size)
            if rng is not None:
                if rng == 'unsatisfiable':
                    self.send_response(416)
                    self.send_header('Content-Range', f'bytes */{size}')
                    self.send_header('Content-Length', '0')
                    self._common_headers()
                    self.end_headers()
                    return
                start, end = rng
                self.send_response(206)
                self.send_header('Content-Range', f'bytes {start}-{end}/{size}')
            else:
                self.send_response(200)
            length = end - start + 1 if size > 0 else 0
            self.send_header('Content-Type', ctype)
            self.send_header('Accept-Ranges', 'bytes')
            self.send_header('Content-Length', str(length))
            self._common_headers(ctype)
            self.end_headers()
            if self.command != 'HEAD':
                try:
                    f.seek(start)
                    left = length
                    while left > 0:
                        chunk = f.read(min(64 * 1024, left))
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        left -= len(chunk)
                except (BrokenPipeError, ConnectionResetError):
                    self.close_connection = True

    def _send_listing(self, real, url_path):
        try:
            names = sorted(os.listdir(real), key=str.lower)
        except OSError:
            self._not_found()
            return
        dirs, files = [], []
        for name in names:
            if name.startswith('.'):
                continue
            full = os.path.join(real, name)
            try:
                st = os.stat(full)
            except OSError:
                continue
            is_dir = stat.S_ISDIR(st.st_mode)
            suffix = '/' if is_dir else ''
            href = urllib.parse.quote(name) + suffix
            meta = 'folder' if is_dir else human_size(st.st_size)
            icon = LISTING_STYLE_ICON['dir' if is_dir else 'file']
            row = (f'<li><a class="p-row" href="{html.escape(href, quote=True)}">'
                   f'<span class="ico">{icon}</span>'
                   f'<span class="p-row-main"><span class="p-row-name">{html.escape(name + suffix)}</span></span>'
                   f'<span class="p-row-meta">{html.escape(meta)}</span></a></li>')
            (dirs if is_dir else files).append(row)
        rows = dirs + files
        if url_path != '/':
            rows.insert(0, '<li><a class="p-row" href="../"><span class="ico">'
                           + LISTING_STYLE_ICON['dir'] + '</span><span class="p-row-main">'
                           '<span class="p-row-name">../</span></span>'
                           '<span class="p-row-meta">up one level</span></a></li>')
        count = len(dirs) + len(files)
        title = html.escape(url_path)
        listing = (f'<ul class="p-list">{"".join(rows)}</ul>' if rows else
                   '<div class="p-empty"><div class="p-empty-title">This folder is empty</div></div>')
        body = ('<!DOCTYPE html><html lang="en" data-app="serve"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width, initial-scale=1">'
                f'<title>Index of {title}</title>{porch_css_tag()}</head><body>'
                '<main class="p-shell">'
                f'<header class="p-head"><div class="p-kicker">{porch_mark(16)}'
                f'<span>a folder on a porch · {count} item{"" if count == 1 else "s"}</span></div>'
                f'<h1 class="p-title p-mono">{title}</h1></header>'
                f'{listing}<footer class="p-foot">served through porch</footer></main>'
                '</body></html>').encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', CSP_LISTING)
        self.send_header('Referrer-Policy', 'same-origin')
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)


def make_handler(root, *, allow_list=False, allow_scripts=False):
    """A handler class bound to one root (keeps tests independent)."""
    return type('BoundServeHandler', (ServeHandler,), {
        'root': os.path.realpath(root),
        'allow_list': allow_list,
        'allow_scripts': allow_scripts,
    })


def main():
    p = argparse.ArgumentParser(description='Static file server (bin/serve)')
    p.add_argument('--port', type=int, required=True)
    p.add_argument('--directory', required=True)
    p.add_argument('--bind', default='127.0.0.1')
    p.add_argument('--list', action='store_true', help='Allow directory listings')
    p.add_argument('--allow-scripts', action='store_true',
                   help='Drop the CSP sandbox so served pages may run JavaScript')
    args = p.parse_args()

    if not os.path.isdir(args.directory):
        sys.stderr.write(f"[serve] not a directory: {args.directory}\n")
        sys.exit(1)
    handler = make_handler(args.directory, allow_list=args.list,
                           allow_scripts=args.allow_scripts)
    server = make_server(handler, args.port, args.bind, tag='serve')
    sys.stderr.write(
        f"[serve] {handler.root} on {args.bind}:{args.port} "
        f"(listing={'on' if args.list else 'off'}, "
        f"scripts={'on' if args.allow_scripts else 'sandboxed'})\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == '__main__':
    main()

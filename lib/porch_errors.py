#!/usr/bin/env python3
"""Porch error pages for HAProxy (`errorfile`): build, check, CLI.

config/templates/haproxy-error.html.tmpl is filled with each code's copy
below and wrapped in a raw HTTP response (status line, headers, blank line,
body), which is what HAProxy's errorfile wants. HAProxy keeps the whole file
in one buffer, so build() refuses a page bigger than MAX_BYTES (the default
tune.bufsize is 16384; we leave room for the rewrite reserve).

The copy is host-agnostic (the page reads location.hostname), so one set of
files serves every host. The style and script are the same on every page and
the CSP names their sha256, so the pages run nothing else.

    python3 lib/porch_errors.py build --out DIR [--brand NAME]   # writes DIR/<code>.http
    python3 lib/porch_errors.py check DIR                        # parse + size each file

bin/haproxy-errors installs them to /etc/haproxy/errors/porch/ and points the
config's errorfile lines there; porch render puts the same paths in a fresh
install's config (lib/porch_setup/render.py, errors_dir).
"""

import argparse
import base64
import hashlib
import html
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(_HERE, '..', 'config', 'templates', 'haproxy-error.html.tmpl')
INSTALL_DIR = '/etc/haproxy/errors/porch'
MAX_BYTES = 14 * 1024
RETRY_AFTER = 10

# code: (reason, title, lede, foot, mode, lamp, button)
#   mode  retry: knock (HEAD) until the app answers, then reload
#         reload: a Try again button   back: a Go back button
#         wait: a countdown before Try again   none: no button
#   lamp  on | off | sputter | busy
PAGES = {
    400: ('Bad Request', 'That didn’t come through right.',
          'Something garbled the request on its way to the door. Go back and try again; '
          'if it keeps happening, the link itself may be broken.',
          'bad request', 'back', 'sputter', 'Go back'),
    403: ('Forbidden', 'Not through this door.',
          'This address doesn’t open for you, or nothing lives here. If someone sent '
          'you, check the link with them.',
          'forbidden', 'back', 'off', 'Go back'),
    408: ('Request Timeout', 'The door got tired of waiting.',
          'Your browser started knocking and then went quiet, so the porch hung up. '
          'Try again; a steadier connection usually fixes it.',
          'request timeout', 'reload', 'sputter', 'Try again'),
    429: ('Too Many Requests', 'Easy there.',
          'That’s a lot of knocking in a short time. Give it a few seconds and '
          'the door opens again.',
          'too many requests', 'wait', 'busy', 'Try again'),
    500: ('Internal Server Error', 'Something tripped inside.',
          'The porch hit a snag handling this. It’s not you. Try again in a moment.',
          'server error', 'reload', 'sputter', 'Try again'),
    502: ('Bad Gateway', 'Lights on, nobody home.',
          'The porch light is on, but the app behind this door isn’t answering. '
          'It may be restarting. This page keeps knocking and lets you in when it’s back.',
          'bad gateway', 'retry', 'on', 'Knock now'),
    503: ('Service Unavailable', 'Lights on, nobody home.',
          'The porch light is on, but the app behind this door isn’t taking visitors '
          'right now. This page keeps knocking and lets you in when it’s back.',
          'service unavailable', 'retry', 'on', 'Knock now'),
    504: ('Gateway Timeout', 'Nobody came to the door.',
          'The app behind this door took too long to answer. This page keeps knocking '
          'and lets you in when it does.',
          'gateway timeout', 'retry', 'on', 'Knock now'),
}
CODES = tuple(sorted(PAGES))


class ErrorPageError(ValueError):
    pass


def _sha(text):
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode('utf-8')).digest()).decode() + "'"


def _inline(body, tag):
    m = re.search(rf'<{tag}>(.*?)</{tag}>', body, re.S)
    if not m:
        raise ErrorPageError(f'template has no <{tag}>')
    return m.group(1)


def csp_for(body):
    return ("default-src 'none'; "
            f"style-src {_sha(_inline(body, 'style'))}; "
            f"script-src {_sha(_inline(body, 'script'))}; "
            "connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; "
            "frame-ancestors 'none'")


def page_html(code, brand='Porch', template=None):
    reason, title, lede, foot, mode, lamp, button = PAGES[code]
    if template is None:
        with open(TEMPLATE, encoding='utf-8') as f:
            template = f.read()
    e = html.escape
    out = template
    for k, v in (('__CODE__', str(code)), ('__REASON__', e(reason)), ('__TITLE__', e(title)),
                 ('__LEDE__', e(lede)), ('__FOOT__', e(foot)), ('__MODE__', mode),
                 ('__LAMP__', lamp), ('__BUTTON__', e(button)), ('__BRAND__', e(brand))):
        out = out.replace(k, v)
    # The template's top comment is for whoever edits it, not for the wire.
    out = re.sub(r'<!--.*?-->\n', '', out, count=1, flags=re.S)
    left = re.findall(r'__[A-Z]+__', out)
    if left:
        raise ErrorPageError(f'unfilled placeholders: {left}')
    return out


def response(code, brand='Porch', template=None):
    """The errorfile bytes for one code."""
    body = page_html(code, brand, template).encode('utf-8')
    reason = PAGES[code][0]
    head = [f'HTTP/1.1 {code} {reason}',
            'Content-Type: text/html; charset=utf-8',
            f'Content-Length: {len(body)}',
            'Cache-Control: no-store',
            'Connection: close',
            f'Content-Security-Policy: {csp_for(body.decode("utf-8"))}',
            'X-Content-Type-Options: nosniff',
            'Referrer-Policy: no-referrer']
    if code == 429:
        head.append(f'Retry-After: {RETRY_AFTER}')
    raw = ('\r\n'.join(head) + '\r\n\r\n').encode('ascii') + body
    if len(raw) > MAX_BYTES:
        raise ErrorPageError(f'{code}.http is {len(raw)} bytes; HAProxy needs it under {MAX_BYTES}')
    return raw


def build(brand='Porch', template=None):
    """{code: bytes} for every page."""
    return {code: response(code, brand, template) for code in CODES}


def parse(raw):
    """(status, {header-lowercase: value}, body) of an errorfile; ErrorPageError
    if it is not a well-formed HTTP response HAProxy would take."""
    head, sep, body = raw.partition(b'\r\n\r\n')
    if not sep:
        raise ErrorPageError('no blank line after the headers')
    lines = head.decode('ascii').split('\r\n')
    m = re.match(r'^HTTP/1\.[01] (\d{3}) [A-Za-z ]+$', lines[0])
    if not m:
        raise ErrorPageError(f'bad status line: {lines[0]!r}')
    headers = {}
    for ln in lines[1:]:
        k, colon, v = ln.partition(':')
        if not colon or not re.match(r'^[A-Za-z0-9-]+$', k):
            raise ErrorPageError(f'bad header line: {ln!r}')
        headers[k.lower()] = v.strip()
    if int(headers.get('content-length', -1)) != len(body):
        raise ErrorPageError('Content-Length does not match the body')
    return int(m.group(1)), headers, body


def check_dir(path):
    """Problems with the built files in `path` (empty list = fine)."""
    out = []
    for code in CODES:
        f = os.path.join(path, f'{code}.http')
        try:
            with open(f, 'rb') as fh:
                raw = fh.read()
            status, headers, _ = parse(raw)
            if status != code:
                out.append(f'{f}: status {status}')
            if len(raw) > MAX_BYTES:
                out.append(f'{f}: {len(raw)} bytes (max {MAX_BYTES})')
        except (OSError, ErrorPageError, ValueError) as e:
            out.append(f'{f}: {e}')
    return out


def write(dest, brand='Porch'):
    os.makedirs(dest, exist_ok=True)
    for code, raw in build(brand).items():
        p = os.path.join(dest, f'{code}.http')
        tmp = p + '.tmp'
        with open(tmp, 'wb') as f:
            f.write(raw)
        os.chmod(tmp, 0o644)
        os.replace(tmp, p)
    return [os.path.join(dest, f'{c}.http') for c in CODES]


def main(argv=None):
    ap = argparse.ArgumentParser(prog='porch_errors.py', description='Porch HAProxy error pages')
    sub = ap.add_subparsers(dest='cmd', required=True)
    b = sub.add_parser('build')
    b.add_argument('--out', required=True)
    b.add_argument('--brand', default=None, help='default: brand.name from the porch config')
    c = sub.add_parser('check')
    c.add_argument('dir')
    sub.add_parser('codes')
    a = ap.parse_args(argv)
    if a.cmd == 'codes':
        print(' '.join(str(c) for c in CODES))
        return 0
    if a.cmd == 'check':
        bad = check_dir(a.dir)
        for b_ in bad:
            print(f'✗ {b_}', file=sys.stderr)
        return 1 if bad else 0
    brand = a.brand
    if brand is None:
        sys.path.insert(0, _HERE)
        import porch_config
        brand = porch_config.get().brand
    try:
        for p in write(a.out, brand):
            print(p)
    except ErrorPageError as e:
        print(f'✗ {e}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

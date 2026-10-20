"""Pocket's fixed asset table (lib/pocketserver.py): the PWA icons and
manifest, the service worker, the page and its scripts, all read from
lib/pocket_static/ at import.

Two kinds of path:
  * fixed: /sw.js (no-cache: a new worker must be noticed), /manifest.webmanifest,
    the icons, /static/seal.js (lib/seal.js, read per request);
  * hashed: /static/<stem>.<sha256[:12]>.<ext> for every script and stylesheet
    in lib/pocket_static/ (plus porch_tus's client as tus.<hash>.js), served
    with an immutable cache. Nothing from the URL reaches the filesystem: a
    path is either in the table or a 404.

The page template (app.html, the Porch app shell) is not served as a file;
pocketserver fills its placeholders (render_shell).
"""

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import porch_tus  # noqa: E402

STATIC_DIR = Path(_HERE) / 'pocket_static'


def _read(name):
    return (STATIC_DIR / name).read_text(encoding='utf-8')


# Night tokens from lib/porch.css (ground, text) and the exchange accent.
GROUND, TEXT, ACCENT = '#121014', '#F3ECE4', '#B39CFF'
ICON_DIR = Path(_HERE) / 'icons'

# ---- icons -------------------------------------------------------------------

def icon_svg(scale=0.66):
    """The porch mark (porch_http.porch_mark's paths) on a full-bleed night
    ground, sized to sit inside the maskable safe zone."""
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 64 64">'
        f'<rect width="64" height="64" fill="{GROUND}"/>'
        f'<g transform="translate(32 32) scale({scale}) translate(-32 -32)" fill="none" '
        f'stroke="{TEXT}" stroke-width="5" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M8 30 L32 10 L56 30"/><path d="M16 28 V54 H48 V28"/>'
        f'<circle cx="32" cy="22" r="5.5" fill="{ACCENT}" stroke="none"/></g></svg>')


def build_icons(dest=ICON_DIR):
    """Render pocket-192.png / pocket-512.png from icon_svg() (rsvg-convert,
    else ImageMagick). Run once; the PNGs are committed."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    svg = icon_svg().encode()
    for size in (192, 512):
        out = dest / f'pocket-{size}.png'
        for cmd in (['rsvg-convert', '-w', str(size), '-h', str(size), '-o', str(out)],
                    ['convert', '-background', 'none', '-density', '384', 'svg:-',
                     '-resize', f'{size}x{size}', str(out)]):
            try:
                subprocess.run(cmd, input=svg, check=True, capture_output=True)
                break
            except (OSError, subprocess.CalledProcessError):
                continue
        else:
            raise SystemExit('need rsvg-convert or ImageMagick to build the icons')
        print(out)


def _load_icons():
    out = {'/icon.svg': (icon_svg().encode(), 'image/svg+xml')}
    for size in (192, 512):
        try:
            out[f'/icon-{size}.png'] = ((ICON_DIR / f'pocket-{size}.png').read_bytes(), 'image/png')
        except OSError:
            pass
    return out


ICONS = _load_icons()

# Same-origin scripts the page loads (CSP script-src 'self'): the porch-seal
# browser library (lib/seal.js), read from the checkout on each request.
STATIC_JS = {'/static/seal.js': os.path.join(_HERE, 'seal.js')}


def manifest(title='Porch'):
    icons = [{'src': '/icon.svg', 'sizes': 'any', 'type': 'image/svg+xml', 'purpose': 'any'}]
    for size in (192, 512):
        if f'/icon-{size}.png' in ICONS:
            icons.append({'src': f'/icon-{size}.png', 'sizes': f'{size}x{size}',
                          'type': 'image/png', 'purpose': 'any'})
    if '/icon-512.png' in ICONS:
        # The mark sits well inside the safe zone, so one file serves both.
        icons.append({'src': '/icon-512.png', 'sizes': '512x512',
                      'type': 'image/png', 'purpose': 'maskable'})
    return {
        'id': '/',
        'name': title,
        'short_name': 'Porch',
        'description': 'Share to your computer, and a clipboard both devices can reach.',
        'start_url': '/',
        'scope': '/',
        'display': 'standalone',
        'theme_color': GROUND,
        'background_color': GROUND,
        'icons': icons,
        'share_target': {
            'action': '/share',
            'method': 'POST',
            'enctype': 'multipart/form-data',
            'params': {'title': 'title', 'text': 'text', 'url': 'url',
                       'files': [{'name': 'files', 'accept': ['*/*']}]},
        },
    }


# The service worker template (its precache manifest URL is filled in below,
# once the hashed table exists).
SW_TEMPLATE = _read('sw.js')

# The Porch app shell. Its scripts and stylesheet are hashed /static/ files
# (below); render_shell() fills the placeholders.
PAGE_HTML = _read('app.html')

# ---- page scripts: QR, Make link, Send encrypted, the links panel ----------
#
# PorchQR: a QR Code Model 2 encoder (byte mode, versions 1-40, L/M/Q/H, the
# usual mask penalty), drawn as one SVG path. It runs in the page because a
# sealed link's QR carries the key (#k=...), which must never reach the server.
# tests/test_pocketserver.py checks its matrices against python-qrcode.
QR_CLIENT_JS = _read('qr.js')
# Make link, Send encrypted, the links panel and the push UI.
LINKS_CLIENT_JS = _read('share.js')


# ---- hashed assets -------------------------------------------------------------

STATIC_TYPES = {'.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
                '.json': 'application/json'}
# Served elsewhere (or not at all): the templates and the service worker.
NOT_HASHED = ('app.html', 'sw.js')


def _hashed_path(name, data):
    stem, ext = os.path.splitext(name)
    return f'/static/{stem}.{hashlib.sha256(data).hexdigest()[:12]}{ext}'


def _build_hashed():
    """{path: (bytes, content type)} and {file name: path}."""
    table, urls = {}, {}
    files = []
    try:
        files = sorted(p for p in STATIC_DIR.iterdir() if p.is_file())
    except OSError:
        pass
    for p in files:
        if p.name in NOT_HASHED or p.suffix not in STATIC_TYPES:
            continue
        data = p.read_bytes()
        path = _hashed_path(p.name, data)
        table[path] = (data, STATIC_TYPES[p.suffix])
        urls[p.name] = path
    tus = porch_tus.TUS_CLIENT_JS.encode('utf-8')
    path = _hashed_path('tus.js', tus)
    table[path] = (tus, STATIC_TYPES['.js'])
    urls['tus.js'] = path
    return table, urls


HASHED, HASHED_URLS = _build_hashed()


def _precache():
    """/static/precache.<hash>.json: every hashed asset (ours and the
    design system's), for the service
    worker's install step. Its hash moves with any asset, and so does the
    worker (it names this file), so a deploy installs a new worker."""
    import porch_http
    # porch.css and its fonts too (/__porch-assets/, hashed and immutable the
    # same way), so an offline launch is styled.
    body = json.dumps(sorted(HASHED) + sorted(porch_http.ASSETS)).encode('utf-8')
    path = _hashed_path('precache.json', body)
    HASHED[path] = (body, STATIC_TYPES['.json'])
    HASHED_URLS['precache.json'] = path
    return path


PRECACHE_URL = _precache()
# Network-first for the page, cache-first for hashed assets, nothing else.
SERVICE_WORKER_JS = SW_TEMPLATE.replace('__PRECACHE_URL__', PRECACHE_URL)
IMMUTABLE = 'public, max-age=31536000, immutable'


def asset_url(name):
    """The hashed /static/ path of lib/pocket_static/<name> (or 'tus.js')."""
    return HASHED_URLS[name]


def lookup(path):
    """(bytes, content type) for a hashed /static/ path, else None."""
    return HASHED.get(path)


_ASSET_RE = re.compile(r'__ASSET_([A-Za-z0-9_.-]+)__')


def render_shell(head, title, nonce, cfg_json):
    """app.html with every placeholder filled: __HEAD__, __TITLE__ (escaped
    by the caller), __NONCE__, __CFG_JSON__ (already '<'-escaped JSON) and
    __ASSET_<file>__ -> the hashed /static/ path (KeyError for an unknown
    file, so a typo fails at the first request, not silently)."""
    page = _ASSET_RE.sub(lambda m: asset_url(m.group(1)), PAGE_HTML)
    return (page.replace('__HEAD__', head).replace('__TITLE__', title)
            .replace('__CFG_JSON__', cfg_json).replace('__NONCE__', nonce))

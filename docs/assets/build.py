#!/usr/bin/env python3
"""Build the README artwork (docs/assets/*.svg) in the Porch palette.

The fonts are the self-hosted woff2 files from lib/vendor/fonts, embedded as
data: URIs so the SVGs look the same on GitHub (an <img> SVG can't fetch
anything). Re-run after changing a colour or a line of copy:

    python3 docs/assets/build.py
"""

import base64
import os
import random
from xml.sax.saxutils import escape

HERE = os.path.dirname(os.path.abspath(__file__))
FONTS = os.path.join(HERE, "..", "..", "lib", "vendor", "fonts")

GROUND, SURFACE, RAISED = "#121014", "#1B181E", "#262129"
LIGHT, TEXT, MUTED, FAINT = "#F5A524", "#F3ECE4", "#A79E95", "#8F867D"
OK = "#5CCB8A"
ACCENT = {"drop": "#5AA2F0", "media": "#3CC8B4", "music": "#F06A8A", "text": "#B39CFF",
          "secret": "#8FD16A", "serve": "#E8E1D8", "porch": LIGHT}


def font_face(family, fname, weight):
    with open(os.path.join(FONTS, fname), "rb") as f:
        data = base64.b64encode(f.read()).decode()
    return (f"@font-face{{font-family:'{family}';font-weight:{weight};"
            f"src:url(data:font/woff2;base64,{data}) format('woff2')}}")


def style(*faces, extra=""):
    css = "".join(font_face(*f) for f in faces)
    css += (".d{font-family:'Bricolage',sans-serif}"
            ".u{font-family:'Geist',sans-serif}"
            ".m{font-family:'GeistMono',monospace}" + extra)
    return f"<style>{css}</style>"


DISPLAY = ("Bricolage", "bricolage-700.woff2", 700)
UI = ("Geist", "geist-500.woff2", 500)
UI4 = ("Geist", "geist-400.woff2", 400)
MONO = ("GeistMono", "geist-mono-400.woff2", 400)
MONO5 = ("GeistMono", "geist-mono-500.woff2", 500)


def svg(w, h, body, label):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
            f'viewBox="0 0 {w} {h}" role="img" aria-label="{escape(label)}">{body}</svg>\n')


def t(x, y, s, cls, size, fill, anchor="start", extra=""):
    return (f'<text x="{x}" y="{y}" class="{cls}" font-size="{size}" fill="{fill}" '
            f'text-anchor="{anchor}" {extra}>{escape(s)}</text>')


def house(cx, base, scale, stroke=TEXT, width=5):
    """The porch mark (64x64 viewBox) centred on cx, bottom at base."""
    s = scale
    x0, y0 = cx - 32 * s, base - 54 * s
    return (f'<g transform="translate({x0} {y0}) scale({s})" fill="none" stroke="{stroke}" '
            f'stroke-width="{width}" stroke-linecap="round" stroke-linejoin="round">'
            '<path d="M8 30 L32 10 L56 30"/><path d="M16 28 V54 H48 V28"/></g>')


# ---- hero ------------------------------------------------------------------

def hero():
    W, H = 1280, 560
    rnd = random.Random(7)
    stars = "".join(
        f'<circle cx="{rnd.uniform(0, W):.1f}" cy="{rnd.uniform(0, H * .62):.1f}" '
        f'r="{rnd.choice((.6, .8, 1, 1.3)):.1f}" fill="{TEXT}" opacity="{rnd.uniform(.12, .5):.2f}"/>'
        for _ in range(110))
    hx, hbase, hs = 960, 452, 4.2          # the house
    lx, ly = hx, hbase - (54 - 22) * hs    # its light (circle at 32,22 in the mark)
    pills = [
        ("demo.tunnel.porch.you.dev", ACCENT["porch"], 790, 150),
        ("wedding.tunnel.porch.you.dev", ACCENT["media"], 1090, 84),
        ("inbox.tunnel.porch.you.dev", ACCENT["drop"], 736, 240),
        ("mixtape.tunnel.porch.you.dev", ACCENT["music"], 1100, 190),
    ]
    pill_svg = ""
    for i, (txt, col, x, y) in enumerate(pills):
        w = 44 + len(txt) * 8.4
        pill_svg += (
            f'<g opacity=".92"><animateTransform attributeName="transform" type="translate" '
            f'values="0 0;0 {-5 if i % 2 else 5};0 0" dur="{6 + i}s" repeatCount="indefinite"/>'
            f'<rect x="{x - w / 2}" y="{y - 17}" width="{w}" height="34" rx="17" fill="{SURFACE}" '
            f'stroke="{col}" stroke-opacity=".55"/>'
            f'<circle cx="{x - w / 2 + 16}" cy="{y}" r="4" fill="{col}"/>'
            + t(x - w / 2 + 30, y + 5, txt, "m", 14, TEXT) + "</g>")
    body = (
        style(DISPLAY, UI, MONO)
        + '<defs>'
        f'<linearGradient id="sky" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#0C0A0E"/>'
        f'<stop offset=".7" stop-color="{GROUND}"/><stop offset="1" stop-color="#1A1410"/></linearGradient>'
        f'<radialGradient id="glow" cx="{lx}" cy="{ly}" r="430" gradientUnits="userSpaceOnUse">'
        f'<stop offset="0" stop-color="{LIGHT}" stop-opacity=".42"/>'
        f'<stop offset=".35" stop-color="#6B3A0A" stop-opacity=".22"/>'
        f'<stop offset="1" stop-color="{GROUND}" stop-opacity="0"/></radialGradient>'
        f'<linearGradient id="cone" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="{LIGHT}" stop-opacity=".30"/>'
        f'<stop offset="1" stop-color="{LIGHT}" stop-opacity="0"/></linearGradient>'
        f'<radialGradient id="earth" cx="{hx}" cy="{hbase}" r="420" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#0A0809"/><stop offset="1" stop-color="#0A0809" stop-opacity="0"/></radialGradient>'
        '<filter id="blur" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="10"/></filter>'
        '<clipPath id="card"><rect width="1280" height="560" rx="24"/></clipPath>'
        '</defs>'
        '<g clip-path="url(#card)">'
        f'<rect width="{W}" height="{H}" fill="url(#sky)"/>{stars}'
        f'<rect width="{W}" height="{H}" fill="url(#glow)"><animate attributeName="opacity" '
        'values="1;.82;1;.93;1" dur="7s" repeatCount="indefinite"/></rect>'
        # ground + steps under the house
        f'<rect x="{hx - 420}" y="{hbase}" width="840" height="{H - hbase}" fill="url(#earth)"/>'
        f'<path d="M{hx - 134} {hbase} L{hx + 134} {hbase} L{hx + 330} {H} L{hx - 330} {H} Z" fill="url(#cone)"/>'
        f'<rect x="{hx - 70}" y="{hbase}" width="140" height="10" rx="2" fill="{RAISED}"/>'
        f'<rect x="{hx - 92}" y="{hbase + 14}" width="184" height="10" rx="2" fill="{RAISED}" opacity=".7"/>'
        + house(hx, hbase, hs, TEXT, 4.2)
        + f'<circle cx="{lx}" cy="{ly}" r="30" fill="{LIGHT}" filter="url(#blur)" opacity=".9">'
        '<animate attributeName="opacity" values=".9;.6;.9;.75;.9" dur="7s" repeatCount="indefinite"/></circle>'
        f'<circle cx="{lx}" cy="{ly}" r="{5.5 * hs:.1f}" fill="{LIGHT}"/>'
        f'<circle cx="{lx - 6}" cy="{ly - 6}" r="6" fill="#FFE2A8" opacity=".8"/>'
        + pill_svg
        # copy
        + t(84, 150, "SELF-HOSTED  ·  BRING YOUR OWN DOMAIN", "m", 15, LIGHT, extra='letter-spacing="2.5"')
        + t(78, 296, "Porch", "d", 168, TEXT, extra='letter-spacing="-6"')
        + t(84, 364, "Leave the light on.", "d", 40, TEXT, extra='letter-spacing="-1"')
        + t(84, 410, "Anything on your machine, one command from", "u", 22, MUTED)
        + t(84, 440, "a real HTTPS link on your own domain.", "u", 22, MUTED)
        + f'<rect x="84" y="476" width="378" height="44" rx="12" fill="{SURFACE}" stroke="{LIGHT}" stroke-opacity=".35"/>'
        + t(104, 504, "$", "m", 17, LIGHT) + t(124, 504, "porch tunnel 3000 demo", "m", 17, TEXT)
        + f'<rect x="352" y="489" width="10" height="20" fill="{LIGHT}"><animate attributeName="opacity" '
          'values="1;1;0;0" dur="1.1s" repeatCount="indefinite"/></rect>'
        + f'</g><rect x=".5" y=".5" width="{W - 1}" height="{H - 1}" rx="24" fill="none" stroke="{TEXT}" stroke-opacity=".08"/>'
    )
    return svg(W, H, body, "Porch: leave the light on. Anything on your machine, one command "
                            "from a real HTTPS link on your own domain.")


# ---- terminal --------------------------------------------------------------

def terminal():
    W = 1280
    lines = [
        ("cmd", "porch tunnel 3000 demo --bg"),
        ("out", [("●", OK), ("  live  ", MUTED), ("https://demo.tunnel.porch.you.dev", ACCENT["porch"]),
                 ("   your dev server, real cert", FAINT)]),
        ("gap",),
        ("cmd", "porch drop inbox --bg"),
        ("out", [("●", OK), ("  live  ", MUTED), ("https://inbox.tunnel.porch.you.dev", ACCENT["drop"]),
                 ("   uploads land in ~/drops/inbox", FAINT)]),
        ("gap",),
        ("cmd", "porch media wedding --bg"),
        ("out", [("●", OK), ("  live  ", MUTED), ("https://wedding.tunnel.porch.you.dev", ACCENT["media"]),
                 ("   guests add, you curate", FAINT)]),
        ("gap",),
        ("cmd", "porch secure-entry stripe --save-to-secrets inf://prod/app/STRIPE_KEY --bg"),
        ("out", [("●", OK), ("  live  ", MUTED), ("https://entry-stripe.tunnel.porch.you.dev/…/", ACCENT["secret"]),
                 ("   one-time form", FAINT)]),
        ("gap",),
        ("cmd", "porch status"),
        ("out", [("  demo      ", TEXT), ("tunnel   ", MUTED), ("58m left", LIGHT)]),
        ("out", [("  inbox     ", TEXT), ("drop     ", MUTED), ("59m left", LIGHT)]),
        ("out", [("  wedding   ", TEXT), ("media    ", MUTED), ("keep-alive", OK)]),
    ]
    top, lh, gap = 92, 30, 12
    h = top + sum(gap if l[0] == "gap" else lh for l in lines) + 44
    body = style(MONO, MONO5, UI)
    body += (f'<rect x=".5" y=".5" width="{W - 1}" height="{h - 1}" rx="20" fill="{GROUND}" '
             f'stroke="{TEXT}" stroke-opacity=".10"/>'
             f'<path d="M.5 52 V20 A20 20 0 0 1 20 .5 H{W - 20} A20 20 0 0 1 {W - .5} 20 V52 Z" fill="{SURFACE}"/>'
             f'<line x1="0" y1="52" x2="{W}" y2="52" stroke="{TEXT}" stroke-opacity=".08"/>'
             + house(46, 38, .38, TEXT, 6)
             + f'<circle cx="46" cy="25.5" r="2.4" fill="{LIGHT}"/>'
             + t(72, 32, "porch", "u", 15, TEXT) + t(122, 32, "— ~/projects", "u", 15, FAINT))
    y = top
    for l in lines:
        if l[0] == "gap":
            y += gap
            continue
        if l[0] == "cmd":
            body += t(40, y, "❯", "m", 18, LIGHT) + t(66, y, l[1], "m", 18, TEXT, extra='font-weight="500"')
        else:
            x = 66
            spans = "".join(f'<tspan fill="{c}">{escape(s)}</tspan>' for s, c in l[1])
            body += f'<text x="{x}" y="{y}" class="m" font-size="16" xml:space="preserve">{spans}</text>'
        y += lh
    return svg(W, h, body, "Terminal: porch tunnel, drop, media and secure-entry each print a live "
                           "HTTPS link on your domain; porch status lists them.")


# ---- apps ------------------------------------------------------------------

APPS = [
    ("tunnel", "porch", "Your localhost, at a real URL", "Auto-expiry, extend or stop from the panel"),
    ("serve", "serve", "A folder becomes a website", "No dotfiles, no symlink escapes, sandboxed"),
    ("drop", "drop", "Drag, drop, done", "Guests upload; only you can list or download"),
    ("media", "media", "Photos + video, together", "Real streaming and seeking, even on iPhone"),
    ("photos", "media", "A gallery anyone can add to", "Delete and reorder stay yours"),
    ("music", "music", "Waveforms. Cover art. Vibes.", "Play-only for guests, uploads for you"),
    ("secure-entry", "secret", "Secrets that skip the chat", "Straight to Infisical, 1Password or a 0600 file"),
    ("paste", "text", "Text, highlighted", "Pipe anything in"),
    ("exchange", "text", "Copy box or paste box", "Big text, both directions"),
    ("form", "text", "A quick web form", "Submissions arrive as JSON"),
    ("chat", "text", "A chat UI for your local LLM", "llama.cpp-compatible"),
    ("qr · snap · shorten", "serve", "The little things", "QR pages, screenshots, short links"),
]


def apps():
    W, cols, cw, ch, g, pad = 1280, 3, 392, 132, 20, 32
    rows = (len(APPS) + cols - 1) // cols
    h = pad * 2 + rows * ch + (rows - 1) * g
    body = style(DISPLAY, UI, UI4, MONO5)
    body += f'<rect width="{W}" height="{h}" rx="24" fill="{GROUND}"/>'
    for i, (cmd, acc, head, sub) in enumerate(APPS):
        c = ACCENT[acc]
        x = pad + (i % cols) * (cw + g)
        y = pad + (i // cols) * (ch + g)
        body += (f'<g><rect x="{x}" y="{y}" width="{cw}" height="{ch}" rx="16" fill="{SURFACE}" '
                 f'stroke="{TEXT}" stroke-opacity=".08"/>'
                 f'<rect x="{x}" y="{y + 22}" width="4" height="34" rx="2" fill="{c}"/>'
                 f'<circle cx="{x + cw - 30}" cy="{y + 36}" r="22" fill="{c}" opacity=".10"/>'
                 f'<circle cx="{x + cw - 30}" cy="{y + 36}" r="6" fill="{c}"/>'
                 + t(x + 24, y + 46, cmd, "m", 20, c, extra='font-weight="500"')
                 + t(x + 24, y + 86, head, "d", 21, TEXT)
                 + t(x + 24, y + 112, sub, "u", 15, MUTED, extra='font-weight="400"')
                 + "</g>")
    return svg(W, h, body, "The Porch apps: tunnel, serve, drop, media, photos, music, secure-entry, "
                           "paste, exchange, form, chat, and qr/snap/shorten.")


# ---- how it works ----------------------------------------------------------

def flow():
    W, H = 1280, 300
    body = style(DISPLAY, UI, UI4, MONO)
    body += (f'<rect width="{W}" height="{H}" rx="24" fill="{GROUND}"/>'
             '<defs><marker id="ah" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="8" markerHeight="8" '
             f'orient="auto"><path d="M0 0 L10 5 L0 10 Z" fill="{LIGHT}"/></marker></defs>')
    nodes = [
        (150, "Anyone", "a phone, a friend,", "your group chat", TEXT),
        (490, "your domain", "HAProxy · Let's Encrypt", "TLS ends here, at home", LIGHT),
        (830, "frp", "one tunnel per app,", "each device its own key", ACCENT["text"]),
        (1130, "localhost:3000", "the thing you", "are working on", OK),
    ]
    for x, title, a, b, c in nodes:
        body += (f'<rect x="{x - 125}" y="70" width="250" height="132" rx="18" fill="{SURFACE}" '
                 f'stroke="{c}" stroke-opacity=".45"/>'
                 + t(x, 116, title, "d" if title != "localhost:3000" else "m", 24, c, "middle")
                 + t(x, 150, a, "u", 15, MUTED, "middle", 'font-weight="400"')
                 + t(x, 172, b, "u", 15, MUTED, "middle", 'font-weight="400"'))
    for x1, x2 in ((275, 365), (615, 705), (955, 1005)):
        body += (f'<line x1="{x1 + 6}" y1="136" x2="{x2 - 8}" y2="136" stroke="{LIGHT}" stroke-width="2.5" '
                 'stroke-dasharray="6 6" marker-end="url(#ah)">'
                 '<animate attributeName="stroke-dashoffset" values="24;0" dur="1.2s" repeatCount="indefinite"/></line>')
    body += (t(150, 248, "https://demo.tunnel.porch.you.dev", "m", 13, FAINT, "middle")
             + t(660, 248, "no open ports?  a $4 relay forwards the encrypted bytes; your keys stay home",
                 "u", 15, FAINT, "middle", 'font-weight="400"'))
    return svg(W, H, body, "How it works: a visitor reaches your domain, HAProxy terminates TLS at home, "
                           "frp carries the request to the app on your machine.")


def main():
    for name, fn in (("hero", hero), ("terminal", terminal), ("apps", apps), ("flow", flow)):
        path = os.path.join(HERE, name + ".svg")
        with open(path, "w", encoding="utf-8") as f:
            f.write(fn())
        print(f"{path}  {os.path.getsize(path) // 1024} KB")


if __name__ == "__main__":
    main()

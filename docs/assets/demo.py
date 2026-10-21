#!/usr/bin/env python3
"""Build docs/assets/demo.svg: the README's 20-second story, as an animated SVG.

One command shares a photo end-to-end encrypted; a friend opens it; an hour
later the door has closed and they ask to reopen; the owner taps Allow on a
lock-screen notification and their page comes back. SMIL only (GitHub shows
an <img> SVG with its animations but never runs scripts), fonts and the two
screenshots embedded as data: URIs, so the file stands alone.

The screenshots are the showcase's own (docs/showcase/shots), recompressed
smaller. Re-run after changing the copy or the timing:

    python3 docs/assets/demo.py
"""

import base64
import io
import os
import sys

from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from build import (ACCENT, DISPLAY, FAINT, GROUND, LIGHT, MONO, MONO5, MUTED,  # noqa: E402
                   OK, RAISED, SURFACE, TEXT, UI, UI4, escape, house, style, svg, t)

SHOTS = os.path.join(HERE, "..", "showcase", "shots")
D = 20.0                      # one loop, seconds
W, H = 1280, 740
PX, PY, PW = 900, 52, 300     # phone screen origin and width
SCALE = PW / 780              # the shots are 780 px wide
PH = round(1688 * SCALE)
HOST = "harbor-sunset-71b0.tunnel.porch.you.dev"
CMD = "porch share --e2e harbor-sunset.jpg --expires 1h"


def shot(name, width=600, quality=68):
    im = Image.open(os.path.join(SHOTS, name)).convert("RGB")
    im = im.resize((width, round(im.height * width / im.width)), Image.LANCZOS)
    buf = io.BytesIO()
    im.save(buf, "WEBP", quality=quality, method=6)
    return "data:image/webp;base64," + base64.b64encode(buf.getvalue()).decode()


def track(points, attr="opacity"):
    """An <animate> over the whole loop through (time, value) points."""
    pts = sorted(points)
    if pts[0][0] > 0:
        pts.insert(0, (0, pts[0][1]))
    if pts[-1][0] < D:
        pts.append((D, pts[-1][1]))
    kt, vals, last = [], [], -1.0
    for tm, v in pts:
        k = max(tm / D, last + 1e-4)
        kt.append(f"{min(k, 1):.4f}")
        vals.append(str(v))
        last = k
    kt[-1] = "1"
    return (f'<animate attributeName="{attr}" dur="{D}s" repeatCount="indefinite" '
            f'keyTimes="{";".join(kt)}" values="{";".join(vals)}"/>')


def shown(a, b, fade=0.35):
    """Visible from a to b (fading in and out)."""
    pts = [(max(a - fade, 0), 0), (a, 1), (b, 1), (min(b + fade, D), 0)]
    if a <= 0:
        pts = [(0, 1), (b, 1), (min(b + fade, D), 0)]
    return track(pts)


def group(a, b, inner, fade=0.35):
    return f'<g opacity="0">{shown(a, b, fade)}{inner}</g>'


def ripple(cx, cy, at):
    """A tap: a ring that grows and fades."""
    return (f'<circle cx="{cx}" cy="{cy}" r="10" fill="{TEXT}" opacity="0">'
            + track([(at - .01, 0), (at, .55), (at + .6, 0)])
            + track([(at - .01, 10), (at, 10), (at + .6, 34)], "r") + '</circle>')


# ---- left: terminal ---------------------------------------------------------

def terminal():
    x0, y0, w, h = 40, 52, 800, 214
    cw = 0.6 * 19                       # Geist Mono advance: 600/1000 em
    out = (f'<rect x="{x0}" y="{y0}" width="{w}" height="{h}" rx="18" fill="{GROUND}" '
           f'stroke="{TEXT}" stroke-opacity=".12"/>'
           f'<path d="M{x0} {y0 + 44} V{y0 + 18} A18 18 0 0 1 {x0 + 18} {y0} H{x0 + w - 18} '
           f'A18 18 0 0 1 {x0 + w} {y0 + 18} V{y0 + 44} Z" fill="{SURFACE}"/>'
           + house(x0 + 28, y0 + 31, .3, TEXT, 6)
           + f'<circle cx="{x0 + 28}" cy="{y0 + 21}" r="2" fill="{LIGHT}"/>'
           + t(x0 + 50, y0 + 27, "porch — ~/photos", "u", 14, FAINT))
    # the typed command, revealed one character at a time
    n = len(CMD)
    t0, t1 = .4, 2.6
    widths = [f"{i * cw:.1f}" for i in range(n + 1)]
    kts = [f"{(t0 + (t1 - t0) * i / n) / D:.4f}" for i in range(n + 1)]
    out += ('<clipPath id="typed"><rect x="{}" y="{}" height="30" width="0">'
            '<animate attributeName="width" dur="{}s" repeatCount="indefinite" calcMode="discrete" '
            'keyTimes="0;{};1" values="0;{};{}"/></rect></clipPath>').format(
        x0 + 52, y0 + 66, D, ";".join(kts), ";".join(widths), widths[-1])
    cy = y0 + 88
    out += t(x0 + 28, cy, "❯", "m", 19, LIGHT)
    out += f'<g clip-path="url(#typed)">{t(x0 + 52, cy, CMD, "m", 19, TEXT, extra='font-weight="500"')}</g>'
    # cursor follows the typing, then blinks at the end of the line
    cur_vals = [f"{x0 + 52 + i * cw:.1f}" for i in range(n + 1)]
    out += ('<rect y="{}" width="10" height="21" fill="{}" x="{}">'
            '<animate attributeName="x" dur="{}s" repeatCount="indefinite" calcMode="discrete" '
            'keyTimes="0;{};1" values="{};{};{}"/>{}</rect>').format(
        cy - 17, LIGHT, x0 + 52, D, ";".join(kts), cur_vals[0], ";".join(cur_vals), cur_vals[-1],
        track([(0, 1), (2.9, 1), (2.91, 0)]))
    lines = [
        (2.9, [("  harbor-sunset.jpg -> seal, ", MUTED), ("end-to-end encrypted (image/jpeg)", FAINT)]),
        (3.3, [("●", OK), ("  link  ", MUTED), (f"https://{HOST}/#k=Qm9yY2gh…", ACCENT["secret"])]),
        (3.7, [("  closes in 1h", LIGHT), (" · the box holds ciphertext; the key is in the link", FAINT)]),
    ]
    y = cy + 38
    for at, spans in lines:
        sp = "".join(f'<tspan fill="{c}">{escape(s)}</tspan>' for s, c in spans)
        out += (f'<text x="{x0 + 28}" y="{y}" class="m" font-size="15.5" xml:space="preserve" opacity="0">'
                + track([(at - .01, 0), (at, 1), (D - .35, 1), (D, 0)]) + sp + '</text>')
        y += 28
    return out


# ---- left: the steps --------------------------------------------------------

STEPS = [
    (0, 4.6, "One command", "Sealed on your box, served on your own domain."),
    (4.6, 9.4, "A friend opens the link", "Decrypted in their browser. The key never reaches the server."),
    (9.4, 14.2, "An hour later, the door is closed", "The porch light is off. They tap Ask to reopen."),
    (14.2, 20, "You answer from your lock screen", "Allow 1h, and their page comes back by itself."),
]


def steps():
    out = ""
    y = 330
    for i, (a, b, head, sub) in enumerate(STEPS):
        num = str(i + 1)
        dim = (f'<circle cx="62" cy="{y - 7}" r="17" fill="none" stroke="{TEXT}" stroke-opacity=".18"/>'
               + t(62, y - 1, num, "m", 16, FAINT, "middle")
               + t(98, y - 8, head, "d", 25, TEXT, extra='opacity=".38"')
               + t(98, y + 20, sub, "u", 17, MUTED, extra='opacity=".45" font-weight="400"'))
        lit = (f'<rect x="30" y="{y - 40}" width="810" height="76" rx="16" fill="{SURFACE}"/>'
               f'<rect x="30" y="{y - 26}" width="4" height="48" rx="2" fill="{LIGHT}"/>'
               f'<circle cx="62" cy="{y - 7}" r="17" fill="{LIGHT}"/>'
               + t(62, y - 1, num, "m", 16, GROUND, "middle", 'font-weight="500"')
               + t(98, y - 8, head, "d", 25, TEXT)
               + t(98, y + 20, sub, "u", 17, MUTED, extra='font-weight="400"'))
        end = b if b < D else D - .35
        out += dim + group(a, end, lit, .3)
        y += 92
    out += t(40, 712, "All on your own domain. No account, no cloud, one box.", "u", 17, FAINT,
             extra='font-weight="400"')
    return out


# ---- right: the phone -------------------------------------------------------

def lock_screen():
    """The owner's phone: a lock screen with Porch's Ask-to-reopen notification."""
    cx = PX + PW / 2
    nx, ny, nw = PX + 14, PY + 236, PW - 28
    note = (f'<rect x="{nx}" y="{ny}" width="{nw}" height="166" rx="20" fill="{RAISED}" fill-opacity=".92" '
            f'stroke="{TEXT}" stroke-opacity=".10"/>'
            f'<rect x="{nx + 14}" y="{ny + 14}" width="26" height="26" rx="7" fill="{GROUND}"/>'
            + house(nx + 27, ny + 36, .26, TEXT, 7)
            + f'<circle cx="{nx + 27}" cy="{ny + 25.5}" r="2" fill="{LIGHT}"/>'
            + t(nx + 50, ny + 32, "PORCH", "u", 12, MUTED, extra='letter-spacing="1.2"')
            + t(nx + nw - 14, ny + 32, "now", "u", 12, FAINT, "end")
            + t(nx + 14, ny + 66, "Asked to reopen", "u", 16, TEXT, extra='font-weight="500"')
            + t(nx + 14, ny + 88, "harbor-sunset-71b0 · “Sam”", "u", 14, MUTED, extra='font-weight="400"'))
    bw = (nw - 38) / 2
    acts = (f'<rect x="{nx + 14}" y="{ny + 108}" width="{bw}" height="42" rx="12" fill="{LIGHT}"/>'
            + t(nx + 14 + bw / 2, ny + 135, "Allow 1h", "u", 15, GROUND, "middle", 'font-weight="500"')
            + f'<rect x="{nx + 24 + bw}" y="{ny + 108}" width="{bw}" height="42" rx="12" fill="{GROUND}" '
              f'fill-opacity=".6" stroke="{TEXT}" stroke-opacity=".14"/>'
            + t(nx + 24 + bw + bw / 2, ny + 135, "Allow 24h", "u", 15, TEXT, "middle", 'font-weight="500"'))
    done = (f'<rect x="{nx + 14}" y="{ny + 108}" width="{nw - 28}" height="42" rx="12" fill="{GROUND}" '
            f'fill-opacity=".6"/>'
            f'<circle cx="{nx + 34}" cy="{ny + 129}" r="5" fill="{OK}"/>'
            + t(nx + 48, ny + 134, "Reopened for 1 hour", "u", 15, TEXT, extra='font-weight="500"'))
    slide = ('<animateTransform attributeName="transform" type="translate" dur="{}s" repeatCount="indefinite" '
             'keyTimes="0;{:.4f};{:.4f};1" values="0 -70;0 -70;0 0;0 0"/>').format(D, 14.6 / D, 15.0 / D)
    return (f'<rect x="{PX}" y="{PY}" width="{PW}" height="{PH}" fill="url(#wall)"/>'
            + t(cx, PY + 64, "Tuesday", "u", 15, TEXT, "middle", 'opacity=".8" font-weight="400"')
            + t(cx, PY + 150, "9:41", "d", 82, TEXT, "middle", 'letter-spacing="-2"')
            + f'<g opacity="0">{track([(14.59, 0), (14.6, 0), (15.0, 1), (D, 1)])}{slide}{note}'
            + group(0, 16.55, acts, .15)
            + group(16.6, D - .35, done, .2)
            + ripple(nx + 14 + bw / 2, ny + 129, 16.2) + '</g>')


def phone():
    seal = shot("seal-photo-phone-night.webp")
    closed = shot("door-closed-phone-night.webp")
    img = lambda href: (f'<image x="{PX}" y="{PY}" width="{PW}" height="{PH}" '
                        f'preserveAspectRatio="xMidYMin slice" href="{href}"/>')
    f = SCALE
    # the closed-door shot came from another door: put this story's host on it
    patch = (f'<rect x="{PX + 38 * f:.1f}" y="{PY + 336 * f:.1f}" width="{PW - 60 * f:.1f}" height="{30 * f:.1f}" '
             f'fill="#131013"/>' + t(PX + 42 * f, PY + 361 * f, HOST, "m", 26.6 * f, LIGHT))
    # 0-4.8: a message arrives with the link
    msg_y = PY + 380
    message = (f'<rect x="{PX}" y="{PY}" width="{PW}" height="{PH}" fill="{GROUND}"/>'
               + t(PX + PW / 2, PY + 70, "Sam", "u", 17, TEXT, "middle", 'font-weight="500"')
               + t(PX + PW / 2, PY + 90, "Messages", "u", 12, FAINT, "middle", 'font-weight="400"')
               + f'<line x1="{PX}" y1="{PY + 110}" x2="{PX + PW}" y2="{PY + 110}" stroke="{TEXT}" stroke-opacity=".08"/>'
               + group(1.2, 4.8, f'<rect x="{PX + 16}" y="{msg_y - 120}" width="190" height="40" rx="18" fill="{RAISED}"/>'
                       + t(PX + 32, msg_y - 94, "send me that photo?", "u", 15, TEXT, extra='font-weight="400"'), .25)
               + group(3.8, 4.8, f'<rect x="{PX + 44}" y="{msg_y - 64}" width="{PW - 60}" height="92" rx="18" fill="{LIGHT}"/>'
                       + t(PX + 60, msg_y - 38, "here, it's sealed:", "u", 15, GROUND, extra='font-weight="500"')
                       + t(PX + 60, msg_y - 14, "https://harbor-sunset-71b0", "m", 12.5, GROUND)
                       + t(PX + 60, msg_y + 4, ".tunnel.porch.you.dev/#k=…", "m", 12.5, GROUND), .25)
               + ripple(PX + PW / 2 + 10, msg_y - 18, 4.45))
    later = (f'<rect x="{PX}" y="{PY}" width="{PW}" height="{PH}" fill="{GROUND}" fill-opacity=".94"/>'
             + t(PX + PW / 2, PY + PH / 2, "one hour later", "d", 30, TEXT, "middle"))
    toast = (f'<rect x="{PX + 20}" y="{PY + PH - 68}" width="{PW - 40}" height="44" rx="14" fill="{RAISED}" '
             f'stroke="{OK}" stroke-opacity=".5"/>'
             f'<circle cx="{PX + 42}" cy="{PY + PH - 46}" r="5" fill="{OK}"/>'
             + t(PX + 56, PY + PH - 41, "The door is open again", "u", 15, TEXT, extra='font-weight="500"'))
    screen = (group(0, 4.8, message, .3)
              + group(4.8, 9.4, img(seal), .35)
              + group(10.0, 14.2, img(closed) + patch + ripple(PX + 390 * f, PY + 1305 * f, 12.7), .35)
              + group(9.4, 10.3, later, .35)
              + group(14.2, 18.2, lock_screen(), .35)
              + group(18.2, D - .35, img(seal) + toast, .35))
    label = lambda a, b, s: group(a, b, t(PX + PW / 2, PY - 22, s, "m", 14, MUTED, "middle",
                                         'letter-spacing="1.5"'), .3)
    bez = 12
    return (f'<rect x="{PX - bez}" y="{PY - bez}" width="{PW + 2 * bez}" height="{PH + 2 * bez}" rx="46" '
            f'fill="#0B0A0C" stroke="{TEXT}" stroke-opacity=".16"/>'
            f'<clipPath id="scr"><rect x="{PX}" y="{PY}" width="{PW}" height="{PH}" rx="36"/></clipPath>'
            f'<g clip-path="url(#scr)"><rect x="{PX}" y="{PY}" width="{PW}" height="{PH}" fill="{GROUND}"/>'
            f'{screen}</g>'
            + label(0, 14.2, "A FRIEND'S PHONE") + label(14.2, 18.2, "YOUR PHONE")
            + label(18.2, D - .35, "THEIR PHONE, AGAIN"))


def demo():
    defs = ('<defs><linearGradient id="wall" x1="0" y1="0" x2=".4" y2="1">'
            '<stop offset="0" stop-color="#2A1B33"/><stop offset=".55" stop-color="#1A1420"/>'
            f'<stop offset="1" stop-color="#5A3410"/></linearGradient></defs>')
    body = (style(DISPLAY, UI, UI4, MONO, MONO5) + defs
            + f'<rect width="{W}" height="{H}" rx="24" fill="#0E0C10"/>'
            + f'<rect x=".5" y=".5" width="{W - 1}" height="{H - 1}" rx="24" fill="none" stroke="{TEXT}" stroke-opacity=".08"/>'
            + terminal() + steps() + phone())
    return svg(W, H, body, "A 20-second demo: porch share --e2e seals a photo and prints a link on your "
                           "domain; a friend opens it and it decrypts in their browser; an hour later the "
                           "door has closed and they ask to reopen; you tap Allow 1h on your lock screen "
                           "and their page comes back.")


def main():
    path = os.path.join(HERE, "demo.svg")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(demo())
    print(f"{path}  {os.path.getsize(path) // 1024} KB")


if __name__ == "__main__":
    main()

""""Your porch is ready": what the CLI prints and the web wizard shows when
every setup step is done.

    info = ready.info(cfg)       # {"urls": {...}, "pocket_signin": url, "steps": [...], "next": [...]}
    print(ready.text(cfg))       # the CLI summary, with a terminal QR when python-qrcode is there

The phone QR points at Pocket's /__porch/start (steps/pocket.signin_url):
a phone with no owner device is sent to the auth host's /login, enrolls
with the admin password, and the handoff brings it back into Pocket signed
in, where it can be installed to the home screen.
"""

from .steps import pocket as _pocket

URL_LABELS = (("landing", "Landing page"), ("admin", "Admin sign-in"), ("panel", "Tunnel panel"),
              ("pocket", "Porch app (Pocket)"), ("tunnel_example", "Your apps live at"))

PHONE_STEPS = (
    "Scan the code with your phone's camera.",
    "Sign in: type the admin password once to enroll this phone as the owner.",
    "Install: Android shows an Install button; on iPhone tap Share, then Add to Home Screen.",
)

NEXT = (
    ("Open your first door", "bin/tunnel 3000 myapp --bg"),
    ("Or share a file", "bin/porch share report.pdf"),
)


def urls(cfg):
    return {"landing": f"https://{cfg.landing_host}/", "admin": cfg.auth_url("/auth/"),
            "panel": f"https://{cfg.panel_host}/", "pocket": _pocket.pocket_url(cfg),
            "tunnel_example": cfg.tunnel_url("myapp")}


def info(cfg):
    return {"urls": urls(cfg), "pocket_signin": _pocket.signin_url(cfg),
            "steps": list(PHONE_STEPS), "next": [{"label": a, "command": b} for a, b in NEXT]}


def text(cfg, qr=True):
    """The CLI summary. qr=False leaves the terminal QR out."""
    u = urls(cfg)
    width = max(len(label) for _, label in URL_LABELS)
    lines = ["", "Your porch is ready.", ""]
    lines += [f"  {label:<{width}}  {u[k]}" for k, label in URL_LABELS]
    lines += ["", "Put Porch on your phone:"]
    lines += [f"  {i}. {s}" for i, s in enumerate(PHONE_STEPS, 1)]
    signin = _pocket.signin_url(cfg)
    lines += ["", f"  {signin}"]
    if qr:
        from .web import qr_text
        art = qr_text(signin)
        if art:
            lines += ["", art]
        else:
            lines += ["  (install python3-qrcode for a QR code here)"]
    lines += ["", "Next:"]
    lines += [f"  {a}: {b}" for a, b in NEXT]
    return "\n".join(lines) + "\n"

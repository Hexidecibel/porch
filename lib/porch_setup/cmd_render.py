"""porch render haproxy|frps|units [--profile fresh|adopt] [--out PATH] [--against CFG] [--json]

haproxy  print (or --out FILE) the rendered HAProxy config. --against reads a
         live config (falls back to `sudo -n cat` when it is not readable),
         prints the adopt diff and exits 5 when anything is missing,
         different or out of order beyond config [adopt] allow.
frps     the frps.toml (the dashboard password is a placeholder here; the
         frps setup step generates the real one). --out writes it 0600.
units    the systemd user units; --out DIR writes one file per unit.
"""

import argparse
import json
import os
import subprocess
import sys

from . import haproxy_diff, render

PLACEHOLDER_PASSWORD = "SET-BY-PORCH-SETUP"


def read_config_file(path, sudo=True):
    """Text of `path`, read directly or with `sudo -n cat` (read-only)."""
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except PermissionError:
        if not sudo:
            raise
    p = subprocess.run(["sudo", "-n", "cat", path], capture_output=True, text=True, timeout=30)
    if p.returncode != 0:
        raise OSError(f"cannot read {path}: {p.stderr.strip() or 'sudo -n cat failed'}")
    return p.stdout


def _write(path, text, mode):
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def main(argv, cfg=None, out=None):
    out = out or sys.stdout
    p = argparse.ArgumentParser(prog="porch render", description="Render porch configs.")
    p.add_argument("what", choices=["haproxy", "frps", "units"])
    p.add_argument("--profile", choices=sorted(render.PROFILES),
                   help="default: config install.mode")
    p.add_argument("--out", help="file (haproxy, frps) or directory (units)")
    p.add_argument("--against", metavar="CFG", help="haproxy: adopt diff against a live config")
    p.add_argument("--relay", action="store_true", help="haproxy: add the relay ingress binds")
    p.add_argument("--json", action="store_true", help="with --against: JSON report")
    p.add_argument("--quiet", "-q", action="store_true", help="with --against: hide allowed findings")
    args = p.parse_args(argv)
    if cfg is None:
        import porch_config
        cfg = porch_config.get()
    try:
        if args.what == "haproxy":
            text = render.render_haproxy(cfg, args.profile, relay=args.relay or None)
            if args.against:
                live = read_config_file(args.against)
                rep = haproxy_diff.diff(text, live, cfg.adopt_allow)
                if args.json:
                    print(json.dumps(rep.as_dict(), indent=2), file=out)
                else:
                    print(rep.text(show_allowed=not args.quiet), file=out)
                return 0 if rep.ok else 5
            if args.out:
                _write(args.out, text, 0o644)
            else:
                out.write(text)
            return 0
        if args.what == "frps":
            text = render.render_frps(cfg, PLACEHOLDER_PASSWORD, args.profile)
            if args.out:
                _write(args.out, text, 0o600)
            else:
                out.write(text)
            return 0
        units = render.render_units(cfg, args.profile)
        if args.out:
            for name, text in units.items():
                _write(os.path.join(args.out, name), text, 0o644)
                print(os.path.join(args.out, name), file=out)
        else:
            for name, text in units.items():
                out.write(f"# ---- {name}\n{text}\n")
        return 0
    except (render.RenderError, OSError) as e:
        print(f"porch render: {e}", file=sys.stderr)
        return 2

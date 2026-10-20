"""Helpers shared by W1's steps (never registered: the name starts with _)."""

import json
import os
import re

from ..engine import Check

PORCH_PORTS = (80, 443, 7000)
RELAY_MODES = ("oracle", "paid", "byo", "relay")


def https_code(ctx, host, path="/", ip="127.0.0.1", timeout=10):
    """(http status or None, curl error text) for https://host/path sent to
    `ip`:443 with SNI = host and normal certificate verification."""
    r = ctx.run.run(["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                     "--max-time", str(timeout), "--resolve", f"{host}:443:{ip}",
                     f"https://{host}{path}"], mutating=False, timeout=timeout + 5)
    code = r.stdout.strip()
    if r.ok and code.isdigit() and code != "000":
        return int(code), ""
    return None, (r.stderr.strip().splitlines() or [f"curl exit {r.returncode}"])[-1]


def https_check(ctx, code_name, host, path="/", ok_codes=(200,), ip="127.0.0.1"):
    code, err = https_code(ctx, host, path, ip)
    if code in ok_codes:
        return Check(True, code_name, f"https://{host}{path} -> {code}")
    if code is None:
        return Check(False, code_name, f"https://{host}{path} via {ip}:443 failed: {err}",
                     "is HAProxy up with a certificate covering this name?")
    return Check(False, code_name, f"https://{host}{path} -> {code}, want {'/'.join(map(str, ok_codes))}")


def http_code(ctx, url, timeout=5):
    """Status of a plain local GET through ctx.http (urlopen-compatible), or None."""
    import urllib.error
    try:
        with ctx.http(url, timeout=timeout) as resp:
            return getattr(resp, "status", None) or resp.getcode()
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:  # noqa: BLE001 - refused, timeout, DNS
        return None


def read_root_file(ctx, path):
    """Text of a file that may be root-only: direct read, else `sudo -n cat`
    (read-only). Raises OSError."""
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except PermissionError:
        pass
    r = ctx.run.run(["cat", path], sudo=True, mutating=False)
    if not r.ok:
        raise OSError(f"cannot read {path}: {r.stderr.strip() or 'sudo -n cat failed'}")
    return r.stdout


def listeners(ctx):
    """{port: process name or ''} for TCP listeners (ss; sudo -n for names)."""
    r = ctx.run.run(["ss", "-ltnpH"], sudo=True, mutating=False)
    if not r.ok:
        r = ctx.run.run(["ss", "-ltnpH"], mutating=False)
    out = {}
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        m = re.search(r":(\d+)$", parts[3])
        if not m:
            continue
        port = int(m.group(1))
        name = re.search(r'users:\(\("([^"]+)"', line)
        out.setdefault(port, name.group(1) if name else "")
    return out


def version_tuple(text):
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text or "")
    return tuple(int(x or 0) for x in m.groups()) if m else None


def app_data_dir(ctx):
    """The apps' data dir (devices.json, .home-frpc-token): <repo>/data, or
    $PORCH_APP_DATA. Not ctx.data_dir, which is setup's own state dir and
    moves with $PORCH_SETUP_DIR."""
    return ctx.env.get("PORCH_APP_DATA") or os.path.join(ctx.repo_dir, "data")


def devices(ctx):
    path = os.path.join(app_data_dir(ctx), "devices.json")
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def relay_mode(ctx):
    """True when the active connection mode is a relay (W3's connection step
    output `mode`, or state["connection"]["active"])."""
    mode = ctx.outputs("connection").get("mode") or (ctx.state.connection or {}).get("active")
    if isinstance(mode, dict):
        mode = mode.get("mode")
    return mode in RELAY_MODES


def user_unit_dir(ctx):
    base = ctx.env.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "systemd", "user")


def adopted(ctx):
    return ctx.adopt or getattr(ctx.cfg, "install_mode", "fresh") == "adopt"


def user_bus_env(ctx):
    """Env for `systemctl --user`. sudo (and `systemd-run --uid`) drop
    XDG_RUNTIME_DIR and DBUS_SESSION_BUS_ADDRESS, so a wizard started with
    sudo found "no systemd user session" even with linger on (found on the
    e2e VPS). Point them at /run/user/<uid>, where linger keeps the user
    manager running."""
    uid = os.getuid()
    run = ctx.env.get("XDG_RUNTIME_DIR") or f"/run/user/{uid}"
    return {"XDG_RUNTIME_DIR": run,
            "DBUS_SESSION_BUS_ADDRESS": ctx.env.get("DBUS_SESSION_BUS_ADDRESS")
            or f"unix:path={run}/bus"}


def systemctl_user(ctx, *args, wait=0, **kw):
    """Run `systemctl --user ARGS` with the user bus found (see user_bus_env).
    wait: seconds to retry while the user manager is still starting (right
    after `loginctl enable-linger`)."""
    env = user_bus_env(ctx)
    r = ctx.run.run(["systemctl", "--user", *args], env=env, **kw)
    t = 0
    while not r.ok and t < wait:
        ctx.sleep(1)
        t += 1
        r = ctx.run.run(["systemctl", "--user", *args], env=env, **kw)
    return r

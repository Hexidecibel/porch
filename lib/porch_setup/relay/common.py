"""Shared by the relay modes (paid, byo, oracle).

A relay is a dumb TCP pass-through: the relay host runs only frps
(porch-relay-frps.service, control port CONTROL_PORT, its own token,
allowPorts 80/443/frp_port, no dashboard). Home runs the porch-relay user unit,
an frpc that opens tcp proxies on the relay's 80, 443 and frp_port pointing
back at home: 80/443 into HAProxy's loopback accept-proxy binds with a PROXY
v2 header (client addresses survive), frp_port into home's own frps. TLS
terminates at home, so the certificate and key never leave it.

Remote devices' frpc then reach home's frps from 127.0.0.1, so a relay is
only safe with the localhost bypass off (bypass_on); every relay mode refuses
while it is on.
"""

import os
import secrets
import shlex
import socket
import string
import urllib.request

from .. import render
from ..engine import Check, StepError
from ..state import REPO_DIR

FRP_VERSION = "0.67.0"
FRP_SHA256 = {   # official release tarballs (frp_sha256_checksums.txt)
    "amd64": "f8629ca7ca56b8e7e7a9903779b8d5c47c56ad1b75b99b2d7138477acc4c7105",
    "arm64": "0e9683226acdcbbb2ac8d073f35ba8be2a8b1e7584684d2073f39d337ebd6de7",
}
CONTROL_PORT = 7835
TAG = "porch-relay"
UNIT = "porch-relay.service"
FRPC_NAME = "relay-frpc.toml"
PROXIES = ("porch-relay-http", "porch-relay-https", "porch-relay-frp")
TEMPLATES = os.path.join(REPO_DIR, "config", "templates")


def bypass_on(ctx):
    """authserver.localhost_bypass_enabled for this run's env + config."""
    v = (ctx.env.get("PORCH_LOCALHOST_BYPASS") or "").strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return bool(getattr(ctx.cfg, "localhost_bypass", False))


BYPASS_REASON = ("the localhost frpc bypass is on: through a relay every remote device reaches "
                 "frps from 127.0.0.1 and would skip auth")
BYPASS_HINT = ("set [adopt] localhost_bypass = false in config/porch.toml (or "
               "PORCH_LOCALHOST_BYPASS=0) and restart the auth server; see CLAUDE.md "
               "'Home frpc token and the localhost bypass'")


def refuse_bypass(ctx):
    if bypass_on(ctx):
        raise StepError("connect.relay.bypass", BYPASS_REASON, BYPASS_HINT)


def new_token():
    return secrets.token_urlsafe(32)


def _tmpl(name, values, where):
    with open(os.path.join(TEMPLATES, name), encoding="utf-8") as f:
        text = f.read()
    try:
        return string.Template(text).substitute(values)
    except (KeyError, ValueError) as e:
        raise StepError("connect.relay.template", f"{where}: {e}") from None


def _check_token(token):
    if not token or any(ch not in string.ascii_letters + string.digits + "-_" for ch in token):
        raise StepError("connect.relay.token", "relay token must be url-safe base64")


def render_install(token, mode, frp_port, ssh_from="", ssh_pubkey=""):
    """install-relay.sh for `mode` (paid resets ufw; byo/oracle only add rules)."""
    _check_token(token)
    if mode not in ("paid", "byo", "oracle"):
        raise StepError("connect.relay.mode", f"unknown relay mode {mode!r}")
    q = shlex.quote
    return _tmpl("relay/install-relay.sh.tmpl", {
        "mode": q(mode), "ssh_from": q(ssh_from or ""), "ssh_pubkey": q(ssh_pubkey or ""),
        "frp_version": q(FRP_VERSION), "sha_amd64": q(FRP_SHA256["amd64"]),
        "sha_arm64": q(FRP_SHA256["arm64"]), "frp_port": int(frp_port),
        "control_port": CONTROL_PORT, "token": token}, "install-relay.sh")


def render_uninstall():
    return _tmpl("relay/uninstall-relay.sh.tmpl", {}, "uninstall-relay.sh")


def render_frpc(cfg, relay_ip, token, admin_password, mode):
    _check_token(token)
    _check_token(admin_password)
    o = render.options(cfg)
    return _tmpl("relay/frpc-relay.toml.tmpl", {
        "mode": mode, "relay_ip": relay_ip, "control_port": CONTROL_PORT, "token": token,
        "admin_port": o["relay_admin_port"], "admin_password": admin_password,
        "relay_http_port": o["relay_http_port"], "relay_https_port": o["relay_https_port"],
        "frp_port": cfg.frp_port}, "frpc-relay.toml")


def render_unit(cfg, relay_ip, repo_dir=REPO_DIR):
    return _tmpl("systemd/porch-relay.service.tmpl",
                 {"brand": cfg.brand, "relay_ip": relay_ip, "repo_dir": repo_dir}, UNIT)


# ---- home side -------------------------------------------------------------------

def frpc_path(ctx):
    return os.path.join(ctx.repo_dir, "config", FRPC_NAME)


def unit_path(ctx):
    from ..steps import _common as c
    return os.path.join(c.user_unit_dir(ctx), UNIT)


def read_frpc(ctx):
    """{serverAddr, token, admin_password} of the current home relay config, or {}."""
    try:
        import tomllib
        with open(frpc_path(ctx), "rb") as f:
            data = tomllib.loads(f.read().decode("utf-8"))
    except (OSError, ValueError):
        return {}
    auth = data.get("auth") or {}
    web = data.get("webServer") or {}
    out = {"serverAddr": data.get("serverAddr"), "token": auth.get("token"),
           "admin_password": web.get("password")}
    for k in ("token", "admin_password"):
        if out[k]:
            ctx.redactor.add(out[k])
    return out


def tokens_for(ctx, relay_ip):
    """(token, admin password): reused from the home config when it already
    points at this relay (re-applying keeps a working relay), else new."""
    cur = read_frpc(ctx)
    if relay_ip and cur.get("serverAddr") == relay_ip and cur.get("token") and cur.get("admin_password"):
        token, pw = cur["token"], cur["admin_password"]
    else:
        token, pw = new_token(), new_token()
    ctx.redactor.add(token)
    ctx.redactor.add(pw)
    return token, pw


def _write_private(path, text, mode):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, f".{os.path.basename(path)}.{secrets.token_hex(6)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def install_home(ctx, mode, relay_ip, token, admin_password):
    """Write config/relay-frpc.toml (0600) and the porch-relay user unit, then
    (re)start it. One write-ahead undo entry (relay.home_remove) covers both."""
    from ..steps import _common as c
    frpc = os.path.join(ctx.repo_dir, "bin", "frpc")
    if not os.path.exists(frpc):
        raise StepError("connect.relay.frpc", f"{frpc} is missing",
                        "install frp (bin/frpc) first: the relay client is an frpc")
    files = [frpc_path(ctx), unit_path(ctx)]
    if not any(e.get("kind") == "relay.home_remove" and e.get("mode") == mode.name
               for e in ctx.undo_entries()):
        mode.record_undo(ctx, "relay.home_remove", files=files, unit=UNIT)
    _write_private(files[0], render_frpc(ctx.cfg, relay_ip, token, admin_password, mode.name), 0o600)
    _write_private(files[1], render_unit(ctx.cfg, relay_ip, ctx.repo_dir), 0o644)
    r = ctx.run.run([frpc, "verify", "-c", files[0]], mutating=False)
    if not r.ok:
        raise StepError("connect.relay.frpc_config", "frpc verify failed: "
                        + (r.stderr or r.stdout).strip()[-300:])
    c.systemctl_user(ctx, "daemon-reload", check=True)
    c.systemctl_user(ctx, "enable", UNIT, check=True)
    c.systemctl_user(ctx, "restart", UNIT, check=True)
    ctx.log(f"porch-relay: frpc -> relay {relay_ip}:{CONTROL_PORT} (tcp 80, 443, {ctx.cfg.frp_port})")


def remove_home(ctx, entry):
    from ..steps import _common as c
    c.systemctl_user(ctx, "disable", "--now", entry.get("unit") or UNIT)
    for p in entry.get("files") or []:
        # only porch's own names: never follow a recorded path elsewhere
        if os.path.basename(p) not in (FRPC_NAME, UNIT):
            continue
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass
    c.systemctl_user(ctx, "daemon-reload")
    ctx.log("porch-relay: unit and relay frpc config removed")


# ---- health ----------------------------------------------------------------------

def tcp_open(host, port, timeout=3.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def proxy_status(ctx):
    """{proxy name: status} from the home relay frpc's admin API, or None."""
    import base64
    import json
    cur = read_frpc(ctx)
    pw = cur.get("admin_password")
    if not pw:
        return None
    port = render.options(ctx.cfg)["relay_admin_port"]
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/status", headers={
        "Authorization": "Basic " + base64.b64encode(f"porch:{pw}".encode()).decode()})
    try:
        with ctx.http(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:  # noqa: BLE001 - frpc not up, refused, bad JSON
        return None
    out = {}
    for items in (data or {}).values():
        for p in items or []:
            if isinstance(p, dict) and p.get("name"):
                out[p["name"]] = p.get("status") or ""
    return out


def health(ctx, relay_ip, tcp=tcp_open, wait=0):
    """Checks: the relay's control port answers, porch-relay is active, and
    its three proxies run on the relay. wait: seconds to let a freshly
    started frpc log in."""
    from ..steps import _common as c
    out = []
    ok = bool(relay_ip) and tcp(relay_ip, CONTROL_PORT)
    out.append(Check(ok, "connect.relay.control",
                     f"relay {relay_ip}:{CONTROL_PORT} " + ("answers" if ok else "does not answer"),
                     "" if ok else "is the relay up? (porch connect --status; the provider's console)"))
    r = c.systemctl_user(ctx, "is-active", UNIT, mutating=False)
    active = r.stdout.strip() == "active"
    out.append(Check(active, "connect.relay.unit", f"{UNIT}: {r.stdout.strip() or 'unknown'}",
                     "" if active else f"journalctl --user -u {UNIT}"))
    st = proxy_status(ctx)
    t = 0
    while wait and t < wait and not (st and all(st.get(n) == "running" for n in PROXIES)):
        ctx.sleep(2)
        t += 2
        st = proxy_status(ctx)
    running = bool(st) and all(st.get(n) == "running" for n in PROXIES)
    detail = ", ".join(f"{n.replace('porch-relay-', '')}={st.get(n) or 'missing'}" for n in PROXIES) \
        if st else "frpc admin API not answering"
    out.append(Check(running, "connect.relay.proxies", f"relay proxies: {detail}",
                     "" if running else f"journalctl --user -u {UNIT}"))
    return out


def ssh_argv(target, key=None, command=None):
    """ssh to user@host for byo/oracle (batch mode, accept-new host keys)."""
    a = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
         "-o", "StrictHostKeyChecking=accept-new", "-o", "ServerAliveInterval=15"]
    if key:
        a += ["-i", os.path.expanduser(key), "-o", "IdentitiesOnly=yes"]
    a.append(target)
    if command:
        a.append(command)
    return a


def public_key_for(key):
    """The .pub next to a private key path (or the path itself if it is one)."""
    if not key:
        return ""
    p = os.path.expanduser(key)
    for cand in (p if p.endswith(".pub") else p + ".pub",):
        try:
            with open(cand, encoding="utf-8") as f:
                line = f.read().strip().splitlines()[0]
        except (OSError, IndexError):
            raise StepError("connect.relay.ssh_key", f"no public key at {cand}") from None
        if not line.startswith(("ssh-", "ecdsa-", "sk-")):
            raise StepError("connect.relay.ssh_key", f"{cand} is not an ssh public key")
        return line
    return ""

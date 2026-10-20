"""preflight: the box can run porch (OS, tools, sudo, clock, ports, linger)."""

import os
import platform
import pwd
import socket
import struct
import sys
import time

from ..engine import Action, Check, Step
from . import _common as c

ORDER = 10

MIN_PY = (3, 10)
MIN_HAPROXY = (2, 4)
MIN_CERTBOT = (2, 0)
MAX_SKEW = 60.0
NTP_SERVERS = ("pool.ntp.org", "time.cloudflare.com")
PORT_OWNERS = {80: ("haproxy",), 443: ("haproxy",), 7000: ("frps",)}


def sntp_offset(server, timeout=3.0, clock=time.time):
    """Clock offset in seconds from one SNTP query (RFC 4330), or None."""
    pkt = b"\x1b" + 47 * b"\0"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            t0 = clock()
            s.sendto(pkt, (server, 123))
            data, _ = s.recvfrom(512)
            t3 = clock()
    except OSError:
        return None
    if len(data) < 48:
        return None
    secs, frac = struct.unpack("!II", data[40:48])
    server_time = secs - 2208988800 + frac / 2**32
    return server_time - (t0 + t3) / 2


class Preflight(Step):
    id = "preflight"
    title = "Check this machine"
    ntp = staticmethod(sntp_offset)       # tests replace it
    platform_system = staticmethod(platform.system)

    def _tool_checks(self, ctx):
        out = []
        sysname = self.platform_system()
        out.append(Check(sysname == "Linux", "preflight.os", f"OS: {sysname}",
                         "porch setup runs on Linux"))
        py = sys.version_info[:2]
        out.append(Check(py >= MIN_PY, "preflight.python", f"Python {py[0]}.{py[1]}",
                         f"needs Python {MIN_PY[0]}.{MIN_PY[1]}+"))
        r = ctx.run.run(["true"], sudo=True, mutating=False)
        out.append(Check(r.ok, "preflight.sudo",
                         "sudo works without a prompt" if r.ok else "sudo -n is not available",
                         "porch needs sudo for HAProxy (/etc/haproxy) and the firewall; "
                         "run `sudo -v` first or add a sudoers rule"))
        for tool, argv, minimum, hint in (
                ("haproxy", ["haproxy", "-v"], MIN_HAPROXY, "sudo apt install haproxy"),
                ("certbot", ["certbot", "--version"], MIN_CERTBOT, "sudo apt install certbot")):
            if not ctx.run.which(tool):
                out.append(Check(False, f"preflight.{tool}", f"{tool} is not installed", hint))
                continue
            r = ctx.run.run(argv, mutating=False)
            v = c.version_tuple(r.stdout + r.stderr)
            ok = v is not None and v[:2] >= minimum
            out.append(Check(ok, f"preflight.{tool}",
                             f"{tool} {'.'.join(map(str, v)) if v else '(version unknown)'}",
                             f"needs {tool} {minimum[0]}.{minimum[1]}+: {hint}"))
        # Optional: the wizard draws the phone-check QR with python-qrcode;
        # without it the page shows only the link. Never fails preflight.
        import importlib.util
        has_qr = importlib.util.find_spec("qrcode") is not None
        out.append(Check(True, "preflight.qrcode",
                         "python-qrcode: QR codes on" if has_qr else
                         "python-qrcode missing: the phone check shows a link, no QR "
                         "(sudo apt install python3-qrcode)"))
        for tool in ("curl", "ss"):
            out.append(Check(bool(ctx.run.which(tool)), f"preflight.{tool}",
                             f"{tool} {'found' if ctx.run.which(tool) else 'missing'}",
                             f"install {tool}"))
        return out

    def _clock_check(self, ctx):
        for server in NTP_SERVERS:
            off = self.ntp(server)
            if off is not None:
                return Check(abs(off) < MAX_SKEW, "preflight.clock",
                             f"clock is {off:+.1f}s off ({server})",
                             "fix the clock (timedatectl set-ntp true): certificates and "
                             "TLS fail with a skewed clock")
        return Check(True, "preflight.clock", "clock not checked (no NTP answer)")

    def _port_checks(self, ctx):
        ls = c.listeners(ctx)
        out = []
        for port, owners in PORT_OWNERS.items():
            who = ls.get(port)
            if who is None:
                out.append(Check(True, f"preflight.port{port}", f"port {port} is free"))
            elif who == "" or any(who.startswith(o) for o in owners):
                out.append(Check(True, f"preflight.port{port}",
                                 f"port {port} is used by {who or 'an unknown process'}"))
            else:
                out.append(Check(False, f"preflight.port{port}", f"port {port} is used by {who}",
                                 f"porch needs {owners[0]} on port {port}; stop {who} or move it"))
        return out

    def _internal_port_checks(self, ctx):
        """Porch's own loopback ports (render.PORTS) must be free on a first
        run. Once the services step has run, whatever holds them is porch."""
        from .. import render
        if c.adopted(ctx) or ctx.state.status_of("services") not in ("pending", None):
            return []
        o = render.options(ctx.cfg)
        ports = {o["auth_port"]: "auth server", o["status_port"]: "status API",
                 o["shortener_port"]: "shortener", o["frp_vhost_port"]: "frps (vhost)",
                 o["frp_dashboard_port"]: "frps (dashboard)", o["acme_http_port"]: "ACME http-01"}
        if o["landing"] == "static":
            ports[o["landing_port"]] = "landing page"
        ls = c.listeners(ctx)
        busy = []
        for port, what in sorted(ports.items()):
            who = ls.get(port)
            if who is None or (who.startswith("frps") and "frps" in what):
                continue
            busy.append(f"{port} ({what}) is held by {who or 'an unknown process'}")
        if not busy:
            return [Check(True, "preflight.internal_ports",
                          "porch's internal ports are free: " + " ".join(map(str, sorted(ports))))]
        return [Check(False, "preflight.internal_ports", "porch's internal ports are in use: "
                      + "; ".join(busy), "porch's services listen there on 127.0.0.1: stop or move "
                      "that program (ss -ltnp shows it)")]

    def _unit_checks(self, ctx):
        """porch-* user units that porch did not write (and that differ from
        what it would write) would be refused later by the services step."""
        if c.adopted(ctx):
            return []
        from .. import render
        from . import pocket
        d = c.user_unit_dir(ctx)
        try:
            want = dict(render.render_units(ctx.cfg))
        except Exception:  # noqa: BLE001 - render problems surface in their own steps
            want = {}
        try:
            want[pocket.UNIT_FILE] = pocket.render_unit(ctx.repo_dir, ctx.cfg.brand)
        except Exception:  # noqa: BLE001
            pass
        foreign = []
        try:
            names = sorted(n for n in os.listdir(d) if n.startswith("porch-"))
        except OSError:
            names = []
        for n in names:
            path = os.path.join(d, n)
            if ctx.files.status(path) != "unmanaged":
                continue
            try:
                with open(path, encoding="utf-8") as f:
                    same = f.read() == want.get(n)
            except OSError:
                same = False
            if not same:
                foreign.append(path)
        if not foreign:
            return [Check(True, "preflight.units", "no foreign porch-* user units")]
        return [Check(False, "preflight.units", "user units porch did not write: " + ", ".join(foreign),
                      "porch's services use these names; move them away (systemctl --user disable "
                      "--now <unit>) and run setup again")]

    def _warnings(self, ctx):
        """Things that do not stop setup but the owner should know (logged as warnings)."""
        r = ctx.run.run(["sudo", "-n", "-l"], mutating=False)
        if r.ok and "NOPASSWD: ALL" in r.stdout:
            user = ctx.env.get("USER") or pwd.getpwuid(os.getuid()).pw_name
            ctx.log(f"WARNING: {user} has passwordless sudo for every command (NOPASSWD: ALL; "
                    "porch.sh writes /etc/sudoers.d/90-porch). Setup installs HAProxy, units, "
                    "certificates and firewall rules through sudo -n, and certificate renewals "
                    f"reload HAProxy through it. Anything that runs as {user} can become root.",
                    "warn")
        live = os.path.join(ctx.env.get("PORCH_ETC_ROOT", "") + "/etc/letsencrypt/live")
        try:
            certs = sorted(n for n in os.listdir(live) if os.path.isdir(os.path.join(live, n)))
        except OSError:
            certs = []
        if certs:
            ctx.log(f"existing certificates in /etc/letsencrypt ({', '.join(certs)}) are left alone: "
                    "porch's certbot runs in its own directory and never renews, revokes or "
                    "deletes them", "warn")
        if ctx.run.which("docker"):
            d = ctx.run.run(["docker", "ps", "--format", "{{.Names}} {{.Ports}}"], mutating=False)
            pub = [ln for ln in d.stdout.splitlines()
                   if any(f":{p}->" in ln for p in (80, 443, 7000))] if d.ok else []
            if pub:
                ctx.log("WARNING: docker publishes ports porch needs (Docker's forwarding bypasses "
                        "HAProxy): " + "; ".join(pub), "warn")

    def _linger(self, ctx):
        user = ctx.env.get("USER") or pwd.getpwuid(os.getuid()).pw_name
        r = ctx.run.run(["loginctl", "show-user", user, "-p", "Linger"], mutating=False)
        return user, r.ok and r.stdout.strip() == "Linger=yes"

    def _linger_check(self, ctx):
        if c.adopted(ctx):
            return Check(True, "preflight.linger", "linger not needed (adopted install)")
        user, ok = self._linger(ctx)
        return Check(ok, "preflight.linger",
                     f"systemd linger is {'on' if ok else 'off'} for {user}",
                     f"porch's user services stop at logout without it: "
                     f"sudo loginctl enable-linger {user}")

    def preflight(self, ctx):
        self._warnings(ctx)
        return (self._tool_checks(ctx) + [self._clock_check(ctx)] + self._port_checks(ctx)
                + self._internal_port_checks(ctx) + self._unit_checks(ctx))

    def plan(self, ctx):
        if c.adopted(ctx) or self._linger(ctx)[1]:
            return []
        return [Action("run", "sudo loginctl enable-linger", "keep porch's user services running")]

    def apply(self, ctx):
        if c.adopted(ctx):
            return {}
        user, ok = self._linger(ctx)
        if not ok:
            if not ctx.confirm(f"Enable systemd linger for {user} so porch keeps running "
                               f"after you log out?", default=True):
                return {"linger": False}
            ctx.run.run(["loginctl", "enable-linger", user], sudo=True, check=True)
        return {"linger": True}

    def verify(self, ctx):
        return self._tool_checks(ctx) + [self._linger_check(ctx)]


STEP = Preflight()

"""services: porch's long-running processes as systemd user units.

Fresh installs: writes porch-{auth,frps,status,shortener,landing}.service to
~/.config/systemd/user/ (all ports > 1024, no root) and enables them.
Verify (and adopt, where the box runs its own units / bin/start-server) is
the loopback health checks, plus `systemctl --user is-active` when porch
installed the units.
"""

import os
import socket

from .. import render
from ..engine import Action, Check, Step, StepError
from . import _common as c

ORDER = 110


def tcp_open(host, port, timeout=2.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class Services(Step):
    id = "services"
    title = "Background services"
    requires = ("frps",)
    tcp_open = staticmethod(tcp_open)
    HEALTH_WAIT = 20        # seconds verify waits for freshly started units

    def units(self, ctx):
        return render.render_units(ctx.cfg)

    def preflight(self, ctx):
        if c.adopted(ctx):
            return []
        if ctx.dry_run and ctx.state.status_of("preflight") not in ("done", "adopted"):
            # preflight turns linger on (which starts the user manager) only
            # in a real run; don't fail a dry run for what it would fix.
            return [Check(True, "services.user_systemd",
                          "systemd user session: preflight would enable linger first")]
        r = c.systemctl_user(ctx, "show-environment", mutating=False, wait=10)
        return [Check(r.ok, "services.user_systemd", "systemd user session available" if r.ok
                      else "no systemd user session",
                      f"is linger on? sudo loginctl enable-linger $USER (looked at {c.user_bus_env(ctx)['XDG_RUNTIME_DIR']})")]

    def plan(self, ctx):
        if c.adopted(ctx):
            return []
        d = c.user_unit_dir(ctx)
        out = [Action("file.write", os.path.join(d, n), "") for n in self.units(ctx)]
        out.append(Action("systemd.enable", " ".join(self.units(ctx)), "systemctl --user enable --now"))
        return out

    def apply(self, ctx):
        if c.adopted(ctx):
            raise StepError("services.adopted", "porch does not install units on an adopted install")
        d = c.user_unit_dir(ctx)
        o = render.options(ctx.cfg)
        if o["landing"] == "static":
            # porch-landing serves this; the landing step (130) fills it, but
            # the unit starts here and exits on a missing directory.
            os.makedirs(o["web_root"], exist_ok=True)
        written = []
        for name, text in self.units(ctx).items():
            ctx.files.write(os.path.join(d, name), text, mode=0o644)
            written.append(name)
        c.systemctl_user(ctx, "daemon-reload", check=True)
        ctx.record_undo("systemd.disable", units=written)
        c.systemctl_user(ctx, "enable", "--now", *written, check=True)
        return {"units": written}

    def health(self, ctx):
        o = render.options(ctx.cfg)
        out = []
        for code, url in (("services.auth", f"http://127.0.0.1:{o['auth_port']}/auth/"),
                          ("services.status", f"http://127.0.0.1:{o['status_port']}/api/me"),
                          ("services.shortener", f"http://127.0.0.1:{o['shortener_port']}/")):
            st = c.http_code(ctx, url)
            out.append(Check(st is not None and st < 500, code, f"{url} -> {st or 'no answer'}",
                             "systemctl --user status porch-*  /  journalctl --user -u porch-*"))
        ok = self.tcp_open("127.0.0.1", ctx.cfg.frp_port)
        out.append(Check(ok, "services.frps", f"frps on 127.0.0.1:{ctx.cfg.frp_port}: "
                         + ("listening" if ok else "not listening")))
        if o["landing"] == "static":
            # Any answer: the page itself arrives with the landing step.
            st = c.http_code(ctx, f"http://127.0.0.1:{o['landing_port']}/")
            out.append(Check(st is not None, "services.landing",
                             f"landing :{o['landing_port']} -> {st or 'no answer'}"))
        return out

    def verify(self, ctx):
        out = []
        entry = ctx.state.steps.get(self.id) or {}
        units = (entry.get("outputs") or {}).get("units")
        if units and not c.adopted(ctx):
            for u in units:
                r = c.systemctl_user(ctx, "is-active", u, mutating=False)
                out.append(Check(r.stdout.strip() == "active", "services.unit",
                                 f"{u}: {r.stdout.strip() or 'unknown'}"))
        # Units were just started: give them a moment to bind (the e2e VPS
        # checked the auth server one second before it was listening).
        health = self.health(ctx)
        for _ in range(self.HEALTH_WAIT):
            if all(ch.ok for ch in health):
                break
            ctx.sleep(1)
            health = self.health(ctx)
        return out + health

    def undo(self, ctx, entry):
        if entry["kind"] != "systemd.disable":
            return super().undo(ctx, entry)
        c.systemctl_user(ctx, "disable", "--now", *entry["units"])
        c.systemctl_user(ctx, "daemon-reload")


STEP = Services()

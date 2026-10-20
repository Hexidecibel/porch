"""pocket: the Porch app (Pocket) as the systemd user unit porch-pocket@pocket.

Pocket is an ordinary tunnel door (https://pocket.<tunnel base>), so it needs
nothing from HAProxy beyond the wildcard route to frps, and nothing from frps
beyond the home frpc token the auth server minted at start (services).

Fresh installs: writes the template unit porch-pocket@.service (the same file
`bin/pocket --install-service` writes, config/templates/systemd/) to
~/.config/systemd/user/, then `systemctl --user enable --now
porch-pocket@pocket.service`. Rollback disables it and removes the file.
Adopted installs: verify only (this box may run Pocket under its own unit or
by hand).

Verify: the unit is active (when porch installed it), Pocket answers
/manifest.webmanifest on the loopback port in its tunnel state file, and the
same path answers 200 through HAProxy at https://pocket.<tunnel base>/.
"""

import json
import os
import string

from ..engine import Action, Check, Step, StepError
from . import _common as c

ORDER = 135
NAME = "pocket"
UNIT_FILE = "porch-pocket@.service"
UNIT = f"porch-pocket@{NAME}.service"
TEMPLATE = os.path.join("config", "templates", "systemd", "porch-pocket@.service.tmpl")
DEFAULT_STATE_DIR = "/tmp/tunnel-state"


def render_unit(repo_dir, brand):
    """The porch-pocket@.service text for this checkout (as pocketserver's
    render_service_unit, without importing the app server)."""
    if any(ch in repo_dir for ch in ' \n\t%$\\"\''):
        raise StepError("pocket.repo_path", f"repo path {repo_dir!r} cannot go into a unit file")
    with open(os.path.join(repo_dir, TEMPLATE), encoding="utf-8") as f:
        text = f.read()
    label = "".join(ch for ch in (brand or "Porch") if ch.isprintable() and ch not in "\r\n")
    return string.Template(text).substitute(repo_dir=repo_dir,
                                            brand=(label.strip() or "Porch").replace("%", "%%"))


def pocket_url(cfg):
    return cfg.tunnel_url(NAME, "/")


def signin_url(cfg):
    """Where a fresh phone starts: Pocket's own /__porch/start, which runs the
    per-host handoff. A browser with no owner device yet is sent to the auth
    host's /login (enroll with the admin password), then back through the
    handoff, so it lands in Pocket signed in."""
    return f"https://{cfg.tunnel_host(NAME)}/__porch/start?rd=%2F"


class Pocket(Step):
    id = "pocket"
    title = "Porch app (Pocket)"
    requires = ("services",)
    HEALTH_WAIT = 30        # seconds: bin/pocket starts the app, then frpc

    def unit_path(self, ctx):
        return os.path.join(c.user_unit_dir(ctx), UNIT_FILE)

    def state_file(self, ctx):
        return os.path.join(ctx.env.get("TUNNEL_STATE_DIR") or DEFAULT_STATE_DIR, f"{NAME}.json")

    def plan(self, ctx):
        if c.adopted(ctx):
            return []
        return [Action("file.write", self.unit_path(ctx), ""),
                Action("systemd.enable", UNIT, "systemctl --user enable --now"),
                Action("door", pocket_url(ctx.cfg), "owner only, never expires")]

    def apply(self, ctx):
        if c.adopted(ctx):
            raise StepError("pocket.adopted", "porch does not install units on an adopted install")
        path = self.unit_path(ctx)
        text = render_unit(ctx.repo_dir, ctx.cfg.brand)
        take_over = False
        if ctx.files.status(path) == "unmanaged":
            # `bin/pocket --install-service` wrote it before: the same file is ours.
            try:
                with open(path, encoding="utf-8") as f:
                    take_over = f.read() == text
            except OSError:
                take_over = False
            if not take_over:
                raise StepError("pocket.unit_exists", f"{path} exists and was not written by porch",
                                "look at it; if it is a leftover, remove it and run setup again")
        ctx.files.write(path, text, mode=0o644, take_over=take_over)
        c.systemctl_user(ctx, "daemon-reload", check=True)
        ctx.record_undo("systemd.disable", units=[UNIT])
        c.systemctl_user(ctx, "enable", "--now", UNIT, check=True)
        return {"unit": UNIT, "url": pocket_url(ctx.cfg)}

    def _port(self, ctx):
        try:
            with open(self.state_file(ctx), encoding="utf-8") as f:
                port = json.load(f).get("port")
        except (OSError, ValueError, AttributeError):
            return None
        return port if isinstance(port, int) and 0 < port < 65536 else None

    def health(self, ctx):
        port = self._port(ctx)
        if port is None:
            local = Check(False, "pocket.local", f"no live Pocket door ({self.state_file(ctx)} missing)",
                          f"systemctl --user status {UNIT}  /  journalctl --user -u {UNIT}")
        else:
            url = f"http://127.0.0.1:{port}/manifest.webmanifest"
            st = c.http_code(ctx, url)
            local = Check(st == 200, "pocket.local", f"{url} -> {st or 'no answer'}",
                          f"journalctl --user -u {UNIT}")
        return [local, c.https_check(ctx, "pocket.https", ctx.cfg.tunnel_host(NAME),
                                     "/manifest.webmanifest")]

    def verify(self, ctx):
        out = []
        entry = ctx.state.steps.get(self.id) or {}
        if (entry.get("outputs") or {}).get("unit") and not c.adopted(ctx):
            r = c.systemctl_user(ctx, "is-active", UNIT, mutating=False)
            out.append(Check(r.stdout.strip() == "active", "pocket.unit",
                             f"{UNIT}: {r.stdout.strip() or 'unknown'}"))
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


STEP = Pocket()

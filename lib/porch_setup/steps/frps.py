"""frps: render config/frps.toml (0600; it holds the dashboard password).

The password is generated once and kept across re-renders. Verify parses the
live file: subDomainHost, bind port, the four plugin ops, and (fresh installs)
proxyBindAddr = 127.0.0.1. An adopted install whose frps still binds its
vhost ports on every interface passes only with "frps: proxyBindAddr" in
config [adopt] allow.
"""

import os
import secrets

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None

from .. import render
from ..engine import Action, Check, Step, StepError
from . import _common as c

ORDER = 100
OPS = ("Login", "NewProxy", "NewWorkConn", "Ping")


class Frps(Step):
    id = "frps"
    title = "frp server config"
    requires = ("domain",)

    def path(self, ctx):
        return os.path.join(ctx.repo_dir, "config", "frps.toml")

    def load(self, ctx):
        try:
            with open(self.path(ctx), "rb") as f:
                return tomllib.loads(f.read().decode("utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as e:
            raise StepError("frps.parse", f"{self.path(ctx)}: {e}") from None

    def password(self, ctx):
        try:
            data = self.load(ctx) or {}
        except StepError:
            data = {}
        pw = (data.get("webServer") or {}).get("password")
        if not pw or pw in ("CHANGE_ME", "frpadmin"):
            pw = secrets.token_urlsafe(18)
        ctx.redactor.add(pw)
        return pw

    def plan(self, ctx):
        if all(ch.ok for ch in self.verify(ctx)):
            return []
        return [Action("file.write", self.path(ctx), "frps.toml (0600)")]

    def apply(self, ctx):
        if c.adopted(ctx):
            raise StepError("frps.adopted", "porch does not rewrite frps.toml on an adopted install")
        text = render.render_frps(ctx.cfg, self.password(ctx))
        try:
            res = ctx.files.write(self.path(ctx), text, mode=0o600)
        except Exception as e:  # noqa: BLE001 - unmanaged or user-edited
            raise StepError("frps.config", str(e), f"move {self.path(ctx)} aside to let porch write it")
        return {"result": res}

    def verify(self, ctx):
        try:
            data = self.load(ctx)
        except StepError as e:
            return [Check(False, e.code, e.message)]
        if data is None:
            return [Check(False, "frps.missing", f"{self.path(ctx)} does not exist")]
        ctx.redactor.add((data.get("webServer") or {}).get("password") or "")
        out = []
        cfg = ctx.cfg
        out.append(Check(data.get("subDomainHost") == cfg.tunnel_base, "frps.subdomain",
                         f"subDomainHost = {data.get('subDomainHost')!r}", f"expected {cfg.tunnel_base}"))
        out.append(Check(data.get("bindPort") == cfg.frp_port, "frps.port",
                         f"bindPort = {data.get('bindPort')}", f"expected {cfg.frp_port}"))
        plugins = data.get("httpPlugins") or []
        auth = next((p for p in plugins if p.get("path") == "/verify"), None)
        ops = set((auth or {}).get("ops") or [])
        out.append(Check(auth is not None and set(OPS) <= ops
                         and str(auth.get("addr", "")).startswith("127.0.0.1:"),
                         "frps.plugin", f"auth plugin ops: {', '.join(sorted(ops)) or 'none'}",
                         "all of Login, NewProxy, NewWorkConn, Ping must go to the auth server"))
        bind = data.get("proxyBindAddr")
        allowed = any(a.split(":", 1)[0].strip() == "frps" and "proxyBindAddr" in a
                      for a in cfg.adopt_allow)
        out.append(Check(bind == "127.0.0.1" or allowed, "frps.bind",
                         f"proxyBindAddr = {bind or '(unset: every interface)'}"
                         + (" (allowed by adopt.allow)" if allowed and bind != "127.0.0.1" else ""),
                         'set proxyBindAddr = "127.0.0.1" so tunnels are reachable only through HAProxy'))
        web = data.get("webServer") or {}
        out.append(Check(web.get("addr", "127.0.0.1") == "127.0.0.1", "frps.dashboard",
                         f"dashboard on {web.get('addr', '127.0.0.1')}:{web.get('port', '-')}"))
        mode = os.stat(self.path(ctx)).st_mode & 0o077
        out.append(Check(mode == 0, "frps.mode", "frps.toml is private" if not mode
                         else "frps.toml is readable by others", f"chmod 600 {self.path(ctx)}"))
        frps = os.path.join(ctx.repo_dir, "bin", "frps")
        if os.path.exists(frps):
            r = ctx.run.run([frps, "verify", "-c", self.path(ctx)], mutating=False)
            out.append(Check(r.ok, "frps.verify", "frps verify: ok" if r.ok else
                             "frps verify: " + (r.stderr or r.stdout).strip()[-200:]))
        return out


STEP = Frps()

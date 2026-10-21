"""haproxy: render the config and install it through bin/haproxy-apply.

Fresh installs: porch owns /etc/haproxy/haproxy.cfg. It refuses to replace
a config that already serves other things (use --adopt there). Adopted
installs: never written; verify is the adopt diff (config [adopt] allow) plus
SNI checks through 127.0.0.1:443.

The config names Porch's error pages (lib/porch_errors.py) in
render.options()['errors_dir'] (/etc/haproxy/errors/porch): apply installs
them there before the config, and preflight checks the config against a
freshly built copy, so haproxy -c passes before anything is installed.
"""

import os
import re
import sys
import tempfile

from .. import haproxy_diff, render
from ..engine import Action, Check, Step, StepError
from . import _common as c

ORDER = 90

LIVE = "/etc/haproxy/haproxy.cfg"
PORCH_SECTIONS = {"global", "defaults", "frontend www-https"}
PORCH_BACKENDS = {"reject", "letsencrypt-backend", "shortener", "tunnel", "panel",
                  "tunnelroot", "porch_auth", "cush_auth", "cushroot"}


class Haproxy(Step):
    id = "haproxy"
    title = "HAProxy"
    requires = ("certificate",)
    live_path = LIVE

    def rendered(self, ctx):
        return render.render_haproxy(ctx.cfg, relay=c.relay_mode(ctx) or None)

    def candidate(self, ctx):
        os.makedirs(ctx.scratch_dir, mode=0o700, exist_ok=True)
        path = os.path.join(ctx.scratch_dir, "haproxy.cfg.candidate")
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.rendered(ctx))
        return path

    def live_text(self, ctx):
        try:
            return c.read_root_file(ctx, self.live_path)
        except FileNotFoundError:
            return None

    @staticmethod
    def foreign_sections(text):
        out = []
        for header, _ in haproxy_diff.parse(text or ""):
            if header in PORCH_SECTIONS:
                continue
            m = re.match(r"^backend (\S+)$", header)
            if m and m.group(1) in PORCH_BACKENDS:
                continue
            out.append(header)
        return out

    @staticmethod
    def build_errors(ctx, dest):
        """Write the error pages into `dest` (0755 dir, 0644 files)."""
        lib = os.path.join(ctx.repo_dir, "lib")
        if lib not in sys.path:
            sys.path.insert(0, lib)
        import porch_errors
        porch_errors.write(dest, brand=ctx.cfg.brand)
        os.chmod(dest, 0o755)
        return dest

    def install_errors(self, ctx):
        """Install the error pages into errors_dir (root-owned)."""
        dest = render.options(ctx.cfg)["errors_dir"]
        built = self.build_errors(ctx, os.path.join(ctx.scratch_dir, "haproxy-errors"))
        ctx.run.run(["install", "-d", "-m", "0755", "-o", "root", "-g", "root", dest],
                    sudo=True, check=True)
        for name in sorted(os.listdir(built)):
            ctx.run.run(["install", "-m", "0644", "-o", "root", "-g", "root",
                         os.path.join(built, name), os.path.join(dest, name)],
                        sudo=True, check=True)

    def preflight(self, ctx):
        out = []
        if not ctx.run.which("haproxy"):
            return [Check(False, "haproxy.missing", "haproxy is not installed", "sudo apt install haproxy")]
        opts = render.options(ctx.cfg)
        cert = opts["cert_path"]
        r = ctx.run.run(["test", "-r", cert], sudo=True, mutating=False)
        if not r.ok and ctx.dry_run and ctx.state.status_of("certificate") not in ("done", "adopted"):
            out.append(Check(True, "haproxy.cert", f"certificate {cert} (the certificate step would write it)"))
            return out
        out.append(Check(r.ok, "haproxy.cert", f"certificate {cert}",
                         "the certificate step writes it (porch setup --only certificate)"))
        if not r.ok:
            return out
        with tempfile.NamedTemporaryFile("w", prefix="porch-haproxy-", suffix=".cfg") as f, \
                tempfile.TemporaryDirectory(prefix="porch-errors-") as errs:
            # The error pages are installed by apply; check against a fresh build.
            f.write(render.render_haproxy(ctx.cfg, relay=c.relay_mode(ctx) or None,
                                          errors_dir=self.build_errors(ctx, errs)))
            f.flush()
            os.chmod(f.name, 0o644)  # haproxy -c runs as root but may drop privileges
            r = ctx.run.run(["haproxy", "-c", "-q", "-f", f.name], sudo=True, mutating=False)
        out.append(Check(r.ok, "haproxy.candidate", "rendered config passes haproxy -c" if r.ok
                         else "rendered config fails haproxy -c: " + (r.stderr.strip()[-300:]),
                         "porch render haproxy shows it"))
        if not c.adopted(ctx):
            foreign = self.foreign_sections(self.live_text(ctx))
            out.append(Check(not foreign, "haproxy.foreign",
                             "live haproxy.cfg has nothing porch would drop" if not foreign
                             else f"live haproxy.cfg also serves: {', '.join(foreign[:6])}"
                             + (" ..." if len(foreign) > 6 else ""),
                             "porch would replace the whole file; run `porch setup --adopt` "
                             "and add porch's lines by hand (porch render haproxy --against)"))
        return out

    def plan(self, ctx):
        live = self.live_text(ctx) or ""
        if live == self.rendered(ctx):
            return []
        return [Action("haproxy.errors", render.options(ctx.cfg)["errors_dir"],
                       "Porch's error pages (lib/porch_errors.py)"),
                Action("haproxy.install", self.live_path, "bin/haproxy-apply (validate, diff, backup, reload)"),
                Action("dir", f"{render.options(ctx.cfg)['maps_dir']}", "owned by you, for the auth maps")]

    def apply(self, ctx):
        if c.adopted(ctx):
            raise StepError("haproxy.adopted", "porch does not write HAProxy on an adopted install",
                            "use porch render haproxy --against /etc/haproxy/haproxy.cfg")
        cand = self.candidate(ctx)
        if (self.live_text(ctx) or "") == self.rendered(ctx):
            return {"changed": False}
        maps = render.options(ctx.cfg)["maps_dir"]
        user = ctx.env.get("USER") or str(os.getuid())
        ctx.run.run(["install", "-d", "-m", "0755", "-o", user, "-g", "haproxy", maps],
                    sudo=True, check=True)
        self.install_errors(ctx)
        entry = ctx.record_undo("haproxy.restore", backup=None)
        r = ctx.run.run([os.path.join(ctx.repo_dir, "bin", "haproxy-apply"), cand, "--yes"])
        m = re.search(r"backed up live config to (\S+)", r.stdout)
        if m:
            entry["backup"] = m.group(1)
            ctx.state.save()
        if not r.ok:
            raise StepError("haproxy.apply", "bin/haproxy-apply failed (the live config was "
                            "restored): " + (r.stderr.strip() or r.stdout.strip())[-300:])
        return {"changed": True, "backup": entry["backup"]}

    def verify(self, ctx):
        live = self.live_text(ctx)
        if live is None:
            return [Check(False, "haproxy.live", f"{self.live_path} does not exist")]
        rep = haproxy_diff.diff(self.rendered(ctx), live, ctx.cfg.adopt_allow)
        cnt = rep.counts()
        msg = (f"adopt diff: {cnt['checked']} checked, {cnt['missing']} missing, "
               f"{cnt['different']} different, {cnt['order']} out of order, {cnt['allowed']} allowed")
        out = [Check(rep.ok, "haproxy.diff", msg,
                     "" if rep.ok else "porch render haproxy --against " + self.live_path)]
        # The backends start later (services, ORDER 110): until then HAProxy
        # answers 503 for them, which still proves TLS and routing work.
        ok = (200,) if ctx.state.status_of("services") in ("done", "adopted") else (200, 503)
        for host, path in ((ctx.cfg.auth_host, "/auth/"), (ctx.cfg.panel_host, "/api/me")):
            out.append(c.https_check(ctx, "haproxy.sni", host, path, ok_codes=ok))
        return out

    def undo(self, ctx, entry):
        if entry["kind"] != "haproxy.restore":
            return super().undo(ctx, entry)
        if not entry.get("backup"):
            ctx.log("haproxy: no backup was taken (the install never ran); nothing to restore")
            return
        r = ctx.run.run([os.path.join(ctx.repo_dir, "bin", "haproxy-apply"), entry["backup"], "--yes"])
        if not r.ok:
            raise StepError("haproxy.rollback", "restoring the backup failed: " + r.stderr.strip()[-300:],
                            f"bin/haproxy-apply {entry['backup']}")


STEP = Haproxy()

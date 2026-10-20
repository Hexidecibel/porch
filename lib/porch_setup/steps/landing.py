"""landing: deploy the landing page (bin/deploy) to the configured web root.

Fresh installs: the porch-landing static server's root
(~/.local/share/porch/landing). Adopted installs: nginx's /var/www/tunnel.
Verify: https://<landing host>/ through 127.0.0.1:443 answers 200.
Rollback: none (the page is regenerated from site/ on every deploy).
"""

import os

from .. import render
from ..engine import Action, Step, StepError
from . import _common as c

ORDER = 130
ADOPT_WEB_ROOT = "/var/www/tunnel"


class Landing(Step):
    id = "landing"
    title = "Landing page"
    requires = ("haproxy",)

    def web_root(self, ctx):
        return ADOPT_WEB_ROOT if c.adopted(ctx) else render.options(ctx.cfg)["web_root"]

    def plan(self, ctx):
        return [Action("run", "bin/deploy", f"site/ -> {self.web_root(ctx)}")]

    def apply(self, ctx):
        root = self.web_root(ctx)
        r = ctx.run.run([os.path.join(ctx.repo_dir, "bin", "deploy")],
                        env={"PORCH_WEB_ROOT": root}, timeout=600)
        if not r.ok:
            raise StepError("landing.deploy", "bin/deploy failed: " + (r.stderr or r.stdout).strip()[-300:])
        return {"web_root": root}

    def verify(self, ctx):
        return [c.https_check(ctx, "landing.https", ctx.cfg.landing_host, "/")]


STEP = Landing()

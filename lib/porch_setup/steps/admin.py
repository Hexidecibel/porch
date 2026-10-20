"""admin: the auth server has an admin password; tell the user how to enroll.

The password comes from getpass (twice) or $PORCH_ADMIN_PASSWORD, is passed
to `bin/auth-admin set-password --stdin` on stdin, and is never stored.
Rollback: none by design.
"""

import os

from ..engine import Action, Check, Input, Step, StepError
from ..io import MissingInput
from . import _common as c

ORDER = 120
PASSWORD_MIN = 12

_PW = Input("admin_password", "secret", "New admin password (12+ characters)",
            env="PORCH_ADMIN_PASSWORD")
_PW2 = Input("admin_password_confirm", "secret", "Confirm the admin password")


def has_admin(ctx):
    d = c.devices(ctx)
    admin = (d or {}).get("admin") or {}
    return bool(admin.get("password_scrypt"))


class Admin(Step):
    id = "admin"
    title = "Admin account"
    requires = ("services",)

    def preflight(self, ctx):
        st = c.http_code(ctx, "http://127.0.0.1:9512/auth/")
        return [Check(st is not None, "admin.authserver", f"auth server answers ({st})" if st
                      else "auth server is not answering on 127.0.0.1:9512",
                      "porch setup --only services")]

    def plan(self, ctx):
        return [] if has_admin(ctx) else [Action("auth.set-password", "admin", "asks for a password")]

    def _ask(self, ctx):
        try:
            a = ctx.io.ask_secret(_PW, ctx)
        except MissingInput:
            raise StepError("admin.password", "no admin password given",
                            "run interactively, or set PORCH_ADMIN_PASSWORD") from None
        if not a.value:
            raise StepError("admin.password", "the admin password must be typed, not a ref")
        ctx.redactor.add(a.value)
        if len(a.value) < PASSWORD_MIN:
            raise StepError("admin.password", f"the password must be at least {PASSWORD_MIN} characters")
        if ctx.io.interactive and not ctx.env.get("PORCH_ADMIN_PASSWORD"):
            b = ctx.io.ask_secret(_PW2, ctx)
            if b.value != a.value:
                raise StepError("admin.password", "the passwords do not match")
        return a.value

    def apply(self, ctx):
        if not has_admin(ctx):
            pw = self._ask(ctx)
            r = ctx.run.run([os.path.join(ctx.repo_dir, "bin", "auth-admin"), "set-password",
                             "--stdin"], input=pw + "\n")
            if not r.ok:
                raise StepError("admin.set_password", "bin/auth-admin set-password failed: "
                                + (r.stderr or r.stdout).strip()[-300:])
        ctx.log(f"Enroll this browser as the owner: {ctx.cfg.auth_url('/auth/')}")
        return {"enroll_url": ctx.cfg.auth_url("/auth/")}

    def verify(self, ctx):
        ok = has_admin(ctx)
        return [Check(ok, "admin.password", "an admin password is set" if ok
                      else "no admin password yet", "porch setup --only admin")]


STEP = Admin()

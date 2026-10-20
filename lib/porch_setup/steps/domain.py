"""domain: which domain this box serves; writes config/porch.toml.

Fresh installs default to a dedicated base, porch.<domain>, so porch never
touches the apex or the user's other subdomains; --apex uses the domain
itself. Every host derives from that root (tunnel.<root>, auth.<root>, ...).
"""

import porch_config

from ..engine import Action, Check, Input, Step, StepError

ORDER = 20


def _domain_default(ctx):
    return ctx.cfg.root if ctx.cfg.source else None


def _apex_default(ctx):
    # An existing config was written for its own root: keep it as is.
    return bool(ctx.cfg.source)


def _validate_domain(v):
    return None if porch_config.is_hostname(str(v).strip().lower()) else \
        "a bare domain like example.com (no scheme, port, path or wildcard)"


def expected_root(ctx):
    d = ctx.input("domain")
    if not d:
        return None
    d = d.strip().lower()
    return d if ctx.input("apex") else f"porch.{d}"


def render_toml(root, brand="Porch"):
    return (
        "# Porch domain config, written by `porch setup` (domain step).\n"
        "# Check it with: python3 lib/porch_config.py check\n"
        "# Unset hosts derive from root: tunnel.<root>, auth.<root>, panel.<root>.\n\n"
        f'[brand]\nname = "{brand}"\n\n'
        f'[domain]\nroot = "{root}"\n\n'
        '[install]\nmode = "fresh"\n'
    )


class Domain(Step):
    id = "domain"
    title = "Domain"
    requires = ("preflight",)
    INPUTS = (
        Input("domain", "text", "Your domain (porch uses porch.<domain> unless --apex)",
              default=_domain_default, validate=_validate_domain, flag="--domain"),
        Input("apex", "bool", "Serve porch at the domain itself instead of porch.<domain>?",
              default=_apex_default, flag="--apex"),
    )

    def preflight(self, ctx):
        root = expected_root(ctx)
        out = []
        try:
            cfg = porch_config.load(path=None, env={"PORCH_CONFIG": "none", "PORCH_DOMAIN": root})
            out.append(Check(True, "domain.hosts",
                             f"hosts: {cfg.auth_host}, {cfg.panel_host}, *.{cfg.tunnel_base}"))
        except porch_config.ConfigError as e:
            out.append(Check(False, "domain.hosts", str(e),
                             "pick a shorter domain or use --apex"))
            return out
        if ctx.dns is not None and hasattr(ctx.dns, "zone_apex"):
            try:
                apex = ctx.dns.zone_apex(root)
                out.append(Check(bool(apex), "domain.zone",
                                 f"DNS zone: {apex}" if apex else f"no DNS zone found for {root}",
                                 "is the domain registered and delegated?"))
            except Exception as e:  # noqa: BLE001
                out.append(Check(False, "domain.zone", f"DNS lookup failed: {e}"))
        return out

    def plan(self, ctx):
        root = expected_root(ctx)
        if ctx.cfg.source and ctx.cfg.root == root:
            return []
        if ctx.dry_run and root:
            # Nothing is written in a dry run, so later steps would plan
            # against the built-in defaults (cush.rocks); give them the
            # config this step would write, in memory only.
            ctx._cfg = porch_config.load(path=None, env={"PORCH_CONFIG": "none", "PORCH_DOMAIN": root})
        return [Action("file.write", ctx.config_path, f"root = {root}")]

    def apply(self, ctx):
        root = expected_root(ctx)
        if ctx.cfg.source and ctx.cfg.root == root:
            return {"root": root, "written": False}
        try:
            ctx.files.write(ctx.config_path, render_toml(root, ctx.cfg.brand), mode=0o644)
        except Exception as e:  # noqa: BLE001 - unmanaged / user-edited
            raise StepError("domain.config", str(e),
                            f"edit {ctx.config_path} yourself, or move it aside") from None
        ctx.reload_cfg()
        return {"root": root, "written": True}

    def verify(self, ctx):
        try:
            cfg = ctx.reload_cfg()
        except porch_config.ConfigError as e:
            return [Check(False, "domain.config", f"config/porch.toml is invalid: {e}",
                          "python3 lib/porch_config.py check")]
        out = [Check(cfg.source is not None, "domain.config",
                     f"config: {cfg.source or 'built-in defaults (no config/porch.toml)'}",
                     "run porch setup without --adopt to write it")]
        root = expected_root(ctx)
        if root:
            out.append(Check(cfg.root == root, "domain.root", f"root = {cfg.root}",
                             f"expected {root}"))
        # room for a 40-character tunnel name under the tunnel base
        fits = len(cfg.tunnel_base) + 41 <= 253
        out.append(Check(fits, "domain.length", f"tunnel names fit under {cfg.tunnel_base}",
                         "the tunnel base is too long for 40-character tunnel names"))
        return out

    # rollback: the base Step.undo restores config/porch.toml (file.restore)


STEP = Domain()

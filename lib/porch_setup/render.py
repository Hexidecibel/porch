"""Render HAProxy, frps and systemd user units from the domain config.

    render_haproxy(cfg, profile=None, **overrides) -> str
    render_frps(cfg, dashboard_password, **overrides) -> str
    render_units(cfg, profile=None, **overrides) -> {unit file name: text}
    options(cfg, profile=None, **overrides) -> dict      (what the renderers use)

Templates live in config/templates/. haproxy.cfg.tmpl is split into
"## @fragment <name>" blocks; compose_haproxy() picks and orders them from
the options, so there is no template logic beyond ${var} substitution
(string.Template; $$ is a literal $).

Profiles (cfg.install_mode picks the default):
  fresh  HAProxy serves everything: the landing host's /auth/, /api/ and /l/
         go straight to the auth server, the status API and the shortener;
         a static server (porch-landing, :9473) serves the landing page. No
         domain-wide cush_auth edge gate, no apex routes, HSTS without
         includeSubDomains/preload, cert at $PORCH_CERT_DIR/porch-<root>.pem (~/.local/share/porch/certs).
  adopt  This box's legacy layout: nginx serves the landing host (:8091) and
         the apex (:8090), the cush_auth edge gate and cookie strip are on,
         the apex routes /l/ to the shortener, cert at /etc/ssl/ssl-certs/<root>.
"""

import os
import string

from .state import REPO_DIR

TEMPLATES_DIR = os.path.join(REPO_DIR, "config", "templates")

PORTS = {
    "auth_port": 9512, "status_port": 9471, "shortener_port": 9411,
    "frp_vhost_port": 7080, "frp_dashboard_port": 7500, "acme_http_port": 9785,
    "apex_port": 8090,
    # relay modes: HAProxy's accept-proxy binds the porch-relay frpc feeds
    # (not 8080/8443: the setup wizard listens on 8443) and frpc's admin API
    "relay_http_port": 9476, "relay_https_port": 9477, "relay_admin_port": 9478,
}
STATIC_LANDING_PORT = 9473
NGINX_LANDING_PORT = 8091

PROFILES = {
    "fresh": {"landing": "static", "edge_gate": False, "apex": False, "relay": False,
              "hsts": "max-age=31536000",
              "cert_path": "{cert_dir}/porch-{root}.pem",
              "auth_backend": "porch_auth"},
    "adopt": {"landing": "nginx", "edge_gate": True, "apex": True, "relay": False,
              "hsts": "max-age=31536000",
              "cert_path": "/etc/ssl/ssl-certs/{root}",
              # this box's live config names the auth backend cush_auth (legacy)
              "auth_backend": "cush_auth"},
}

UNITS = ("porch-auth", "porch-frps", "porch-status", "porch-shortener", "porch-landing")


class RenderError(Exception):
    pass


def default_web_root(env=None):
    env = os.environ if env is None else env
    base = env.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.join(base, "porch", "landing")


def cert_dir(env=None):
    """Where bin/porch-cert-deploy writes the combined PEM (acme.cert_dir).
    HAProxy loads it as root at start/reload, before dropping privileges."""
    env = os.environ if env is None else env
    return env.get("PORCH_CERT_DIR") or os.path.expanduser("~/.local/share/porch/certs")


def options(cfg, profile=None, **overrides):
    """The full option set: profile preset + ports + paths + overrides."""
    profile = profile or getattr(cfg, "install_mode", "fresh")
    if profile not in PROFILES:
        raise RenderError(f"unknown profile {profile!r} (known: {', '.join(PROFILES)})")
    o = dict(PROFILES[profile])
    o["profile"] = profile
    o.update(PORTS)
    o["landing_port"] = STATIC_LANDING_PORT if o["landing"] == "static" else NGINX_LANDING_PORT
    o.update({"repo_dir": REPO_DIR, "data_dir": os.path.join(REPO_DIR, "data"),
              "maps_dir": "/etc/haproxy/maps", "web_root": default_web_root(),
              # Porch's error pages (lib/porch_errors.py, bin/haproxy-errors).
              "errors_dir": "/etc/haproxy/errors/porch"})
    for k, v in overrides.items():
        if v is not None:
            o[k] = v
    if "landing" in overrides and "landing_port" not in overrides:
        o["landing_port"] = STATIC_LANDING_PORT if o["landing"] == "static" else NGINX_LANDING_PORT
    o["cert_path"] = o["cert_path"].format(root=cfg.root, cert_dir=cert_dir())
    return o


def variables(cfg, opts):
    v = {"brand": cfg.brand, "root": cfg.root, "tunnel_base": cfg.tunnel_base,
         "auth_host": cfg.auth_host, "panel_host": cfg.panel_host,
         "landing_host": cfg.landing_host, "frp_port": cfg.frp_port}
    v.update({k: val for k, val in opts.items() if not isinstance(val, bool)})
    return v


def _read(name):
    with open(os.path.join(TEMPLATES_DIR, name), encoding="utf-8") as f:
        return f.read()


def _subst(text, vars_, where):
    try:
        return string.Template(text).substitute(vars_)
    except KeyError as e:
        raise RenderError(f"{where}: no value for ${{{e.args[0]}}}") from None
    except ValueError as e:
        raise RenderError(f"{where}: {e}") from None


def fragments(text=None):
    """{name: text} from haproxy.cfg.tmpl, in file order."""
    text = _read("haproxy.cfg.tmpl") if text is None else text
    out, cur = {}, None
    for line in text.splitlines(keepends=True):
        if line.startswith("## @fragment "):
            cur = line.split(None, 2)[2].strip()
            out[cur] = ""
            continue
        if line.startswith("##") or cur is None:
            continue
        out[cur] += line
    return out


def compose_haproxy(opts):
    """Ordered fragment names for these options."""
    names = ["global", "defaults", "frontend_head"]
    if opts["relay"]:
        names.append("relay_binds")
    names.append("frontend_headers")
    if opts["apex"]:
        names.append("acls_apex")
    names.append("acls_core")
    if opts["edge_gate"]:
        names.append("gate_acls")
    names.append("routing_auth")
    if opts["edge_gate"]:
        names += ["gate", "cookie_strip"]
    if opts["apex"]:
        names.append("routing_apex")
    if opts["landing"] == "static":
        names.append("routing_landing_static")
    names += ["routing", "frontend_tail", "backends"]
    if opts["apex"]:
        names.append("backends_apex")
    return names


def render_haproxy(cfg, profile=None, **overrides):
    opts = options(cfg, profile, **overrides)
    frags = fragments()
    vars_ = variables(cfg, opts)
    parts = []
    for name in compose_haproxy(opts):
        if name not in frags:
            raise RenderError(f"haproxy.cfg.tmpl has no fragment {name!r}")
        parts.append(_subst(frags[name], vars_, f"haproxy fragment {name}"))
    head = (f"# Rendered by porch (profile {opts['profile']}) for {cfg.root}. "
            f"Regenerate with: porch render haproxy\n")
    return head + "".join(parts)


def render_frps(cfg, dashboard_password, profile=None, **overrides):
    if not dashboard_password or '"' in dashboard_password or "\\" in dashboard_password:
        raise RenderError("frps dashboard password must be non-empty without quotes or backslashes")
    opts = options(cfg, profile, **overrides)
    vars_ = variables(cfg, opts)
    vars_["frp_dashboard_password"] = dashboard_password
    return _subst(_read("frps.toml.tmpl"), vars_, "frps.toml.tmpl")


def unit_names(opts):
    return [u for u in UNITS if u != "porch-landing" or opts["landing"] == "static"]


def render_units(cfg, profile=None, **overrides):
    opts = options(cfg, profile, **overrides)
    vars_ = variables(cfg, opts)
    # Without the edge gate HAProxy loads no maps, so the auth server neither
    # writes them nor needs the haproxy admin socket (no haproxy group).
    vars_["auth_maps_args"] = (f"--maps-dir {opts['maps_dir']}" if opts["edge_gate"]
                               else "--no-maps")
    return {f"{u}.service": _subst(_read(f"systemd/{u}.service.tmpl"), vars_, u)
            for u in unit_names(opts)}

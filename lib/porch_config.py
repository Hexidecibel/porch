#!/usr/bin/env python3
"""Porch domain config: the one place that knows which domain this box serves.

Source, highest priority first:
  1. PORCH_* environment variables (see ENV_KEYS),
  2. the TOML file at $PORCH_CONFIG, else <repo>/config/porch.toml,
  3. built-in defaults, which are this box's cush.rocks values.

PORCH_CONFIG=none skips the file (bin/test uses it, so the suite never reads
the live config). A missing default file is not an error: the defaults apply.
An unreadable or invalid file IS an error (ConfigError), never a silent
fallback to the defaults, so a typo cannot quietly point the box elsewhere.

Unset host keys derive from domain.root: tunnel_base = "tunnel.<root>",
auth_host = "auth.<root>", panel_host = "panel.<root>", landing_host =
<tunnel_base>, cookie_domain = ".<root>", server.frp_addr = <tunnel_base>.

Python:
    import porch_config
    cfg = porch_config.get()          # cached; porch_config.reset() drops it
    cfg.tunnel_base, cfg.tunnel_url("drop"), cfg.auth_url("/auth/")
    porch_config.load(path=..., env={...})   # uncached, for tests / the wizard

Shell (lib/porch-config.sh wraps the first form):
    eval "$(python3 lib/porch_config.py shell)"   # PORCH_DOMAIN=..., PORCH_TUNNEL_BASE=...
    python3 lib/porch_config.py get domain.tunnel_base
    python3 lib/porch_config.py check [path]      # validate, exit 1 on error
    python3 lib/porch_config.py dump              # resolved values as JSON
"""

import json
import os
import re
import shlex
import sys

try:
    import tomllib as _toml
except ImportError:  # Python < 3.11 (a paired macOS laptop, say)
    try:
        import tomli as _toml  # type: ignore
    except ImportError:
        _toml = None

LIB_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(LIB_DIR)
DEFAULT_PATH = os.path.join(REPO_DIR, "config", "porch.toml")

DEFAULT_ROOT = "cush.rocks"
DEFAULT_BRAND = "Porch"
DEFAULT_FRP_PORT = 7000

# Only for the built-in root: these are this box's own gated apps. Any other
# root starts with none, and default_rd falls back to the landing page.
_CUSH_AUTH_DEFAULTS = {
    "default_rd": "https://grab.cush.rocks/",
    "protected_apps": ["grab.cush.rocks"],
    "known_apps": [
        "grab.cush.rocks", "issues.cush.rocks", "autodj.cush.rocks",
        "sentinel.cush.rocks", "dash.cush.rocks", "up.cush.rocks",
        "gallery.cush.rocks", "invoicer.cush.rocks", "ma.cush.rocks",
        "trendlab.cush.rocks", "hexitech.cush.rocks", "velo.cush.rocks",
    ],
}

# (section, key) -> environment variable. Also the shell variable names that
# `porch_config.py shell` prints.
ENV_KEYS = {
    ("brand", "name"): "PORCH_BRAND",
    ("domain", "root"): "PORCH_DOMAIN",
    ("domain", "tunnel_base"): "PORCH_TUNNEL_BASE",
    ("domain", "auth_host"): "PORCH_AUTH_HOST",
    ("domain", "panel_host"): "PORCH_PANEL_HOST",
    ("domain", "landing_host"): "PORCH_LANDING_HOST",
    ("domain", "cookie_domain"): "PORCH_COOKIE_DOMAIN",
    ("server", "frp_addr"): "PORCH_FRP_ADDR",
    ("server", "frp_port"): "PORCH_FRP_PORT",
}

KNOWN = {
    "brand": {"name"},
    "domain": {"root", "tunnel_base", "auth_host", "panel_host",
               "landing_host", "cookie_domain"},
    "server": {"frp_addr", "frp_port"},
    "auth": {"default_rd", "protected_apps", "known_apps"},
    "adopt": {"localhost_bypass", "allow"},
    "install": {"mode"},
}
INSTALL_MODES = ("fresh", "adopt")

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
# A plain DNS name: two or more labels, the last one not all digits (so an
# IPv4 address is not a "domain"). No scheme, port, path, wildcard, trailing
# dot or uppercase (input is lowercased first).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)" + _LABEL + r"(?:\." + _LABEL + r")*\.(?=[a-z0-9-]*[a-z])" + _LABEL + r"$")
_BRAND_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$")
_RD_PATH_RE = re.compile(r"^/(?!/)[^\s\"'<>\\`]*$")


class ConfigError(ValueError):
    pass


def is_hostname(s):
    return isinstance(s, str) and bool(_HOSTNAME_RE.fullmatch(s))


def host_re(host):
    """re-escaped host for building anchored patterns."""
    return re.escape(host)


def label_under_re(base):
    """Regex source (unanchored) for exactly one DNS label under `base`."""
    return _LABEL + r"\." + re.escape(base)


def js_regex_escape(host):
    """A validated hostname escaped for a JS regex literal (only dots need it)."""
    if not is_hostname(host):
        raise ConfigError(f"not a hostname: {host!r}")
    return host.replace(".", r"\.")


def _host(value, what):
    if not isinstance(value, str):
        raise ConfigError(f"{what} must be a string")
    v = value.strip().lower()
    if not is_hostname(v):
        raise ConfigError(
            f"{what} must be a bare hostname like example.org "
            f"(no scheme, port, path, wildcard or trailing dot): {value!r}")
    return v


def _under(host, base):
    return host == base or host.endswith("." + base)


class Config:
    """Resolved, validated config. Attributes are plain strings/ints/tuples."""

    __slots__ = ("brand", "root", "tunnel_base", "auth_host", "panel_host",
                 "landing_host", "cookie_domain", "frp_addr", "frp_port",
                 "default_rd", "protected_apps", "known_apps", "localhost_bypass",
                 "adopt_allow", "install_mode", "source")

    def __init__(self, **kw):
        for k in self.__slots__:
            object.__setattr__(self, k, kw[k])

    def __setattr__(self, k, v):
        raise AttributeError("Config is read-only")

    def tunnel_host(self, name):
        return f"{name}.{self.tunnel_base}"

    def tunnel_url(self, name, path=""):
        return f"https://{name}.{self.tunnel_base}{path}"

    def auth_url(self, path="/"):
        return f"https://{self.auth_host}{path}"

    def as_dict(self):
        return {
            "brand": {"name": self.brand},
            "domain": {
                "root": self.root, "tunnel_base": self.tunnel_base,
                "auth_host": self.auth_host, "panel_host": self.panel_host,
                "landing_host": self.landing_host,
                "cookie_domain": self.cookie_domain,
            },
            "server": {"frp_addr": self.frp_addr, "frp_port": self.frp_port},
            "auth": {
                "default_rd": self.default_rd,
                "protected_apps": list(self.protected_apps),
                "known_apps": list(self.known_apps),
            },
            "install": {"mode": self.install_mode},
            "adopt": {
                "localhost_bypass": self.localhost_bypass,
                "allow": list(self.adopt_allow),
            },
        }

    def shell_vars(self):
        d = self.as_dict()
        out = {}
        for (sec, key), var in ENV_KEYS.items():
            out[var] = str(d[sec][key])
        return out


# ---- minimal TOML subset, only when tomllib/tomli are missing -----------------

def _mini_toml(text):
    """[section] headers; key = "string" | 'string' | int | true/false |
    ["a", "b"] (one line). Enough for config/porch.toml.example."""
    data, cur = {}, None
    lines = text.splitlines()
    n = 0
    while n < len(lines):
        raw = lines[n]
        n += 1
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # A multi-line array: join until the closing bracket.
        if re.match(r"^[A-Za-z0-9_-]+\s*=\s*\[", line) and "]" not in line:
            while n < len(lines) and "]" not in line:
                nxt = lines[n].strip()
                n += 1
                if not nxt.startswith("#"):
                    line += " " + nxt
            raw = line
        m = re.match(r"^\[([A-Za-z0-9_-]+)\]\s*(#.*)?$", line)
        if m:
            cur = data.setdefault(m.group(1), {})
            continue
        m = re.match(r"^([A-Za-z0-9_-]+)\s*=\s*(.+?)\s*(#[^\"']*)?$", line)
        if not m or cur is None:
            raise ConfigError(f"line {n}: cannot parse {raw!r}")
        key, val = m.group(1), m.group(2)
        try:
            if val in ("true", "false"):
                cur[key] = val == "true"
            elif re.fullmatch(r"-?\d+", val):
                cur[key] = int(val)
            elif val.startswith("'") and val.endswith("'") and len(val) >= 2:
                cur[key] = val[1:-1]
            else:
                cur[key] = json.loads(re.sub(r",\s*\]$", "]", val))
        except ValueError:
            raise ConfigError(f"line {n}: bad value {val!r}")
    return data


def _read_file(path):
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise ConfigError(f"cannot read {path}: {e}")
    try:
        if _toml is not None:
            return _toml.loads(raw.decode("utf-8"))
        return _mini_toml(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise ConfigError(f"{path}: {e}")


def _resolve_path(path, env):
    if path is not None:
        return path, True
    p = env.get("PORCH_CONFIG")
    if p == "none":
        return None, False
    if p:
        return p, True
    return DEFAULT_PATH, False


def load(path=None, env=None):
    """Resolve the config. `path` (or $PORCH_CONFIG) must exist when given;
    the default path may be missing. `env` defaults to os.environ."""
    env = os.environ if env is None else env
    path, required = _resolve_path(path, env)
    data, source = {}, None
    if path is not None and (required or os.path.exists(path)):
        data = _read_file(path)
        source = path
    if not isinstance(data, dict):
        raise ConfigError("config must be a table")
    for sec, val in data.items():
        if sec not in KNOWN:
            raise ConfigError(f"unknown section [{sec}]")
        if not isinstance(val, dict):
            raise ConfigError(f"[{sec}] must be a table")
        for k in val:
            if k not in KNOWN[sec]:
                raise ConfigError(f"unknown key {sec}.{k}")

    def pick(sec, key):
        var = ENV_KEYS.get((sec, key))
        if var and env.get(var, "") != "":
            return env[var]
        return data.get(sec, {}).get(key)

    brand = pick("brand", "name")
    brand = DEFAULT_BRAND if brand is None else brand
    if not isinstance(brand, str) or not _BRAND_RE.fullmatch(brand.strip()):
        raise ConfigError(f"brand.name must be 1-40 plain characters: {brand!r}")
    brand = brand.strip()

    root = pick("domain", "root")
    root = DEFAULT_ROOT if root is None else _host(root, "domain.root")

    def host_key(key, default):
        v = pick("domain", key)
        return default if v is None else _host(v, f"domain.{key}")

    tunnel_base = host_key("tunnel_base", f"tunnel.{root}")
    auth_host = host_key("auth_host", f"auth.{root}")
    panel_host = host_key("panel_host", f"panel.{root}")
    landing_host = host_key("landing_host", tunnel_base)

    cd = pick("domain", "cookie_domain")
    if cd is None:
        cookie_domain = "." + root
    else:
        if not isinstance(cd, str) or not cd.strip().startswith("."):
            raise ConfigError(f"domain.cookie_domain must start with a dot, like .example.org: {cd!r}")
        cookie_domain = "." + _host(cd.strip()[1:], "domain.cookie_domain")
    cbase = cookie_domain[1:]
    for what, h in (("auth_host", auth_host), ("tunnel_base", tunnel_base),
                    ("panel_host", panel_host)):
        if not _under(h, cbase):
            raise ConfigError(
                f"domain.{what} ({h}) is not under domain.cookie_domain ({cookie_domain}); "
                f"the auth server's cookie would never reach it")
    if not _under(auth_host, root):
        raise ConfigError(f"domain.auth_host ({auth_host}) must be under domain.root ({root})")

    frp_addr = pick("server", "frp_addr")
    frp_addr = tunnel_base if frp_addr is None else _host(frp_addr, "server.frp_addr")
    port = pick("server", "frp_port")
    if port is None:
        port = DEFAULT_FRP_PORT
    if isinstance(port, bool):
        raise ConfigError("server.frp_port must be an integer 1-65535")
    try:
        if isinstance(port, str) and not re.fullmatch(r"\d{1,5}", port.strip()):
            raise ValueError
        port = int(port)
    except (TypeError, ValueError):
        raise ConfigError(f"server.frp_port must be an integer 1-65535: {port!r}")
    if not 1 <= port <= 65535:
        raise ConfigError(f"server.frp_port must be an integer 1-65535: {port!r}")

    # [auth]: the auth server's gate. Hosts are one label under root.
    one_label = re.compile(r"^" + label_under_re(root) + r"$")
    builtin = _CUSH_AUTH_DEFAULTS if root == DEFAULT_ROOT else {
        "default_rd": f"https://{landing_host}/", "protected_apps": [], "known_apps": []}
    auth = data.get("auth", {})

    def host_list(key):
        v = auth.get(key, builtin[key])
        if not isinstance(v, list):
            raise ConfigError(f"auth.{key} must be a list of hostnames")
        out = []
        for h in v:
            h = _host(h, f"auth.{key} entry")
            if not one_label.fullmatch(h) or h == auth_host:
                raise ConfigError(
                    f"auth.{key}: {h} must be one label under {root} and not the auth host")
            if h not in out:
                out.append(h)
        return tuple(out)

    protected = host_list("protected_apps")
    known = host_list("known_apps")
    rd = auth.get("default_rd", builtin["default_rd"])
    m = re.fullmatch(r"https://([^/]+)(/.*)?$", rd) if isinstance(rd, str) else None
    rd_host = m.group(1) if m else ""
    if not m or not one_label.fullmatch(rd_host) or not _RD_PATH_RE.fullmatch(m.group(2) or "/"):
        raise ConfigError(
            f"auth.default_rd must be https://<one label under {root}>/...: {rd!r}")
    if m.group(2) is None:
        rd += "/"

    # [install] mode: "fresh" (porch setup built this box) or "adopt" (an
    # existing install porch only verifies; render uses its legacy layout).
    # [adopt]: settings for such an install.
    # localhost_bypass keeps authserver's old "any 127.0.0.1 frpc login is
    # trusted" rule (PORCH_LOCALHOST_BYPASS=1/0 overrides it); fresh installs
    # leave it off and the home frpc uses data/.home-frpc-token. allow lists
    # accepted haproxy adopt-diff deltas (lib/porch_setup/haproxy_diff.py).
    mode = data.get("install", {}).get("mode", "fresh")
    if mode not in INSTALL_MODES:
        raise ConfigError(f"install.mode must be one of {', '.join(INSTALL_MODES)}: {mode!r}")
    adopt = data.get("adopt", {})
    bypass = adopt.get("localhost_bypass", mode == "adopt")
    if not isinstance(bypass, bool):
        raise ConfigError("adopt.localhost_bypass must be true or false")
    allow = adopt.get("allow", [])
    if not isinstance(allow, list) or not all(isinstance(a, str) and a.strip() for a in allow):
        raise ConfigError("adopt.allow must be a list of non-empty strings")

    return Config(brand=brand, root=root, tunnel_base=tunnel_base,
                  auth_host=auth_host, panel_host=panel_host,
                  landing_host=landing_host, cookie_domain=cookie_domain,
                  frp_addr=frp_addr, frp_port=port, default_rd=rd,
                  protected_apps=protected, known_apps=known,
                  localhost_bypass=bypass, install_mode=mode, adopt_allow=tuple(a.strip() for a in allow),
                  source=source)


_CACHED = None


def get():
    """The process-wide config (loaded once)."""
    global _CACHED
    if _CACHED is None:
        _CACHED = load()
    return _CACHED


def reset():
    global _CACHED
    _CACHED = None


# The raw repo copies of site/*.sh are what strangers run before they have a
# Porch server: site/porch.sh installs the latest GitHub release, and
# site/install.sh (the client installer, which only makes sense against
# somebody's Porch server) carries LANDING_MARK and refuses to run until
# rendered. site_render turns all three into this box's own landing URLs, so a
# running Porch serves installers that fetch its own tarball.
GITHUB_REPO = "Hexidecibel/porch"
RELEASE_TARBALL_URL = f"https://github.com/{GITHUB_REPO}/releases/latest/download/porch.tar.gz"
RAW_INSTALLER_URL = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/site/porch.sh"
LANDING_MARK = "@PORCH_LANDING_URL@"


def site_render(text, cfg):
    """site/ files are written for the default domain and the public GitHub
    install path. Swap the release tarball / raw installer URLs and the
    LANDING_MARK for this box's landing URLs, and the default
    landing/panel/auth URLs for the configured ones. Longest hosts first,
    so no replacement feeds another."""
    d = load(env={"PORCH_CONFIG": "none"})
    land = f"https://{cfg.landing_host}"
    pairs = [(RELEASE_TARBALL_URL, f"{land}/cush-tools.tar.gz"),
             (RAW_INSTALLER_URL, f"{land}/porch.sh"),
             (LANDING_MARK, land),
             (f"https://{d.panel_host}", f"https://{cfg.panel_host}"),
             (f"https://{d.auth_host}", f"https://{cfg.auth_host}"),
             (f"https://{d.landing_host}", land)]
    marks = []
    for i, (old, _new) in enumerate(pairs):
        mark = f"\x00porch{i}\x00"
        text = text.replace(old, mark)
        marks.append(mark)
    for mark, (_old, new) in zip(marks, pairs):
        text = text.replace(mark, new)
    return text


def _lookup(cfg, dotted):
    d = cfg.as_dict()
    sec, _, key = dotted.partition(".")
    if sec not in d or key not in d[sec]:
        raise KeyError(dotted)
    return d[sec][key]


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    usage = ("usage: porch_config.py get <section.key> | shell | dump | check [path]"
             " | render <file>")
    if not argv:
        print(usage, file=sys.stderr)
        return 2
    cmd, rest = argv[0], argv[1:]
    try:
        if cmd == "check":
            cfg = load(path=rest[0] if rest else None)
            print(f"ok: {cfg.source or 'built-in defaults'} -> root={cfg.root} tunnel_base={cfg.tunnel_base}")
            return 0
        cfg = load()
        if cmd == "get" and len(rest) == 1:
            try:
                v = _lookup(cfg, rest[0])
            except KeyError:
                print(f"porch_config: unknown key {rest[0]}", file=sys.stderr)
                return 2
            print(" ".join(v) if isinstance(v, list) else v)
            return 0
        if cmd == "shell" and not rest:
            for k, v in cfg.shell_vars().items():
                print(f"{k}={shlex.quote(v)}")
            return 0
        if cmd == "render" and len(rest) == 1:
            with open(rest[0], encoding="utf-8") as f:
                sys.stdout.write(site_render(f.read(), cfg))
            return 0
        if cmd == "dump" and not rest:
            d = cfg.as_dict()
            d["source"] = cfg.source
            print(json.dumps(d, indent=2))
            return 0
    except ConfigError as e:
        print(f"porch_config: {e}", file=sys.stderr)
        return 1
    print(usage, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())

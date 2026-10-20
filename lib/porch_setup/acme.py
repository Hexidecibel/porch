"""certbot driver for porch: unprivileged DNS-01 issuance, renewal, inspection,
and the provider-generic certbot --manual hook behind bin/porch-acme-hook.

certbot runs as the porch user with its own dirs (no root, so the hook can
read the user's Infisical / file:// secrets):

    ~/.local/share/porch/acme/{config,work,logs}     ($PORCH_ACME_DIR)
    ~/.local/share/porch/certs/<cert-name>.pem       ($PORCH_CERT_DIR; combined
                                                      fullchain+key for HAProxy,
                                                      written by bin/porch-cert-deploy)

    argv = certonly_argv(domains, cert_name, hook_cmd=..., deploy_hook=..., dry_run=True)
    info = inspect_pem(runner, pem_text)      # CertInfo(sans, not_after, subject)
    served_pem("auth.example.com")            # what HAProxy serves for that SNI

The hook (`hook_main("auth"|"cleanup", env)`) reads the provider, its
username, the token ref and the zone from the setup state file
($PORCH_SETUP_DIR/porch-setup.json), ADDS the TXT value at
_acme-challenge.<domain> (tunnel.X and *.tunnel.X share that name, so two
values are live at once), waits until every authoritative NS serves it, and on
cleanup deletes only the record holding its own value.
"""

import datetime
import json
import os
import re
import shlex
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field
from typing import List, Optional

from . import state as _state
from .dnsq import DNSError, Resolver, norm

MIN_CERTBOT = (2, 0, 0)
RENEW_DAYS = 20
CERTBOT = "certbot"


class AcmeError(Exception):
    def __init__(self, code, message, hint=""):
        self.code, self.message, self.hint = code, message, hint
        super().__init__(f"{code}: {message}")


# ---- paths -------------------------------------------------------------------------

def acme_dir(env=None):
    env = os.environ if env is None else env
    return env.get("PORCH_ACME_DIR") or os.path.expanduser("~/.local/share/porch/acme")


def cert_dir(env=None):
    env = os.environ if env is None else env
    return env.get("PORCH_CERT_DIR") or os.path.join(
        env.get("HOME") or os.path.expanduser("~"), ".local/share/porch/certs")


def dir_args(base):
    return ["--config-dir", os.path.join(base, "config"), "--work-dir", os.path.join(base, "work"),
            "--logs-dir", os.path.join(base, "logs")]


def cert_name_for(root):
    return "porch-" + norm(root)


def lineage(base, name):
    live = os.path.join(base, "config", "live", name)
    return {"live": live, "fullchain": os.path.join(live, "fullchain.pem"),
            "privkey": os.path.join(live, "privkey.pem"),
            "renewal": os.path.join(base, "config", "renewal", name + ".conf")}


def combined_pem_path(name, env=None):
    return os.path.join(cert_dir(env), name + ".pem")


# ---- certbot ------------------------------------------------------------------------

def parse_version(text):
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text or "")
    if not m:
        return None
    return tuple(int(x or 0) for x in m.groups())


def certbot_version(runner):
    """(major, minor, patch) or None when certbot is not installed."""
    r = runner.run([CERTBOT, "--version"], mutating=False, timeout=60)
    if r.returncode != 0:
        return None
    return parse_version(r.stdout + " " + r.stderr)


def version_check(runner):
    v = certbot_version(runner)
    if v is None:
        raise AcmeError("cert.certbot_missing", "certbot is not installed",
                        "install it: sudo apt install certbot  (or: sudo snap install --classic certbot)")
    if v < MIN_CERTBOT:
        raise AcmeError("cert.certbot_old", f"certbot {'.'.join(map(str, v))} is too old "
                        f"(need {'.'.join(map(str, MIN_CERTBOT))}+)",
                        "upgrade certbot (snap has current releases)")
    return v


def hook_command(repo_dir, action):
    return shlex.quote(os.path.join(repo_dir, "bin", "porch-acme-hook")) + " " + action


def deploy_command(repo_dir):
    return shlex.quote(os.path.join(repo_dir, "bin", "porch-cert-deploy"))


def certonly_argv(domains, cert_name, *, base, repo_dir, email=None, staging=False,
                  dry_run=False, force=False):
    argv = [CERTBOT, "certonly", *dir_args(base), "--non-interactive", "--agree-tos",
            "--manual", "--preferred-challenges", "dns",
            "--manual-auth-hook", hook_command(repo_dir, "auth"),
            "--manual-cleanup-hook", hook_command(repo_dir, "cleanup"),
            "--cert-name", cert_name, "--expand"]
    argv += ["--email", email, "--no-eff-email"] if email else ["--register-unsafely-without-email"]
    if dry_run:
        argv.append("--dry-run")          # staging, nothing saved, no deploy hook
    else:
        argv += ["--deploy-hook", deploy_command(repo_dir)]
        if staging:
            argv.append("--test-cert")
        argv.append("--force-renewal" if force else "--keep-until-expiring")
    for d in domains:
        argv += ["-d", d]
    return argv


def renew_argv(cert_name, *, base, repo_dir, dry_run=False, force=False):
    argv = [CERTBOT, "renew", *dir_args(base), "--non-interactive", "--cert-name", cert_name,
            "--deploy-hook", deploy_command(repo_dir)]
    if dry_run:
        argv.append("--dry-run")
    if force:
        argv.append("--force-renewal")
    return argv


def hook_env(ctx_env, data_dir, secrets_root):
    """Env for certbot so its hooks find this run's state and secrets."""
    return {"PORCH_SETUP_DIR": data_dir, "PORCH_SECRETS_DIR": secrets_root,
            "PORCH_CERT_DIR": cert_dir(ctx_env), "PORCH_ACME_DIR": acme_dir(ctx_env)}


def tail(text, n=6):
    lines = [x for x in (text or "").strip().splitlines() if x.strip()]
    return " | ".join(lines[-n:])


# ---- transient CA errors: retry; rate limits: stop and say when -----------------------
#
# Let's Encrypt sheds load with "Service busy; retry later" (an
# urn:ietf:params:acme:error:rateLimited problem without "too many"), 503s
# and "Service Unavailable". Those clear in a minute or two, so certbot is
# re-run (3 tries over ~2 minutes, or what a Retry-After hint asks for). A real
# rate limit ("too many certificates/failed authorizations/new orders/...")
# lasts hours to days and retrying only digs deeper: never retried, reported
# with the "retry after <date>" certbot prints.

BUSY_TRIES = 3
BUSY_DELAYS = (30, 90)          # seconds before try 2 and try 3
BUSY_MAX_WAIT = 300             # a Retry-After longer than this is not waited out

_RATE_LIMIT_RE = re.compile(
    r"too many (?:certificates|failed authori[sz]ations|new orders|registrations|"
    r"pending authori[sz]ations|requests|accounts|new authori[sz]ations)", re.I)
_BUSY_RE = re.compile(
    r"service busy|retry later|service unavailable|temporarily unavailable|"
    r"\b503\b|urn:ietf:params:acme:error:rateLimited|:: rateLimited", re.I)
_RETRY_DATE_RE = re.compile(
    r"retry after (\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?: ?UTC|Z|[+-]\d{2}:?\d{2})?)",
    re.I)
_RETRY_SECS_RE = re.compile(r"retry[- ]after:?\s*(\d+)\s*(?:s|secs?|seconds?)?(?![-:\d])", re.I)


def classify_certbot_failure(text):
    """(kind, retry_after_seconds, retry_after_date) for certbot's output.
    kind: "rate_limit" (never retry), "busy" (transient, retry) or None."""
    text = text or ""
    m = _RETRY_DATE_RE.search(text)
    when = m.group(1) if m else None
    if _RATE_LIMIT_RE.search(text):
        return "rate_limit", None, when
    if _BUSY_RE.search(text):
        m = _RETRY_SECS_RE.search(text)
        return "busy", (int(m.group(1)) if m else None), when
    return None, None, when


def rate_limit_line(text):
    """The certbot line naming the rate limit (for the error message)."""
    for line in (text or "").splitlines():
        if _RATE_LIMIT_RE.search(line):
            return line.strip()
    return tail(text, 2)


def run_certbot(runner, argv, *, env=None, timeout=1800, sleep=None, log=None,
                tries=BUSY_TRIES, delays=BUSY_DELAYS, max_wait=BUSY_MAX_WAIT):
    """Run certbot, re-running it while Let's Encrypt is merely busy. Returns
    the last Result (returncode != 0 for any other failure). Raises AcmeError
    cert.rate_limited for a real rate limit (with certbot's retry-after date)
    and cert.busy when the CA stays busy or asks for a longer wait."""
    sleep = sleep or time.sleep
    log = log or (lambda msg: None)
    for attempt in range(1, tries + 1):
        r = runner.run(argv, env=env, timeout=timeout)
        if r.returncode == 0:
            return r
        out = (r.stdout or "") + "\n" + (r.stderr or "")
        kind, wait_s, when = classify_certbot_failure(out)
        if kind == "rate_limit":
            raise AcmeError(
                "cert.rate_limited",
                "Let's Encrypt rate limit hit: " + rate_limit_line(out)
                + (f" (you can try again after {when})" if when else ""),
                "not retried: retrying a rate limit only extends it. Wait until "
                + (when or "the time Let's Encrypt names") + ", then run `porch setup` again "
                "(or test with --acme-staging, which has its own limits). "
                "https://letsencrypt.org/docs/rate-limits/")
        if kind != "busy":
            return r
        if attempt == tries:
            raise AcmeError(
                "cert.busy",
                f"Let's Encrypt is busy (tried {tries} times): " + tail(out, 2),
                "a transient load-shedding answer, not a problem with this box: "
                "run `porch setup` again in a few minutes")
        delay = delays[min(attempt - 1, len(delays) - 1)]
        if wait_s is not None:
            if wait_s > max_wait:
                raise AcmeError(
                    "cert.busy",
                    f"Let's Encrypt is busy and asks to retry after {wait_s} seconds",
                    "run `porch setup` again after that")
            delay = max(wait_s, 1)
        log(f"Let's Encrypt is busy (try {attempt}/{tries}); retrying in {delay}s")
        sleep(delay)
    return r


# ---- inspection ---------------------------------------------------------------------

@dataclass
class CertInfo:
    subject: str = ""
    sans: List[str] = field(default_factory=list)
    not_after: Optional[float] = None       # epoch seconds
    issuer: str = ""

    def days_left(self, now):
        if self.not_after is None:
            return None
        return (self.not_after - now) / 86400.0

    def covers(self, host):
        return covers(self.sans, host)


def covers(sans, host):
    host = norm(host)
    for s in sans:
        s = norm(s)
        if s == host:
            return True
        if s.startswith("*.") and not host.startswith("*."):
            if "." in host and host.split(".", 1)[1] == s[2:]:
                return True
    return False


def parse_openssl(text):
    info = CertInfo()
    lines = (text or "").splitlines()
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith("notAfter="):
            try:
                info.not_after = float(ssl.cert_time_to_seconds(s.split("=", 1)[1].strip()))
            except ValueError:
                info.not_after = None
        elif s.startswith("subject="):
            info.subject = s.split("=", 1)[1].strip()
        elif s.startswith("issuer="):
            info.issuer = s.split("=", 1)[1].strip()
        elif "Subject Alternative Name" in s and i + 1 < len(lines):
            for part in lines[i + 1].split(","):
                part = part.strip()
                if part.startswith("DNS:"):
                    info.sans.append(part[4:].strip().lower())
                elif part.startswith("IP Address:"):
                    info.sans.append(part[len("IP Address:"):].strip())
    return info


def inspect_pem(runner, pem_text):
    """CertInfo for the first certificate in `pem_text` (openssl x509)."""
    r = runner.run(["openssl", "x509", "-noout", "-subject", "-issuer", "-enddate",
                    "-ext", "subjectAltName"], input=pem_text, mutating=False, timeout=30)
    if r.returncode != 0:
        raise AcmeError("cert.parse", "openssl could not read the certificate: " + tail(r.stderr, 2))
    return parse_openssl(r.stdout)


def read_cert_file(path):
    """The certificate part of a PEM file (never the key), or None."""
    try:
        with open(path, "r", encoding="ascii", errors="replace") as f:
            text = f.read()
    except OSError:
        return None
    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.S)
    return m.group(0) + "\n" if m else None


def served_pem(host, addr="127.0.0.1", port=443, timeout=5.0):
    """(pem, trusted) for the certificate served to SNI `host` at addr:port."""
    trusted = True
    der = None
    try:
        ctxv = ssl.create_default_context()
        with socket.create_connection((addr, port), timeout=timeout) as s:
            with ctxv.wrap_socket(s, server_hostname=host) as t:
                der = t.getpeercert(True)
    except ssl.SSLError:
        trusted = False
    if der is None:
        ctxn = ssl.create_default_context()
        ctxn.check_hostname = False
        ctxn.verify_mode = ssl.CERT_NONE
        with socket.create_connection((addr, port), timeout=timeout) as s:
            with ctxn.wrap_socket(s, server_hostname=host) as t:
                der = t.getpeercert(True)
    return ssl.DER_cert_to_PEM_cert(der), trusted


# ---- the certbot --manual hook --------------------------------------------------------

def challenge_name(domain):
    d = norm(domain)
    if d.startswith("*."):
        d = d[2:]
    return "_acme-challenge." + d


def load_hook_config(env):
    """{provider, username, token_ref, zone} from the setup state, with
    PORCH_DNS_* env overrides (refs only, never values)."""
    data_dir = _state.default_data_dir(env)
    path = os.path.join(data_dir, _state.STATE_NAME)
    data = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {}
    except (OSError, ValueError) as e:
        raise AcmeError("hook.state", f"cannot read the porch setup state: {type(e).__name__}")
    inputs = data.get("inputs") or {}
    refs = data.get("secret_refs") or {}
    facts = data.get("facts") or {}
    outs = ((data.get("steps") or {}).get("dns_provider") or {}).get("outputs") or {}
    cfg = {
        "provider": env.get("PORCH_DNS_PROVIDER") or outs.get("provider") or inputs.get("dns_provider"),
        "username": env.get("PORCH_DNS_USERNAME") or inputs.get("dns_username"),
        "token_ref": env.get("PORCH_DNS_TOKEN_REF") or refs.get("dns_token"),
        "zone": env.get("PORCH_DNS_ZONE") or outs.get("zone") or facts.get("zone_apex"),
    }
    if not cfg["provider"]:
        raise AcmeError("hook.config", "no DNS provider in the porch setup state",
                        "run `porch setup --only dns_provider` first")
    return cfg


def _hook_provider(cfg, env, secrets=None, http=None):
    from .dns import base as dbase
    from .secretstore import SecretStore
    cls = dbase.provider_class(cfg["provider"])
    if cls is None:
        raise AcmeError("hook.config", f"unknown DNS provider {cfg['provider']!r}")
    if isinstance(cls, dbase.Provider):
        return cls
    creds = {}
    if "token" in cls.CREDENTIALS:
        if not cfg["token_ref"]:
            raise AcmeError("hook.config", "no DNS token ref in the porch setup state",
                            "run `porch setup --only dns_provider` first")
        store = secrets or SecretStore(file_root=env.get("PORCH_SECRETS_DIR") or None)
        creds["token"] = store.get(cfg["token_ref"])
    if "username" in cls.CREDENTIALS:
        creds["username"] = cfg["username"] or ""
    return cls(creds, http=http, base_url=env.get("PORCH_DNS_BASE_URL") or None)


def _hook_resolver(env):
    servers = [s for s in (env.get("PORCH_ACME_NS") or "").split(",") if s.strip()]
    return Resolver(servers=servers) if servers else Resolver()


def _wait_txt(resolver, name, value, zone, env, clock, sleep, log, timeout):
    """Wait until every authoritative NS (or $PORCH_ACME_NS) serves the value."""
    from .dns.base import Record
    from .dns import manual
    rec = Record(name, "TXT", value)
    fixed = [s.strip() for s in (env.get("PORCH_ACME_NS") or "").split(",") if s.strip()]
    start = clock()
    while True:
        if fixed:
            res = {}
            for s in fixed:
                try:
                    res[s] = resolver.resolve(name, "TXT", server=s)
                except Exception:  # noqa: BLE001
                    res[s] = None
        else:
            try:
                res = resolver.authoritative(name, "TXT", zone=zone)
            except Exception as e:  # noqa: BLE001
                res = {}
                log(f"porch-acme-hook: authoritative lookup failed: {e}")
        if res and all(manual.matches(rec, v) for v in res.values()):
            log(f"porch-acme-hook: {name} is live on {len(res)} name server(s) after "
                f"{int(clock() - start)}s")
            return True
        if clock() - start >= timeout:
            return False
        sleep(5)


def hook_main(action, env=None, *, provider=None, resolver=None, secrets=None, http=None,
              clock=None, sleep=None, out=None):
    """certbot --manual-{auth,cleanup}-hook body. Returns an exit code."""
    import time
    env = os.environ if env is None else env
    clock = clock or time.time
    sleep = sleep or time.sleep
    out = out or sys.stderr

    def log(msg):
        print(msg, file=out, flush=True)

    if action not in ("auth", "cleanup"):
        log("usage: porch-acme-hook auth|cleanup  (run by certbot)")
        return 2
    domain = env.get("CERTBOT_DOMAIN", "")
    value = env.get("CERTBOT_VALIDATION", "")
    if not domain or not value:
        log("porch-acme-hook: CERTBOT_DOMAIN / CERTBOT_VALIDATION not set (certbot runs this)")
        return 2
    from .dns.base import ProviderError, Record
    from .secretstore import SecretError
    name = challenge_name(domain)
    try:
        cfg = load_hook_config(env)
        resolver = resolver or _hook_resolver(env)
        zone = cfg["zone"] or Resolver().zone_apex(name)
        p = provider or _hook_provider(cfg, env, secrets=secrets, http=http)
    except (AcmeError, SecretError, DNSError) as e:
        log(f"porch-acme-hook: {e}" + (f" ({e.hint})" if getattr(e, "hint", "") else ""))
        return 1
    manual = getattr(p, "MANUAL", False)
    try:
        if action == "auth":
            if manual:
                log(f"porch-acme-hook: add this record at your DNS host now:\n"
                    f"  TXT  {name}  {value}")
                timeout = float(env.get("PORCH_ACME_MANUAL_WAIT") or 900)
            else:
                existing = p.list(zone, name=name, rtype="TXT")
                if any(r.content == value for r in existing):
                    log(f"porch-acme-hook: TXT {name} already holds this value")
                else:
                    p.create(zone, Record(name, "TXT", value, ttl=300))
                    log(f"porch-acme-hook: added TXT {name} "
                        f"({len(existing) + 1} value(s) at that name now)")
                timeout = float(env.get("PORCH_ACME_WAIT") or 300)
            if _wait_txt(resolver, name, value, zone, env, clock, sleep, log, timeout):
                return 0
            log(f"porch-acme-hook: TXT {name} not live on every authoritative NS after "
                f"{int(timeout)}s; letting the CA try anyway")
            return 0
        # cleanup: delete only the record(s) holding our own value
        if manual:
            log(f"porch-acme-hook: you can now delete TXT {name} {value}")
            return 0
        mine = [r for r in p.list(zone, name=name, rtype="TXT") if r.content == value]
        for r in mine:
            p.delete(zone, r.id)
        log(f"porch-acme-hook: removed {len(mine)} TXT value(s) at {name}")
        return 0
    except ProviderError as e:
        log(f"porch-acme-hook: {e.code}: {e.message}" + (f" ({e.hint})" if e.hint else ""))
        return 1 if action == "auth" else 0


def utc_iso(epoch):
    if epoch is None:
        return None
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).replace(
        microsecond=0).isoformat().replace("+00:00", "Z")


# ---- IP-address bootstrap certificate (web wizard) ----------------------------------
#
# Let's Encrypt issues certificates for a bare IP address only under the
# `shortlived` profile (about 6 days) and only through http-01 / tls-alpn-01.
# The web wizard serves /.well-known/acme-challenge/ on :80 from `webroot`;
# certbot runs unprivileged and its --manual hook (bin/porch-acme-http-hook)
# drops the token file there. The cert is never renewed: the wizard deletes
# it when it exits.

IP_CERT_NAME = "porch-bootstrap-ip"
IP_PROFILE = "shortlived"
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{1,256}")


def http_hook_command(repo_dir, action):
    return shlex.quote(os.path.join(repo_dir, "bin", "porch-acme-http-hook")) + " " + action


def ip_certonly_argv(ip, *, base, repo_dir, email=None, staging=False, cert_name=IP_CERT_NAME):
    argv = [CERTBOT, "certonly", *dir_args(base), "--non-interactive", "--agree-tos",
            "--manual", "--preferred-challenges", "http",
            "--manual-auth-hook", http_hook_command(repo_dir, "auth"),
            "--manual-cleanup-hook", http_hook_command(repo_dir, "cleanup"),
            "--ip-address", ip, "--required-profile", IP_PROFILE,
            "--cert-name", cert_name, "--force-renewal"]
    argv += ["--email", email, "--no-eff-email"] if email else ["--register-unsafely-without-email"]
    if staging:
        argv.append("--test-cert")
    return argv


def ip_cert_delete_argv(*, base, cert_name=IP_CERT_NAME):
    return [CERTBOT, "delete", *dir_args(base), "--non-interactive", "--cert-name", cert_name]


def issue_ip_cert(ctx, ip, *, webroot, staging=False, email=None, base=None, timeout=600):
    """Issue the wizard's bootstrap certificate for `ip` (http-01, shortlived
    profile). `webroot` is the directory the wizard serves at
    /.well-known/acme-challenge/. Returns lineage(base, IP_CERT_NAME) (paths
    of fullchain.pem and privkey.pem). Raises AcmeError."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise AcmeError("cert.ip_invalid", f"not an IP address: {ip!r}") from None
    if not addr.is_global:
        raise AcmeError("cert.ip_private", f"{ip} is not a public address",
                        "an IP certificate needs this box's public IPv4/IPv6; "
                        "use the self-signed fallback over ssh -L instead")
    version_check(ctx.run)
    base = base or acme_dir(ctx.env)
    os.makedirs(base, mode=0o700, exist_ok=True)
    env = {"PORCH_ACME_WEBROOT": webroot}
    r = run_certbot(ctx.run, ip_certonly_argv(str(addr), base=base, repo_dir=ctx.repo_dir,
                                              email=email, staging=staging),
                    env=env, timeout=timeout, sleep=getattr(ctx, "sleep", None),
                    log=getattr(ctx, "log", None))
    if r.returncode != 0:
        raise AcmeError("cert.ip_issue", "certbot could not issue the IP certificate: "
                        + tail(r.stderr or r.stdout),
                        "port 80 must reach this box from the internet, and the CA must offer "
                        f"the {IP_PROFILE!r} profile for IP identifiers")
    return lineage(base, IP_CERT_NAME)


def delete_ip_cert(ctx, base=None):
    base = base or acme_dir(ctx.env)
    return ctx.run.run(ip_cert_delete_argv(base=base), timeout=120)


def http_hook_main(action, env=None, out=None):
    """bin/porch-acme-http-hook auth|cleanup: certbot --manual http-01 hook.
    Writes CERTBOT_VALIDATION to $PORCH_ACME_WEBROOT/$CERTBOT_TOKEN (0644,
    atomic) on auth and removes it on cleanup. Returns an exit code."""
    env = os.environ if env is None else env
    out = out or sys.stderr
    if action not in ("auth", "cleanup"):
        print("usage: porch-acme-http-hook auth|cleanup  (run by certbot)", file=out)
        return 2
    root = env.get("PORCH_ACME_WEBROOT", "")
    token = env.get("CERTBOT_TOKEN", "")
    value = env.get("CERTBOT_VALIDATION", "")
    if not root or not os.path.isdir(root) or os.path.islink(root):
        print("porch-acme-http-hook: PORCH_ACME_WEBROOT is not a directory", file=out)
        return 2
    if not _TOKEN_RE.fullmatch(token):
        print("porch-acme-http-hook: CERTBOT_TOKEN missing or malformed", file=out)
        return 2
    path = os.path.join(root, token)
    if action == "cleanup":
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        return 0
    if not value or "\n" in value:
        print("porch-acme-http-hook: CERTBOT_VALIDATION missing", file=out)
        return 2
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o644)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(value)
    os.replace(tmp, path)
    return 0

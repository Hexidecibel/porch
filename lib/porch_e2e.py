"""bin/porch-e2e: a throwaway DigitalOcean droplet for testing porch's
fresh-install path (`porch setup --web`) end to end.

    porch-e2e up [--region nyc3] [--size s-1vcpu-1gb] [--branch HEAD]
    porch-e2e up --redeploy [--branch HEAD]     # re-upload code, restart the wizard
    porch-e2e up --installer [--image debian-12-x64] [--production] [--domain D --dns-provider P]
                                                # the real site/porch.sh one-line installer
                                                # (curl | sudo sh) on a bare droplet
    porch-e2e up --cli --domain D --dns-provider cloudflare [--connection direct] [--acme-staging]
                                                # fully automated `porch setup` over ssh
    porch-e2e up --installer --cli --domain D --dns-provider cloudflare [--production]
                                                # porch.sh, then `porch setup --non-interactive`
    porch-e2e relay-test --domain D --dns-provider cloudflare [--acme-staging] [--keep]
                         [--mode paid|byo] [--oracle-sim] [--relay-provider digitalocean|vultr]
                                                # home droplet (inbound: ssh only) + a porch
                                                # relay (paid, byo on a plain droplet, or oracle
                                                # against Oracle's iptables), checked, torn down
    porch-e2e status
    porch-e2e ssh [cmd ...]
    porch-e2e logs [-n N]
    porch-e2e down [--yes]

The DO token comes from inf://prod/porch/DIGITALOCEAN_TOKEN (override with
PORCH_E2E_TOKEN_REF). It is only ever held in memory and sent in the
Authorization header: never printed, never in argv, never on disk. Every
droplet this tool creates or deletes carries the `porch-e2e` tag; deletion is
by tag, so nothing else in the account is touched.

Local state (key pair, known_hosts, state.json) lives in
~/.local/share/porch/e2e (PORCH_E2E_DIR), 0700/0600. The droplet gets only
`git archive <branch>` (tracked files) plus the official frp release
(sha256-pinned): no secrets, devices.json, porch.toml or DNS credentials.
--cli and relay-test send the DNS token and a throwaway admin password on
ssh's stdin (never argv, never a file). relay-test also writes the DO token
to a 0600 file:// secret on the home droplet for `porch connect paid`, and
deletes it right after setup (and again after the rollback in `down`).
"""

import argparse
import ipaddress
import json
import os
import re
import secrets as _secrets
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request

API = "https://api.digitalocean.com/v2"
TAG = "porch-e2e"
TOKEN_REF = "inf://prod/porch/DIGITALOCEAN_TOKEN"
CF_TOKEN_REF = "inf://prod/porch/CLOUDFLARE_TOKEN"
WIZARD_PORT = 8443
DNS_CLEAN_WAIT = 60     # seconds down polls the authoritative NS for leftover records
IMAGE = "ubuntu-24-04-x64"
DEFAULT_REGION = "nyc3"
DEFAULT_SIZE = "s-1vcpu-1gb"
USER = "porch"
REMOTE_REPO = "/home/porch/porch"
WIZARD_UNIT = "porch-e2e-wizard"
WIZARD_LOG = "/home/porch/wizard.log"
DEFAULT_ROOT = "cush.rocks"                     # lib/porch_config.py's built-in domain.root
INSTALLER_UNIT = "porch-wizard"                 # site/porch.sh's wizard unit
INSTALL_UPLOAD = "/root/porch-install"          # tarball + .sha256 for PORCH_TARBALL=file://
INSTALLER_PORTS = ("22", "80", "8443")          # cloud firewall for up --installer
INSTALLER_CLI_PORTS = ("443", "7000")           # + these with --installer --cli (the finished box)
FRP_VERSION = "0.67.0"
FRP_SHA256 = "f8629ca7ca56b8e7e7a9903779b8d5c47c56ad1b75b99b2d7138477acc4c7105"  # linux_amd64
URL_RE = re.compile(r"https://\S+/#k=[A-Za-z0-9_\-]+")
FIREWALL_PREFIX = "porch-e2e-"
RELAY_TOKEN_FILE = ".config/porch/secrets/do-relay"         # under /home/porch
RELAY_TOKEN_REF = "file://~/" + RELAY_TOKEN_FILE
VULTR_TOKEN_REF = "inf://prod/porch/VULTR_TOKEN"
# relay-test --relay-provider: (env override, default ref, what, token file on home)
RELAY_PROVIDERS = {
    "digitalocean": ("PORCH_E2E_TOKEN_REF", TOKEN_REF, "DigitalOcean token", RELAY_TOKEN_FILE),
    "vultr": ("PORCH_E2E_VULTR_TOKEN_REF", VULTR_TOKEN_REF, "Vultr token", ".config/porch/secrets/vultr-relay"),
}
BYO_SIZE = "s-1vcpu-512mb-10gb"                 # relay-test --mode byo: "your own server"
BYO_KEY = "/home/porch/.ssh/porch-relay"        # home's key for it (made on home, never leaves)
# relay-test --oracle-sim: the firewall Oracle's Ubuntu images ship (iptables
# REJECT everything but ssh, saved by netfilter-persistent, ufw off).
ORACLE_SIM = r"""set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
cloud-init status --wait >/dev/null 2>&1 || true
ufw disable >/dev/null 2>&1 || true
for i in $(seq 60); do fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || break; sleep 5; done
echo iptables-persistent iptables-persistent/autosave_v4 boolean false | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean false | debconf-set-selections
apt-get update -q >/dev/null
apt-get install -y -q iptables-persistent >/dev/null
iptables -F INPUT
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p udp --sport 123 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited
netfilter-persistent save >/dev/null 2>&1
echo oracle-sim-ready
"""
STEP_COUNT = 14


class E2EError(Exception):
    pass


def state_dir(env=None):
    env = os.environ if env is None else env
    return env.get("PORCH_E2E_DIR") or os.path.expanduser("~/.local/share/porch/e2e")


def ensure_dir(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def write_private(path, data):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(data)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def load_state(d):
    p = os.path.join(d, "state.json")
    try:
        with open(p) as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def save_state(d, st):
    write_private(os.path.join(d, "state.json"), json.dumps(st, indent=2, sort_keys=True) + "\n")


# ---- DigitalOcean API ----------------------------------------------------------------

def urllib_http(method, url, headers, body, timeout=30):
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


class DO:
    """Minimal DO v2 client. `http(method, url, headers, body) -> (status, bytes)`."""

    def __init__(self, token, http=None):
        self._token = token
        self.http = http or urllib_http

    def _redact(self, s):
        return s.replace(self._token, "<token>") if self._token else s

    def request(self, method, path, body=None, ok=(200, 201, 202, 204)):
        headers = {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}
        data = json.dumps(body).encode() if body is not None else None
        status, raw = self.http(method, API + path, headers, data)
        if status not in ok:
            msg = raw.decode("utf-8", "replace")[:300]
            raise E2EError(self._redact(f"DigitalOcean {method} {path}: HTTP {status}: {msg}"))
        return json.loads(raw) if raw else {}

    def droplets(self, tag=TAG):
        out = self.request("GET", f"/droplets?tag_name={tag}&per_page=200").get("droplets", [])
        # belt and braces: never act on a droplet whose tags lack ours
        return [d for d in out if tag in (d.get("tags") or [])]

    def droplet(self, did):
        return self.request("GET", f"/droplets/{int(did)}")["droplet"]

    def create_droplet(self, name, region, size, key_id, image=IMAGE):
        body = {"name": name, "region": region, "size": size, "image": image or IMAGE,
                "ssh_keys": [key_id], "tags": [TAG], "ipv6": True, "monitoring": False}
        return self.request("POST", "/droplets", body)["droplet"]

    def delete_tagged(self, tag=TAG):
        if not tag:
            raise E2EError("refusing to delete droplets without a tag")
        self.request("DELETE", f"/droplets?tag_name={tag}", ok=(204, 404))

    def add_key(self, name, public_key):
        return self.request("POST", "/account/keys", {"name": name, "public_key": public_key})["ssh_key"]

    def delete_key(self, key_id):
        self.request("DELETE", f"/account/keys/{int(key_id)}", ok=(204, 404))

    def size_regions(self, size):
        for z in self.request("GET", "/sizes?per_page=200").get("sizes", []):
            if z.get("slug") == size and z.get("available"):
                return list(z.get("regions") or [])
        return []

    def keys(self):
        return self.request("GET", "/account/keys?per_page=200").get("ssh_keys", [])

    # cloud firewalls cannot carry tags: porch-e2e's are named porch-e2e-*
    def create_firewall(self, name, droplet_ids, ports=("22",)):
        if not name.startswith(FIREWALL_PREFIX):
            raise E2EError(f"firewall name must start with {FIREWALL_PREFIX}")
        anywhere = {"addresses": ["0.0.0.0/0", "::/0"]}
        body = {"name": name, "droplet_ids": [int(d) for d in droplet_ids],
                "inbound_rules": [{"protocol": "tcp", "ports": str(p), "sources": anywhere}
                                  for p in ports],
                "outbound_rules": [{"protocol": "tcp", "ports": "all", "destinations": anywhere},
                                   {"protocol": "udp", "ports": "all", "destinations": anywhere},
                                   {"protocol": "icmp", "destinations": anywhere}]}
        return self.request("POST", "/firewalls", body)["firewall"]

    def firewalls(self):
        out = self.request("GET", "/firewalls?per_page=200").get("firewalls", [])
        return [f for f in out if str(f.get("name", "")).startswith(FIREWALL_PREFIX)]

    def delete_firewall(self, fid):
        if not re.match(r"\A[0-9a-f-]{8,64}\Z", str(fid)):
            raise E2EError(f"not a firewall id: {fid!r}")
        self.request("DELETE", f"/firewalls/{fid}", ok=(204, 404))


REGION_PREFERENCE = ("nyc3", "nyc1", "tor1", "sfo3", "sfo2", "ams3", "lon1", "fra1")


def pick_region(want, available):
    """`want` if the size is offered there, else the first preferred region
    that has it (DO's size availability shifts), else None."""
    if want in available:
        return want
    for r in REGION_PREFERENCE:
        if r in available:
            return r
    return available[0] if available else None


def public_ip(d):
    for n in (d.get("networks") or {}).get("v4", []):
        if n.get("type") == "public":
            return n.get("ip_address")
    return None


def parse_ts(s):
    import datetime
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc).timestamp()


def est_cost(d, now):
    hours = max(0.0, (now - parse_ts(d["created_at"])) / 3600)
    price = float((d.get("size") or {}).get("price_hourly") or 0)
    return hours, hours * price


# ---- ssh -------------------------------------------------------------------------------

class Remote:
    def __init__(self, d, ip, run=None, popen=None):
        self.d, self.ip = d, ip
        self.run = run or subprocess.run
        self.popen = popen or subprocess.Popen

    def stream(self, user, cmd, input=None, on_line=None, timeout=3600):
        """Run cmd, handing each output line to on_line as it arrives.
        stdin (secrets) is written then closed. Returns the exit code."""
        p = self.popen(self.argv(user, cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT)
        try:
            if input is not None:
                p.stdin.write(input)
            p.stdin.close()
        except BrokenPipeError:
            pass
        for raw in p.stdout:
            if on_line:
                on_line(_text(raw).rstrip("\n"))
        return p.wait(timeout=timeout)

    def argv(self, user, cmd=None, tty=False):
        a = ["ssh", "-i", os.path.join(self.d, "id_ed25519"),
             "-o", f"UserKnownHostsFile={os.path.join(self.d, 'known_hosts')}",
             "-o", "StrictHostKeyChecking=accept-new", "-o", "IdentitiesOnly=yes",
             "-o", "ConnectTimeout=10", "-o", "BatchMode=yes", "-o", "ServerAliveInterval=15"]
        if tty:
            a.append("-t")
        a.append(f"{user}@{self.ip}")
        if cmd:
            a.append(cmd)
        return a

    def sh(self, user, cmd, input=None, capture=True, timeout=1800, check=True):
        p = self.run(self.argv(user, cmd), input=input, capture_output=capture,
                     timeout=timeout)
        if check and p.returncode != 0:
            tail = ""
            if capture:
                tail = (_text(p.stdout)[-2000:] + _text(p.stderr)[-2000:]).strip()
            raise E2EError(f"ssh {user}@{self.ip} failed (exit {p.returncode}): {tail}")
        return p


def _text(b):
    if b is None:
        return ""
    return b.decode("utf-8", "replace") if isinstance(b, bytes) else b


PROVISION = r"""set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
cloud-init status --wait >/dev/null 2>&1 || true
for i in $(seq 60); do fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || break; sleep 5; done
apt-get update -q
apt-get install -y -q haproxy python3 python3-qrcode openssl curl snapd
snap wait system seed.loaded
snap list certbot >/dev/null 2>&1 || snap install --classic certbot
/snap/bin/certbot --version
/snap/bin/certbot --help all | grep -q -- --ip-address || { echo "certbot lacks --ip-address" >&2; exit 1; }
id porch >/dev/null 2>&1 || useradd -m -s /bin/bash porch
echo 'porch ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-porch-e2e   # test VM only
chmod 440 /etc/sudoers.d/90-porch-e2e
visudo -cf /etc/sudoers.d/90-porch-e2e
install -d -m 700 -o porch -g porch /home/porch/.ssh
install -m 600 -o porch -g porch /root/.ssh/authorized_keys /home/porch/.ssh/authorized_keys
echo provisioned
"""

FRP_FETCH = r"""set -euo pipefail
cd {repo}
name=frp_{ver}_linux_amd64
tmp=$(mktemp -d)
curl -fsSL -o "$tmp/frp.tar.gz" "https://github.com/fatedier/frp/releases/download/v{ver}/$name.tar.gz"
echo "{sha}  $tmp/frp.tar.gz" | sha256sum -c -
tar -xzf "$tmp/frp.tar.gz" -C "$tmp"
install -m 0755 "$tmp/$name/frps" "$tmp/$name/frpc" bin/
rm -rf "$tmp"
bin/frps --version
"""


def frp_script():
    return FRP_FETCH.format(repo=REMOTE_REPO, ver=FRP_VERSION, sha=FRP_SHA256)


DOMAIN_RE = re.compile(r"\A[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+\Z")
PROVIDER_RE = re.compile(r"\A[a-z0-9]{1,32}\Z")


def prefill_args(prefill):
    """Wizard prefill flags from {"domain", "dns_provider"} (validated)."""
    out = []
    d, prov = (prefill or {}).get("domain"), (prefill or {}).get("dns_provider")
    if d:
        if not DOMAIN_RE.match(d):
            raise E2EError(f"not a domain: {d!r}")
        out += ["--domain", d]
    if prov:
        if not PROVIDER_RE.match(prov):
            raise E2EError(f"not a DNS provider name: {prov!r}")
        out += ["--dns-provider", prov]
    return out


def wizard_start_cmd(extra=(), staging=True):
    # staging: the wizard's own IP certificate comes from LE staging (browsers
    # warn); --production gets a trusted one (counts against LE rate limits).
    args = " ".join(shlex.quote(a) for a in (*(("--staging",) if staging else ()), "--no-qr", *extra))
    return (
        f"sudo systemctl stop {WIZARD_UNIT} 2>/dev/null; sudo systemctl reset-failed {WIZARD_UNIT} 2>/dev/null; "
        # the old wizard may still hold the port for a moment ("Address already in use")
        f"for i in $(seq 60); do ss -Hltn 'sport = :{WIZARD_PORT}' | grep -q . || break; sleep 1; done; "
        f"rm -f {WIZARD_LOG}; install -m 600 /dev/null {WIZARD_LOG}; "
        f"sudo systemd-run --unit={WIZARD_UNIT} --uid=porch --gid=porch "
        f"-p WorkingDirectory={REMOTE_REPO} -p StandardOutput=append:{WIZARD_LOG} "
        f"-p StandardError=append:{WIZARD_LOG} --setenv=PYTHONUNBUFFERED=1 "
        f"/usr/bin/sudo -n {REMOTE_REPO}/bin/porch setup --web {args}"
    )


def _image_slug(v):
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,62}", v or ""):
        raise argparse.ArgumentTypeError(f"not a DigitalOcean image slug: {v!r}")
    return v


def installer_cmd(flags=(), tarball=f"{INSTALL_UPLOAD}/porch.tar.gz"):
    """site/porch.sh fed on stdin, as `curl ... | sudo sh -s -- <flags>` runs it."""
    return (f"PORCH_TARBALL={shlex.quote('file://' + tarball)} sh -s -- "
            + " ".join(shlex.quote(f) for f in flags)).rstrip()


def parse_wizard_log(text):
    """-> dict(url, fingerprint, ip_cert_error, fell_back, staging)"""
    urls = URL_RE.findall(text)
    out = {"url": urls[-1] if urls else None, "fingerprint": None, "ip_cert_error": None,
           "fell_back": "Falling back to a self-signed certificate" in text,
           "staging": "staging certificate" in text,
           "domain_cert": "Setup has a domain certificate" in text}
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if "IP certificate failed" in ln:
            out["ip_cert_error"] = ln.strip()
        if "fingerprint is exactly" in ln and i + 1 < len(lines):
            out["fingerprint"] = lines[i + 1].strip()
    out["exited"] = "porch setup --web: exiting" in text or bool(
        re.search(r"porch setup --web: (cannot|refusing|running as root|privilege)", text))
    return out


# ---- commands -------------------------------------------------------------------------

class App:
    def __init__(self, *, env=None, http=None, run=None, token_reader=None, out=None,
                 err=None, clock=time.time, sleep=time.sleep, inp=input, repo=None,
                 resolver=None, dns_provider=None, popen=None):
        self.env = os.environ if env is None else env
        self.dir = state_dir(self.env)
        self.http, self.run = http, run or subprocess.run
        self.token_reader = token_reader
        self.out, self.err = out or sys.stdout, err or sys.stderr
        self.clock, self.sleep, self.inp = clock, sleep, inp
        self.repo = repo or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self._do = None
        self.resolver = resolver            # dnsq.Resolver (tests: a fake)
        self.dns_provider = dns_provider    # token -> provider with .list(zone) (tests: a fake)
        self.popen = popen
        self._secrets = []                  # values to scrub from anything printed

    def p(self, *a):
        print(*a, file=self.out, flush=True)

    def _reader(self):
        if self.token_reader is not None:
            return self.token_reader
        sys.path.insert(0, os.path.join(self.repo, "lib"))
        import cush_secrets
        return cush_secrets.read

    def do(self):
        if self._do is None:
            reader = self._reader()
            try:
                tok = reader(self.env.get("PORCH_E2E_TOKEN_REF") or TOKEN_REF).strip()
            except Exception as e:  # never echo the value; the ref is fine
                raise E2EError(f"cannot read the DigitalOcean token: {type(e).__name__}")
            if not tok:
                raise E2EError("the DigitalOcean token is empty")
            self._do = DO(tok, http=self.http)
        return self._do

    def remote(self, st):
        return Remote(self.dir, st["ip"], run=self.run, popen=self.popen)

    def scrub(self, text):
        for v in self._secrets:
            if v:
                text = text.replace(v, "<secret>")
        return text

    def read_secret(self, ref_env, default_ref, what):
        try:
            v = (self._reader()(self.env.get(ref_env) or default_ref) or "").strip()
        except Exception as e:  # never echo the value; the ref is fine
            raise E2EError(f"cannot read the {what}: {type(e).__name__}")
        if not v:
            raise E2EError(f"the {what} is empty")
        self._secrets.append(v)
        return v

    def tagged_state(self):
        """state.json, checked against a live tagged droplet (never ssh elsewhere)."""
        st = load_state(self.dir)
        if not st or not st.get("droplet_id"):
            raise E2EError(f"no porch-e2e droplet recorded in {self.dir} (run: porch-e2e up)")
        ds = {d["id"]: d for d in self.do().droplets()}
        d = ds.get(st["droplet_id"])
        if d is None:
            raise E2EError(f"droplet {st['droplet_id']} from state.json is gone or not tagged {TAG}")
        if public_ip(d) and public_ip(d) != st.get("ip"):
            st["ip"] = public_ip(d)
            save_state(self.dir, st)
        return st

    # -- up --
    def up(self, a):
        if a.redeploy:
            return self.redeploy(a)
        if getattr(a, "installer", False):
            if a.cli:
                self.check_cli_args(a)
            return self.installer_up(a)
        if a.cli:
            self.check_cli_args(a)
        st = self.create_home(a)
        if a.cli:
            return self.cli_setup(st, a, a.connection)
        return self.start_wizard(st)

    def create_home(self, a, provision=True):
        """Create, boot, provision and deploy the (home) droplet -> state.
        provision=False stops once root ssh works (a bare droplet)."""
        existing = self.do().droplets()
        if existing:
            raise E2EError("a porch-e2e droplet already exists ("
                           + ", ".join(f"{d['id']} {public_ip(d) or '?'}" for d in existing)
                           + "): use status / up --redeploy / down")
        if load_state(self.dir):
            raise E2EError(f"stale state in {self.dir}/state.json: run porch-e2e down first")
        self.set_prefill({}, a)
        region = pick_region(a.region, self.do().size_regions(a.size))
        if region is None:
            raise E2EError(f"size {a.size} is not available in any region")
        if region != a.region:
            self.p(f"{a.size} is not available in {a.region}; using {region}")
        a.region = region
        ensure_dir(self.dir)
        key = os.path.join(self.dir, "id_ed25519")
        for f in (key, key + ".pub", os.path.join(self.dir, "known_hosts")):
            if os.path.exists(f):
                os.unlink(f)
        ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime(self.clock()))
        name = f"porch-e2e-{ts}"
        self.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", key],
                 check=True, capture_output=True)
        os.chmod(key, 0o600)
        os.chmod(key + ".pub", 0o600)
        with open(key + ".pub") as f:
            pub = f.read().strip()
        k = self.do().add_key(name, pub)
        image = getattr(a, "image", None) or IMAGE
        st = {"name": name, "key_id": k["id"], "created_at": int(self.clock()),
              "region": a.region, "size": a.size, "image": image}
        self.set_prefill(st, a)
        st["production"] = bool(getattr(a, "production", False))
        save_state(self.dir, st)
        try:
            d = self.do().create_droplet(name, a.region, a.size, k["id"], image=image)
        except E2EError:
            self.do().delete_key(k["id"])
            os.unlink(os.path.join(self.dir, "state.json"))
            raise
        st["droplet_id"] = d["id"]
        save_state(self.dir, st)
        self.p(f"droplet {d['id']} ({name}, {a.region}, {a.size}, {image}) created; waiting for it to boot")
        ip = None
        for _ in range(120):
            d = self.do().droplet(d["id"])
            ip = public_ip(d)
            if d.get("status") == "active" and ip:
                break
            self.sleep(5)
        else:
            raise E2EError("droplet did not become active in 10 minutes")
        st["ip"] = ip
        save_state(self.dir, st)
        self.p(f"active at {ip}; waiting for ssh")
        r = self.remote(st)
        for _ in range(60):
            p = r.sh("root", "true", check=False, timeout=30)
            if p.returncode == 0:
                break
            self.sleep(5)
        else:
            raise E2EError("ssh did not come up in 5 minutes")
        kh = os.path.join(self.dir, "known_hosts")
        if os.path.exists(kh):
            os.chmod(kh, 0o600)
        if not provision:
            return st
        self.p("provisioning (apt, snap certbot, porch user)")
        p = r.sh("root", "bash -s", input=PROVISION.encode(), timeout=1800)
        self.p("  " + _text(p.stdout).strip().replace("\n", "\n  "))
        self.deploy(st, a.branch)
        return st

    def set_prefill(self, st, a):
        pre = dict(st.get("prefill") or {})
        if a.domain is not None:
            pre["domain"] = a.domain.lower()
        if a.dns_provider is not None:
            pre["dns_provider"] = a.dns_provider
        prefill_args(pre)       # validate before anything happens
        st["prefill"] = pre

    def redeploy(self, a):
        st = self.tagged_state()
        self.set_prefill(st, a)
        st["production"] = bool(getattr(a, "production", False))
        if st.get("installer"):
            return self.run_installer(st)       # the installer's upgrade path
        self.deploy(st, a.branch)
        return self.start_wizard(st)

    # -- up --installer: the real one-line installer on a bare droplet --
    def installer_up(self, a):
        st = self.create_home(a, provision=False)
        st["installer"] = True
        st["wizard_unit"] = INSTALLER_UNIT
        save_state(self.dir, st)
        ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime(self.clock()))
        ports = INSTALLER_PORTS + (INSTALLER_CLI_PORTS if a.cli else ())
        fw = self.do().create_firewall(f"{FIREWALL_PREFIX}inst-{ts}", [st["droplet_id"]],
                                       ports=ports)
        st["firewall_id"] = fw["id"]
        save_state(self.dir, st)
        self.p(f"cloud firewall {fw['id']}: inbound tcp {', '.join(ports)}")
        rc = self.run_installer(st)
        if rc or not a.cli:
            return rc
        # --cli: the installer's wizard holds :80 (HAProxy needs it); setup runs
        # non-interactively instead, in the directory porch.sh installed into.
        origin = (st.get("wizard") or {}).get("origin")
        if origin:
            code, _ = self.curl(origin + "/", insecure=not st.get("production"))
            st["results"]["wizard_http"] = code
            save_state(self.dir, st)
            self.p(f"wizard {origin}/ answered {code}")
        self.p(f"--cli: stopping {INSTALLER_UNIT}; running porch setup over ssh instead")
        self.remote(st).sh("root", f"systemctl stop {INSTALLER_UNIT}; "
                                   f"for i in $(seq 60); do ss -Hltn 'sport = :80' | grep -q . || break; sleep 1; done",
                           check=False, timeout=120)
        return self.cli_setup(st, a, a.connection)

    def build_tarball(self, out_dir):
        """bin/publish-tarball --out: the working tree's allowlisted files -> (tarball, sha256 file)."""
        tb = os.path.join(out_dir, "porch.tar.gz")
        self.run([os.path.join(self.repo, "bin", "publish-tarball"), "--out", tb],
                 check=True, capture_output=True)
        return tb, tb + ".sha256"

    def run_installer(self, st):
        import tempfile
        r = self.remote(st)
        with tempfile.TemporaryDirectory(prefix="porch-e2e-tb-") as tmp:
            self.p("building the install tarball (bin/publish-tarball --out; working tree)")
            tb, sha = self.build_tarball(tmp)
            r.sh("root", f"install -d -m 700 {INSTALL_UPLOAD}", timeout=60)
            for path in (tb, sha):
                with open(path, "rb") as f:
                    data = f.read()
                r.sh("root", f"cat > {INSTALL_UPLOAD}/{os.path.basename(path)}", input=data, timeout=600)
            with open(os.path.join(self.repo, "site", "porch.sh"), "rb") as f:
                script = f.read()
        flags = (["--staging"] if not st.get("production") else []) + prefill_args(st.get("prefill"))
        cmd = installer_cmd(flags)
        self.p(f"running site/porch.sh as root: {cmd} (script on stdin)")
        t0 = self.clock()
        rc = r.stream("root", cmd, input=script, on_line=lambda ln: self.p("  | " + ln))
        st.setdefault("results", {})["installer"] = {"exit": rc, "seconds": int(self.clock() - t0)}
        save_state(self.dir, st)
        self.p(f"installer exit {rc} in {int(self.clock() - t0)}s")
        if rc != 0:
            return 1
        # porch-e2e's other commands ssh in as porch
        r.sh("root", f"install -d -m 700 -o {USER} -g {USER} /home/{USER}/.ssh && "
                     f"install -m 600 -o {USER} -g {USER} /root/.ssh/authorized_keys "
                     f"/home/{USER}/.ssh/authorized_keys", timeout=60)
        st["deployed"] = {"installer": True, "at": int(self.clock())}
        save_state(self.dir, st)
        return self.wait_wizard(st, timeout=60)

    def unit(self, st):
        return (st or {}).get("wizard_unit") or WIZARD_UNIT

    def deploy(self, st, branch):
        r = self.remote(st)
        sha = subprocess.run(["git", "-C", self.repo, "rev-parse", "--short", branch],
                             check=True, capture_output=True, text=True).stdout.strip()
        self.p(f"uploading git archive {branch} ({sha}) to {REMOTE_REPO}")
        tar = subprocess.run(["git", "-C", self.repo, "archive", "--format=tar", branch],
                             check=True, capture_output=True).stdout
        r.sh(USER, f"sudo systemctl stop {WIZARD_UNIT} 2>/dev/null; mkdir -p {REMOTE_REPO} "
                   f"&& tar -x -C {REMOTE_REPO}", input=tar, timeout=600)
        # No .git up there: ship the file manifest so bin/deploy can still
        # pack the install tarball for new machines (lib/porch_files.py).
        man = subprocess.run([sys.executable, "-I", os.path.join(self.repo, "lib", "porch_files.py"),
                              "manifest", self.repo, "--ref", branch],
                             check=True, capture_output=True).stdout
        r.sh(USER, f"mkdir -p {REMOTE_REPO}/share && cat > {REMOTE_REPO}/share/porch-files.txt",
             input=man, timeout=60)
        p = r.sh(USER, "bash -s", input=frp_script().encode(), timeout=600)
        self.p("  frp: " + _text(p.stdout).strip().replace("\n", " | "))
        st["deployed"] = {"branch": branch, "commit": sha, "at": int(self.clock())}
        save_state(self.dir, st)

    def start_wizard(self, st, timeout=900):
        r = self.remote(st)
        staging = not st.get("production")
        self.p(f"starting the wizard: sudo bin/porch setup --web{' --staging' if staging else ''} (systemd unit "
               f"{WIZARD_UNIT}, log {WIZARD_LOG})")
        extra = prefill_args(st.get("prefill"))
        if extra:
            self.p("  prefill: " + " ".join(extra))
        r.sh(USER, wizard_start_cmd(extra, staging=staging), timeout=60)
        return self.wait_wizard(st, timeout)

    def wait_wizard(self, st, timeout=900):
        r = self.remote(st)
        t0 = self.clock()
        text = ""
        info = {}
        while self.clock() - t0 < timeout:
            text = _text(r.sh(USER, f"cat {WIZARD_LOG}", check=False, timeout=60).stdout)
            info = parse_wizard_log(text)
            if info["url"] or info["exited"]:
                break
            self.sleep(5)
        if info.get("ip_cert_error"):
            self.p("IP certificate failed (verbatim):")
            self.p("  " + info["ip_cert_error"])
        if not info.get("url"):
            self.p("wizard did not print a URL; log:")
            self.p(text[-4000:])
            return 1
        st["wizard"] = {"url_seen_at": int(self.clock()), "fingerprint": info["fingerprint"],
                        "origin": info["url"].split("/#", 1)[0],
                        "self_signed": bool(info["fingerprint"]), "staging": info["staging"]}
        save_state(self.dir, st)
        kind = ("self-signed, SHA-256 " + info["fingerprint"]) if info["fingerprint"] else \
            ("the setup's domain certificate" if info.get("domain_cert") else
             "Let's Encrypt staging IP certificate" if info["staging"] else "IP certificate")
        self.p(f"wizard: {kind}")
        self.p(f"WIZARD URL: {info['url']}")
        return 0

    # -- up --cli: the fully automated CLI install --
    @staticmethod
    def check_cli_args(a):
        if not a.domain or not a.dns_provider:
            raise E2EError("--cli needs --domain and --dns-provider")
        if a.dns_provider != "cloudflare":
            raise E2EError("--cli reads the DNS token from the Cloudflare ref only (--dns-provider cloudflare)")

    def setup_flags(self, st, a, connection, extra=()):
        pre = st.get("prefill") or {}
        flags = ["--non-interactive", "--yes", "--domain", pre["domain"], "--apex",
                 "--connection", connection, "--dns-provider", pre["dns_provider"],
                 "--acme-staging" if getattr(a, "acme_staging", False) else "--no-acme-staging"]
        return flags + list(extra)

    def cli_setup(self, st, a, connection="direct", extra=()):
        """`bin/porch setup --non-interactive` on the droplet, streamed. The
        DNS token and a throwaway admin password go over ssh's stdin. Exit
        0 only when the run succeeds and every step is done."""
        dns_token = self.read_secret("PORCH_E2E_CF_TOKEN_REF", CF_TOKEN_REF, "Cloudflare token")
        admin_pw = _secrets.token_urlsafe(18)
        self._secrets.append(admin_pw)
        flags = self.setup_flags(st, a, connection, extra)
        cmd = (f"cd {REMOTE_REPO} && IFS= read -r PORCH_DNS_TOKEN && IFS= read -r PORCH_ADMIN_PASSWORD "
               f"&& export PORCH_DNS_TOKEN PORCH_ADMIN_PASSWORD && exec bin/porch setup "
               + " ".join(shlex.quote(f) for f in flags) + " 2>&1")
        self.p("porch setup " + " ".join(flags))
        t0 = self.clock()
        rc = self.remote(st).stream(USER, cmd, input=f"{dns_token}\n{admin_pw}\n".encode(),
                                    on_line=lambda ln: self.p("  | " + self.scrub(ln)))
        steps = self.step_statuses(st)
        done = [s for s in steps if s["status"] == "done"]
        st.setdefault("results", {})["setup"] = {"exit": rc, "done": len(done), "steps": len(steps),
                                                 "seconds": int(self.clock() - t0)}
        save_state(self.dir, st)
        self.p(f"setup exit {rc}: {len(done)}/{len(steps)} steps done in {int(self.clock() - t0)}s")
        for s in steps:
            if s["status"] != "done":
                err = s.get("error") or {}
                self.p(f"  {s['id']}: {s['status']} {err.get('code', '')} {self.scrub(str(err.get('message', '')))}")
        return 0 if rc == 0 and steps and len(done) == len(steps) else 1

    def step_statuses(self, st):
        p = self.remote(st).sh(USER, f"cd {REMOTE_REPO} && bin/porch setup --status --json",
                               check=False, timeout=120)
        try:
            return json.loads(_text(p.stdout)).get("steps") or []
        except ValueError:
            return []

    # -- relay-test --
    def relay_test(self, a):
        """Home droplet with inbound ssh only (a DO cloud firewall), then
        `porch setup --connection paid|byo|oracle` run on it, checks from
        here, and teardown via `down` (unless --keep). paid: porch creates
        the relay itself (DigitalOcean or Vultr, tagged porch-e2e too).
        byo: porch-e2e first creates a plain droplet as "your own server";
        --oracle-sim gives it Oracle's iptables REJECT firewall and uses
        the oracle mode."""
        self.check_cli_args(a)
        mode = "oracle" if a.oracle_sim else a.mode
        provider = a.relay_provider or "digitalocean"
        if mode != "paid" and a.relay_provider:
            raise E2EError("--relay-provider goes with --mode paid")
        tfile = None
        if mode == "paid":
            env_ref, ref, what, tfile = RELAY_PROVIDERS[provider]
            relay_token = self.read_secret(env_ref, ref, what)
            self._relay_token = relay_token
        st = self.create_home(a)
        st["relay_test"] = {"region": a.region, "mode": mode,
                            "provider": provider if mode == "paid" else None, "token_file": tfile}
        save_state(self.dir, st)
        r = self.remote(st)
        ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime(self.clock()))
        fw = self.do().create_firewall(f"{FIREWALL_PREFIX}home-{ts}", [st["droplet_id"]])
        st["firewall_id"] = fw["id"]
        save_state(self.dir, st)
        self.p(f"cloud firewall {fw['id']}: home droplet {st['ip']} accepts inbound tcp 22 only")
        rc = 1
        relay = None
        t0 = self.clock()
        try:
            if mode == "paid":
                self.put_relay_token(r, relay_token, tfile)
                extra = ["--relay-provider", provider, "--relay-token-ref", "file://~/" + tfile,
                         "--relay-tag", TAG]
                region = a.relay_region or (a.region if provider == "digitalocean" else None)
                if region:
                    extra += ["--relay-region", region]
                    st["relay_test"]["relay_region"] = region
                if a.relay_size:
                    extra += ["--relay-size", a.relay_size]
                rc = self.cli_setup(st, a, "paid", extra)
            else:
                relay = self.create_byo(st, a, mode)
                extra = ["--relay-host", f"root@{relay['ip']}", "--relay-ssh-key", BYO_KEY]
                rc = self.cli_setup(st, a, mode, extra)
        finally:
            if mode == "paid":
                self.drop_relay_token(r, tfile)
        if mode == "paid":
            relay = self.find_relay(st)
        if relay:
            if not relay.get("created_at"):
                relay["since"] = int(t0)        # Vultr: billed from about here
            st["relay_test"]["relay"] = relay
            st["relay_test"]["setup_seconds"] = int(self.clock() - t0)
            save_state(self.dir, st)
            self.p(f"relay {relay.get('provider', 'digitalocean')} {relay['id']} at {relay['ip']} "
                   f"({relay['size']}, tagged {TAG})")
            if rc:
                self.p("setup did not finish; checking what is there anyway")
            rc = self.relay_checks(st, relay, insecure=bool(a.acme_staging)) or rc
        else:
            self.p("no relay server appeared: skipping the checks")
        if a.keep:
            self.p("--keep: leaving everything up; run `porch-e2e down --yes` when done")
            return rc
        self.p("tearing down")
        down_rc = self.down(argparse.Namespace(yes=True))
        return rc or down_rc

    def create_byo(self, st, a, mode):
        """A plain droplet as the user's own server (tagged porch-e2e, root
        ssh with this tool's key), plus home's own key for porch on it."""
        ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime(self.clock()))
        name = f"porch-e2e-byo-{ts}"
        d = self.do().create_droplet(name, a.region, BYO_SIZE, st["key_id"])
        st["relay_test"]["byo_id"] = d["id"]
        save_state(self.dir, st)
        self.p(f"byo server: droplet {d['id']} ({name}, {BYO_SIZE}) created; waiting for it to boot")
        ip = None
        for _ in range(120):
            d = self.do().droplet(d["id"])
            ip = public_ip(d)
            if d.get("status") == "active" and ip:
                break
            self.sleep(5)
        else:
            raise E2EError("byo droplet did not become active in 10 minutes")
        byo = Remote(self.dir, ip, run=self.run, popen=self.popen)
        for _ in range(60):
            if byo.sh("root", "true", check=False, timeout=30).returncode == 0:
                break
            self.sleep(5)
        else:
            raise E2EError("ssh to the byo droplet did not come up in 5 minutes")
        p = self.remote(st).sh(USER, f"test -f {BYO_KEY} || ssh-keygen -q -t ed25519 -N '' -C porch-relay "
                                     f"-f {BYO_KEY}; cat {BYO_KEY}.pub", timeout=60)
        pub = _text(p.stdout).strip().splitlines()[-1]
        byo.sh("root", "umask 077 && cat >> ~/.ssh/authorized_keys", input=(pub + "\n").encode(), timeout=60)
        self.p(f"byo server {ip}: home's key added to root's authorized_keys")
        if mode == "oracle":
            p = byo.sh("root", "bash -s", input=ORACLE_SIM.encode(), timeout=900)
            self.p(f"oracle-sim: {ip} now REJECTs everything but ssh in iptables "
                   f"({_text(p.stdout).strip().splitlines()[-1]})")
        return {"id": d["id"], "ip": ip, "name": name, "size": BYO_SIZE, "kind": mode,
                "provider": "digitalocean", "created_at": d.get("created_at"),
                "price_hourly": float((d.get("size") or {}).get("price_hourly") or 0)}

    def relay_provider_client(self, provider):
        from porch_setup.relay import providers as _prov
        if provider == "digitalocean":
            return None
        tok = getattr(self, "_relay_token", None)
        if not tok:
            env_ref, ref, what, _f = RELAY_PROVIDERS[provider]
            tok = self.read_secret(env_ref, ref, what)
            self._relay_token = tok
        return _prov.PROVIDERS[provider](tok, http=getattr(self, "relay_http", None))

    def put_relay_token(self, r, token, tfile=RELAY_TOKEN_FILE):
        r.sh(USER, "umask 077 && mkdir -p ~/.config/porch/secrets && chmod 700 ~/.config/porch "
                   f"~/.config/porch/secrets && cat > ~/{tfile}", input=token.encode(), timeout=60)

    def drop_relay_token(self, r, tfile=RELAY_TOKEN_FILE):
        try:
            r.sh(USER, f"rm -f ~/{tfile}", check=False, timeout=60)
        except Exception as e:  # noqa: BLE001 - the droplet is deleted anyway
            self.p(f"could not remove the relay token file: {e}")

    def find_relay(self, st):
        provider = (st.get("relay_test") or {}).get("provider") or "digitalocean"
        if provider != "digitalocean":
            c = self.relay_provider_client(provider)
            for sv in c.list_tagged(TAG):
                if str(sv.get("name") or "").startswith("porch-relay-"):
                    try:
                        plan = c.plan(region=(st.get("relay_test") or {}).get("relay_region"))
                        hourly = plan.get("hourly") or 0
                        size = plan.get("size")
                    except Exception:  # noqa: BLE001 - the price is only for the report
                        hourly, size = 0, None
                    return {"id": sv["id"], "ip": sv.get("ipv4"), "name": sv.get("name"), "size": size,
                            "provider": provider, "created_at": None, "seen_at": int(self.clock()),
                            "price_hourly": float(hourly)}
            return None
        for d in self.do().droplets():
            if d["id"] != st.get("droplet_id") and str(d.get("name", "")).startswith("porch-relay-"):
                return {"id": d["id"], "ip": public_ip(d), "name": d["name"], "size": d.get("size_slug"),
                        "created_at": d.get("created_at"),
                        "price_hourly": float((d.get("size") or {}).get("price_hourly") or 0)}
        return None

    def curl(self, url, resolve=None, method="GET", headers=(), data=None, timeout=20, insecure=False):
        """(http code or 0, body text) with normal certificate checks
        (insecure: LE staging runs only)."""
        argv = ["curl", "-sS", "-o", "-", "-w", "\n%{http_code}", "--max-time", str(timeout),
                "--connect-timeout", str(min(timeout, 10))] + (["-k"] if insecure else [])
        if resolve:
            argv += ["--resolve", resolve]
        if method != "GET":
            argv += ["-X", method]
        for h in headers:
            argv += ["-H", h]
        if data is not None:
            argv += ["--data-binary", "@-"]
        argv.append(url)
        p = self.run(argv, input=data.encode() if data is not None else None, capture_output=True,
                     timeout=timeout + 10)
        out = _text(p.stdout)
        body, _, code = out.rpartition("\n")
        return (int(code) if code.strip().isdigit() else 0), body

    def my_ip(self):
        for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
            code, body = self.curl(url, timeout=10)
            try:
                return str(ipaddress.ip_address(body.strip())) if code == 200 else None
            except ValueError:
                continue
        return None

    def relay_checks(self, st, relay, insecure=False):
        """From this box, through the relay: TLS + codes, a tunnel made on
        home, the auth server logging our address, and home itself closed."""
        dom = st["prefill"]["domain"]
        rip, hip = relay["ip"], st["ip"]
        res = {}
        ok = True

        def check(name, good, detail):
            nonlocal ok
            ok = ok and good
            res[name] = {"ok": bool(good), "detail": detail}
            self.p(f"  [{'ok  ' if good else 'FAIL'}] {name}: {detail}")

        self.p(f"checks via the relay {rip} (home {hip} takes ssh only)")
        dns = self.authoritative_a(f"auth.{dom}", dom, rip)
        check("dns", dns == [rip], f"auth.{dom} A at the authoritative NS: {', '.join(dns) or 'none'}")
        for host, path, want in ((f"auth.{dom}", "/auth/", 200), (f"tunnel.{dom}", "/", 200),
                                 (f"panel.{dom}", "/", 403),
                                 (f"porch-e2e-{_secrets.token_hex(3)}.tunnel.{dom}", "/", 404)):
            code, _ = self.curl(f"https://{host}{path}", resolve=f"{host}:443:{rip}", insecure=insecure)
            check(f"https {host}{path}", code == want,
                  f"{code} (want {want}, {'STAGING cert, not verified' if insecure else 'trusted cert'})")
        nonce = _secrets.token_hex(8)
        r = self.remote(st)
        r.sh(USER, f"mkdir -p /tmp/e2erelay && echo porch-relay-{nonce} > /tmp/e2erelay/index.html && "
                   f"cd {REMOTE_REPO} && bin/serve /tmp/e2erelay e2erelay --bg", timeout=120)
        host = f"e2erelay.tunnel.{dom}"
        code, body = 0, ""
        for _ in range(20):
            code, body = self.curl(f"https://{host}/", resolve=f"{host}:443:{rip}", insecure=insecure)
            if code == 200:
                break
            self.sleep(3)
        check("tunnel made on home", code == 200 and f"porch-relay-{nonce}" in body,
              f"https://{host}/ -> {code}")
        r.sh(USER, f"cd {REMOTE_REPO} && bin/status close e2erelay", check=False, timeout=60)
        me = self.my_ip()
        code, _ = self.curl(f"https://auth.{dom}/auth/admin/login", resolve=f"auth.{dom}:443:{rip}",
                            method="POST", headers=(f"Origin: https://auth.{dom}", "Content-Type: application/json"),
                            data=json.dumps({"password": "porch-e2e-wrong-" + nonce}), insecure=insecure)
        self.sleep(2)
        p = r.sh(USER, "sudo journalctl _SYSTEMD_USER_UNIT=porch-auth.service --since -10min --no-pager -o cat "
                       "| grep 'admin login failed' | tail -n 3", check=False, timeout=60)
        seen = _text(p.stdout).strip().splitlines()
        check("auth server sees the real client", code == 401 and bool(me) and any(f"ip={me}" in ln for ln in seen),
              f"POST /auth/admin/login -> {code}; this box is {me}; auth log: {seen[-1] if seen else 'nothing'}")
        reached = self.tcp_reachable(rip, 7000)
        check(f"relay {rip}:7000 (paired devices' frps)", reached, "open" if reached else "closed")
        for port in (443, 80, 7000):
            reached = self.tcp_reachable(hip, port)
            check(f"home {hip}:{port} direct", not reached, "refused/filtered" if not reached else "REACHABLE")
        p = r.sh(USER, "ss -Hltn 'sport = :443' | head -1", check=False, timeout=60)
        check("home HAProxy listens on 443", bool(_text(p.stdout).strip()), _text(p.stdout).strip() or "nothing")
        p = r.sh(USER, f"cd {REMOTE_REPO} && bin/porch connect --status --no-probe | sed -n '/^active/,$p'",
                 check=False, timeout=120)
        status = _text(p.stdout).strip()
        check("porch connect --status", "FAIL" not in status and "relay proxies: http=running" in status,
              status.replace("\n", " | "))
        st["relay_test"]["checks"] = res
        st["relay_test"]["client_ip"] = me
        save_state(self.dir, st)
        self.p(f"relay checks: {sum(1 for v in res.values() if v['ok'])}/{len(res)} passed")
        return 0 if ok else 1

    def authoritative_a(self, name, domain, want, wait=180):
        from porch_setup import dnsq
        res = self.resolver or dnsq.Resolver()
        zone = res.zone_apex(domain)
        t0 = self.clock()
        while True:
            vals = set()
            try:
                for _ns, v in res.authoritative(name, "A", zone=zone).items():
                    vals.update(v or [])
            except dnsq.DNSError:
                pass
            if vals == {want} or self.clock() - t0 >= wait:
                return sorted(vals)
            self.sleep(5)

    @staticmethod
    def tcp_reachable(ip, port, timeout=6):
        import socket
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except OSError:
            return False

    # -- status / ssh / logs --
    def status(self, a):
        now = self.clock()
        ds = self.do().droplets()
        if not ds:
            self.p("no porch-e2e droplets")
        for d in ds:
            hours, cost = est_cost(d, now)
            self.p(f"{d['id']}  {public_ip(d) or '-'}  {d['region']['slug']}  {d['size_slug']}  "
                   f"{d['status']}  age {hours:.2f}h  est ${cost:.4f}")
        st = load_state(self.dir)
        if st and st.get("ip") and any(d["id"] == st.get("droplet_id") for d in ds):
            p = self.remote(st).sh(USER, f"systemctl is-active {self.unit(st)}; tail -n 15 {WIZARD_LOG}",
                                   check=False, timeout=60)
            self.p("--- wizard ---")
            self.p(_text(p.stdout).rstrip())
        return 0

    def ssh(self, a):
        st = self.tagged_state()
        r = self.remote(st)
        cmd = " ".join(shlex.quote(c) for c in a.remote_cmd) if a.remote_cmd else None
        return self.run(r.argv(USER, cmd, tty=not cmd)).returncode

    def logs(self, a):
        st = self.tagged_state()
        r = self.remote(st)
        n = int(a.n)
        p = r.sh(USER, f"echo '== {WIZARD_LOG}'; tail -n {n} {WIZARD_LOG}; "
                       f"echo '== {REMOTE_REPO}/data/porch-setup.log'; "
                       f"tail -n {n} {REMOTE_REPO}/data/porch-setup.log 2>/dev/null || true",
                 check=False, timeout=60)
        self.p(_text(p.stdout).rstrip())
        return 0

    # -- down --
    def down(self, a):
        ds = self.do().droplets()
        st = load_state(self.dir) or {}
        if not ds and not st:
            self.p("nothing to tear down")
            return 0
        for d in ds:
            self.p(f"will delete droplet {d['id']} {d['name']} {public_ip(d) or '-'}")
        if st.get("key_id"):
            self.p(f"will delete ssh key {st['key_id']} ({st.get('name')})")
        if not a.yes:
            if self.inp("type yes to continue: ").strip() != "yes":
                self.p("aborted")
                return 6
        now = self.clock()
        live = bool(st.get("ip") and any(d["id"] == st.get("droplet_id") for d in ds))
        remote_cfg = self.remote_domain_cfg(st) if live else None
        rt = st.get("relay_test") or {}
        relay = rt.get("relay")
        paid = bool(rt) and rt.get("mode", "paid") == "paid"
        provider = rt.get("provider") or "digitalocean"
        tfile = rt.get("token_file") or RELAY_TOKEN_FILE
        if live:
            self.p("rollback on the droplet: bin/porch setup --rollback --non-interactive")
            r = self.remote(st)
            try:
                if paid:
                    # porch's own rollback deletes the relay server: it needs the token
                    env_ref, ref, what, _f = RELAY_PROVIDERS[provider]
                    self.put_relay_token(r, self.read_secret(env_ref, ref, what), tfile)
                p = r.sh(USER, f"sudo systemctl stop {self.unit(st)} 2>/dev/null; cd {REMOTE_REPO} && "
                               "bin/porch setup --rollback --non-interactive 2>&1", check=False,
                         timeout=900)
                self.p(self.scrub(_text(p.stdout).rstrip()))
                self.p(f"(rollback exit {p.returncode})")
            except Exception as e:  # best effort
                self.p(f"rollback skipped: {self.scrub(str(e))}")
            finally:
                if paid:
                    self.drop_relay_token(r, tfile)
        if relay and paid and provider != "digitalocean":
            gone = self.relay_provider_client(provider).get(relay["id"]) is None
            st["relay_test"]["relay_deleted_by_porch"] = gone
            self.p(f"relay {provider} {relay['id']}: " + ("deleted by porch's rollback" if gone
                                                        else "still there (porch-e2e deletes it by tag)"))
        elif relay and paid:
            gone = relay["id"] not in {d["id"] for d in self.do().droplets()}
            st["relay_test"]["relay_deleted_by_porch"] = gone
            self.p(f"relay droplet {relay['id']}: " + ("deleted by porch's rollback" if gone
                                                     else "still there (porch-e2e deletes it by tag)"))
        elif relay and live and relay["id"] in {d["id"] for d in ds}:
            self.byo_clean_check(relay)
        dns_clean = self.dns_check(st, remote_cfg)
        total = 0.0
        for d in ds:
            hours, cost = est_cost(d, now)
            total += cost
            self.p(f"droplet {d['id']}: ran {hours:.2f}h, est ${cost:.4f}")
        if relay and paid and relay["id"] not in {d["id"] for d in ds} and \
                (relay.get("created_at") or relay.get("since")):
            start = parse_ts(relay["created_at"]) if relay.get("created_at") else relay["since"]
            hours = max(0.0, (now - start) / 3600)
            total += hours * relay.get("price_hourly", 0)
            self.p(f"relay {provider} {relay['id']}: ran about {hours:.2f}h, "
                   f"est ${hours * relay.get('price_hourly', 0):.4f}")
        if self.do().droplets():
            self.do().delete_tagged(TAG)
            self.p(f"deleted droplets tagged {TAG}")
        if paid and provider != "digitalocean":
            c = self.relay_provider_client(provider)
            for sv in c.list_tagged(TAG):
                if str(sv.get("name") or "").startswith("porch-relay-"):
                    c.delete(sv["id"])
                    self.p(f"deleted {provider} instance {sv['id']} ({sv.get('name')}) by tag {TAG}")
            left = [sv["id"] for sv in c.list_tagged(TAG)]
            self.p(f"{provider} instances tagged {TAG} left: {', '.join(map(str, left)) or 'none'}")
        for fw in self.do().firewalls():
            self.do().delete_firewall(fw["id"])
            self.p(f"deleted cloud firewall {fw['id']} ({fw['name']})")
        if st.get("key_id"):
            self.do().delete_key(st["key_id"])
            self.p(f"deleted ssh key {st['key_id']}")
        for f in ("state.json", "id_ed25519", "id_ed25519.pub", "known_hosts"):
            try:
                os.unlink(os.path.join(self.dir, f))
            except FileNotFoundError:
                pass
        self.p(f"total est. cost ${total:.4f}")
        if dns_clean is False:
            self.p("porch DNS records are still published: delete them by hand (see above)")
            return 3
        return 0

    def byo_clean_check(self, relay):
        """After porch's rollback the byo server must hold nothing of porch's
        (uninstall-relay.sh removes exactly what the install recorded)."""
        cmd = ("echo dir=$(test -e /etc/porch-relay && echo present || echo gone); "
               "echo unit=$(systemctl is-active porch-relay-frps 2>/dev/null || true); "
               "echo iptables=$(iptables -S INPUT 2>/dev/null | grep -c porch-relay); "
               "echo saved=$(grep -c porch-relay /etc/iptables/rules.v4 2>/dev/null || echo 0); "
               "echo reject=$(iptables -S INPUT 2>/dev/null | grep -c REJECT)")
        try:
            p = Remote(self.dir, relay["ip"], run=self.run, popen=self.popen).sh(
                "root", cmd, check=False, timeout=60)
        except Exception as e:  # noqa: BLE001 - deleted anyway
            self.p(f"byo server check skipped: {e}")
            return None
        facts = dict(ln.split("=", 1) for ln in _text(p.stdout).split() if "=" in ln)
        clean = (facts.get("dir") == "gone" and facts.get("unit") in ("inactive", "unknown", "")
                 and facts.get("iptables") == "0" and facts.get("saved") in ("0", ""))
        self.p(f"byo server {relay['ip']} after rollback: " + ("clean" if clean else "NOT clean")
               + f" ({', '.join(f'{k}={v}' for k, v in facts.items())})")
        return clean

    # -- DNS teardown check --
    def remote_domain_cfg(self, st):
        """The droplet's resolved [domain] (read before rollback removes porch.toml)."""
        try:
            p = self.remote(st).sh(USER, f"cd {REMOTE_REPO} && python3 lib/porch_config.py dump",
                                   check=False, timeout=60)
            d = json.loads(_text(p.stdout)).get("domain") if p.returncode == 0 else None
        except Exception:  # noqa: BLE001 - fall back to the prefill domain's layouts
            return None
        if not isinstance(d, dict):
            return None
        # The built-in default root is this home box's own domain: a droplet that
        # resolves to it never ran the domain step (no porch.toml), and its live
        # records are not the droplet's to clean up.
        if d.get("root") == DEFAULT_ROOT and \
                ((st.get("prefill") or {}).get("domain") or "").lower() != DEFAULT_ROOT:
            return None
        return d

    def dns_check(self, st, remote_cfg):
        """After rollback: no A/AAAA/CNAME left for the porch hosts, asked of
        the zone's authoritative name servers (polled up to DNS_CLEAN_WAIT s),
        plus the provider's own record list when it is Cloudflare. True clean,
        False records left, None not checked / inconclusive."""
        domain = ((st.get("prefill") or {}).get("domain") or "").lower()
        if not domain and not remote_cfg:
            self.p("DNS check skipped: no domain recorded")
            return None
        names, bases = dns_check_names(domain, remote_cfg)
        from porch_setup import dnsq
        res = self.resolver or dnsq.Resolver()
        try:
            zone = res.zone_apex(domain or remote_cfg.get("root"))
        except dnsq.DNSError as e:
            self.p(f"DNS check: cannot find the zone: {e}")
            return None
        self.p(f"DNS check: {len(names)} names at {zone}'s authoritative name servers")
        t0 = self.clock()
        while True:
            left, unknown = {}, set()
            for n in names:
                for t in ("A", "AAAA", "CNAME"):
                    try:
                        ans = res.authoritative(n, t, zone=zone)
                    except dnsq.DNSError:
                        unknown.add(n)
                        continue
                    for ip, vals in ans.items():
                        if vals is None:
                            unknown.add(n)
                        elif vals:
                            left.setdefault(f"{n} {t}", set()).update(vals)
            if not left and not unknown:
                break
            if self.clock() - t0 >= DNS_CLEAN_WAIT:
                break
            self.sleep(5)
        clean = None
        if left:
            clean = False
            for k, v in sorted(left.items()):
                self.p(f"  still published: {k} -> {', '.join(sorted(v))}")
        elif unknown:
            self.p("  no records seen, but some name servers did not answer for: "
                   + ", ".join(sorted(unknown)))
        else:
            clean = True
            self.p("DNS clean: no A/AAAA/CNAME left at the authoritative name servers")
        prov = self.provider_check(st, zone, set(names), bases)
        if prov is False:
            clean = False
        elif prov is True and clean is None and not left:
            clean = True
        return clean

    def provider_check(self, st, zone, names, bases):
        if (st.get("prefill") or {}).get("dns_provider") != "cloudflare":
            return None
        tok = None
        try:
            tok = (self._reader()(self.env.get("PORCH_E2E_CF_TOKEN_REF") or CF_TOKEN_REF) or "").strip()
            if not tok:
                raise E2EError("empty token")
            if self.dns_provider is not None:
                prov = self.dns_provider(tok)
            else:
                from porch_setup.dns.cloudflare import Cloudflare
                prov = Cloudflare(creds={"token": tok})
            recs = prov.list(zone)
        except Exception as e:  # noqa: BLE001 - never echo the token
            msg = f"{type(e).__name__}: {e}"
            if tok:
                msg = msg.replace(tok, "<token>")
            self.p(f"Cloudflare check skipped ({msg[:200]})")
            return None
        left = [r for r in recs if r.type in ("A", "AAAA", "CNAME") and
                (r.name in names or any(r.name.endswith("." + b) for b in bases))]
        for r in left:
            self.p(f"  Cloudflare still has: {r.name} {r.type} {r.content}")
        if not left:
            self.p(f"Cloudflare: no porch A/AAAA/CNAME records left in {zone}")
        return not left


def dns_check_names(domain, remote_cfg=None):
    """(names to ask the authoritative NS, tunnel bases) for the porch hosts:
    the droplet's own config when known, plus both layouts (apex and
    porch.<domain>) of the prefill domain. A random label stands in for the
    *.tunnel wildcard. The zone apex itself is never checked (it may hold
    the owner's own site)."""
    hosts, bases = [], []
    if remote_cfg:
        for k in ("auth_host", "panel_host", "landing_host", "tunnel_base"):
            if remote_cfg.get(k):
                hosts.append(remote_cfg[k].lower().rstrip("."))
        if remote_cfg.get("tunnel_base"):
            bases.append(remote_cfg["tunnel_base"].lower().rstrip("."))
    if domain:
        for root in (domain, "porch." + domain):
            hosts += [f"auth.{root}", f"panel.{root}", f"tunnel.{root}"]
            bases.append(f"tunnel.{root}")
    probe = "porch-e2e-" + _secrets.token_hex(4)
    out = []
    for h in hosts + [f"{probe}.{b}" for b in bases]:
        if h not in out and h != domain:
            out.append(h)
    return out, sorted(set(bases))


def parser():
    p = argparse.ArgumentParser(prog="porch-e2e", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("up", help="create + provision the droplet and start the wizard")
    u.add_argument("--region", default=DEFAULT_REGION)
    u.add_argument("--size", default=DEFAULT_SIZE)
    u.add_argument("--image", default=IMAGE, type=_image_slug,
                   help=f"droplet image slug (default {IMAGE}; e.g. debian-12-x64, ubuntu-22-04-x64)")
    u.add_argument("--branch", default="HEAD")
    u.add_argument("--domain", help="prefill the wizard's domain (e.g. cjc1.com)")
    u.add_argument("--dns-provider", help="prefill the wizard's DNS provider (e.g. cloudflare)")
    u.add_argument("--production", action="store_true",
                   help="trusted (not staging) LE IP certificate for the wizard itself")
    u.add_argument("--redeploy", action="store_true",
                   help="re-upload code to the existing droplet and restart the wizard")
    u.add_argument("--cli", action="store_true",
                   help="instead of the wizard: run `porch setup --non-interactive` over ssh (needs "
                        "--domain and --dns-provider cloudflare), streamed; exit 1 unless all steps are done")
    u.add_argument("--connection", default="direct", help="with --cli: the connection mode")
    u.add_argument("--acme-staging", action="store_true", help="with --cli: LE staging certificate")
    u.add_argument("--installer", action="store_true",
                   help="bare droplet + the real site/porch.sh (curl | sudo sh) with a locally built "
                        "tarball (file://); cloud firewall allows 22, 80, 8443. --redeploy re-runs it. "
                        "With --cli: then stop the wizard and run porch setup non-interactively "
                        "(firewall adds 443, 7000)")
    t = sub.add_parser("relay-test", help="home droplet behind a cloud firewall + a porch relay (paid/byo/oracle)")
    t.add_argument("--region", default=DEFAULT_REGION)
    t.add_argument("--size", default=DEFAULT_SIZE)
    t.add_argument("--mode", choices=("paid", "byo"), default="paid",
                   help="paid: porch rents the relay; byo: porch-e2e makes a plain droplet first and "
                        "porch installs the relay on it over ssh")
    t.add_argument("--oracle-sim", action="store_true",
                   help="byo with Oracle's iptables REJECT firewall on that server, via the oracle mode")
    t.add_argument("--relay-provider", choices=sorted(RELAY_PROVIDERS),
                   help="paid: digitalocean (default) or vultr (token inf://prod/porch/VULTR_TOKEN, "
                        "PORCH_E2E_VULTR_TOKEN_REF)")
    t.add_argument("--relay-region", help="paid: relay region (default: --region on DO, porch's on Vultr)")
    t.add_argument("--relay-size", help="relay size (default: porch's cheapest)")
    t.add_argument("--branch", default="HEAD")
    t.add_argument("--domain", required=True)
    t.add_argument("--dns-provider", required=True)
    t.add_argument("--acme-staging", action="store_true", help="LE staging certificate (untrusted)")
    t.add_argument("--keep", action="store_true", help="leave everything up (then: down --yes)")
    sub.add_parser("status", help="list porch-e2e droplets + wizard log tail")
    s = sub.add_parser("ssh", help="ssh in as porch")
    s.add_argument("remote_cmd", nargs=argparse.REMAINDER, metavar="cmd")
    lg = sub.add_parser("logs", help="tail the wizard and porch-setup logs")
    lg.add_argument("-n", default="60")
    d = sub.add_parser("down", help="rollback, delete the droplet(s) and key, forget state")
    d.add_argument("--yes", action="store_true")
    return p


def main(argv=None, **kw):
    a = parser().parse_args(argv)
    app = App(**kw)
    try:
        return getattr(app, a.cmd.replace("-", "_"))(a)
    except E2EError as e:
        print(f"porch-e2e: {e}", file=app.err)
        return 1


if __name__ == "__main__":
    sys.exit(main())

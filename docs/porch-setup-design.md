# Porch setup engine: implementation plan

Two things on the live box change the design:

1. **The localhost bypass makes relay mode unsafe as things stand.** In `lib/authserver.py` (around line 1998), `_verify_login` approves any frp Login whose `client_address` starts with `127.0.0.1:` or `[::1]:`. In every relay mode, remote devices reach the home frps through a home-side frpc forward. frps therefore sees all of them as coming from 127.0.0.1, and every device skips auth. This has to be fixed before any relay mode ships (step R0 below).
2. **An existing HAProxy config may be shared with many services that aren't Porch's.** Porch can own the whole file on a fresh install, but never on such a box. There it can only check its own lines against the live file (an "adopt" diff, section 5).

What I checked:
- **certbot 5.8.0** has `--ip-address` and `--required-profile`. HAProxy is 2.8.16, frps 0.67.0, Python 3.12.
- **DNS** for the reference install is at a registrar with an API (name.com); Cloudflare is the other supported provider.
- **The reference box has a public IPv4 (e.g. 203.0.113.16), not CGNAT,** and IPv6.
- **Some legacy listeners were open on every interface** (frps vhost ports, a fronting web server). Generated configs bind them to 127.0.0.1.
- **`lib/porch_config.py` / `config/porch.toml` don't exist yet.** Everything below reads hosts through them.

---

## 1. Architecture

### Layout (new package; stdlib only)
```
bin/porch                         dispatcher (python)
bin/porch-acme-hook               certbot --manual auth/cleanup hook -> dns providers (replaces name.com-only hooks)
bin/porch-cert-deploy             certbot deploy hook: combined PEM + haproxy reload (generalizes certbot-deploy-hook)
lib/porch_setup/
  engine.py      Step, Check, Action, Input, Context, Engine (run/resume/rollback/plan)
  state.py       load/save/lock state file, schema migration
  io.py          UI protocol: CliIO (tty prompts, --yes/flags), WebIO (queue-backed), NullIO (tests)
  runner.py      subprocess wrapper: dry-run, sudo, redaction, recorded calls (FakeRunner for tests)
  files.py       managed-file writer: atomic, sha256 manifest, refuses to overwrite user edits
  secretstore.py ref-based secrets: inf:// op:// (via cush_secrets) + file:// (0600 under ~/.config/porch/secrets/)
  render.py      template rendering (string.Template + small {% if %}-free fragment composition)
  haproxy_diff.py section-aware normalizer + adopt diff
  dnsq.py        minimal stdlib DNS client (UDP/TCP wire format: A, AAAA, NS, SOA, TXT, CNAME; @server)
  dns/  base.py detect.py manual.py cloudflare.py namecom.py route53.py digitalocean.py
        porkbun.py hetzner.py gandi.py lexicon.py
  acme.py        certbot driver (unprivileged config-dir), IP-cert issue, cert inspection
  net/  probe.py upnp.py natpmp.py (NAT-PMP+PCP) router.py reach.py
  connect/ base.py direct.py portforward.py upnp.py ipv6.py relay.py
           relay_hetzner.py relay_do.py relay_vultr.py relay_ssh.py (BYO + Oracle)
  steps/ preflight.py domain.py network_probe.py connection.py firewall.py dns_provider.py
         dns_records.py certificate.py haproxy.py frps.py services.py admin.py landing.py smoke.py
  web.py         wizard server (TLS, one-time key, JSON API, SSE)
  web/wizard.html wizard.js       (porch.css, strict CSP, no inline)
  doctor.py      read-only verify of every step + extras
  dnswatch.py    dynamic-IP updater
config/templates/
  haproxy.cfg.tmpl (fragments: global, defaults, frontend_head, acls, routing, gate, cookie_strip, backends)
  frps.toml.tmpl  frpc-relay.toml.tmpl  nginx-landing.conf.tmpl (optional)
  systemd/porch-{auth,frps,status,shortener,landing,relay-frpc,dns-watch,renew}.{service,timer}.tmpl
  relay/cloud-init.yaml.tmpl  relay/frps-relay.toml.tmpl  relay/install-relay.sh.tmpl
data/porch/router-guides.json   brand -> admin URL, menu path, notes
data/porch/oui.json             small OUI->brand table (about 40 brands)
```

### Step contract (`engine.py`)
```python
@dataclass class Check:  ok: bool; code: str; message: str; hint: str = ""
@dataclass class Action: kind: str; target: str; detail: str   # used by plan/--dry-run and web "what will happen"
@dataclass class Input:  name: str; kind: Literal["text","secret","choice","bool"]; prompt: str
                         default: Any = None; choices: list | Callable[[Context], list] = None
                         validate: Callable[[Any], str|None] = None; flag: str = ""  # e.g. "--dns-provider"
class Step:
    id: str; title: str; requires: tuple[str, ...] = ()
    def inputs(self, ctx) -> list[Input]: ...
    def applicable(self, ctx) -> bool: return True
    def preflight(self, ctx) -> list[Check]: ...
    def plan(self, ctx) -> list[Action]: ...
    def apply(self, ctx) -> dict: ...          # idempotent; returns outputs (persisted)
    def verify(self, ctx) -> list[Check]: ...  # also used by doctor and --adopt
    def rollback(self, ctx, outputs: dict) -> None: ...
class Context:  cfg (porch_config), state, io, run (Runner), files, secrets, dns (dnsq resolver),
                http (urlopen wrapper, injectable), clock, dry_run: bool, adopt: bool
class Engine:
    def __init__(self, steps, ctx); def run(self, until=None, only=None); def resume(self)
    def rollback(self, to_step=None); def plan(self) -> dict[str, list[Action]]; def status(self) -> dict
```
How the engine runs a step: lock, check `requires` are done, collect missing inputs through `ctx.io`, run `preflight`. Any failing Check stops the step with `failed/preflight` and its hint. Then `apply`, then `verify`, then persist. A step whose verify still passes on re-run is a no-op, which is what makes runs idempotent. `--adopt` runs `verify` only and marks passing steps `adopted`.

### State file
Path: `data/porch-setup.json`, mode 0600, written atomically through `porch_http.atomic_write_json`. Lock: `data/.porch-setup.lock` (fcntl.flock), so the CLI and web front-ends cannot run at the same time.
```json
{ "version": 1, "run_id": "…", "created_at": "…", "mode": "fresh|adopt",
  "inputs": {"domain": "example.com", "dns_provider": "cloudflare", "connection": "upnp", "admin_set": true},
  "secret_refs": {"dns": "inf://prod/porch/CLOUDFLARE_TOKEN", "relay": "file://~/.config/porch/secrets/hetzner"},
  "facts": {"lan_ip":"…","gateway":"…","public_ipv4":"…","wan_ipv4":"…","ipv6":["…"],"cgnat":false,
            "upnp":{"found":true,"model":"…"},"natpmp":false,"pcp":false,"router_brand":"netgear",
            "zone_apex":"example.com","ns":["…"], "inbound":{"80":"ok|blocked|unknown","443":"…","7000":"…"}},
  "steps": { "<id>": {"status":"pending|running|done|failed|skipped|adopted|rolled_back",
             "attempts":1,"started_at":"…","finished_at":"…","outputs":{},
             "error":{"code":"dns.auth","message":"…","hint":"…"}, "undo":[{"kind":"dns.delete","id":"…"}] } },
  "files": {"/etc/haproxy/haproxy.cfg": {"sha256":"…","backup":"/etc/haproxy/backups/…"}},
  "connection": {"active":"upnp","history":[{"mode":"…","at":"…"}],
                 "relay":{"provider":"hetzner","server_id":"…","ip":"…","created_at":"…","monthly_usd":4.5}} }
```
Rules:
- A step left in `running` (crashed partway) is treated as `failed` on resume. Its `undo` list is replayed only if the user asks.
- Each `apply` appends to `undo` before it acts (write-ahead), so a crash still leaves a correct rollback list.
- Rollback runs in reverse order: `porch setup --rollback [--to <step>]`.

### Secrets flow
- **CLI:** tokens are read with `getpass` or from `--dns-token-ref inf://…|op://…|file://…`, or from the `PORCH_DNS_TOKEN` env var for scripted runs. They are never accepted as argv values.
- **Web:** tokens arrive in a POST over the wizard's own TLS. Either way the value goes straight to `secretstore.put(ref, value)`.
- **Storage:** Infisical by default (`inf://<env>/porch/<KEY>`), otherwise `file://` at 0600 inside a 0700 dir. Only the ref is kept in state and porch.toml.
- **Redaction:** `Runner` and every log line go through a redactor that holds every secret value read in that process.
- **Test:** a unit test greps the state file and captured logs for the fake token.
- **certbot runs unprivileged** (`--config-dir ~/.local/share/porch/acme --work-dir … --logs-dir …`). DNS-01 needs no root, so the hook can read the user's Infisical credentials. Root is needed only for the haproxy reload and for writing `/etc/haproxy/haproxy.cfg`. Those go through the existing `bin/haproxy-apply` and a sudoers line that `porch setup` shows and asks the user to install: `systemctl reload haproxy`.

### How CLI and web share the engine
Both build the same `Engine(STEPS, ctx)` and differ only in `ctx.io`.
- **CliIO** prompts on a tty and maps each `Input.flag` to argparse. `--non-interactive` fails with exit code 2 and lists the missing flags.
- **WebIO** keeps pending `Input`s in a queue. The engine thread blocks until the browser posts an answer. Events (`step_started`, `check`, `log`, `needs_input`, `done`) go to an SSE stream.

---

## 2. Step contracts (in graph order)

| id | preflight | apply | verify | rollback / failure text |
|---|---|---|---|---|
| `preflight` | Linux; py ≥3.10; sudo; haproxy ≥2.4; certbot ≥2.0 (≥ the first version with `--ip-address` if using web bootstrap, detected with `certbot --help all`); clock skew <60s via NTP query in dnsq-style UDP; ports 80/443/7000 free **or** owned by haproxy/frps; `loginctl` linger | enable linger (asks first) | same | "Port 443 is used by `<proc>`. Porch needs HAProxy there." |
| `domain` | `domain` input; `dnsq` SOA walk finds the zone apex; NS resolvable | `porch_config.write(domain.root, tunnel_base=tunnel.<root>, auth_host, panel_host, landing_host)` | hosts derive cleanly, no label over 63 characters | restore the previous porch.toml from the files manifest |
| `network_probe` | — | facts: LAN IP and gateway (`/proc/net/route`); public v4 from 2 echo services that must agree; WAN v4 from UPnP `GetExternalIPAddress` / NAT-PMP; CGNAT = WAN in 100.64/10 or RFC1918, or WAN ≠ public; global v6; router brand | facts present | no-op |
| `connection` | see section 3; marks each mode works / likely / unavailable with a reason | runs the mode's sub-steps; outputs `ingress_ipv4`, `ingress_ipv6`, `ddns: bool` | mode-specific reachability | mode teardown |
| `firewall` | detect ufw / firewalld / nft | open tcp 80, 443, 7000 (relay: none at home); records the rules it adds | rules present | delete only the rules it added |
| `dns_provider` | NS → provider (`dns/detect.py`) | asks for credentials (secret input); `provider.check()` lists the zone; stores the ref | `check()` OK | none. On failure: "Cloudflare token needs Zone:DNS:Edit on example.com" |
| `dns_records` | desired set: `A/AAAA` for `auth`, `panel`, `tunnel` (landing), `*.tunnel`; apex only with explicit opt-in; diff against existing records | create, or update after asking on conflict; Cloudflare `proxied=false`; TTL 300; stores record ids and previous values | `dnsq` against each authoritative NS, then 1.1.1.1/8.8.8.8, polls up to 10 min with progress | delete what it created, restore values it overwrote |
| `certificate` | provider working; LE staging dry-run first (`certbot certonly --dry-run`) | `certbot certonly --manual --preferred-challenges dns --manual-auth-hook "bin/porch-acme-hook auth" --manual-cleanup-hook "bin/porch-acme-hook cleanup" --deploy-hook bin/porch-cert-deploy --cert-name porch-<root> -d auth.<root> -d panel.<root> -d tunnel.<root> -d '*.tunnel.<root>'`; installs a `porch-renew.timer` user timer | parse PEM (`openssl x509 -noout -ext subjectAltName -enddate`); SANs match; more than 20 days left | remove the combined PEM; keep the LE lineage (no revoke) |
| `haproxy` | `haproxy -c` on the candidate | render → candidate in the scratch dir → `bin/haproxy-apply <cand>` (existing: validate, diff, backup, reload, rollback) | adopt diff = 0 missing; `curl --resolve` SNI checks at 127.0.0.1:443 | `bin/haproxy-apply <backup>` |
| `frps` | — | render `config/frps.toml` (`subDomainHost`, 4 plugin ops, `proxyBindAddr="127.0.0.1"`, random dashboard password at 0600) | `frps verify -c` (if supported) plus a TOML parse | restore the earlier file |
| `services` | systemd user session available | install `porch-{auth,frps,status,shortener,landing}` user units (all ports >1024, so no root); `enable --now` | `systemctl --user is-active`; loopback HTTP health checks (9512 `/auth/`, 9471 `/api/me`) | disable + remove units it wrote |
| `admin` | authserver up | no admin yet: CLI asks for a password twice (getpass) and runs the `bin/auth-admin set-password` path; web: a form backed by the same function. Then print `https://auth.<root>/auth/` to enroll this browser | `devices.json` has an admin | none (by design) |
| `landing` | — | `bin/deploy` with the web root from config | `GET landing/` 200 | restore the earlier files |
| `smoke` | — | (1) SNI handshake at 127.0.0.1:443 for each host, with chain and hostname checks (`ssl`); (2) `GET https://auth.<root>/auth/` 200; (3) a throwaway `bin/tunnel` to a stdlib server as `porch-smoke-<rand>`, fetched through 127.0.0.1:443 with SNI; (4) an external check (below) | all pass | — |

**External reachability (no third-party service in the MVP).**
- "Phone check": print a QR for `https://porch-smoke-<rand>.tunnel.<root>/<nonce>` and ask the user to open it on cellular. The engine sees the request land and marks the check passed.
- When port 80 is up, an LE http-01 validation (the IP cert) also proves reachability.
- A Porch-hosted probe can be added later (open question 4).
- Don't rely on hairpin NAT. Many routers don't support it.

**ACME client: keep certbot, don't vendor one.** The stdlib has no RSA/ECDSA signing, so a vendored client would have to shell out to `openssl` the way acme-tiny does. That's more code to own for no real gain. certbot is already here, can be installed with apt or snap, and handles renewal. DNS-01 runs through our own `--manual` hook, the same pattern as today's `certbot-auth-hook`, but provider-generic.
- The hook must **add** a TXT record, not replace it. `tunnel.<root>` and `*.tunnel.<root>` share `_acme-challenge.tunnel.<root>`, so two values are live at once.
- Cleanup must delete **only** its own value.
- The hook waits on the authoritative NS through `dnsq`, not on 8.8.8.8.

**IP-certificate bootstrap (for the web wizard).**
- From what I know (to verify when implementing): Let's Encrypt issues IP-address certs only under the `shortlived` profile (about 160 hours), only through http-01 or tls-alpn-01 (no DNS-01), for public IPv4 and IPv6.
- certbot 5.8 here has `--ip-address` and `--required-profile`. Before relying on it, confirm on staging that the LE directory lists `shortlived` and accepts IP identifiers.
- Flow:
  1. `porch setup --web`, started with sudo, binds :80 and :443 and drops to the porch user (`os.setgid`/`os.setuid` after bind).
  2. :80 serves `/.well-known/acme-challenge/` from a temp dir.
  3. certbot runs unprivileged: `certonly --manual --preferred-challenges http --manual-auth-hook <writes token file> --ip-address <public_ip> --required-profile shortlived --cert-name porch-bootstrap-ip`.
  4. :443 serves TLS with that cert.
  5. Once setup is done, the wizard exits and the cert is deleted (it is never renewed).
- The chicken-and-egg: port 80 must already reach the box. So the CLI front-end first runs `preflight`, `network_probe` and the UPnP/NAT-PMP mapping (with consent), then issues the cert and hands over to the web UI.
- Fallbacks when that isn't possible (CGNAT, blocked 80): (a) CLI only; (b) `ssh -L 8443:127.0.0.1:8443 box`, then `https://localhost:8443` with a self-signed cert whose SHA-256 fingerprint the terminal prints; (c) LAN `http://<lan-ip>:8443` behind an explicit warning.
- IP certs go into Certificate Transparency logs, so scanners will find the wizard quickly. Keep the key, rate limits and TTL tight.

**Web wizard security.**
- Key: 32 random bytes, in `https://<ip>/#k=<key>` (printed and shown as a QR). The page JS reads it, clears it with `history.replaceState`, and POSTs `/api/session`. The key is single-use and comparisons use `hmac.compare_digest`.
- The server answers with a host-only `Secure; HttpOnly; SameSite=Strict` session cookie.
- 5 wrong keys locks the session endpoint for 10 minutes.
- Every POST must carry `X-Porch-CSRF` matching the session.
- Strict nonce CSP plus porch.css. The server exits after 60 minutes idle or when setup is done.
- API: `GET /api/state`, `GET /api/events` (SSE), `POST /api/inputs/<step>`, `POST /api/run`, `POST /api/rollback`.

**HTTPS-policy defaults for bring-your-own domains** (the live config's habits would be harmful on someone else's domain):
- Send no HSTS `preload`, and no `includeSubDomains` on the apex.
- Turn off the domain-wide `cush_auth` edge gate on fresh installs (`PORCH_ACCEPT_LEGACY_COOKIE=0`, no `cookie_domain` cookie), because it would leak to the user's other subdomains.
- Leave apex records alone unless asked.

---

## 3. Connection modes

**Detection (in `connection.py`)** sets `recommended` and a status per mode:
- **Host has a public IPv4 on an interface (VPS)** → `direct`: no forwarding needed.
- **WAN is public, WAN equals the public IP, and UPnP or NAT-PMP/PCP answers** → `upnp` (recommended).
- **WAN is public and there's no UPnP** → `manual` (guided).
- **CGNAT or double NAT** → relays (`oracle`, `paid`, `byo`). `ipv6` is offered with a caveat: it only works for IPv6 visitors and devices.
- **A global v6 address and an inbound pinhole are possible** → `ipv6` is marked works, but only as an add-on to IPv4 modes or alone with that caveat.

**Per mode:**
- **`upnp` (`net/upnp.py`, `net/natpmp.py`):**
  - SSDP M-SEARCH, fetch the device XML, SOAP `AddPortMapping` for tcp 80, 443 and 7000 with a 0 or 7-day lease plus a refresh timer.
  - NAT-PMP/PCP over UDP 5351 to the gateway.
  - Undo: `DeletePortMapping`.
  - The IP changes, so this mode sets `ddns=true` and enables `porch dns watch`.
- **`manual`:**
  - Router brand comes from the UPnP description, the gateway HTTP `<title>`/`Server` header, or the ARP MAC OUI.
  - Show the matching `router-guides.json` entry (admin URL, menu path; app-only for eero / Google Wifi; ISP-gateway notes), the LAN IP to forward to, and ports 80, 443, 7000.
  - The user presses "done", then the engine runs the reachability check (phone check, plus LE http-01 if the IP cert is in play) and loops with a specific hint per failure.
- **`ipv6`:** AAAA records only; PCP or IGDv2 `AddPinhole` when available, otherwise a guide to the router's firewall setting. Warn that IPv4-only visitors can't reach it.
- **Relays (all of them):** built (paid, byo, oracle). See CLAUDE.md "porch connect" for the as-built details.
  - The relay runs **only frps** (`porch-relay-frps.service`, DynamicUser). Its config has a control `bindPort=7835`, a random token, `allowPorts` 80/443/7000 and no dashboard.
  - Home runs the `porch-relay` user unit (frpc, `config/relay-frpc.toml`) with three `tcp` proxies, remotePort 80, 443 and 7000. Proxies 80 and 443 use `transport.proxyProtocolVersion = "v2"`.
  - That is pure TCP pass-through, so TLS and the private key stay at home. The relay never sees plaintext.
  - Home HAProxy gets extra `bind 127.0.0.1:9476 accept-proxy` / `bind 127.0.0.1:9477 ssl crt … accept-proxy` lines (not 8080/8443: the setup wizard listens on 8443). frpc targets those, so client IPs survive and XFF stays right. Port 7000 goes straight to home frps (no PROXY header).
  - No HAProxy is needed on a single-tenant relay. HAProxy `mode tcp` + `req.ssl_sni` only matters for the later hosted multi-tenant relay.
  - DNS points at the relay IP, which is static, so `ddns=false`.
  - **R0 prerequisite:** replace the IP-based localhost bypass with a home device token at `data/.home-frpc-token` (0600), added by home launchers. Keep the bypass only behind `PORCH_LOCALHOST_BYPASS=1` for adopt mode. `porch connect` refuses relay modes while the bypass is on.
- **`paid` (Hetzner, DigitalOcean, Vultr):**
  - The API token is collected as a secret.
  - Pick the smallest plan and show the price from the API (about $4–6/month). Create the server with `user_data` = rendered `cloud-init.yaml.tmpl`, which:
    - downloads frps with a pinned version and sha256;
    - writes `frps-relay.toml` and a systemd unit;
    - opens nftables for 80, 443, 7000 and 7835;
    - turns on unattended-upgrades.
  - Server id and IP are stored. Poll until the relay's 7835 accepts the token.
  - Teardown: `porch connect --off` (alias `--teardown-relay`) deletes the server. It asks first (`--yes` when unattended) and shows the monthly cost. `porch setup --rollback` deletes it without asking (the rollback was the consent). Only a server that still carries the `porch-relay` tag is deleted.
  - As built: ufw instead of raw nftables (reset, 22 only from the creating box's public IP); no unattended-upgrades step (Ubuntu images ship it on).
- **`byo` / `oracle`:**
  - `relay_ssh.py` asks for `user@host` and runs `install-relay.sh` over `ssh` (the same content as the cloud-init).
  - Oracle Always Free gets a guide only: create the VM by hand, open the VCN security list for 80, 443, 7000 and 7835, then BYO-over-SSH. The OCI API needs RSA request signing, which is not worth it.

**Switching with `porch connect <mode>`** is make-before-break:
1. Lower the TTL to 60.
2. Bring up the new ingress.
3. Verify it by direct-IP SNI checks against the new IP.
4. Flip the DNS records (porch-managed ids only).
5. Wait for propagation, then run smoke.
6. Tear down the old ingress after a grace period (relay deletion asks first).
7. Append to `connection.history`.

`server.frp_addr` stays `tunnel.<root>`, a hostname, so paired devices survive mode switches.

**DNS providers (`dns/base.py`):**
```python
class Provider:
    name: str
    def __init__(self, token: dict, http=urlopen): ...
    def check(self, zone: str) -> None
    def list(self, zone, name=None, rtype=None) -> list[Record]
    def create(self, zone, Record) -> str        # returns id
    def update(self, zone, id, Record) -> None
    def delete(self, zone, id) -> None
```
- Cloudflare: Bearer token; `proxied=false`.
- name.com: v4 Basic auth. It's on the dogfood box, so it goes in the MVP.
- Route 53: SigV4 written with hmac/hashlib, plus a minimal IAM policy shown to the user.
- DigitalOcean: v2.
- Porkbun: hint that API access must be enabled per domain.
- Hetzner: target the Cloud API zones/rrsets, since the old dns.hetzner.com API is being retired. Verify.
- Gandi: LiveDNS with a Personal Access Token.
- `lexicon.py`: shells out to `lexicon` when it's on PATH (`pipx install dns-lexicon==<pin>`). Not vendored, because it pulls in `requests` and `tldextract`.
- `detect.py`: maps NS suffixes to providers (`ns.cloudflare.com`, `awsdns-`, `digitalocean.com`, `porkbun.com`, `name.com`, `hetzner`, `gandi.net`). It also maps registrar NS to lexicon providers (godaddy, namecheap, ovh, …). Anything unknown goes to `manual`.
- `manual.py`: shows the record table and polls `dnsq` until the records resolve.

**`porch dns watch`:** a user timer every 5 minutes. It reads the WAN IP (UPnP first, then echo services) and updates only porch-managed record ids. It is active only when `ddns=true`.

---

## 4. `bin/porch` CLI
Python argparse dispatcher. Its own subcommands:
```
porch setup [--web] [--adopt] [--dry-run] [--non-interactive] [--domain D] [--dns-provider P]
            [--dns-token-ref REF] [--connection MODE] [--only STEP] [--from STEP] [--rollback [--to STEP]] [--status]
porch doctor [--json] [--fix-hints]
porch connect <direct|upnp|manual|ipv6|oracle|paid|byo> [user@host] [--provider digitalocean|hetzner|vultr]
              [--token-ref REF] [--region R] [--size S] [--ssh-key K] [--tag T] [--off]
porch dns {show|watch [--once]|set}       porch cert {issue|renew|status}
porch render {haproxy|frps|units|cloud-init} [--out F] [--against /etc/haproxy/haproxy.cfg]
```
Existing tools are passed through with `os.execv` so they keep working:
- `porch tunnel|serve|drop|media|music|paste|exchange|secure-entry|form|share` → `bin/<tool>`
- `porch auth …` → `bin/auth-admin`
- `porch server start|stop` → `bin/start-server` / `bin/stop-server`
- `porch status` → `bin/status`

Old scripts change as follows:
- `bin/renew-cert`, `certbot-auth-hook`, `certbot-cleanup-hook` become thin wrappers over `porch cert renew` and `porch-acme-hook`, after adopt is verified.
- `issue-cert` stays as it is (HTTP-01 for other services on this box).

Exit codes: 0 ok, 2 usage / missing input, 3 preflight, 4 apply, 5 verify, 6 aborted.

---

## 5. Tests and checks on the live box
- **Unit tests (stdlib, no network):**
  - `FakeProvider` is an in-memory zone that records each call.
  - `FakeResolver` is a dict that can simulate propagation delay with a fake clock.
  - `FakeRunner` matches argv to canned results. A "fake certbot" calls the auth/cleanup hooks with `CERTBOT_DOMAIN`/`CERTBOT_VALIDATION` and drops a fixture cert.
  - Provider clients run against a loopback `http.server` that mimics each API's request/response shapes (via an injected `base_url`).
  - UPnP and NAT-PMP use a loopback SSDP/SOAP responder and a UDP responder.
  - Cert fixtures are a test-only self-signed PEM in `tests/fixtures/`, or generated with `openssl` (the test is skipped without it).
- **Engine tests:**
  - Stop after step k, reload state, resume, and expect no duplicate creates.
  - Run twice and expect zero mutating calls the second time.
  - Rollback order and the write-ahead undo list.
  - A user-edited managed file is refused.
  - Secret redaction: grep the state file and logs.
  - Web: key single-use, lockout, CSRF, session cookie flags.
- **Render golden test:** render with cush.rocks defaults and compare to a committed `tests/fixtures/haproxy-porch.golden.cfg`.
- **Adopt diff (`haproxy_diff.py`):**
  - Parse both configs into `{section: [normalized directive]}`: comments stripped, whitespace collapsed, and Porch-irrelevant sections and directives dropped.
  - For each section in the rendered template, check every template directive exists in the same live section, and that the template's relative order holds (LCS over the shared directives). `use_backend` order and the gate-before-strip order matter.
  - Report `missing`, `different` (same key such as `bind`/`server`, different args) and `order`.
  - `config/porch.toml` gets an `adopt.allow` list for accepted deltas, e.g. the extra `crt …veri-fi.org.pem` and the 0.0.0.0 frps binds.
  - Target on this box: `porch render haproxy --against /etc/haproxy/haproxy.cfg` reports 0 missing.
- **Safe on this box (read-only):**
  - `porch setup --adopt --dry-run`: all verify calls, nothing applied.
  - `porch doctor`.
  - `porch render … --against`.
  - name.com provider `check()`/`list()` (read-only API).
  - NS detection.
  - `network_probe`: SSDP is read-only, and `GetExternalIPAddress` doesn't change anything.
  - `certbot certonly --dry-run` against staging, using the unprivileged config-dir. It creates and removes a TXT record, which is harmless.
- **Not on this box:** `haproxy` apply, `services`, `upnp` add, relays. Use a throwaway VM or a test domain for those.

---

## 6. Workstreams (file ownership)

**Day 0, a 1–2 hour freeze owned by W1:** `engine.py` (dataclasses + Engine signatures), `state.py` schema, `io.py` protocol, `runner.py`, and `secretstore.py` signatures (`get(ref)`, `put(ref, value)`). W2 and W3 code against these.

- **W1: engine, CLI, rendering, core steps.**
  - Owns `bin/porch`, `lib/porch_setup/{engine,state,io,runner,files,render,haproxy_diff,doctor}.py`, `steps/{preflight,domain,firewall,haproxy,frps,services,admin,landing,smoke}.py`, `config/templates/{haproxy.cfg.tmpl,frps.toml.tmpl,nginx-landing.conf.tmpl,systemd/*}`, `tests/test_porch_{engine,render,haproxy_diff,cli}.py`, `tests/fixtures/haproxy-porch.golden.cfg`.
  - Also does R0, the bypass-to-home-token change in `lib/authserver.py`, `bin/start-server` and the launchers. It's a separate small change with its own tests.
- **W2: DNS, ACME, secrets.**
  - Owns `lib/porch_setup/{dnsq,acme,secretstore,dnswatch}.py`, `dns/*`, `steps/{dns_provider,dns_records,certificate}.py`, `bin/porch-acme-hook`, `bin/porch-cert-deploy`, `config/templates/systemd/porch-{renew,dns-watch}.*` (W1 hands these over), and `tests/test_porch_{dnsq,dns_*,acme,secretstore}.py`.
- **W3: network, connection, web wizard.**
  - Owns `lib/porch_setup/net/*`, `connect/*`, `steps/{network_probe,connection}.py`, `web.py`, `web/*`, `config/templates/relay/*`, `data/porch/{router-guides,oui}.json`, and `tests/test_porch_{net,upnp,natpmp,connect,web}.py`.

**Delivery order:**
1. **MVP (CLI):** W1 engine, CLI, render and adopt diff, plus R0. W2: dnsq, detect, Cloudflare, name.com, manual, certbot DNS-01, secretstore. W3: probe, `direct` / `upnp` / `manual` modes, phone check.
   - Exit test: adopt passes on this box, and a fresh VM with a Cloudflare test domain passes smoke.
2. **Web wizard:** W3 `web.py`. W2 `acme.issue_ip_cert` and the privilege-drop bootstrap.
3. **More, in parallel:**
   - W2: Route 53, DigitalOcean, Porkbun, Hetzner, Gandi, lexicon, `dns watch`.
   - W3: `ipv6`, `byo` / `oracle`, `paid` relays and `porch connect` switching. (Relays built 2026-10-19; `ipv6` still to come.)
   - W1: doctor polish, migrating `bin/renew-cert` and the hooks.

---

## 7. Risks and open questions for you
1. **Localhost bypass (R0).** Relay modes are unsafe until home's own frpc authenticates with a token. OK to make that the default and keep the bypass only for adopt mode?
2. **The IP-cert web bootstrap can't work behind CGNAT or a blocked port 80.** Are the CLI and the SSH `-L` route acceptable fallbacks there? Also, LE IP-cert availability (the `shortlived` profile) needs re-checking on staging when this is built.
3. **Apex vs. subdomain base.** Should fresh installs default to a dedicated base like `porch.example.com`, so Porch never touches the apex or the user's other subdomains? And should the domain-wide `cush_auth` edge gate be off by default?
4. **External reachability probe.** Is the phone check (human-in-the-loop) plus LE http-01 enough, or do you want an opt-in Porch-hosted probe? It would need a hosted endpoint, which has privacy implications.
5. **nginx.** I suggest fresh installs drop nginx: HAProxy routes `/auth/` and `/api/`, and a small static server serves the landing page. Adopt mode keeps the current nginx 8090/8091 setup. OK?
6. **Dependencies.** certbot from the system (apt or snap, version-gated); dns-lexicon optional through pipx with a pinned version; everything else stdlib. No vendored Python packages.

### Critical Files for Implementation
- lib/authserver.py (localhost bypass at the `_verify_login` function, about line 1992; setup token; `server` addr/port; hardcoded hosts)
- /etc/haproxy/haproxy.cfg (reference for the template and the adopt diff: `frontend www-https` lines 40–330, backends `cush_auth`/`tunnel`/`panel`/`tunnelroot`/`cushroot`/`shortener`/`letsencrypt-backend`)
- bin/haproxy-apply (reuse as the haproxy step's installer and rollback)
- bin/certbot-auth-hook, bin/renew-cert, bin/certbot-deploy-hook (to generalize into `porch-acme-hook` / `porch-cert-deploy`)
- config/frps.toml.example and lib/cush_secrets.py (frps template source; secrets backend that `secretstore.py` wraps)
---
## User decisions (2026-10-18), answering the open questions above
1. R0: home frpc gets its own device token by default; the localhost bypass survives only behind PORCH_LOCALHOST_BYPASS=1 for this box's adopt mode; `porch connect` refuses relay modes while it is on.
2. Fresh installs default to a dedicated base subdomain (porch.<domain>); apex is opt-in. Domain-wide cush_auth edge gate off on fresh installs.
3. Reachability: phone check (QR on cellular) + LE http-01. No hosted probe.
4. Fresh installs drop nginx (HAProxy routes /auth/ and /api/, small static server for landing). Adopt mode keeps this box's nginx.
5. Dependencies: system certbot (version-gated), optional pinned dns-lexicon via pipx, otherwise stdlib.

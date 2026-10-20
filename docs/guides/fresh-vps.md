# Fresh VPS (`direct`)

**For:** anyone who wants Porch on a small cloud server with its own public
IPv4. Nothing to configure on a router; the simplest path.

**Cost:** the VPS. On DigitalOcean, `s-1vcpu-1gb` is $6/month with 1 TB of
transfer (October 2026). 512 MB machines work for Porch itself, but 1 GB
leaves room for certbot, video light copies and your own apps.

**Status:** tested end to end by `bin/porch-e2e` on fresh Ubuntu 24.04 and
Debian 13 droplets (installer, wizard and fully unattended setup).

## You need

- A fresh **Ubuntu 22.04/24.04 or Debian 12/13** server, amd64 or arm64, with
  a public IPv4 and root (or sudo) access.
- **A domain.** Cloudflare and name.com DNS are set up automatically with an
  API token; any other DNS host works with records you add by hand. Porch lives
  at `porch.<domain>` (so `auth.porch.example.com`, `*.tunnel.porch.example.com`)
  and leaves the rest of your domain alone unless you choose `--apex`.
- For automatic DNS: a **Cloudflare token** with Zone > DNS > Edit on the zone,
  or a **name.com** username + API token.
- Nothing else listening on ports 80 and 443.

## Steps

### 1. Install

On the server, as root:

```bash
curl -sSL https://raw.githubusercontent.com/Hexidecibel/porch/main/site/porch.sh | sudo sh
# or, from a clone of this repo:
sudo sh site/porch.sh
```

Not a brand-new box? See what it would change first (read-only):

```bash
curl -sSL https://raw.githubusercontent.com/Hexidecibel/porch/main/site/porch.sh | sudo sh -s -- --check
```

Prefill the wizard while you are at it:

```bash
curl -sSL https://raw.githubusercontent.com/Hexidecibel/porch/main/site/porch.sh | sudo sh -s -- \
  --domain example.com --dns-provider cloudflare
```

The installer apt-installs HAProxy, Python, openssl and curl, snap-installs
certbot, creates a `porch` user (passwordless sudo, no password), downloads
Porch and frp (both sha256-checked), opens 80 and 8443 in an active ufw and
starts the setup wizard. It prints a one-time link (and a QR code):

```
https://203.0.113.7/#k=...      (a short-lived Let's Encrypt certificate for the IP)
```

Lost it? `sudo sh porch.sh --url` prints it again. See
[Where the installers download from](../install.md#where-the-installers-download-from)
if you run your own copy.

### 2. Run the wizard

Open the link. The wizard runs the same steps as `porch setup`, live:

| Step | Choose |
|---|---|
| Domain | `example.com`; leave *apex* off unless Porch should own the whole domain |
| Connection | **Direct (this machine has a public IP)**; the wizard marks it *works* |
| DNS provider | Cloudflare / name.com (paste the token, or a stored ref) / manual |
| Certificate | an email for expiry notices (optional) |
| Admin password | at least 12 characters; it guards the admin page and the Porch app's step-up |

It then configures the firewall (tcp 80, 443, 7000), HAProxy, frps, the DNS
records, the certificate, the services and the landing page, and finishes with
a smoke test.

**Terminal instead of a browser:**

```bash
sudo systemctl stop porch-wizard      # if the installer started it
sudo -iu porch
cd ~/porch
bin/porch setup                # asks the same questions
# or fully unattended:
PORCH_ADMIN_PASSWORD='a long passphrase' bin/porch setup --non-interactive --yes \
  --domain example.com --connection direct \
  --dns-provider cloudflare --dns-token-ref inf://prod/porch/CLOUDFLARE_TOKEN \
  --acme-email you@example.com
```

Tokens are always passed as refs (`inf://`, `op://` or
`file://~/.config/porch/secrets/<name>`), or through `PORCH_DNS_TOKEN`; never
as a value on the command line.

## Verify

- The wizard's last page lists your URLs. `https://auth.porch.example.com/auth/`
  should load the admin login with a trusted certificate.
- Open a door and load it on your phone with Wi-Fi off:

  ```bash
  porch tunnel 8080 hello --bg     # anything listening on 8080
  # https://hello.tunnel.porch.example.com
  ```

- `porch doctor` re-checks every step without changing anything.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Installer stops: "80/443 in use" | Something else (nginx, apache, caddy) holds the port. Stop it, or use [adopt](adopt-existing.md). |
| Wizard link does not load | The cloud provider's firewall: allow inbound tcp 80 and 8443 (and later 443, 7000). |
| DNS step waits a long time | It waits until every authoritative name server answers (up to 10 minutes; `PORCH_DNS_WAIT`). Check the token's zone. |
| Certificate step fails | DNS not visible yet, or Let's Encrypt rate limits. Re-run `porch setup`; it resumes where it stopped. Use `--acme-staging` while experimenting. |
| `porch doctor` shows a failing step | Its hint names the fix; `porch setup --only <step>` re-runs one step. |

## Undo

```bash
porch setup --rollback            # everything porch did, newest first
```

Rollback undoes each step from its own write-ahead record: the DNS records it
created, the services, the HAProxy config (its backup comes back), the
firewall rules it added. Then delete the server.

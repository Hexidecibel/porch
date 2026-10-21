# Install

This page covers requirements, the one-line installer, a manual install,
unattended setup and pairing your other machines. For a step-by-step walk
through your situation (VPS, home router, relay), start with the
**[setup guides](guides/README.md)**.

## You'll need

- **A domain.** Cloudflare and name.com DNS are automatic; any other provider
  works with records you add by hand. Porch lives at `porch.<domain>` and
  leaves your apex alone unless you pass `--apex`.
- **A Linux box**: a home server, a mini PC or a small VPS. Ubuntu 22.04/24.04
  and Debian 12/13, amd64 or arm64.
- **Passwordless sudo** for the user that runs Porch (setup checks this first;
  certificate renewals use it to reload HAProxy).
- Packages: Python 3.10+, HAProxy 2.4+, certbot 2.0+ (with `--ip-address` for
  the web wizard), openssl, curl, frp 0.67.0. The installer fetches all of
  them. Optional: `python3-cryptography` (E2E shares, passkeys, Web Push),
  `python3-qrcode` (terminal QR codes), `ffmpeg`/`ffprobe` (video posters,
  light copies, waveforms), Pillow (image verification and thumbnails),
  Chrome or Chromium (`snap`).

## One line, on a fresh server

```bash
curl -sSL https://raw.githubusercontent.com/Hexidecibel/porch/main/site/porch.sh | sudo sh
```

It installs the prerequisites, creates a `porch` user, downloads Porch (the
latest GitHub release) and frp (both sha256-checked), starts the setup wizard
and prints its link and QR code. Prefill it with
`| sudo sh -s -- --domain example.com --dns-provider cloudflare`; print the
link again with `sudo sh porch.sh --url`.

On a server that already runs something, run the read-only check first. It
reports every package, user, unit, firewall rule, port and directory the
installer would touch, and anything that would stop it, and changes nothing:

```bash
curl -sSL https://raw.githubusercontent.com/Hexidecibel/porch/main/site/porch.sh | sudo sh -s -- --check
```

## Where the installers download from

- **`site/porch.sh`** (the server installer) in this repo downloads the latest
  GitHub release: `porch.tar.gz` and its `porch.tar.gz.sha256` from
  `https://github.com/Hexidecibel/porch/releases/latest/download/`. Set
  `PORCH_TARBALL` (and optionally `PORCH_TARBALL_SHA256`) to install another
  build; `file://` works.
- **Your landing page's copies.** Once your Porch is up, `bin/deploy` renders
  `site/*.sh` for your domain and publishes them on your landing page with a
  fresh `porch.tar.gz` (+ `.sha256`; also as `cush-tools.tar.gz`, its old
  name, for installers already out there) built from your own install, so
  `curl -sSL https://tunnel.<your-domain>/porch.sh | sudo sh` installs exactly
  what your server runs.
- **`site/install.sh`** (the client installer) only makes sense against a
  Porch server: run it from your landing page (below). The repo copy is a
  template and stops with a message unless `PORCH_AUTH_URL` and
  `PORCH_REPO_TARBALL` are set (the old `CUSH_*` names still work). It installs
  into `~/porch` (`PORCH_DIR`); a machine paired before the rename keeps its
  `~/cush-tools`. **`bin/bootstrap`** likewise needs
  `--auth-url https://tunnel.<your-domain>` on a machine with no Porch config.
- The tarball holds one top-level directory, `porch/` (older landing-page
  tarballs used `cush-tools/`); the installers take either.

## By hand

```bash
sudo apt update && sudo apt install -y haproxy python3 python3-qrcode python3-cryptography openssl curl git
sudo snap install --classic certbot

git clone <this repo> ~/porch && cd ~/porch
arch=amd64   # or arm64
curl -fsSL https://github.com/fatedier/frp/releases/download/v0.67.0/frp_0.67.0_linux_$arch.tar.gz | tar -xz
install -m 0755 frp_0.67.0_linux_$arch/frp{s,c} bin/ && rm -rf frp_0.67.0_linux_$arch
mkdir -p ~/.local/bin && ln -sf ~/porch/bin/porch ~/.local/bin/porch

sudo porch setup --web          # browser wizard
porch setup                     # or: the same steps in the terminal
```

The wizard walks you through your domain, how the box is reachable, DNS, the
certificate and an admin password, and streams every step live. On a VPS it
serves itself over a short-lived Let's Encrypt certificate for the bare IP; on
a home box it listens on `127.0.0.1:8443` (use `ssh -L 8443:127.0.0.1:8443 <box>`
and compare the printed fingerprint).

<details>
<summary><b>Unattended setup</b></summary>

```bash
PORCH_ADMIN_PASSWORD='a long passphrase' porch setup --non-interactive --yes \
  --domain example.com \
  --connection direct \
  --dns-provider cloudflare --dns-token-ref inf://prod/porch/CLOUDFLARE_TOKEN \
  --acme-email you@example.com
```

Tokens are always **refs** (`inf://…`, `op://…` or
`file://~/.config/porch/secrets/<name>`), never values on the command line.
`porch setup --help` lists every flag.
</details>

```bash
porch doctor              # read-only health check of every step
porch setup --status      # what's done
porch setup --rollback    # undo it all, newest first
```

When it's done (for `--domain example.com`):

| | |
|---|---|
| **Admin**: devices, invites, pairing | `https://auth.porch.example.com/auth/` |
| **Panel**: live doors, history, launch | `https://panel.porch.example.com` |
| **Landing page** and client installer | `https://tunnel.porch.example.com` |
| **Your doors** | `https://<name>.tunnel.porch.example.com` |

## No open ports?

`porch connect --status` reads your network (router, public IP, carrier-grade
NAT, IPv6) and says which connection mode will work. Each mode has a
step-by-step guide, with costs and test status: **[Setup guides](guides/README.md)**.

| Mode | When |
|---|---|
| `porch connect direct` | The box has a public IPv4 (a VPS) |
| `porch connect manual` | You forward ports by hand (guides per router brand) |
| `porch connect upnp` | Your router speaks UPnP, NAT-PMP or PCP |
| `porch connect paid` | CGNAT or a locked router: Porch rents a small relay on DigitalOcean or Vultr |
| `porch connect byo user@host` | A relay on a server you already have |
| `porch connect oracle` | A relay on Oracle's free tier, guided (experimental) |

A relay only forwards TCP: TLS still terminates at your box, so the relay never
holds your key or sees your traffic. Every mode ends with a phone check, a QR
code you open on cellular.

## Bring your other machines

```bash
curl -sSL https://tunnel.<your-porch-domain>/install.sh | sh
```

(from your own Porch server's landing page, which fills in its address)

It installs the client (Linux and macOS, amd64 and arm64) and prints a pairing
code like `ABCD-1234`. Approve it in the admin page (or `bin/auth-admin approve
<code>` on the server, or the Porch app), and that machine can open doors with
its own revocable device token.

## Quick start

```bash
porch tunnel 8080 myapp --bg          # https://myapp.tunnel.<domain>
porch drop inbox --bg                 # an upload page; files land in ~/drops/inbox/
porch share notes.md                  # the right viewer for the file
echo "hello" | porch paste hi --bg
porch secure-entry dbpass --bg        # receive a secret without it touching chat
porch status                          # what's running
porch status extend myapp             # another hour
porch status close myapp
```

`--bg` keeps a door running after your shell exits. Doors close after an hour
unless you pass `--expires`, extend them, or keep them.

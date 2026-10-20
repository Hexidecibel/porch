# Home + port forward (`manual`)

**For:** a home server, mini PC or NAS-like Linux box behind your own router,
where you can log in to the router's admin page.

**Cost:** $0 beyond the domain. Visitors are limited by your home upload speed.

**Status:** in daily use on the author's home box (adopted install, manual
forwards). The guided flow and its phone check are covered by unit tests.

## You need

- A Linux box at home (Ubuntu 22.04/24.04 or Debian 12/13, amd64/arm64) that
  stays on, with passwordless sudo for the user that runs Porch.
- Admin access to your router.
- A domain (Cloudflare / name.com automatic, anything else by hand).
- A **public IPv4** on the router's WAN side. `porch connect --status` tells
  you: if it reports carrier-grade NAT or double NAT, port forwarding cannot
  work; use a [relay](home-paid-relay.md) instead.

## Steps

### 1. Install

Either the one-line installer without the browser wizard:

```bash
curl -sSL https://raw.githubusercontent.com/Hexidecibel/porch/main/site/porch.sh | sudo sh -s -- --check       # read-only report first
curl -sSL https://raw.githubusercontent.com/Hexidecibel/porch/main/site/porch.sh | sudo sh -s -- --no-wizard
sudo -iu porch && cd ~/porch
```

or by hand from a clone (see [Install](../install.md#by-hand)).

### 2. Give the box a fixed LAN address

Add a **DHCP reservation** for the box in the router (or a static IP). The
forwards point at this address; if it changes, they point at nothing.

### 3. Run setup

```bash
bin/porch setup                     # terminal
bin/porch setup --web               # browser: listens on 127.0.0.1:8443
ssh -L 8443:127.0.0.1:8443 <box>    # from your laptop, then open the printed https://localhost:8443/#k=... link
```

(On a home box the wizard uses a self-signed certificate: compare the SHA-256
fingerprint it prints with the one your browser shows.)

Choose:

| Question | Answer |
|---|---|
| Domain | `example.com` (Porch uses `porch.example.com`) |
| Connection | **Port forwarding (guided, in your router's settings)** (`--connection manual`) |
| DNS provider | Cloudflare / name.com / manual |
| Admin password | 12+ characters |

The connection step shows a guide for your router brand when it recognises it
(admin URL, menu path, notes), your box's LAN IP and the three forwards to add:

| External port | Protocol | Internal IP | Internal port |
|---|---|---|---|
| 80 | TCP | the box's LAN IP | 80 |
| 443 | TCP | the box's LAN IP | 443 |
| 7000 | TCP | the box's LAN IP | 7000 |

Add them in the router, then answer **yes** to "Have you forwarded TCP 80,
443, 7000 to ...?". Port 7000 is what your other machines' tunnels connect
to; 80 only answers Let's Encrypt and redirects to HTTPS.

Unattended: `--connection manual --yes` (only when the forwards already exist).

## Verify

On a fresh install the phone check runs at the end of setup (the smoke step),
once HAProxy, DNS and the certificate exist. Later, any time:

```bash
porch connect manual          # re-runs the guide and the phone check
```

It shows a QR code and a URL. Open it **on your phone with Wi-Fi off**. A hit
from your own LAN or your own public address (hairpin NAT on Wi-Fi) is
recorded but not accepted, so it really proves the internet reaches you.

## Troubleshooting

The phone check gives a hint per failed attempt:

- Each forward must point at the box's LAN IP, use TCP, and keep the same
  external and internal port.
- If the LAN IP changed, add a DHCP reservation and fix the forwards.
- Two routers (an ISP gateway in front of yours): forward on both, or put the
  ISP box in bridge mode.
- Some ISPs block inbound 80/443 on home plans. Ask them, or use a relay.
- `porch connect --status` says CGNAT: forwarding cannot work there; see the
  relay guides.
- Your home IP changed (most home lines are dynamic): point DNS at the new
  one with `porch dns set --ipv4 <new ip>` (`porch dns show` lists the
  records). Automatic updating is planned.

## Undo

```bash
porch connect --off          # forget the mode (the router's forwards are yours: remove them there)
porch setup --rollback       # undo the whole install
```

# Setup guides

Porch needs one thing from the internet: visitors must reach TCP 80, 443 and
7000 on your box. How that happens is the **connection mode**. Pick the row
that matches where your box lives, then follow its guide.

Not sure? On the box, run:

```bash
porch connect --status
```

It reads your network (router, public IP, carrier-grade NAT, IPv6) and marks
every mode *works*, *likely* or *unavailable*, with a recommendation. It
changes nothing.

## Which guide

| Your box | Mode | Guide |
|---|---|---|
| A VPS or any machine with its own public IPv4 | `direct` | [Fresh VPS](fresh-vps.md) |
| At home, and you can log in to your router | `manual` | [Home + port forward](home-port-forward.md) |
| At home, router has UPnP / NAT-PMP turned on | `upnp` | [Home + automatic router setup](home-upnp.md) |
| At home behind CGNAT, a locked router, or a landlord's network | `paid` | [Home + paid relay](home-paid-relay.md) |
| Same, and you already have a server somewhere | `byo` | [Home + your own server](home-byo-relay.md) |
| Same, and you want it free (experimental) | `oracle` | [Home + Oracle Always Free](home-oracle-relay.md) |
| A box that already runs HAProxy, frps and certificates | adopt | [Adopting an existing server](adopt-existing.md) |

## Cost and comparison

Prices are monthly, from the providers' APIs in October 2026, in USD. Every
mode also needs a domain (about $10-15 a year at most registrars).

| Mode | Monthly cost | Transfer included | What you need | Speed limit | Status |
|---|---|---|---|---|---|
| `direct` (VPS) | $6 (DigitalOcean `s-1vcpu-1gb`) | 1 TB | a VPS, a domain | the VPS's | Tested end to end on fresh Ubuntu 24.04 and Debian 13 droplets |
| `manual` | $0 | your ISP's | router admin access | your upload | In daily use on the author's home box |
| `upnp` | $0 | your ISP's | UPnP or NAT-PMP/PCP on the router | your upload | Tested against a simulated router (miniupnpd); not yet on real routers |
| `paid` on DigitalOcean | $4 (`s-1vcpu-512mb-10gb`) | 500 GB | a DO API token | your upload | Relay created, connected and deleted on DigitalOcean; HTTPS checks via the shared relay path ([details](home-paid-relay.md#test-status)) |
| `paid` on Vultr | $5 (`vc2-1c-1gb`, 31 regions) | 1 TB | a Vultr API token | your upload | Not yet passed: the test key was refused by Vultr's IP access list ([details](home-paid-relay.md#test-status)) |
| `byo` | what you already pay | your server's | ssh + passwordless sudo on a server with a public IPv4 | your upload | Tested end to end on a plain droplet ([details](home-byo-relay.md#test-status)) |
| `oracle` | $0 (Always Free) | 10 TB | an Oracle Cloud account | ~50 Mbps on the AMD micro shape | **Experimental.** Oracle's firewall tested on a simulated image (13/13 checks); not yet on a real Oracle VM |

Notes:

- Vultr's cheapest plan ($2.50, `vc2-1c-0.5gb`) is IPv6-only in most regions,
  and a relay needs IPv4, so porch never picks it.
- DigitalOcean's next size up (`s-1vcpu-1gb`, $6, 1 TB) is the one to choose
  for a relay that moves a lot of video: `--relay-size s-1vcpu-1gb`.
- A relay forwards raw TCP only. TLS still terminates at your box, so the
  relay never holds your certificate's key and cannot read your traffic.
- "Your upload" matters for home modes: visitors download at most as fast as
  your home connection uploads.

## What every path has in common

1. **Install** Porch (the one-line installer on a fresh server, or a clone).
2. **Run setup**, in the browser (`porch setup --web`) or the terminal
   (`porch setup`). It asks for your domain, the connection mode, your DNS
   provider and an admin password, then does the rest: firewall, HAProxy, frps,
   DNS records, a Let's Encrypt certificate, services, the landing page.
3. **Verify** with the phone check: setup shows a QR code; open it on your
   phone **with Wi-Fi off**. "It works." means the internet reaches you.
4. **Check later** with `porch doctor` (read-only) and `porch connect --status`.
5. **Undo** with `porch connect --off` (just the connection) or
   `porch setup --rollback` (everything, newest first).

Switching modes later is one command (`porch connect <mode>`); it prints the
follow-up steps, if any (for a relay: re-run the haproxy step; when the public
address changed: update DNS).

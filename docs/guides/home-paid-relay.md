# Home + paid relay (DigitalOcean / Vultr)

**For:** a home box that the internet cannot reach directly: carrier-grade NAT
(common on mobile, fibre and satellite ISPs), a router you cannot configure, a
dorm or landlord network. Porch rents the smallest server it can find, makes
it a relay, and points your DNS at it.

**Cost (October 2026):**

| Provider | Plan porch picks | Monthly | Transfer |
|---|---|---|---|
| DigitalOcean | `s-1vcpu-512mb-10gb` | $4 | 500 GB |
| DigitalOcean (`--relay-size s-1vcpu-1gb`) | `s-1vcpu-1gb` | $6 | 1 TB |
| Vultr | `vc2-1c-1gb` (31 regions) | $5 | 1 TB |

The price comes from the provider's API and is shown before anything is
created, behind a confirmation. Vultr's $2.50 plan is IPv6-only and is never
used: visitors need IPv4.

## How it works

The relay runs **only frps** (frp 0.67.0, sha256-pinned) as
`porch-relay-frps.service`, with its own random token, and forwards raw TCP
80, 443 and 7000 to your box over an outbound connection your box opens
(the `porch-relay` user unit, frpc). TLS terminates **at home**: the relay
never sees your certificate's key or your traffic in the clear. HAProxy at
home receives the visitor's real address over the PROXY protocol, so logs and
per-IP limits see real clients. The relay's firewall allows ssh only from your
home's public address, plus 80, 443, 7000 and the relay's control port.

## Test status

- **DigitalOcean:** `bin/porch-e2e relay-test` (a home droplet that accepts
  inbound ssh only, then `porch setup --connection paid`) created the relay,
  connected it (`relay proxies: http=running, https=running, frp=running`,
  port 7000 open on the relay, home ports closed) and porch's rollback deleted
  it, in two runs in October 2026 (about 8 minutes, under a cent each). In
  both, Let's Encrypt stopped the certificate step (once "service busy", once
  its weekly limit on the test domain), so the HTTPS checks did not run there.
  The same relay path (frps on the relay, PROXY protocol to home HAProxy)
  passed all 13 outside checks in the byo and oracle runs.
- **Vultr:** not yet passed end to end. The provider client is unit-tested
  and `porch-e2e relay-test --relay-provider vultr` exists, but the test key
  was refused (HTTP 401) from the throwaway home server while it works from
  the author's own address: Vultr keys carry an IP **Access Control** list.
  Porch now says so when it happens, quoting Vultr's reason ("Unauthorized
  IP address: ..."). Under Account > API, allow your home's addresses, or
  turn on both **Any IPv4** and **Any IPv6**: a box with IPv6 calls the API
  over IPv6, so allowing IPv4 alone is not enough.

## You need

- A home Linux box with Porch installed (see the
  [manual guide](home-port-forward.md#1-install)) and a domain.
- An API token:
  - **DigitalOcean:** API > Tokens > Generate, with **write** scope.
  - **Vultr:** Account > API > enable the API and copy the key. If you
    restrict API access by IP, allow your home's public address.
- Store it as a ref, never on the command line:

  ```bash
  install -d -m 700 ~/.config/porch/secrets
  (umask 077; cat > ~/.config/porch/secrets/relay-token)   # paste, Enter, Ctrl-D
  ```

  (`inf://...` and `op://...` refs work too, or `PORCH_RELAY_TOKEN` in the
  environment.)

## Steps

During setup, choose **Relay on a small paid VPS** (`--connection paid`), or on
an installed box:

```bash
porch connect paid --provider digitalocean \
  --token-ref file://~/.config/porch/secrets/relay-token --yes
porch connect paid --provider vultr --region ewr \
  --token-ref file://~/.config/porch/secrets/relay-token --yes
```

Setup flags: `--relay-provider digitalocean|vultr`, `--relay-token-ref`,
`--relay-region` (e.g. `nyc3` / `ewr`), `--relay-size`, `--relay-tag` (an extra
tag; porch always adds `porch-relay`), `--relay-ssh-key` (its `.pub` goes on
the relay's root account, for you to ssh in).

Porch creates the server with the relay installer as user data, waits for it
to come up, writes `config/relay-frpc.toml` (0600) and starts `porch-relay`.
When switching an installed box to a relay, it prints the follow-ups:

```bash
porch setup --only haproxy                      # adds the relay's PROXY-protocol binds
porch setup --only dns_records --dns-ipv4 <relay ip>
```

DigitalOcean emails a root password for the new server (porch registers no
key there unless you pass `--relay-ssh-key`); you never need it.

## Verify

```bash
porch connect --status          # active: paid, relay <ip>, relay proxies: http=running, https=running, frp=running
porch doctor
```

Then the phone check (QR code, Wi-Fi off), or open any door from your phone.

## Troubleshooting

| Symptom | Fix |
|---|---|
| "refused: the localhost bypass is on" | An adopted older install. Turn the bypass off first (see [Adopting](adopt-existing.md#the-localhost-bypass)). |
| Token rejected | DigitalOcean needs write scope; Vultr needs the API enabled (and your IP allowed if you use its access list). |
| Size not offered in the region | Pick another `--relay-region`, or leave it blank for the provider's default. |
| `relay proxies: ... stopped` | `systemctl --user status porch-relay`; the relay may still be booting (a minute or two). |
| Setup failed after the server was created | `porch connect --off` deletes it (by its recorded id, only while it carries the porch-relay tag). |

## Undo

```bash
porch connect --off --yes       # deletes the relay server and the home unit; prints what it deletes
```

Porch deletes exactly the server it created (by id, and only while it still
carries the `porch-relay` tag). Afterwards, check the provider's console: no
`porch-relay-*` server should remain.

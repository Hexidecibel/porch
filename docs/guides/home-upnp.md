# Home + automatic router setup (`upnp`)

**For:** a home box behind a router that has UPnP (IGD) or NAT-PMP / PCP
turned on. Porch asks the router to forward the ports itself: nothing to click.

**Cost:** $0 beyond the domain.

**Status:** tested against a simulated home router: miniupnpd (UPnP IGD v2 +
NAT-PMP/PCP) in an isolated network namespace, driven by the real
`porch connect` commands (`bin/porch-fake-router test`, see
[CONTRIBUTING](../../CONTRIBUTING.md#testing-connection-modes)). Map, refresh,
undo, an existing forward to this box kept, a forward to another machine
refused, and the NAT-PMP fallback all pass. Not yet confirmed on a range of
real consumer routers; if yours misbehaves, use the
[manual guide](home-port-forward.md) and please report it.

## You need

- A home Linux box with passwordless sudo, and a domain (as in the
  [manual guide](home-port-forward.md#you-need)).
- UPnP or NAT-PMP/PCP enabled in the router (often "UPnP" under advanced /
  WAN / NAT settings). Some routers also need "allow UPnP to change port
  mappings".
- A public IPv4 on the router's WAN side (no CGNAT).

## Steps

1. Install as in the [manual guide](home-port-forward.md#1-install), and give
   the box a DHCP reservation.
2. See what Porch finds:

   ```bash
   porch connect --status
   ```

   You want `UPnP IGD: <router name>` or `NAT-PMP: yes`, the router's WAN
   address, `CGNAT / double NAT: no`, and `upnp` marked *works* or *likely*.

3. Run setup with **Automatic port mapping (UPnP / NAT-PMP)**:

   ```bash
   bin/porch setup                                  # choose it when asked
   bin/porch setup --connection upnp --yes ...      # unattended
   porch connect upnp --yes                         # on an installed box, switch to it
   ```

   Porch maps TCP 80, 443 and 7000 on the router to the box's LAN IP, with
   7-day leases (permanent on old IGDv1 routers that only take those). Every
   mapping is recorded before it is made, so undo removes exactly what porch
   added.

## What porch does with mappings that already exist

Porch looks at all three ports before it maps any:

- A port that already forwards **to this box** (say, a forward you made
  yourself, or another app's) is **reused and left alone**: porch does not
  take it over, and undo does not delete it.
- A port that forwards **to another machine** stops the step before anything
  changes, naming that machine: move or remove that forward, then run
  `porch connect upnp` again.
- Static forwards made in the router's web page are often invisible to UPnP.
  A router that reports them answers "conflict" and porch stops; one that
  hides them may accept the mapping on top. If you already forward the ports
  by hand, you do not need this mode: use `manual`.

On NAT-PMP / PCP routers there is no way to ask what is already mapped; porch
maps the ports and stops if the router hands back a different external port.

## Verify

- `porch connect --status` shows `active: upnp ... ddns=on`.
- The phone check at the end of setup (QR code, open it on your phone with
  Wi-Fi off).
- `porch doctor` checks that the router still forwards each port to this box.

## Keep it running

Leases last 7 days. Renew them (no question asked, it renews what you already
approved):

```bash
porch connect upnp --refresh
```

Put it in a weekly timer or cron job. A router reboot can drop mappings;
`porch doctor` notices, and `--refresh` puts them back.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `upnp` is *unavailable*: "router answers neither UPnP nor NAT-PMP/PCP" | Turn UPnP on in the router, or use `manual`. |
| "router refused: allow UPnP port mapping changes" | The router's UPnP is read-only; enable changes in its settings. |
| `connect.upnp.conflict` | Another machine owns that port on the router; move it, or use other ports via `manual`. |
| The phone check fails although mappings exist | CGNAT or a second router upstream; `porch connect --status` says which. Use a relay. |
| A step failed half-way | `porch connect --off` undoes whatever the failed attempt mapped. |

## Undo

```bash
porch connect --off --yes      # deletes porch's mappings (only those still pointing at this box)
porch setup --rollback         # the whole install
```

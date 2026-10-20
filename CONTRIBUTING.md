# Contributing to Porch

Thanks for helping. Porch is a small, self-hosted stack: frp for the tunnels,
HAProxy in front, and a set of stdlib Python servers behind it. This page says
how to run the tests, what the code expects of a change, and where things live.

## Running the tests

```bash
bin/test                    # the whole suite (stdlib unittest, a few minutes)
bin/test -k seal            # only tests whose names match
cd tests && PORCH_CONFIG=none python3 -m unittest test_porch_seal   # one module
```

- `bin/test` unsets every `PORCH_*` variable and sets `PORCH_CONFIG=none`, so
  the suite runs on the built-in domain defaults and never reads a live
  `config/porch.toml`. Do the same when you run a module by hand.
- Launch recipes go to a throwaway `PORCH_DOORS_DIR`; servers bind loopback on
  free ports; everything else lives in temp dirs. No test needs the network.
- Only Python 3.10+ is required. Tests that need an optional tool skip when it
  is missing: `python3-cryptography` (E2E shares, passkeys, Web Push),
  `python3-qrcode`, `openssl`, `node` (the browser-side crypto and QR code),
  `ffmpeg`/`ffprobe` (media posters, light copies, waveforms), `dash` (the
  POSIX installers), `haproxy` (config validation, and a throwaway instance on a
  loopback port that checks the edge gate; never the system one), `git`, and the frp
  binaries in `bin/`.
- Tests must never touch a real router, DNS provider or cloud API: setup
  steps run through `FakeRunner` and fake HTTP clients. Never run a real
  `porch connect` mode from a test.
- Timing-sensitive tests (the door proxy, SSE streams) can flake on a loaded
  machine; re-run the single module before chasing a failure.

## Testing connection modes

Two opt-in harnesses exercise `porch connect` for real, outside `bin/test`.

**A fake home router** (`bin/porch-fake-router`, needs `sudo -n`, the
`miniupnpd-nftables` and `miniupnpc` packages; mask the packaged service
first with `sudo systemctl mask miniupnpd` so it never runs on your LAN):

```bash
bin/porch-fake-router test        # build, run every scenario, tear down (about 45s)
bin/porch-fake-router up          # or by hand: up, then
bin/porch-fake-router exec bin/porch connect --status
bin/porch-fake-router status      # miniupnpd's current mappings
bin/porch-fake-router down
```

It builds two network namespaces joined by one veth pair and nothing else:
porch runs in `porchfr-lan`, miniupnpd (UPnP IGD v2 + NAT-PMP/PCP) in
`porchfr-rtr` with a dummy WAN interface and a fake IP echo service
(`PORCH_IP_ECHO`). Before porch runs it checks each namespace's interfaces and
that the host's gateway is only reachable through the fake router (which has
no route on), so SSDP, NAT-PMP and PCP cannot reach your real router. porch
runs as you, with `PORCH_CONFIG=none` and a throwaway `PORCH_SETUP_DIR`.
Scenarios: detection; UPnP map / refresh / off; a mapping to this box made by
someone else is kept; a mapping to another machine stops the step before
anything is mapped; the NAT-PMP fallback with UPnP off.

**Real relays on throwaway cloud servers** (`bin/porch-e2e relay-test`, a
DigitalOcean token and a Cloudflare-hosted test domain; see the module
docstring in `lib/porch_e2e.py`):

```bash
bin/porch-e2e relay-test --domain example.com --dns-provider cloudflare                 # paid, DigitalOcean
bin/porch-e2e relay-test --domain example.com --dns-provider cloudflare --relay-provider vultr
bin/porch-e2e relay-test --domain example.com --dns-provider cloudflare --mode byo       # a plain droplet as "your server"
bin/porch-e2e relay-test --domain example.com --dns-provider cloudflare --oracle-sim    # byo + Oracle's iptables REJECT image
```

Each creates a home droplet that accepts inbound ssh only, runs the
non-interactive setup with that connection mode, checks DNS, trusted HTTPS,
a tunnel, the real client address and the closed home ports from outside, then
rolls back and deletes everything tagged `porch-e2e` (`--keep` leaves it up;
`bin/porch-e2e down --yes` cleans up). Costs are cents per run.

## Code conventions

- **Stdlib first.** Python servers use the standard library only.
  `python3-cryptography` is the one optional dependency and is imported
  lazily, so everything that doesn't need it still works without it. Shared
  HTTP plumbing lives in `lib/porch_http.py`; reuse it rather than writing a
  new server loop.
- **Loopback only.** Every server binds `127.0.0.1` by default; frp and
  HAProxy are the only way in. A new server must not add a public listener.
- **Fail closed.** No device registry, an invalid config, a malformed request:
  refuse, never fall back to "everyone is the owner" or a guessed domain.
  Hosts come from `lib/porch_config.py` (`config/porch.toml` + `PORCH_*` env),
  never from literals.
- **The design system.** Every page links `lib/porch.css` (tokens, per-app
  accents, `p-` components) through `porch_http.serve_asset`; don't inline
  styles or add another stylesheet.
- **Strict CSP.** Per-response nonces, no `'unsafe-inline'`, no `style=""`
  attributes, no `innerHTML`, no `alert()`. Untrusted strings reach the DOM
  only through `textContent`; errors are `p-notice` banners.
- **No secrets in argv or logs.** Passwords come from the environment or a
  prompt; setup stores refs (`inf://`, `op://`, `file://`), not values;
  received secrets are written 0600 by atomic rename into a 0700 run dir.
- **Scripts first.** Every operational task (deploy, cert renewal, HAProxy
  changes, migrations) is a script in `bin/`. If one is missing, add the
  script rather than documenting a one-off command, and fix the script when
  it breaks.
- Add or update tests with every change, and update the docs that describe
  what you changed (`README.md`, `docs/`).

## Cutting a release

Releases are GitHub releases of `Hexidecibel/porch`. The public repo is
generated, not edited: `bin/release` exports the private tree's HEAD with
`bin/public-export` (exclude list + leak scan), builds `porch.tar.gz` and
`porch.tar.gz.sha256` from that export, replaces the public `main` with the
export's single commit (a force-push) and uploads the two files with
`gh release create`. `site/porch.sh` installs
`releases/latest/download/porch.tar.gz`, so a new release is live for new
installs at once.

```bash
git status                       # commit first: only HEAD is released
bin/release --dry-run            # export + tarball locally, print the git/gh commands
bin/release --yes                # v0.1.0, then patch bumps; or --version v0.2.0
```

Needs `gh auth login` with push rights. Check the tarball with
`tar -tzf ~/.local/share/porch/release/<version>/porch.tar.gz` and try it on a
throwaway VM with `PORCH_TARBALL=file:///path/porch.tar.gz sudo -E sh site/porch.sh`.

## Layout at a glance

```
bin/            launchers and operator scripts
  tunnel, serve, view, seal, paste, exchange, drop, photos, media, music,
  hook, secure-entry, chat, pocket       one door per tool (all take --bg
                                         and the door flags: --expires,
                                         --password, --guest-link, --burn ...)
  porch                                  the CLI: setup, doctor, share, door,
                                         inspect, connect, cert, dns, mcp ...
  status, start-server, stop-server      run and inspect the stack
  auth-admin, bootstrap                  devices, pairing, invites
  deploy, publish-tarball                landing page, installers, tarball
  public-export, release                 the public repo and GitHub releases
  haproxy-apply, haproxy-porch           validated HAProxy installs
  inject, stash, cush-init, cush-audit   secrets tooling
  test                                   the test suite
lib/
  porch_http.py, porch_auth.py, porch_config.py   shared HTTP core, the owner
                                         check, the domain config
  porch.css, vendor/                     design system, vendored JS and fonts
  *server.py                             one server per tool (media, music,
                                         drop, paste, view, seal, pocket,
                                         status, auth, ...)
  doorproxy.py, door_*.py, inspect_store.py   the door proxy (rules, opens,
                                         inspector) and its state
  pocket*.py, pocket_static/             the Porch app (owner control center)
  porch_seal.py, seal.js                 end-to-end encrypted shares
  porch_webauthn.py, porch_push.py       passkeys, Web Push
  porch_setup/                           the setup engine: steps, DNS
                                         providers, connection modes, wizard
config/         examples and templates (real configs are gitignored)
site/           landing page, closed-door page, installers
docs/           tool reference, app guide and API, formats, design notes
tests/          stdlib unittest suite
```

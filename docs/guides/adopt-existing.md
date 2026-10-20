# Adopting an existing server

**For:** a box that already runs HAProxy, frps, certificates and the Porch
services, set up by hand or by an older cush-tools install. Adopt mode makes
`porch setup` and `porch doctor` **verify** that box instead of rewriting it.

**Cost:** none. **Status:** this is how the author's own home box runs.

## What adopt does (and does not)

- `porch setup --adopt` runs every step's inputs and **verify** only. A
  passing step is marked *adopted*; a failing one is reported with a hint;
  the run continues so you see everything.
- The **haproxy**, **frps** and **services** steps never apply on an adopted
  install, even without `--adopt` on the command line, once
  `install.mode = "adopt"` is in `config/porch.toml`. Your hand-made configs
  stay yours.
- Steps that are safe to run (DNS records, the admin password, the landing
  page) can still be applied one at a time with `porch setup --only <step>`.

## Steps

1. **Put the code in place** (a clone, or the existing checkout) and write
   `config/porch.toml` with your domain layout:

   ```toml
   [install]
   mode = "adopt"

   [domain]
   root = "example.com"
   # tunnel_base = "tunnel.example.com"   # every host can be spelled out
   ```

   `python3 lib/porch_config.py check` validates it; `... dump` shows the
   resolved hosts.

2. **Dry run, with a throwaway state dir** so nothing is recorded yet:

   ```bash
   PORCH_SETUP_DIR=$(mktemp -d) bin/porch setup --adopt --dry-run \
     --non-interactive --domain example.com --apex --connection manual \
     --dns-provider cloudflare --dns-token-ref inf://prod/porch/CLOUDFLARE_TOKEN
   ```

   Pick the `--connection` that describes how the box is reached today
   (usually `manual` or `direct`).

3. **Compare HAProxy** with what Porch would render:

   ```bash
   bin/porch render haproxy --against /etc/haproxy/haproxy.cfg
   ```

   It reads the live file (`sudo -n cat`, read-only) and reports, per
   section, directives that are missing, different or out of order. Accept
   intentional differences in `config/porch.toml`:

   ```toml
   [adopt]
   allow = ["frontend www-https: http-response set-header Strict-Transport-Security"]
   ```

4. **Adopt for real** (drop the dry-run flags): `bin/porch setup --adopt ...`,
   then `porch doctor` any time.

## The localhost bypass

Older installs let a tunnel client on the box itself log in to frps without a
device token (the *localhost bypass*). That is unsafe once a relay forwards
remote clients in through localhost, so relay modes refuse to run while it is
on, and fresh installs leave it off. Adopted installs default to on, until you
switch over:

1. `sudo systemctl restart cush-auth` (or `porch-auth`): the auth server mints
   `data/.home-frpc-token` and registers a `home` device. `bin/auth-admin
   list` shows it.
2. Relaunch every running tunnel (`porch status`, then close and relaunch, or
   Revive from the panel) so its config carries the token.
3. Set `[adopt] localhost_bypass = false` in `config/porch.toml` and restart
   the auth server; its log says `bypass: off`.
4. Check: `porch tunnel 8000 r0check --bg` connects; `porch status close
   r0check`.

To go back, set it to `true` and restart.

## Troubleshooting

| Symptom | Fix |
|---|---|
| A step fails verify | Its hint says what differs; fix the box (or allowlist an intentional HAProxy delta) and re-run `--adopt`. |
| `porch render --against` reports many "out of order" lines | `use_backend` order matters (first match wins); reorder the live config, or allowlist. |
| Relay modes refused | Turn the localhost bypass off (above). |

## Undo

Adopting writes only porch's state file (`data/porch-setup.json`) and log.
Delete them to forget the adoption; `porch setup --rollback` leaves adopted
steps alone.

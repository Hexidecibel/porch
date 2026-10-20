# Home + your own server (`byo`)

**For:** a home box the internet cannot reach directly (CGNAT, a locked
router) when you already have a server with a public IPv4 somewhere: a VPS,
a box at a friend's, a work machine you are allowed to use.

**Cost:** nothing extra. The relay is one small process (frps); bandwidth
counts against that server's transfer allowance.

## Test status

Tested end to end (October 2026) with `bin/porch-e2e relay-test --mode byo`:
a plain DigitalOcean droplet as "your server" (root ssh, ufw off), a home
droplet that accepts inbound ssh only, then `porch setup --connection byo`
(14/14 steps). From outside: DNS at the relay, trusted HTTPS on the auth,
landing, panel and tunnel hosts, a tunnel opened at home, the auth server
logging the real client address, the home ports closed. After rollback the
server held nothing of porch's (no `/etc/porch-relay`, service gone, no
firewall rules). About 7 minutes and under a cent per run.

## You need

- Porch installed on the home box (see the
  [manual guide](home-port-forward.md#1-install)) and a domain.
- A server with a **public IPv4**, reachable over ssh from the home box, with
  **passwordless sudo** for the ssh user (`sudo -n true` must work), running
  systemd (Ubuntu / Debian are tested).
- Nothing on that server already using tcp 80, 443, 7000 or 7835.
- An ssh key on the home box (the user that runs Porch) that the server
  accepts:

  ```bash
  ssh-keygen -t ed25519 -f ~/.ssh/porch-relay -N ''
  ssh-copy-id -i ~/.ssh/porch-relay.pub you@relay.example.net
  ssh -i ~/.ssh/porch-relay you@relay.example.net sudo -n true && echo ok
  ```

## Steps

During setup choose **Relay on your own server over SSH**, or:

```bash
bin/porch setup --connection byo --relay-host you@relay.example.net \
  --relay-ssh-key ~/.ssh/porch-relay
porch connect byo you@relay.example.net --ssh-key ~/.ssh/porch-relay --yes   # an installed box
```

Porch sends its installer over ssh's **stdin** (the relay token never
appears in a process list) and runs it with `sudo -n`. On the server it:

- downloads frp 0.67.0 (sha256-checked) and installs only `frps` as
  `porch-relay-frps.service`, with its own random token;
- opens tcp 80, 443, 7000 and 7835: in ufw when ufw is active, else as
  iptables ACCEPT rules when the firewall rejects by default (as on Oracle's
  images, saved with netfilter-persistent when present);
- never touches ssh or anything else, and records each change in
  `/etc/porch-relay/installed`.

At home it writes `config/relay-frpc.toml` (0600) and starts the
`porch-relay` user unit. When switching an installed box, run the printed
follow-ups (`porch setup --only haproxy`, then `porch setup --only dns_records
--dns-ipv4 <server ip>`).

If the server has a cloud firewall in front (AWS security groups,
DigitalOcean cloud firewalls, Oracle security lists), open the same four ports
there yourself.

## Verify

```bash
porch connect --status    # active: byo, relay <ip>, relay proxies: http=running, https=running, frp=running
porch doctor
```

Then the phone check (Wi-Fi off), or any door from your phone.

## Troubleshooting

| Symptom | Fix |
|---|---|
| "passwordless sudo is needed there" | Add `you ALL=(ALL) NOPASSWD:ALL` (or narrower) on the server; `sudo -n true` must succeed. |
| ssh fails | Test the exact command: `ssh -i <key> you@host sudo -n true`. Porch uses BatchMode (no prompts) and accepts a new host key once. |
| Install failed | Read `/var/log/porch-relay-install.log` on the server. |
| Proxies stay stopped | The server's cloud firewall blocks 7835: open it. |
| "refused: the localhost bypass is on" | See [Adopting](adopt-existing.md#the-localhost-bypass). |

## Undo

```bash
porch connect --off --yes
```

Porch runs its uninstaller over ssh: it removes exactly what the install
recorded (the service, the binaries, the firewall rules it added, re-saving
netfilter-persistent) and **never deletes or reconfigures the server itself**.

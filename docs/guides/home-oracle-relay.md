# Home + Oracle Always Free (`oracle`) — EXPERIMENTAL

**For:** a home box behind CGNAT or a locked router, when you want the relay
to cost nothing. Oracle Cloud's Always Free tier includes small VMs and 10 TB
of outbound transfer a month.

**Cost:** $0.

> **Experimental.** It works the same way as [byo](home-byo-relay.md) (porch
> installs the relay over ssh), but Oracle itself is the risky part:
>
> - **Sign-up is often rejected** (card checks, region capacity), sometimes
>   with no reason given. Try another home region or card, or use a
>   [paid relay](home-paid-relay.md).
> - **Idle Always Free VMs get reclaimed.** Oracle stops instances it deems
>   idle (low CPU, network and memory over a week). A relay is mostly idle.
>   **Upgrade the account to Pay As You Go**: it is still $0 for Always Free
>   resources, and reclamation does not apply.
> - **Use the AMD micro shape, `VM.Standard.E2.1.Micro`.** The Ampere A1
>   (ARM) shapes are scarce ("out of capacity") and Oracle cut the A1 free
>   allowance in 2026. The micro shape (1/8 OCPU, 1 GB) is plenty for frps.
> - **Throughput is about 50 Mbps** on the micro shape. Fine for pages,
>   files and photos; slow for video to many people at once.

## Test status

The firewall path is tested end to end with `bin/porch-e2e relay-test
--oracle-sim`: a DigitalOcean droplet given Oracle's image firewall (iptables
REJECT everything but ssh, saved by netfilter-persistent, ufw off), then
`porch setup --connection oracle`. All 13 outside checks passed (trusted HTTPS
through the relay, a tunnel, the real client address, ports 7000/7835 open
through the REJECT rules), and rollback removed porch's rules while keeping
Oracle's. **Not yet run on a real Oracle Cloud VM**: the security list (step
3), sign-up and reclamation are Oracle-side and untested.

## You need

- Porch installed on the home box (see the
  [manual guide](home-port-forward.md#1-install)) and a domain.
- An Oracle Cloud account (cloud.oracle.com), ideally upgraded to Pay As You Go.

## Steps

`porch connect oracle` with no server prints this guide too.

1. **Create the VM.** Compute > Instances > Create instance.
   Image: Canonical Ubuntu 24.04. Shape: **VM.Standard.E2.1.Micro**
   ("Always Free-eligible").
2. **Networking:** a public subnet with *Assign a public IPv4 address*. Paste
   the home box's ssh public key (`cat ~/.ssh/porch-relay.pub`; make one with
   `ssh-keygen -t ed25519 -f ~/.ssh/porch-relay -N ''`).
3. **Open the ports in Oracle's network.** Networking > Virtual cloud
   networks > (the VCN) > Security Lists > Default Security List > Add
   Ingress Rules: source `0.0.0.0/0`, TCP, destination ports
   `80,443,7000,7835`.
4. Note the instance's public IP. The user is `ubuntu` (passwordless sudo).
5. Install the relay:

   ```bash
   porch connect oracle ubuntu@<public ip> --ssh-key ~/.ssh/porch-relay --yes
   # or during setup:
   bin/porch setup --connection oracle --relay-host ubuntu@<public ip> --relay-ssh-key ~/.ssh/porch-relay
   ```

   Oracle's Ubuntu images also block everything but ssh **inside the VM**
   (iptables REJECT rules). Porch inserts ACCEPT rules for its four ports
   ahead of them and saves them with netfilter-persistent, so they survive a
   reboot.

6. When switching an installed box, run the printed follow-ups
   (`porch setup --only haproxy`, `porch setup --only dns_records --dns-ipv4
   <public ip>`).

## Verify

```bash
porch connect --status    # active: oracle, relay proxies: http=running, https=running, frp=running
```

Then the phone check (Wi-Fi off).

## Troubleshooting

| Symptom | Fix |
|---|---|
| "Out of capacity" creating the VM | Use the E2.1.Micro shape; try another availability domain. |
| ssh works but proxies stay stopped | Step 3 missing: the security list must allow 7835 (and 80, 443, 7000). |
| The relay stopped after a week or two | Oracle reclaimed an idle VM. Upgrade to Pay As You Go, recreate it, run step 5 again. |
| Slow downloads | The micro shape's ~50 Mbps cap; consider a [paid relay](home-paid-relay.md). |

## Undo

```bash
porch connect --off --yes
```

This removes what porch installed on the VM (service, binaries, the iptables
rules it added, re-saved) and leaves the VM. Terminate it in Oracle's console
if you no longer need it.

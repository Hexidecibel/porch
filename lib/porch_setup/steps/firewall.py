"""firewall: open tcp 80, 443 and 7000 on the host firewall (ufw / firewalld).

Relay modes need nothing open at home (the relay frpc dials out). Only the
rules porch adds are recorded and removed on rollback. With plain nftables
or iptables rules porch does not edit anything; it only says what to open.
"""

import re

from ..engine import Action, Check, Step
from . import _common as c

ORDER = 50


class Firewall(Step):
    id = "firewall"
    title = "Host firewall"
    requires = ("preflight",)

    def ports(self, ctx):
        return () if c.relay_mode(ctx) else c.PORCH_PORTS

    def detect(self, ctx):
        """("ufw"|"firewalld"|"none", active: bool, text)."""
        if ctx.run.which("ufw"):
            r = ctx.run.run(["ufw", "status"], sudo=True, mutating=False)
            if r.ok and "Status: active" in r.stdout:
                return "ufw", True, r.stdout
        if ctx.run.which("firewall-cmd"):
            r = ctx.run.run(["firewall-cmd", "--state"], sudo=True, mutating=False)
            if r.ok and r.stdout.strip() == "running":
                p = ctx.run.run(["firewall-cmd", "--list-ports"], sudo=True, mutating=False)
                return "firewalld", True, p.stdout
        return "none", False, ""

    @staticmethod
    def open_ports(kind, text):
        opened = set()
        if kind == "ufw":
            for line in text.splitlines():
                # "443/tcp   ALLOW   Anywhere", "80,443/tcp ALLOW ...", "Anywhere ALLOW 10.0.0.0/8" is not public
                m = re.match(r"^([\d,:]+)(?:/tcp)?\s+ALLOW(?: IN)?\s+Anywhere", line.strip())
                if not m:
                    continue
                for part in m.group(1).split(","):
                    if ":" in part:
                        lo, hi = part.split(":")
                        opened.update(range(int(lo), int(hi) + 1))
                    else:
                        opened.add(int(part))
        elif kind == "firewalld":
            for tok in text.split():
                m = re.match(r"^(\d+)(?:-(\d+))?/tcp$", tok)
                if m:
                    lo = int(m.group(1))
                    opened.update(range(lo, int(m.group(2) or lo) + 1))
        return opened

    def missing(self, ctx):
        kind, active, text = self.detect(ctx)
        if not active:
            return kind, []
        have = self.open_ports(kind, text)
        return kind, [p for p in self.ports(ctx) if p not in have]

    def plan(self, ctx):
        kind, miss = self.missing(ctx)
        return [Action("firewall.open", f"{p}/tcp", kind) for p in miss]

    def apply(self, ctx):
        kind, miss = self.missing(ctx)
        added = []
        for p in miss:
            ctx.record_undo("firewall.close", tool=kind, port=p)
            if kind == "ufw":
                ctx.run.run(["ufw", "allow", f"{p}/tcp", "comment", "porch"], sudo=True, check=True)
            else:
                ctx.run.run(["firewall-cmd", "--permanent", f"--add-port={p}/tcp"], sudo=True, check=True)
            added.append(p)
        if kind == "firewalld" and added:
            ctx.run.run(["firewall-cmd", "--reload"], sudo=True, check=True)
        return {"tool": kind, "added": added}

    def verify(self, ctx):
        kind, active, _ = self.detect(ctx)
        if not active:
            return [Check(True, "firewall.none",
                          "no active ufw/firewalld; if nftables or a cloud firewall filters "
                          "traffic, open tcp " + ", ".join(map(str, self.ports(ctx))))]
        _, miss = self.missing(ctx)
        if not self.ports(ctx):
            return [Check(True, "firewall.relay", "relay mode: no inbound ports needed")]
        return [Check(not miss, "firewall.ports",
                      f"{kind}: tcp {', '.join(map(str, self.ports(ctx)))} open" if not miss
                      else f"{kind}: tcp {', '.join(map(str, miss))} not open to Anywhere",
                      "porch setup --only firewall opens them" if miss else "")]

    def undo(self, ctx, entry):
        if entry["kind"] != "firewall.close":
            return super().undo(ctx, entry)
        p = entry["port"]
        if entry["tool"] == "ufw":
            ctx.run.run(["ufw", "delete", "allow", f"{p}/tcp"], sudo=True, check=True)
        else:
            ctx.run.run(["firewall-cmd", "--permanent", f"--remove-port={p}/tcp"], sudo=True, check=True)
            ctx.run.run(["firewall-cmd", "--reload"], sudo=True, check=True)


STEP = Firewall()

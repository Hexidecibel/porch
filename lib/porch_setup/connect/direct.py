"""direct: the host itself has a public IPv4 (a VPS, or a modem in bridge
mode). Nothing to forward; only the host firewall matters (firewall step)."""

from ..engine import Action, Check
from .base import LIKELY, UNAVAILABLE, WORKS, Mode, PORTS, ingress_v6


class DirectMode(Mode):
    name = "direct"
    title = "Direct (this machine has a public IP)"
    summary = "No router in the way: visitors reach this machine's own public address."
    order = 10

    def _ip(self, facts):
        host = facts.get("host_public_ipv4") or []
        pub = facts.get("public_ipv4")
        if pub and pub in host:
            return pub
        return host[0] if host else None

    def detect(self, ctx, facts):
        host = facts.get("host_public_ipv4") or []
        if not host:
            return UNAVAILABLE, "no public IPv4 address on any interface (this machine is behind a router)"
        pub = facts.get("public_ipv4")
        if pub and pub not in host:
            return LIKELY, (f"interface has {', '.join(host)} but the internet sees {pub}; "
                            "outbound traffic may leave another way")
        return WORKS, f"public IPv4 {self._ip(facts)} is on this machine"

    def steps(self, ctx, facts):
        return [f"Use {self._ip(facts)} for the DNS records.",
                "Open TCP " + ", ".join(map(str, PORTS)) + " in the host firewall (next step)."]

    def plan(self, ctx, facts):
        return [Action("connect.direct", str(self._ip(facts)), "no port forwarding needed")]

    def apply(self, ctx, facts):
        ip = self._ip(facts)
        return {"ingress_ipv4": ip, "ingress_ipv6": ingress_v6(facts), "ddns": False}

    def verify(self, ctx, facts, outputs):
        ip = outputs.get("ingress_ipv4")
        ok = bool(ip) and ip in (facts.get("host_public_ipv4") or [])
        return [Check(ok, "connect.direct.ip",
                      f"{ip} is on this machine" if ok else f"{ip} is no longer on any interface",
                      "" if ok else "re-run `porch connect --status`; the address changed")]


MODE = DirectMode()

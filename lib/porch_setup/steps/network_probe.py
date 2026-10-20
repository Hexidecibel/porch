"""network_probe (ORDER 30): read-only facts about how this box meets the
internet. Stored in state["facts"]["network"] (plus public_ipv4 / public_ipv6
shortcuts for later steps). Changes nothing, so rollback is a no-op."""

from ..engine import Action, Check, Step
from ..net import probe as _probe

ORDER = 30

# Overridable for tests: callable(ctx) -> facts dict.
PROBE = None


def run_probe(ctx):
    if PROBE is not None:
        return PROBE(ctx)
    return _probe.probe(http=ctx.http, log=lambda m: ctx.log(m, "debug"))


def ensure(ctx, refresh=False):
    """The stored network facts, probing (and storing) them when missing."""
    facts = ctx.facts.get("network")
    if facts and not refresh:
        return facts
    facts = run_probe(ctx)
    store(ctx, facts)
    return facts


def store(ctx, facts):
    ctx.facts["public_ipv4"] = facts.get("public_ipv4")
    v6 = facts.get("ipv6") or []
    ctx.facts["public_ipv6"] = v6[0] if v6 else None
    ctx.set_fact("network", facts)     # saves (a no-op in dry run)


class NetworkProbe(Step):
    id = "network_probe"
    title = "Network probe"

    def plan(self, ctx):
        return [Action("probe", "network", "LAN/gateway, public IP (2 echo services), UPnP, NAT-PMP, IPv6, router brand")]

    def apply(self, ctx):
        facts = ensure(ctx, refresh=True)
        for line in _probe.summary(facts):
            ctx.log(line)
        return {"public_ipv4": facts.get("public_ipv4"), "wan_ipv4": facts.get("wan_ipv4"),
                "lan_ipv4": facts.get("lan_ipv4"), "cgnat": facts.get("cgnat"),
                "router": (facts.get("router") or {}).get("brand")}

    def verify(self, ctx):
        f = ctx.facts.get("network") or {}
        checks = [Check(bool(f.get("gateway") and f.get("lan_ipv4")), "network.lan",
                        f"LAN {f.get('lan_ipv4')} via {f.get('gateway')}" if f.get("gateway")
                        else "no default route / LAN address found",
                        "" if f.get("gateway") else "is this machine online? check `ip route`")]
        pub_ok = bool(f.get("public_ipv4") or f.get("host_public_ipv4"))
        checks.append(Check(pub_ok, "network.public_ipv4",
                            f"public IPv4 {f.get('public_ipv4')}" if pub_ok
                            else f"public IPv4 unknown: {f.get('public_ipv4_error') or 'no answer'}",
                            "" if pub_ok else "outbound HTTPS to the IP echo services must work; retry later"))
        return checks

    def rollback(self, ctx, outputs):
        return None


STEP = NetworkProbe()

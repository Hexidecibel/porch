"""Helpers the DNS steps share: the resolver, the zone, the desired hosts and
a provider built from what dns_provider collected."""

from ..dnsq import DNSError, Resolver, norm
from .base import Provider, ProviderError, make_provider, provider_class


def resolver(ctx):
    """ctx.dns, or a default dnsq.Resolver installed on ctx."""
    if ctx.dns is None:
        ctx.dns = Resolver()
    return ctx.dns


def zone_info(ctx, root=None):
    """(zone apex, [ns names]) for the configured root, cached in facts."""
    root = norm(root or ctx.cfg.root)
    zone = ctx.facts.get("zone_apex")
    ns = ctx.facts.get("ns")
    if zone and (root == zone or root.endswith("." + zone)) and ns:
        return zone, list(ns)
    r = resolver(ctx)
    zone = r.zone_apex(root)
    ns = r.ns(zone)
    if not ns:
        raise DNSError(f"{zone} has no NS records")
    ctx.set_fact("zone_apex", zone)
    ctx.set_fact("ns", ns)
    return zone, ns


def desired_hosts(ctx, apex=None):
    """The names porch serves, from porch_config: auth, panel, landing,
    tunnel_base and *.tunnel_base (deduplicated, in that order), plus the
    zone apex only when the user opted in (dns_apex)."""
    cfg = ctx.cfg
    hosts = []
    for h in (cfg.auth_host, cfg.panel_host, cfg.landing_host, cfg.tunnel_base,
              "*." + cfg.tunnel_base):
        h = norm(h)
        if h not in hosts:
            hosts.append(h)
    if apex is None:
        apex = bool(ctx.input("dns_apex", False))
    if apex:
        z = ctx.facts.get("zone_apex") or norm(cfg.root)
        if z not in hosts:
            hosts.append(z)
    return hosts


def provider_name(ctx):
    return ctx.outputs("dns_provider").get("provider") or ctx.input("dns_provider")


def creds(ctx, name):
    cls = provider_class(name)
    need = () if cls is None else getattr(cls, "CREDENTIALS", ())
    out = {}
    if "token" in need:
        try:
            out["token"] = ctx.secret("dns_token")
        except KeyError:
            raise ProviderError("dns.auth", "no DNS API token collected",
                                "pass --dns-token-ref inf://...|op://...|file://... or set "
                                "PORCH_DNS_TOKEN, then re-run") from None
    if "username" in need:
        out["username"] = ctx.input("dns_username") or ""
    return out


def provider(ctx, name=None):
    name = name or provider_name(ctx)
    if not name:
        raise ProviderError("dns.unknown", "no DNS provider chosen yet",
                            "run `porch setup --only dns_provider` first")
    p = make_provider(ctx, name, creds(ctx, name))
    return p


def is_manual(p):
    return isinstance(p, Provider) and getattr(p, "MANUAL", False)

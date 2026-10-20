"""Name servers -> DNS provider.

    detect(["ns1dhq.name.com", ...]) -> Detection(provider="namecom", ...)

`provider` is a porch provider name when porch has an API client for it
(MVP: cloudflare, namecom), else "manual". `lexicon` names the dns-lexicon
provider for registrar name servers porch does not speak to itself (phase 3:
dns/lexicon.py), and `known` says whether the NS were recognized at all."""

from dataclasses import dataclass, field
from typing import List, Optional

from ..dnsq import norm

# (NS suffix or substring, provider name, human title). Substring matches are
# marked with a leading "~".
NS_TABLE = (
    (".ns.cloudflare.com", "cloudflare", "Cloudflare"),
    (".name.com", "namecom", "name.com"),
    ("~awsdns-", "route53", "Amazon Route 53"),
    (".digitalocean.com", "digitalocean", "DigitalOcean"),
    (".porkbun.com", "porkbun", "Porkbun"),
    (".hetzner.com", "hetzner", "Hetzner"),
    (".hetzner.de", "hetzner", "Hetzner"),
    (".gandi.net", "gandi", "Gandi"),
)

# Registrar / host NS -> dns-lexicon provider name.
LEXICON_TABLE = (
    (".domaincontrol.com", "godaddy", "GoDaddy"),
    (".registrar-servers.com", "namecheap", "Namecheap"),
    (".ovh.net", "ovh", "OVH"),
    (".ovh.ca", "ovh", "OVH"),
    (".linode.com", "linode4", "Linode"),
    (".vultr.com", "vultr", "Vultr"),
    (".dnsimple.com", "dnsimple", "DNSimple"),
    (".dnsmadeeasy.com", "dnsmadeeasy", "DNS Made Easy"),
    (".googledomains.com", "googleclouddns", "Google"),
    ("~.dns.google", "googleclouddns", "Google Cloud DNS"),
    (".azure-dns.com", "azure", "Azure DNS"),
    (".azure-dns.net", "azure", "Azure DNS"),
    (".inwx.de", "inwx", "INWX"),
    (".transip.nl", "transip", "TransIP"),
    (".hover.com", "hover", "Hover"),
    (".easydns.com", "easydns", "easyDNS"),
    (".gname.net", "gname", "Gname"),
    (".dynadot.com", "dynadot", "Dynadot"),
)


@dataclass
class Detection:
    provider: str                  # porch provider name, or "manual"
    title: str                     # who runs the NS ("name.com", "unknown")
    ns: List[str] = field(default_factory=list)
    known: bool = False
    lexicon: Optional[str] = None  # dns-lexicon provider when porch has no client
    supported: bool = False        # porch has an API client for `provider`


def _match(ns, pattern):
    if pattern.startswith("~"):
        return pattern[1:] in ns
    return ns.endswith(pattern) or ns == pattern.lstrip(".")


def _lookup(table, ns_list):
    for pattern, name, title in table:
        if ns_list and all(_match(n, pattern) for n in ns_list):
            return name, title
    for pattern, name, title in table:   # mixed NS sets: majority wins below
        if any(_match(n, pattern) for n in ns_list):
            return name, title
    return None


def detect(ns_list, available=None):
    """available: provider names porch can drive (default: the registry's)."""
    ns_list = [norm(n) for n in ns_list or [] if n]
    if available is None:
        from .. import registry
        available = set(registry.providers())
    hit = _lookup(NS_TABLE, ns_list)
    if hit:
        name, title = hit
        if name in available:
            return Detection(name, title, ns_list, known=True, supported=True)
        return Detection("manual", title, ns_list, known=True, lexicon=name, supported=False)
    lx = _lookup(LEXICON_TABLE, ns_list)
    if lx:
        return Detection("manual", lx[1], ns_list, known=True, lexicon=lx[0])
    return Detection("manual", "unknown", ns_list)

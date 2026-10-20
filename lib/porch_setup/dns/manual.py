"""Manual DNS: porch shows the records, the user adds them at their DNS host,
and porch polls until they resolve (authoritative NS first, then 1.1.1.1 and
8.8.8.8). The propagation helpers here are shared by every provider: the
dns_records step and the ACME hook use them too.

    table(records) -> str
    probe(resolver, rec, zone)          -> {"auth": {ip: ok}, "public": {ip: ok}}
    wait_for(resolver, records, zone, clock=, sleep=, timeout=600, ...) -> (ok, results)
"""

import ipaddress
import secrets as _secrets

from .base import Provider, ProviderError
from ..dnsq import DNSError, PUBLIC_RESOLVERS, norm


class Manual(Provider):
    name = "manual"
    title = "manual (you add the records)"
    CREDENTIALS = ()
    MANUAL = True

    def check(self, zone):
        return None

    def list(self, zone, name=None, rtype=None):
        return []

    def _refuse(self, *a, **k):
        raise ProviderError("dns.manual", "manual DNS: porch cannot change records itself",
                            "add the records shown at your DNS host, then re-run")

    create = update = delete = _refuse


PROVIDER = Manual


def table(records):
    rows = [("TYPE", "NAME", "VALUE", "TTL")]
    for r in records:
        rows.append((r.type, r.name, r.content, str(r.ttl)))
    w = [max(len(row[i]) for row in rows) for i in range(4)]
    return "\n".join("  " + "  ".join(c.ljust(w[i]) for i, c in enumerate(row)).rstrip()
                     for row in rows)


def query_name(name):
    """A concrete name to ask for: a wildcard is probed with a random label."""
    name = norm(name)
    if name.startswith("*."):
        return f"porch-check-{_secrets.token_hex(4)}.{name[2:]}"
    return name


def _norm_value(rtype, v):
    v = str(v).strip()
    if rtype in ("A", "AAAA"):
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            return v
    if rtype in ("CNAME", "NS"):
        return norm(v)
    return v


def matches(rec, values):
    """A/AAAA/CNAME: the answer set equals the record; TXT: the value is present
    (other TXT values may share the name, e.g. two ACME challenges)."""
    if values is None:
        return False
    got = {_norm_value(rec.type, v) for v in values}
    want = _norm_value(rec.type, rec.content)
    if rec.type == "TXT":
        return want in got
    return got == {want}


def probe(resolver, rec, zone, public=PUBLIC_RESOLVERS):
    qname = query_name(rec.name)
    out = {"auth": {}, "public": {}, "values": {}}
    try:
        auth = resolver.authoritative(qname, rec.type, zone=zone)
    except DNSError as e:
        auth = {}
        out["error"] = str(e)
    for ip, vals in auth.items():
        out["auth"][ip] = matches(rec, vals)
        out["values"][ip] = vals
    for srv in public or ():
        try:
            vals = resolver.resolve(qname, rec.type, server=srv)
        except DNSError:
            vals = None
        out["public"][srv] = matches(rec, vals)
        out["values"][srv] = vals
    return out


def probe_ok(p, need_public=True):
    if not p["auth"] or not all(p["auth"].values()):
        return False
    return all(p["public"].values()) if need_public else True


def wait_for(resolver, records, zone, *, clock, sleep, timeout=600, interval=10,
             public=PUBLIC_RESOLVERS, progress=None):
    """Poll until every record is live on all authoritative NS and (if
    `public`) the public resolvers. Returns (ok, {name type: probe})."""
    start = clock()
    pending = list(records)
    results = {}
    while True:
        still = []
        for r in pending:
            p = probe(resolver, r, zone, public=public)
            results[f"{r.name} {r.type}"] = p
            if not probe_ok(p, need_public=bool(public)):
                still.append(r)
        pending = still
        if not pending:
            return True, results
        waited = clock() - start
        if waited >= timeout:
            return False, results
        if progress:
            progress(f"waiting for DNS: {len(pending)} record(s) not live yet "
                     f"({int(waited)}s of {int(timeout)}s): "
                     + ", ".join(f"{r.type} {r.name}" for r in pending[:4]))
        sleep(min(interval, max(0.0, timeout - waited)) or interval)


def describe_failure(results):
    """Short text for the records that did not resolve."""
    bad = []
    for key, p in results.items():
        if probe_ok(p):
            continue
        a = [ip for ip, ok in p["auth"].items() if not ok]
        pub = [ip for ip, ok in p["public"].items() if not ok]
        why = []
        if not p["auth"]:
            why.append(p.get("error") or "no authoritative answer")
        if a:
            why.append("authoritative " + ",".join(a) + " says " +
                       ";".join(str(p["values"].get(ip)) for ip in a[:1]))
        if pub:
            why.append("not yet at " + ",".join(pub))
        bad.append(f"{key}: " + "; ".join(why))
    return bad

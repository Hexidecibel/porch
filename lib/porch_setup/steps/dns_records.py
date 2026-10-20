"""dns_records: point porch's names at this box's ingress.

Desired set (dns/zone.py desired_hosts): A (and AAAA when there is an IPv6
ingress) for auth_host, panel_host, landing_host, tunnel_base and
*.tunnel_base from porch_config, TTL 300, Cloudflare proxied=false. Fresh
installs put these under a dedicated base (porch.<domain>, chosen by the
domain step); the zone apex is touched only with --dns-apex. In adopt mode the
same names come straight from config/porch.toml.

A name with a different value is a conflict: porch asks before replacing it
and records the old value, so rollback restores it. A name already answered
by a matching wildcard in the zone is left alone. verify polls every
authoritative NS, then 1.1.1.1 and 8.8.8.8 (up to $PORCH_DNS_WAIT, 600 s).
"""

import ipaddress

from ..dnsq import DNSError
from ..dns import manual as _manual
from ..dns import zone as _zone
from ..dns.base import ProviderError, Record
from ..engine import Action, Check, Input, Step, StepError

ORDER = 70
TTL = 300


def _ip_default(ctx, key, fact):
    v = ctx.outputs("connection").get(key)
    if not v and fact:
        v = ctx.facts.get(fact)
    return v or None


def _valid_ip(version):
    def check(v):
        if v in (None, ""):
            return None
        try:
            ip = ipaddress.ip_address(str(v).strip())
        except ValueError:
            return f"not an IPv{version} address"
        if ip.version != version:
            return f"not an IPv{version} address"
        if not ip.is_global:
            return f"{ip} is not a public address"
        return None
    return check


APEX_INPUT = Input("dns_apex", "bool", "Also point the domain's apex (bare domain) at porch?",
                   default=False, flag="--dns-apex",
                   help="off by default: porch never touches the apex unless asked")
IPV4_INPUT = Input("dns_ipv4", "text", "Public IPv4 address the records point at",
                   default=lambda ctx: _ip_default(ctx, "ingress_ipv4", "public_ipv4"),
                   validate=_valid_ip(4), flag="--dns-ipv4", required=False,
                   help="default: the connection step's ingress (or the detected public IP)")
IPV6_INPUT = Input("dns_ipv6", "text", "Public IPv6 address for AAAA records (blank: none)",
                   default=lambda ctx: _ip_default(ctx, "ingress_ipv6", None),
                   validate=_valid_ip(6), flag="--dns-ipv6", required=False)


def targets(ctx):
    v4 = ctx.input("dns_ipv4") or _ip_default(ctx, "ingress_ipv4", "public_ipv4")
    v6 = ctx.input("dns_ipv6") or _ip_default(ctx, "ingress_ipv6", None)
    return (str(v4).strip() if v4 else None), (str(v6).strip() if v6 else None)


def desired_records(ctx):
    v4, v6 = targets(ctx)
    out = []
    for h in _zone.desired_hosts(ctx):
        if v4:
            out.append(Record(h, "A", v4, TTL))
        if v6:
            out.append(Record(h, "AAAA", v6, TTL))
    return out


def diff(desired, existing):
    """[(kind, desired Record, [existing Records])], kind in ok | covered |
    create | replace | cname."""
    by = {}
    for r in existing:
        by.setdefault((r.name, r.type), []).append(r)
    out = []
    for d in desired:
        same = by.get((d.name, d.type), [])
        cname = by.get((d.name, "CNAME"), [])
        if cname:
            out.append(("cname", d, cname))
        elif same:
            vals = {r.content.strip() for r in same}
            out.append(("ok" if vals == {d.content} else "replace", d, same))
        else:
            parent = d.name.split(".", 1)[1] if "." in d.name else ""
            wild = by.get(("*." + parent, d.type), []) if not d.name.startswith("*.") else []
            if wild and {r.content.strip() for r in wild} == {d.content}:
                out.append(("covered", d, wild))
            else:
                out.append(("create", d, []))
    return out


class DnsRecordsStep(Step):
    id = "dns_records"
    title = "DNS records"
    requires = ("dns_provider",)
    INPUTS = (APEX_INPUT, IPV4_INPUT, IPV6_INPUT)

    # ---- helpers --------------------------------------------------------------
    def _zone(self, ctx):
        return ctx.outputs("dns_provider").get("zone") or _zone.zone_info(ctx)[0]

    def _scope_checks(self, ctx, zone):
        checks = []
        apex = bool(ctx.input("dns_apex", False))
        for h in _zone.desired_hosts(ctx):
            bare = h[2:] if h.startswith("*.") else h
            if not (bare == zone or bare.endswith("." + zone)):
                checks.append(Check(False, "dns.zone", f"{h} is not inside the zone {zone}",
                                    "fix domain.* in config/porch.toml"))
            elif h == zone and not apex:
                checks.append(Check(False, "dns.apex",
                                    f"{h} is the zone apex, which porch leaves alone by default",
                                    "use a base like porch." + zone + " (porch setup --domain), "
                                    "or pass --dns-apex to let porch point the apex"))
        return checks

    def _provider(self, ctx):
        try:
            return _zone.provider(ctx)
        except ProviderError as e:
            raise StepError(e.code, e.message, e.hint) from None

    # ---- contract --------------------------------------------------------------
    def preflight(self, ctx):
        try:
            zone = self._zone(ctx)
        except DNSError as e:
            return [Check(False, "dns.zone", str(e), "run the dns_provider step first")]
        checks = self._scope_checks(ctx, zone)
        if checks:
            return checks
        v4, v6 = targets(ctx)
        if not v4 and not v6:
            return [Check(False, "dns.no_target", "no public IP to point the records at",
                          "pass --dns-ipv4 <public IP>, or run the connection step first")]
        return [Check(True, "dns.desired", f"{len(desired_records(ctx))} record(s) in {zone}")]

    def plan(self, ctx):
        zone = self._zone(ctx)
        desired = desired_records(ctx)
        p = self._provider(ctx)
        if _zone.is_manual(p):
            return [Action("dns.manual", f"{r.type} {r.name}", r.content) for r in desired]
        try:
            existing = p.list(zone)
        except ProviderError as e:
            return [Action("error", "dns.list", f"{e.code}: {e.message}")]
        acts = []
        for kind, d, ex in diff(desired, existing):
            tgt = f"{d.type} {d.name}"
            if kind == "ok":
                acts.append(Action("dns.keep", tgt, d.content))
            elif kind == "covered":
                acts.append(Action("dns.keep", tgt, f"{d.content} (via {ex[0].name})"))
            elif kind == "create":
                acts.append(Action("dns.create", tgt, f"{d.content} ttl {d.ttl}"))
            elif kind == "replace":
                acts.append(Action("dns.update", tgt, f"{', '.join(r.content for r in ex)} -> "
                                   f"{d.content} (asks first)"))
            else:
                acts.append(Action("dns.replace_cname", tgt, f"CNAME {ex[0].content} -> "
                                   f"{d.content} (asks first)"))
        return acts

    def apply(self, ctx):
        zone = self._zone(ctx)
        desired = desired_records(ctx)
        p = self._provider(ctx)
        out = {"zone": zone, "records": [r.as_dict() for r in desired], "created": [],
               "updated": [], "manual": False}
        if _zone.is_manual(p):
            out["manual"] = True
            ctx.log("add these records at your DNS host:\n" + _manual.table(desired))
            if ctx.io.interactive:
                ctx.confirm("Press enter once the records are added (porch then waits for them)",
                            default=True)
            return out
        try:
            existing = p.list(zone)
            for kind, d, ex in diff(desired, existing):
                if kind in ("ok", "covered"):
                    continue
                if kind == "create":
                    ctx.record_undo("dns.delete", zone=zone, name=d.name, type=d.type,
                                    content=d.content)
                    rid = p.create(zone, d)
                    out["created"].append({"id": rid, "name": d.name, "type": d.type})
                    continue
                old = ", ".join(f"{r.type} {r.content}" for r in ex)
                if not ctx.confirm(f"{d.name} already has {old}. Replace it with {d.type} "
                                   f"{d.content}?", default=False):
                    raise StepError("dns.conflict", f"{d.name} already points elsewhere ({old})",
                                    "re-run and answer yes (or --yes), or change the record "
                                    "yourself and re-run")
                if kind == "cname":
                    for r in ex:
                        ctx.record_undo("dns.recreate", zone=zone, name=r.name, type=r.type,
                                        content=r.content, ttl=r.ttl)
                        p.delete(zone, r.id)
                    ctx.record_undo("dns.delete", zone=zone, name=d.name, type=d.type,
                                    content=d.content)
                    rid = p.create(zone, d)
                    out["created"].append({"id": rid, "name": d.name, "type": d.type})
                    continue
                first, rest = ex[0], ex[1:]
                ctx.record_undo("dns.restore", zone=zone, id=first.id, name=first.name,
                                type=first.type, content=first.content, ttl=first.ttl,
                                new=d.content)
                p.update(zone, first.id, d)
                out["updated"].append({"id": first.id, "name": d.name, "type": d.type,
                                       "previous": first.content})
                for r in rest:
                    ctx.record_undo("dns.recreate", zone=zone, name=r.name, type=r.type,
                                    content=r.content, ttl=r.ttl)
                    p.delete(zone, r.id)
        except ProviderError as e:
            raise StepError(e.code, e.message, e.hint) from None
        return out

    def _wait(self, ctx):
        if ctx.adopt:
            return 0
        try:
            return float(ctx.env.get("PORCH_DNS_WAIT") or 600)
        except ValueError:
            return 600

    def verify(self, ctx):
        try:
            zone = self._zone(ctx)
        except DNSError as e:
            return [Check(False, "dns.zone", str(e))]
        bad = self._scope_checks(ctx, zone)
        if bad:
            return bad
        res = _zone.resolver(ctx)
        desired = desired_records(ctx)
        if not desired:
            return self._verify_consistent(ctx, res, zone)
        ok, results = _manual.wait_for(res, desired, zone, clock=ctx.clock, sleep=ctx.sleep,
                                       timeout=self._wait(ctx), interval=10,
                                       progress=lambda m: ctx.log(m))
        if ok:
            return [Check(True, "dns.resolves",
                          f"{len(desired)} record(s) live on every authoritative NS and at "
                          "1.1.1.1 / 8.8.8.8")]
        failures = _manual.describe_failure(results)
        auth_ok = all(_manual.probe_ok(p, need_public=False) for p in results.values())
        if auth_ok:
            return [Check(False, "dns.propagation",
                          "the authoritative name servers have the records but public resolvers "
                          "do not yet: " + "; ".join(failures[:3]),
                          "resolvers may cache an old or missing answer for up to the zone's "
                          "negative TTL; re-run `porch setup` in a while")]
        return [Check(False, "dns.resolves", "records not served by the authoritative name "
                      "servers: " + "; ".join(failures[:3]),
                      "check the records at your DNS host (porch dns show)")]

    def _verify_consistent(self, ctx, res, zone):
        """No target IP known (adopt without the connection step): every name
        must resolve at the authoritative NS, all to the same address set."""
        seen = {}
        for h in _zone.desired_hosts(ctx):
            q = _manual.query_name(h)
            try:
                answers = res.authoritative(q, "A", zone=zone)
            except DNSError as e:
                return [Check(False, "dns.resolves", f"{h}: {e}")]
            vals = {tuple(sorted(v)) for v in answers.values() if v}
            if not vals or any(v is None or not v for v in answers.values()):
                return [Check(False, "dns.resolves", f"{h} has no A record on every "
                              "authoritative NS", "porch dns show")]
            if len(vals) > 1:
                return [Check(False, "dns.inconsistent", f"{h}: the name servers disagree: {vals}")]
            seen[h] = vals.pop()
        sets = set(seen.values())
        if len(sets) > 1:
            return [Check(False, "dns.inconsistent", "porch's names point at different "
                          "addresses: " + ", ".join(f"{h}={','.join(v)}" for h, v in seen.items()),
                          "pass --dns-ipv4 to say which one is right")]
        ips = ",".join(sets.pop())
        return [Check(True, "dns.resolves", f"{len(seen)} name(s) resolve to {ips} on every "
                      "authoritative NS")]

    def undo(self, ctx, entry):
        kind = entry.get("kind")
        if kind not in ("dns.delete", "dns.restore", "dns.recreate"):
            return super().undo(ctx, entry)
        p = self._provider(ctx)
        zone = entry["zone"]
        try:
            if kind == "dns.delete":
                for r in p.list(zone, name=entry["name"], rtype=entry["type"]):
                    if r.content.strip() == entry["content"]:
                        p.delete(zone, r.id)
            elif kind == "dns.recreate":
                cur = p.list(zone, name=entry["name"], rtype=entry["type"])
                if not any(r.content.strip() == entry["content"] for r in cur):
                    p.create(zone, Record(entry["name"], entry["type"], entry["content"],
                                          int(entry.get("ttl") or TTL)))
            else:
                rec = Record(entry["name"], entry["type"], entry["content"],
                             int(entry.get("ttl") or TTL))
                cur = p.list(zone, name=entry["name"], rtype=entry["type"])
                match = [r for r in cur if r.id == entry.get("id")]
                if match:
                    p.update(zone, entry["id"], rec)
                else:
                    stale = [r for r in cur if r.content.strip() == entry.get("new")]
                    for r in stale:
                        p.delete(zone, r.id)
                    if not any(r.content.strip() == entry["content"] for r in cur):
                        p.create(zone, rec)
        except ProviderError as e:
            raise StepError(e.code, f"rollback of {entry['name']}: {e.message}", e.hint) from None


STEP = DnsRecordsStep()

"""porch dns show|set|watch

  porch dns show [--json]       the records porch wants, and whether every
                                authoritative NS and 1.1.1.1 / 8.8.8.8 serve them
  porch dns set [--ipv4 IP] [--ipv6 IP] [--apex] [--yes] [--dry-run]
                                (re)point porch's records: runs the
                                dns_provider + dns_records setup steps
  porch dns watch [--once]      dynamic-IP updater (not built yet)
"""

import argparse
import json
import sys

from . import engine as _engine
from . import io as _io
from .dnsq import DNSError
from .dns import manual as _manual
from .dns import zone as _zone


def _ctx(ctx_kwargs=None):
    kw = {"io": _io.CliIO(interactive=False), "log": False}
    kw.update(ctx_kwargs or {})
    return _engine.make_context(**kw)


def show(args, out, ctx_kwargs=None):
    from .steps import dns_records as _rec
    ctx = _ctx(ctx_kwargs)
    try:
        zone, ns = _zone.zone_info(ctx)
    except DNSError as e:
        print(f"porch dns: cannot find the zone of {ctx.cfg.root}: {e}", file=sys.stderr)
        return 1
    desired = _rec.desired_records(ctx)
    provider = _zone.provider_name(ctx) or "(not chosen yet)"
    res = _zone.resolver(ctx)
    rows = []
    for r in desired:
        p = _manual.probe(res, r, zone)
        rows.append({"type": r.type, "name": r.name, "value": r.content, "ttl": r.ttl,
                     "authoritative": _manual.probe_ok(p, need_public=False),
                     "public": all(p["public"].values()) if p["public"] else False})
    if args.json:
        print(json.dumps({"zone": zone, "ns": ns, "provider": provider, "records": rows,
                          "hosts": _zone.desired_hosts(ctx)}, indent=2), file=out)
        return 0
    print(f"zone {zone}  (NS {', '.join(ns)})  provider: {provider}", file=out)
    if not rows:
        print("  no target IP recorded yet; what the authoritative NS answer now:", file=out)
        for h in _zone.desired_hosts(ctx):
            try:
                ans = res.authoritative(_manual.query_name(h), "A", zone=zone)
                vals = sorted({v for vs in ans.values() if vs for v in vs})
            except DNSError as e:
                vals = [f"error: {e}"]
            print(f"  A     {h}  {', '.join(vals) or '(none)'}", file=out)
        print("  set a target with: porch dns set --ipv4 <public IP>", file=out)
        return 0
    w = max(len(r["name"]) for r in rows)
    for r in rows:
        state = ("live" if r["public"] else "authoritative only") if r["authoritative"] else "missing"
        print(f"  {r['type']:<5} {r['name']:<{w}}  {r['value']:<15} ttl {r['ttl']}  {state}",
              file=out)
    return 0


def set_(args, out, ctx_kwargs=None):
    from . import cli
    argv = ["--only", "dns_provider,dns_records"]
    if args.ipv4:
        argv += ["--dns-ipv4", args.ipv4]
    if args.ipv6:
        argv += ["--dns-ipv6", args.ipv6]
    if args.apex:
        argv += ["--dns-apex"]
    for flag in ("yes", "dry_run", "non_interactive"):
        if getattr(args, flag):
            argv.append("--" + flag.replace("_", "-"))
    return cli.cmd_setup(argv, out=out, ctx_kwargs=ctx_kwargs)


def main(argv, out=None, ctx_kwargs=None):
    out = out or sys.stdout
    p = argparse.ArgumentParser(prog="porch dns", description="porch DNS records")
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("show", help="desired records and whether they resolve")
    s.add_argument("--json", action="store_true")
    st = sub.add_parser("set", help="create/update porch's records via the DNS provider")
    st.add_argument("--ipv4")
    st.add_argument("--ipv6")
    st.add_argument("--apex", action="store_true", help="also point the zone apex")
    st.add_argument("--yes", "-y", action="store_true")
    st.add_argument("--dry-run", action="store_true")
    st.add_argument("--non-interactive", action="store_true")
    w = sub.add_parser("watch", help="dynamic-IP updater (later)")
    w.add_argument("--once", action="store_true")
    args = p.parse_args(argv)
    if args.cmd == "show":
        return show(args, out, ctx_kwargs)
    if args.cmd == "set":
        return set_(args, out, ctx_kwargs)
    if args.cmd == "watch":
        print("porch dns watch: not built yet (comes with dynamic-IP support, phase 3)",
              file=sys.stderr)
        return _engine.EXIT_USAGE
    p.print_help(sys.stderr)
    return _engine.EXIT_USAGE

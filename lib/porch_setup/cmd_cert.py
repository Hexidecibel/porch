"""porch cert issue|renew|status

  porch cert status [--json]    the porch lineage (SANs, expiry, combined PEM)
                                and what HAProxy serves for each porch name
  porch cert issue [--email E] [--staging] [--yes] [--dry-run]
                                runs the certificate setup step (staging
                                --dry-run first, then the real issue)
  porch cert renew [--dry-run] [--force]
                                certbot renew for the porch lineage (unprivileged)
"""

import argparse
import json
import os
import sys

from . import acme
from . import engine as _engine
from . import io as _io
from .dns import zone as _zone


def _ctx(ctx_kwargs=None):
    kw = {"io": _io.CliIO(interactive=False), "log": False}
    kw.update(ctx_kwargs or {})
    return _engine.make_context(**kw)


def status(args, out, ctx_kwargs=None):
    ctx = _ctx(ctx_kwargs)
    name = acme.cert_name_for(ctx.cfg.root)
    base = acme.acme_dir(ctx.env)
    lin = acme.lineage(base, name)
    now = ctx.clock()
    report = {"cert_name": name, "acme_dir": base, "lineage": None,
              "pem": acme.combined_pem_path(name, ctx.env), "served": []}
    report["pem_exists"] = os.path.exists(report["pem"])
    pem = acme.read_cert_file(lin["fullchain"])
    if pem:
        try:
            info = acme.inspect_pem(ctx.run, pem)
            report["lineage"] = {"sans": info.sans, "not_after": acme.utc_iso(info.not_after),
                                 "days_left": int(info.days_left(now) or 0), "issuer": info.issuer}
        except acme.AcmeError as e:
            report["lineage"] = {"error": e.message}
    probe = getattr(ctx, "tls_probe", None) or acme.served_pem
    for d in _zone.desired_hosts(ctx):
        host = d if not d.startswith("*.") else "porch-check." + d[2:]
        row = {"host": host}
        try:
            p, trusted = probe(host)
            info = acme.inspect_pem(ctx.run, p)
            row.update(covers=info.covers(host), trusted=trusted, sans=info.sans,
                       days_left=int(info.days_left(now) or 0))
        except (OSError, acme.AcmeError) as e:
            row["error"] = getattr(e, "message", None) or str(e)
        report["served"].append(row)
    if args.json:
        print(json.dumps(report, indent=2), file=out)
        return 0
    lin_r = report["lineage"]
    if lin_r is None:
        print(f"{name}: not issued yet (porch cert issue)", file=out)
    elif "error" in lin_r:
        print(f"{name}: {lin_r['error']}", file=out)
    else:
        print(f"{name}: {', '.join(lin_r['sans'])}; expires {lin_r['not_after']} "
              f"({lin_r['days_left']} days)", file=out)
    print(f"combined PEM: {report['pem']} ({'present' if report['pem_exists'] else 'missing'})",
          file=out)
    print("served at 127.0.0.1:443:", file=out)
    for r in report["served"]:
        if "error" in r:
            print(f"  {r['host']}: {r['error']}", file=out)
        else:
            flag = "ok" if r["covers"] and r["trusted"] and r["days_left"] > acme.RENEW_DAYS else "CHECK"
            print(f"  {r['host']}: {flag}  {r['days_left']} days, "
                  f"{'trusted' if r['trusted'] else 'NOT trusted'}, SANs {', '.join(r['sans'])}",
                  file=out)
    return 0


def issue(args, out, ctx_kwargs=None):
    from . import cli
    argv = ["--only", "certificate"]
    if args.email:
        argv += ["--acme-email", args.email]
    if args.staging:
        argv += ["--acme-staging"]
    for flag in ("yes", "dry_run", "non_interactive"):
        if getattr(args, flag):
            argv.append("--" + flag.replace("_", "-"))
    return cli.cmd_setup(argv, out=out, ctx_kwargs=ctx_kwargs)


def renew(args, out, ctx_kwargs=None):
    ctx = _ctx(ctx_kwargs)
    name = acme.cert_name_for(ctx.cfg.root)
    base = acme.acme_dir(ctx.env)
    if not os.path.exists(acme.lineage(base, name)["renewal"]):
        print(f"porch cert renew: no {name} lineage under {base}; run porch cert issue",
              file=sys.stderr)
        return 1
    try:
        acme.version_check(ctx.run)
    except acme.AcmeError as e:
        print(f"porch cert renew: {e.message} ({e.hint})", file=sys.stderr)
        return 3
    argv = acme.renew_argv(name, base=base, repo_dir=ctx.repo_dir, dry_run=args.dry_run,
                           force=args.force)
    try:
        r = acme.run_certbot(ctx.run, argv,
                             env=acme.hook_env(ctx.env, ctx.data_dir, ctx.secrets.file_root),
                             timeout=1800, sleep=ctx.sleep,
                             log=lambda m: print(f"porch cert renew: {m}", file=sys.stderr))
    except acme.AcmeError as e:
        print(f"porch cert renew: {ctx.redactor.redact(e.message)}\n  {e.hint}", file=sys.stderr)
        return 4
    print(ctx.redactor.redact(r.stdout).rstrip(), file=out)
    if r.returncode != 0:
        print("porch cert renew: certbot failed: " + ctx.redactor.redact(acme.tail(r.stderr, 4)),
              file=sys.stderr)
        return 4
    return 0


def main(argv, out=None, ctx_kwargs=None):
    out = out or sys.stdout
    p = argparse.ArgumentParser(prog="porch cert", description="porch TLS certificate")
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("status")
    s.add_argument("--json", action="store_true")
    i = sub.add_parser("issue")
    i.add_argument("--email")
    i.add_argument("--staging", action="store_true")
    i.add_argument("--yes", "-y", action="store_true")
    i.add_argument("--dry-run", action="store_true")
    i.add_argument("--non-interactive", action="store_true")
    r = sub.add_parser("renew")
    r.add_argument("--dry-run", action="store_true")
    r.add_argument("--force", action="store_true")
    args = p.parse_args(argv)
    if args.cmd == "status":
        return status(args, out, ctx_kwargs)
    if args.cmd == "issue":
        return issue(args, out, ctx_kwargs)
    if args.cmd == "renew":
        return renew(args, out, ctx_kwargs)
    p.print_help(sys.stderr)
    return _engine.EXIT_USAGE

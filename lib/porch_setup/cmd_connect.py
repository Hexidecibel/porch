"""`porch connect`: show or switch how the internet reaches this box.

    porch connect --status [--json] [--no-probe]   probe (read-only) and list every mode,
                                                   plus the active relay's health
    porch connect direct|upnp|manual [--yes] [--dry-run] [--non-interactive]
    porch connect upnp --refresh                   renew UPnP / NAT-PMP / PCP leases
    porch connect paid [--provider digitalocean|vultr] [--region R] [--size S]
                       --token-ref inf://...|op://...|file://... [--ssh-key K] [--tag T]
    porch connect byo user@host [--ssh-key K]
    porch connect oracle [ubuntu@<ip>] [--ssh-key K]   (no host: print the guide)
    porch connect --off [--yes]                    tear the active mode down (a paid
                                                   relay's server is deleted)
    porch connect ipv6                             coming later

A switch runs the network_probe and connection steps through the engine
(fresh facts, the same undo log as `porch setup`), sets up the new mode, then
tears down the old one's changes. Relay modes refuse while the localhost
frpc bypass is on.
"""

import argparse
import json
import sys

from . import engine as _engine
from . import io as _io
from . import registry
from .net import probe as _probe
from .steps import connection as _conn
from .steps import network_probe as _np


def _parser():
    p = argparse.ArgumentParser(prog="porch connect", description=__doc__.split("\n\n")[0])
    p.add_argument("mode", nargs="?", help="direct, upnp, manual, paid, byo or oracle (ipv6: later)")
    p.add_argument("target", nargs="?", help="byo / oracle: the relay server, user@host")
    p.add_argument("--status", action="store_true", help="probe and list the modes; change nothing")
    p.add_argument("--json", action="store_true", help="with --status: JSON output")
    p.add_argument("--no-probe", action="store_true", help="with --status: use the stored facts")
    p.add_argument("--refresh", action="store_true", help="renew the active mode's port-mapping leases")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--yes", "-y", action="store_true")
    p.add_argument("--non-interactive", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--provider", help="paid: digitalocean (default) or vultr")
    p.add_argument("--region", help="paid: provider region (default: the provider's)")
    p.add_argument("--size", help="paid: server size (default: the cheapest that fits)")
    p.add_argument("--token-ref", help="paid: the provider API token as a ref "
                   "(inf://, op://, file://; or set PORCH_RELAY_TOKEN)")
    p.add_argument("--ssh-key", help="byo/oracle: ssh private key; paid: its .pub goes on the relay")
    p.add_argument("--tag", help="paid: an extra tag on the relay server")
    p.add_argument("--ssh", help="same as the user@host argument")
    p.add_argument("--off", "--teardown-relay", dest="off", action="store_true",
                   help="tear down the active mode (deletes a paid relay's server)")
    return p


RELAY_FLAGS = (("provider", "relay_provider"), ("region", "relay_region"), ("size", "relay_size"),
               ("token_ref", "relay_token"), ("ssh_key", "relay_ssh_key"), ("tag", "relay_tag"))


def _answers(args):
    out = {"connection": args.mode} if args.mode else {}
    for attr, name in RELAY_FLAGS:
        v = getattr(args, attr)
        if v:
            out[name] = v
    target = args.target or args.ssh
    if target:
        out["relay_host"] = target
    return out


def _relay_lines(ctx, active, out):
    """Relay health for --status (read-only: tcp, unit, frpc admin API)."""
    from .relay import common as _relay
    entry = ctx.state.steps.get(_conn.STEP.id) or {}
    relay = (entry.get("outputs") or {}).get("relay") or {}
    ip = relay.get("ip") or active.get("ingress_ipv4")
    desc = relay.get("provider") or relay.get("target") or active["mode"]
    line = f"relay: {desc} {ip}"
    if relay.get("id") is not None:
        line += f" (server {relay['id']}, {relay.get('size')} in {relay.get('region')}"
        if relay.get("monthly") is not None:
            line += f", {relay['monthly']:.2f} {relay.get('currency') or 'USD'}/month"
        line += ")"
    print(line, file=out)
    ok = True
    mode = registry.modes().get(active["mode"])
    for ch in _relay.health(ctx, ip, tcp=getattr(mode, "tcp_open", _relay.tcp_open)):
        ok = ok and ch.ok
        print(f"  [{'ok  ' if ch.ok else 'FAIL'}] {ch.message}" + (f"  ({ch.hint})" if ch.hint and not ch.ok else ""),
              file=out)
    return ok


def _status(args, out, ctx_kwargs, env):
    ctx = _engine.make_context(io=_io.NullIO(), dry_run=True, log=False, env=env, **ctx_kwargs)
    facts = ctx.facts.get("network") if args.no_probe else None
    if not facts:
        facts = _np.run_probe(ctx)
    rows, rec = _conn.assess(ctx, facts)
    active = ctx.state.connection.get("active")
    if args.json:
        print(json.dumps({"facts": facts, "modes": rows, "recommended": rec, "active": active},
                         indent=2), file=out)
        return 0
    for line in _probe.summary(facts):
        print(line, file=out)
    print("", file=out)
    print("Connection modes:", file=out)
    for line in _conn.table(rows, rec, (active or {}).get("mode")):
        print(line, file=out)
    if active:
        print(f"\nactive: {active['mode']} since {active.get('since')}, ingress "
              f"{active.get('ingress_ipv4')}, ddns={'on' if active.get('ddns') else 'off'}", file=out)
        if active.get("mode") in _RELAYS:
            _relay_lines(ctx, active, out)
    return 0


_RELAYS = ("paid", "byo", "oracle")


def _off(args, out, io, ctx_kwargs, env):
    ctx = _engine.make_context(io=io, dry_run=args.dry_run, env=env, **ctx_kwargs)
    active = ctx.state.connection.get("active") or {}
    entry = ctx.state.steps.get(_conn.STEP.id) or {}
    if not active and entry.get("status") == "failed" and entry.get("undo"):
        # A mode that failed half-way (say, a router port conflict after two
        # ports were mapped) is not active, but what it did must still go.
        active = {"mode": f"the failed {ctx.state.inputs.get('connection') or 'connection'} attempt",
                  "ingress_ipv4": None}
    if not active:
        print("porch connect --off: no active connection mode", file=out)
        return 0
    relay = (entry.get("outputs") or {}).get("relay") or {}
    print(f"tearing down {active['mode']}"
          + (f" (ingress {active['ingress_ipv4']})" if active.get("ingress_ipv4") else ""), file=out)
    for u in reversed(entry.get("undo") or []):
        print(f"  - {u.get('kind')} {u.get('id') or u.get('target') or u.get('port') or ''}".rstrip(), file=out)
    if relay.get("id") is not None:
        cost = (f", {relay['monthly']:.2f} {relay.get('currency') or 'USD'}/month"
                if relay.get("monthly") is not None else "")
        print(f"  the {relay.get('provider')} server {relay['id']} ({relay.get('ip')}{cost}) is deleted",
              file=out)
    if not args.dry_run and not args.yes and not ctx.confirm(
            f"Tear down {active['mode']}? Visitors cannot reach this box until another mode is set up.",
            default=False):
        print("porch connect --off: not confirmed (pass --yes)", file=sys.stderr)
        return _engine.EXIT_USAGE
    r = _engine.Engine([_conn.STEP], ctx).rollback()
    if r.ok and not args.dry_run:
        print("connection: off", file=out)
    elif not r.ok:
        e = r.error or {}
        print(f"porch connect --off: {e.get('code')}: {e.get('message')}", file=sys.stderr)
    return r.exit_code


def _refresh(args, out, io, ctx_kwargs, env):
    ctx = _engine.make_context(io=io, dry_run=args.dry_run, env=env, **ctx_kwargs)
    eng = _engine.Engine([_np.STEP, _conn.STEP], ctx)
    try:
        eng.lock.acquire()
    except Exception as e:  # noqa: BLE001
        print(f"porch connect: {e}", file=sys.stderr)
        return _engine.EXIT_ABORTED
    try:
        ctx.state.reload()
        active = (ctx.state.connection.get("active") or {}).get("mode")
        mode = registry.modes().get(active or "")
        if mode is None:
            print("porch connect --refresh: no active connection mode", file=sys.stderr)
            return _engine.EXIT_USAGE
        if active != "upnp":
            print(f"porch connect --refresh: {active} has nothing to renew", file=out)
            return 0
        facts = _np.ensure(ctx, refresh=True)
        ctx.step_id = _conn.STEP.id
        try:
            res = mode.apply(ctx, facts)
        except _engine.StepError as e:
            print(f"porch connect --refresh: {e.code}: {e.message}" + (f"\n  hint: {e.hint}" if e.hint else ""),
                  file=sys.stderr)
            return _engine.EXIT_APPLY
        entry = ctx.state.step(_conn.STEP.id)
        entry["outputs"] = ctx.redactor.redact_obj({**entry.get("outputs", {}), **res})
        ctx.state.save()
        print(f"renewed {len(res.get('mappings', []))} mappings via {res.get('method')}, "
              f"lease {res.get('lease')}s", file=out)
        return 0
    finally:
        ctx.step_id = None
        eng.lock.release()


def main(argv, *, io=None, out=None, env=None, ctx_kwargs=None):
    out = out or sys.stdout
    ctx_kwargs = dict(ctx_kwargs or {})
    args = _parser().parse_args(list(argv))
    if args.status or (not args.mode and not args.refresh and not args.off):
        return _status(args, out, ctx_kwargs, env)
    if io is None:
        # --refresh renews mappings the owner already approved: no new question.
        io = _io.CliIO(answers=_answers(args),
                       interactive=False if args.non_interactive else None,
                       yes=args.yes or args.refresh,
                       env=env, verbose=args.verbose)
    if args.off:
        return _off(args, out, io, ctx_kwargs, env)
    if args.refresh:
        return _refresh(args, out, io, ctx_kwargs, env)
    if args.mode in _conn.LATER and args.mode not in registry.modes():
        print(f"porch connect {args.mode}: {_conn.LATER[args.mode]}: coming later.", file=sys.stderr)
        return _engine.EXIT_USAGE
    if args.mode not in registry.modes():
        print(f"porch connect: unknown mode {args.mode!r}; choose one of: "
              + ", ".join(sorted(set(registry.modes()) | set(_conn.LATER))), file=sys.stderr)
        return _engine.EXIT_USAGE
    if args.mode in _RELAYS:
        rc = _relay_precheck(args, out, ctx_kwargs, env)
        if rc is not None:
            return rc
    elif any(getattr(args, a) for a, _ in RELAY_FLAGS) or args.target or args.ssh:
        print(f"porch connect {args.mode}: relay options only go with paid, byo or oracle",
              file=sys.stderr)
        return _engine.EXIT_USAGE
    if not args.dry_run and not args.yes and not getattr(io, "interactive", False):
        # Switching can change the router; never do that unattended without --yes.
        print(f"porch connect {args.mode}: no terminal to confirm on; pass --yes "
              "(or --dry-run to see the plan)", file=sys.stderr)
        return _engine.EXIT_USAGE
    ctx =_engine.make_context(io=io, dry_run=args.dry_run, env=env, **ctx_kwargs)
    ctx.refresh_network = True
    r = _engine.Engine([_np.STEP, _conn.STEP], ctx).run()
    if r.ok:
        active = ctx.state.connection.get("active") or {}
        if not args.dry_run:
            print(f"connection: {active.get('mode')} (ingress {active.get('ingress_ipv4')}, "
                  f"ddns={'on' if active.get('ddns') else 'off'})", file=out)
            for line in _follow_ups(ctx, active):
                print(line, file=out)
    elif r.missing:
        print("porch connect: missing input; pass: " + " ".join(r.missing), file=sys.stderr)
    elif not args.dry_run:
        e = ctx.state.steps.get(_conn.STEP.id) or {}
        if e.get("status") == "failed" and e.get("undo"):
            print(f"porch connect: the failed attempt left {len(e['undo'])} change(s) in place; "
                  "`porch connect --off` undoes them", file=sys.stderr)
    return r.exit_code


def _relay_precheck(args, out, ctx_kwargs, env):
    """Refuse relay modes up front while the localhost bypass is on, and
    print the Oracle guide when no VM was given. None: go ahead."""
    from .connect import oracle as _oracle
    from .relay import common as _relay
    ctx = _engine.make_context(io=_io.NullIO(), dry_run=True, log=False, env=env, **ctx_kwargs)
    if _relay.bypass_on(ctx):
        print(f"porch connect {args.mode}: refused: {_relay.BYPASS_REASON}.\n  hint: {_relay.BYPASS_HINT}",
              file=sys.stderr)
        return _engine.EXIT_PREFLIGHT
    if args.mode == "oracle" and not (args.target or args.ssh) and not ctx.input("relay_host"):
        for line in _oracle.GUIDE:
            print(line, file=out)
        return _engine.EXIT_USAGE
    return None


def _follow_ups(ctx, active):
    """What a later mode switch leaves for the other steps to redo."""
    from .steps import _common as c
    out = []
    done = lambda sid: ctx.state.status_of(sid) in ("done", "adopted")  # noqa: E731
    if done("haproxy") and c.relay_mode(ctx) and active.get("mode") in _RELAYS:
        out.append("next: porch setup --only haproxy   (adds the relay's accept-proxy binds)")
    ip = active.get("ingress_ipv4")
    if done("dns_records") and ip and ctx.input("dns_ipv4") not in (None, "", ip):
        out.append(f"next: porch setup --only dns_records --dns-ipv4 {ip}   "
                   f"(DNS still points at {ctx.input('dns_ipv4')})")
    return out

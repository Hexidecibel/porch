"""`porch` command line (bin/porch is a thin wrapper around main()).

    porch setup [--dry-run] [--adopt] [--non-interactive] [--yes] [--only STEP[,STEP]]
                [--from STEP] [--until STEP] [--rollback [--to STEP]] [--status [--json]]
                [--web] [<flags declared by the registered steps' Input.flag>]
    porch doctor | render | connect | dns | cert | web | door ...   -> porch_setup/cmd_<name>.py main(argv)
    porch tunnel|serve|drop|... -> bin/<tool>, porch auth -> bin/auth-admin,
    porch public ... -> bin/auth-admin public ...,
    porch server start|stop -> bin/start-server|stop-server, porch status -> bin/status
"""

import argparse
import json
import os
import sys

from . import engine as _engine
from . import io as _io
from . import registry
from .state import REPO_DIR

BIN_DIR = os.path.join(REPO_DIR, "bin")

PASSTHROUGH = ("tunnel", "serve", "drop", "photos", "media", "music", "paste", "exchange",
               "secure-entry", "form", "qr", "snap", "shorten", "chat", "inject", "stash",
               "expose", "hook", "pocket", "view")
ALIASES = {"auth": "auth-admin", "status": "status",
           # the secrets workflow (bin/porch-*; bin/cush-* are the old names)
           "init": "porch-init", "audit": "porch-audit", "hooks-install": "porch-hooks-install",
           "find-empties": "porch-find-empties", "migrate-backend": "porch-migrate-backend",
           "migrate-all": "porch-migrate-all", "secrets-reap": "porch-secrets-reap"}
SERVER = {"start": "start-server", "stop": "stop-server"}
# Subcommands implemented by porch_setup/cmd_<name>.py (built by W1/W2/W3).
MODULE_COMMANDS = {
    "doctor": "read-only check of every setup step",
    "render": "render haproxy/frps/units/cloud-init from config",
    "connect": "switch connection mode (direct, upnp, manual, ipv6, relays)",
    "dns": "show / watch / set porch DNS records",
    "cert": "issue / renew / inspect the porch certificate",
    "web": "web setup wizard",
    "door": "running doors: ls, expire, keep, share rules",
    "inspect": "requests an inspected door / webhook saw: list, follow, show, replay",
    "clip": "Pocket clipboard: print, set, ls, watch, rm",
    "share": "share a file, folder or stdin as the right door (view/media/music/serve)",
    "tail": "live read-only log door for a growing file",
    "mcp": "Model Context Protocol server over stdio (--print-config)",
}

USAGE = """usage: porch <command> [args]

setup engine:
  setup        run / resume / roll back the setup steps (porch setup --help)
""" + "".join(f"  {k:<12} {v}\n" for k, v in MODULE_COMMANDS.items()) + """
existing tools:
  """ + " ".join(PASSTHROUGH) + """
  auth ...     bin/auth-admin          server start|stop   status
  init audit hooks-install find-empties migrate-backend migrate-all secrets-reap
               the secrets workflow (bin/porch-init, ...)
  public ...   public paths on gated apps: ls | add HOST PATH --app A --why W | on|off|rm ID
"""


def passthrough_target(argv):
    """(path, argv for execv) for a passthrough command, else None."""
    if not argv:
        return None
    cmd, rest = argv[0], argv[1:]
    if cmd in PASSTHROUGH:
        tool = cmd
    elif cmd in ALIASES:
        tool = ALIASES[cmd]
    elif cmd == "server" and rest[:1] and rest[0] in SERVER:
        tool, rest = SERVER[rest[0]], rest[1:]
    elif cmd == "public":
        tool, rest = "auth-admin", ["public"] + rest
    else:
        return None
    path = os.path.join(BIN_DIR, tool)
    return path, [path] + rest


def _flag_inputs(steps):
    """Unique Inputs with a CLI flag, from every step's static INPUTS."""
    seen, out = set(), []
    for s in steps:
        for inp in s.INPUTS:
            if inp.flag and inp.flag not in seen:
                seen.add(inp.flag)
                out.append(inp)
    return out


def _dest(inp):
    return "in_" + inp.flag.lstrip("-").replace("-", "_")


def setup_parser(steps):
    p = argparse.ArgumentParser(prog="porch setup", description="Run the porch setup steps.")
    p.add_argument("--dry-run", action="store_true", help="show what would change; change nothing")
    p.add_argument("--adopt", action="store_true",
                   help="verify an existing install; mark passing steps adopted")
    p.add_argument("--non-interactive", action="store_true",
                   help="never prompt; fail (exit 2) listing missing flags")
    p.add_argument("--yes", "-y", action="store_true", help="answer yes to confirmations")
    p.add_argument("--only", action="append", default=[], metavar="STEP",
                   help="run only these steps (repeatable or comma-separated)")
    p.add_argument("--from", dest="from_", metavar="STEP", help="start at this step")
    p.add_argument("--until", metavar="STEP", help="stop after this step")
    p.add_argument("--rollback", action="store_true", help="undo steps in reverse order")
    p.add_argument("--to", metavar="STEP", help="with --rollback: stop after undoing this step")
    p.add_argument("--status", action="store_true", help="show step status and exit")
    p.add_argument("--json", action="store_true", help="with --status: JSON output")
    p.add_argument("--web", action="store_true", help="run the web wizard instead")
    p.add_argument("--verbose", "-v", action="store_true")
    g = p.add_argument_group("step inputs")
    for inp in _flag_inputs(steps):
        h = inp.help or inp.prompt
        if inp.kind == "bool":
            g.add_argument(inp.flag, dest=_dest(inp), action=argparse.BooleanOptionalAction,
                           default=None, help=h)
        elif inp.kind == "secret":
            g.add_argument(inp.flag, dest=_dest(inp), metavar="REF",
                           help=h + " (a ref: inf://, op:// or file://; never the value"
                           + (f"; or set {inp.env}" if inp.env else "") + ")")
        else:
            g.add_argument(inp.flag, dest=_dest(inp), metavar=inp.name.upper(), help=h)
    return p


def _print_status(st, out, as_json):
    if as_json:
        print(json.dumps(st, indent=2), file=out)
        return
    print(f"state: {st['state_path']}  mode: {st['mode']}  run: {st['run_id']}", file=out)
    if not st["steps"]:
        print("  (no setup steps installed yet)", file=out)
    for s in st["steps"]:
        line = f"  {s['id']:<16} {s['status']:<12}"
        if s["error"]:
            line += f" {s['error'].get('code', '')}: {s['error'].get('message', '')}"
        print(line, file=out)


def ready_to_print(r, args):
    """"Your porch is ready" only after a real run (not a dry run) in which
    every registered step, the Pocket step among them, is done."""
    return (r.ok and not args.dry_run and "pocket" in r.statuses
            and all(v in _engine.DONE_LIKE for v in r.statuses.values()))


def cmd_setup(argv, steps=None, env=None, io=None, out=None, ctx_kwargs=None):
    out = out or sys.stdout
    steps = registry.steps() if steps is None else steps
    if "--web" in argv:
        # Routed before parsing: the wizard has its own flags (--tls, --port, ...)
        # and parses the step flags itself.
        main_fn = registry.command("web")
        if main_fn is None:
            print("porch setup --web: not built yet", file=sys.stderr)
            return _engine.EXIT_USAGE
        return main_fn([a for a in argv if a != "--web"])
    args = setup_parser(steps).parse_args(argv)
    if args.to and not args.rollback:
        print("porch setup: --to needs --rollback", file=sys.stderr)
        return _engine.EXIT_USAGE
    answers = {}
    for inp in _flag_inputs(steps):
        v = getattr(args, _dest(inp))
        if v is not None:
            answers[inp.name] = v
    if io is None:
        io = _io.CliIO(answers=answers, interactive=False if args.non_interactive else None,
                       yes=args.yes, env=env, verbose=args.verbose)
    ctx = _engine.make_context(io=io, dry_run=args.dry_run, adopt=args.adopt, env=env,
                               **(ctx_kwargs or {}))
    eng = _engine.Engine(steps, ctx)
    if args.status:
        _print_status(eng.status(), out, args.json)
        return 0
    if not steps:
        print("porch setup: no setup steps are installed yet", file=out)
        return 0
    only = [s for o in args.only for s in o.split(",") if s]
    if args.rollback:
        r = eng.rollback(to_step=args.to)
    else:
        r = eng.run(until=args.until, only=only or None, from_=args.from_)
        if ready_to_print(r, args):
            from . import ready
            try:
                print(ready.text(ctx.cfg), file=out)
            except Exception as e:  # noqa: BLE001 - never fail a finished setup over the summary
                print(f"porch setup: done (summary unavailable: {e})", file=out)
    if not r.ok and r.error:
        if r.missing:
            print("porch setup: missing input; pass: " + " ".join(r.missing), file=sys.stderr)
        elif r.error.get("code") in ("engine.usage", "engine.locked"):
            print(f"porch setup: {r.error['message']}", file=sys.stderr)
    return r.exit_code


def main(argv=None, steps=None, env=None, io=None, out=None, execv=os.execv, ctx_kwargs=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE, file=out or sys.stdout)
        return 0 if argv else _engine.EXIT_USAGE
    cmd, rest = argv[0], argv[1:]
    if cmd == "setup":
        return cmd_setup(rest, steps=steps, env=env, io=io, out=out, ctx_kwargs=ctx_kwargs)
    if cmd in MODULE_COMMANDS:
        fn = registry.command(cmd)
        if fn is None:
            print(f"porch {cmd}: not built yet", file=sys.stderr)
            return _engine.EXIT_USAGE
        return fn(rest)
    target = passthrough_target(argv)
    if target:
        path, args = target
        if not os.path.exists(path):
            print(f"porch {cmd}: {path} not found", file=sys.stderr)
            return _engine.EXIT_USAGE
        execv(path, args)
        return 0  # only reached with a fake execv
    print(f"porch: unknown command {cmd!r}\n\n{USAGE}", file=sys.stderr)
    return _engine.EXIT_USAGE

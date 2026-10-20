"""porch door: list running doors and change their expiry and share rules.

    porch door ls [--json]
    porch door expire <name> <30m|2h|1d|ISO-8601 time|never>
    porch door keep <name>                       (= expire <name> never)
    porch door reopen <name> [--expires 1h|24h|30m|...]
                                                 (a closed door, from its launch recipe)
    porch door rules <name> [--password | --no-password]
                            [--guest-link | --no-guest-link]
                            [--max-opens N | --burn | --no-limit]

Edits go to /tmp/tunnel-state/<name>.json under its lock (lib/door_state.py);
the door proxy re-reads the file on the next request and the watchdog on its
next 30s pass. --password reads PORCH_DOOR_PASSWORD or prompts on the
terminal; only its scrypt hash is stored. --guest-link always mints a new
token (the old link stops working).

A door started without rules has no proxy in front of it (frpc goes straight
to the app). A first rule is still added live: the rules are written, then
the door's bin/tunnel (its `tunnel_pid`) gets SIGUSR1, starts lib/doorproxy.py,
points its frpc config at it and restarts only frpc (one reconnect; the app
keeps running). If that proxy is not up within PROXY_WAIT seconds the rules
are rolled back. Doors started before bin/tunnel recorded its pid (or tcp/udp
tunnels) can't do this: the error prints the exact relaunch command from the
launch history. Exit codes: 0 ok, 1 no such door, 2 usage, 3 needs a relaunch,
4 the live switch failed (rules rolled back).

`reopen` opens a door that expired or was closed again under its name, from
the launch recipe its launcher wrote (lib/door_recipe.py, data/doors/): the
same file or folder, password, guest link and inspector; opens start at zero.
Burned or used-up doors, doors closed more than 7 days ago, and doors from
launchers without recipes (tunnel, exchange, secure-entry, hook) can't. Exit
codes: 0 reopened, 3 can't be reopened (the reason is printed), 2 usage.
"""

import argparse
import json
import os
import sys
import time

import door_ops
import door_recipe
import door_state
import porch_config

REPO_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROXY_WAIT = 15


# The rules logic lives in lib/door_ops.py (shared with the panel and
# Pocket); these names stay as aliases.
_alive = door_ops._alive
_has_proxy = door_ops.has_proxy
_is_our_tunnel = door_ops.is_our_tunnel
relaunch_command = door_ops.relaunch_command


def _doors(state_dir):
    out = []
    try:
        names = sorted(os.listdir(state_dir))
    except OSError:
        return out
    for fn in names:
        if not fn.endswith('.json') or fn.startswith('.'):
            continue
        try:
            s = door_state.read_state(os.path.join(state_dir, fn))
        except (OSError, ValueError):
            continue
        if not isinstance(s.get('name'), str) or not _alive(s.get('pid')):
            continue
        out.append(s)
    return out


def _row(s, tunnel_base):
    rules = door_state.clean_rules(s.get('rules'))
    exp = door_state.expires_of(s)
    name = s['name']
    row = {
        'name': name,
        'type': s.get('type', ''),
        'url': f'https://{name}.{tunnel_base}',
        'expires': exp,
        'never': exp is None,
        'opens': s.get('opens', 0) or 0,
        'last_open': s.get('last_open'),
        'rules': door_state.public_rules(rules),
        'proxy': _has_proxy(s),
    }
    if 'guest' in rules:
        row['guest_url'] = door_state.guest_url(name, rules['guest'], tunnel_base)
    return row


def _tunnel_base():
    # An invalid config raises porch_config.ConfigError (main() reports it, exit 1).
    import porch_config
    return porch_config.get().tunnel_base


def cmd_ls(args, out):
    base = _tunnel_base()
    states = _doors(args.state_dir)
    rows = [_row(s, base) for s in states]
    if args.json:
        print(json.dumps(rows, indent=2), file=out)
        return 0
    if not rows:
        print('no doors open', file=out)
        return 0
    now = int(time.time())
    for s, r in zip(states, rows):
        print(f"{r['name']:<22} {r['type']:<10} {r['url']}", file=out)
        print(f"    expires: {door_state.fmt_expires(s, now)}", file=out)
        rules = door_state.rules_summary(s.get('rules'))
        if rules != 'none' or r['opens']:
            print(f"    rules: {rules} · opens: {r['opens']}", file=out)
        if 'guest_url' in r:
            print(f"    guest link: {r['guest_url']}", file=out)
    return 0


def _path_or_die(args):
    path = door_state.state_path(args.name, args.state_dir)
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    return path


def cmd_expire(args, out):
    path = _path_or_die(args)
    s = door_state.set_expiry(path, door_state.parse_expires(args.when))
    print(f"{args.name}: expires {door_state.fmt_expires(s)}", file=out)
    return 0


def cmd_keep(args, out):
    path = _path_or_die(args)
    door_state.set_expiry(path, None)
    print(f"{args.name}: never expires (close it with: bin/status close {args.name})", file=out)
    return 0


def _wait_for_proxy(path, since_pid=None, wait=None):
    return door_ops.wait_for_proxy(path, since_pid, PROXY_WAIT if wait is None else wait)


def cmd_rules(args, out):
    path = _path_or_die(args)
    current = door_state.read_state(path)
    if args.max_opens is not None and not 1 <= args.max_opens <= door_state.MAX_OPENS:
        raise door_state.DoorError('--max-opens must be at least 1')
    changing = any([args.password, args.guest_link, args.max_opens is not None, args.burn,
                    args.no_password, args.no_guest_link, args.no_limit])
    if not changing:
        print(f"{args.name}: rules: {door_state.rules_summary(current.get('rules'))}", file=out)
        return 0
    keep = door_ops.KEEP
    try:
        res = door_ops.set_rules(
            args.state_dir, args.name,
            # read only once the change is known to be possible (no prompt
            # before a relaunch refusal)
            password=door_state.read_password if args.password else (
                None if args.no_password else keep),
            guest='new' if args.guest_link else (None if args.no_guest_link else keep),
            max_opens=1 if args.burn else (args.max_opens if args.max_opens is not None else (
                None if args.no_limit else keep)),
            signal_wait=PROXY_WAIT, relaunch_flags=_flags(args), tunnel_base=_tunnel_base())
    except door_ops.DoorOpError as e:
        if e.code == 'relaunch_needed':
            print(f"{args.name} has no door proxy in front of it and {e.extra['why']}, so the "
                  "rule can't be added live. Relaunch it with the flags:", file=sys.stderr)
            print(f"  bin/status close {args.name}", file=sys.stderr)
            print('  ' + e.extra['command'], file=sys.stderr)
            return 3
        if e.code == 'switch_failed':
            print(f"porch door: {args.name}: the door proxy did not come up, so the rules were "
                  "rolled back (the door is unchanged). See its log, or relaunch it with "
                  "the flags.", file=sys.stderr)
            return 4
        if e.status == 404:
            raise FileNotFoundError(args.name) from None
        raise door_state.DoorError(e.message) from None
    if res['live_switch']:
        print(f"{args.name}: door proxy started in front of it (frpc reconnected)", file=out)
    print(f"{args.name}: rules: {res['summary']}", file=out)
    if res['minted']:
        print(f"guest link: {res['guest_url']}", file=out)
    return 0


def cmd_reopen(args, out):
    try:
        st = door_recipe.reopen(args.name, args.expires, state_dir=args.state_dir)
    except door_recipe.RecipeError as e:
        print(f'porch door: {e}', file=sys.stderr)
        return 3
    print(f"{args.name}: open again at https://{args.name}.{_tunnel_base()} "
          f"(expires {door_state.fmt_expires(st)})", file=out)
    rules = door_state.clean_rules(st.get('rules'))
    if 'guest' in rules:
        print(f"guest link: {door_state.guest_url(args.name, rules['guest'], _tunnel_base())}",
              file=out)
    return 0


def _flags(args):
    f = []
    if args.password:
        f.append('--password')
    if args.guest_link:
        f.append('--guest-link')
    if args.burn:
        f.append('--burn')
    elif args.max_opens is not None:
        f += ['--max-opens', str(args.max_opens)]
    return f


def main(argv, out=None):
    out = out or sys.stdout
    p = argparse.ArgumentParser(prog='porch door', description='Running doors: expiry and share rules.')
    p.add_argument('--state-dir', default=door_state.STATE_DIR, help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest='cmd')
    ls = sub.add_parser('ls', help='list open doors')
    ls.add_argument('--json', action='store_true')
    e = sub.add_parser('expire', help='set the exact expiry')
    e.add_argument('name')
    e.add_argument('when', help='30m, 2h, 1d, an ISO-8601 time, or never')
    k = sub.add_parser('keep', help='never expire')
    k.add_argument('name')
    ro = sub.add_parser('reopen', help='open a closed door again, as it was')
    ro.add_argument('name')
    ro.add_argument('--expires', default='1h', help='how long it stays open (default 1h)')
    r = sub.add_parser('rules', help='show or change share rules')
    r.add_argument('name')
    g = r.add_mutually_exclusive_group()
    g.add_argument('--password', action='store_true',
                   help='require a password (PORCH_DOOR_PASSWORD or a prompt)')
    g.add_argument('--no-password', action='store_true')
    g2 = r.add_mutually_exclusive_group()
    g2.add_argument('--guest-link', action='store_true', help='mint a new ?k= guest link')
    g2.add_argument('--no-guest-link', action='store_true')
    g3 = r.add_mutually_exclusive_group()
    g3.add_argument('--max-opens', type=int, metavar='N')
    g3.add_argument('--burn', action='store_true', help='= --max-opens 1')
    g3.add_argument('--no-limit', action='store_true')
    try:
        args = p.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    if not args.cmd:
        p.print_help(file=out)
        return 2
    try:
        return {'ls': cmd_ls, 'expire': cmd_expire, 'keep': cmd_keep,
                'rules': cmd_rules, 'reopen': cmd_reopen}[args.cmd](args, out)
    except door_state.DoorError as e:
        print(f'porch door: {e}', file=sys.stderr)
        return 2
    except porch_config.ConfigError as e:
        print(f'porch door: invalid Porch config: {e}', file=sys.stderr)
        return 1
    except FileNotFoundError:
        print(f'porch door: no door named {getattr(args, "name", "?")} is open', file=sys.stderr)
        return 1

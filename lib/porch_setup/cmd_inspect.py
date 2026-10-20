"""porch inspect: what an inspected door (--inspect) or a bin/hook webhook saw.

    porch inspect <name> [-n N] [--json]       the last N requests (default 20)
    porch inspect <name> --follow [--json]     ... then each new one as it arrives
    porch inspect <name> --show ID [--json]    one request in full
    porch inspect <name> --replay ID           re-send it to the door's own app

Reads <run dir>/inspect/<name>.jsonl directly (lib/inspect_store.py; the
same user owns it). Secret headers are stored masked unless the door was
started with --inspect-raw. A replay is done by the door proxy itself (over
its private control socket): it goes to the app's local port only, uses the
original header values while that proxy still holds them, and is recorded
as a new request marked "replay of #ID". A hook door has no app, so nothing
can be replayed there. Exit codes: 0 ok, 1 no such door/record, 2 usage,
3 replay refused.
"""

import argparse
import json
import os
import sys
import time

import door_state
import inspect_store


def _color(out):
    return hasattr(out, 'isatty') and out.isatty() and not os.environ.get('NO_COLOR')


def _door_state(name, state_dir):
    try:
        return door_state.read_state(door_state.state_path(name, state_dir))
    except (OSError, ValueError):
        return None


def main(argv, out=None, state_dir=None, base=None, poll=0.5, follow_for=None):
    out = out or sys.stdout
    p = argparse.ArgumentParser(prog='porch inspect',
                                description='Requests an inspected door or webhook received.')
    p.add_argument('name')
    p.add_argument('--follow', '-f', action='store_true', help='keep printing new requests')
    p.add_argument('--json', action='store_true', help='JSON (one object per line with --follow)')
    p.add_argument('--show', type=int, metavar='ID', help='print one request in full')
    p.add_argument('--replay', type=int, metavar='ID', help='re-send a request to the app')
    p.add_argument('-n', type=int, default=20, metavar='N', help='how many to list (default 20)')
    p.add_argument('--state-dir', default=state_dir or door_state.STATE_DIR, help=argparse.SUPPRESS)
    a = p.parse_args(argv)
    try:
        inspect_store.check_name(a.name)
        path = inspect_store.store_path(a.name, base)
    except (inspect_store.InspectError, OSError) as e:
        print(f'porch inspect: {e}', file=sys.stderr)
        return 2
    st = _door_state(a.name, a.state_dir)
    color = _color(out)

    if a.replay is not None:
        if st is not None and isinstance(st.get('capture'), dict):
            print(f'porch inspect: {a.name} is a capture-only hook door: there is no app '
                  'behind it to replay to', file=sys.stderr)
            return 3
        try:
            r = inspect_store.request_replay(a.name, a.replay, base)
        except inspect_store.InspectError as e:
            print(f'porch inspect: replay refused: {e}', file=sys.stderr)
            return 3
        if a.json:
            print(json.dumps(r), file=out)
            return 0
        rec = inspect_store.get_record(path, r.get('id'))
        if rec:
            print(inspect_store.one_line(rec, color), file=out)
        else:
            print(f"replayed #{a.replay} as #{r.get('id')}: {r.get('status')}", file=out)
        if r.get('dropped'):
            print('note: masked headers were dropped (originals no longer held): '
                  + ', '.join(r['dropped']), file=out)
        return 0

    if st is None and not os.path.exists(path):
        print(f'porch inspect: no door named {a.name} (is it open?)', file=sys.stderr)
        return 1
    if st is not None and not (st.get('inspect') or st.get('capture')):
        print(f'porch inspect: {a.name} is not inspected; relaunch it with --inspect',
              file=sys.stderr)
        return 1

    if a.show is not None:
        rec = inspect_store.get_record(path, a.show)
        if rec is None:
            print(f'porch inspect: no request #{a.show} on {a.name}', file=sys.stderr)
            return 1
        print(json.dumps(rec, indent=2) if a.json else inspect_store.details(rec), file=out)
        return 0

    recs = inspect_store.read_records(path)
    shown = recs[-a.n:] if a.n > 0 else []
    if a.json and not a.follow:
        print(json.dumps([inspect_store.summary(r) for r in shown], indent=2), file=out)
        return 0
    if not shown and not a.follow:
        print(f'{a.name}: no requests yet', file=out)
        return 0
    for r in shown:
        print(json.dumps(r) if a.json else inspect_store.one_line(r, color), file=out)
    if not a.follow:
        return 0

    tail = inspect_store.Tail(path, since=recs[-1]['id'] if recs else 0)
    tail.offset = 0
    deadline = None if follow_for is None else time.time() + follow_for
    try:
        while deadline is None or time.time() < deadline:
            for r in tail.poll():
                print(json.dumps(r) if a.json else inspect_store.one_line(r, color),
                      file=out, flush=True)
            if st is not None and deadline is None and not os.path.exists(
                    door_state.state_path(a.name, a.state_dir)):
                print(f'{a.name}: the door closed', file=sys.stderr)
                return 0
            time.sleep(poll)
    except KeyboardInterrupt:
        pass
    return 0

"""porch clip: the Pocket clipboard from this box.

    porch clip [--name N]                print the current text
    porch clip set <text...> | set -     set it (- reads stdin)
    porch clip ls [--json]               current + history
    porch clip watch [--json]            print each new current text as it changes
    porch clip rm <id>                   delete an entry

Talks to the running pocket (bin/pocket <name>, default "pocket") straight on
127.0.0.1: the port comes from /tmp/tunnel-state/<name>.json, and the
credential is the token the server writes 0600 at start to
<run dir>/pocket/<name>.token (lib/rundir.py). The server only accepts that
token on a direct loopback request with no forwarding or Origin headers, so
it is useless through the tunnel. PORCH_POCKET picks the default name.

Exit codes: 0 ok, 1 pocket not running / server refused, 2 usage.
"""

import argparse
import http.client
import json
import os
import sys
import time

_LIB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
import rundir  # noqa: E402

STATE_DIR = '/tmp/tunnel-state'
TOKEN_HEADER = 'X-Porch-CLI-Token'
MAX_STDIN = 1024 * 1024 + 1


class ClipError(Exception):
    pass


def locate(name, state_dir=None, token_file=None):
    """(port, token) of the running pocket `name`."""
    path = os.path.join(state_dir or STATE_DIR, f'{name}.json')
    try:
        with open(path) as f:
            state = json.load(f)
    except (OSError, ValueError):
        raise ClipError(f'pocket "{name}" is not running (no {path}); start it with bin/pocket {name} --bg')
    port = state.get('port') if isinstance(state, dict) else None
    if state.get('type') != 'pocket' or not isinstance(port, int) or isinstance(port, bool):
        raise ClipError(f'"{name}" is not a pocket door')
    tpath = token_file or os.path.join(rundir.tool_dir('pocket'), f'{name}.token')
    try:
        with open(tpath) as f:
            token = f.read().strip()
    except OSError:
        raise ClipError(f'no CLI token at {tpath} (is pocket "{name}" running on this box?)')
    return port, token


def request(port, token, method, path, body=None, timeout=15):
    c = http.client.HTTPConnection('127.0.0.1', port, timeout=timeout)
    headers = {TOKEN_HEADER: token}
    data = None
    if body is not None:
        data = json.dumps(body).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    try:
        c.request(method, path, body=data, headers=headers)
        r = c.getresponse()
        raw = r.read()
    except OSError as e:
        raise ClipError(f'could not reach the pocket on 127.0.0.1:{port}: {e}')
    finally:
        c.close()
    try:
        out = json.loads(raw.decode('utf-8') or '{}')
    except ValueError:
        out = {}
    if r.status != 200:
        raise ClipError(out.get('message') or f'HTTP {r.status}')
    return out


def _ago(ts):
    s = max(0, time.time() - ts)
    if s < 60:
        return 'just now'
    if s < 3600:
        return f'{int(s // 60)}m ago'
    if s < 86400:
        return f'{int(s // 3600)}h ago'
    return time.strftime('%Y-%m-%d', time.localtime(ts))


def _preview(text, n=70):
    one = ' '.join(text.split())
    return one if len(one) <= n else one[:n - 1] + '…'


def watch(port, token, out=sys.stdout, as_json=False, max_events=None, last_id=False):
    """Follow /api/events and print each new current text. The snapshot the
    stream opens with is not printed; it only sets the baseline (last_id,
    False = none yet). Returns the last id seen, for the next connection."""
    c = http.client.HTTPConnection('127.0.0.1', port, timeout=60)
    try:
        c.request('GET', '/api/events', headers={TOKEN_HEADER: token})
        r = c.getresponse()
        if r.status != 200:
            raise ClipError(f'HTTP {r.status}')
        event, seen = None, 0
        while True:
            line = r.fp.readline()
            if not line:
                return last_id
            line = line.decode('utf-8', 'replace').rstrip('\r\n')
            if line.startswith('event:'):
                event = line[6:].strip()
            elif line.startswith('data:') and event == 'clip':
                cur = json.loads(line[5:]).get('current')
                cid = cur['id'] if cur else None
                if last_id is not False and cid != last_id:
                    if as_json:
                        out.write(json.dumps(cur) + '\n')
                    elif cur:
                        out.write(cur['text'] + ('' if cur['text'].endswith('\n') else '\n'))
                    out.flush()
                    seen += 1
                    if max_events and seen >= max_events:
                        return cid
                last_id = cid
            elif line == '':
                event = None
    except OSError as e:
        raise ClipError(f'lost the pocket on 127.0.0.1:{port}: {e}')
    finally:
        c.close()


def main(argv=None, stdin=None, out=None, state_dir=None, token_file=None):
    stdin = stdin or sys.stdin
    out = out or sys.stdout
    p = argparse.ArgumentParser(prog='porch clip', description='The Pocket clipboard from this box.')
    p.add_argument('--name', default=os.environ.get('PORCH_POCKET') or 'pocket',
                   help='pocket door name (default: pocket, or $PORCH_POCKET)')
    sub = p.add_subparsers(dest='cmd')
    s = sub.add_parser('set', help='set the clipboard (- reads stdin)')
    s.add_argument('text', nargs='+')
    ls = sub.add_parser('ls', help='current entry and history')
    ls.add_argument('--json', action='store_true')
    w = sub.add_parser('watch', help='print each new clipboard text')
    w.add_argument('--json', action='store_true')
    rm = sub.add_parser('rm', help='delete an entry by id')
    rm.add_argument('id')
    sub.add_parser('get', help='print the current text (the default)')
    args = p.parse_args(argv)

    try:
        port, token = locate(args.name, state_dir, token_file)
        if args.cmd in (None, 'get'):
            cur = request(port, token, 'GET', '/api/clip').get('current')
            if cur:
                out.write(cur['text'] + ('' if cur['text'].endswith('\n') or not out.isatty() else '\n'))
            return 0
        if args.cmd == 'set':
            if args.text == ['-']:
                text = stdin.read(MAX_STDIN)
            else:
                text = ' '.join(args.text)
            if not text.strip():
                sys.stderr.write('porch clip: nothing to set\n')
                return 2
            request(port, token, 'POST', '/api/clip', {'text': text})
            return 0
        if args.cmd == 'ls':
            snap = request(port, token, 'GET', '/api/clip')
            entries = ([snap['current']] if snap.get('current') else []) + snap.get('history', [])
            if args.json:
                out.write(json.dumps(entries, indent=2) + '\n')
                return 0
            if not entries:
                out.write('(empty)\n')
            for i, e in enumerate(entries):
                mark = '*' if i == 0 else ' '
                out.write(f"{mark} {e['id']}  {_ago(e['ts']):>9}  {e.get('source', ''):<7}  "
                          f"{_preview(e['text'])}\n")
            return 0
        if args.cmd == 'rm':
            request(port, token, 'POST', f"/api/clip/{args.id}/delete", {})
            return 0
        if args.cmd == 'watch':
            last = False
            try:
                while True:
                    last = watch(port, token, out, args.json, last_id=last)
                    time.sleep(1)          # the server recycles streams; follow on
            except KeyboardInterrupt:
                return 0
    except ClipError as e:
        sys.stderr.write(f'porch clip: {e}\n')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

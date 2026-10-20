"""Pocket's doors API (/api/doors*) and request inspector, over lib/door_ops.py
(the same control plane statusserver and `porch door` use) and
lib/inspect_store.py, in-process: same user, same /tmp/tunnel-state, same
door_state locks as the panel.

Differences from the panel: guest links are shown (owner-only data), a
launch may carry door flags (expiry, password in env only, guest link, max
opens), rules can be edited (door_ops.set_rules, with the live first-rule
switch), and Pocket's own door can't be stopped from here (409; Stop all
skips it and every type `pocket` door).
"""

import json
import os
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import door_ops  # noqa: E402
import door_recipe  # noqa: E402
import door_state  # noqa: E402
import inspect_store  # noqa: E402
from door_ops import DoorOpError  # noqa: E402

EXTEND_SECONDS = (3600, 86400)
INSPECT_STREAMS = 2
INSPECT_HEARTBEAT = 15
INSPECT_MAX_SECONDS = 300
INSPECT_POLL = 0.5
HISTORY_MIN_INTERVAL = 5          # s between `history` SSE events
_inspect_slots = threading.BoundedSemaphore(INSPECT_STREAMS)


def doors_sig(state_dir):
    """Changes whenever any door state file is added, removed or rewritten
    (links_sig, for every door)."""
    sig = []
    try:
        names = os.listdir(state_dir)
    except OSError:
        return None
    for fn in sorted(names):
        if fn.endswith('.json'):
            try:
                sig.append((fn, os.stat(os.path.join(state_dir, fn)).st_mtime_ns))
            except OSError:
                pass
    return tuple(sig)


def history_sig(history_path, doors_dir=None):
    out = []
    try:
        ddir = door_recipe.doors_dir(doors_dir)
    except OSError:
        ddir = None
    for p in (history_path, ddir):
        if not p:
            continue
        try:
            st = os.stat(p)
            out.append((st.st_mtime_ns, st.st_size))
        except OSError:
            out.append(None)
    return tuple(out)


class DoorsMixin:
    history_path = None         # data/history.jsonl (main() sets it)
    doors_dir = None            # None = door_recipe's default (PORCH_DOORS_DIR in tests)
    door_runner = staticmethod(subprocess.run)
    door_reopener = None        # (name, expires) -> ...; None = door_recipe.reopen
    inspect_base = None         # None = lib/rundir.py's <run dir>/inspect
    doors_unmanaged = True      # list frpc processes no state file knows (tests: off)
    inspect_heartbeat = INSPECT_HEARTBEAT
    inspect_max_seconds = INSPECT_MAX_SECONDS
    launch_lock = threading.Lock()

    def _door_log(self, msg):
        sys.stderr.write(f"[pocketserver] {msg}\n")

    def _is_self_door(self, d):
        return d.get('name') == self.pocket_name or d.get('type') == 'pocket'

    # ---- listing ----

    def doors_listing(self):
        out = []
        for d in door_ops.list_doors(self.state_dir, unmanaged=self.doors_unmanaged,
                                      cleanup=False, log=self._door_log):
            name = d.get('name')
            unmanaged = d.get('type') == 'unmanaged'
            guest = None
            tag = None
            if not unmanaged:
                try:
                    raw = door_state.read_state(door_state.state_path(name, str(self.state_dir)))
                    tok = door_state.clean_rules(raw.get('rules')).get('guest')
                    guest = door_state.guest_url(name, tok) if tok else None
                    t = raw.get('pocket')
                    if isinstance(t, dict):
                        tag = {'kind': str(t.get('kind') or ''), 'label': str(t.get('label') or '')}
                except (OSError, ValueError, TypeError):
                    pass
            rules = d.get('rules') or {}
            out.append({
                'name': name, 'type': d.get('type') or '', 'url': d.get('url'),
                'guest_url': guest, 'expires': d.get('expires'), 'never': bool(d.get('never')),
                'time_remaining': d.get('time_remaining'),
                'rules': {'password': bool(rules.get('password')),
                          'guest': bool(rules.get('guest_link')),
                          'max_opens': rules.get('max_opens')},
                'opens': d.get('opens', 0), 'last_open': d.get('last_open'),
                'inspect': bool(d.get('inspect')), 'inspect_raw': bool(d.get('inspect_raw')),
                'capture': bool(d.get('capture')), 'started': d.get('started'),
                'unmanaged': unmanaged, 'self': self._is_self_door(d), 'pocket': tag,
            })
        return out

    def doors_reply(self):
        return {'status': 'ok', 'now': int(time.time()), 'doors': self.doors_listing()}

    def history_listing(self):
        if not self.history_path:
            return []
        items = door_ops.history(self.history_path, self.state_dir, self.doors_dir,
                                 log=self._door_log)
        keep = ('name', 'type', 'started', 'url', 'revivable', 'reopenable', 'reopen_why',
                'closed', 'reason')
        return [{k: it.get(k) for k in keep} for it in items]

    # ---- routes ----

    def api_doors(self, query):
        self.send_json(self.doors_reply())

    def api_doors_history(self, query):
        self.send_json(self.history_listing())

    def _own_door(self, name):
        if name == self.pocket_name:
            return True
        try:
            st = door_state.read_state(door_state.state_path(name, str(self.state_dir)))
            return st.get('type') == 'pocket'
        except (OSError, ValueError):
            return False

    def api_door_extend(self, data, name):
        secs = data.get('seconds', 3600)
        if secs not in EXTEND_SECONDS or isinstance(secs, bool):
            raise DoorOpError(400, 'seconds must be 3600 or 86400')
        reply = door_ops.extend(self.state_dir, name, secs, log=self._door_log)
        self._audit('door.extend', name)
        self.send_json(reply)

    def api_door_expire(self, data, name):
        if 'at' not in data:
            raise DoorOpError(400, 'at is required (epoch, "+2h", ISO or "never")')
        reply = door_ops.set_expires(self.state_dir, name, data.get('at'), log=self._door_log)
        self._audit('door.expire', name)
        self.send_json(reply)

    def api_door_stop(self, data, name):
        if self._own_door(name):
            raise DoorOpError(409, "That is this pocket's own door; stop it from the box",
                              code='conflict')
        reply = door_ops.stop(self.state_dir, name, log=self._door_log)
        self._audit('door.stop', name)
        self.send_json(reply)

    def api_doors_stop_all(self, data):
        out = door_ops.stop_all(self.state_dir, exclude=(self.pocket_name,),
                                exclude_types=('pocket',), log=self._door_log)
        self._audit('door.stop_all', f"{len(out['stopped'])} doors")
        self.send_json({'status': 'ok', **out})

    def api_door_rules(self, data, name):
        keep = door_ops.KEEP
        password = data['password'] if 'password' in data else keep
        guest = data['guest'] if 'guest' in data else keep
        max_opens = data['max_opens'] if 'max_opens' in data else keep
        if password is not keep and password is not None and not isinstance(password, str):
            raise DoorOpError(400, 'password must be a string or null')
        if guest not in (keep, None, 'new'):
            raise DoorOpError(400, 'guest must be "new" or null')
        if max_opens is not keep and max_opens is not None and (
                not isinstance(max_opens, int) or isinstance(max_opens, bool)):
            raise DoorOpError(400, 'max_opens must be a number or null')
        if password is keep and guest is keep and max_opens is keep:
            raise DoorOpError(400, 'Nothing to change')
        try:
            cur = door_state.clean_rules(door_state.read_state(
                door_state.state_path(name, str(self.state_dir))).get('rules'))
        except FileNotFoundError:
            raise DoorOpError(404, 'Tunnel not found', code='not_found') from None
        except (OSError, ValueError):
            raise DoorOpError(409, 'Tunnel state file is unreadable') from None
        # ★ only when it widens access.
        widens = (password is None and 'password' in cur) or \
                 (max_opens is None and 'max_opens' in cur)
        if widens and not self.require_stepup():
            return
        out = door_ops.set_rules(self.state_dir, name, password=password, guest=guest,
                                 max_opens=max_opens, history=self.history_path)
        what = [k for k, v in (('password', password), ('guest', guest),
                               ('max_opens', max_opens)) if v is not keep]
        self._audit('door.rules', name, detail=','.join(what))
        self.send_json({'status': 'ok', 'rules': {'password': out['rules']['password'],
                                                  'guest': out['rules']['guest_link'],
                                                  'max_opens': out['rules']['max_opens']},
                        'guest_url': out['guest_url'], 'live_switch': out['live_switch']})

    def api_history_reopen(self, data, name):
        reply = door_ops.reopen(name, data.get('expires'), self.doors_dir, self.state_dir,
                                reopener=self.door_reopener, log=self._door_log)
        self._audit('door.reopen', name)
        self.send_json(reply)

    def api_history_revive(self, data, name):
        plan = door_ops.revive_plan(self.history_path, self.state_dir, name,
                                    log=self._door_log)
        if not self.launch_lock.acquire(blocking=False):
            raise DoorOpError(409, 'Another launch is in progress', code='conflict')
        try:
            reply = door_ops.run_launch(plan, self.door_runner, log=self._door_log)
        finally:
            self.launch_lock.release()
        self._audit('door.revive', name)
        self.send_json(reply)

    def api_history_forget(self, data, name):
        reply = door_ops.forget(self.history_path, name, log=self._door_log)
        self._audit('door.forget', name)
        self.send_json(reply)

    def api_doors_launch(self, data):
        content = data.get('content', '')
        if not isinstance(content, str):
            raise DoorOpError(400, 'content must be a string')
        plan = door_ops.launch_plan(self.state_dir, data.get('type'), data.get('name'),
                                    content=content, view_only=data.get('view_only', False),
                                    expires=data.get('expires'), rules=data.get('rules'))
        if not self.launch_lock.acquire(blocking=False):
            raise DoorOpError(409, 'Another launch is in progress', code='conflict')
        try:
            reply = door_ops.run_launch(plan._replace(timeout=min(plan.timeout, 30)),
                                        self.door_runner, log=self._door_log)
        finally:
            self.launch_lock.release()
        try:
            raw = door_state.read_state(door_state.state_path(plan.name, str(self.state_dir)))
            tok = door_state.clean_rules(raw.get('rules')).get('guest')
            if tok:
                reply['guest_url'] = door_state.guest_url(plan.name, tok)
        except (OSError, ValueError):
            pass
        self._audit('door.launch', plan.name, detail=plan.rtype)
        self.send_json(reply)

    # ---- inspector ----

    def _store(self, name):
        return door_ops.inspect_store_for(self.state_dir, name, self.inspect_base)

    def api_door_requests(self, query, name):
        store = self._store(name)
        since = _int(query.get('since'), 0)
        limit = _int(query.get('limit'), door_ops.REQUESTS_PAGE) or door_ops.REQUESTS_PAGE
        self.send_json({'status': 'ok', **door_ops.requests_page(store, since, limit)})

    def api_door_request(self, query, name, rid):
        store = self._store(name)
        self.send_json({'status': 'ok', 'record': door_ops.request_detail(store, int(rid))})

    def api_door_replay(self, data, name, rid):
        store = self._store(name)
        reply = door_ops.replay(name, store, int(rid), self.inspect_base)
        self._audit('door.replay', name, detail=str(rid))
        self.send_json(reply)

    def api_door_request_events(self, query, name):
        store = self._store(name)
        if not _inspect_slots.acquire(blocking=False):
            self._api_error(429, 'Too many live streams', 'rate_limited', retry_after=10,
                            headers={'Retry-After': '10'})
            return
        try:
            last = (self.headers.get('Last-Event-ID') or '').strip()
            since = int(last) if last.isdigit() and len(last) <= 12 else _int(query.get('since'), 0)
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Accel-Buffering', 'no')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.close_connection = True
            w = self.wfile
            w.write(b'retry: 3000\n\n')
            w.flush()
            tail = inspect_store.Tail(store, since)
            state_file = Path(self.state_dir) / f'{name}.json'
            start = beat = time.monotonic()
            while time.monotonic() - start < self.inspect_max_seconds:
                recs = tail.poll()
                for r in recs:
                    data = json.dumps(inspect_store.summary(r))
                    w.write(f'id: {r["id"]}\nevent: request\ndata: {data}\n\n'.encode('utf-8'))
                if recs:
                    w.flush()
                    beat = time.monotonic()
                elif time.monotonic() - beat >= self.inspect_heartbeat:
                    w.write(b': ping\n\n')
                    w.flush()
                    beat = time.monotonic()
                if not state_file.exists():
                    w.write(b'event: closed\ndata: {}\n\n')
                    w.flush()
                    break
                time.sleep(INSPECT_POLL)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            _inspect_slots.release()


def _int(v, default):
    if isinstance(v, str) and v.isdigit() and len(v) <= 12:
        return int(v)
    return default


def parse_query(raw):
    return {k: v[-1] for k, v in urllib.parse.parse_qs(raw, keep_blank_values=True).items()}

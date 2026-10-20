#!/usr/bin/env python3
"""Ask to reopen: requests from the closed-door page, decided in Pocket.

A visitor on a dead door's page (site/door-closed.html) asks the owner to open
it again. statusserver takes the ask (POST /api/reopen-requests, public) and
stores it here; Pocket (and the panel) list the pending ones and decide; the
visitor's page polls GET /api/reopen-requests/<id>?t=<token> until it is
approved (then reloads into the door), denied, or 30 minutes go by.

Store: <run dir>/reopen/requests.json (lib/rundir.py: tmpfs, 0700 dir, file
0600), every read-modify-write under an flock on .requests.lock, so
statusserver and Pocket (same user, same run dir) never lose each other's
writes. A record:

    {"id", "name", "note", "ip", "created", "real": bool, "state":
     pending|opening|approved|denied, "tokens": [sha256 hex, ...],
     "decided", "expires" (the reopen length), "type", "closed", "reason"}

`real` is False for a name that can't be reopened (no recipe, burned, open
already, unknown): it is stored and answered exactly like a real one, so the
public endpoint never tells which door names exist, but nobody is notified
and it simply runs out ("No answer yet"). Only the sha256 of each visitor
token is kept. A second ask for a door with a pending request joins it (one
more token, at most MAX_TOKENS): one pending request per door.
"""

import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import tempfile
import threading
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import door_state  # noqa: E402

TTL = 30 * 60                 # s a request waits for the owner
KEEP = 30 * 60                # s a decided or expired request is still answered
MAX_PENDING = 50              # across all doors
MAX_TOKENS = 10               # visitors joined to one request
PER_IP = (3, 3600)            # asks per client address per window (s)
NOTE_MAX = 40
BODY_MAX = 1024
DECISION_EXPIRES = ('1h', '24h')
_ID_RE = re.compile(r'^[A-Za-z0-9_-]{16}$')
_TOKEN_RE = re.compile(r'^[A-Za-z0-9_-]{32}$')


class Refused(Exception):
    """An ask that can't be taken (limits). status: the HTTP status to answer."""

    def __init__(self, message, status=429):
        super().__init__(message)
        self.message = message
        self.status = status


def valid_id(rid):
    return isinstance(rid, str) and bool(_ID_RE.match(rid))


def clean_note(text):
    """Printable characters only, whitespace collapsed, at most NOTE_MAX."""
    if not isinstance(text, str):
        return ''
    text = ''.join(c if c.isprintable() else ' ' for c in text[:NOTE_MAX * 4])
    return ' '.join(text.split())[:NOTE_MAX].strip()


def door_for_host(host, tunnel_base):
    """'deck.tunnel.cush.rocks' -> 'deck' (lowercase), or None when the host
    is not exactly one valid door label under the tunnel base."""
    if not isinstance(host, str) or len(host) > 253:
        return None
    host = host.strip().lower().rstrip('.')
    suffix = '.' + tunnel_base.lower()
    if not host.endswith(suffix):
        return None
    label = host[:-len(suffix)]
    if '.' in label or not door_state.NAME_RE.match(label):
        return None
    return label


def _sha(token):
    return hashlib.sha256(token.encode('ascii')).hexdigest()


def default_path():
    import rundir
    return os.path.join(rundir.tool_dir('reopen'), 'requests.json')


class Store:
    """The request file, shared by statusserver and Pocket."""

    def __init__(self, path=None):
        self.path = path or default_path()

    def _lock(self):
        lp = os.path.join(os.path.dirname(self.path), '.requests.lock')
        fd = os.open(lp, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0), 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd

    def _load(self):
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return []
        with os.fdopen(fd, 'rb') as f:
            try:
                data = json.loads(f.read(4 * 1024 * 1024).decode('utf-8'))
            except (ValueError, UnicodeDecodeError):
                return []
        return [r for r in data if isinstance(r, dict) and valid_id(r.get('id'))] \
            if isinstance(data, list) else []

    def _save(self, recs):
        d = os.path.dirname(self.path)
        fd, tmp = tempfile.mkstemp(prefix='.requests.', suffix='.tmp', dir=d)
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(recs, f)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _edit(self, fn, now):
        fd = self._lock()
        try:
            recs = [r for r in self._load() if not self._stale(r, now)]
            out = fn(recs)
            self._save(recs)
            return out
        finally:
            os.close(fd)

    def _read(self, now):
        fd = self._lock()
        try:
            return [r for r in self._load() if not self._stale(r, now)]
        finally:
            os.close(fd)

    @staticmethod
    def _stale(r, now):
        base = r.get('decided') or r.get('created') or 0
        life = KEEP if r.get('decided') else TTL + KEEP
        return now - base > life

    @staticmethod
    def _live(r, now):
        return r.get('state') in ('pending', 'opening') and now - r.get('created', 0) <= TTL

    # ---- the visitor side ----

    def ask(self, name, note, ip, real, info=None, now=None):
        """Store an ask; (id, token, record, joined). Refused past the caps."""
        now = int(time.time() if now is None else now)
        token = secrets.token_urlsafe(24)
        out = {}

        def fn(recs):
            for r in recs:
                if r.get('name') == name and self._live(r, now):
                    if len(r.get('tokens') or []) >= MAX_TOKENS:
                        raise Refused('This door has been asked about enough for now')
                    r['tokens'].append(_sha(token))
                    out.update(rec=dict(r), joined=True)
                    return
            if sum(1 for r in recs if self._live(r, now)) >= MAX_PENDING:
                raise Refused('Too many open requests right now; try again later', 503)
            rec = {'id': secrets.token_urlsafe(12), 'name': name, 'note': clean_note(note),
                   'ip': ip, 'created': now, 'real': bool(real), 'state': 'pending',
                   'tokens': [_sha(token)], 'decided': None, 'expires': None}
            for k in ('type', 'closed', 'reason'):
                if info and info.get(k) is not None:
                    rec[k] = info[k]
            recs.append(rec)
            out.update(rec=dict(rec), joined=False)
        self._edit(fn, now)
        return out['rec']['id'], token, out['rec'], out['joined']

    def status(self, rid, token, now=None):
        """pending | approved | denied | expired, or None for an unknown id or
        a token that is not one of its visitors' (the same answer)."""
        now = int(time.time() if now is None else now)
        if not valid_id(rid) or not isinstance(token, str) or not _TOKEN_RE.match(token):
            return None
        want = _sha(token)
        for r in self._read(now):
            if r.get('id') != rid:
                continue
            if not any(hmac.compare_digest(want, t) for t in r.get('tokens') or []):
                return None
            st = r.get('state')
            if st in ('approved', 'denied'):
                return st
            return 'pending' if now - r.get('created', 0) <= TTL else 'expired'
        return None

    # ---- the owner side ----

    @staticmethod
    def public(r):
        return {k: r.get(k) for k in ('id', 'name', 'note', 'ip', 'created', 'state', 'decided',
                                      'expires', 'type', 'closed', 'reason')} | {
            'waiting': len(r.get('tokens') or []), 'until': r.get('created', 0) + TTL}

    def pending(self, now=None):
        """Real requests still waiting (oldest first), owner view."""
        now = int(time.time() if now is None else now)
        return [self.public(r) for r in self._read(now) if r.get('real') and self._live(r, now)]

    def recent(self, now=None):
        """Real requests still answered: pending plus recently decided."""
        now = int(time.time() if now is None else now)
        return [self.public(r) for r in self._read(now) if r.get('real')]

    def get(self, rid, now=None):
        now = int(time.time() if now is None else now)
        for r in self._read(now):
            if r.get('id') == rid and r.get('real'):
                out = self.public(r)
                if out['state'] in ('pending', 'opening') and now > out['until']:
                    out['state'] = 'expired'
                return out
        return None

    def sig(self):
        try:
            st = os.stat(self.path)
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return None

    def decide(self, rid, decision, expires=None, reopen=None, now=None):
        """allow (reopen the door for `expires`, 1h or 24h) or deny one real
        request. Returns the public record. ValueError for a bad decision,
        LookupError when there is no such pending request, RuntimeError (the
        reopen's message) when the door did not come back; the request is
        then pending again."""
        now = int(time.time() if now is None else now)
        if decision not in ('allow', 'deny'):
            raise ValueError('decision must be allow or deny')
        if decision == 'allow' and expires not in DECISION_EXPIRES:
            raise ValueError('expires must be ' + ' or '.join(DECISION_EXPIRES))
        claimed = {}

        def claim(recs):
            for r in recs:
                if r.get('id') == rid and r.get('real'):
                    if r.get('state') != 'pending' or not self._live(r, now):
                        raise LookupError('That request is not waiting any more')
                    if decision == 'deny':
                        r.update(state='denied', decided=now)
                    else:
                        r['state'] = 'opening'
                    claimed.update(r)
                    return
            raise LookupError('No such request')
        self._edit(claim, now)
        if decision == 'deny':
            return self.public(claimed)
        err = None
        try:
            if reopen is not None:
                reopen(claimed['name'], expires)
        except Exception as e:  # noqa: BLE001
            err = str(e) or 'the door did not reopen'

        def finish(recs):
            for r in recs:
                if r.get('id') == rid:
                    if err:
                        r['state'] = 'pending'
                    else:
                        # Every visitor joined to it is let in.
                        r.update(state='approved', decided=now, expires=expires)
                    claimed.update(r)
        self._edit(finish, now)
        if err:
            raise RuntimeError(err)
        return self.public(claimed)


class RateLimit:
    """`limit` hits per key per `window` seconds, in memory."""

    def __init__(self, limit, window, max_keys=4096):
        self.limit, self.window, self.max_keys = limit, window, max_keys
        self.hits = {}
        self.lock = threading.Lock()

    def hit(self, key, now=None):
        """Record one; False when the key is over the limit (not recorded)."""
        now = time.time() if now is None else now
        with self.lock:
            q = [t for t in self.hits.get(key, ()) if now - t < self.window]
            if len(q) >= self.limit:
                self.hits[key] = q
                return False
            q.append(now)
            self.hits[key] = q
            if len(self.hits) > self.max_keys:
                for k in list(self.hits)[:len(self.hits) - self.max_keys]:
                    del self.hits[k]
            return True


def ago(seconds):
    s = max(0, int(seconds))
    if s < 90:
        return 'just now'
    if s < 3600:
        return f'{round(s / 60)} min ago'
    if s < 86400:
        return f'{round(s / 3600)} h ago'
    return f'{round(s / 86400)} d ago'


def push_payload(rec, now=None):
    """The notification for one real request (Pocket's service worker shows
    title/body; Allow 1h / Allow 24h act on `id`)."""
    now = int(time.time() if now is None else now)
    name = rec.get('name', '')
    bits = []
    if rec.get('note'):
        bits.append(f'From {rec["note"]}.')
    if isinstance(rec.get('closed'), int):
        why = {'expired': 'expired', 'closed': 'was closed'}.get(rec.get('reason'), 'closed')
        bits.append(f'It {why} {ago(now - rec["closed"])}.')
    if rec.get('ip'):
        bits.append(f'Asked from {rec["ip"]}.')
    return {'t': 'reopen', 'id': rec['id'], 'name': name,
            'title': f'Reopen "{name}"?', 'body': ' '.join(bits) or 'Someone is at the door.',
            'url': f'/reopen/{rec["id"]}'}

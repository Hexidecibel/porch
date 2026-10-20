#!/usr/bin/env python3
"""Ask for access: requests from the gate pages, decided in Pocket or the CLI.

A visitor HAProxy sent to the auth host's gate page (lib/gate_pages.py) for a
gated app asks the owner to let them in. The auth server takes the ask
(POST /auth/access-requests, public) and keeps it here; the owner lists the
pending ones and decides through the CLI-token admin API
(/auth/admin/access-requests, used by Pocket and `bin/auth-admin access`).
The visitor's page polls GET /auth/access-requests/<id>?t=<token> until it is
approved, denied, or 30 minutes go by.

Two kinds of asker:
  device    a browser with a live device that lacks the host. Allow adds the
            host to that device's scope, so HAProxy lets it straight in.
  stranger  no device, or one that ran out (`expired`). Allow mints a
            single-use invite for exactly that host; its URL goes back to the
            visitor in their own poll answer (the token proves it is them) and
            nowhere else: never logged, never in the owner's views.

The store is memory only (one auth server process owns it): a restart drops
open asks and the visitor's page says "No answer yet". A record:

    {"id", "host", "note", "ip", "created", "real", "kind", "device_id",
     "device_name", "rd", "state": pending|granting|approved|denied,
     "tokens": [sha256 hex, ...], "decided", "how": device|invite|None,
     "invite_id", "invite_url" (private)}

`real` is False for a host that is not a gated app (or that the device can
already open): stored and answered exactly like a real one, so the public
endpoint never tells which hosts exist, but nobody is told and it runs out.
Only the sha256 of each visitor token is kept. One pending request per
(host, device) or (host, address): a second ask joins it (one more token, at
most MAX_TOKENS).
"""

import hashlib
import hmac
import re
import secrets
import threading
import time

TTL = 30 * 60                 # s a request waits for the owner
KEEP = 30 * 60                # s a decided request is still answered
MAX_PENDING = 50              # across all hosts
MAX_TOKENS = 10               # visitors joined to one request
PER_IP = (3, 3600)            # asks per client address per window (s)
NOTE_MAX = 40
BODY_MAX = 1024
POLL = 4                      # s between the visitor's polls
INVITE_HOURS = 1              # how long a stranger's invite link stays good
KINDS = ('device', 'stranger', 'expired')
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


def _sha(token):
    return hashlib.sha256(token.encode('ascii')).hexdigest()


class Store:
    """The open asks, in memory, under one lock."""

    def __init__(self, clock=time.time):
        self.clock = clock
        self.lock = threading.Lock()
        self.recs = []

    def _now(self, now):
        return int(self.clock() if now is None else now)

    @staticmethod
    def _stale(r, now):
        base = r.get('decided') or r.get('created') or 0
        life = KEEP if r.get('decided') else TTL + KEEP
        return now - base > life

    @staticmethod
    def _live(r, now):
        return r.get('state') in ('pending', 'granting') and now - r.get('created', 0) <= TTL

    def _prune(self, now):
        self.recs = [r for r in self.recs if not self._stale(r, now)]

    # ---- the visitor side ----

    def ask(self, host, note, ip, real, kind='stranger', device_id=None, device_name=None,
            rd=None, now=None):
        """Store an ask; (id, token, record copy, joined). Refused past the caps."""
        now = self._now(now)
        token = secrets.token_urlsafe(24)
        who = ('dev', device_id) if device_id else ('ip', ip)
        with self.lock:
            self._prune(now)
            for r in self.recs:
                if r.get('host') == host and r.get('who') == who and self._live(r, now):
                    if len(r['tokens']) >= MAX_TOKENS:
                        raise Refused('You have asked about this enough for now')
                    r['tokens'].append(_sha(token))
                    if note and not r.get('note'):
                        r['note'] = clean_note(note)
                    return r['id'], token, dict(r), True
            if sum(1 for r in self.recs if self._live(r, now)) >= MAX_PENDING:
                raise Refused('Too many open requests right now; try again later', 503)
            rec = {'id': secrets.token_urlsafe(12), 'host': host, 'note': clean_note(note),
                   'ip': ip, 'created': now, 'real': bool(real),
                   'kind': kind if kind in KINDS else 'stranger',
                   'device_id': device_id, 'device_name': (device_name or '')[:64] or None,
                   'rd': rd, 'who': who, 'state': 'pending', 'tokens': [_sha(token)],
                   'decided': None, 'how': None, 'invite_id': None, 'invite_url': None}
            self.recs.append(rec)
            return rec['id'], token, dict(rec), False

    def status(self, rid, token, now=None):
        """The visitor's answer: {'state': pending|approved|denied|expired}
        plus, once approved, 'invite' (a stranger's one-time link) or 'rd'.
        None for an unknown id or a token that is not one of its visitors'
        (the same answer)."""
        now = self._now(now)
        if not valid_id(rid) or not isinstance(token, str) or not _TOKEN_RE.match(token):
            return None
        want = _sha(token)
        with self.lock:
            self._prune(now)
            for r in self.recs:
                if r.get('id') != rid:
                    continue
                if not any(hmac.compare_digest(want, t) for t in r['tokens']):
                    return None
                st = r.get('state')
                if st == 'approved':
                    out = {'state': 'approved'}
                    if r.get('invite_url'):
                        out['invite'] = r['invite_url']
                    elif r.get('rd'):
                        out['rd'] = r['rd']
                    return out
                if st == 'denied':
                    return {'state': 'denied'}
                return {'state': 'pending' if now - r.get('created', 0) <= TTL else 'expired'}
        return None

    # ---- the owner side ----

    @staticmethod
    def public(r, now):
        """The owner's view of one request: never the tokens or an invite URL."""
        state = r.get('state')
        if state in ('pending', 'granting') and now - r.get('created', 0) > TTL:
            state = 'expired'
        return {k: r.get(k) for k in ('id', 'host', 'note', 'ip', 'created', 'kind',
                                      'device_id', 'device_name', 'decided', 'how',
                                      'invite_id')} | {
            'state': state, 'waiting': len(r.get('tokens') or []),
            'until': r.get('created', 0) + TTL}

    def pending(self, now=None):
        """Real requests still waiting (oldest first)."""
        now = self._now(now)
        with self.lock:
            self._prune(now)
            return [self.public(r, now) for r in self.recs if r.get('real') and self._live(r, now)]

    def recent(self, now=None):
        """Real requests still answered: pending plus recently decided."""
        now = self._now(now)
        with self.lock:
            self._prune(now)
            return [self.public(r, now) for r in self.recs if r.get('real')]

    def get(self, rid, now=None):
        now = self._now(now)
        with self.lock:
            for r in self.recs:
                if r.get('id') == rid and r.get('real'):
                    return self.public(r, now)
        return None

    def decide(self, rid, decision, grant=None, now=None):
        """allow or deny one real pending request; the owner's view after.

        allow calls grant(record copy) outside the lock; it returns
        {'how': 'device'} or {'how': 'invite', 'invite_id', 'invite_url'}.
        ValueError for a bad decision, LookupError when there is no such
        pending request, RuntimeError (grant's message) when the grant
        failed; the request is then pending again."""
        now = self._now(now)
        if decision not in ('allow', 'deny'):
            raise ValueError('decision must be allow or deny')
        with self.lock:
            self._prune(now)
            rec = next((r for r in self.recs if r.get('id') == rid and r.get('real')), None)
            if rec is None:
                raise LookupError('No such request')
            if rec.get('state') != 'pending' or not self._live(rec, now):
                raise LookupError('That request is not waiting any more')
            if decision == 'deny':
                rec.update(state='denied', decided=now)
                return self.public(rec, now)
            rec['state'] = 'granting'
            snapshot = dict(rec)
        err, out = None, {}
        try:
            out = (grant(snapshot) if grant is not None else {}) or {}
        except Exception as e:  # noqa: BLE001
            err = str(e) or 'the grant failed'
        with self.lock:
            if err:
                rec['state'] = 'pending'
                raise RuntimeError(err)
            rec.update(state='approved', decided=now, how=out.get('how'),
                       invite_id=out.get('invite_id'), invite_url=out.get('invite_url'))
            return self.public(rec, now)


class RateLimit:
    """`limit` hits per key per `window` seconds, in memory."""

    def __init__(self, limit, window, max_keys=4096, clock=time.time):
        self.limit, self.window, self.max_keys = limit, window, max_keys
        self.clock = clock
        self.hits = {}
        self.lock = threading.Lock()

    def hit(self, key, now=None):
        """Record one; False when the key is over the limit (not recorded)."""
        now = self.clock() if now is None else now
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


def push_payload(rec):
    """The notification for one real request (Pocket's service worker shows
    title/body; a tap opens /#/requests/access/<id>; no buttons, since
    allowing needs a step-up)."""
    host = rec.get('host', '')
    who = rec.get('note') or ''
    bits = []
    if rec.get('kind') == 'device' and rec.get('device_name'):
        bits.append(f'{who + " on " if who else ""}{rec["device_name"]} wants it added to their pass.')
    elif rec.get('kind') == 'expired':
        bits.append(f'{who + ": " if who else ""}their pass ran out.')
    elif who:
        bits.append(f'From {who}.')
    if rec.get('ip'):
        bits.append(f'Asked from {rec["ip"]}.')
    return {'t': 'access', 'id': rec['id'], 'host': host,
            'title': f'Let someone into {host}?',
            'body': ' '.join(bits) or 'Someone is asking for access.'}

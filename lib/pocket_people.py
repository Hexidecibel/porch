"""Pocket's people and requests API (/api/people*, /api/requests*) through
porch-auth's CLI-token API (lib/auth_client.py), plus AuthWatcher.

Every answer is rebuilt from a whitelist of fields, never passed through as
porch-auth sent it. The CLI token stays in auth_client (read per call from
data/.admin-cli-token); it is never logged, echoed or put in an error.
An invite's URL is in the create answer once and nowhere else (not logged,
not audited, not kept).

AuthWatcher polls /auth/admin/state (every 5s, every 30s while porch-auth is
down). On a change (ignoring last_seen and run_id_history) it bumps the hub's
`people` counter; a new pending pairing pushes {t: 'pairing'} (topic
`pairing`), an invite whose uses went up or that minted a new device pushes
{t: 'invite'} (topic `invite`) and is remembered in `accepts` (last 20), and
a new Ask for access (lib/access_requests.py, the gate pages) pushes
{t: 'access'} (topic `access`). The first good poll after start only seeds:
it never pushes.
"""

import collections
import hashlib
import json
import os
import re
import sys
import threading
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import access_requests  # noqa: E402  (push_payload for an Ask for access)
import auth_client  # noqa: E402

PAIRING_CODE = re.compile(r'^[A-Z]{4}-[0-9]{4}$')
DEVICE_ID = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
INVITE_ID = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
PUBLIC_ID = re.compile(r'^pp_[0-9a-f]{8}$')
HOST_RE = re.compile(r'^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
                     r'(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$')
POLL = 5
POLL_DOWN = 30
STALE_AFTER = 90
PROBE_EVERY = 600
MAX_ACCEPTS = 20
MIN_ADMIN_PASSWORD = 12
_CTRL = re.compile(r'[\x00-\x1f\x7f]')


def _s(v, n=80):
    return _CTRL.sub(' ', v)[:n] if isinstance(v, str) else ''


def _num(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def _hosts(v):
    return [h for h in v if isinstance(h, str)][:200] if isinstance(v, list) else None


# ---- whitelists -----------------------------------------------------------------

def public_device(d, me=None):
    p = d.get('pass') if isinstance(d.get('pass'), dict) else None
    return {
        'id': _s(d.get('id'), 64), 'name': _s(d.get('name'), 64),
        'type': 'browser' if d.get('type') == 'browser' else 'tunnel',
        'apps': _hosts(d.get('apps')),
        'pass': {'apps': _hosts(p.get('apps')) or [], 'expires_at': _num(p.get('expires_at')),
                 'invite_id': _s(p.get('invite_id'), 64) or None} if p else None,
        'role': d.get('role') if d.get('role') in ('admin', 'guest') else None,
        'tunnel_admin': d.get('tunnel_admin') if isinstance(d.get('tunnel_admin'), bool) else None,
        'revoked': bool(d.get('revoked')),
        'created_at': _num(d.get('created_at')), 'expires_at': _num(d.get('expires_at')),
        'last_seen': _num(d.get('last_seen')),
        'invite_id': _s(d.get('invite_id'), 64) or None,
        'run_ids': [_s(r, 64) for r in d.get('run_id_history') or [] if isinstance(r, str)][-5:]
        if isinstance(d.get('run_id_history'), list) else [],
        'this': bool(me) and d.get('id') == me,
    }


def public_invite(i):
    return {
        'id': _s(i.get('id'), 64), 'note': _s(i.get('note'), 80), 'apps': _hosts(i.get('apps')) or [],
        'landing': _s(i.get('landing'), 253) or None, 'uses': _num(i.get('uses')) or 0,
        'max_uses': _num(i.get('max_uses')), 'live': _num(i.get('live')) or 0,
        'standing': bool(i.get('standing')),
        'device_ttl_minutes': _num(i.get('device_ttl_minutes')),
        'status': _s(i.get('status'), 20), 'expires_at': _num(i.get('expires_at')),
        'created_at': _num(i.get('created_at')),
        'devices': [{'id': _s(x.get('id'), 64), 'name': _s(x.get('name'), 64)}
                    for x in i.get('devices') or [] if isinstance(x, dict)][:200],
    }


def public_pairing(p):
    return {'code': _s(p.get('code'), 9), 'device_name': _s(p.get('device_name'), 64),
            'kind': 'web' if p.get('kind') == 'web' else 'tunnel',
            'created_at': _num(p.get('created_at')), 'expires_at': _num(p.get('expires_at'))}


def public_path(p):
    return {
        'id': _s(p.get('id'), 16), 'host': _s(p.get('host'), 253), 'path': _s(p.get('path'), 128),
        'kind': 'prefix' if p.get('kind') == 'prefix' else 'exact',
        'app': _s(p.get('app'), 40), 'why': _s(p.get('why'), 120),
        'created_at': _num(p.get('created_at')), 'created_by': _s(p.get('created_by'), 16),
        'enabled': bool(p.get('enabled')), 'active': bool(p.get('active')),
        'inactive': _s(p.get('inactive'), 40) or None,
    }


ACCESS_ID = re.compile(r'^[A-Za-z0-9_-]{16}$')
ACCESS_STATES = ('pending', 'granting', 'approved', 'denied', 'expired')


def public_access(r):
    """One Ask for access, owner view (porch-auth never sends tokens or links)."""
    return {
        'id': _s(r.get('id'), 16), 'host': _s(r.get('host'), 253), 'note': _s(r.get('note'), 40),
        'ip': _s(r.get('ip'), 64) or None,
        'kind': r.get('kind') if r.get('kind') in access_requests.KINDS else 'stranger',
        'device_id': _s(r.get('device_id'), 64) or None,
        'device_name': _s(r.get('device_name'), 64) or None,
        'state': r.get('state') if r.get('state') in ACCESS_STATES else 'expired',
        'how': r.get('how') if r.get('how') in ('device', 'invite') else None,
        'invite_id': _s(r.get('invite_id'), 64) or None,
        'created': _num(r.get('created')), 'decided': _num(r.get('decided')),
        'until': _num(r.get('until')), 'waiting': _num(r.get('waiting')) or 1,
    }


def access_view(state):
    return [public_access(r) for r in _list(state, 'access_requests')
            if ACCESS_ID.match(str(r.get('id') or ''))]


def _list(state, key):
    v = state.get(key) if isinstance(state, dict) else None
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


def people_view(state, me=None):
    return {
        'devices': [public_device(d, me) for d in _list(state, 'devices')],
        'invites': [public_invite(i) for i in _list(state, 'invites')],
        'apps': [{'host': _s(a.get('host'), 253), 'protected': bool(a.get('protected'))}
                 for a in _list(state, 'known_hosts')],
        'public_paths': [public_path(p) for p in _list(state, 'public_paths')
                         if PUBLIC_ID.match(str(p.get('id') or ''))],
    }


def pairings_view(state):
    return [public_pairing(p) for p in _list(state, 'pairings')
            if PAIRING_CODE.match(str(p.get('code') or ''))]


def digest(state):
    """What counts as a change: everything but last_seen and run_id_history."""
    s = {'pairings': pairings_view(state), 'access': access_view(state), 'invites': [public_invite(i) for i in _list(state, 'invites')],
         'apps': people_view(state)['apps'],
         'public_paths': people_view(state)['public_paths'],
         'devices': [{k: v for k, v in public_device(d).items()
                      if k not in ('last_seen', 'run_ids', 'this')}
                     for d in _list(state, 'devices')]}
    return hashlib.sha256(json.dumps(s, sort_keys=True).encode()).hexdigest()


# ---- the watcher ----------------------------------------------------------------

class AuthWatcher:

    def __init__(self, client, bump=None, push=None, clock=time.time, interval=POLL,
                 down_interval=POLL_DOWN, log=None):
        self.client = client
        self.bump = bump or (lambda: None)
        self.push = push or (lambda payload, topic: None)
        self.clock = clock
        self.interval, self.down_interval = interval, down_interval
        self.log = log or (lambda m: sys.stderr.write(f"[pocketserver] {m}\n"))
        self.lock = threading.Lock()
        self.snapshot = None         # last good /auth/admin/state
        self.last_ok = None          # clock() of it
        self.last_error = None       # None | 'down' | 'error'
        self.digest = None
        self.seeded = False
        self.accepts = collections.deque(maxlen=MAX_ACCEPTS)
        self.caps = {'rename': None, 'verify': None}
        self.probed = None
        self._stop = threading.Event()
        self._thread = None

    # -- state --

    def auth_state(self):
        with self.lock:
            if self.last_error is not None:
                return 'down'
            if self.last_ok is None or self.clock() - self.last_ok > STALE_AFTER:
                return 'stale' if self.snapshot is not None else 'down'
            if self.caps.get('verify') is False or self.caps.get('rename') is False:
                return 'old'
            return 'ok'

    def current(self):
        with self.lock:
            return self.snapshot

    def recent_accepts(self):
        with self.lock:
            return list(reversed(self.accepts))

    # -- one poll --

    def probe(self):
        """Does porch-auth have verify-password / device-rename? A body the
        endpoint refuses (400) means yes, 404 'not found' means no. Never a
        password attempt: the body is a JSON list."""
        caps = {}
        for key, path in (('verify', '/auth/admin/verify-password'),
                          ('rename', '/auth/admin/device-rename')):
            try:
                self.client.request('POST', path, [])
                caps[key] = True
            except auth_client.AuthError as e:
                caps[key] = not (e.status == 404 and e.message == 'not found')
            except auth_client.AuthDown:
                return
        with self.lock:
            self.caps.update(caps)
            self.probed = self.clock()

    def poll_once(self):
        try:
            state = self.client.state()
        except (auth_client.AuthDown, auth_client.TokenError):
            with self.lock:
                was = self.last_error
                self.last_error = 'down'
            if was != 'down':
                self.log('auth watcher: porch-auth is not answering')
                self.bump()
            return False
        except auth_client.AuthError as e:
            with self.lock:
                was = self.last_error
                self.last_error = 'error'
            if was != 'error':
                self.log(f'auth watcher: porch-auth answered {e.status}')
                self.bump()
            return False
        if not isinstance(state, dict) or state.get('needs_setup'):
            state = {}
        recovered = self.last_error is not None or self.last_ok is None
        if recovered or self.probed is None or self.clock() - self.probed > PROBE_EVERY:
            self.probe()
        d = digest(state)
        with self.lock:
            prev, seeded = self.snapshot, self.seeded
            self.snapshot, self.last_ok, self.last_error = state, self.clock(), None
            changed = d != self.digest
            self.digest, self.seeded = d, True
        if recovered:
            self.log('auth watcher: ok')
        if seeded and prev is not None:
            self._diff(prev, state)
        if changed or recovered:
            self.bump()
        return True

    def _diff(self, prev, state):
        old_codes = {p['code'] for p in pairings_view(prev)}
        for p in pairings_view(state):
            if p['code'] in old_codes:
                continue
            what = 'browser' if p['kind'] == 'web' else 'machine'
            self._push({'t': 'pairing', 'code': p['code'], 'device_name': p['device_name'],
                        'kind': p['kind'], 'title': f'A new {what} wants in',
                        'body': f"{p['device_name'] or 'Unnamed'} · code {p['code']}"},
                       'pairing')
        old_access = {a['id'] for a in access_view(prev)}
        for a in access_view(state):
            if a['id'] in old_access or a['state'] != 'pending':
                continue
            self._push(access_requests.push_payload(a), 'access')
        old = {i['id']: i for i in (public_invite(x) for x in _list(prev, 'invites'))}
        for inv in (public_invite(x) for x in _list(state, 'invites')):
            before = old.get(inv['id'], {'uses': 0, 'devices': []})
            seen = {d['id'] for d in before['devices']}
            new_devs = [d for d in inv['devices'] if d['id'] not in seen]
            if inv['uses'] <= before['uses'] and not new_devs:
                continue
            name = new_devs[-1]['name'] if new_devs else ''
            acc = {'invite_id': inv['id'], 'note': inv['note'], 'device_name': name,
                   'at': int(self.clock())}
            with self.lock:
                self.accepts.append(acc)
            label = inv['note'] or 'An invite'
            self._push({'t': 'invite', 'invite_id': inv['id'], 'note': inv['note'],
                        'device_name': name, 'title': f'{label} was used',
                        'body': f'It let in {name}.' if name else 'Someone accepted it.'},
                       'invite')

    def _push(self, payload, topic):
        try:
            self.push(payload, topic)
        except Exception as e:  # noqa: BLE001  (a push never stops the watcher)
            self.log(f'auth watcher: push failed ({e.__class__.__name__})')

    # -- thread --

    def start(self):
        self._thread = threading.Thread(target=self._run, name='auth-watcher', daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.is_set():
            try:
                ok = self.poll_once()
            except Exception as e:  # noqa: BLE001
                self.log(f'auth watcher: {e.__class__.__name__}')
                ok = False
            self._stop.wait(self.interval if ok else self.down_interval)


# ---- the handler side -------------------------------------------------------------

class AuthOpError(Exception):
    def __init__(self, status, message, code=None, **extra):
        super().__init__(message)
        self.status, self.message, self.code, self.extra = status, message, code, extra


class PeopleMixin:
    auth = None                 # auth_client.Client; None = no porch-auth (auth_down)
    watcher = None              # AuthWatcher

    def _auth(self, fn, *args, old_ok=False):
        """Call porch-auth; map its failures to AuthOpError."""
        if self.auth is None:
            raise AuthOpError(503, "porch-auth isn't configured for this pocket", 'auth_down')
        try:
            out = fn(*args)
        except (auth_client.AuthDown, auth_client.TokenError):
            raise AuthOpError(503, "porch-auth isn't answering; doors still work",
                              'auth_down') from None
        except auth_client.AuthError as e:
            if e.status == 404 and e.message == 'not found':
                raise AuthOpError(501, 'update porch-auth (bin/auth-deploy)', 'auth_old') from None
            if e.status == 404:
                raise AuthOpError(404, _s(e.message, 200) or 'Not found', 'not_found') from None
            if e.status in (400, 409, 410):
                raise AuthOpError(e.status, _s(e.message, 200) or 'Refused',
                                  'conflict' if e.status == 409 else None) from None
            if e.status == 429:
                raise AuthOpError(429, 'Too many attempts; wait a minute', 'rate_limited',
                                  retry_after=60) from None
            raise AuthOpError(502, f'porch-auth answered {e.status}', 'auth_error') from None
        if self.watcher is not None and getattr(fn, '__name__', '') not in ('state', 'public_paths'):
            # A write: let the watcher see it now rather than in 5s.
            threading.Thread(target=self.watcher.poll_once, daemon=True).start()
        return out

    def auth_info(self):
        w = self.watcher
        if w is None:
            return {'state': 'down' if self.auth is None else 'stale',
                    'can_rename': False, 'can_verify_password': False}
        return {'state': w.auth_state(), 'can_rename': w.caps.get('rename') is not False,
                'can_verify_password': w.caps.get('verify') is not False}

    def _me(self):
        return (self.owner_ctx() or {}).get('device_id')

    def _fresh_auth(self):
        """auth_info() right after a successful call: it answers, so only
        'old' (missing endpoints) can still be said about it."""
        info = self.auth_info()
        if info['state'] != 'old':
            info['state'] = 'ok'
        return info

    def people_reply(self, state):
        return {'status': 'ok', **people_view(state, self._me()), 'auth': self._fresh_auth()}

    # ---- reads ----

    def api_people(self, query):
        state = self._auth(self.auth.state if self.auth else None)
        self.send_json(self.people_reply(state))

    def api_requests(self, query):
        out = {'status': 'ok', 'reopen': self._requests(), 'pairings': [], 'access': [],
               'accepts': []}
        try:
            state = self._auth(self.auth.state if self.auth else None)
            out['pairings'] = pairings_view(state)
            out['access'] = access_view(state)
            out['auth'] = self._fresh_auth()
        except AuthOpError as e:
            out['auth'] = dict(self.auth_info(), state='old' if e.code == 'auth_old' else 'down')
        if self.watcher is not None:
            out['accepts'] = self.watcher.recent_accepts()
        self.send_json(out)

    def people_event(self):
        """The `people` SSE payload, from the watcher's snapshot (no call)."""
        w = self.watcher
        state = w.current() if w is not None else None
        view = people_view(state or {}, self._me())
        return {**view, 'pairings': pairings_view(state or {}), 'access': access_view(state or {}),
                'accepts': w.recent_accepts() if w is not None else [],
                'auth': self.auth_info()}

    # ---- pairings ----

    def _pairing(self, code):
        state = self._auth(self.auth.state)
        for p in pairings_view(state):
            if p['code'] == code:
                return p
        raise AuthOpError(404, 'No such pending pairing (it may have expired)', 'not_found')

    def api_pairing_approve(self, data, code):
        p = self._pairing(code)
        apps = data.get('apps')
        tunnel_admin = data.get('tunnel_admin', False)
        if not isinstance(tunnel_admin, bool):
            raise AuthOpError(400, 'tunnel_admin must be true or false')
        if p['kind'] == 'web':
            apps = self._apps_arg(apps, data)
            if tunnel_admin:
                raise AuthOpError(400, 'tunnel_admin is for machines, not browsers')
        else:
            apps = None
        out = self._auth(self.auth.approve, code, apps)
        dev = out.get('device_id') if isinstance(out.get('device_id'), str) else None
        if p['kind'] != 'web' and tunnel_admin and dev:
            self._auth(self.auth.device_role, dev, 'admin')
        self._audit('pairing.approve', code, detail=p['kind'] + (' admin' if tunnel_admin else ''))
        self.send_json({'status': 'ok', 'device_id': dev, 'kind': p['kind'],
                        'tunnel_admin': bool(tunnel_admin and p['kind'] != 'web')})

    def api_pairing_reject(self, data, code):
        self._auth(self.auth.reject, code)
        self._audit('pairing.reject', code)
        self.send_json({'status': 'ok'})

    # ---- Ask for access (the gate pages) ----

    def _access_reply(self, out, decision, rid):
        rec = public_access(out.get('request')) if isinstance(out.get('request'), dict) else None
        self._audit('access.' + decision, (rec or {}).get('host') or rid,
                    detail=((rec or {}).get('how') or '') if decision == 'allow' else '')
        self.send_json({'status': 'ok', 'request': rec})

    def api_access_allow(self, data, rid):
        """★ (route table): letting someone in widens access. A device gets
        the host added to its pass; a stranger a one-time invite that only
        their own page sees. device_ttl_minutes: how long a stranger's new
        device lasts (null = for good)."""
        ttl = data.get('device_ttl_minutes')
        if ttl is not None and (not isinstance(ttl, int) or isinstance(ttl, bool)
                                or not 1 <= ttl <= 30 * 24 * 60):
            raise AuthOpError(400, 'device_ttl_minutes must be 1 to 43200 or null')
        out = self._auth(self.auth.access_decide, rid, 'allow', ttl)
        self._access_reply(out, 'allow', rid)

    def api_access_deny(self, data, rid):
        out = self._auth(self.auth.access_decide, rid, 'deny')
        self._access_reply(out, 'deny', rid)

    # ---- devices ----

    def _apps_arg(self, apps, data):
        if apps == ['*']:
            if data.get('confirm_all') is not True:
                raise AuthOpError(400, 'All apps gives owner-level reach; confirm it',
                                  'confirm_all')
            return apps
        if not isinstance(apps, list) or not apps or len(apps) > 100 or \
                not all(isinstance(h, str) and HOST_RE.match(h.strip().lower()) for h in apps):
            raise AuthOpError(400, 'apps must be a list of hosts (or ["*"])')
        return [h.strip().lower() for h in apps]

    def api_device_revoke(self, data, did):
        if did == self._me() and data.get('confirm_self') is not True:
            raise AuthOpError(400, 'This is the browser you are using; confirm it',
                              'confirm_self')
        self._auth(self.auth.revoke, did)
        self._audit('device.revoke', did)
        self.send_json({'status': 'ok'})

    def api_device_role(self, data, did):
        role = data.get('role')
        if role not in ('admin', 'guest'):
            raise AuthOpError(400, 'role must be admin or guest')
        out = self._auth(self.auth.device_role, did, role)
        self._audit('device.role', did, detail=role)
        self.send_json({'status': 'ok', 'role': role,
                        'tunnel_admin': out.get('tunnel_admin') if isinstance(
                            out.get('tunnel_admin'), bool) else None})

    def api_device_apps(self, data, did):
        apps = self._apps_arg(data.get('apps'), data)
        self._auth(self.auth.device_apps, did, apps)
        self._audit('device.apps', did, detail=','.join(apps)[:100])
        self.send_json({'status': 'ok', 'apps': apps})

    def api_device_rename(self, data, did):
        name = data.get('name')
        name = name.strip() if isinstance(name, str) else ''
        if not name or len(name) > 64 or not name.isprintable():
            raise AuthOpError(400, 'name must be 1 to 64 printable characters')
        self._auth(self.auth.device_rename, did, name)
        self._audit('device.rename', did)
        self.send_json({'status': 'ok', 'name': name})

    # ---- invites + apps ----

    def api_invite_create(self, data):
        apps = data.get('apps')
        if apps == ['*']:
            raise AuthOpError(400, 'an invite cannot grant all apps; list the hosts')
        apps = self._apps_arg(apps, data)
        body = {'apps': apps}
        note = data.get('note', '')
        if not isinstance(note, str) or len(note) > 80:
            raise AuthOpError(400, 'note must be at most 80 characters')
        body['note'] = note
        if data.get('landing') not in (None, ''):
            if not isinstance(data['landing'], str):
                raise AuthOpError(400, 'invalid landing')
            body['landing'] = data['landing']
        standing = data.get('standing', False)
        if not isinstance(standing, bool):
            raise AuthOpError(400, 'standing must be true or false')
        body['standing'] = standing
        for key in ('expires_hours', 'max_uses', 'device_ttl_minutes'):
            if key in data:
                v = data[key]
                if v is not None and (not isinstance(v, int) or isinstance(v, bool)):
                    raise AuthOpError(400, f'{key} must be a whole number or null')
                body[key] = v
        out = self._auth(self.auth.invite_create, body)
        url = out.get('url')
        inv = out.get('invite') if isinstance(out.get('invite'), dict) else {}
        if not isinstance(url, str) or not url.startswith('https://'):
            raise AuthOpError(502, 'porch-auth sent no invite link', 'auth_error')
        self._audit('invite.create', _s(inv.get('id'), 64),
                    detail='standing' if standing else 'one-time')
        # The link is in this answer and nowhere else.
        self.send_json({'status': 'ok', 'invite': public_invite(inv), 'url': url}, 201)

    def api_invite_revoke(self, data, iid):
        revoke_devices = data.get('revoke_devices', False)
        if not isinstance(revoke_devices, bool):
            raise AuthOpError(400, 'revoke_devices must be true or false')
        if revoke_devices and not self.require_stepup():
            return
        self._auth(self.auth.invite_revoke, iid, revoke_devices)
        self._audit('invite.revoke', iid, detail='with devices' if revoke_devices else '')
        self.send_json({'status': 'ok'})

    def api_apps(self, data):
        host = data.get('host')
        action = data.get('action')
        if action not in ('protect', 'unprotect', 'forget'):
            raise AuthOpError(400, 'action must be protect, unprotect or forget')
        if not isinstance(host, str) or not HOST_RE.match(host.strip().lower()):
            raise AuthOpError(400, 'host must be a host name')
        host = host.strip().lower()
        self._auth(self.auth.apps, host, action)
        self._audit('app.' + action, host)
        self.send_json({'status': 'ok', 'host': host, 'action': action})

    # ---- public paths (on gated apps) ----

    def _public_reply(self, out, status=200, **extra):
        items = [public_path(p) for p in out.get('public_paths') or [] if isinstance(p, dict)]
        entry = out.get('entry')
        hap = out.get('haproxy')
        self.send_json({'status': 'ok', 'entry': public_path(entry) if isinstance(entry, dict)
                        else None, 'public_paths': items,
                        'haproxy': _s(hap, 120) if isinstance(hap, str) else None, **extra},
                       status)

    def api_public_paths(self, query):
        out = self._auth(self.auth.public_paths if self.auth else None)
        items = [public_path(p) for p in out.get('public_paths') or [] if isinstance(p, dict)]
        self.send_json({'status': 'ok', 'public_paths': items,
                        'max': _num(out.get('max'))})

    def api_public_path_add(self, data):
        """★ (route table): opening a path widens access."""
        host, path = data.get('host'), data.get('path')
        app, why = data.get('app'), data.get('why', '')
        if not isinstance(host, str) or not HOST_RE.match(host.strip().lower()):
            raise AuthOpError(400, 'host must be a host name')
        if not isinstance(path, str) or not path.startswith('/') or len(path) > 128:
            raise AuthOpError(400, 'path must start with / (at most 128 characters)')
        if not isinstance(app, str) or not app.strip() or len(app) > 40:
            raise AuthOpError(400, 'app must be 1 to 40 characters')
        if not isinstance(why, str) or len(why) > 120:
            raise AuthOpError(400, 'why must be at most 120 characters')
        host = host.strip().lower()
        out = self._auth(lambda: self.auth.public_path(
            'add', 'pocket', host=host, path=path, app=app.strip(), why=why.strip()))
        self._audit('public.add', host + path, detail=_s(app, 40))
        self._public_reply(out, 201)

    def _public_switch(self, pid, action):
        if not PUBLIC_ID.match(pid):
            raise AuthOpError(400, 'invalid public path id')
        out = self._auth(lambda: self.auth.public_path(action, 'pocket', id=pid))
        entry = out.get('entry') if isinstance(out.get('entry'), dict) else {}
        target = (_s(entry.get('host'), 253) + _s(entry.get('path'), 128)) or pid
        self._audit({'enable': 'public.on', 'disable': 'public.off',
                     'remove': 'public.remove'}[action], target, detail=pid)
        self._public_reply(out)

    def api_public_path_on(self, data, pid):
        """★ (route table): switching a path back on widens access."""
        self._public_switch(pid, 'enable')

    def api_public_path_off(self, data, pid):
        self._public_switch(pid, 'disable')

    def api_public_path_remove(self, data, pid):
        self._public_switch(pid, 'remove')

    def api_password(self, data):
        cur, new = data.get('current'), data.get('new')
        if not isinstance(cur, str) or not cur or len(cur) > 1024:
            raise AuthOpError(400, 'Enter the current password')
        if not isinstance(new, str) or not MIN_ADMIN_PASSWORD <= len(new) <= 1024:
            raise AuthOpError(400, f'The new password needs at least {MIN_ADMIN_PASSWORD} '
                              'characters')
        if self._blocked():
            return
        ok = self._verify_admin_password(cur)
        if ok is None:
            return
        if not ok:
            self._failed('password-change', 'bad_password', message='The current password is not right')
            return
        self._auth(self.auth.set_password, new)
        self._audit('password.change', 'admin')
        self.send_json({'status': 'ok'})

"""Pocket step-up: "confirm it's you" before a privileged action, with a
passkey (WebAuthn, lib/porch_webauthn.py) or the porch-auth admin password.

    PasskeyStore     ~/pocket/<name>/.passkeys.json (0600, atomic, locked)
    ChallengeStore   WebAuthn challenges in memory: single use, 120s, bound
                     to the purpose, the owner's device and owner cookie
    StepUpStore      step-up sessions in memory: sha256(cookie token) ->
                     {device_id, owner_sha, method, expires}; fixed 5 minutes
    StepUpMixin      the routes (/api/stepup/*, /api/passkeys*) and the
                     require_stepup() guard the route table calls for ★ routes

A step-up is the cookie `__Host-pocket_stepup` (Secure, HttpOnly,
SameSite=Strict, Path=/, Max-Age=300) plus the server record it names. It
counts only on a request that also carries the same owner cookie (porch_host,
or the legacy cush_auth) of the same device: the step-up cookie alone is
worth nothing, and it dies with the owner session. A restart forgets every
step-up.

Failures (passkey or password) are limited per client IP (5 / 5 min) and per
owner device (10 / 15 min); options per device (30 / min). A blocked caller
gets 429 + retry_after before any verification work. Every failure is
audited with its WebAuthnError code; the answer itself stays generic.

rp_id / origin come from the configured Pocket host (pocketserver
--rp-id/--rp-origin override them), never from the request.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import auth_client  # noqa: E402
import porch_auth  # noqa: E402
import porch_webauthn as wa  # noqa: E402
from pocket_core import RateLimit, device_hint  # noqa: E402
from porch_http import atomic_write_bytes, client_ip  # noqa: E402

STEPUP_COOKIE = '__Host-pocket_stepup'
STEPUP_WINDOW = 300                 # s, fixed from the ceremony (not sliding)
MAX_STEPUPS = 16
CHALLENGE_TTL = 120
MAX_CHALLENGES_PER_DEVICE = 8
MAX_CHALLENGES = 64
MAX_PASSKEYS = 10
MAX_PASSKEY_LABEL = 40
STEPUP_TIMEOUT_MS = 60000
FAIL_IP_RATE = (5, 300)
FAIL_DEVICE_RATE = (10, 900)
OPTIONS_RATE = (30, 60)
PASSKEY_ID = re.compile(r'^[A-Za-z0-9_-]{16,1400}$')
GENERIC_FAIL = "That passkey didn't check out"
_CTRL = re.compile(r'[\x00-\x1f\x7f]')


def _b64u(b):
    return base64.urlsafe_b64encode(bytes(b)).rstrip(b'=').decode('ascii')


def _sha(s):
    return hashlib.sha256(s.encode('utf-8') if isinstance(s, str) else s).hexdigest()


def clean_passkey_label(label, fallback=''):
    if not isinstance(label, str):
        label = ''
    label = ' '.join(_CTRL.sub(' ', label).split())[:MAX_PASSKEY_LABEL]
    return label or fallback


def retry_after(rl, key, now=None):
    """Seconds until RateLimit `rl` lets `key` through again (0 = now)."""
    now = time.monotonic() if now is None else now
    with rl.lock:
        q = rl._prune(key, now)
        if len(q) < rl.limit:
            return 0
        return max(1, int(rl.window - (now - q[0])) + 1)


# ---- passkeys on disk -----------------------------------------------------------

class PasskeyStore:
    """{version: 1, rp_id, user_handle, credentials: [{id, public_key (SPKI
    DER, b64url), alg, sign_count, label, created_at, last_used_at,
    transports, aaguid, be, bs, rp_id}]}. A credential registered under
    another rp_id (the pocket was renamed) is kept but `unusable`."""

    def __init__(self, path, rp_id, clock=time.time):
        self.path = Path(path)
        self.rp_id = rp_id
        self.clock = clock
        self.lock = threading.Lock()

    def _load(self):
        try:
            with open(self.path, 'rb') as f:
                data = json.loads(f.read().decode('utf-8'))
        except FileNotFoundError:
            data = None
        except (OSError, ValueError, UnicodeDecodeError) as e:
            sys.stderr.write(f"[pocketserver] passkeys file unreadable ({e.__class__.__name__}); "
                             "treating it as empty\n")
            data = None
        if not isinstance(data, dict):
            data = {}
        creds = data.get('credentials')
        top_rp = data.get('rp_id') if isinstance(data.get('rp_id'), str) else self.rp_id
        out = []
        for c in creds if isinstance(creds, list) else ():
            if isinstance(c, dict) and isinstance(c.get('id'), str) \
                    and isinstance(c.get('public_key'), str) and c.get('alg') in (wa.ALG_ES256,
                                                                                    wa.ALG_RS256):
                c.setdefault('rp_id', top_rp)
                out.append(c)
        uh = data.get('user_handle') if isinstance(data.get('user_handle'), str) else None
        return {'version': 1, 'rp_id': top_rp, 'user_handle': uh, 'credentials': out}

    def _save(self, data):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(self.path, json.dumps(data, indent=1).encode('utf-8'), mode=0o600)

    def load(self):
        with self.lock:
            return self._load()

    def user_handle(self):
        with self.lock:
            data = self._load()
            if not data['user_handle']:
                data['user_handle'] = _b64u(secrets.token_bytes(16))
                self._save(data)
            return wa.unb64u(data['user_handle'], 64, 'user_handle')

    def credentials(self):
        return self.load()['credentials']

    def usable(self):
        return [c for c in self.credentials() if c.get('rp_id') == self.rp_id]

    def rp_mismatch(self):
        return any(c.get('rp_id') != self.rp_id for c in self.credentials())

    def add(self, reg, label):
        """Store a verify_registration() result. ValueError when full or
        already stored."""
        now = int(self.clock())
        with self.lock:
            data = self._load()
            if len(data['credentials']) >= MAX_PASSKEYS:
                raise ValueError(f'at most {MAX_PASSKEYS} passkeys; delete one first')
            if any(c['id'] == reg['id'] for c in data['credentials']):
                raise ValueError('that passkey is already registered')
            rec = {'id': reg['id'], 'public_key': reg['public_key'], 'alg': reg['alg'],
                   'sign_count': reg['sign_count'], 'label': label, 'created_at': now,
                   'last_used_at': None, 'transports': reg.get('transports') or [],
                   'aaguid': reg.get('aaguid'), 'be': bool(reg.get('be')),
                   'bs': bool(reg.get('bs')), 'rp_id': self.rp_id}
            data['credentials'].append(rec)
            data['rp_id'] = self.rp_id
            if not data['user_handle']:
                data['user_handle'] = _b64u(secrets.token_bytes(16))
            self._save(data)
            return rec

    def used(self, cid, sign_count, be=None, bs=None):
        with self.lock:
            data = self._load()
            for c in data['credentials']:
                if c['id'] == cid:
                    c['sign_count'] = sign_count
                    c['last_used_at'] = int(self.clock())
                    if be is not None:
                        c['be'] = bool(be)
                    if bs is not None:
                        c['bs'] = bool(bs)
                    self._save(data)
                    return True
            return False

    def rename(self, cid, label):
        with self.lock:
            data = self._load()
            for c in data['credentials']:
                if c['id'] == cid:
                    c['label'] = label
                    self._save(data)
                    return self.public_one(c)
            return None

    def delete(self, cid):
        with self.lock:
            data = self._load()
            keep = [c for c in data['credentials'] if c['id'] != cid]
            if len(keep) == len(data['credentials']):
                return None
            gone = next(c for c in data['credentials'] if c['id'] == cid)
            data['credentials'] = keep
            self._save(data)
            return gone

    def public_one(self, c):
        return {'id': c['id'], 'short_id': c['id'][:8] + '…' + c['id'][-4:],
                'label': c.get('label') or '', 'created_at': c.get('created_at'),
                'last_used_at': c.get('last_used_at'), 'synced': bool(c.get('be')),
                'transports': [t for t in c.get('transports') or () if t in wa.TRANSPORTS],
                'unusable': c.get('rp_id') != self.rp_id}

    def public(self):
        return [self.public_one(c) for c in self.credentials()]


# ---- memory stores --------------------------------------------------------------

class ChallengeStore:
    """WebAuthn challenges: 32 random bytes each, keyed by their sha256,
    single use (popped on verify whatever the outcome), CHALLENGE_TTL."""

    def __init__(self, clock=time.time, ttl=CHALLENGE_TTL, per_device=MAX_CHALLENGES_PER_DEVICE,
                 total=MAX_CHALLENGES):
        self.clock, self.ttl, self.per_device, self.total = clock, ttl, per_device, total
        self.lock = threading.Lock()
        self.items = {}            # sha -> entry (insertion order = age)

    def issue(self, purpose, device_id, owner_sha):
        ch = secrets.token_bytes(32)
        now = self.clock()
        with self.lock:
            for k in [k for k, e in self.items.items() if e['expires'] <= now]:
                del self.items[k]
            mine = [k for k, e in self.items.items() if e['device_id'] == device_id]
            while len(mine) >= self.per_device:
                self.items.pop(mine.pop(0), None)
            while len(self.items) >= self.total:
                self.items.pop(next(iter(self.items)))
            self.items[hashlib.sha256(ch).hexdigest()] = {
                'challenge': ch, 'purpose': purpose, 'device_id': device_id,
                'owner_sha': owner_sha, 'expires': now + self.ttl}
        return ch

    def take(self, cred):
        """Pop the entry whose challenge this credential's clientDataJSON
        names. None when there is none (unknown, used, malformed)."""
        try:
            resp = cred.get('response') if isinstance(cred, dict) else None
            cdj = wa.unb64u(resp.get('clientDataJSON'), wa.MAX_CLIENT_DATA, 'clientDataJSON')
            got = json.loads(cdj.decode('utf-8')).get('challenge')
            ch = wa.unb64u(got, 64, 'challenge')
        except (wa.WebAuthnError, AttributeError, ValueError, UnicodeDecodeError, TypeError):
            return None
        with self.lock:
            return self.items.pop(hashlib.sha256(ch).hexdigest(), None)

    def valid(self, entry, purpose, device_id, owner_sha):
        return (entry is not None and entry['purpose'] == purpose
                and entry['device_id'] == device_id
                and hmac.compare_digest(entry['owner_sha'], owner_sha)
                and entry['expires'] > self.clock())


class StepUpStore:
    def __init__(self, clock=time.time, window=STEPUP_WINDOW, total=MAX_STEPUPS):
        self.clock, self.window, self.total = clock, window, total
        self.lock = threading.Lock()
        self.items = {}            # sha256(token) -> entry

    def _sweep(self, now):
        for k in [k for k, e in self.items.items() if e['expires'] <= now]:
            del self.items[k]

    def create(self, device_id, owner_sha, method):
        token = secrets.token_bytes(32)
        now = self.clock()
        exp = int(now + self.window)
        with self.lock:
            self._sweep(now)
            for k in [k for k, e in self.items.items() if e['device_id'] == device_id]:
                del self.items[k]
            while len(self.items) >= self.total:
                self.items.pop(next(iter(self.items)))
            self.items[hashlib.sha256(token).hexdigest()] = {
                'device_id': device_id, 'owner_sha': owner_sha, 'method': method,
                'expires': exp}
        return _b64u(token), exp

    def check(self, token, device_id, owner_sha):
        if not isinstance(token, str) or not token or len(token) > 64:
            return None
        try:
            raw = base64.urlsafe_b64decode(token + '=' * (-len(token) % 4))
        except (ValueError, TypeError):
            return None
        now = self.clock()
        with self.lock:
            e = self.items.get(hashlib.sha256(raw).hexdigest())
            if e is None or e['expires'] <= now or e['device_id'] != device_id \
                    or not hmac.compare_digest(e['owner_sha'], owner_sha):
                return None
            return dict(e)

    def status(self, device_id, owner_sha):
        """The live step-up of this device + owner cookie, whatever cookie
        a request carries (an SSE stream opened before the step-up)."""
        now = self.clock()
        with self.lock:
            for e in self.items.values():
                if e['device_id'] == device_id and e['expires'] > now \
                        and hmac.compare_digest(e['owner_sha'], owner_sha):
                    return {'active': True, 'expires_at': e['expires'], 'method': e['method']}
        return {'active': False, 'expires_at': None, 'method': None}

    def end(self, device_id):
        with self.lock:
            gone = [k for k, e in self.items.items() if e['device_id'] == device_id]
            for k in gone:
                del self.items[k]
            return bool(gone)


# ---- the handler side -------------------------------------------------------------

class StepUpMixin:
    """Routes + guard. Needs on the handler: devices_path, base_dir, hub,
    audit (AuditLog|None), auth (auth_client.Client|None), _api_error(),
    send_json(), _audit()."""

    # init_stepup() (main) replaces these with fresh ones; the class defaults
    # only keep a handler that never called it working.
    passkeys = None             # PasskeyStore; None = <base_dir>/.passkeys.json
    challenges = ChallengeStore()
    stepups = StepUpStore()
    rp_id = 'localhost'
    rp_origin = 'http://localhost'
    brand = 'Porch'
    stepup_fail_ip = RateLimit(*FAIL_IP_RATE)
    stepup_fail_dev = RateLimit(*FAIL_DEVICE_RATE)
    stepup_options_rate = RateLimit(*OPTIONS_RATE)
    cookie_secure = True        # tests over plain http keep it (clients ignore it)

    @classmethod
    def init_stepup(cls, base_dir, rp_id, rp_origin, clock=time.time):
        cls.rp_id, cls.rp_origin = rp_id, rp_origin
        cls.passkeys = PasskeyStore(Path(base_dir) / '.passkeys.json', rp_id, clock)
        cls.challenges = ChallengeStore(clock)
        cls.stepups = StepUpStore(clock)
        cls.stepup_fail_ip = RateLimit(*FAIL_IP_RATE)
        cls.stepup_fail_dev = RateLimit(*FAIL_DEVICE_RATE)
        cls.stepup_options_rate = RateLimit(*OPTIONS_RATE)
        if cls.passkeys.rp_mismatch():
            sys.stderr.write(f"[pocketserver] some passkeys were made for another rp_id (not "
                             f"{rp_id}): they are unusable; use the password and re-enroll\n")

    # ---- identity ----

    def owner_ctx(self):
        """{device_id, device_name, owner_sha} of the owner credential on
        this request, or None. Cached per request."""
        cached = getattr(self, '_owner_ctx_cache', None)
        if cached is not None and cached[0] is self.headers:
            return cached[1]
        cred = porch_auth.owner_credential(self, self.devices_path)
        ctx = None
        if cred:
            _, value, dev = cred
            did = dev.get('id') if isinstance(dev.get('id'), str) and dev.get('id') else \
                'tok:' + str(dev.get('token_sha256') or _sha(value))[:16]
            ctx = {'device_id': did, 'device_name': str(dev.get('name') or ''),
                   'owner_sha': _sha(value)}
        self._owner_ctx_cache = (self.headers, ctx)
        return ctx

    def _stepup_cookie(self):
        return porch_auth._cookies(self).get(STEPUP_COOKIE, '')

    def stepup_entry(self):
        ctx = self.owner_ctx()
        if ctx is None:
            return None
        return self.stepups.check(self._stepup_cookie(), ctx['device_id'], ctx['owner_sha'])

    def stepup_ok(self):
        return self.stepup_entry() is not None

    def stepup_status(self):
        ctx = self.owner_ctx()
        if ctx is None:
            return {'active': False, 'expires_at': None, 'method': None}
        e = self.stepup_entry()
        if e is None:
            return {'active': False, 'expires_at': None, 'method': None}
        return {'active': True, 'expires_at': e['expires'], 'method': e['method']}

    def _passkey_store(self):
        if self.passkeys is None:
            type(self).passkeys = PasskeyStore(Path(self.base_dir) / '.passkeys.json',
                                               self.rp_id)
        return self.passkeys

    def stepup_methods(self):
        n = len(self._passkey_store().usable()) if wa.available() else 0
        return (['passkey', 'password'] if n else ['password']), n

    def require_stepup(self):
        """The ★ guard: True when a fresh step-up is on this request;
        otherwise 401 {code: step_up, methods, passkeys} has been sent."""
        if self.stepup_ok():
            return True
        methods, n = self.stepup_methods()
        self._api_error(401, 'Confirm it is you first', 'step_up', methods=methods, passkeys=n)
        return False

    # ---- limits ----

    def _blocked(self):
        """429 sent (True) when this IP or owner device is over its failure budget."""
        ip = client_ip(self)
        dev = (self.owner_ctx() or {}).get('device_id', '')
        wait = max(retry_after(self.stepup_fail_ip, ip), retry_after(self.stepup_fail_dev, dev))
        if wait:
            self._api_error(429, 'Too many failed attempts; wait a few minutes',
                            'rate_limited', retry_after=wait, headers={'Retry-After': str(wait)})
            return True
        return False

    def _failed(self, how, code, status=401, message=None):
        self.stepup_fail_ip.hit(client_ip(self))
        self.stepup_fail_dev.hit((self.owner_ctx() or {}).get('device_id', ''))
        self._audit('stepup', how, result='failed', code=code)
        self._api_error(status, message or GENERIC_FAIL, 'stepup_failed')

    def _options_limited(self):
        dev = (self.owner_ctx() or {}).get('device_id', '')
        if not self.stepup_options_rate.hit(dev):
            wait = retry_after(self.stepup_options_rate, dev) or 60
            self._api_error(429, 'Too many requests; wait a minute', 'rate_limited',
                            retry_after=wait, headers={'Retry-After': str(wait)})
            return True
        return False

    def _grant(self, method):
        ctx = self.owner_ctx()
        token, exp = self.stepups.create(ctx['device_id'], ctx['owner_sha'], method)
        cookie = (f'{STEPUP_COOKIE}={token}; Secure; HttpOnly; SameSite=Strict; Path=/; '
                  f'Max-Age={STEPUP_WINDOW}')
        self._audit('stepup', method, method=method)
        if self.hub:
            self.hub.bump('stepup')
        self.send_json({'status': 'ok', 'expires_at': exp, 'method': method},
                       headers={'Set-Cookie': cookie})

    # ---- routes ----

    def api_stepup_options(self, data):
        if self._options_limited():
            return
        if not wa.available():
            self.send_json({'status': 'ok', 'passkeys': 0, 'why': 'unavailable'})
            return
        creds = self._passkey_store().usable()
        if not creds:
            self.send_json({'status': 'ok', 'passkeys': 0})
            return
        ctx = self.owner_ctx()
        ch = self.challenges.issue('stepup', ctx['device_id'], ctx['owner_sha'])
        self.send_json({'status': 'ok', 'passkeys': len(creds),
                        'publicKey': wa.request_options(ch, self.rp_id, allow=creds,
                                                        timeout=STEPUP_TIMEOUT_MS)})

    def api_stepup_passkey(self, data):
        if self._blocked():
            return
        cred = data.get('credential')
        entry = self.challenges.take(cred)
        ctx = self.owner_ctx()
        if not self.challenges.valid(entry, 'stepup', ctx['device_id'], ctx['owner_sha']):
            self._failed('passkey', 'challenge_mismatch')
            return
        store = self._passkey_store()
        try:
            res = wa.verify_assertion(cred, store.usable(), entry['challenge'], self.rp_origin,
                                      self.rp_id, store.user_handle())
        except wa.WebAuthnError as e:
            if e.code == 'unavailable':
                self._api_error(501, 'Passkeys need python3-cryptography on this box',
                                'unavailable')
                return
            if e.code == 'counter_regressed':
                sys.stderr.write("[pocketserver] passkey signCount went backwards: "
                                 "possible cloned authenticator; refused\n")
            self._failed('passkey', e.code)
            return
        store.used(res['id'], res['sign_count'], res.get('be'), res.get('bs'))
        self._grant('passkey')

    def api_stepup_password(self, data):
        if self._blocked():
            return
        pw = data.get('password')
        if not isinstance(pw, str) or not pw or len(pw) > 1024:
            self._api_error(400, 'Enter the admin password')
            return
        ok = self._verify_admin_password(pw)
        if ok is None:
            return                      # answered (auth down/old/limited)
        if not ok:
            self._failed('password', 'bad_password', message='That password is not right')
            return
        self._grant('password')

    def _verify_admin_password(self, pw):
        """True / False, or None after sending the error (porch-auth down,
        too old, or its own limiter)."""
        if self.auth is None:
            self._api_error(503, "porch-auth isn't configured for this pocket", 'auth_down')
            return None
        try:
            return self.auth.verify_password(pw, client_ip(self))
        except auth_client.AuthDown:
            self._api_error(503, "porch-auth isn't answering", 'auth_down')
        except auth_client.TokenError:
            self._api_error(503, "porch-auth's CLI token is unreadable", 'auth_down')
        except auth_client.AuthError as e:
            if e.status == 404:
                self._api_error(501, 'update porch-auth (bin/auth-deploy)', 'auth_old')
            elif e.status == 429:
                self._api_error(429, 'Too many password attempts; wait a minute',
                                'rate_limited', retry_after=60, headers={'Retry-After': '60'})
            elif e.status == 503:
                self._api_error(503, 'porch-auth is busy; try again', 'auth_busy')
            else:
                self._api_error(502, 'porch-auth refused the check', 'auth_error')
        return None

    def api_stepup_end(self, data):
        ctx = self.owner_ctx()
        self.stepups.end(ctx['device_id'])
        if self.hub:
            self.hub.bump('stepup')
        self.send_json({'status': 'ok'}, headers={
            'Set-Cookie': f'{STEPUP_COOKIE}=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'})

    def api_passkeys(self, query):
        self.send_json(self._passkey_store().public())

    def api_passkey_register_options(self, data):
        if self._options_limited():
            return
        store = self._passkey_store()
        if not wa.available():
            self._api_error(501, 'Passkeys need python3-cryptography on this box', 'unavailable')
            return
        if not store.usable() and self.stepup_entry()['method'] != 'password':
            self._api_error(401, 'Your first passkey needs the admin password',
                            'step_up_password', methods=['password'], passkeys=0)
            return
        if len(store.credentials()) >= MAX_PASSKEYS:
            self._api_error(409, f'at most {MAX_PASSKEYS} passkeys; delete one first', 'conflict')
            return
        ctx = self.owner_ctx()
        ch = self.challenges.issue('register', ctx['device_id'], ctx['owner_sha'])
        host = self.rp_id
        self.send_json({'status': 'ok', 'publicKey': wa.creation_options(
            ch, self.rp_id, store.user_handle(), brand=self.brand,
            user_name=f'owner@{host}', exclude=store.credentials())})

    def api_passkey_register(self, data):
        if not self.require_stepup():
            return
        if self._blocked():
            return
        cred = data.get('credential')
        entry = self.challenges.take(cred)
        ctx = self.owner_ctx()
        if not self.challenges.valid(entry, 'register', ctx['device_id'], ctx['owner_sha']):
            self._failed('register', 'challenge_mismatch')
            return
        try:
            reg = wa.verify_registration(cred, entry['challenge'], self.rp_origin, self.rp_id)
        except wa.WebAuthnError as e:
            if e.code == 'unavailable':
                self._api_error(501, 'Passkeys need python3-cryptography on this box',
                                'unavailable')
                return
            self._failed('register', e.code)
            return
        label = clean_passkey_label(data.get('label'),
                                    device_hint(self.headers.get('User-Agent', '')) or 'Passkey')
        try:
            rec = self._passkey_store().add(reg, label)
        except ValueError as e:
            self._api_error(409, str(e), 'conflict')
            return
        self._audit('passkey.add', label)
        self.send_json({'status': 'ok', 'passkey': self._passkey_store().public_one(rec)}, 201)

    def api_passkey_rename(self, data, cid):
        label = clean_passkey_label(data.get('label'))
        if not label:
            self._api_error(400, f'label must be 1 to {MAX_PASSKEY_LABEL} characters')
            return
        out = self._passkey_store().rename(cid, label)
        if out is None:
            self._api_error(404, 'No such passkey', 'not_found')
            return
        self._audit('passkey.rename', label)
        self.send_json({'status': 'ok', 'passkey': out})

    def api_passkey_delete(self, data, cid):
        gone = self._passkey_store().delete(cid)
        if gone is None:
            self._api_error(404, 'No such passkey', 'not_found')
            return
        self._audit('passkey.delete', gone.get('label') or cid[:8])
        self.send_json({'status': 'ok', 'passkeys': self._passkey_store().public()})

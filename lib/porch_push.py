#!/usr/bin/env python3
"""Self-hosted Web Push: VAPID (RFC 8292) + aes128gcm payloads (RFC 8291).

Pocket's page subscribes the owner's browsers (PushManager.subscribe with
this pocket's VAPID public key) and stores each subscription in
~/pocket/<name>/.push.json (0600). Anything on this box that wants to tell
the owner something (statusserver, for an "ask to reopen") encrypts a small
JSON payload to each subscription and POSTs it to the browser vendor's push
service, signed with ~/pocket/<name>/.vapid.pem (a P-256 key, 0600, made on
first use). No third party sees the content: the push service only relays
ciphertext.

    encrypt()   RFC 8291: ECDH(ephemeral, p256dh), HKDF with the auth secret,
                AES-128-GCM, one record (rs 4096), payload + 0x02 delimiter
    vapid()     RFC 8292: an ES256 JWT {aud: the push origin, exp: 12h, sub},
                sent as `Authorization: vapid t=<jwt>, k=<public key>`
    send()      stdlib HTTPS POST (TTL, Urgency, Content-Encoding: aes128gcm),
                no redirects; 404/410 = the subscription is gone (dropped)

Endpoints must be https on a known push service (FCM, Mozilla autopush,
Apple, Windows): a subscription is data the browser hands us, and without
the allowlist it would be a way to make this box POST to any URL (SSRF).
Tests add a loopback endpoint through allow_test_endpoint(), never config.

Needs python3-cryptography (already required by --e2e); available() says.
"""

import base64
import hashlib
import http.client
import json
import os
import ssl
import struct
import sys
import tempfile
import threading
import time
import urllib.parse

APT_HINT = 'sudo apt install python3-cryptography'
RS = 4096
MAX_PAYLOAD = 3000             # plaintext bytes; the record (+86 header, +17) stays under 4096
MAX_SUBS = 20
# What a notification is about. A subscription with a `topics` list gets only
# those; one without (every subscription made before topics existed) gets all.
TOPICS = ('reopen', 'pairing', 'invite', 'access')
JWT_TTL = 12 * 3600
SEND_TIMEOUT = 10
PUSH_HOSTS = ('fcm.googleapis.com', 'android.googleapis.com', 'updates.push.services.mozilla.com',
              'web.push.apple.com')
PUSH_SUFFIXES = ('.push.services.mozilla.com', '.push.apple.com', '.notify.windows.com')

_test_prefixes = []            # allow_test_endpoint(): http://127.0.0.1:<port>/ in tests only
_store_lock = threading.Lock()


class PushUnavailable(RuntimeError):
    pass


def _crypto():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            decode_dss_signature, encode_dss_signature)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
    except ImportError:
        raise PushUnavailable(f'Web Push needs python3-cryptography ({APT_HINT})') from None
    return {'hashes': hashes, 'serialization': serialization, 'ec': ec, 'AESGCM': AESGCM,
            'HKDF': HKDF, 'HKDFExpand': HKDFExpand, 'decode': decode_dss_signature,
            'encode': encode_dss_signature}


def available():
    try:
        _crypto()
        return True
    except PushUnavailable:
        return False


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')


def unb64u(s):
    if not isinstance(s, str) or len(s) > 4096:
        raise ValueError('not base64url')
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


# ---- keys ------------------------------------------------------------------------

def public_bytes(key):
    """The uncompressed P-256 point (65 bytes) of a private or public key."""
    c = _crypto()
    pub = key.public_key() if hasattr(key, 'public_key') else key
    return pub.public_bytes(c['serialization'].Encoding.X962,
                            c['serialization'].PublicFormat.UncompressedPoint)


def load_public(raw):
    c = _crypto()
    if len(raw) != 65 or raw[0] != 4:
        raise ValueError('not an uncompressed P-256 point')
    return c['ec'].EllipticCurvePublicKey.from_encoded_point(c['ec'].SECP256R1(), raw)


def private_from_bytes(raw):
    c = _crypto()
    return c['ec'].derive_private_key(int.from_bytes(raw, 'big'), c['ec'].SECP256R1())


def load_or_create_vapid(path):
    """The pocket's VAPID key: a P-256 PEM at `path`, 0600, created once
    (O_EXCL, never through a symlink)."""
    c = _crypto()
    ser = c['serialization']
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as f:
            return ser.load_pem_private_key(f.read(16384), password=None)
    except FileNotFoundError:
        pass
    key = c['ec'].generate_private_key(c['ec'].SECP256R1())
    pem = key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        return load_or_create_vapid(path)           # another process made it first
    with os.fdopen(fd, 'wb') as f:
        f.write(pem)
    return key


def read_vapid(path):
    """The key at `path`, or None (no key yet, or no cryptography)."""
    try:
        c = _crypto()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as f:
            return c['serialization'].load_pem_private_key(f.read(16384), password=None)
    except (OSError, ValueError, PushUnavailable):
        return None


# ---- VAPID (RFC 8292) ---------------------------------------------------------------

def audience(endpoint):
    u = urllib.parse.urlsplit(endpoint)
    return f'{u.scheme}://{u.netloc}'


def vapid_jwt(key, aud, sub, now=None, ttl=JWT_TTL):
    c = _crypto()
    now = int(time.time() if now is None else now)
    head = b64u(json.dumps({'typ': 'JWT', 'alg': 'ES256'}, separators=(',', ':')).encode())
    body = b64u(json.dumps({'aud': aud, 'exp': now + ttl, 'sub': sub},
                           separators=(',', ':')).encode())
    signing = f'{head}.{body}'.encode('ascii')
    der = key.sign(signing, c['ec'].ECDSA(c['hashes'].SHA256()))
    r, s = c['decode'](der)
    return f'{head}.{body}.{b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}'


def vapid_header(key, endpoint, sub, now=None):
    return f'vapid t={vapid_jwt(key, audience(endpoint), sub, now)}, k={b64u(public_bytes(key))}'


def verify_vapid(header, endpoint, now=None):
    """What a push service checks (used by the tests): the k= key verifies
    the ES256 JWT, aud is the endpoint's origin, exp is in the future and at
    most 24h away. Returns (claims, k bytes); ValueError otherwise."""
    c = _crypto()
    now = int(time.time() if now is None else now)
    if not header.startswith('vapid '):
        raise ValueError('not a vapid Authorization')
    parts = dict(p.strip().split('=', 1) for p in header[6:].split(','))
    jwt, k = parts['t'], unb64u(parts['k'])
    head, body, sig = jwt.split('.')
    if json.loads(unb64u(head)) != {'typ': 'JWT', 'alg': 'ES256'}:
        raise ValueError('bad JWT header')
    raw = unb64u(sig)
    if len(raw) != 64:
        raise ValueError('ES256 signature must be 64 bytes')
    der = c['encode'](int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:], 'big'))
    from cryptography.exceptions import InvalidSignature
    try:
        load_public(k).verify(der, f'{head}.{body}'.encode('ascii'),
                              c['ec'].ECDSA(c['hashes'].SHA256()))
    except InvalidSignature:
        raise ValueError('JWT signature does not verify') from None
    claims = json.loads(unb64u(body))
    if claims.get('aud') != audience(endpoint):
        raise ValueError('aud is not the push service origin')
    if not now < claims.get('exp', 0) <= now + 86400:
        raise ValueError('exp out of range')
    if not str(claims.get('sub', '')).startswith(('mailto:', 'https://')):
        raise ValueError('sub must be mailto: or https:')
    return claims, k


# ---- aes128gcm (RFC 8291 / RFC 8188) --------------------------------------------------

def _hkdf(c, salt, ikm, info, length):
    return c['HKDF'](algorithm=c['hashes'].SHA256(), length=length, salt=salt,
                     info=info).derive(ikm)


def _keys(c, ecdh, auth, ua_pub, as_pub, salt):
    ikm = _hkdf(c, auth, ecdh, b'WebPush: info\x00' + ua_pub + as_pub, 32)
    cek = _hkdf(c, salt, ikm, b'Content-Encoding: aes128gcm\x00', 16)
    nonce = _hkdf(c, salt, ikm, b'Content-Encoding: nonce\x00', 12)
    return cek, nonce


def encrypt(plaintext, p256dh, auth, salt=None, as_private=None):
    """One aes128gcm record for a subscription's keys (raw bytes). salt and
    as_private are only given by the RFC 8291 test vector."""
    c = _crypto()
    if len(plaintext) > MAX_PAYLOAD:
        raise ValueError(f'push payload over {MAX_PAYLOAD} bytes')
    ua = load_public(p256dh)
    as_key = as_private or c['ec'].generate_private_key(c['ec'].SECP256R1())
    as_pub = public_bytes(as_key)
    salt = salt or os.urandom(16)
    ecdh = as_key.exchange(c['ec'].ECDH(), ua)
    cek, nonce = _keys(c, ecdh, auth, p256dh, as_pub, salt)
    ct = c['AESGCM'](cek).encrypt(nonce, plaintext + b'\x02', None)
    return salt + struct.pack('>IB', RS, len(as_pub)) + as_pub + ct


def decrypt(body, ua_private, auth):
    """The receiving browser's side (tests, the fake push service)."""
    c = _crypto()
    salt, rs, idlen = body[:16], struct.unpack('>I', body[16:20])[0], body[20]
    as_pub = body[21:21 + idlen]
    ct = body[21 + idlen:]
    if rs < 18 or len(ct) > rs:
        raise ValueError('one record expected')
    ecdh = ua_private.exchange(c['ec'].ECDH(), load_public(as_pub))
    cek, nonce = _keys(c, ecdh, auth, public_bytes(ua_private), as_pub, salt)
    pt = c['AESGCM'](cek).decrypt(nonce, ct, None).rstrip(b'\x00')
    if not pt.endswith(b'\x02'):
        raise ValueError('not the last record')
    return pt[:-1]


# ---- subscriptions ---------------------------------------------------------------------

def allow_test_endpoint(prefix):
    """Tests only: also accept endpoints starting with `prefix` (a loopback
    http:// fake push service). Nothing in the product calls this."""
    _test_prefixes.append(prefix)


def endpoint_allowed(url):
    if not isinstance(url, str) or len(url) > 2048 or any(ord(ch) < 33 for ch in url):
        return False
    if any(url.startswith(p) for p in _test_prefixes):
        return True
    try:
        u = urllib.parse.urlsplit(url)
        port = u.port
    except ValueError:
        return False
    host = (u.hostname or '').lower()
    if u.scheme != 'https' or port not in (None, 443) or u.username or u.password:
        return False
    return host in PUSH_HOSTS or any(host.endswith(s) for s in PUSH_SUFFIXES)


def clean_subscription(sub):
    """A PushSubscription.toJSON() -> {endpoint, p256dh, auth} (base64url),
    or ValueError with a user-facing reason."""
    if not isinstance(sub, dict):
        raise ValueError('subscription must be an object')
    ep = sub.get('endpoint')
    keys = sub.get('keys') if isinstance(sub.get('keys'), dict) else {}
    if not endpoint_allowed(ep):
        raise ValueError('that push service is not one Pocket knows (FCM, Mozilla, Apple, Windows)')
    try:
        p256dh, auth = unb64u(keys.get('p256dh')), unb64u(keys.get('auth'))
        load_public(p256dh)
    except (ValueError, TypeError):
        raise ValueError('the subscription keys are malformed') from None
    if len(auth) != 16:
        raise ValueError('the subscription keys are malformed')
    return {'endpoint': ep, 'p256dh': b64u(p256dh), 'auth': b64u(auth)}


def clean_topics(topics):
    """A list of known topics (deduplicated, in TOPICS order), or ValueError."""
    if not isinstance(topics, list) or not all(isinstance(t, str) for t in topics):
        raise ValueError('topics must be a list of names')
    unknown = [t for t in topics if t not in TOPICS]
    if unknown:
        raise ValueError(f'unknown topic: {unknown[0][:20]}')
    return [t for t in TOPICS if t in topics]


def wants(sub, topic):
    """Does subscription `sub` take a notification about `topic`? None (a
    test, or anything without a topic) goes to everyone."""
    if topic is None:
        return True
    t = sub.get('topics')
    return not isinstance(t, list) or topic in t


def sub_id(endpoint):
    """A short stable id for a subscription (the endpoint itself is never
    shown): the page hashes its own endpoint the same way to find itself."""
    return hashlib.sha256(endpoint.encode('utf-8')).hexdigest()[:16]


class SubStore:
    """~/pocket/<name>/.push.json: [{endpoint, p256dh, auth, label, created,
    topics?}] (no `topics` = every topic)."""

    def __init__(self, path):
        self.path = str(path)

    def load(self):
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            return []
        with os.fdopen(fd, 'rb') as f:
            try:
                data = json.loads(f.read(1024 * 1024).decode('utf-8'))
            except (ValueError, UnicodeDecodeError):
                return []
        if not isinstance(data, list):
            return []
        return [s for s in data if isinstance(s, dict) and endpoint_allowed(s.get('endpoint'))
                and isinstance(s.get('p256dh'), str) and isinstance(s.get('auth'), str)]

    def _save(self, subs):
        d = os.path.dirname(self.path) or '.'
        fd, tmp = tempfile.mkstemp(prefix='.push.', suffix='.tmp', dir=d)
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(subs, f, indent=1)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def add(self, sub, label=''):
        clean = clean_subscription(sub)
        with _store_lock:
            subs = self.load()
            old = next((s for s in subs if s['endpoint'] == clean['endpoint']), None)
            subs = [s for s in subs if s['endpoint'] != clean['endpoint']]
            rec = clean | {'label': str(label)[:40], 'created': int(time.time())}
            if old is not None and isinstance(old.get('topics'), list):
                rec['topics'] = old['topics']     # re-subscribing keeps the choice
            subs.append(rec)
            self._save(subs[-MAX_SUBS:])
        return clean

    def set_topics(self, endpoint, topics):
        """Set which topics one subscription takes. Returns the cleaned list,
        or None when no subscription has that endpoint. ValueError for an
        unknown topic."""
        topics = clean_topics(topics)
        with _store_lock:
            subs = self.load()
            hit = False
            for s in subs:
                if s['endpoint'] == endpoint:
                    s['topics'] = topics
                    hit = True
            if not hit:
                return None
            self._save(subs)
        return topics

    def remove(self, endpoint):
        with _store_lock:
            subs = self.load()
            kept = [s for s in subs if s['endpoint'] != endpoint]
            if len(kept) != len(subs):
                self._save(kept)
            return len(subs) - len(kept)

    def public(self):
        out = []
        for s in self.load():
            t = s.get('topics')
            out.append({'id': sub_id(s['endpoint']),
                        'endpoint_host': urllib.parse.urlsplit(s['endpoint']).hostname,
                        'label': s.get('label') or '', 'created': s.get('created'),
                        'topics': [x for x in TOPICS if x in t] if isinstance(t, list)
                        else list(TOPICS)})
        return out


# ---- delivery ----------------------------------------------------------------------------

def send(sub, payload, key, sub_claim, ttl=1800, urgency='high', timeout=SEND_TIMEOUT, now=None):
    """POST one encrypted payload (a dict, as JSON) to one subscription.
    Returns the push service's HTTP status (201 = queued; 404/410 = the
    subscription is gone). OSError on a network failure."""
    ep = sub['endpoint']
    if not endpoint_allowed(ep):
        raise ValueError('endpoint not allowed')
    data = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    body = encrypt(data, unb64u(sub['p256dh']), unb64u(sub['auth']))
    u = urllib.parse.urlsplit(ep)
    path = (u.path or '/') + (f'?{u.query}' if u.query else '')
    if u.scheme == 'https':
        conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout,
                                           context=ssl.create_default_context())
    else:                                       # allow_test_endpoint() only
        conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    try:
        conn.request('POST', path, body=body, headers={
            'Authorization': vapid_header(key, ep, sub_claim, now),
            'Content-Encoding': 'aes128gcm',
            'Content-Type': 'application/octet-stream',
            'TTL': str(int(ttl)),
            'Urgency': urgency,
        })
        resp = conn.getresponse()
        resp.read(4096)
        return resp.status
    finally:
        conn.close()


def deliver(base_dir, payload, sub_claim, ttl=1800, log=None, topic=None):
    """Send `payload` to every subscription of the pocket at base_dir (its
    .push.json, signed with its .vapid.pem) that takes `topic` (None: all).
    Gone subscriptions are dropped. Returns {sent, failed, dropped}."""
    out = {'sent': 0, 'failed': 0, 'dropped': 0}
    store = SubStore(os.path.join(base_dir, '.push.json'))
    subs = [s for s in store.load() if wants(s, topic)]
    if not subs:
        return out
    key = read_vapid(os.path.join(base_dir, '.vapid.pem'))
    if key is None:
        return out
    for s in subs:
        host = urllib.parse.urlsplit(s['endpoint']).hostname
        try:
            st = send(s, payload, key, sub_claim, ttl=ttl)
        except (OSError, ValueError, http.client.HTTPException) as e:
            out['failed'] += 1
            if log:
                log(f'push to {host} failed: {e.__class__.__name__}')
            continue
        if st in (404, 410):
            store.remove(s['endpoint'])
            out['dropped'] += 1
        elif 200 <= st < 300:
            out['sent'] += 1
        else:
            out['failed'] += 1
            if log:
                log(f'push to {host}: HTTP {st}')
    return out


def pocket_dirs(root=None):
    """Every pocket under ~/pocket (PORCH_POCKET_ROOT overrides) that has
    push subscriptions."""
    root = root or os.environ.get('PORCH_POCKET_ROOT') or os.path.expanduser('~/pocket')
    out = []
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return out
    for n in names:
        d = os.path.join(root, n)
        if not n.startswith('.') and os.path.isfile(os.path.join(d, '.push.json')) \
                and not os.path.islink(d):
            out.append(d)
    return out


def notify_all(payload, sub_claim, root=None, log=None, topic=None):
    """Fan `payload` out to every pocket's subscriptions that take `topic`
    (default: the payload's own `t` when it is a topic, e.g. 'reopen')."""
    total = {'sent': 0, 'failed': 0, 'dropped': 0}
    if not available():
        return total
    if topic is None and isinstance(payload, dict) and payload.get('t') in TOPICS:
        topic = payload['t']
    for d in pocket_dirs(root):
        for k, v in deliver(d, payload, sub_claim, log=log, topic=topic).items():
            total[k] += v
    return total


if __name__ == '__main__':
    print(__doc__)
    sys.exit(0 if available() else 3)

#!/usr/bin/env python3
"""WebAuthn (passkeys) relying-party checks: registration and assertion.

Just enough of WebAuthn Level 2 for one owner's passkeys on one host:

    cbor_decode(data)              strict, minimal CBOR (RFC 8949 subset)
    cbor_decode_prefix(data, off)  -> (value, end): one item, bytes may follow
    parse_auth_data(raw)           authenticatorData -> dict
    parse_cose_key(cose)           COSE_Key map -> (alg, public key object)
    verify_registration(cred, challenge, origin, rp_id)
    verify_assertion(cred, stored, challenge, origin, rp_id, user_handle)
    creation_options(...) / request_options(...)   JSON-ready option dicts

Policy: attestation "none" is requested; any `fmt` is accepted and `attStmt`
is ignored (the spec's "None" trust path, no attestation trust). Only ES256
(-7, P-256) and RS256 (-257, RSA >= 2048 bits) keys. UP and UV are required on
both ceremonies. signCount: 0 then 0 is accepted (Apple, synced passkeys);
otherwise the new count must be strictly greater, else `counter_regressed`
(a possible cloned authenticator).

Credentials come in as the browser's PublicKeyCredential.toJSON() shape
(base64url strings): {id, rawId, type, response: {clientDataJSON,
attestationObject, transports?}} or {..., response: {clientDataJSON,
authenticatorData, signature, userHandle?}}.

Every failure is WebAuthnError(code) with a stable `code` (ERROR_CODES); show
the user something generic and put the code in the audit log.

Needs python3-cryptography, imported lazily (available() says).
"""

import base64
import hashlib
import hmac
import json
import re
import struct
import uuid

APT_HINT = 'sudo apt install python3-cryptography'

ALG_ES256 = -7
ALG_RS256 = -257
RSA_MIN_BITS = 2048

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_AT = 0x40
FLAG_ED = 0x80

CBOR_MAX_DEPTH = 8
CBOR_MAX_ITEMS = 512
MAX_CRED_ID = 1023
MAX_CLIENT_DATA = 8192
MAX_ATT_OBJECT = 65536
MAX_AUTH_DATA = 16384
MAX_SIGNATURE = 1024
MAX_USER_HANDLE = 64
TIMEOUT_MS = 120000
TRANSPORTS = ('usb', 'nfc', 'ble', 'internal', 'hybrid', 'smart-card', 'cable')

ERROR_CODES = frozenset({
    'bad_client_data',     # clientDataJSON not UTF-8 JSON, or wrong `type`
    'challenge_mismatch',  # clientData challenge is not the issued one
    'origin_mismatch',     # wrong origin, crossOrigin true, or a topOrigin
    'rp_mismatch',         # rpIdHash != sha256(rp_id)
    'no_up',               # user-present flag off
    'no_uv',               # user-verified flag off
    'bad_signature',       # assertion signature does not verify
    'unknown_credential',  # assertion for a credential id we don't store
    'counter_regressed',   # signCount not increasing (possible clone)
    'malformed_cbor',      # CBOR outside the strict subset
    'unsupported_alg',     # COSE key not ES256 / RS256 >= 2048
    'bad_credential',      # credential JSON shape: type, id/rawId, base64url, sizes
    'bad_auth_data',       # authenticatorData structure (length, AT missing, trailing)
    'user_mismatch',       # assertion userHandle != the stored user handle
    'unavailable',         # python3-cryptography is not installed
})


class WebAuthnError(Exception):
    """A failed check. `code` is one of ERROR_CODES; `detail` is for logs."""

    def __init__(self, code, detail=''):
        assert code in ERROR_CODES, code
        self.code = code
        self.detail = detail
        super().__init__(f'{code}: {detail}' if detail else code)


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    except ImportError:
        raise WebAuthnError('unavailable', f'passkeys need python3-cryptography ({APT_HINT})') from None
    return {'InvalidSignature': InvalidSignature, 'hashes': hashes,
            'serialization': serialization, 'ec': ec, 'padding': padding, 'rsa': rsa}


def available():
    try:
        _crypto()
        return True
    except WebAuthnError:
        return False


# ---- base64url ---------------------------------------------------------------------

_B64U_RE = re.compile(r'[A-Za-z0-9_-]*={0,2}\Z')


def b64u(b):
    return base64.urlsafe_b64encode(bytes(b)).rstrip(b'=').decode('ascii')


def unb64u(s, limit=MAX_ATT_OBJECT, what='value'):
    """Strict base64url (padding optional) -> bytes, or bad_credential."""
    if not isinstance(s, str) or len(s) > (limit * 4) // 3 + 4 or not _B64U_RE.match(s):
        raise WebAuthnError('bad_credential', f'{what} is not base64url')
    s = s.rstrip('=')
    if len(s) % 4 == 1:
        raise WebAuthnError('bad_credential', f'{what} is not base64url')
    try:
        out = base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
    except (ValueError, TypeError):
        raise WebAuthnError('bad_credential', f'{what} is not base64url') from None
    if len(out) > limit:
        raise WebAuthnError('bad_credential', f'{what} is too long')
    return out


# ---- CBOR --------------------------------------------------------------------------

class _Decoder:
    def __init__(self, data):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise WebAuthnError('malformed_cbor', 'not bytes')
        self.b = bytes(data)
        self.items = 0

    def _need(self, off, n):
        if n < 0 or off + n > len(self.b):
            raise WebAuthnError('malformed_cbor', 'truncated')

    def _arg(self, off, ai):
        if ai < 24:
            return ai, off
        if ai > 27:
            raise WebAuthnError('malformed_cbor', 'indefinite length or reserved info')
        n = 1 << (ai - 24)
        self._need(off, n)
        return int.from_bytes(self.b[off:off + n], 'big'), off + n

    def item(self, off, depth):
        self.items += 1
        if self.items > CBOR_MAX_ITEMS:
            raise WebAuthnError('malformed_cbor', 'too many items')
        self._need(off, 1)
        ib = self.b[off]
        off += 1
        major, ai = ib >> 5, ib & 0x1f
        if major == 7:
            if ai == 20:
                return False, off
            if ai == 21:
                return True, off
            if ai == 22:
                return None, off
            if 25 <= ai <= 27:
                raise WebAuthnError('malformed_cbor', 'floats are not allowed')
            raise WebAuthnError('malformed_cbor', 'simple value not allowed')
        if major == 6:
            raise WebAuthnError('malformed_cbor', 'tags are not allowed')
        val, off = self._arg(off, ai)
        if major == 0:
            return val, off
        if major == 1:
            return -1 - val, off
        if major in (2, 3):
            self._need(off, val)
            raw = self.b[off:off + val]
            off += val
            if major == 2:
                return raw, off
            try:
                return raw.decode('utf-8'), off
            except UnicodeDecodeError:
                raise WebAuthnError('malformed_cbor', 'text is not UTF-8') from None
        # 4 = array, 5 = map
        if depth >= CBOR_MAX_DEPTH:
            raise WebAuthnError('malformed_cbor', 'nested too deep')
        per = 1 if major == 4 else 2
        if val * per > len(self.b) - off:        # every item takes at least one byte
            raise WebAuthnError('malformed_cbor', 'length past the buffer')
        if major == 4:
            out = []
            for _ in range(val):
                v, off = self.item(off, depth + 1)
                out.append(v)
            return out, off
        out = {}
        for _ in range(val):
            k, off = self.item(off, depth + 1)
            if isinstance(k, bool) or not isinstance(k, (int, str)):
                raise WebAuthnError('malformed_cbor', 'map key must be int or text')
            if k in out:
                raise WebAuthnError('malformed_cbor', 'duplicate map key')
            v, off = self.item(off, depth + 1)
            out[k] = v
        return out, off


def cbor_decode_prefix(data, off=0):
    """Decode one CBOR item at `off`; returns (value, end offset)."""
    d = _Decoder(data)
    if not isinstance(off, int) or off < 0 or off > len(d.b):
        raise WebAuthnError('malformed_cbor', 'bad offset')
    return d.item(off, 0)


def cbor_decode(data):
    """Decode exactly one CBOR item that uses every byte of `data`."""
    val, end = cbor_decode_prefix(data, 0)
    if end != len(data):
        raise WebAuthnError('malformed_cbor', 'trailing bytes')
    return val


# ---- authenticatorData -------------------------------------------------------------

def parse_auth_data(raw):
    """authenticatorData -> {rp_id_hash, flags, up, uv, be, bs, sign_count,
    aaguid, credential_id, cose_key, cose_raw, extensions} (attested fields None
    when AT is off)."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 37:
        raise WebAuthnError('bad_auth_data', 'shorter than 37 bytes')
    if len(raw) > MAX_AUTH_DATA:
        raise WebAuthnError('bad_auth_data', 'too long')
    raw = bytes(raw)
    flags = raw[32]
    out = {
        'rp_id_hash': raw[:32], 'flags': flags, 'sign_count': struct.unpack('>I', raw[33:37])[0],
        'up': bool(flags & FLAG_UP), 'uv': bool(flags & FLAG_UV),
        'be': bool(flags & FLAG_BE), 'bs': bool(flags & FLAG_BS),
        'aaguid': None, 'credential_id': None, 'cose_key': None, 'cose_raw': None,
        'extensions': None,
    }
    off = 37
    if flags & FLAG_AT:
        if len(raw) < off + 18:
            raise WebAuthnError('bad_auth_data', 'attested data truncated')
        out['aaguid'] = raw[off:off + 16]
        n = struct.unpack('>H', raw[off + 16:off + 18])[0]
        off += 18
        if n == 0 or n > MAX_CRED_ID:
            raise WebAuthnError('bad_auth_data', 'credential id length')
        if len(raw) < off + n:
            raise WebAuthnError('bad_auth_data', 'credential id truncated')
        out['credential_id'] = raw[off:off + n]
        off += n
        key, end = cbor_decode_prefix(raw, off)
        if not isinstance(key, dict):
            raise WebAuthnError('unsupported_alg', 'COSE key is not a map')
        out['cose_key'], out['cose_raw'] = key, raw[off:end]
        off = end
    if flags & FLAG_ED:
        ext, off = cbor_decode_prefix(raw, off)
        if not isinstance(ext, dict):
            raise WebAuthnError('bad_auth_data', 'extensions are not a map')
        out['extensions'] = ext
    if off != len(raw):
        raise WebAuthnError('bad_auth_data', 'trailing bytes')
    return out


# ---- COSE keys ---------------------------------------------------------------------

def parse_cose_key(cose):
    """A decoded COSE_Key map -> (alg, cryptography public key)."""
    c = _crypto()
    if not isinstance(cose, dict):
        raise WebAuthnError('unsupported_alg', 'COSE key is not a map')
    kty, alg = cose.get(1), cose.get(3)
    if kty == 2 and alg == ALG_ES256:
        x, y = cose.get(-2), cose.get(-3)
        if cose.get(-1) != 1 or not isinstance(x, bytes) or not isinstance(y, bytes) \
                or len(x) != 32 or len(y) != 32:
            raise WebAuthnError('unsupported_alg', 'EC2 key is not P-256')
        try:
            key = c['ec'].EllipticCurvePublicKey.from_encoded_point(
                c['ec'].SECP256R1(), b'\x04' + x + y)
        except ValueError:
            raise WebAuthnError('unsupported_alg', 'EC2 point is not on P-256') from None
        return ALG_ES256, key
    if kty == 3 and alg == ALG_RS256:
        n, e = cose.get(-1), cose.get(-2)
        if not isinstance(n, bytes) or not isinstance(e, bytes) or not n or not e or len(e) > 8:
            raise WebAuthnError('unsupported_alg', 'RSA key fields')
        ni, ei = int.from_bytes(n, 'big'), int.from_bytes(e, 'big')
        if ni.bit_length() < RSA_MIN_BITS:
            raise WebAuthnError('unsupported_alg', f'RSA key under {RSA_MIN_BITS} bits')
        if ei < 3 or ei % 2 == 0:
            raise WebAuthnError('unsupported_alg', 'RSA exponent')
        try:
            key = c['rsa'].RSAPublicNumbers(ei, ni).public_key()
        except ValueError:
            raise WebAuthnError('unsupported_alg', 'RSA key') from None
        return ALG_RS256, key
    raise WebAuthnError('unsupported_alg', f'kty {kty!r} alg {alg!r}')


def _spki(key):
    s = _crypto()['serialization']
    return s.Encoding.DER, s.PublicFormat.SubjectPublicKeyInfo


def public_key_b64(key):
    """SubjectPublicKeyInfo DER, base64url: how a stored passkey keeps its key."""
    enc, fmt = _spki(key)
    return b64u(key.public_bytes(enc, fmt))


def load_public_key(alg, spki_b64):
    c = _crypto()
    try:
        key = c['serialization'].load_der_public_key(unb64u(spki_b64, 4096, 'public_key'))
    except (ValueError, TypeError, WebAuthnError):
        raise WebAuthnError('unsupported_alg', 'stored public key does not load') from None
    if alg == ALG_ES256 and isinstance(key, c['ec'].EllipticCurvePublicKey) \
            and isinstance(key.curve, c['ec'].SECP256R1):
        return key
    if alg == ALG_RS256 and isinstance(key, c['rsa'].RSAPublicKey) and key.key_size >= RSA_MIN_BITS:
        return key
    raise WebAuthnError('unsupported_alg', f'stored key does not match alg {alg!r}')


# ---- shared checks -----------------------------------------------------------------

def _shape(cred, field):
    if not isinstance(cred, dict) or cred.get('type') != 'public-key':
        raise WebAuthnError('bad_credential', 'type is not public-key')
    cid, raw = cred.get('id'), cred.get('rawId')
    id_bytes = unb64u(cid, MAX_CRED_ID, 'id')
    if not id_bytes or unb64u(raw, MAX_CRED_ID, 'rawId') != id_bytes:
        raise WebAuthnError('bad_credential', 'rawId != id')
    resp = cred.get('response')
    if not isinstance(resp, dict) or not isinstance(resp.get('clientDataJSON'), str) \
            or not isinstance(resp.get(field), str):
        raise WebAuthnError('bad_credential', 'response fields missing')
    return id_bytes, resp


def _client_data(raw, want_type, challenge, origin):
    try:
        cd = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        raise WebAuthnError('bad_client_data', 'not UTF-8 JSON') from None
    if not isinstance(cd, dict) or cd.get('type') != want_type:
        raise WebAuthnError('bad_client_data', f'type is not {want_type}')
    got = cd.get('challenge')
    if not isinstance(challenge, (bytes, bytearray)) or not challenge:
        raise WebAuthnError('challenge_mismatch', 'no issued challenge')
    if not isinstance(got, str) or not hmac.compare_digest(
            got.encode('utf-8', 'replace'), b64u(challenge).encode('ascii')):
        raise WebAuthnError('challenge_mismatch')
    if not isinstance(cd.get('origin'), str) or cd['origin'] != origin:
        raise WebAuthnError('origin_mismatch', f'origin {cd.get("origin")!r}')
    if cd.get('crossOrigin') is True:
        raise WebAuthnError('origin_mismatch', 'crossOrigin')
    if 'topOrigin' in cd:
        raise WebAuthnError('origin_mismatch', 'topOrigin')
    return cd


def _check_rp_flags(ad, rp_id):
    if not hmac.compare_digest(ad['rp_id_hash'], hashlib.sha256(rp_id.encode('utf-8')).digest()):
        raise WebAuthnError('rp_mismatch')
    if not ad['up']:
        raise WebAuthnError('no_up')
    if not ad['uv']:
        raise WebAuthnError('no_uv')


# ---- registration ------------------------------------------------------------------

def verify_registration(cred, challenge, origin, rp_id):
    """Check a navigator.credentials.create() result (toJSON shape).

    challenge: the issued bytes. origin: the exact expected origin
    ("https://pocket.tunnel.cush.rocks"). rp_id: the exact rpId.
    Returns {id, public_key, alg, sign_count, aaguid, be, bs, transports}:
    id is base64url, public_key the SPKI DER as base64url (load_public_key),
    aaguid a UUID string. Raises WebAuthnError.
    """
    _crypto()
    id_bytes, resp = _shape(cred, 'attestationObject')
    cdj = unb64u(resp['clientDataJSON'], MAX_CLIENT_DATA, 'clientDataJSON')
    _client_data(cdj, 'webauthn.create', challenge, origin)
    att = cbor_decode(unb64u(resp['attestationObject'], MAX_ATT_OBJECT, 'attestationObject'))
    if not isinstance(att, dict) or not isinstance(att.get('fmt'), str) \
            or not isinstance(att.get('attStmt'), dict) or not isinstance(att.get('authData'), bytes):
        raise WebAuthnError('malformed_cbor', 'attestationObject needs fmt, attStmt, authData')
    # attestation "none" policy: any fmt, attStmt ignored.
    ad = parse_auth_data(att['authData'])
    _check_rp_flags(ad, rp_id)
    if ad['credential_id'] is None:
        raise WebAuthnError('bad_auth_data', 'no attested credential (AT off)')
    if not hmac.compare_digest(ad['credential_id'], id_bytes):
        raise WebAuthnError('bad_credential', 'authData credential id != rawId')
    alg, key = parse_cose_key(ad['cose_key'])
    transports = resp.get('transports')
    transports = [t for t in transports if t in TRANSPORTS][:8] if isinstance(transports, list) else []
    return {
        'id': b64u(id_bytes),
        'public_key': public_key_b64(key),
        'alg': alg,
        'sign_count': ad['sign_count'],
        'aaguid': str(uuid.UUID(bytes=ad['aaguid'])),
        'be': ad['be'],
        'bs': ad['bs'],
        'transports': transports,
    }


# ---- assertion ---------------------------------------------------------------------

def _find(stored, id_b64):
    records = [stored] if isinstance(stored, dict) else list(stored or ())
    for rec in records:
        if isinstance(rec, dict) and isinstance(rec.get('id'), str) \
                and hmac.compare_digest(rec['id'].rstrip('=').encode(), id_b64.encode()):
            return rec
    raise WebAuthnError('unknown_credential')


def verify_assertion(cred, stored, challenge, origin, rp_id, user_handle):
    """Check a navigator.credentials.get() result (toJSON shape).

    stored: one record or a list of records as verify_registration returned
    them (needs id, public_key, alg, sign_count). user_handle: the owner's
    user handle bytes (a present, non-empty userHandle must equal it).
    Returns {id, sign_count, be, bs}; the caller saves sign_count.
    Raises WebAuthnError (counter_regressed only after the signature checked).
    """
    c = _crypto()
    id_bytes, resp = _shape(cred, 'authenticatorData')
    rec = _find(stored, b64u(id_bytes))
    cdj = unb64u(resp['clientDataJSON'], MAX_CLIENT_DATA, 'clientDataJSON')
    _client_data(cdj, 'webauthn.get', challenge, origin)
    ad_raw = unb64u(resp['authenticatorData'], MAX_AUTH_DATA, 'authenticatorData')
    ad = parse_auth_data(ad_raw)
    _check_rp_flags(ad, rp_id)
    uh = resp.get('userHandle')
    if uh not in (None, ''):
        got = unb64u(uh, MAX_USER_HANDLE, 'userHandle')
        if user_handle is None or not hmac.compare_digest(got, bytes(user_handle)):
            raise WebAuthnError('user_mismatch')
    sig = unb64u(resp.get('signature'), MAX_SIGNATURE, 'signature')
    key = load_public_key(rec.get('alg'), rec.get('public_key'))
    signed = ad_raw + hashlib.sha256(cdj).digest()
    try:
        if rec['alg'] == ALG_ES256:
            key.verify(sig, signed, c['ec'].ECDSA(c['hashes'].SHA256()))
        else:
            key.verify(sig, signed, c['padding'].PKCS1v15(), c['hashes'].SHA256())
    except (c['InvalidSignature'], ValueError):
        raise WebAuthnError('bad_signature') from None
    old, new = rec.get('sign_count') or 0, ad['sign_count']
    if not (old == 0 and new == 0) and new <= old:
        raise WebAuthnError('counter_regressed', f'stored {old}, got {new}')
    return {'id': b64u(id_bytes), 'sign_count': new, 'be': ad['be'], 'bs': ad['bs']}


# ---- options -----------------------------------------------------------------------

def _descriptors(creds):
    out = []
    for item in creds or ():
        if isinstance(item, dict):
            d = {'type': 'public-key', 'id': item['id']}
            ts = [t for t in item.get('transports') or () if t in TRANSPORTS]
            if ts:
                d['transports'] = ts
        else:
            d = {'type': 'public-key', 'id': item}
        out.append(d)
    return out


def creation_options(challenge, rp_id, user_handle, *, brand='Porch', user_name=None,
                     display_name=None, exclude=(), timeout=TIMEOUT_MS):
    """PublicKeyCredentialCreationOptions as JSON (b64url strings), for
    PublicKeyCredential.parseCreationOptionsFromJSON or a manual decode.
    exclude: stored ids (b64url) or records with id/transports."""
    return {
        'rp': {'id': rp_id, 'name': brand},
        'user': {'id': b64u(user_handle), 'name': user_name or f'owner@{rp_id}',
                 'displayName': display_name or f'{brand} owner'},
        'challenge': b64u(challenge),
        'pubKeyCredParams': [{'type': 'public-key', 'alg': ALG_ES256},
                             {'type': 'public-key', 'alg': ALG_RS256}],
        'authenticatorSelection': {'residentKey': 'preferred', 'requireResidentKey': False,
                                   'userVerification': 'required'},
        'attestation': 'none',
        'excludeCredentials': _descriptors(exclude),
        'timeout': timeout,
    }


def request_options(challenge, rp_id, *, allow=(), timeout=TIMEOUT_MS):
    """PublicKeyCredentialRequestOptions as JSON. allow: every stored id (or
    record), so iOS offers the right passkey."""
    return {
        'challenge': b64u(challenge),
        'rpId': rp_id,
        'allowCredentials': _descriptors(allow),
        'userVerification': 'required',
        'timeout': timeout,
    }

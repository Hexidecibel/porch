"""A software WebAuthn authenticator for tests only (never imported by lib/).

    cbor_encode(value)          canonical CBOR (CTAP2 ordering) for int, bytes,
                                str, list, dict, bool, None
    SoftAuthenticator(alg=-7)   holds one credential (ES256 or RS256) and
                                makes toJSON-shaped results:
        .register(challenge, origin, rp_id, **knobs)
        .assertion(challenge, origin, rp_id, **knobs)

The knobs let a test break exactly one rule: flags, rp_id_hash, client data
fields (`client={...}` merged over the defaults, `client_raw=` bytes
verbatim), fmt/attStmt, the COSE map, the counter, userHandle, a flipped
signature byte.
"""
import base64
import hashlib
import json
import os
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

UP, UV, BE, BS, AT, ED = 0x01, 0x04, 0x08, 0x10, 0x40, 0x80


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')


def _head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | ai]) + n.to_bytes(size, 'big')
    raise ValueError('int too large')


def cbor_encode(v):
    if v is False:
        return b'\xf4'
    if v is True:
        return b'\xf5'
    if v is None:
        return b'\xf6'
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, (bytes, bytearray)):
        return _head(2, len(v)) + bytes(v)
    if isinstance(v, str):
        b = v.encode('utf-8')
        return _head(3, len(b)) + b
    if isinstance(v, (list, tuple)):
        return _head(4, len(v)) + b''.join(cbor_encode(x) for x in v)
    if isinstance(v, dict):
        items = sorted(((cbor_encode(k), cbor_encode(x)) for k, x in v.items()),
                       key=lambda kv: (len(kv[0]), kv[0]))
        return _head(5, len(items)) + b''.join(k + x for k, x in items)
    raise TypeError(type(v))


class SoftAuthenticator:
    def __init__(self, alg=-7, rsa_bits=2048, sign_count=0, aaguid=None, cred_id=None,
                 user_handle=None):
        self.alg = alg
        if alg == -7:
            self.key = ec.generate_private_key(ec.SECP256R1())
        elif alg == -257:
            self.key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
        else:
            raise ValueError(alg)
        self.sign_count = sign_count
        self.aaguid = aaguid if aaguid is not None else bytes(range(16))
        self.cred_id = cred_id if cred_id is not None else os.urandom(32)
        self.user_handle = user_handle if user_handle is not None else os.urandom(16)

    # ---- pieces ----
    def cose(self):
        pub = self.key.public_key()
        if self.alg == -7:
            n = pub.public_numbers()
            return {1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, 'big'), -3: n.y.to_bytes(32, 'big')}
        n = pub.public_numbers()
        return {1: 3, 3: -257, -1: n.n.to_bytes((n.n.bit_length() + 7) // 8, 'big'),
                -2: n.e.to_bytes(3, 'big')}

    @staticmethod
    def client_data(type_, challenge, origin, client=None, client_raw=None):
        if client_raw is not None:
            return client_raw
        cd = {'type': type_, 'challenge': b64u(challenge), 'origin': origin, 'crossOrigin': False}
        cd.update(client or {})
        cd = {k: v for k, v in cd.items() if v is not ...}
        return json.dumps(cd, separators=(',', ':')).encode()

    def auth_data(self, rp_id, flags, count, *, rp_id_hash=None, attested=False, cose=None,
                  extensions=None, cred_id=None, trailing=b''):
        h = rp_id_hash if rp_id_hash is not None else hashlib.sha256(rp_id.encode()).digest()
        out = h + bytes([flags]) + struct.pack('>I', count)
        if attested:
            cid = self.cred_id if cred_id is None else cred_id
            out += self.aaguid + struct.pack('>H', len(cid)) + cid
            out += cbor_encode(self.cose() if cose is None else cose)
        if extensions is not None:
            out += cbor_encode(extensions)
        return out + trailing

    def sign(self, data):
        if self.alg == -7:
            return self.key.sign(data, ec.ECDSA(hashes.SHA256()))
        return self.key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    # ---- ceremonies ----
    def register(self, challenge, origin, rp_id, *, flags=UP | UV | AT, fmt='none',
                 att_stmt=None, client=None, client_raw=None, rp_id_hash=None, cose=None,
                 extensions=None, auth_data=None, transports=('internal',), cred_id=None,
                 raw_id=None, type_='public-key'):
        if extensions is not None:
            flags |= ED
        cdj = self.client_data('webauthn.create', challenge, origin, client, client_raw)
        ad = auth_data if auth_data is not None else self.auth_data(
            rp_id, flags, self.sign_count, rp_id_hash=rp_id_hash, attested=bool(flags & AT),
            cose=cose, extensions=extensions, cred_id=cred_id)
        att = cbor_encode({'fmt': fmt, 'attStmt': att_stmt or {}, 'authData': ad})
        cid = b64u(self.cred_id)
        return {'id': cid, 'rawId': raw_id if raw_id is not None else cid, 'type': type_,
                'response': {'clientDataJSON': b64u(cdj), 'attestationObject': b64u(att),
                             'transports': list(transports)},
                'clientExtensionResults': {}}

    def assertion(self, challenge, origin, rp_id, *, flags=UP | UV, client=None,
                  client_raw=None, rp_id_hash=None, count=None, step=1, user_handle=...,
                  flip_sig=False, cred_id=None):
        if count is None:
            self.sign_count = self.sign_count + step if step else self.sign_count
            count = self.sign_count
        cdj = self.client_data('webauthn.get', challenge, origin, client, client_raw)
        ad = self.auth_data(rp_id, flags, count, rp_id_hash=rp_id_hash)
        sig = bytearray(self.sign(ad + hashlib.sha256(cdj).digest()))
        if flip_sig:
            sig[len(sig) // 2] ^= 0x01
        uh = self.user_handle if user_handle is ... else user_handle
        cid = b64u(self.cred_id if cred_id is None else cred_id)
        return {'id': cid, 'rawId': cid, 'type': 'public-key',
                'response': {'clientDataJSON': b64u(cdj), 'authenticatorData': b64u(ad),
                             'signature': b64u(bytes(sig)),
                             'userHandle': b64u(uh) if uh is not None else None},
                'clientExtensionResults': {}}

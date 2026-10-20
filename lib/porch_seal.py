#!/usr/bin/env python3
"""porch-seal v1: end-to-end encrypted files for `porch share --e2e`.

The box that serves a sealed share only ever holds ciphertext; the key travels
in the link's fragment (#k=..., never sent to a server) or is derived from a
password the recipient types. lib/seal.js is the browser/node twin of this
module and must stay byte-compatible with it (tests/test_porch_seal.py checks
both directions and fixed vectors). Spec and threat model: docs/porch-seal.md.

Format (all integers big-endian):

    header H (48 bytes)
        magic "PSEAL1\\n\\0" (8) | version 0x01 | mode (0 key, 1 password)
        | salt (16, zeros in key mode) | nonce prefix (8) | record size R (4,
        = 65536) | 10 zero bytes
    record 0 (metadata)   plaintext exactly 4096 bytes: uint32 L | UTF-8 JSON
                          {"name","type","size"} (L <= 4092) | zero padding
    records 1..n          R plaintext bytes each, the last 1..R; an empty
                          file has n = 0
    each record           AES-256-GCM, 16-byte tag appended; nonce =
                          prefix (8) | uint32(i); AAD = H | final flag
                          (0x01 on the last record: record 0 when n = 0, else
                          record n; 0x00 otherwise)
    key                   32 random bytes (link: #k=<base64url, no padding>),
                          or PBKDF2-HMAC-SHA256(password, salt, 600000, 32)

Ciphertext layout: record 0 at 48 (4112 bytes); record i >= 1 at
48 + 4112 + (i-1)*(R+16), R+16 bytes, the last shorter. Total
48 + 4112 + n*16 + size.

`cryptography` (python3-cryptography) is imported lazily, only when a record
is actually encrypted or decrypted; header/offset helpers work without it.

CLI (tests and debugging):
    porch_seal.py seal <src> <dst> [--name N] [--type MIME] [--key B64 | --password-env VAR]
                       prints the key (key mode) or "password"
    porch_seal.py open <src> <dst|-> [--key B64 | --password-env VAR]
                       writes the plaintext, prints the metadata JSON on stderr
    porch_seal.py info <src>          header + sizes as JSON (no key needed)
"""

import base64
import hashlib
import json
import math
import os
import secrets
import struct
import sys

MAGIC = b'PSEAL1\n\x00'
VERSION = 1
MODE_KEY = 0
MODE_PASSWORD = 1
HEADER_LEN = 48
RECORD_SIZE = 65536
TAG_LEN = 16
META_PLAIN = 4096
META_JSON_MAX = META_PLAIN - 4
META_CT = META_PLAIN + TAG_LEN              # 4112
DATA_START = HEADER_LEN + META_CT           # 4160: first content record
KEY_LEN = 32
SALT_LEN = 16
PREFIX_LEN = 8
PBKDF2_ITERATIONS = 600000
MAX_NAME = 255

APT_HINT = 'sudo apt install python3-cryptography'


class SealError(ValueError):
    """A sealed file that does not open. kind: 'format' (not a porch-seal v1
    file, or its length does not add up), 'key' (record 0 does not decrypt:
    wrong key/password, or the start of the file was changed), 'tamper' (a
    later record does not decrypt: changed, reordered or cut)."""

    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


class SealUnavailable(RuntimeError):
    """python3-cryptography is not installed."""


def _aesgcm(key):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise SealUnavailable('end-to-end encryption needs python3-cryptography '
                              f'(install it with: {APT_HINT})') from None
    return AESGCM(key)


def available():
    try:
        _aesgcm(bytes(KEY_LEN))
        return True
    except SealUnavailable:
        return False


# ---- keys ---------------------------------------------------------------------

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def unb64url(text):
    if not isinstance(text, str) or not text or len(text) > 128:
        raise SealError('key', 'the key is missing or malformed')
    try:
        return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))
    except (ValueError, TypeError):
        raise SealError('key', 'the key is not base64url') from None


def new_key():
    return secrets.token_bytes(KEY_LEN)


def key_bytes(key):
    """32 raw key bytes from bytes or a base64url string."""
    raw = key if isinstance(key, (bytes, bytearray)) else unb64url(key)
    if len(raw) != KEY_LEN:
        raise SealError('key', 'the key must be 32 bytes')
    return bytes(raw)


def derive_key(password, salt):
    if not isinstance(password, str) or not password:
        raise SealError('key', 'empty password')
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes(salt),
                               PBKDF2_ITERATIONS, KEY_LEN)


# ---- header and offsets -----------------------------------------------------

def build_header(mode, salt, prefix, record_size=RECORD_SIZE):
    if mode not in (MODE_KEY, MODE_PASSWORD):
        raise ValueError('mode must be 0 (key) or 1 (password)')
    if len(salt) != SALT_LEN or len(prefix) != PREFIX_LEN:
        raise ValueError('salt is 16 bytes, nonce prefix 8')
    h = MAGIC + bytes([VERSION, mode]) + bytes(salt) + bytes(prefix) \
        + struct.pack('>I', record_size) + bytes(10)
    assert len(h) == HEADER_LEN
    return h


def parse_header(h):
    """{'mode', 'salt', 'prefix', 'record_size'} or SealError('format')."""
    if len(h) < HEADER_LEN:
        raise SealError('format', 'too short to be a sealed file')
    h = bytes(h[:HEADER_LEN])
    if h[:8] != MAGIC:
        raise SealError('format', 'not a porch-seal file (bad magic)')
    if h[8] != VERSION:
        raise SealError('format', f'unsupported porch-seal version {h[8]}')
    mode = h[9]
    if mode not in (MODE_KEY, MODE_PASSWORD):
        raise SealError('format', f'unknown porch-seal mode {mode}')
    salt, prefix = h[10:26], h[26:34]
    (rs,) = struct.unpack('>I', h[34:38])
    if rs != RECORD_SIZE:
        raise SealError('format', f'unsupported record size {rs}')
    if h[38:48] != bytes(10):
        raise SealError('format', 'reserved header bytes are not zero')
    if mode == MODE_KEY and salt != bytes(SALT_LEN):
        raise SealError('format', 'key-mode header carries a salt')
    return {'mode': mode, 'salt': salt, 'prefix': prefix, 'record_size': rs}


def record_count(size, record_size=RECORD_SIZE):
    return math.ceil(size / record_size) if size > 0 else 0


def ciphertext_size(size, record_size=RECORD_SIZE):
    """Exact sealed length of a `size`-byte plaintext (tus Upload-Length)."""
    return DATA_START + record_count(size, record_size) * TAG_LEN + size


def record_span(i, size, record_size=RECORD_SIZE):
    """(offset, length) of record i in the ciphertext of a `size`-byte file."""
    if i == 0:
        return HEADER_LEN, META_CT
    n = record_count(size, record_size)
    if not 1 <= i <= n:
        raise IndexError(f'record {i} out of range (n={n})')
    off = DATA_START + (i - 1) * (record_size + TAG_LEN)
    plain = record_size if i < n else size - (n - 1) * record_size
    return off, plain + TAG_LEN


def plaintext_size(ct_size, record_size=RECORD_SIZE):
    """Invert ciphertext_size(); SealError('format') if no plaintext size fits
    (truncated or padded file)."""
    rest = ct_size - DATA_START
    if rest < 0:
        raise SealError('format', 'the sealed file is cut short')
    if rest == 0:
        return 0
    n = math.ceil(rest / (record_size + TAG_LEN))
    size = rest - n * TAG_LEN
    if size <= (n - 1) * record_size:
        raise SealError('format', 'the sealed file has a broken length')
    return size


def nonce(prefix, i):
    return bytes(prefix) + struct.pack('>I', i)


def aad(header, final):
    return bytes(header) + (b'\x01' if final else b'\x00')


def meta_plaintext(name, mime, size):
    name = str(name or 'file')
    if len(name) > MAX_NAME:
        stem, ext = os.path.splitext(name)
        ext = ext if len(ext) <= 16 else ''
        name = stem[:MAX_NAME - len(ext)] + ext
    body = json.dumps({'name': name, 'type': str(mime or 'application/octet-stream'),
                       'size': int(size)}, separators=(',', ':'),
                      ensure_ascii=False).encode('utf-8')
    if len(body) > META_JSON_MAX:
        raise ValueError('metadata does not fit in record 0')
    return struct.pack('>I', len(body)) + body + bytes(META_JSON_MAX - len(body))


def parse_meta(plain):
    if len(plain) != META_PLAIN:
        raise SealError('format', 'metadata record has the wrong size')
    (n,) = struct.unpack('>I', plain[:4])
    if n > META_JSON_MAX or any(plain[4 + n:]):
        raise SealError('format', 'metadata record is malformed')
    try:
        meta = json.loads(plain[4:4 + n].decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        raise SealError('format', 'metadata is not JSON') from None
    if (not isinstance(meta, dict) or not isinstance(meta.get('name'), str)
            or not isinstance(meta.get('type'), str)
            or not isinstance(meta.get('size'), int) or isinstance(meta.get('size'), bool)
            or meta['size'] < 0):
        raise SealError('format', 'metadata is missing name/type/size')
    return meta


# ---- seal ---------------------------------------------------------------------

class _borrowed:
    """A caller's file object in a with block, left open afterwards."""

    def __init__(self, f):
        self.f = f

    def __enter__(self):
        return self.f

    def __exit__(self, *exc):
        return False


def seal_file(src, dst, name, mime, key=None, password=None, *, _test_salt=None,
              _test_prefix=None):
    """Seal `src` (a path, or a seekable binary file object such as BytesIO:
    stdin never touches the disk) into `dst` (created 0600, O_EXCL),
    streaming one record at a time. Key mode (default): `key` (bytes or base64url) or a fresh one;
    returns the key as base64url. Password mode: returns None. The
    _test_* arguments fix the salt / nonce prefix for test vectors only."""
    if key is not None and password is not None:
        raise ValueError('give a key or a password, not both')
    salt_prefix = _test_prefix if _test_prefix is not None else secrets.token_bytes(PREFIX_LEN)
    if password is not None:
        mode = MODE_PASSWORD
        salt = _test_salt if _test_salt is not None else secrets.token_bytes(SALT_LEN)
        k = derive_key(password, salt)
    else:
        mode = MODE_KEY
        salt = bytes(SALT_LEN)
        k = key_bytes(key) if key is not None else new_key()
    gcm = _aesgcm(k)
    header = build_header(mode, salt, salt_prefix)
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
                 | getattr(os, 'O_CLOEXEC', 0), 0o600)
    try:
        with (_borrowed(src) if hasattr(src, 'read') else open(src, 'rb')) as fin, \
                os.fdopen(fd, 'wb') as fout:
            fd = None
            if hasattr(src, 'read'):
                size = fin.seek(0, os.SEEK_END)
                fin.seek(0)
            else:
                size = os.fstat(fin.fileno()).st_size
            n = record_count(size)
            fout.write(header)
            fout.write(gcm.encrypt(nonce(salt_prefix, 0), meta_plaintext(name, mime, size),
                                   aad(header, n == 0)))
            for i in range(1, n + 1):
                want = RECORD_SIZE if i < n else size - (n - 1) * RECORD_SIZE
                chunk = fin.read(want)
                if len(chunk) != want:
                    raise OSError(f'{src} changed while it was being sealed')
                fout.write(gcm.encrypt(nonce(salt_prefix, i), chunk, aad(header, i == n)))
            if fin.read(1):
                raise OSError(f'{src} grew while it was being sealed')
            fout.flush()
            os.fsync(fout.fileno())
    except BaseException:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(dst)
        except OSError:
            pass
        raise
    return b64url(k) if mode == MODE_KEY else None


# ---- open -----------------------------------------------------------------------

def _read_exact(f, n):
    data = f.read(n)
    if len(data) != n:
        raise SealError('tamper', 'the sealed file is cut short')
    return data


def open_file(src, key_b64=None, password=None):
    """(meta, iterator of plaintext chunks). Record 0 is checked before this
    returns (wrong key/password -> SealError('key')); each later record is
    checked as the iterator reaches it (SealError('tamper')). The length is
    checked up front against the metadata, so a cut or padded file fails
    before any content is yielded."""
    f = open(src, 'rb')
    try:
        total = os.fstat(f.fileno()).st_size
        header = f.read(HEADER_LEN)
        hdr = parse_header(header)
        if hdr['mode'] == MODE_PASSWORD:
            if password is None:
                raise SealError('key', 'this file is sealed with a password')
            k = derive_key(password, hdr['salt'])
        else:
            if key_b64 is None:
                raise SealError('key', 'this file needs its key (#k=...)')
            k = key_bytes(key_b64)
        n = record_count(plaintext_size(total))
        gcm = _aesgcm(k)
        from cryptography.exceptions import InvalidTag
        try:
            plain0 = gcm.decrypt(nonce(hdr['prefix'], 0), _read_exact(f, META_CT),
                                 aad(header, n == 0))
        except (InvalidTag, SealError):
            raise SealError('key', 'wrong password, or the file was changed' if password is not None
                            else 'wrong key, or the file was changed') from None
        meta = parse_meta(plain0)
        if ciphertext_size(meta['size']) != total:
            raise SealError('tamper', 'the sealed file has the wrong length (cut or padded)')
    except BaseException:
        f.close()
        raise

    def chunks():
        with f:
            for i in range(1, n + 1):
                _, length = record_span(i, meta['size'])
                ct = _read_exact(f, length)
                try:
                    yield gcm.decrypt(nonce(hdr['prefix'], i), ct, aad(header, i == n))
                except InvalidTag:
                    raise SealError('tamper', f'record {i} was changed, reordered or cut') from None
            if f.read(1):
                raise SealError('tamper', 'trailing bytes after the last record')
    return meta, chunks()


def info(src):
    with open(src, 'rb') as f:
        total = os.fstat(f.fileno()).st_size
        hdr = parse_header(f.read(HEADER_LEN))
    size = plaintext_size(total)
    return {'mode': 'password' if hdr['mode'] == MODE_PASSWORD else 'key',
            'record_size': hdr['record_size'], 'ciphertext_size': total,
            'plaintext_size': size, 'records': record_count(size)}


# ---- CLI --------------------------------------------------------------------------

def _secret_from_env(var):
    v = os.environ.get(var or '')
    if not v:
        raise SystemExit(f'porch_seal: ${var} is not set')
    return v


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(description='porch-seal v1 (tests and debugging)')
    sub = p.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('seal')
    s.add_argument('src')
    s.add_argument('dst')
    s.add_argument('--name')
    s.add_argument('--type', default='application/octet-stream')
    s.add_argument('--key')
    s.add_argument('--password-env')
    o = sub.add_parser('open')
    o.add_argument('src')
    o.add_argument('dst')
    o.add_argument('--key')
    o.add_argument('--password-env')
    i = sub.add_parser('info')
    i.add_argument('src')
    a = p.parse_args(argv)
    try:
        if a.cmd == 'info':
            print(json.dumps(info(a.src)))
            return 0
        pw = _secret_from_env(a.password_env) if a.password_env else None
        if a.cmd == 'seal':
            k = seal_file(a.src, a.dst, a.name or os.path.basename(a.src), a.type,
                          key=a.key, password=pw)
            print(k if k else 'password')
            return 0
        meta, it = open_file(a.src, key_b64=a.key, password=pw)
        if a.dst == '-':
            for chunk in it:
                sys.stdout.buffer.write(chunk)
        else:
            try:
                with open(a.dst, 'xb') as out:
                    for chunk in it:
                        out.write(chunk)
            except SealError:
                os.unlink(a.dst)            # never leave a half-checked plaintext
                raise
        sys.stderr.write(json.dumps(meta) + '\n')
        return 0
    except SealUnavailable as e:
        sys.stderr.write(f'porch_seal: {e}\n')
        return 3
    except SealError as e:
        sys.stderr.write(f'porch_seal: {e.kind}: {e}\n')
        return 1
    except OSError as e:
        sys.stderr.write(f'porch_seal: {e}\n')
        return 1


if __name__ == '__main__':
    sys.exit(main())

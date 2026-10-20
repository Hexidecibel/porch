"""Pocket's stores and helpers, used by lib/pocketserver.py: the clipboard,
device share keys, rate limits, the SSE change hub, multipart with field
names, the inbox and sealed-upload helpers, and the limits they share."""

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
import rundir  # noqa: E402
from porch_http import MultipartStreamer, atomic_write_bytes  # noqa: E402  (shared HTTP core)
from porch_http import sanitize_filename as _sanitize_filename  # noqa: E402


MAX_FILE_SIZE = 1024 * 1024 * 1024    # 1GB per file
DEFAULT_MAX_TOTAL_MB = 10 * 1024      # inbox total; --max-total-mb overrides
MAX_FILES = 2000
MAX_NAME = 120
MAX_CLIP_BYTES = 1024 * 1024          # one clipboard entry (UTF-8)
MAX_HISTORY = 20
MAX_FIELD_BYTES = MAX_CLIP_BYTES      # one share-target text field
SSE_HEARTBEAT = 15                    # s between keep-alive comments
SSE_MAX_AGE = 25 * 60                 # s before a stream is recycled (the page reconnects)
SSE_MAX_TOTAL = 16
SSE_MAX_PER_CLIENT = 4

CLI_TOKEN_HEADER = 'X-Porch-CLI-Token'
# Device share keys (iOS Shortcuts): write-only, POST /share and nothing else.
SHARE_KEY_HEADER = 'X-Porch-Share-Key'
SHARE_KEY_PREFIX = 'pks_'
MAX_SHARE_KEYS = 10
MAX_KEY_LABEL = 40
KEY_RATE = (60, 600)           # shares one key may make per window (s)
KEY_FAIL_RATE = (10, 600)      # wrong-key attempts per client address per window
_KEY_ID = re.compile(r'^[A-Za-z0-9_-]{8,16}$')
_SHARE_KEY = re.compile(r'^' + SHARE_KEY_PREFIX + r'[A-Za-z0-9_-]{43}$')
# Present on anything that came through HAProxy/frp or from a page: the CLI
# token is ignored on such a request even when it is right.
NOT_LOCAL_HEADERS = ('X-Forwarded-For', 'X-Forwarded-Host', 'X-Forwarded-Proto',
                     'X-Forwarded-Port', 'X-Real-IP', 'Forwarded', 'Via',
                     'Origin', 'Referer')
_LOCAL_HOST = re.compile(r'^(127\.0\.0\.1|localhost|\[::1\])(:[0-9]{1,5})?$')
_CLIP_ID = re.compile(r'^[A-Za-z0-9_-]{8,32}$')
_PHONE_UA = re.compile(r'Mobi|Android|iPhone|iPad|iPod', re.I)


# Inline only for types a browser shows without running anything; everything
# else (and any ?dl=1) goes out as an opaque attachment.
INLINE_TYPES = {
    '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
    '.gif': 'image/gif', '.webp': 'image/webp', '.avif': 'image/avif',
    '.mp4': 'video/mp4', '.webm': 'video/webm', '.mov': 'video/quicktime',
    '.mp3': 'audio/mpeg', '.m4a': 'audio/mp4', '.ogg': 'audio/ogg',
    '.pdf': 'application/pdf', '.txt': 'text/plain; charset=utf-8',
}


def sanitize_filename(name):
    return _sanitize_filename(name, MAX_NAME)


def name_candidates(name):
    """As-is, then a counter, then random suffixes (place_unique claims one)."""
    yield name
    stem, suffix = os.path.splitext(name)
    for counter in range(1, 50):
        yield f"{stem}_{counter}{suffix}"
    for _ in range(16):
        yield f"{stem}_{secrets.token_hex(6)}{suffix}"


def device_hint(ua):
    """'phone' or 'desktop' from a User-Agent. Display only, never trusted."""
    return 'phone' if _PHONE_UA.search(ua or '') else 'desktop'




# ---- clipboard store ---------------------------------------------------------

class ClipStore:
    """The clipboard: newest entry first; entries[0] is the current slot.

    Persisted to one 0600 JSON file (atomic replace) after every change.
    """

    def __init__(self, path, max_entries=MAX_HISTORY, max_text=MAX_CLIP_BYTES):
        self.path = Path(path)
        self.max_entries = max_entries
        self.max_text = max_text
        self.lock = threading.Lock()
        self.entries = self._load()

    def _load(self):
        try:
            data = json.loads(self.path.read_text('utf-8'))
        except (OSError, ValueError):
            return []
        out = []
        for e in data.get('entries', []) if isinstance(data, dict) else []:
            if not isinstance(e, dict):
                continue
            eid, text, ts = e.get('id'), e.get('text'), e.get('ts')
            if not (isinstance(eid, str) and _CLIP_ID.match(eid) and isinstance(text, str)
                    and isinstance(ts, (int, float))):
                continue
            src = e.get('source') if isinstance(e.get('source'), str) else ''
            out.append({'id': eid, 'text': text[:self.max_text], 'ts': ts, 'source': src[:16]})
        return out[:self.max_entries]

    def _save(self):
        body = json.dumps({'entries': self.entries}).encode('utf-8')
        atomic_write_bytes(self.path, body, mode=0o600)

    def snapshot(self):
        with self.lock:
            return {'current': self.entries[0] if self.entries else None,
                    'history': list(self.entries[1:])}

    def add(self, text, source):
        """Make `text` the current entry. An identical older entry moves up
        instead of being duplicated. Returns the entry."""
        entry = {'id': secrets.token_urlsafe(9), 'text': text,
                 'ts': round(time.time(), 3), 'source': source}
        with self.lock:
            self.entries = [entry] + [e for e in self.entries if e['text'] != text]
            del self.entries[self.max_entries:]
            self._save()
        return entry

    def get(self, eid):
        with self.lock:
            for e in self.entries:
                if e['id'] == eid:
                    return dict(e)
        return None

    def delete(self, eid):
        with self.lock:
            kept = [e for e in self.entries if e['id'] != eid]
            if len(kept) == len(self.entries):
                return False
            self.entries = kept
            self._save()
            return True


# ---- device share keys -------------------------------------------------------

def _hash_key(key):
    return hashlib.sha256(key.encode('utf-8')).hexdigest()


def clean_label(label):
    """A display label: printable, single-line, at most MAX_KEY_LABEL chars."""
    if not isinstance(label, str):
        return ''
    label = ''.join(ch if ch.isprintable() else ' ' for ch in label)
    return ' '.join(label.split())[:MAX_KEY_LABEL]


class KeyStore:
    """Device share keys: what an iOS Shortcut sends instead of a cookie.

    A key only ever unlocks POST /share (write-only: it can add to the inbox
    and set the clipboard, never read either). Only its SHA-256 is kept, in
    one 0600 JSON file; the key itself is shown once, at creation or
    rotation. Several keys, each with a label, each revocable.
    """

    def __init__(self, path, max_keys=MAX_SHARE_KEYS):
        self.path = Path(path)
        self.max_keys = max_keys
        self.lock = threading.Lock()
        self.keys = self._load()

    def _load(self):
        try:
            data = json.loads(self.path.read_text('utf-8'))
        except (OSError, ValueError):
            return []
        out = []
        for k in data.get('keys', []) if isinstance(data, dict) else []:
            if not isinstance(k, dict):
                continue
            kid, digest = k.get('id'), k.get('sha256')
            if not (isinstance(kid, str) and _KEY_ID.match(kid) and isinstance(digest, str)
                    and re.fullmatch(r'[0-9a-f]{64}', digest)):
                continue
            out.append({'id': kid, 'label': clean_label(k.get('label')) or 'device',
                        'sha256': digest,
                        'created': k.get('created') if isinstance(k.get('created'), (int, float)) else 0,
                        'last_used': k.get('last_used') if isinstance(k.get('last_used'), (int, float)) else None,
                        'uses': k.get('uses') if isinstance(k.get('uses'), int) else 0})
        return out[:self.max_keys]

    def _save(self):
        atomic_write_bytes(self.path, json.dumps({'keys': self.keys}).encode('utf-8'), mode=0o600)

    @staticmethod
    def _public(k):
        return {'id': k['id'], 'label': k['label'], 'created': k['created'],
                'last_used': k['last_used'], 'uses': k['uses']}

    def listing(self):
        with self.lock:
            return [self._public(k) for k in self.keys]

    def create(self, label):
        """(public entry + 'key', None), or (None, reason) when full."""
        key = SHARE_KEY_PREFIX + secrets.token_urlsafe(32)
        entry = {'id': secrets.token_urlsafe(9), 'label': clean_label(label) or 'iPhone',
                 'sha256': _hash_key(key), 'created': round(time.time(), 3),
                 'last_used': None, 'uses': 0}
        with self.lock:
            if len(self.keys) >= self.max_keys:
                return None, f'at most {self.max_keys} device keys; revoke one first'
            self.keys.append(entry)
            self._save()
            return dict(self._public(entry), key=key), None

    def rotate(self, kid):
        """A new secret for an existing key (the old one stops at once)."""
        key = SHARE_KEY_PREFIX + secrets.token_urlsafe(32)
        with self.lock:
            for k in self.keys:
                if k['id'] == kid:
                    k['sha256'] = _hash_key(key)
                    k['created'] = round(time.time(), 3)
                    k['last_used'], k['uses'] = None, 0
                    self._save()
                    return dict(self._public(k), key=key)
        return None

    def revoke(self, kid):
        with self.lock:
            kept = [k for k in self.keys if k['id'] != kid]
            if len(kept) == len(self.keys):
                return False
            self.keys = kept
            self._save()
            return True

    def match(self, key):
        """The entry a presented key belongs to, or None. Compares digests
        in constant time against every entry."""
        if not isinstance(key, str) or not _SHARE_KEY.match(key):
            return None
        digest = _hash_key(key).encode()
        found = None
        with self.lock:
            for k in self.keys:
                if hmac.compare_digest(digest, k['sha256'].encode()):
                    found = k
            return dict(found) if found else None

    def used(self, kid):
        with self.lock:
            for k in self.keys:
                if k['id'] == kid:
                    k['last_used'] = round(time.time(), 3)
                    k['uses'] += 1
                    try:
                        self._save()
                    except OSError:
                        pass
                    return


class RateLimit:
    """At most `limit` hits per `window` seconds per key (sliding window).
    Bounded: at most `max_keys` keys are tracked; the stalest go first."""

    def __init__(self, limit, window, max_keys=4096):
        self.limit, self.window, self.max_keys = limit, window, max_keys
        self.lock = threading.Lock()
        self.hits = {}

    def _prune(self, key, now):
        q = [t for t in self.hits.get(key, ()) if now - t < self.window]
        if q:
            self.hits[key] = q
        else:
            self.hits.pop(key, None)
        return q

    def blocked(self, key, now=None):
        now = time.monotonic() if now is None else now
        with self.lock:
            return len(self._prune(key, now)) >= self.limit

    def hit(self, key, now=None):
        """Count one hit. False (and not counted) when already at the limit."""
        now = time.monotonic() if now is None else now
        with self.lock:
            q = self._prune(key, now)
            if len(q) >= self.limit:
                return False
            if key not in self.hits and len(self.hits) >= self.max_keys:
                oldest = min(self.hits, key=lambda k: self.hits[k][-1])
                self.hits.pop(oldest, None)
            self.hits.setdefault(key, []).append(now)
            return True


# ---- change hub (SSE) --------------------------------------------------------

class Hub:
    """Version counters (clip, inbox, links, doors, people, stepup), plus
    the SSE connection caps."""

    KINDS = ('clip', 'inbox', 'links', 'doors', 'people', 'stepup')

    def __init__(self, max_total=SSE_MAX_TOTAL, per_client=SSE_MAX_PER_CLIENT):
        self.cond = threading.Condition()
        self.versions = {k: 0 for k in self.KINDS}
        self.max_total = max_total
        self.per_client = per_client
        self.clients = 0
        self.by_ip = {}

    def bump(self, kind):
        with self.cond:
            self.versions[kind] = self.versions.get(kind, 0) + 1
            self.cond.notify_all()

    def wait(self, seen, timeout):
        with self.cond:
            self.cond.wait_for(lambda: self.versions != seen, timeout)
            return dict(self.versions)

    def acquire(self, ip):
        with self.cond:
            if self.clients >= self.max_total or self.by_ip.get(ip, 0) >= self.per_client:
                return False
            self.clients += 1
            self.by_ip[ip] = self.by_ip.get(ip, 0) + 1
            return True

    def release(self, ip):
        with self.cond:
            self.clients = max(0, self.clients - 1)
            left = self.by_ip.get(ip, 0) - 1
            if left > 0:
                self.by_ip[ip] = left
            else:
                self.by_ip.pop(ip, None)


# ---- multipart with field names ----------------------------------------------

_FILENAME = re.compile(r'filename\*?=("([^"]*)"|([^;\r\n]*))', re.I)
_FIELDNAME = re.compile(r'(?:^|[;\s])name="([^"]*)"', re.I)


class FieldStreamer(MultipartStreamer):
    """MultipartStreamer.parts() plus each part's form-field name, which the
    share target needs (title/text/url/files)."""

    def fields(self):
        """Yield (field_name, filename_or_None, chunk_iterator) per part."""
        if not self._skip_to_first_delim():
            return
        while True:
            if self._peek(2) == b'--':
                return
            line = self._read_until(b'\r\n', 1024)
            if line.startswith(b'--'):
                return
            raw = self._read_until(b'\r\n\r\n', self.max_part_headers).decode('utf-8', 'replace')
            m = _FILENAME.search(raw)
            filename = None
            if m:
                filename = (m.group(2) if m.group(2) is not None else m.group(3) or '').strip()
            n = _FIELDNAME.search(raw)
            yield (n.group(1) if n else ''), filename, self._iter_part_body()


# ---- inbox and sealed uploads ------------------------------------------------

_SEALED_NAME = re.compile(r'^[A-Za-z0-9_-]{22}\.pseal$')
SEAL_MAGIC = b'PSEAL1\n\x00\x01'       # porch-seal v1 magic + version byte (lib/porch_seal.py)
SEAL_DATA_START = 48 + 4112            # header + the metadata record
SEAL_RECORD = 65536 + 16               # one sealed content record
SEALED_ORPHAN_AGE = 3600               # s before an unlinked sealed upload is swept


def _dir_sig(directory):
    try:
        st = os.stat(directory)
        return (st.st_mtime_ns, st.st_nlink)
    except OSError:
        return None


def list_inbox(directory):
    files = []
    try:
        entries = list(Path(directory).iterdir())
    except OSError:
        entries = []
    for entry in entries:
        if entry.is_symlink() or not entry.is_file():
            continue
        if entry.name.startswith('.') or entry.name.endswith('.part'):
            continue
        try:
            st = entry.stat()
        except OSError:
            continue
        files.append({'name': entry.name, 'size': st.st_size, 'modified': st.st_mtime})
    return files


def inbox_usage(directory):
    files = list_inbox(directory)
    return sum(f['size'] for f in files), len(files)


def sealed_files(directory):
    """[(name, size, mtime)] of the finished sealed uploads in <dir>/sealed/."""
    out = []
    try:
        entries = list(Path(directory).iterdir())
    except OSError:
        return out
    for entry in entries:
        if not _SEALED_NAME.match(entry.name) or entry.is_symlink():
            continue
        try:
            st = entry.stat()
        except OSError:
            continue
        if os.path.isfile(entry):
            out.append((entry.name, st.st_size, st.st_mtime))
    return out


def sealed_usage(directory):
    files = sealed_files(directory)
    return sum(f[1] for f in files), len(files)


def sealed_create(meta, length, handler):
    """tus on_create for /tus-sealed/: the page marks a sealed upload, and
    it is at least one header plus one sealed chunk long."""
    if meta.get('sealed') != '1':
        return 'not a sealed upload (Upload-Metadata needs sealed=1)'
    if not sealed_length_ok(length):
        return 'that length is not a porch-seal v1 file'
    return None


def sealed_length_ok(n):
    """48 + 4112 + records of 65552 bytes, the last 17..65552."""
    if n < SEAL_DATA_START:
        return False
    rest = (n - SEAL_DATA_START) % SEAL_RECORD
    return rest == 0 or rest > 16


def sealed_head(head):
    """tus on_head: the porch-seal magic, nothing more (it is ciphertext)."""
    if not head.startswith(SEAL_MAGIC):
        return 'not a porch-seal file'
    return None


def cli_token_path(name):
    """Where pocket <name> publishes its CLI token (and `porch clip` reads it)."""
    return os.path.join(rundir.tool_dir('pocket'), f'{name}.token')

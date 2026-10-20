"""porch_tus: a resumable-upload (tus 1.0.0) server core for the Porch apps.

A phone that locks its screen halfway through a 400MB clip kills a multipart
POST and the whole thing starts over. tus splits an upload into a creation
request and any number of PATCHes that each append at a known offset, so a
dropped connection costs one chunk, not the file. Media and drop mount this at
/tus/; a later app can mount it the same way with its own hooks.

Protocol: core + creation (+ creation-with-upload) + termination +
expiration, OPTIONS discovery. Not supported: deferred length, checksum,
concatenation, X-HTTP-Method-Override (refused, not honoured).

Mounting (see TusServer for the hook signatures):

    tus = TusServer(directory, quota=cls.quota, max_size=cls.max_file,
                    finalize=fn, on_head=fn, on_create=fn, tag='mediaserver')
    # in the handler, AFTER the app's own gates (same-origin, guest lock,
    # upload slots) and only for paths where tus.owns(path) is true:
    tus.handle(handler)

The app keeps its gates: tus itself has no auth. Upload ids are 128 random
bits, so knowing one is the capability; same-origin (checked by the app on
POST/PATCH/DELETE) pins the writes to the app's own page as for /upload.

Storage: <directory>/.tus/<id>.part (the bytes so far; its size IS the
offset, so a crash can never leave the offset claiming bytes that are not on
disk) and <id>.json (length, metadata, creator address, timestamps; written
atomically). Both 0600 in a 0700 directory. The leading dot keeps partials out
of every app listing.

Quota: the full Upload-Length is reserved against the app's Quota at
creation (begin/add/end(kept=True)), so it counts as if the file had landed;
the app's Quota scan must add pending_usage() so a resync keeps counting it.
Termination, rejection and expiry hand it back with Quota.removed(); a
finished upload becomes a real file and the scan sees it as one. A restart
needs nothing: the scan reads pending uploads back from .tus/.
"""

import base64
import binascii
import json
import os
import re
import secrets
import stat
import sys
import threading
import time
from email.utils import formatdate
from pathlib import Path

from porch_http import client_ip, content_length, security_headers

TUS_VERSION = '1.0.0'
TUS_EXTENSIONS = 'creation,creation-with-upload,termination,expiration'
OCTET = 'application/offset+octet-stream'

TUS_DIR = '.tus'
EXPIRE_IDLE = 24 * 3600        # an upload idle this long is swept
EXPIRE_EMPTY = 3600            # ...or this long if it never received a byte
SWEEP_EVERY = 15 * 60
DEFAULT_CHUNK_MAX = 64 * 1024 * 1024   # bytes one PATCH may carry
DEFAULT_MAX_PER_IP = 6         # unfinished uploads per client address
DEFAULT_MAX_TOTAL = 32         # unfinished uploads overall
SNIFF_BYTES = 64

MAX_METADATA_HEADER = 4096
MAX_METADATA_PAIRS = 16
MAX_METADATA_VALUE = 1024      # decoded bytes
_META_KEY = re.compile(r'[A-Za-z0-9._-]{1,64}')
_B64 = re.compile(r'[A-Za-z0-9+/]*={0,2}')
_ID = re.compile(r'[A-Za-z0-9_-]{22}')
_OFFSET = re.compile(r'[0-9]{1,15}')
READ_CHUNK = 65536


class TusRejected(Exception):
    """Raised by a finalize hook to refuse a completed upload."""

    def __init__(self, reason, status=422):
        super().__init__(reason)
        self.reason = reason
        self.status = status


class MetadataError(ValueError):
    pass


def parse_metadata(raw):
    """Upload-Metadata -> {key: str}. Raises MetadataError when it is bad.

    'key b64value,key2 b64value2,flagkey'. Bounded: header length, pair
    count, key charset, decoded value size; duplicate keys are refused.
    Values are decoded as UTF-8 with replacement (they are only hints).
    """
    if raw is None or raw.strip() == '':
        return {}
    if len(raw) > MAX_METADATA_HEADER:
        raise MetadataError('Upload-Metadata is too long')
    pairs = raw.split(',')
    if len(pairs) > MAX_METADATA_PAIRS:
        raise MetadataError('too many Upload-Metadata pairs')
    out = {}
    for pair in pairs:
        parts = pair.strip().split(' ')
        if len(parts) > 2 or not _META_KEY.fullmatch(parts[0]):
            raise MetadataError('malformed Upload-Metadata')
        key = parts[0]
        if key in out:
            raise MetadataError('duplicate Upload-Metadata key')
        value = ''
        if len(parts) == 2:
            enc = parts[1]
            if not _B64.fullmatch(enc) or len(enc) % 4:
                raise MetadataError('Upload-Metadata values must be base64')
            if len(enc) > (MAX_METADATA_VALUE * 4) // 3 + 4:
                raise MetadataError('Upload-Metadata value is too long')
            try:
                dec = base64.b64decode(enc, validate=True)
            except (binascii.Error, ValueError):
                raise MetadataError('Upload-Metadata values must be base64')
            if len(dec) > MAX_METADATA_VALUE:
                raise MetadataError('Upload-Metadata value is too long')
            value = dec.decode('utf-8', 'replace')
        out[key] = value
    return out


class TusUpload:
    """One unfinished upload. `offset` is read from the .part file's size."""

    __slots__ = ('id', 'length', 'metadata', 'ip', 'created', 'updated', 'lock')

    def __init__(self, uid, length, metadata, ip, created=None, updated=None):
        now = time.time()
        self.id = uid
        self.length = length
        self.metadata = metadata
        self.ip = ip
        self.created = created or now
        self.updated = updated or self.created
        self.lock = threading.Lock()      # one PATCH/DELETE/finalize at a time

    def as_json(self):
        return {'length': self.length, 'metadata': self.metadata, 'ip': self.ip,
                'created': self.created, 'updated': self.updated}


class TusServer:
    """The tus endpoint for one app directory.

    directory   the app's storage dir; partials live in <directory>/.tus/
    quota       () -> porch_http.Quota (called lazily, never under our lock)
    max_size    largest Upload-Length accepted (the app's per-file cap)
    finalize    (part_path: Path, upload: TusUpload, handler) -> str name.
                Called once offset == length, under the upload's lock. It
                must move part_path away (place_unique does) and return the
                stored name; raise TusRejected(reason) to refuse. The bytes
                were reserved at creation, so it must NOT touch the quota.
    on_head     (first_bytes) -> None | reason. Called as soon as SNIFF_BYTES
                (or the whole upload, if shorter) have arrived; a reason
                deletes the upload at once (415).
    on_create   (metadata: dict, length: int, handler) -> None | reason,
                checked before anything is reserved (400).
    prefix      URL prefix ('/tus/'); the endpoint is prefix and prefix<id>.
    chunk_max   bytes one PATCH (or creation-with-upload) may carry.
    max_per_ip / max_total   caps on unfinished uploads (429 / 503).

    handle(handler) answers OPTIONS/POST/HEAD/PATCH/DELETE; the app routes
    to it after its own gates. Finished uploads answer 204 with an extra
    `Porch-Upload-Name` header carrying the stored name.
    """

    def __init__(self, directory, quota, max_size, finalize, on_head=None,
                 on_create=None, prefix='/tus/', chunk_max=DEFAULT_CHUNK_MAX,
                 max_per_ip=DEFAULT_MAX_PER_IP, max_total=DEFAULT_MAX_TOTAL,
                 expire_idle=EXPIRE_IDLE, expire_empty=EXPIRE_EMPTY, tag='porch-tus'):
        self.directory = Path(directory)
        self.dir = self.directory / TUS_DIR
        self._quota = quota
        self.max_size = max_size
        self.finalize = finalize
        self.on_head = on_head
        self.on_create = on_create
        self.prefix = prefix if prefix.endswith('/') else prefix + '/'
        self.chunk_max = chunk_max
        self.max_per_ip = max_per_ip
        self.max_total = max_total
        self.expire_idle = expire_idle
        self.expire_empty = expire_empty
        self.tag = tag
        self._lock = threading.Lock()
        self._uploads = {}
        self._sweeper = None
        self._load()

    # ---- storage -------------------------------------------------------------

    def _ensure_dir(self):
        try:
            os.mkdir(self.dir, 0o700)
        except FileExistsError:
            pass
        st = os.lstat(self.dir)
        if not stat.S_ISDIR(st.st_mode):
            raise OSError(f'{self.dir} is not a directory')

    def part_path(self, uid):
        return self.dir / (uid + '.part')

    def _meta_path(self, uid):
        return self.dir / (uid + '.json')

    def _write_meta(self, up):
        path = self._meta_path(up.id)
        tmp = self.dir / f'.{up.id}.{secrets.token_hex(4)}.tmp'
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(up.as_json(), f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _remove_files(self, uid):
        for p in (self.part_path(uid), self._meta_path(uid)):
            try:
                os.unlink(p)
            except OSError:
                pass

    def offset_of(self, up):
        try:
            return os.lstat(self.part_path(up.id)).st_size
        except OSError:
            return -1

    def _load(self):
        """Read unfinished uploads back after a restart; drop broken ones."""
        try:
            entries = list(self.dir.iterdir())
        except OSError:
            return
        for e in entries:
            if not e.name.endswith('.json') or not _ID.fullmatch(e.name[:-5]):
                continue
            uid = e.name[:-5]
            try:
                with open(e) as f:
                    d = json.load(f)
                length = int(d['length'])
                meta = d.get('metadata') or {}
                if not isinstance(meta, dict) or length <= 0:
                    raise ValueError
                up = TusUpload(uid, length, {str(k): str(v) for k, v in meta.items()},
                               str(d.get('ip', '')), float(d.get('created', 0)) or None,
                               float(d.get('updated', 0)) or None)
                if not os.path.isfile(self.part_path(uid)):
                    raise ValueError
            except (OSError, ValueError, KeyError, TypeError):
                self._remove_files(uid)
                continue
            self._uploads[uid] = up
        # Nothing is reserved yet at load time (the Quota's first scan counts
        # these through pending_usage()), so expired ones just go.
        self.sweep(release=False)

    # ---- accounting ----------------------------------------------------------

    def pending_usage(self):
        """(bytes, items) reserved by unfinished uploads, for the Quota scan."""
        with self._lock:
            return (sum(u.length for u in self._uploads.values()), len(self._uploads))

    def pending_count(self):
        with self._lock:
            return len(self._uploads)

    def _drop(self, up, release=True):
        """Forget an upload, delete its files, hand its reservation back."""
        with self._lock:
            known = self._uploads.pop(up.id, None) is not None
        self._remove_files(up.id)
        if known and release:
            try:
                self._quota().removed(up.length)
            except Exception:
                pass

    def sweep(self, now=None, release=True):
        """Remove expired uploads (and orphan files). Returns how many went."""
        now = time.time() if now is None else now
        with self._lock:
            ups = list(self._uploads.values())
        gone = 0
        for up in ups:
            idle = now - up.updated
            empty = self.offset_of(up) <= 0
            if idle > self.expire_idle or (empty and idle > self.expire_empty):
                if not up.lock.acquire(blocking=False):
                    continue                      # a PATCH is running right now
                try:
                    self._drop(up, release=release)
                finally:
                    up.lock.release()
                gone += 1
        # Files no upload owns: leftovers of a crash between writes.
        try:
            entries = list(self.dir.iterdir())
        except OSError:
            entries = []
        with self._lock:
            known = set(self._uploads)
        for e in entries:
            stem = e.name.split('.', 1)[0] if not e.name.startswith('.') else \
                e.name[1:].split('.', 1)[0]
            if stem in known:
                continue
            try:
                st = e.lstat()
                if stat.S_ISREG(st.st_mode) and now - st.st_mtime > 300:
                    e.unlink()
            except OSError:
                pass
        if gone:
            sys.stderr.write(f"[{self.tag}] swept {gone} expired resumable upload(s)\n")
        return gone

    def _start_sweeper(self):
        with self._lock:
            if self._sweeper is not None:
                return
            self._sweeper = threading.Thread(target=self._sweep_loop,
                                             name='tus-sweeper', daemon=True)
            self._sweeper.start()

    def _sweep_loop(self):
        while True:
            time.sleep(SWEEP_EVERY)
            try:
                self.sweep()
            except Exception as e:  # never let the sweeper die
                sys.stderr.write(f"[{self.tag}] sweep failed: {e}\n")

    # ---- routing -------------------------------------------------------------

    def owns(self, path):
        """True iff `path` (no query) is this endpoint: prefix or prefix<id>."""
        return path == self.prefix.rstrip('/') or path.startswith(self.prefix)

    def handle(self, handler):
        """Answer a request on this endpoint. The app's gates come first."""
        self._start_sweeper()
        path = handler.path.split('?', 1)[0]
        method = handler.command
        if handler.headers.get('X-HTTP-Method-Override'):
            self._refuse(handler, 400, 'X-HTTP-Method-Override is not supported')
            return
        rest = path[len(self.prefix):] if path.startswith(self.prefix) else ''
        rest = rest.rstrip('/')
        if method == 'OPTIONS':
            self._send(handler, 204, {
                'Tus-Version': TUS_VERSION, 'Tus-Extension': TUS_EXTENSIONS,
                'Tus-Max-Size': str(self.max_size)})
            return
        if handler.headers.get('Tus-Resumable') != TUS_VERSION:
            self._refuse(handler, 412, 'Tus-Resumable: 1.0.0 required',
                         {'Tus-Version': TUS_VERSION})
            return
        if not rest:
            if method == 'POST':
                self._create(handler)
            else:
                self._refuse(handler, 405, 'Method not allowed', {'Allow': 'OPTIONS, POST'})
            return
        if not _ID.fullmatch(rest):
            self._refuse(handler, 404, 'Not found')
            return
        with self._lock:
            up = self._uploads.get(rest)
        if up is None:
            self._refuse(handler, 404, 'Upload not found (it may have expired)')
            return
        if method == 'HEAD':
            # Give a PATCH that is still winding down (its client just went
            # away) a moment to finish, so the offset reported is settled and
            # the PATCH that follows does not find the upload busy.
            if up.lock.acquire(timeout=5):
                up.lock.release()
            offset = self.offset_of(up)
            if offset < 0:
                self._drop(up)
                self._send(handler, 404)
                return
            self._send(handler, 200, {'Upload-Offset': str(offset),
                                      'Upload-Length': str(up.length),
                                      'Upload-Expires': self._expires(up)})
        elif method == 'PATCH':
            self._patch(handler, up)
        elif method == 'DELETE':
            if not up.lock.acquire(blocking=False):
                self._refuse(handler, 423, 'Upload is busy')
                return
            try:
                self._drop(up)
            finally:
                up.lock.release()
            sys.stderr.write(f"[{self.tag}] terminated upload {up.id} from {client_ip(handler)}\n")
            self._send(handler, 204)
        else:
            self._refuse(handler, 405, 'Method not allowed',
                         {'Allow': 'HEAD, PATCH, DELETE, OPTIONS'})

    # ---- responses -----------------------------------------------------------

    def _expires(self, up):
        return formatdate(up.updated + self.expire_idle, usegmt=True)

    def _send(self, handler, status, headers=None, body=None):
        data = json.dumps(body).encode() if body is not None else b''
        handler.send_response(status)
        handler.send_header('Tus-Resumable', TUS_VERSION)
        for k, v in (headers or {}).items():
            handler.send_header(k, v)
        if body is not None:
            handler.send_header('Content-Type', 'application/json')
        handler.send_header('Content-Length', str(len(data)))
        handler.send_header('Cache-Control', 'no-store')
        if handler.close_connection:
            handler.send_header('Connection', 'close')
        security_headers(handler)
        handler.end_headers()
        if data and handler.command != 'HEAD':
            handler.wfile.write(data)

    def _refuse(self, handler, status, message, headers=None):
        """An error answer. A request whose body we did not read can't share
        its connection with the next one."""
        if handler.command in ('POST', 'PATCH') and content_length(handler) != 0:
            handler.close_connection = True
        self._send(handler, status, headers, {'status': 'error', 'message': message})

    # ---- creation ------------------------------------------------------------

    def _create(self, handler):
        if handler.headers.get('Upload-Defer-Length'):
            self._refuse(handler, 400, 'Upload-Defer-Length is not supported')
            return
        raw_len = (handler.headers.get('Upload-Length') or '').strip()
        if not _OFFSET.fullmatch(raw_len):
            self._refuse(handler, 400, 'Upload-Length required')
            return
        length = int(raw_len)
        if length <= 0:
            self._refuse(handler, 400, 'empty file')
            return
        if length > self.max_size:
            self._refuse(handler, 413, f'over the {_human(self.max_size)} per-file limit')
            return
        try:
            meta = parse_metadata(handler.headers.get('Upload-Metadata'))
        except MetadataError as e:
            self._refuse(handler, 400, str(e))
            return
        if self.on_create:
            reason = self.on_create(meta, length, handler)
            if reason:
                self._refuse(handler, 400, reason)
                return
        ip = client_ip(handler)
        with self._lock:
            mine = sum(1 for u in self._uploads.values() if u.ip == ip)
            total = len(self._uploads)
        if mine >= self.max_per_ip:
            self._refuse(handler, 429, 'Too many unfinished uploads from you; '
                         'finish or cancel one first', {'Retry-After': '60'})
            return
        if total >= self.max_total:
            self._refuse(handler, 503, 'Too many unfinished uploads, try again later',
                         {'Retry-After': '60'})
            return

        quota = self._quota()
        refusal = quota.begin()
        if refusal:
            self._refuse(handler, 413, refusal)
            return
        refusal = quota.add(length)
        if refusal:
            quota.end(0, kept=False)
            self._refuse(handler, 413, refusal)
            return
        # Registered before quota.end(): from end() on, a Quota resync may run
        # and must already see this reservation through pending_usage().
        uid = secrets.token_urlsafe(16)
        up = TusUpload(uid, length, meta, ip)
        kept = False
        try:
            self._ensure_dir()
            fd = os.open(self.part_path(uid),
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0),
                         0o600)
            os.close(fd)
            self._write_meta(up)
            with self._lock:
                self._uploads[uid] = up
            kept = True
        finally:
            quota.end(length, kept=kept)
            if not kept:
                self._remove_files(uid)
        location = self.prefix + uid
        sys.stderr.write(f"[{self.tag}] tus upload {uid} created ({_human(length)}) by {ip}\n")

        # creation-with-upload: a body on the POST is the first chunk.
        if (handler.headers.get('Content-Type') or '').split(';')[0].strip().lower() == OCTET \
                and content_length(handler) > 0:
            self._patch(handler, up, status=201, extra={'Location': location}, offset_hdr='0')
            return
        if content_length(handler) != 0:
            handler.close_connection = True
        self._send(handler, 201, {'Location': location, 'Upload-Offset': '0',
                                  'Upload-Expires': self._expires(up)})

    # ---- PATCH ---------------------------------------------------------------

    def _patch(self, handler, up, status=204, extra=None, offset_hdr=None):
        extra = dict(extra or {})
        ctype = (handler.headers.get('Content-Type') or '').split(';')[0].strip().lower()
        if ctype != OCTET:
            self._refuse(handler, 415, f'Content-Type must be {OCTET}', extra)
            return
        raw_off = offset_hdr if offset_hdr is not None else \
            (handler.headers.get('Upload-Offset') or '').strip()
        if not _OFFSET.fullmatch(raw_off):
            self._refuse(handler, 400, 'Upload-Offset required', extra)
            return
        n = content_length(handler)
        if n < 0:
            self._refuse(handler, 400, 'bad Content-Length', extra)
            return
        if n == 0 and handler.headers.get('Transfer-Encoding'):
            self._refuse(handler, 411, 'Content-Length required', extra)
            return
        if n > self.chunk_max:
            self._refuse(handler, 413, f'one request may carry at most {_human(self.chunk_max)}',
                         extra)
            return
        if not up.lock.acquire(blocking=False):
            self._refuse(handler, 423, 'Upload is busy (another request is writing it)', extra)
            return
        # The answer goes out only after the lock is released: a client
        # sends its next PATCH the moment it has this one's reply.
        replies = []
        try:
            self._patch_locked(handler, up, int(raw_off), n, status, extra,
                               lambda fn, *args: replies.append((fn, args)))
        finally:
            up.lock.release()
        for fn, args in replies:
            fn(*args)

    def _patch_locked(self, handler, up, client_off, n, status, extra, reply):
        with self._lock:
            live = self._uploads.get(up.id) is up
        offset = self.offset_of(up) if live else -1
        if offset < 0:
            reply(self._refuse, handler, 404, 'Upload not found (it may have expired)', extra)
            return
        if client_off != offset:
            reply(self._refuse, handler, 409, 'Upload-Offset does not match',
                         dict(extra, **{'Upload-Offset': str(offset)}))
            return
        if offset + n > up.length:
            reply(self._refuse, handler, 413, 'more bytes than Upload-Length', extra)
            return

        head = b''
        if self.on_head and offset < SNIFF_BYTES:
            try:
                with open(self.part_path(up.id), 'rb') as f:
                    head = f.read(SNIFF_BYTES)
            except OSError:
                head = b''
        sniffed = not self.on_head or offset >= SNIFF_BYTES
        need = min(SNIFF_BYTES, up.length)

        written = 0
        reason = None
        broken = False
        if not sniffed and len(head) >= need:
            # Everything the sniff needs is already on disk but was never
            # judged: a short upload whose last byte landed just before a
            # crash, finished now by an empty PATCH. Judge it before finalize.
            sniffed = True
            reason = self.on_head(head)
        credit = getattr(handler, 'transferred', None)   # the transfer deadline
        fd = os.open(self.part_path(up.id), os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            os.lseek(fd, offset, os.SEEK_SET)
            remaining = 0 if reason else n
            while remaining > 0:
                try:
                    chunk = handler.rfile.read(min(READ_CHUNK, remaining))
                except (OSError, ValueError):
                    chunk = b''
                if not chunk:
                    broken = True                 # client went away mid-chunk
                    break
                remaining -= len(chunk)
                if credit:
                    credit(len(chunk))
                if not sniffed:
                    head += chunk[:SNIFF_BYTES - len(head)]
                    if len(head) >= need:
                        sniffed = True
                        reason = self.on_head(head)
                        if reason:
                            break
                view = memoryview(chunk)
                while view:
                    k = os.write(fd, view)
                    view = view[k:]
                written += len(chunk)
            os.fsync(fd)
        finally:
            os.close(fd)

        if reason:
            handler.close_connection = True
            self._drop(up)
            sys.stderr.write(f"[{self.tag}] tus upload {up.id} rejected: {reason}\n")
            reply(self._send, handler, 415, extra, {'status': 'error', 'message': reason})
            return

        up.updated = time.time()
        try:
            self._write_meta(up)
        except OSError:
            pass
        offset += written
        if broken:
            # Nothing to answer on a dead connection; the bytes that did
            # arrive are kept and HEAD reports them.
            handler.close_connection = True
            return

        headers = dict(extra)
        headers['Upload-Offset'] = str(offset)
        if offset < up.length:
            headers['Upload-Expires'] = self._expires(up)
            reply(self._send, handler, status, headers)
            return

        # Complete: the app validates and places it.
        try:
            name = self.finalize(self.part_path(up.id), up, handler)
        except TusRejected as e:
            self._drop(up)
            sys.stderr.write(f"[{self.tag}] tus upload {up.id} refused: {e.reason}\n")
            reply(self._send, handler, e.status, headers, {'status': 'error', 'message': e.reason})
            return
        except Exception as e:
            self._drop(up)
            sys.stderr.write(f"[{self.tag}] tus finalize failed for {up.id}: {e}\n")
            reply(self._send, handler, 500, headers, {'status': 'error', 'message': 'Server error'})
            return
        # The bytes now live in a real file the Quota scan counts, so the
        # reservation is not handed back, only forgotten.
        self._drop(up, release=False)
        sys.stderr.write(f"[{self.tag}] Saved: {name} ({_human(up.length)}) via tus "
                         f"from {client_ip(handler)}\n")
        headers['Porch-Upload-Name'] = name
        reply(self._send, handler, status, headers)


def _human(n):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024 or unit == 'GB':
            return f'{n:.0f} {unit}' if unit == 'B' else f'{n:.1f} {unit}'
        n /= 1024
    return f'{n} B'


# ---- browser client -----------------------------------------------------------
#
# Spliced into each app page's (nonced) inline script. Exposes PorchTus with
#   PorchTus.upload(file, {endpoint, onProgress(sent, total)})
#     -> Promise<{ok:true, name, size} | {ok:false, error, retry} | {fallback:true}>
# fallback means "this server has no tus endpoint": use the multipart path.
# Chunks start at 8MB (2MB on a slow or data-saver link), halve when a chunk
# is slow and grow back when fast. After any failure it waits (backoff, or
# until the tab is visible / online again: a phone whose screen locked) and
# asks the server for the real offset with HEAD before sending more. The
# upload URL is remembered in localStorage per file (name+size+mtime), so
# picking the same file after a reload resumes it.
TUS_CLIENT_JS = r"""
const PorchTus = (function(){
  const V = '1.0.0', MAXC = 8*1024*1024, MINC = 256*1024, KEEP_MS = 23*3600*1000;
  let probe = null;
  function available(ep){
    // A network error is not an answer: don't cache it, and try tus anyway
    // (the creation POST retries until the link is back, and a server with
    // no /tus/ answers it 404, which still falls back to multipart).
    if(!probe) probe = fetch(ep, {method:'OPTIONS', credentials:'same-origin'})
      .then(r => r.ok && (r.headers.get('Tus-Version')||'').split(',').map(s=>s.trim()).includes(V))
      .catch(() => { probe = null; return true; });
    return probe;
  }
  function key(f){ return 'porch-tus:' + f.name + ':' + f.size + ':' + f.lastModified; }
  function remember(f, url){ try{ localStorage.setItem(key(f), JSON.stringify({url, t:Date.now()})); }catch(e){} }
  function forget(f){ try{ localStorage.removeItem(key(f)); }catch(e){} }
  function recall(f){
    try{
      const v = JSON.parse(localStorage.getItem(key(f)) || 'null');
      if(v && typeof v.url === 'string' && Date.now() - v.t < KEEP_MS) return v.url;
    }catch(e){}
    return null;
  }
  function b64(s){
    const b = new TextEncoder().encode(s); let bin = '';
    for(let i=0;i<b.length;i++) bin += String.fromCharCode(b[i]);
    return btoa(bin);
  }
  function slowLink(){
    const c = navigator.connection;
    return !!(c && (c.saveData || /2g|3g/.test(c.effectiveType||'') || (c.downlink && c.downlink < 2)));
  }
  // Resolves after ms, or sooner when the tab comes back / the network returns.
  function pause(ms){
    return new Promise((res)=>{
      let done = false;
      const fin = ()=>{ if(done) return; done = true; clearTimeout(t);
        document.removeEventListener('visibilitychange', vis); window.removeEventListener('online', fin); res(); };
      const vis = ()=>{ if(!document.hidden) fin(); };
      const t = setTimeout(fin, ms);
      document.addEventListener('visibilitychange', vis);
      window.addEventListener('online', fin);
    });
  }
  function req(method, url, headers, body, onprog){
    return new Promise((res)=>{
      const x = new XMLHttpRequest();
      let stall = null;
      const kick = ()=>{ clearTimeout(stall); stall = setTimeout(()=>x.abort(), 30000); };
      x.open(method, url);
      x.setRequestHeader('Tus-Resumable', V);
      for(const k in headers) x.setRequestHeader(k, headers[k]);
      if(x.upload && onprog) x.upload.onprogress = (e)=>{ kick(); onprog(e.loaded); };
      x.onload = ()=>{ clearTimeout(stall); res(x); };
      x.onerror = x.onabort = ()=>{ clearTimeout(stall); res(null); };
      kick();
      x.send(body === undefined ? null : body);
    });
  }
  function msg(x){
    try{ const j = JSON.parse(x.responseText); if(j && j.message) return j.message; }catch(e){}
    return 'HTTP ' + x.status;
  }
  async function upload(file, opts){
    const ep = opts.endpoint || '/tus/', prog = opts.onProgress || function(){};
    if(!(await available(ep))) return {fallback:true};
    let url = recall(file), offset = -1, chunk = slowLink() ? 2*1024*1024 : MAXC;
    let fails = 0;
    while(true){
      if(fails){
        if(fails > 12) return {ok:false, error:'connection lost, try again', retry:true};
        // A hidden tab or offline phone isn't failing, it's waiting: don't
        // burn retries until it is back.
        while(document.hidden || navigator.onLine === false) await pause(30000);
        await pause(Math.min(30000, 1000 * Math.pow(2, Math.min(fails-1, 5))));
      }
      if(url && offset < 0){
        const h = await req('HEAD', url, {});
        if(!h){ fails++; continue; }
        if(h.status === 200 && +h.getResponseHeader('Upload-Length') === file.size){
          offset = +h.getResponseHeader('Upload-Offset');
        }else if(h.status >= 500 || h.status === 423 || h.status === 429){ fails++; continue; }
        else { forget(file); url = null; }
      }
      if(!url){
        const meta = 'filename ' + b64(file.name) + ',filetype ' + b64(file.type || 'application/octet-stream');
        const c = await req('POST', ep, {'Upload-Length': String(file.size), 'Upload-Metadata': meta});
        if(!c){ fails++; continue; }
        if(c.status === 404 || c.status === 405) return {fallback:true};
        if(c.status !== 201){
          return {ok:false, error:msg(c), retry: c.status >= 500 || c.status === 429};
        }
        url = new URL(c.getResponseHeader('Location'), location.href).pathname;
        remember(file, url); offset = 0;
      }
      prog(offset, file.size);
      const end = Math.min(file.size, offset + chunk), t0 = Date.now();
      const p = await req('PATCH', url,
        {'Content-Type':'application/offset+octet-stream', 'Upload-Offset': String(offset)},
        file.slice(offset, end), (n)=>prog(offset + n, file.size));
      if(!p){ fails++; offset = -1; continue; }
      if(p.status === 204){
        const next = +p.getResponseHeader('Upload-Offset');
        if(next > offset) fails = 0;
        offset = next;
        const dt = (Date.now() - t0) / 1000;
        if(dt > 20) chunk = Math.max(MINC, chunk >> 1);
        else if(dt < 5) chunk = Math.min(MAXC, chunk << 1);
        if(offset >= file.size){
          forget(file);
          prog(file.size, file.size);
          return {ok:true, name: p.getResponseHeader('Porch-Upload-Name') || file.name, size:file.size};
        }
        continue;
      }
      if(p.status === 409 || p.status === 423 || p.status === 429 || p.status >= 500){
        fails++; offset = -1; continue;          // re-ask the server where we are
      }
      if(p.status === 404 || p.status === 410){ forget(file); url = null; offset = -1; fails++; continue; }
      forget(file);
      return {ok:false, error:msg(p), retry:false};
    }
  }
  return {upload, available};
})();
"""

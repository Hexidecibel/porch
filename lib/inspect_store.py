#!/usr/bin/env python3
"""Request inspector store: what an inspected door (or a bin/hook webhook) saw.

lib/doorproxy.py runs a Recorder (a DoorObserver) when the door was opened
with --inspect / --inspect-raw, and always for a capture-only hook door. Each
finished exchange becomes one JSON line in

    <run dir>/inspect/<door>.jsonl      (lib/rundir.py: 0700 dirs, file 0600)

next to a control socket <door>.sock (0600, same dir) that only the door
proxy listens on. Readers (porch inspect, the status API) read the file
directly; they run as the same user and resolve the same run dir.

Record (one line per exchange, newest last):
    id, ts, ms, ttfb_ms, method, target, client_ip, owner, admitted,
    handled_by (upstream | gate | intercept | asset | replay), status,
    req_headers / resp_headers [[name, value], ...], req_bytes, resp_bytes,
    req_body / resp_body {kind: none|text|binary, size, truncated, type,
                          data (text), hex (binary head), decoded (gzip)},
    upgraded, error, replay_of, masked [header names], raw (bool)

Limits: bodies are captured up to BODY_CAP (64KB) each, with `truncated`
set past that. Media/binary types (and anything that is not UTF-8) keep only
metadata and a HEX_HEAD-byte hex head. A gzip/deflate body is decoded for
display only when the whole compressed body fit the cap, and the decoded
text is cut at the cap too. WebSocket (upgraded) exchanges are metadata only.
The store keeps the newest RING (500) records and at most MAX_STORE_BYTES:
appends are O_APPEND writes from the one proxy process, and once the file
passes RING + SLACK lines (or the byte cap) it is compacted by an atomic
rewrite (rundir.write_private). The file and socket are deleted when the
door closes (door proxy exit, tunnel_state_cleanup, door_state.stop_door).

Masking (unless --inspect-raw): Authorization, Proxy-Authorization, Cookie,
Set-Cookie and any header whose name contains token/secret/key/signature are
stored as `<first 4 chars>…[masked, N chars]` (only the length for values
under 12 chars), and a guest link's ?k= value is masked in the target. The
originals never touch disk.

Replay: `porch inspect --replay ID` and the status API ask the door proxy
over its control socket (SO_PEERCRED: our uid only). The proxy re-sends the
stored request to its own upstream app port (127.0.0.1, never another host)
and records the answer as a new exchange with `replay_of`. Masked headers
are replayed with their original values only while the proxy that recorded
them still holds them in memory (the same records as the ring); otherwise
they are dropped and the reply lists them. Refused: a hook door (no app), a
truncated, binary or decoded request body, an upgraded exchange, and
anything the door answered itself (gate pages, intercepts).

CLI:  inspect_store.py path <door>     prints the store path
      inspect_store.py remove <door>   deletes the store + socket
"""

import collections
import json
import os
import re
import socket
import struct
import sys
import threading
import time
import zlib
from types import SimpleNamespace

_LIB = os.path.dirname(os.path.abspath(__file__))
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
import rundir  # noqa: E402

TOOL = 'inspect'
BODY_CAP = 64 * 1024
HEX_HEAD = 32
RING = 500
SLACK = 50
MAX_STORE_BYTES = 32 * 1024 * 1024
REPLAY_TIMEOUT = 30
REPLAY_READ_MAX = 64 * 1024 * 1024      # read (and discard past the cap) at most this much
CTRL_MAX = 4096

NAME_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')

SENSITIVE_EXACT = frozenset({'authorization', 'proxy-authorization', 'cookie', 'set-cookie'})
SENSITIVE_PARTS = ('token', 'secret', 'key', 'signature')
MASK_MARK = '[masked'

# Never replayed as recorded: framing is rebuilt, and these describe the
# original connection.
REPLAY_DROP = frozenset({
    'connection', 'keep-alive', 'proxy-connection', 'te', 'trailer', 'transfer-encoding',
    'upgrade', 'expect', 'content-length', 'proxy-authorization',
})

_BINARY_PREFIXES = ('image/', 'audio/', 'video/', 'font/', 'model/')
_BINARY_TYPES = frozenset({
    'application/octet-stream', 'application/zip', 'application/gzip', 'application/x-gzip',
    'application/pdf', 'application/x-tar', 'application/x-7z-compressed',
    'application/x-bzip2', 'application/x-xz', 'application/vnd.rar', 'application/wasm',
    'application/x-protobuf', 'application/protobuf', 'application/msgpack',
    'application/x-msgpack', 'application/cbor', 'application/grpc', 'application/java-archive',
})
_TEXT_ENCODINGS = ('gzip', 'x-gzip', 'deflate')


class InspectError(Exception):
    """A user-facing refusal or failure (replay refused, no store, ...)."""


# ---- paths -------------------------------------------------------------------

def check_name(name):
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise InspectError(f'invalid door name: {name!r}')
    return name


def store_dir():
    return rundir.tool_dir(TOOL)


def store_path(name, base=None):
    return os.path.join(base or store_dir(), f'{check_name(name)}.jsonl')


def socket_path(name, base=None):
    return os.path.join(base or store_dir(), f'{check_name(name)}.sock')


def remove_store(name, base=None):
    """Delete a door's store and control socket (missing is fine)."""
    try:
        d = base or store_dir()
    except (rundir.UnsafeDirError, OSError, ValueError):
        return
    for p in (store_path(name, d), socket_path(name, d)):
        try:
            os.unlink(p)
        except OSError:
            pass


# ---- masking -----------------------------------------------------------------

def is_sensitive(header_name):
    n = (header_name or '').lower()
    return n in SENSITIVE_EXACT or any(p in n for p in SENSITIVE_PARTS)


def mask_value(value):
    v = str(value)
    keep = v[:4] if len(v) >= 12 else ''
    return f'{keep}…{MASK_MARK}, {len(v)} chars]'


def is_masked(value):
    return isinstance(value, str) and MASK_MARK in value and value.endswith(' chars]')


def mask_headers(headers):
    """[(k, v)] -> (masked list, {index: original}, [masked names])."""
    out, originals, names = [], {}, []
    for i, (k, v) in enumerate(headers):
        if is_sensitive(k):
            out.append([k, mask_value(v)])
            originals[i] = v
            if k.lower() not in names:
                names.append(k.lower())
        else:
            out.append([k, v])
    return out, originals, names


_K_RE = re.compile(r'(^|[?&])k=[^&#]*')

# Field names whose values are masked in form-encoded and JSON bodies and in
# query strings ('-' counts as '_', so api-key matches api_key).
SECRET_FIELD_RE = re.compile(
    r'password|passwd|secret|token|api_key|apikey|access_key|private|auth|signature'
    r'|session|cookie', re.I)


def is_secret_field(name):
    return bool(SECRET_FIELD_RE.search(str(name).replace('-', '_')))


def _mask_pairs(text, sep):
    """Mask the values of secret-named fields in `a=1<sep>b=2` text (form
    bodies, query strings) token by token, so the rest stays byte-for-byte.
    Returns (text, [masked field names])."""
    from urllib.parse import unquote_plus
    names, out = [], []
    for part in text.split(sep):
        k, eq, v = part.partition('=')
        key = unquote_plus(k)
        if eq and v and is_secret_field(key):
            part = f'{k}={mask_value(unquote_plus(v))}'
            if key not in names:
                names.append(key)
        out.append(part)
    return sep.join(out), names


def mask_query(target):
    """Mask secret-named query parameters of a request target."""
    path, q, rest = (target or '').partition('?')
    if not q:
        return target, []
    query, hash_, frag = rest.partition('#')
    masked, names = _mask_pairs(query, '&')
    return path + q + masked + hash_ + frag, names


def _mask_json_value(v, names, key=None):
    if isinstance(v, dict):
        return {k: (_mask_all(x, names, k) if is_secret_field(k) else _mask_json_value(x, names, k))
                for k, x in v.items()}
    if isinstance(v, list):
        return [_mask_json_value(x, names, key) for x in v]
    return v


def _mask_all(v, names, key):
    """Everything under the secret-named `key`: every scalar leaf masked."""
    if isinstance(v, dict):
        return {k: _mask_all(x, names, key) for k, x in v.items()}
    if isinstance(v, list):
        return [_mask_all(x, names, key) for x in v]
    if v is None or isinstance(v, bool) or v == '':
        return v
    if key not in names:
        names.append(key)
    return mask_value(v)


_JSON_PAIR_RE = re.compile(
    r'("((?:[^"\\]|\\.)*)"\s*:\s*)("(?:[^"\\]|\\.)*"|-?[0-9][0-9.eE+-]*)')


def _mask_json_text(text):
    """JSON body: parse, mask, re-serialize when anything was masked. A body
    that does not parse (truncated at the cap) falls back to masking
    "secret-key": "string"/number pairs in place."""
    names = []
    try:
        obj = json.loads(text)
    except ValueError:
        obj = None
    else:
        masked = _mask_json_value(obj, names)
        if not names:
            return text, []
        return json.dumps(masked, ensure_ascii=False), names

    def sub(m):
        key = m.group(2)
        if not is_secret_field(key):
            return m.group(0)
        val = m.group(3)
        raw = val[1:-1] if val.startswith('"') else val
        if not raw:
            return m.group(0)
        if key not in names:
            names.append(key)
        return m.group(1) + json.dumps(mask_value(raw), ensure_ascii=False)
    return _JSON_PAIR_RE.sub(sub, text), names


def mask_body_text(text, ctype):
    """(masked text, [field names]) for a stored text body: form-encoded and
    JSON bodies get secret-named fields masked; anything else is unchanged."""
    mt = media_type(ctype)
    if mt == 'application/x-www-form-urlencoded':
        return _mask_pairs(text, '&')
    stripped = text.lstrip()
    if mt.endswith('/json') or mt.endswith('+json') or (
            stripped[:1] in ('{', '[') and (not mt or mt.startswith('text/'))):
        return _mask_json_text(text)
    return text, []


def mask_guest_key(target):
    return _K_RE.sub(lambda m: m.group(1) + 'k=' + mask_value('x' * 32), target or '')


# ---- bodies ------------------------------------------------------------------

def _header(headers, name):
    name = name.lower()
    for k, v in headers or ():
        if k.lower() == name:
            return v
    return ''


def media_type(ctype):
    return (ctype or '').split(';', 1)[0].strip().lower()


def is_binary_type(ctype):
    mt = media_type(ctype)
    return mt.startswith(_BINARY_PREFIXES) or mt in _BINARY_TYPES


def _utf8(data, cut_tail):
    """Strict UTF-8, allowing a code point cut off by the cap at the end."""
    for trim in range(0, 4 if cut_tail else 1):
        try:
            return (data[:len(data) - trim] if trim else data).decode('utf-8')
        except UnicodeDecodeError:
            continue
    return None


def body_repr(raw, size, truncated, headers):
    """The stored form of one captured body (raw is at most BODY_CAP bytes)."""
    ctype = _header(headers, 'Content-Type')
    if not size and not raw:
        return {'kind': 'none', 'size': 0}
    out = {'size': size, 'truncated': bool(truncated), 'type': ctype[:200]}
    if is_binary_type(ctype):
        out.update(kind='binary', hex=bytes(raw[:HEX_HEAD]).hex())
        return out
    data = bytes(raw)
    cut = bool(truncated)
    enc = (_header(headers, 'Content-Encoding') or '').strip().lower()
    if enc and enc != 'identity':
        if enc not in _TEXT_ENCODINGS or truncated:
            out.update(kind='binary', hex=data[:HEX_HEAD].hex(), encoding=enc[:40])
            return out
        try:
            d = zlib.decompressobj(47 if enc != 'deflate' else 15)
            data = d.decompress(data, BODY_CAP)
            if d.unconsumed_tail:
                out['decoded_truncated'] = True
                cut = True
        except zlib.error:
            try:        # raw deflate, as some servers send it
                d = zlib.decompressobj(-15)
                data = d.decompress(bytes(raw), BODY_CAP)
            except zlib.error:
                out.update(kind='binary', hex=bytes(raw[:HEX_HEAD]).hex(), encoding=enc[:40])
                return out
        out['decoded'] = enc
    text = _utf8(data, cut)
    if text is None:
        out.update(kind='binary', hex=bytes(raw[:HEX_HEAD]).hex())
        return out
    out.update(kind='text', data=text)
    return out


class _Cap:
    """A body tap: keeps the first BODY_CAP bytes, counts the rest."""
    __slots__ = ('buf', 'size', 'truncated')

    def __init__(self):
        self.buf = bytearray()
        self.size = 0
        self.truncated = False

    def add(self, chunk):
        self.size += len(chunk)
        room = BODY_CAP - len(self.buf)
        if room > 0:
            self.buf += chunk[:room]
        if len(chunk) > room:
            self.truncated = True


# ---- the store (writer side, inside the door proxy) ----------------------------

class Store:
    """Append-only JSONL ring for one door, written only by its door proxy."""

    def __init__(self, path, ring=RING, max_bytes=MAX_STORE_BYTES, slack=SLACK):
        self.path = path
        self.ring = ring
        self.max_bytes = max_bytes
        self.slack = slack
        self.lock = threading.Lock()
        self.closed = False
        self.lines = 0
        self.bytes = 0
        self.next_id = 1
        for r in read_records(path):
            self.next_id = max(self.next_id, int(r.get('id') or 0) + 1)
            self.lines += 1
        try:
            self.bytes = os.path.getsize(path)
        except OSError:
            self.bytes = 0

    def reset(self):
        with self.lock:
            try:
                os.unlink(self.path)
            except OSError:
                pass
            self.lines = self.bytes = 0

    def new_id(self):
        with self.lock:
            i = self.next_id
            self.next_id += 1
            return i

    def append(self, rec):
        line = (json.dumps(rec, separators=(',', ':')) + '\n').encode('utf-8')
        with self.lock:
            if self.closed:
                return
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
                         | getattr(os, 'O_CLOEXEC', 0), 0o600)
            try:
                view = memoryview(line)
                while view:
                    n = os.write(fd, view)
                    view = view[n:]
            finally:
                os.close(fd)
            self.lines += 1
            self.bytes += len(line)
            if self.lines > self.ring + self.slack or self.bytes > self.max_bytes:
                self._compact()

    def _compact(self):
        recs = read_records(self.path)[-self.ring:]
        lines = [(json.dumps(r, separators=(',', ':')) + '\n').encode('utf-8') for r in recs]
        total = sum(len(x) for x in lines)
        while lines and total > self.max_bytes * 3 // 4:
            total -= len(lines.pop(0))
        rundir.write_private(self.path, b''.join(lines))
        self.lines, self.bytes = len(lines), total

    def get(self, rid):
        for r in read_records(self.path):
            if r.get('id') == rid:
                return r
        return None

    def close(self, remove=True):
        with self.lock:
            self.closed = True
            if remove:
                try:
                    os.unlink(self.path)
                except OSError:
                    pass


# ---- reading (CLI, status API) --------------------------------------------------

def _parse_lines(data):
    out = []
    for line in data.split(b'\n'):
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if isinstance(r, dict) and isinstance(r.get('id'), int):
            out.append(r)
    return out


def read_records(path, since=0):
    """Every complete record with id > since (a half-written last line is
    skipped). Missing file -> []."""
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError:
        return []
    if data and not data.endswith(b'\n'):
        data = data[:data.rfind(b'\n') + 1]
    recs = _parse_lines(data)
    return [r for r in recs if r['id'] > since] if since else recs


def get_record(path, rid):
    for r in read_records(path):
        if r['id'] == rid:
            return r
    return None


class Tail:
    """Incremental reader for --follow and the SSE stream: new complete
    records since the last poll. A compaction (new inode, or the file got
    shorter) re-reads from the start and filters by id."""

    def __init__(self, path, since=0):
        self.path = path
        self.last = since
        self.offset = 0
        self.ino = None

    def poll(self):
        try:
            st = os.stat(self.path)
        except OSError:
            self.offset, self.ino = 0, None
            return []
        if st.st_ino != self.ino or st.st_size < self.offset:
            self.ino, self.offset = st.st_ino, 0
        if st.st_size == self.offset:
            return []
        try:
            with open(self.path, 'rb') as f:
                f.seek(self.offset)
                data = f.read(st.st_size - self.offset)
        except OSError:
            return []
        end = data.rfind(b'\n') + 1
        self.offset += end
        recs = [r for r in _parse_lines(data[:end]) if r['id'] > self.last]
        if recs:
            self.last = max(r['id'] for r in recs)
        return recs


def summary(rec):
    """The list-row view of a record (no headers, no bodies)."""
    rb = rec.get('resp_body') or {}
    return {
        'id': rec.get('id'), 'ts': rec.get('ts'), 'ms': rec.get('ms'),
        'method': rec.get('method'), 'target': (rec.get('target') or '')[:500],
        'status': rec.get('status'), 'req_bytes': rec.get('req_bytes'),
        'resp_bytes': rec.get('resp_bytes'), 'handled_by': rec.get('handled_by'),
        'replay_of': rec.get('replay_of'), 'upgraded': bool(rec.get('upgraded')),
        'error': rec.get('error'), 'client_ip': rec.get('client_ip'),
        'type': media_type(rb.get('type') or ''),
    }


# ---- formatting (porch inspect) -------------------------------------------------

def fmt_size(n):
    n = int(n or 0)
    if n < 1024:
        return f'{n}B'
    if n < 1024 * 1024:
        return f'{n / 1024:.1f}K'
    return f'{n / 1024 / 1024:.1f}M'


_UNSAFE_RE = re.compile('[\x00-\x08\x0b-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]')


def term_safe(text):
    """Text from a request (anyone on the internet) is printed to the owner's
    terminal: control characters (ESC sequences, OSC 52 clipboard writes, C1,
    bidi overrides) become visible escapes. Newlines and tabs stay."""
    return _UNSAFE_RE.sub(lambda m: (f'\\x{ord(m.group()):02x}' if ord(m.group()) < 0x100
                                     else f'\\u{ord(m.group()):04x}'), str(text))


def one_line(rec, color=False):
    ts = time.strftime('%H:%M:%S', time.localtime(rec.get('ts') or 0))
    st = rec.get('status')
    ms = rec.get('ms')
    tag = ''
    if rec.get('replay_of'):
        tag = f' (replay of #{rec["replay_of"]})'
    elif rec.get('upgraded'):
        tag = ' (websocket)'
    elif rec.get('handled_by') == 'gate':
        tag = ' (gate)'
    if rec.get('error'):
        tag += f' error: {rec["error"]}'
    target = term_safe(rec.get('target') or '')
    tag = term_safe(tag)
    if len(target) > 120:
        target = target[:117] + '...'
    status = str(st) if st is not None else '---'
    if color:
        c = '32' if st and st < 300 else '36' if st and st < 400 else '33' if st and st < 500 else '31'
        status = f'\033[{c}m{status}\033[0m'
        ts = f'\033[2m{ts}\033[0m'
        method = f'\033[1m{term_safe(rec.get("method") or "?"):<6}\033[0m'
    else:
        method = f'{term_safe(rec.get("method") or "?"):<6}'
    ms_s = f'{ms:.0f}ms' if isinstance(ms, (int, float)) else '-'
    return (f'#{rec.get("id"):<4} {ts} {method} {target} {status} {ms_s:>7} '
            f'{fmt_size(rec.get("resp_bytes"))}{tag}')


def _body_text(b):
    kind = (b or {}).get('kind')
    if kind in (None, 'none'):
        return '  (no body)'
    head = f'  {fmt_size(b.get("size"))} {b.get("type") or ""}'.rstrip()
    if b.get('truncated'):
        head += f' (truncated: first {fmt_size(BODY_CAP)} kept)'
    if b.get('decoded'):
        head += f' (decoded from {b["decoded"]})'
    if kind == 'binary':
        return head + f'\n  binary: not stored; first bytes {b.get("hex", "")}'
    data = b.get('data') or ''
    if media_type(b.get('type')).endswith('json') or media_type(b.get('type')).endswith('+json'):
        try:
            data = json.dumps(json.loads(data), indent=2, ensure_ascii=False)
        except ValueError:
            pass
    return head + '\n' + '\n'.join('    ' + ln for ln in data.split('\n'))


def details(rec):
    when = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(rec.get('ts') or 0))
    lines = [f'#{rec.get("id")}  {rec.get("method")} {rec.get("target")}',
             f'  at {when} from {rec.get("client_ip")}  ->  {rec.get("status")} '
             f'in {rec.get("ms")}ms (handled by {rec.get("handled_by")})']
    if rec.get('replay_of'):
        lines.append(f'  replay of #{rec["replay_of"]}')
    if rec.get('upgraded'):
        lines.append('  websocket: recorded as metadata only')
    if rec.get('error'):
        lines.append(f'  error: {rec["error"]}')
    if rec.get('raw'):
        lines.append('  raw capture: header values are NOT masked')
    lines.append('')
    lines.append(f'Request headers ({fmt_size(rec.get("req_bytes"))} body):')
    lines += [f'  {k}: {v}' for k, v in rec.get('req_headers') or []]
    lines.append('Request body:')
    lines.append(_body_text(rec.get('req_body')))
    lines.append('')
    lines.append(f'Response headers ({fmt_size(rec.get("resp_bytes"))} body):')
    lines += [f'  {k}: {v}' for k, v in rec.get('resp_headers') or []]
    lines.append('Response body:')
    lines.append(_body_text(rec.get('resp_body')))
    return term_safe('\n'.join(lines))


# ---- the recorder (a DoorObserver, inside the door proxy) -----------------------

class Recorder:
    """Records every exchange of one door into its Store. Duck-types
    doorproxy.DoorObserver (no import: doorproxy imports us)."""

    def __init__(self, door, raw=False, base=None, store=None):
        self.door = door
        self.raw = bool(raw)
        self.base = base
        self.store = store or Store(store_path(door.name, base))
        self._live = {}
        self._lock = threading.Lock()
        # id -> {'h': {header index: original}, 'body': text, 'target': str},
        # for replay; same bound as the ring. Never written anywhere.
        self._originals = collections.OrderedDict()
        self._ctrl = None

    # observer hooks
    def _slot(self, exch):
        with self._lock:
            s = self._live.get(exch.id)
            if s is None:
                s = self._live[exch.id] = {'req': _Cap(), 'resp': _Cap(), 'ttfb': None}
            return s

    def intercept(self, exch):
        return None

    def on_request(self, exch):
        pass

    def on_request_body(self, exch, chunk):
        self._slot(exch)['req'].add(chunk)

    def on_response(self, exch):
        self._slot(exch)['ttfb'] = self.door.clock()

    def on_response_body(self, exch, chunk):
        self._slot(exch)['resp'].add(chunk)

    def on_exchange(self, exch):
        with self._lock:
            s = self._live.pop(exch.id, None) or {'req': _Cap(), 'resp': _Cap(), 'ttfb': None}
        if exch.handled_by == 'asset':
            return          # porch.css/fonts for a gate page: noise
        rec = self.build(exch, s)
        self.store.append(rec)

    # records
    def _guest_on(self):
        try:
            return 'guest' in self.door.rules()
        except Exception:  # noqa: BLE001
            return False

    def build(self, exch, s, replay_of=None):
        rid = self.store.new_id()
        req_h = [(k, v) for k, v in exch.request_headers]
        resp_h = [(k, v) for k, v in exch.response_headers]
        target = exch.target
        keep = {}
        target_masked = []
        if self.raw:
            rq, originals, masked = [list(h) for h in req_h], {}, []
            rs = [list(h) for h in resp_h]
        else:
            rq, originals, masked = mask_headers(req_h)
            rs, _, masked_resp = mask_headers(resp_h)
            masked += [n for n in masked_resp if n not in masked]
            # A matching ?k= is always answered by the gate (a redirect), so
            # only the door's own answers can carry a live guest key.
            if exch.handled_by in ('gate', 'asset') and (exch.admitted == 'guest'
                                                         or self._guest_on()):
                target = mask_guest_key(target)
            target, target_masked = mask_query(target)
            if target_masked:
                keep['target'] = exch.target
        if originals:
            keep['h'] = originals
        started = exch.started
        ended = exch.ended or self.door.clock()
        rec = {
            'id': rid, 'ts': round(started, 3),
            'ms': round((ended - started) * 1000, 1),
            'ttfb_ms': round((s['ttfb'] - started) * 1000, 1) if s.get('ttfb') else None,
            'method': exch.method, 'target': target, 'client_ip': exch.client_ip,
            'owner': bool(exch.owner), 'admitted': exch.admitted,
            'handled_by': exch.handled_by, 'status': exch.status,
            'req_headers': rq, 'resp_headers': rs,
            'req_bytes': exch.req_bytes, 'resp_bytes': exch.resp_bytes,
            'upgraded': bool(exch.upgraded), 'error': exch.error,
            'masked': masked, 'raw': self.raw,
        }
        if target_masked:
            rec['target_masked'] = target_masked
        if exch.upgraded:
            rec['req_body'] = rec['resp_body'] = {'kind': 'none', 'size': 0, 'websocket': True}
        else:
            rec['req_body'] = body_repr(s['req'].buf, s['req'].size, s['req'].truncated, req_h)
            rec['resp_body'] = body_repr(s['resp'].buf, s['resp'].size, s['resp'].truncated,
                                         resp_h)
            if not self.raw:
                for side in ('req_body', 'resp_body'):
                    b = rec[side]
                    if b.get('kind') != 'text':
                        continue
                    text, fields = mask_body_text(b.get('data') or '', b.get('type'))
                    if fields:
                        if side == 'req_body':
                            keep['body'] = b['data']
                        b['data'] = text
                        b['masked_fields'] = fields
        if keep:
            with self._lock:
                self._originals[rid] = keep
                while len(self._originals) > self.store.ring:
                    self._originals.popitem(last=False)
        if replay_of is not None:
            rec['replay_of'] = replay_of
        return rec

    # replay (runs in the door proxy: it alone knows the upstream and the originals)
    def replay(self, rid):
        door = self.door
        if door.upstream is None:
            raise InspectError('this is a capture-only hook door: there is no app behind it '
                               'to replay to')
        rec = self.store.get(rid)
        if rec is None:
            raise InspectError(f'no request #{rid} (only the last {self.store.ring} are kept)')
        if rec.get('upgraded'):
            raise InspectError('websocket exchanges cannot be replayed')
        if rec.get('handled_by') not in ('upstream', 'replay'):
            raise InspectError(f'#{rid} was answered by the door itself '
                               f'({rec.get("handled_by")}), not by the app')
        body = rec.get('req_body') or {}
        kind = body.get('kind')
        if body.get('truncated'):
            raise InspectError(f'#{rid} has a truncated request body (over {fmt_size(BODY_CAP)}): '
                               'refusing to replay a partial request')
        if kind == 'binary' or body.get('decoded'):
            raise InspectError(f'#{rid} has a binary or encoded request body that was not '
                               'stored in full: it cannot be replayed')
        with self._lock:
            kept = dict(self._originals.get(rid) or {})
        originals = dict(kept.get('h') or {})
        text = body.get('data') or ''
        if body.get('masked_fields'):
            if 'body' not in kept:
                raise InspectError(
                    f'#{rid} has secret fields masked in its body '
                    f'({", ".join(body["masked_fields"])}) and the door proxy that recorded it '
                    'no longer holds the originals: refusing to replay a masked body')
            text = kept['body']
        payload = text.encode('utf-8') if kind == 'text' else b''
        target = rec.get('target') or '/'
        if rec.get('target_masked'):
            if 'target' not in kept:
                raise InspectError(
                    f'#{rid} has masked query parameters ({", ".join(rec["target_masked"])}) '
                    'and the door proxy that recorded it no longer holds the originals')
            target = kept['target']
        headers, dropped = [], []
        for i, (k, v) in enumerate(rec.get('req_headers') or []):
            if not isinstance(k, str) or k.lower() in REPLAY_DROP:
                continue
            if i in originals:
                v = originals[i]
            elif not rec.get('raw') and is_sensitive(k) and is_masked(v):
                dropped.append(k)
                continue
            headers.append((k, str(v).replace('\r', ' ').replace('\n', ' ')))
        headers.append(('X-Porch-Replay', str(rid)))
        if payload or rec.get('method') in ('POST', 'PUT', 'PATCH'):
            headers.append(('Content-Length', str(len(payload))))
        headers.append(('Connection', 'close'))

        started = door.clock()
        exch = SimpleNamespace(
            id=None, started=started, ended=None, method=rec.get('method') or 'GET',
            target=target, client_ip='replay', owner=True, admitted='replay',
            handled_by='replay', status=None, response_headers=[], request_headers=headers,
            req_bytes=len(payload), resp_bytes=0, upgraded=False, error=None)
        s = {'req': _Cap(), 'resp': _Cap(), 'ttfb': None}
        s['req'].add(payload)
        target = exch.target
        try:
            self._send(exch, s, target, payload)
        except (OSError, ValueError) as e:
            exch.error = f'replay: {e}'
        exch.ended = door.clock()
        new = self.build(exch, s, replay_of=rid)
        self.store.append(new)
        return {'ok': True, 'id': new['id'], 'status': new['status'], 'error': new['error'],
                'dropped': dropped}

    def _send(self, exch, s, target, payload):
        import http.client
        host, port = self.door.upstream
        if host not in ('127.0.0.1', '::1', 'localhost'):
            raise ValueError('replay only goes to the local app')
        c = http.client.HTTPConnection(host, port, timeout=REPLAY_TIMEOUT)
        try:
            c.putrequest(exch.method, target, skip_host=True, skip_accept_encoding=True)
            for k, v in exch.request_headers:
                c.putheader(k, v)
            c.endheaders(payload or None)
            r = c.getresponse()
            s['ttfb'] = self.door.clock()
            exch.status = r.status
            exch.response_headers = list(r.getheaders())
            total = 0
            while total < REPLAY_READ_MAX:
                chunk = r.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                s['resp'].add(chunk)
            exch.resp_bytes = total
        finally:
            c.close()

    # control socket
    def start_control(self):
        path = socket_path(self.door.name, self.base)
        try:
            os.unlink(path)
        except OSError:
            pass
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)
        try:
            srv.bind(path)
        finally:
            os.umask(old)
        os.chmod(path, 0o600)
        srv.listen(8)
        self._ctrl = (srv, path)
        threading.Thread(target=self._serve_control, args=(srv,), daemon=True).start()
        return path

    def _serve_control(self, srv):
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=self._control_conn, args=(conn,), daemon=True).start()

    def _control_conn(self, conn):
        with conn:
            try:
                creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                        struct.calcsize('3i'))
                _pid, uid, _gid = struct.unpack('3i', creds)
                if uid != os.getuid():
                    return
            except (OSError, AttributeError):
                return
            conn.settimeout(5)
            try:
                buf = b''
                while b'\n' not in buf and len(buf) < CTRL_MAX:
                    d = conn.recv(CTRL_MAX)
                    if not d:
                        break
                    buf += d
                req = json.loads(buf.split(b'\n', 1)[0] or b'{}')
                if not isinstance(req, dict):
                    raise ValueError('bad request')
            except (OSError, ValueError):
                return
            try:
                if req.get('op') == 'replay' and isinstance(req.get('id'), int) \
                        and not isinstance(req.get('id'), bool):
                    reply = self.replay(req['id'])
                elif req.get('op') == 'ping':
                    reply = {'ok': True, 'capture': self.door.upstream is None}
                else:
                    reply = {'ok': False, 'error': 'unknown request'}
            except InspectError as e:
                reply = {'ok': False, 'error': str(e)}
            except Exception as e:  # noqa: BLE001
                reply = {'ok': False, 'error': f'replay failed: {e!r}'}
            try:
                conn.settimeout(10)
                conn.sendall((json.dumps(reply) + '\n').encode('utf-8'))
            except OSError:
                pass

    def close(self):
        if self._ctrl:
            srv, path = self._ctrl
            try:
                srv.close()
            except OSError:
                pass
            try:
                os.unlink(path)
            except OSError:
                pass
        self.store.close(remove=True)


def request_replay(name, rid, base=None, timeout=REPLAY_TIMEOUT + 10):
    """Ask the door's proxy to replay record `rid`. Returns its reply dict
    ({ok, id, status, error, dropped}); raises InspectError when the door's
    proxy can't be reached or refuses."""
    path = socket_path(name, base)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        try:
            s.connect(path)
        except OSError:
            raise InspectError(f"{name}: no inspector is running for this door "
                               "(is it open, and was it started with --inspect?)") from None
        s.sendall((json.dumps({'op': 'replay', 'id': int(rid)}) + '\n').encode('utf-8'))
        buf = b''
        while b'\n' not in buf and len(buf) < 65536:
            d = s.recv(65536)
            if not d:
                break
            buf += d
    except socket.timeout:
        raise InspectError('the replay timed out') from None
    finally:
        s.close()
    try:
        reply = json.loads(buf.split(b'\n', 1)[0])
    except ValueError:
        raise InspectError('the door proxy gave no answer') from None
    if not isinstance(reply, dict):
        raise InspectError('the door proxy gave a bad answer')
    if not reply.get('ok'):
        raise InspectError(str(reply.get('error') or 'replay refused'))
    return reply


# ---- capture-only webhook responder ---------------------------------------------

class CaptureResponder:
    """intercept(): answer every admitted request with the configured
    response (bin/hook). Duck-types doorproxy.DoorObserver."""

    def __init__(self, status=200, body=b'ok\n', content_type='text/plain; charset=utf-8'):
        self.status = int(status)
        self.body = body if isinstance(body, bytes) else str(body).encode('utf-8')
        self.content_type = content_type

    @classmethod
    def from_state(cls, capture):
        c = capture if isinstance(capture, dict) else {}
        status = c.get('status')
        if not isinstance(status, int) or isinstance(status, bool) or not 200 <= status <= 599:
            status = 200
        body = c.get('body')
        if not isinstance(body, str):
            body = 'ok\n'
        ct = c.get('content_type')
        if not isinstance(ct, str) or not ct or '\n' in ct or '\r' in ct:
            ct = 'text/plain; charset=utf-8'
        return cls(status, body.encode('utf-8')[:BODY_CAP], ct[:200])

    def intercept(self, exch):
        return (self.status, [('Content-Type', self.content_type),
                              ('Cache-Control', 'no-store'),
                              ('X-Content-Type-Options', 'nosniff')], self.body)

    def on_request(self, exch):
        pass

    def on_request_body(self, exch, chunk):
        pass

    def on_response(self, exch):
        pass

    def on_response_body(self, exch, chunk):
        pass

    def on_exchange(self, exch):
        pass


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) == 2 and argv[0] in ('path', 'remove'):
        try:
            if argv[0] == 'path':
                print(store_path(argv[1]))
            else:
                remove_store(argv[1])
        except (InspectError, rundir.UnsafeDirError, OSError) as e:
            print(f'Error: {e}', file=sys.stderr)
            return 1
        return 0
    print('usage: inspect_store.py path|remove <door>', file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main())

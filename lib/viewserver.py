#!/usr/bin/env python3
"""Read-only viewer door: one shared file, rendered in the browser.

Used by bin/view (and `porch share` / `porch tail`). The server knows exactly
one file, resolved at startup; no part of a URL ever names a path on disk.
What it can show:

    markdown    marked (vendored) with a sanitizing renderer: raw HTML is
                escaped, links only http(s)/mailto, images only same-origin
    code/text   highlight.js, line numbers, wrap toggle
    pdf         pdf.js (vendored, lib/vendor/pdfjs), pages on a canvas
    csv/tsv     sortable, filterable table (first MAX_TABLE_ROWS rows)
    json        collapsible tree + raw view (up to MAX_JSON_BYTES)
    zip         a tree of entries; text/images/pdf/markdown/csv/json/diff
                entries open in the same renderers, read straight from the
                archive (never extracted), with entry-count, size,
                compression-ratio and encryption guards
    diff        per-file sections, split (wide) or unified (narrow)
    image/video/audio/other   a simple view plus a download
    --follow    a live log: the file is followed server-side (truncation
                and rotation handled) and lines are pushed over SSE

Endpoints: / (the page), /static/* (vendored JS, fixed table), /raw (the
file as an attachment), /file (inline, only for image/video/audio/pdf, under
a sandbox CSP), /content, /table, /diff (text, parsed table, parsed diff;
?e=<entry> for a zip entry), /zip/list, /zip/meta?e=, /zip/e/<entry>
(an entry inline when safe, ?dl=1 to download), /events (SSE, --follow).
"""

import argparse
import codecs
import csv
import html
import io
import itertools
import json
import os
import re
import socket
import stat
import sys
import threading
import urllib.parse
import zipfile
from struct import error as struct_error
from collections import deque, namedtuple
from http.server import BaseHTTPRequestHandler
from pathlib import Path

_HERE_LIB = os.path.dirname(os.path.abspath(__file__))
if _HERE_LIB not in sys.path:
    sys.path.insert(0, _HERE_LIB)
from porch_http import (  # noqa: E402  (shared HTTP core)
    SANDBOX_CSP, HardenedHandlerMixin, csp_nonce, human_size, make_server,
    porch_css_tag, porch_mark, porch_style_src, sanitize_filename,
    security_headers, serve_asset, stream_file,
)

# ---- limits -------------------------------------------------------------------

MIB = 1024 * 1024
MAX_TEXT_BYTES = 4 * MIB         # markdown/code/text shown inline; the rest is a download
MAX_JSON_BYTES = 8 * MIB         # JSON can't be shown truncated: over this, download only
MAX_TABLE_BYTES = 16 * MIB       # bytes of a CSV/TSV parsed for the table
MAX_TABLE_ROWS = 10000
MAX_TABLE_COLS = 256
MAX_DIFF_BYTES = 8 * MIB
MAX_DIFF_LINES = 100000
ZIP_MAX_ENTRIES = 10000          # entries listed (and servable)
ZIP_MAX_ENTRY_BYTES = 32 * MIB   # uncompressed bytes of one entry we will inflate
ZIP_MAX_RATIO = 100              # uncompressed / compressed, above ZIP_RATIO_FLOOR
ZIP_RATIO_FLOOR = 1 * MIB
ZIP_MAX_CD_ENTRIES = 100000      # central directory entries we will parse at all
ZIP_MAX_CD_BYTES = 16 * MIB      # central directory size we will parse at all
ZIP_PARSERS = 2                  # concurrent central-directory parses
SNIFF_BYTES = 8192
TAIL_KEEP = 5000                 # lines the server ring and the page keep
TAIL_BACKLOG_BYTES = 256 * 1024  # how far back from the end a new follow starts
TAIL_MAX_LINE = 8192             # chars per line; longer lines are cut
TAIL_POLL = 0.5                  # s between stat()s of the followed file
TAIL_HEARTBEAT = 15              # s of quiet before an SSE comment ping
TAIL_MAX_CLIENTS = 16            # concurrent /events streams
TAIL_BATCH = 500                 # lines per SSE event
TAIL_MAX_DRAIN = 8 * MIB         # bytes read per poll; a file growing faster skips ahead

# Big fields in a CSV are legal; the default 128 KiB limit raises mid-file.
csv.field_size_limit(MIB)

# ---- vendored front-end (lib/vendor, see SOURCES there) ----------------------

VENDOR_DIR = Path(__file__).resolve().parent / 'vendor'
_JS = 'text/javascript; charset=utf-8'
STATIC_FILES = {
    '/static/highlight.min.js': ('highlight.min.js', _JS),
    '/static/atom-one-dark.min.css': ('atom-one-dark.min.css', 'text/css; charset=utf-8'),
    '/static/marked.min.js': ('marked.min.js', _JS),
    '/static/pdfjs/pdf.min.mjs': ('pdfjs/pdf.min.mjs', _JS),
    '/static/pdfjs/pdf.worker.min.mjs': ('pdfjs/pdf.worker.min.mjs', _JS),
}
# pdf.js's packed CMaps (non-embedded CJK fonts) and standard fonts (the 14
# base fonts a PDF may name without embedding). Listed once at import: the
# table stays exact paths, so nothing in a URL ever reaches the filesystem.
PDF_CMAPS = '/static/pdfjs/cmaps/'
PDF_STD_FONTS = '/static/pdfjs/standard_fonts/'
_VENDOR_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$')


def _vendor_dir_table(sub, url_prefix, types):
    out = {}
    d = VENDOR_DIR / sub
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return out
    for n in names:
        ctype = types.get(os.path.splitext(n)[1].lower())
        if ctype and _VENDOR_NAME.match(n) and not os.path.islink(d / n) and (d / n).is_file():
            out[url_prefix + n] = (f'{sub}/{n}', ctype)
    return out


STATIC_FILES.update(_vendor_dir_table('pdfjs/cmaps', PDF_CMAPS,
                                      {'.bcmap': 'application/octet-stream'}))
STATIC_FILES.update(_vendor_dir_table('pdfjs/standard_fonts', PDF_STD_FONTS,
                                      {'.pfb': 'application/octet-stream', '.ttf': 'font/ttf'}))
_static_cache = {}

# ---- sniffing -----------------------------------------------------------------

MODES = ('markdown', 'code', 'text', 'pdf', 'csv', 'tsv', 'json', 'zip', 'diff',
         'image', 'video', 'audio', 'other')
TEXT_MODES = frozenset({'markdown', 'code', 'text', 'csv', 'tsv', 'json', 'diff'})
# What a zip entry can be opened as in the page (video/audio would need ranges).
ZIP_VIEWABLE = TEXT_MODES | {'pdf', 'image'}

Sniff = namedtuple('Sniff', 'mode mime lang')

# Images a browser can draw and we are happy to serve inline (no SVG: it can
# carry script, so SVG is shown as XML source instead).
SAFE_IMAGE_MIMES = frozenset({'image/png', 'image/jpeg', 'image/gif', 'image/webp',
                              'image/bmp', 'image/avif', 'image/tiff', 'image/heic'})

TEXT_EXT_MODE = {
    '.md': 'markdown', '.markdown': 'markdown', '.mdown': 'markdown', '.mkd': 'markdown',
    '.csv': 'csv', '.tsv': 'tsv', '.tab': 'tsv',
    '.json': 'json', '.geojson': 'json', '.webmanifest': 'json',
    '.diff': 'diff', '.patch': 'diff',
}

# Extension -> highlight.js language (all in the vendored "common" build).
LANG_BY_EXT = {
    '.py': 'python', '.pyw': 'python', '.js': 'javascript', '.mjs': 'javascript',
    '.cjs': 'javascript', '.jsx': 'javascript', '.ts': 'typescript', '.tsx': 'typescript',
    '.json': 'json', '.sh': 'bash', '.bash': 'bash', '.zsh': 'bash', '.fish': 'bash',
    '.html': 'xml', '.htm': 'xml', '.xml': 'xml', '.svg': 'xml', '.plist': 'xml',
    '.css': 'css', '.scss': 'scss', '.less': 'less', '.go': 'go', '.rs': 'rust',
    '.rb': 'ruby', '.yaml': 'yaml', '.yml': 'yaml', '.toml': 'ini', '.ini': 'ini',
    '.cfg': 'ini', '.conf': 'ini', '.md': 'markdown', '.sql': 'sql', '.c': 'c',
    '.h': 'c', '.cc': 'cpp', '.cpp': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp',
    '.java': 'java', '.kt': 'kotlin', '.kts': 'kotlin', '.swift': 'swift',
    '.php': 'php', '.pl': 'perl', '.pm': 'perl', '.lua': 'lua', '.r': 'r',
    '.cs': 'csharp', '.m': 'objectivec', '.diff': 'diff', '.patch': 'diff',
    '.mk': 'makefile', '.graphql': 'graphql', '.vb': 'vbnet', '.wasm': 'wasm',
}
LANG_BY_NAME = {'makefile': 'makefile', 'dockerfile': 'dockerfile', 'gnumakefile': 'makefile'}

# A head that looks like a patch even without .diff/.patch.
_DIFF_HEAD = re.compile(r'(?:diff --git |Index: \S|From [0-9a-f]{40} |--- \S[^\n]*\n\+\+\+ \S)')


def _ext(name):
    return os.path.splitext(str(name).lower())[1]


def _looks_binary(head):
    if b'\x00' in head:
        return True
    if not head:
        return False
    try:
        # Incremental: a multi-byte character cut by the sniff window is fine.
        codecs.getincrementaldecoder('utf-8')().decode(head, final=False)
        return False
    except UnicodeDecodeError:
        pass
    # Not UTF-8: call it text only when control characters are rare (Latin-1
    # prose, a log with a stray byte); ESC is allowed for ANSI colour.
    ctrl = sum(1 for b in head if b < 9 or 13 < b < 27 or 27 < b < 32)
    return ctrl > len(head) // 20


def sniff_bytes(head, name='', complete=False):
    """Sniff(mode, mime, lang) for content starting with `head`.

    Magic bytes decide first; the name's extension only refines text (and the
    weaker audio signatures). `complete` says head is the whole file, which
    lets an extensionless file be recognised as JSON.
    """
    ext = _ext(name)
    h = bytes(head[:SNIFF_BYTES])
    if h.startswith(b'%PDF-'):
        return Sniff('pdf', 'application/pdf', '')
    if h.startswith(b'\x89PNG\r\n\x1a\n'):
        return Sniff('image', 'image/png', '')
    if h.startswith(b'\xff\xd8\xff'):
        return Sniff('image', 'image/jpeg', '')
    if h[:6] in (b'GIF87a', b'GIF89a'):
        return Sniff('image', 'image/gif', '')
    if h[:2] == b'BM' and len(h) >= 14 and h[6:10] == b'\x00\x00\x00\x00':
        return Sniff('image', 'image/bmp', '')
    if h[:4] in (b'II*\x00', b'MM\x00*'):
        return Sniff('image', 'image/tiff', '')
    if h[:4] == b'RIFF' and len(h) >= 12:
        kind = h[8:12]
        if kind == b'WEBP':
            return Sniff('image', 'image/webp', '')
        if kind == b'WAVE':
            return Sniff('audio', 'audio/wav', '')
        if kind == b'AVI ':
            return Sniff('video', 'video/x-msvideo', '')
    if h[4:8] == b'ftyp' and len(h) >= 12:
        brand = h[8:12]
        if brand in (b'avif', b'avis'):
            return Sniff('image', 'image/avif', '')
        if brand in (b'heic', b'heix', b'heim', b'heis', b'hevc', b'hevx', b'mif1', b'msf1'):
            return Sniff('image', 'image/heic', '')
        if brand in (b'M4A ', b'M4B ', b'M4P ', b'F4A '):
            return Sniff('audio', 'audio/mp4', '')
        if brand == b'qt  ':
            return Sniff('video', 'video/quicktime', '')
        if brand.startswith(b'3g'):
            return Sniff('video', 'video/3gpp', '')
        return Sniff('video', 'video/mp4', '')
    if h.startswith(b'\x1aE\xdf\xa3'):
        return Sniff('video', 'video/webm', '')
    if h.startswith(b'OggS'):
        if ext == '.ogv':
            return Sniff('video', 'video/ogg', '')
        return Sniff('audio', 'audio/ogg', '')
    if h.startswith(b'fLaC'):
        return Sniff('audio', 'audio/flac', '')
    if h.startswith(b'ID3') or (len(h) >= 2 and h[0] == 0xFF and (h[1] & 0xE0) == 0xE0
                                and ext in ('.mp3', '.mp2', '.mpga')):
        return Sniff('audio', 'audio/mpeg', '')
    if h[:4] in (b'FORM',) and h[8:12] in (b'AIFF', b'AIFC'):
        return Sniff('audio', 'audio/aiff', '')
    if h.startswith((b'PK\x03\x04', b'PK\x05\x06')):
        return Sniff('zip', 'application/zip', '')
    if _looks_binary(h):
        return Sniff('other', 'application/octet-stream', '')

    # Text from here on.
    lang = LANG_BY_EXT.get(ext) or LANG_BY_NAME.get(os.path.basename(str(name)).lower(), '')
    mode = TEXT_EXT_MODE.get(ext)
    if mode:
        return Sniff(mode, 'text/plain', lang)
    text = h.decode('utf-8', 'replace').lstrip('﻿')
    if _DIFF_HEAD.match(text):
        return Sniff('diff', 'text/plain', 'diff')
    stripped = text.lstrip()
    if complete and stripped[:1] in ('{', '[') and not lang:
        try:
            json.loads(stripped)
            return Sniff('json', 'text/plain', 'json')
        except ValueError:
            pass
    return Sniff('code' if lang else 'text', 'text/plain', lang)


def sniff_file(path):
    """sniff_bytes() for a file on disk (reads the first SNIFF_BYTES)."""
    with open(path, 'rb') as f:
        head = f.read(SNIFF_BYTES + 1)
    return sniff_bytes(head, os.path.basename(str(path)), complete=len(head) <= SNIFF_BYTES)


# ---- text, tables, diffs ------------------------------------------------------

def decode_text(data):
    text = bytes(data).decode('utf-8', 'replace')
    return text[1:] if text.startswith('﻿') else text


def table_delimiter(data, hint):
    """',' / '\\t' / ';' / '|' for a CSV-ish file. hint: 'tab', a literal
    delimiter, or 'auto' (csv.Sniffer over the first 8 KiB, ',' if unsure)."""
    if hint == 'tab':
        return '\t'
    if hint in (',', ';', '|'):
        return hint
    sample = decode_text(data[:SNIFF_BYTES])
    try:
        return csv.Sniffer().sniff(sample, delimiters=',;|\t').delimiter
    except csv.Error:
        return ','


def parse_table(data, delimiter=',', max_rows=MAX_TABLE_ROWS, max_cols=MAX_TABLE_COLS,
                cut=False):
    """Parse CSV/TSV bytes into {header, rows, truncated, ...}.

    At most max_rows data rows (after the header) and max_cols columns are
    kept. `cut` says data is only the start of the file: the trailing partial
    line is dropped and the result is marked truncated.
    """
    text = decode_text(data)
    if cut:
        text = text[:text.rfind('\n') + 1]
    reader = csv.reader(io.StringIO(text, newline=''), delimiter=delimiter)
    rows, truncated, wide, error = [], bool(cut), False, None
    try:
        for row in reader:
            if len(rows) > max_rows:
                truncated = True
                break
            if len(row) > max_cols:
                wide = True
                row = row[:max_cols]
            rows.append(row)
    except csv.Error as e:
        error = str(e)
    return {
        'header': rows[0] if rows else [],
        'rows': rows[1:max_rows + 1],
        'truncated': truncated,
        'colsTruncated': wide,
        'maxRows': max_rows,
        'maxCols': max_cols,
        'delimiter': delimiter,
        'error': error,
    }


_HUNK = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@ ?(.*)$')
_GIT_HEAD = re.compile(r'^diff --git (?:"?a/)?(.+?)"? (?:"?b/)?(.+?)"?$')
_FILE_META = ('new file mode', 'deleted file mode', 'rename from', 'rename to',
              'similarity index', 'dissimilarity index', 'index ', 'old mode',
              'new mode', 'copy from', 'copy to', 'Binary files', 'GIT binary patch')


def _diff_path(raw):
    p = raw.split('\t', 1)[0].strip()
    if p.startswith('"') and p.endswith('"') and len(p) > 1:
        p = p[1:-1]
    if p == '/dev/null':
        return None
    if p[:2] in ('a/', 'b/'):
        p = p[2:]
    return p


def parse_diff(text, max_lines=MAX_DIFF_LINES):
    """Unified / git diff text -> {files: [...], preamble, truncated}.

    Each file: {old, new, status (modified|added|deleted|renamed|binary),
    adds, dels, meta: [...], hunks: [{h, lines: [[tag, old_no, new_no, text]]}]}
    with tag one of ' ', '-', '+', '\\\\'. Hunk line counts decide where a hunk
    ends, so a removed line that starts with '-- ' is never taken for a header.
    """
    files, preamble = [], []
    cur = hunk = None
    old_left = new_left = 0
    old_no = new_no = 0
    truncated = False

    def new_file():
        return {'old': None, 'new': None, 'status': 'modified', 'adds': 0, 'dels': 0,
                'meta': [], 'hunks': []}

    lines = text.split('\n')
    if lines and lines[-1] == '':
        lines.pop()
    for count, line in enumerate(lines, 1):
        if count > max_lines:
            truncated = True
            break
        line = line.rstrip('\r')
        if hunk is not None and (old_left > 0 or new_left > 0):
            tag = line[:1]
            if tag == ' ' or line == '':
                hunk['lines'].append([' ', old_no, new_no, line[1:]])
                old_no += 1
                new_no += 1
                old_left -= 1
                new_left -= 1
                continue
            if tag == '-':
                hunk['lines'].append(['-', old_no, None, line[1:]])
                old_no += 1
                old_left -= 1
                cur['dels'] += 1
                continue
            if tag == '+':
                hunk['lines'].append(['+', None, new_no, line[1:]])
                new_no += 1
                new_left -= 1
                cur['adds'] += 1
                continue
            if tag == '\\':
                hunk['lines'].append(['\\', None, None, line[1:].strip()])
                continue
            hunk = None                      # malformed: the counts lied
        if line.startswith('\\') and hunk is not None:
            hunk['lines'].append(['\\', None, None, line[1:].strip()])
            continue
        if line.startswith('diff --git '):
            # The header regex backtracks: quadratic on a huge line. Real
            # headers are short; a longer one keeps its raw text as the name.
            m = _GIT_HEAD.match(line) if len(line) <= 4096 else None
            cur = new_file()
            if m:
                cur['old'], cur['new'] = m.group(1), m.group(2)
            else:
                cur['old'] = cur['new'] = line[len('diff --git '):][:300]
            files.append(cur)
            hunk = None
            continue
        if line.startswith('--- '):
            if cur is None or cur['hunks'] or cur.get('_minus'):
                # A new file in a plain unified diff (no "diff --git" line).
                cur = new_file()
                files.append(cur)
                hunk = None
            cur['old'] = _diff_path(line[4:])
            cur['_minus'] = True
            continue
        if line.startswith('+++ ') and cur is not None and not cur['hunks']:
            cur['new'] = _diff_path(line[4:])
            continue
        m = _HUNK.match(line)
        if m:
            if cur is None:
                cur = new_file()
                files.append(cur)
            old_no, new_no = int(m.group(1)), int(m.group(3))
            old_left = int(m.group(2)) if m.group(2) is not None else 1
            new_left = int(m.group(4)) if m.group(4) is not None else 1
            hunk = {'h': line, 'lines': []}
            cur['hunks'].append(hunk)
            continue
        if cur is not None and line.startswith(_FILE_META):
            cur['meta'].append(line)
            continue
        if cur is None:
            preamble.append(line)
    for f in files:
        f.pop('_minus', None)
        meta = ' '.join(f['meta'])
        if f['old'] is None and f['new'] is not None and ('new file' in meta or f['hunks']):
            f['status'] = 'added'
        elif f['new'] is None and f['old'] is not None:
            f['status'] = 'deleted'
        elif 'new file mode' in meta:
            f['status'] = 'added'
        elif 'deleted file mode' in meta:
            f['status'] = 'deleted'
        elif f['old'] and f['new'] and f['old'] != f['new']:
            f['status'] = 'renamed'
        elif 'Binary files' in meta or 'GIT binary patch' in meta:
            f['status'] = 'binary'
    return {'files': files, 'preamble': '\n'.join(preamble)[:20000], 'truncated': truncated}


# ---- zip ----------------------------------------------------------------------

_DRIVE = re.compile(r'^[A-Za-z]:')
_ZIP_METHODS = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA}


class EntryRefused(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def unsafe_zip_name(name):
    """True for names that would escape a directory if anyone extracted them
    (absolute, drive letters, backslashes, '..' segments, control chars).
    They are listed as such and never served; nothing is ever written."""
    if not name or any(ord(c) < 32 or c == '\x7f' for c in name):
        return True
    if name.startswith(('/', '\\')) or '\\' in name or _DRIVE.match(name):
        return True
    return any(part == '..' for part in name.split('/'))


def zip_refusal(info, max_bytes=ZIP_MAX_ENTRY_BYTES, max_ratio=ZIP_MAX_RATIO,
                ratio_floor=ZIP_RATIO_FLOOR):
    """Why an entry will not be inflated, or None."""
    if info.flag_bits & 0x1:
        return 'encrypted'
    if info.compress_type not in _ZIP_METHODS:
        return 'unsupported compression'
    if info.file_size > max_bytes:
        return 'too large to view'
    if info.file_size > ratio_floor and info.file_size > max_ratio * max(info.compress_size, 1):
        return 'compression ratio too high'
    return None


_zip_parse_slots = threading.BoundedSemaphore(ZIP_PARSERS)


def _check_central_directory(fh, max_cd_entries, max_cd_bytes):
    """Refuse an archive whose central directory is too big to parse: zipfile
    builds a ZipInfo for every entry before we can look at any of them."""
    try:
        end = zipfile._EndRecData(fh)
    except (OSError, AttributeError, ValueError, struct_error):
        end = None
    if not end:
        raise EntryRefused(422, 'not a readable zip: no end of central directory')
    total, size = end[zipfile._ECD_ENTRIES_TOTAL], end[zipfile._ECD_SIZE]
    if total > max_cd_entries or size > max_cd_bytes:
        raise EntryRefused(413, f'this archive has {total} entries ({human_size(size)} of '
                                'directory); too many to browse. Download it instead.')
    fh.seek(0)


class _OpenZip:
    """A ZipFile over the shared file opened with O_NOFOLLOW (never through a
    symlink swapped in later), after the central-directory guard, holding one
    of ZIP_PARSERS slots."""

    def __init__(self, path, max_cd_entries=ZIP_MAX_CD_ENTRIES, max_cd_bytes=ZIP_MAX_CD_BYTES):
        self.args = (path, max_cd_entries, max_cd_bytes)
        self.fh = self.zf = None

    def __enter__(self):
        path, max_cd_entries, max_cd_bytes = self.args
        if not _zip_parse_slots.acquire(timeout=30):
            raise EntryRefused(503, 'busy reading other archives; try again')
        try:
            self.fh, _ = _open_regular(path)
            _check_central_directory(self.fh, max_cd_entries, max_cd_bytes)
            self.zf = zipfile.ZipFile(self.fh)
        except BaseException:
            self._close()
            raise
        return self.zf

    def _close(self):
        try:
            if self.zf is not None:
                self.zf.close()
            if self.fh is not None:
                self.fh.close()
        finally:
            _zip_parse_slots.release()

    def __exit__(self, *exc):
        self._close()
        return False


def zip_listing(path, max_entries=ZIP_MAX_ENTRIES, **limits):
    """{entries, total, truncated} for an archive. Directory entries are kept
    (the page builds its tree from names anyway)."""
    with _OpenZip(path) as zf:
        infos = zf.infolist()
    entries = []
    for info in infos[:max_entries]:
        name = info.filename
        e = {'name': name, 'size': info.file_size, 'csize': info.compress_size,
             'dir': info.is_dir()}
        if unsafe_zip_name(name):
            e['unsafe'] = True
        elif not e['dir']:
            why = zip_refusal(info, **limits)
            if why:
                e['refused'] = why
        entries.append(e)
    return {'entries': entries, 'total': len(infos), 'truncated': len(infos) > max_entries,
            'maxEntries': max_entries}


def read_zip_entry(path, name, max_entries=ZIP_MAX_ENTRIES, head=None, **limits):
    """(info, bytes) of one entry, inflated in memory. `head` reads only that
    many bytes (for sniffing). Raises EntryRefused."""
    max_bytes = limits.get('max_bytes', ZIP_MAX_ENTRY_BYTES)
    if unsafe_zip_name(name):
        raise EntryRefused(403, 'unsafe entry name')
    try:
        opened = _OpenZip(path)
        zf = opened.__enter__()
    except zipfile.BadZipFile as e:
        raise EntryRefused(422, f'not a readable zip: {e}')
    try:
        info = None
        for cand in zf.infolist()[:max_entries]:
            if cand.filename == name and not cand.is_dir():
                info = cand                  # a repeated name: the last one wins
        if info is None:
            raise EntryRefused(404, 'no such entry')
        why = zip_refusal(info, **limits)
        if why:
            raise EntryRefused(403 if why == 'encrypted' else 413, why)
        want = head if head is not None else max_bytes + 1
        try:
            with zf.open(info) as f:
                data = f.read(want)
        except (zipfile.BadZipFile, NotImplementedError, RuntimeError, OSError,
                EOFError, ValueError) as e:
            raise EntryRefused(422, f'entry unreadable: {e}')
    finally:
        opened.__exit__(None, None, None)
    # The header's file_size is attacker-controlled; never trust it alone.
    if head is None and (len(data) > max_bytes or len(data) > info.file_size):
        raise EntryRefused(413, 'entry larger than it claims')
    return info, data


# ---- tail -f ------------------------------------------------------------------

# OSC strings, CSI sequences, two-byte escapes and C0 controls (not \t, \n,
# or the ESC of a kept SGR). SGR colour sequences survive for the page.
_ANSI = re.compile(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?'
                   r'|\x1b\[[0-9;?]*[ -/]*[@-~]'
                   r'|\x1b[^\[\]]'
                   r'|[\x00-\x08\x0b-\x1a\x1c-\x1f\x7f]')
_SGR = re.compile(r'\x1b\[[0-9;]*m')


def clean_line(text, max_len=TAIL_MAX_LINE):
    """A log line made safe to ship: escapes stripped except SGR colours."""
    text = _ANSI.sub(lambda m: m.group(0) if _SGR.fullmatch(m.group(0)) else '', text)
    text = re.sub(r'\x1b(?!\[[0-9;]*m)', '', text)
    return text[:max_len]


def _open_regular(path):
    """A binary file object for `path`, refusing symlinks and non-files."""
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError('not a regular file')
    except BaseException:
        os.close(fd)
        raise
    return os.fdopen(fd, 'rb'), st


class Follower:
    """Follows one file like `tail -F` into a bounded ring of lines.

    One thread polls the file; every SSE client reads the shared ring, so a
    client costs a cursor, not a copy. Entries are (seq, kind, text) with
    kind 'l' (a line) or 'n' (a notice: truncated, rotated, skipped).
    """

    def __init__(self, path, keep=TAIL_KEEP, poll=TAIL_POLL, backlog=TAIL_BACKLOG_BYTES,
                 max_line=TAIL_MAX_LINE, max_drain=TAIL_MAX_DRAIN):
        self.path = str(path)
        self.keep = keep
        self.poll = poll
        self.backlog = backlog
        self.max_line = max_line
        self.max_drain = max_drain
        self.ring = deque(maxlen=keep)
        self.seq = 0
        self.cond = threading.Condition()
        self._fh = None
        self._id = None
        self._pos = 0
        self._partial = b''
        self._stop = threading.Event()

    def start(self):
        self._open(initial=True)
        self.poll_once()
        threading.Thread(target=self._run, name='follow', daemon=True).start()
        return self

    def stop(self):
        self._stop.set()
        with self.cond:
            self.cond.notify_all()

    @property
    def stopped(self):
        return self._stop.is_set()

    def _open(self, initial=False):
        try:
            fh, st = _open_regular(self.path)
        except OSError:
            self._fh = None
            return False
        self._fh, self._id, self._partial = fh, (st.st_dev, st.st_ino), b''
        if initial and st.st_size > self.backlog:
            fh.seek(st.st_size - self.backlog)
            fh.readline()                    # the first line is cut: drop it
        self._pos = fh.tell()
        return True

    def _run(self):
        try:
            while not self._stop.wait(self.poll):
                try:
                    self.poll_once()
                except Exception as e:       # keep following whatever happens
                    sys.stderr.write(f"[viewserver] follow: {e}\n")
        finally:
            if self._fh is not None:
                self._fh.close()

    def poll_once(self):
        if self._fh is None:
            if not self._open():
                return
            self._push([('n', 'the file is back; following it from the start')])
        try:
            st = os.stat(self.path)
        except OSError:
            st = None                        # mid-rotation: keep reading the old one
        if st is not None and (st.st_dev, st.st_ino) != self._id:
            self._drain()
            self._fh.close()
            self._fh = None
            if self._open():
                self._push([('n', 'the file was replaced (rotated); following the new one')])
            else:
                return
        elif st is not None and st.st_size < self._pos:
            self._fh.seek(0)
            self._pos = 0
            self._partial = b''
            self._push([('n', 'the file was truncated; following it from the start')])
        self._drain()

    def _drain(self):
        out = []
        budget = self.max_drain
        while True:
            if budget <= 0:
                # Writing faster than we read: jump to the last `backlog`
                # bytes instead of reading (and holding the thread) forever.
                size = os.fstat(self._fh.fileno()).st_size
                if size - self._pos > self.backlog:
                    skip = size - self.backlog - self._pos
                    if out:
                        self._push([('l', clean_line(b.decode('utf-8', 'replace'), self.max_line))
                                    for b in out])
                        out = []
                    self._fh.seek(size - self.backlog)
                    self._fh.readline()
                    self._pos = self._fh.tell()
                    self._partial = b''
                    self._push([('n', f'the file grew too fast; skipped about {human_size(skip)}')])
                budget = self.max_drain
            chunk = self._fh.read(65536)
            if not chunk:
                break
            budget -= len(chunk)
            self._pos += len(chunk)
            parts = (self._partial + chunk).split(b'\n')
            self._partial = parts.pop()
            if len(self._partial) > self.max_line * 4:
                parts.append(self._partial)  # a runaway line: ship what we have
                self._partial = b''
            out.extend(parts)
            if len(out) > self.keep:
                out = out[-self.keep:]
        if out:
            self._push([('l', clean_line(b.decode('utf-8', 'replace'), self.max_line))
                        for b in out])

    def _push(self, items):
        with self.cond:
            for kind, text in items:
                self.seq += 1
                self.ring.append((self.seq, kind, text))
            self.cond.notify_all()

    def since(self, seq, limit=TAIL_BATCH):
        """(entries after `seq`, at most `limit`; lines lost to the ring)."""
        with self.cond:
            if not self.ring:
                return [], 0
            first = self.ring[0][0]
            skipped = max(0, first - (seq + 1)) if seq else 0
            start = max(0, seq + 1 - first)
            return list(itertools.islice(self.ring, start, start + limit)), skipped

    def wait(self, seq, timeout):
        """Block until there is something after `seq`, a stop, or timeout."""
        with self.cond:
            self.cond.wait_for(lambda: self.seq > seq or self._stop.is_set(), timeout)
            return self.seq > seq


# ---- page ---------------------------------------------------------------------

MODE_LABELS = {
    'markdown': 'Markdown', 'code': 'Code', 'text': 'Text', 'pdf': 'PDF',
    'csv': 'CSV table', 'tsv': 'TSV table', 'json': 'JSON', 'zip': 'Zip archive',
    'diff': 'Diff', 'image': 'Image', 'video': 'Video', 'audio': 'Audio',
    'other': 'File', 'tail': 'Live log',
}

HLJS_CSS = '<link rel="stylesheet" href="/static/atom-one-dark.min.css">'
SCRIPT_HLJS = '<script src="/static/highlight.min.js"></script>'
SCRIPT_MARKED = '<script src="/static/marked.min.js"></script>'
# pdf.js is an ES module; it hands itself to the page script through window.
PDF_MODULE = """<script type="module" nonce="__NONCE__">
import * as pdfjsLib from '/static/pdfjs/pdf.min.mjs';
pdfjsLib.GlobalWorkerOptions.workerSrc = '/static/pdfjs/pdf.worker.min.mjs';
window.porchPdf = pdfjsLib;
window.dispatchEvent(new Event('porch-pdf'));
</script>"""

PAGE_HTML = r"""<!DOCTYPE html>
<html lang="en" data-app="serve">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>__TITLE__</title>
__PORCH_CSS__
__HEAD_EXTRA__
<style nonce="__NONCE__">
.p-title{word-break:break-word}
.bar{display:flex;flex-wrap:wrap;align-items:center;gap:8px}
.tools{display:flex;flex-wrap:wrap;align-items:center;gap:8px;flex:1 1 auto;min-width:0}
.tools .p-input{height:38px;flex:1 1 200px;max-width:340px;min-width:0;font-size:14px}
.meta{font:500 13px var(--font-mono);color:var(--muted)}
.p-btn[aria-pressed=true]{background:var(--accent-soft);border-color:var(--accent-line)}
.stage{display:flex;justify-content:center;background:var(--surface);border:1px solid var(--line);
  border-radius:var(--r-2xl);padding:16px;overflow:auto}
.stage img,.stage video{max-height:80vh;border-radius:var(--r-md)}
.stage audio{width:100%}
/* code: night in both themes (the vendored highlight theme is a dark one) */
.code{background:#1B181E;color:#F3ECE4;border:1px solid rgba(255,240,220,.10);border-radius:var(--r-2xl);
  overflow:auto;max-height:78vh}
.lines{font:400 13px/1.65 var(--font-mono);padding:12px 0;counter-reset:ln;min-width:max-content}
.lines .l{display:flex;padding-right:18px}
.lines .l::before{counter-increment:ln;content:counter(ln);flex:none;width:calc(var(--gw,3) * 1ch + 30px);
  padding:0 14px 0 16px;text-align:right;color:#7A7168;user-select:none;-webkit-user-select:none}
.lines .l:hover{background:rgba(255,240,220,.04)}
.lines .c{white-space:pre;flex:1}
.lines.g4{--gw:4}.lines.g5{--gw:5}.lines.g6{--gw:6}.lines.g7{--gw:7}
.code.wrap .lines{min-width:0}
.code.wrap .c{white-space:pre-wrap;overflow-wrap:anywhere}
.code .hljs{background:transparent;color:inherit}
/* markdown */
.md{background:var(--surface);border:1px solid var(--line);border-radius:var(--r-2xl);
  padding:28px clamp(18px,4vw,48px);font-size:16px;line-height:1.7}
.md>:first-child{margin-top:0}.md>:last-child{margin-bottom:0}
.md h1,.md h2,.md h3,.md h4,.md h5,.md h6{margin:1.5em 0 .55em;line-height:1.2}
.md h1{font-size:30px}.md h2{font-size:23px;padding-bottom:.3em;border-bottom:1px solid var(--line)}
.md h3{font-size:19px}.md h4,.md h5,.md h6{font-size:16px}
.md p,.md ul,.md ol,.md blockquote,.md pre,.md table,.md dl{margin:0 0 1em}
.md ul,.md ol{padding-left:1.5em}.md li+li{margin-top:.25em}
.md code{font-size:.86em;background:var(--raised);padding:.14em .38em;border-radius:6px}
.md pre{background:#1B181E;color:#F3ECE4;padding:14px 18px;border-radius:var(--r-lg);overflow:auto;
  border:1px solid rgba(255,240,220,.10)}
.md pre code{background:none;padding:0;font-size:13px;line-height:1.6;color:inherit}
.md blockquote{border-left:3px solid var(--porchlight);padding:.1em 1em;color:var(--muted)}
.md table{border-collapse:collapse;display:block;overflow:auto;max-width:100%}
.md th,.md td{border:1px solid var(--line-mid);padding:6px 12px;text-align:left}
.md th{background:var(--raised)}
.md img{max-width:100%;border-radius:var(--r-md)}
.md hr{border:0;border-top:1px solid var(--line);margin:2em 0}
.md a{color:var(--porchlight)}
/* tables */
.tablewrap{overflow:auto;max-height:76vh;border:1px solid var(--line);border-radius:var(--r-xl);background:var(--surface)}
table.grid{border-collapse:separate;border-spacing:0;font-size:13.5px;min-width:100%}
.grid th{position:sticky;top:0;z-index:1;background:var(--raised);text-align:left;font-weight:600;white-space:nowrap;
  border-bottom:1px solid var(--line-mid)}
.grid th button{all:unset;box-sizing:border-box;display:block;width:100%;padding:9px 12px;cursor:pointer}
.grid th button:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
.grid th[aria-sort=ascending] button::after{content:" \2191";color:var(--porchlight)}
.grid th[aria-sort=descending] button::after{content:" \2193";color:var(--porchlight)}
.grid td{padding:7px 12px;border-top:1px solid var(--line);white-space:nowrap;max-width:420px;overflow:hidden;
  text-overflow:ellipsis}
.grid td.num{text-align:right;font-family:var(--font-mono);font-variant-numeric:tabular-nums}
.grid .rn{color:var(--faint);font-family:var(--font-mono);text-align:right;padding:7px 10px}
.grid tbody tr:hover td{background:var(--veil)}
.more{align-self:center}
/* json */
.tree{font:400 13.5px/1.75 var(--font-mono);background:var(--surface);border:1px solid var(--line);
  border-radius:var(--r-2xl);padding:14px 18px;overflow:auto;max-height:78vh}
.tree .jkids{padding-left:18px;border-left:1px solid var(--line);margin-left:5px}
.tree summary{cursor:pointer;list-style:none;white-space:nowrap}
.tree summary::-webkit-details-marker{display:none}
.tree summary::before{content:"\25B8";display:inline-block;width:14px;color:var(--muted)}
.tree details[open]>summary::before{content:"\25BE"}
.tree .jrow{padding-left:14px;white-space:pre-wrap;overflow-wrap:anywhere}
.k{color:var(--text);font-weight:500}.ki{color:var(--faint)}.pu{color:var(--muted)}
.js{color:var(--ok)}.jn{color:var(--porchlight)}.jb,.jz{color:var(--muted);font-style:italic}
.prev{color:var(--muted)}.jmore{color:var(--faint);padding-left:14px}
/* diff */
.dfiles{display:flex;flex-direction:column;gap:14px}
.dfile{border:1px solid var(--line);border-radius:var(--r-xl);overflow:hidden;background:var(--surface)}
.dhead{display:flex;flex-wrap:wrap;gap:10px;align-items:center;padding:10px 14px;background:var(--raised);
  font:500 13px var(--font-mono)}
.dhead .path{flex:1 1 auto;min-width:0;overflow-wrap:anywhere}
.dhead .add{color:var(--ok)}.dhead .del{color:var(--danger)}
.dscroll{overflow-x:auto}
.dtable{width:100%;border-collapse:collapse;font:400 12.5px/1.6 var(--font-mono);table-layout:fixed}
.dtable td{padding:0 10px;vertical-align:top;white-space:pre-wrap;overflow-wrap:anywhere}
.dtable col.no{width:56px}
.dtable td.no{text-align:right;color:var(--faint);user-select:none;-webkit-user-select:none;white-space:nowrap;padding:0 8px}
.dtable tr.hunk td{background:var(--veil);color:var(--muted);padding:5px 10px}
@media (max-width:600px){.dtable col.no{width:40px}.dtable td.no{padding:0 4px}}
.dtable td.a{background:var(--ok-soft)}.dtable td.d{background:var(--danger-soft)}
.dtable td.no.a{background:color-mix(in srgb,var(--ok) 18%,transparent)}
.dtable td.no.d{background:color-mix(in srgb,var(--danger) 16%,transparent)}
.dtable td.e{background:var(--veil)}
.dtable tr.meta td{color:var(--muted);font-style:italic}
.dnote{padding:10px 14px;color:var(--muted);font-size:13px}
.preamble{margin:0;padding:14px 16px;background:var(--surface);border:1px solid var(--line);border-radius:var(--r-xl);
  font:400 13px/1.6 var(--font-mono);white-space:pre-wrap;color:var(--muted)}
/* pdf */
.pdfstage{background:var(--raised);border:1px solid var(--line);border-radius:var(--r-2xl);padding:16px;
  overflow:auto;max-height:82vh;text-align:center}
.pdfstage canvas{max-width:none;background:#fff;box-shadow:var(--shadow);border-radius:4px;vertical-align:top}
/* zip */
.ztree{background:var(--surface);border:1px solid var(--line);border-radius:var(--r-2xl);padding:8px}
.zdir>summary{display:flex;align-items:center;gap:8px;padding:8px 12px;cursor:pointer;list-style:none;
  font:500 14px var(--font-mono);border-radius:8px}
.zdir>summary::-webkit-details-marker{display:none}
.zdir>summary::before{content:"\25B8";color:var(--muted);width:12px}
.zdir[open]>summary::before{content:"\25BE"}
.zdir>summary:hover{background:var(--veil)}
.zkids{padding-left:18px}
.zrow{display:flex;align-items:center;gap:10px;width:100%;padding:8px 12px;font:400 13.5px var(--font-mono);
  background:none;border:0;text-align:left;color:inherit;cursor:pointer;border-radius:8px;text-decoration:none}
.zrow:hover{background:var(--veil)}
.zrow .zn{flex:1 1 auto;min-width:0;overflow-wrap:anywhere}
.zrow .sz,.zdir .sz{margin-left:auto;color:var(--muted);font-size:12px;white-space:nowrap}
.zrow[aria-disabled=true]{cursor:not-allowed;color:var(--muted)}
.zcount{color:var(--faint);font-size:12px}
.zentry{display:flex;flex-direction:column;gap:14px}
.zentry .zhead{display:flex;flex-wrap:wrap;align-items:center;gap:10px}
.zentry .zname{font:500 14px var(--font-mono);overflow-wrap:anywhere;flex:1 1 auto;min-width:0}
.unsafe{margin-top:10px}
/* tail */
.log{background:#141116;color:#F3ECE4;border:1px solid rgba(255,240,220,.10);border-radius:var(--r-2xl);
  font:400 12.5px/1.6 var(--font-mono);height:72vh;overflow:auto;padding:10px 0}
.log .l{padding:0 16px;white-space:pre;min-height:1.6em}
.log.wrap .l{white-space:pre-wrap;overflow-wrap:anywhere}
.log .l.note{color:#F5A524;font-style:italic}
.log .l.hit{background:rgba(245,165,36,.09)}
.log .l.cur{background:rgba(245,165,36,.20)}
.log mark{background:#F5A524;color:#1A1206;border-radius:3px}
.log:empty::before{content:"waiting for lines\2026";color:#8F867D;padding:0 16px}
.a-b{font-weight:600}.a-d{opacity:.7}.a-i{font-style:italic}.a-u{text-decoration:underline}
.a-30{color:#8F867D}.a-31{color:#F0605A}.a-32{color:#5CCB8A}.a-33{color:#F5C451}
.a-34{color:#6FA8F0}.a-35{color:#C792EA}.a-36{color:#56C8D8}.a-37{color:#E8E1D8}
.a-90{color:#A79E95}.a-91{color:#FF8A84}.a-92{color:#8AE0AE}.a-93{color:#FFD97A}
.a-94{color:#9CC4FF}.a-95{color:#DDB4FF}.a-96{color:#8AE6F0}.a-97{color:#FFFFFF}
.a-40{background:#3a3238}.a-41{background:#5a1f1c}.a-42{background:#1d4a30}.a-43{background:#5a4416}
.a-44{background:#1f3658}.a-45{background:#47295a}.a-46{background:#17474e}.a-47{background:#5c5650}
.jump{position:sticky;bottom:8px;float:right;margin-right:12px}
</style>
</head>
<body>
<main class="p-shell p-shell--wide">
  <header class="p-head">
    <div class="p-kicker">__MARK__<span>__KICKER__</span></div>
    <h1 class="p-title">__TITLE__</h1>
    <p class="p-lede meta">__META__</p>
  </header>
  <div class="bar">
    <div class="tools" id="tools"></div>
    <a class="p-btn p-btn--sm" id="dl" href="/raw">Download</a>
  </div>
  <div class="p-notice" id="notice" role="status" hidden></div>
  <section id="view" aria-live="off"></section>
  <footer class="p-foot">shared through porch &middot; read-only</footer>
</main>
<script type="application/json" id="cfg">__CFG_JSON__</script>
__SCRIPTS__
<script nonce="__NONCE__">
'use strict';
const CFG = JSON.parse(document.getElementById('cfg').textContent);
const view = document.getElementById('view');
const toolsEl = document.getElementById('tools');
const noticeEl = document.getElementById('notice');
const HL_MAX = 1500000;           // chars highlight.js is asked to colour
const DOM_ROWS = 2000;            // table rows put in the DOM per "show more"
const JSON_KIDS = 1000;           // children shown per JSON object/array

// Every untrusted string goes in through textContent. innerHTML only ever
// receives highlight.js output (it escapes its input), esc()'d text, or the
// sanitizing markdown renderer below.
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}
function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function fmtSize(n) {
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(n < 10 ? 1 : 0) : n) + ' ' + u[i];
}
function notice(text, kind) {
  noticeEl.textContent = text || '';
  noticeEl.className = 'p-notice' + (kind ? ' p-notice--' + kind : '');
  noticeEl.hidden = !text;
}
function btn(label, onClick, cls) {
  const b = el('button', 'p-btn p-btn--sm ' + (cls || 'p-btn--ghost'), label);
  b.type = 'button';
  if (onClick) b.addEventListener('click', onClick);
  return b;
}
function toggle(label, on, onChange) {
  const b = btn(label, () => { const v = b.getAttribute('aria-pressed') !== 'true';
    b.setAttribute('aria-pressed', String(v)); onChange(v); });
  b.setAttribute('aria-pressed', String(!!on));
  return b;
}
function linkBtn(label, href, cls) {
  const a = el('a', 'p-btn p-btn--sm ' + (cls || 'p-btn--ghost'), label);
  a.href = href;
  return a;
}
function withQ(url, kv) { return url + (url.indexOf('?') >= 0 ? '&' : '?') + kv; }
async function fetchOk(url) {
  const r = await fetch(url, {cache: 'no-store', credentials: 'same-origin'});
  if (!r.ok) {
    let msg = 'HTTP ' + r.status;
    try { const j = await r.json(); if (j && j.error) msg = j.error; } catch (e) {}
    const err = new Error(msg); err.status = r.status; throw err;
  }
  return r;
}
async function getText(url) {
  const r = await fetchOk(url);
  return {text: await r.text(), truncated: r.headers.get('X-Porch-Truncated') === '1',
          total: Number(r.headers.get('X-Porch-Total')) || 0};
}
async function getJSON(url) { return (await fetchOk(url)).json(); }
function truncNotice(r, what) {
  if (r.truncated) notice('Showing the first ' + fmtSize(new Blob([r.text]).size) + ' of ' +
    fmtSize(r.total) + ' ' + (what || '') + '. Download it for the whole file.', 'warn');
}

// ---- code -----------------------------------------------------------------
// Split highlighted HTML into lines, closing and reopening the <span>s that
// cross a newline so every line is balanced markup of its own.
function splitLines(h) {
  const out = [], open = [];
  const re = /<span[^>]*>|<\/span>|\n/g;
  let cur = '', last = 0, m;
  while ((m = re.exec(h))) {
    cur += h.slice(last, m.index);
    last = re.lastIndex;
    const t = m[0];
    if (t === '\n') { out.push(cur + '</span>'.repeat(open.length)); cur = open.join(''); }
    else if (t.charAt(1) === '/') { open.pop(); cur += t; }
    else { open.push(t); cur += t; }
  }
  out.push(cur + h.slice(last) + '</span>'.repeat(open.length));
  return out;
}
function highlight(text, lang) {
  if (window.hljs && lang && hljs.getLanguage(lang) && text.length <= HL_MAX) {
    try { return hljs.highlight(text, {language: lang, ignoreIllegals: true}).value; } catch (e) {}
  }
  return esc(text);
}
function codeBlock(text, lang, tools) {
  const card = el('div', 'code');
  const lines = el('div', 'lines');
  const rows = splitLines(highlight(text, lang));
  if (rows.length > 1 && rows[rows.length - 1] === '') rows.pop();
  const digits = String(rows.length).length;
  if (digits > 3) lines.classList.add('g' + Math.min(digits, 7));
  lines.innerHTML = rows.map(r => '<div class="l"><span class="c">' + r + '</span></div>').join('');
  card.appendChild(lines);
  if (tools) {
    tools.append(el('span', 'meta', rows.length.toLocaleString() + ' lines' + (lang ? ' · ' + lang : '')),
      toggle('Wrap', false, v => card.classList.toggle('wrap', v)),
      btn('Copy', ev => {
        const b = ev.currentTarget;
        navigator.clipboard.writeText(text).then(() => { b.textContent = 'Copied';
          setTimeout(() => { b.textContent = 'Copy'; }, 1800); }, () => { b.textContent = 'Select and copy'; });
      }));
  }
  return card;
}
async function renderCode(src, host, tools) {
  const r = await getText(src.content);
  truncNotice(r);
  host.appendChild(codeBlock(r.text, src.lang, tools));
}

// ---- markdown ---------------------------------------------------------------
// BEGIN markdown-sanitize (tests/test_viewserver.py runs this block in node)
// marked passes raw HTML straight through, and its output goes to innerHTML:
// raw HTML is never rendered. Its tags are dropped (script/style with their
// content) and what text is left is escaped, so a README's <p align=center>
// banner reads as its words, not as markup. [x](javascript:...) is the other
// way in: only http(s)/mailto links survive, and images only when they
// resolve to this origin (the CSP would block others anyway; a zip entry's
// relative images resolve to /zip/e/... and work).
function escHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function htmlToText(raw) {
  const t = String(raw).replace(/<(script|style|textarea|title)\b[\s\S]*?(?:<\/\1\s*>|$)/gi, '')
    .replace(/<!--[\s\S]*?(?:-->|$)/g, '').replace(/<\/?[A-Za-z!?][^>]*>?/g, '');
  // Entity references stay (they are inert text); every other & < > is escaped.
  return t.replace(/&(?!#?[A-Za-z0-9]{1,32};)/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function escAttr(s) {
  return escHtml(s).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function safeUrl(href, base, schemes) {
  if (typeof href !== 'string' || !href.trim()) return null;
  let u;
  // new URL() normalises what browsers accept ("java\tscript:", case games).
  try { u = new URL(href.trim(), base); } catch (e) { return null; }
  return schemes.indexOf(u.protocol) >= 0 ? u : null;
}
function mdRenderer(base) {
  return {
    html(raw) { return htmlToText(raw); },
    link(href, title, text) {
      const u = safeUrl(href, base, ['http:', 'https:', 'mailto:']);
      if (!u) return text;
      const t = title ? ' title="' + escAttr(title) + '"' : '';
      return '<a href="' + escAttr(u.href) + '"' + t + ' rel="noopener noreferrer nofollow">' + text + '</a>';
    },
    image(href, title, text) {
      const u = safeUrl(href, base, ['http:', 'https:']);
      if (!u || u.origin !== location.origin) return escHtml(text || '');
      const t = title ? ' title="' + escAttr(title) + '"' : '';
      return '<img src="' + escAttr(u.href) + '" alt="' + escAttr(text || '') + '"' + t + ' loading="lazy">';
    },
    code(code, info) {
      const lang = String(info || '').trim().split(/\s+/)[0].toLowerCase();
      let body = null;
      if (typeof hljs !== 'undefined' && lang && hljs.getLanguage(lang)) {
        try { body = hljs.highlight(code, {language: lang, ignoreIllegals: true}).value; } catch (e) {}
      }
      if (body === null) body = escHtml(code);
      return '<pre><code class="hljs' + (lang ? ' language-' + escAttr(lang) : '') + '">' + body + '</code></pre>\n';
    },
  };
}
function renderMd(md, base) {
  const m = new marked.Marked({gfm: true});
  m.use({renderer: mdRenderer(base)});
  return m.parse(md);
}
// END markdown-sanitize
async function renderMarkdown(src, host, tools) {
  const r = await getText(src.content);
  truncNotice(r);
  const art = el('article', 'md');
  art.innerHTML = renderMd(r.text, src.base);
  let source = null;
  tools.appendChild(toggle('Source', false, v => {
    if (!source) source = codeBlock(r.text, 'markdown', null);
    host.replaceChildren(v ? source : art);
  }));
  host.appendChild(art);
}

// ---- csv / tsv ----------------------------------------------------------------
async function renderTable(src, host, tools) {
  const d = await getJSON(withQ(src.table, 'd=' + (src.mode === 'tsv' ? 'tab' : 'auto')));
  if (d.error) notice('The parser stopped early (' + d.error + '); showing the rows before that.', 'warn');
  else if (d.truncated) notice('Showing the first ' + d.rows.length.toLocaleString() +
    ' rows: the viewer stops at ' + d.maxRows.toLocaleString() + '. Download the file for all of it.', 'warn');
  const header = d.header, all = d.rows.map((r, i) => ({i: i + 1, r: r}));
  const ncol = Math.max(header.length, ...d.rows.slice(0, 200).map(r => r.length), 0);
  const num = [];
  for (let c = 0; c < ncol; c++) {
    let n = 0, t = 0;
    for (const o of all.slice(0, 500)) { const v = (o.r[c] || '').trim(); if (v) { t++; if (isFinite(Number(v.replace(/,/g, '')))) n++; } }
    num.push(t > 0 && n / t >= 0.8);
  }
  const filter = el('input', 'p-input');
  filter.type = 'search'; filter.placeholder = 'Filter rows'; filter.setAttribute('aria-label', 'Filter rows');
  const count = el('span', 'meta');
  tools.append(filter, count);
  const wrap = el('div', 'tablewrap'), table = el('table', 'grid');
  const thead = el('thead'), tbody = el('tbody'), hr = el('tr');
  hr.appendChild(el('th', 'rn', '#'));
  let sortCol = -1, dir = 1, limit = DOM_ROWS, list = all;
  const ths = [];
  for (let c = 0; c < ncol; c++) {
    const th = el('th'), b = el('button', null, header[c] || ('column ' + (c + 1)));
    b.type = 'button';
    b.addEventListener('click', () => { if (sortCol === c) dir = -dir; else { sortCol = c; dir = 1; } apply(); });
    th.appendChild(b); hr.appendChild(th); ths.push(th);
  }
  thead.appendChild(hr); table.append(thead, tbody); wrap.appendChild(table);
  const more = btn('Show more rows', () => { limit += DOM_ROWS; draw(); }, 'p-btn--ghost more');
  host.append(wrap, more);
  const val = (o, c) => o.r[c] || '';
  function apply() {
    const q = filter.value.trim().toLowerCase();
    list = q ? all.filter(o => o.r.some(v => v.toLowerCase().indexOf(q) >= 0)) : all.slice();
    if (sortCol >= 0) {
      const c = sortCol, isNum = num[c];
      list.sort((a, b) => {
        if (isNum) {
          const x = parseFloat(val(a, c).replace(/,/g, '')), y = parseFloat(val(b, c).replace(/,/g, ''));
          if (isNaN(x) || isNaN(y)) return isNaN(x) - isNaN(y);
          return (x - y) * dir;
        }
        return val(a, c).localeCompare(val(b, c), undefined, {numeric: true}) * dir;
      });
    }
    ths.forEach((th, i) => th.setAttribute('aria-sort', i === sortCol ? (dir > 0 ? 'ascending' : 'descending') : 'none'));
    limit = DOM_ROWS;
    draw();
  }
  function draw() {
    const frag = document.createDocumentFragment();
    for (const o of list.slice(0, limit)) {
      const tr = el('tr');
      tr.appendChild(el('td', 'rn', String(o.i)));
      for (let c = 0; c < ncol; c++) {
        const td = el('td', num[c] ? 'num' : null, val(o, c));
        if (val(o, c).length > 40) td.title = val(o, c);
        tr.appendChild(td);
      }
      frag.appendChild(tr);
    }
    tbody.replaceChildren(frag);
    count.textContent = (list.length === all.length ? '' : list.length.toLocaleString() + ' of ') +
      all.length.toLocaleString() + ' rows · ' + ncol + ' columns';
    more.hidden = list.length <= limit;
  }
  let t = null;
  filter.addEventListener('input', () => { clearTimeout(t); t = setTimeout(apply, 150); });
  apply();
}

// ---- json -------------------------------------------------------------------
function jsonPrim(v) {
  if (typeof v === 'string') return el('span', 'js', JSON.stringify(v));
  if (typeof v === 'number') return el('span', 'jn', String(v));
  if (typeof v === 'boolean') return el('span', 'jb', String(v));
  return el('span', 'jz', 'null');
}
function jsonKey(parent, key, isIndex) {
  if (key === null) return;
  parent.append(el('span', isIndex ? 'ki' : 'k', isIndex ? key : JSON.stringify(key)), el('span', 'pu', ': '));
}
function jsonNode(key, v, depth, isIndex) {
  if (v === null || typeof v !== 'object') {
    const row = el('div', 'jrow');
    jsonKey(row, key, isIndex);
    row.appendChild(jsonPrim(v));
    return row;
  }
  const arr = Array.isArray(v), keys = arr ? null : Object.keys(v), n = arr ? v.length : keys.length;
  const d = el('details'), s = el('summary');
  jsonKey(s, key, isIndex);
  s.appendChild(el('span', 'prev', (arr ? '[ ' : '{ ') + n + (arr ? ' ]' : ' }')));
  d.appendChild(s);
  let built = false;
  const build = () => {
    if (built) return;
    built = true;
    const kids = el('div', 'jkids'), lim = Math.min(n, JSON_KIDS);
    for (let i = 0; i < lim; i++) kids.appendChild(arr ? jsonNode(String(i), v[i], depth + 1, true)
      : jsonNode(keys[i], v[keys[i]], depth + 1, false));
    if (n > lim) kids.appendChild(el('div', 'jmore', '… ' + (n - lim).toLocaleString() + ' more not shown (see Raw)'));
    d.appendChild(kids);
  };
  d.addEventListener('toggle', () => { if (d.open) build(); });
  if (depth < 2 && n <= 200) { build(); d.open = true; }
  return d;
}
async function renderJson(src, host, tools) {
  let r;
  try { r = await getText(withQ(src.content, 'as=json')); }
  catch (e) {
    if (e.status === 413) { notice(e.message, 'warn'); return renderOther(src, host, tools, true); }
    throw e;
  }
  let v;
  try { v = JSON.parse(r.text); }
  catch (e) {
    notice('This is not valid JSON (' + e.message + '); showing it as text.', 'warn');
    return host.appendChild(codeBlock(r.text, 'json', tools));
  }
  const tree = el('div', 'tree');
  tree.appendChild(jsonNode(null, v, 0, false));
  let raw = null;
  const rawTools = el('span', 'tools');
  tools.append(toggle('Raw', false, on => {
    if (on && !raw) { raw = codeBlock(JSON.stringify(v, null, 2), 'json', rawTools); }
    host.replaceChildren(on ? raw : tree);
    rawTools.hidden = !on;
  }), btn('Collapse all', () => tree.querySelectorAll('details[open]').forEach(d => { d.open = false; })), rawTools);
  rawTools.hidden = true;
  host.appendChild(tree);
}

// ---- diff -------------------------------------------------------------------
function td(cls, text) { return el('td', cls, text == null ? '' : String(text)); }
function hunkRow(text, span) { const tr = el('tr', 'hunk'), c = td(null, text); c.colSpan = span; tr.appendChild(c); return tr; }
// table-layout:fixed takes column widths from a <colgroup> (the first row is
// a full-width hunk header, which would otherwise decide them).
function cols(t, spec) {
  const g = el('colgroup');
  for (const c of spec) g.appendChild(el('col', c || null));
  t.appendChild(g);
}
function unifiedTable(f) {
  const t = el('table', 'dtable'), body = el('tbody');
  cols(t, ['no', 'no', '']);
  for (const h of f.hunks) {
    body.appendChild(hunkRow(h.h, 3));
    for (const ln of h.lines) {
      const tr = el('tr', ln[0] === '\\' ? 'meta' : null);
      const k = ln[0] === '+' ? 'a' : ln[0] === '-' ? 'd' : null;
      tr.append(td('no' + (k ? ' ' + k : ''), ln[1]), td('no' + (k ? ' ' + k : ''), ln[2]),
        td(k, (ln[0] === '\\' ? '' : ln[0]) + ln[3]));
      body.appendChild(tr);
    }
  }
  t.appendChild(body);
  return t;
}
function splitTable(f) {
  const t = el('table', 'dtable'), body = el('tbody');
  cols(t, ['no', '', 'no', '']);
  const row = (l, r) => {
    const tr = el('tr');
    const lk = !l ? 'e' : l[0] === '-' ? 'd' : null, rk = !r ? 'e' : r[0] === '+' ? 'a' : null;
    tr.append(td('no' + (lk ? ' ' + lk : ''), l ? l[1] : ''), td(lk, l ? l[3] : ''),
      td('no' + (rk ? ' ' + rk : ''), r ? r[2] : ''), td(rk, r ? r[3] : ''));
    body.appendChild(tr);
  };
  for (const h of f.hunks) {
    body.appendChild(hunkRow(h.h, 4));
    const L = h.lines;
    let i = 0;
    while (i < L.length) {
      const ln = L[i];
      if (ln[0] === ' ') { row(ln, ln); i++; continue; }
      if (ln[0] === '\\') { const tr = el('tr', 'meta'), c = td(null, ln[3]); c.colSpan = 4; tr.appendChild(c); body.appendChild(tr); i++; continue; }
      const dels = [], adds = [];
      while (i < L.length && L[i][0] === '-') dels.push(L[i++]);
      while (i < L.length && L[i][0] === '+') adds.push(L[i++]);
      for (let k = 0; k < Math.max(dels.length, adds.length); k++) row(dels[k], adds[k]);
    }
  }
  t.appendChild(body);
  return t;
}
async function renderDiff(src, host, tools) {
  const d = await getJSON(src.diff);
  if (!d.files.length) {
    notice('No file changes found in this diff; showing it as text.', 'warn');
    return renderCode(Object.assign({}, src, {lang: 'diff'}), host, tools);
  }
  if (d.truncated) notice('This diff is long; the viewer shows its first part. Download it for all of it.', 'warn');
  let adds = 0, dels = 0;
  d.files.forEach(f => { adds += f.adds; dels += f.dels; });
  const mq = window.matchMedia('(min-width: 900px)');
  let split = mq.matches;
  const sw = toggle('Split view', split, v => { split = v; draw(); });
  tools.append(el('span', 'meta', d.files.length + ' file' + (d.files.length === 1 ? '' : 's') +
    ' · +' + adds + ' −' + dels), sw);
  mq.addEventListener('change', () => { split = mq.matches; sw.setAttribute('aria-pressed', String(split)); draw(); });
  const box = el('div', 'dfiles');
  if (d.preamble && d.preamble.trim()) host.appendChild(el('pre', 'preamble', d.preamble.trim()));
  host.appendChild(box);
  function draw() {
    box.replaceChildren();
    for (const f of d.files) {
      const sec = el('section', 'dfile'), head = el('div', 'dhead');
      const path = f.status === 'renamed' ? f.old + ' → ' + f.new : (f.new || f.old || '(unnamed)');
      head.append(el('span', 'path', path));
      if (f.status !== 'modified') head.appendChild(el('span', 'p-badge' + (f.status === 'added' ? ' p-badge--ok' : f.status === 'deleted' ? ' p-badge--danger' : ''), f.status));
      head.append(el('span', 'add', '+' + f.adds), el('span', 'del', '−' + f.dels));
      sec.appendChild(head);
      if (f.hunks.length) { const sc = el('div', 'dscroll'); sc.appendChild(split ? splitTable(f) : unifiedTable(f)); sec.appendChild(sc); }
      else sec.appendChild(el('div', 'dnote', f.meta.join('\n') || 'no content changes'));
      box.appendChild(sec);
    }
  }
  draw();
}

// ---- pdf --------------------------------------------------------------------
function pdfLib() {
  if (window.porchPdf) return Promise.resolve(window.porchPdf);
  return new Promise((ok, fail) => {
    window.addEventListener('porch-pdf', () => ok(window.porchPdf), {once: true});
    setTimeout(() => fail(new Error('the PDF viewer did not load')), 20000);
  });
}
async function renderPdf(src, host, tools) {
  const lib = await pdfLib();
  const doc = await lib.getDocument({url: src.file, isEvalSupported: false, enableXfa: false,
    withCredentials: true, cMapPacked: true,
    cMapUrl: new URL('/static/pdfjs/cmaps/', location.href).href,
    standardFontDataUrl: new URL('/static/pdfjs/standard_fonts/', location.href).href}).promise;
  let page = 1, scale = 'fit', task = null;
  const stage = el('div', 'pdfstage'), canvas = el('canvas');
  stage.appendChild(canvas);
  host.appendChild(stage);
  const label = el('span', 'meta'), zoomLabel = el('span', 'meta');
  const prev = btn('Prev', () => go(page - 1)), next = btn('Next', () => go(page + 1));
  const fit = toggle('Fit width', true, v => { scale = v ? 'fit' : cur; draw(); });
  let cur = 1;
  const zoom = f => { cur = Math.min(5, Math.max(0.25, cur * f)); scale = cur; fit.setAttribute('aria-pressed', 'false'); draw(); };
  tools.append(prev, label, next, btn('−', () => zoom(1 / 1.25)), zoomLabel, btn('+', () => zoom(1.25)), fit);
  function go(p) { if (p >= 1 && p <= doc.numPages && p !== page) { page = p; draw(); stage.scrollTop = 0; } }
  async function draw() {
    if (task) { try { task.cancel(); } catch (e) {} }
    const p = await doc.getPage(page);
    const base = p.getViewport({scale: 1});
    const s = scale === 'fit' ? Math.max(0.25, (stage.clientWidth - 50) / base.width) : scale;
    cur = s;
    const dpr = window.devicePixelRatio || 1;
    const vp = p.getViewport({scale: s * dpr});
    canvas.width = Math.floor(vp.width);
    canvas.height = Math.floor(vp.height);
    canvas.style.width = Math.floor(vp.width / dpr) + 'px';
    canvas.style.height = Math.floor(vp.height / dpr) + 'px';
    label.textContent = 'Page ' + page + ' / ' + doc.numPages;
    zoomLabel.textContent = Math.round(s * 100) + '%';
    prev.disabled = page <= 1; next.disabled = page >= doc.numPages;
    task = p.render({canvas: canvas, viewport: vp});
    try { await task.promise; } catch (e) { if (!e || e.name !== 'RenderingCancelledException') throw e; }
  }
  document.addEventListener('keydown', e => {
    if (e.target.closest && e.target.closest('input,textarea') || !host.isConnected) return;
    if (e.key === 'ArrowRight' || e.key === 'PageDown') go(page + 1);
    if (e.key === 'ArrowLeft' || e.key === 'PageUp') go(page - 1);
  });
  let rt = null;
  window.addEventListener('resize', () => { if (scale === 'fit') { clearTimeout(rt); rt = setTimeout(draw, 150); } });
  await draw();
}

// ---- image / media / other --------------------------------------------------------
function renderImage(src, host) {
  const st = el('div', 'stage'), img = el('img');
  img.src = src.file; img.alt = src.name;
  st.appendChild(img); host.appendChild(st);
}
function renderMedia(src, host) {
  const st = el('div', 'stage'), m = el(src.mode === 'audio' ? 'audio' : 'video');
  m.controls = true; m.preload = 'metadata'; m.src = src.file;
  if (src.mode === 'video') m.playsInline = true;
  st.appendChild(m); host.appendChild(st);
}
function renderOther(src, host, tools, quiet) {
  const card = el('div', 'p-card p-empty');
  card.append(el('div', 'p-empty-title', quiet ? 'Too big to preview' : 'No preview for this file'),
    el('p', 'p-empty-text', (src.mime && src.mime !== 'text/plain' ? src.mime + ' · ' : '') + fmtSize(src.size || 0)),
    linkBtn('Download ' + src.name.split('/').pop(), src.dl, 'p-btn--lg'));
  host.appendChild(card);
}

const RENDER = {markdown: renderMarkdown, code: renderCode, text: renderCode, json: renderJson,
  csv: renderTable, tsv: renderTable, diff: renderDiff, pdf: renderPdf, image: renderImage,
  video: renderMedia, audio: renderMedia, other: renderOther};

async function showSource(src, host, tools) {
  host.replaceChildren(); tools.replaceChildren(); notice('');
  try { await (RENDER[src.mode] || renderOther)(src, host, tools); }
  catch (e) {
    notice('Could not show this file: ' + (e && e.message || e), 'error');
    host.replaceChildren(); tools.replaceChildren();
    renderOther(src, host, tools);
  }
}
function mainSource() {
  return {name: CFG.file, mode: CFG.mode, lang: CFG.lang, size: CFG.size, mime: CFG.mime,
    content: '/content', table: '/table', diff: '/diff', file: '/file', dl: '/raw', base: location.href};
}

// ---- zip --------------------------------------------------------------------
function entryPath(name) { return '/zip/e/' + name.split('/').map(encodeURIComponent).join('/'); }
function entrySource(m) {
  const q = '?e=' + encodeURIComponent(m.name), p = entryPath(m.name);
  return {name: m.name, mode: m.mode, lang: m.lang, size: m.size, mime: m.mime,
    content: '/content' + q, table: '/table' + q, diff: '/diff' + q, file: p, dl: p + '?dl=1',
    base: new URL(p, location.href).href};
}
async function renderZip() {
  const d = await getJSON('/zip/list');
  const index = new Map();
  const root = {dirs: new Map(), files: []}, unsafe = [];
  let nfiles = 0, total = 0;
  for (const e of d.entries) {
    if (e.unsafe) { unsafe.push(e); continue; }
    if (e.dir) continue;
    index.set(e.name, e); nfiles++; total += e.size;
    const parts = e.name.split('/').filter(Boolean);
    let node = root;
    for (const p of parts.slice(0, -1)) {
      if (!node.dirs.has(p)) node.dirs.set(p, {dirs: new Map(), files: []});
      node = node.dirs.get(p);
    }
    node.files.push([parts[parts.length - 1] || e.name, e]);
  }
  const listHost = el('div'), entryHost = el('div', 'zentry');
  entryHost.hidden = true;
  view.append(listHost, entryHost);
  const listTools = el('span', 'tools');
  listTools.append(el('span', 'meta', nfiles.toLocaleString() + ' files · ' + fmtSize(total) + ' unpacked'));
  toolsEl.appendChild(listTools);
  const listNotice = d.truncated ? 'This archive has ' + d.total.toLocaleString() + ' entries; the viewer lists the first ' +
    d.maxEntries.toLocaleString() + '.' : '';
  notice(listNotice, 'warn');
  function count(node) { let n = node.files.length; node.dirs.forEach(c => { n += count(c); }); return n; }
  function drawNode(node, into, depth) {
    [...node.dirs.keys()].sort((a, b) => a.localeCompare(b)).forEach(name => {
      const child = node.dirs.get(name), det = el('details', 'zdir'), sum = el('summary');
      sum.append(el('span', null, name + '/'), el('span', 'zcount', String(count(child))));
      det.appendChild(sum);
      const kids = el('div', 'zkids');
      det.appendChild(kids);
      let drawn = false;
      det.addEventListener('toggle', () => { if (det.open && !drawn) { drawn = true; drawNode(child, kids, depth + 1); } });
      if (depth < 1) { drawn = true; drawNode(child, kids, depth + 1); det.open = true; }
      into.appendChild(det);
    });
    node.files.sort((a, b) => a[0].localeCompare(b[0])).forEach(([label, e]) => {
      const viewable = !e.refused;
      const row = viewable ? el('a', 'zrow') : el('div', 'zrow');
      if (viewable) row.href = '#e=' + encodeURIComponent(e.name);
      else row.setAttribute('aria-disabled', 'true');
      row.appendChild(el('span', 'zn', label));
      if (e.refused) row.appendChild(el('span', 'p-badge p-badge--danger', e.refused));
      row.appendChild(el('span', 'sz', fmtSize(e.size)));
      into.appendChild(row);
    });
  }
  const tree = el('div', 'ztree');
  drawNode(root, tree, 0);
  if (!nfiles) tree.appendChild(el('div', 'p-empty', 'This archive has no files.'));
  listHost.appendChild(tree);
  if (unsafe.length) {
    const box = el('div', 'p-card p-card--tight unsafe');
    box.appendChild(el('div', 'p-section-label', 'Not served: ' + unsafe.length + ' unsafe name' + (unsafe.length === 1 ? '' : 's')));
    unsafe.slice(0, 200).forEach(e => box.appendChild(el('div', 'meta', e.name)));
    listHost.appendChild(box);
  }
  async function route() {
    const m = /^#e=(.*)$/.exec(location.hash);
    const name = m ? decodeURIComponent(m[1]) : null;
    const e = name !== null ? index.get(name) : null;
    if (!e || e.refused) {
      entryHost.hidden = true; listHost.hidden = false; listTools.hidden = false;
      entryHost.replaceChildren(); notice(listNotice, 'warn');
      return;
    }
    let meta;
    try { meta = await getJSON('/zip/meta?e=' + encodeURIComponent(name)); }
    catch (err) { notice(name + ': ' + err.message, 'error'); return; }
    if (ZIP_VIEWABLE.indexOf(meta.mode) < 0) {
      location.href = entrySource(meta).dl;
      history.replaceState(null, '', location.pathname);
      return;
    }
    listHost.hidden = true; listTools.hidden = true; entryHost.hidden = false;
    const head = el('div', 'zhead'), etools = el('div', 'tools'), body = el('div');
    const src = entrySource(meta);
    head.append(linkBtn('← Archive', '#'), el('span', 'zname', name), linkBtn('Download entry', src.dl));
    entryHost.replaceChildren(head, etools, body);
    await showSource(src, body, etools);
  }
  window.addEventListener('hashchange', route);
  route();
}
const ZIP_VIEWABLE = CFG.zipViewable || [];

// ---- tail -------------------------------------------------------------------
// SGR (colour) sequences -> classes; nothing ever becomes a style attribute.
function sgrParse(s) {
  const out = [], st = {b: 0, d: 0, i: 0, u: 0, fg: null, bg: null};
  const re = /\x1b\[([0-9;]*)m/g;
  let last = 0, m;
  const cls = () => [st.b && 'a-b', st.d && 'a-d', st.i && 'a-i', st.u && 'a-u',
    st.fg && 'a-' + st.fg, st.bg && 'a-' + st.bg].filter(Boolean).join(' ');
  while ((m = re.exec(s))) {
    if (m.index > last) out.push([cls(), s.slice(last, m.index)]);
    last = re.lastIndex;
    const codes = m[1] === '' ? [0] : m[1].split(';').map(Number);
    for (let k = 0; k < codes.length; k++) {
      const c = codes[k];
      if (c === 0) { st.b = st.d = st.i = st.u = 0; st.fg = st.bg = null; }
      else if (c === 1) st.b = 1; else if (c === 2) st.d = 1; else if (c === 3) st.i = 1; else if (c === 4) st.u = 1;
      else if (c === 22) st.b = st.d = 0; else if (c === 23) st.i = 0; else if (c === 24) st.u = 0;
      else if ((c >= 30 && c <= 37) || (c >= 90 && c <= 97)) st.fg = c;
      else if (c === 39) st.fg = null;
      else if (c >= 40 && c <= 47) st.bg = c; else if (c >= 100 && c <= 107) st.bg = c - 60;
      else if (c === 49) st.bg = null;
      else if (c === 38 || c === 48) {
        // 256-colour: map the first 16 onto the basic classes, skip the rest.
        if (codes[k + 1] === 5) { const n = codes[k + 2]; k += 2;
          if (n >= 0 && n < 16) { const base = n < 8 ? 30 + n : 82 + n; if (c === 38) st.fg = base; else if (n < 8) st.bg = 40 + n; } }
        else if (codes[k + 1] === 2) k += 4;
      }
    }
  }
  if (last < s.length) out.push([cls(), s.slice(last)]);
  return out;
}
function renderTail() {
  const status = el('span', 'p-badge p-badge--dot p-badge--wait', 'connecting');
  const search = el('input', 'p-input');
  search.type = 'search'; search.placeholder = 'Search (Enter: next match)'; search.setAttribute('aria-label', 'Search the log');
  const hits = el('span', 'meta');
  let paused = false, stuck = true, pending = 0, query = '', hitIdx = -1;
  const log = el('div', 'log');
  log.setAttribute('role', 'log');
  const jump = btn('', () => { paused = false; pauseBtn.setAttribute('aria-pressed', 'false'); toBottom(); }, 'p-btn--quiet jump');
  jump.hidden = true;
  const pauseBtn = toggle('Pause', false, v => { paused = v; if (!v) toBottom(); });
  toolsEl.append(status, search, hits, pauseBtn, toggle('Wrap', false, v => log.classList.toggle('wrap', v)));
  view.append(log, jump);
  function paint(div) {
    div.replaceChildren();
    const hit = query && div._plain.toLowerCase().indexOf(query) >= 0;
    div.classList.toggle('hit', !!hit);
    for (const [c, t] of div._segs) {
      const into = c ? div.appendChild(el('span', c)) : div;
      if (!hit) { into.appendChild(document.createTextNode(t)); continue; }
      const low = t.toLowerCase();
      let i = 0, j;
      while ((j = low.indexOf(query, i)) >= 0) {
        if (j > i) into.appendChild(document.createTextNode(t.slice(i, j)));
        into.appendChild(el('mark', null, t.slice(j, j + query.length)));
        i = j + query.length;
      }
      if (i < t.length) into.appendChild(document.createTextNode(t.slice(i)));
    }
  }
  function lineEl(kind, text) {
    const div = el('div', kind === 'n' ? 'l note' : 'l');
    div._segs = kind === 'n' ? [['', '— ' + text + ' —']] : sgrParse(text);
    div._plain = div._segs.map(s => s[1]).join('');
    paint(div);
    return div;
  }
  function toBottom() { log.scrollTop = log.scrollHeight; pending = 0; jump.hidden = true; stuck = true; }
  function countHits() {
    if (!query) { hits.textContent = ''; return; }
    const n = log.querySelectorAll('.l.hit').length;
    hits.textContent = n.toLocaleString() + ' matching line' + (n === 1 ? '' : 's');
  }
  log.addEventListener('scroll', () => {
    stuck = log.scrollHeight - log.scrollTop - log.clientHeight < 40;
    if (stuck) { pending = 0; jump.hidden = true; }
  });
  let st = null;
  search.addEventListener('input', () => { clearTimeout(st); st = setTimeout(() => {
    query = search.value.trim().toLowerCase(); hitIdx = -1;
    for (const div of log.children) paint(div);
    countHits();
  }, 150); });
  search.addEventListener('keydown', e => {
    if (e.key !== 'Enter' || !query) return;
    const list = log.querySelectorAll('.l.hit');
    if (!list.length) return;
    log.querySelectorAll('.l.cur').forEach(x => x.classList.remove('cur'));
    hitIdx = (hitIdx + (e.shiftKey ? -1 : 1) + list.length) % list.length;
    list[hitIdx].classList.add('cur');
    paused = true; pauseBtn.setAttribute('aria-pressed', 'true');
    list[hitIdx].scrollIntoView({block: 'center'});
  });
  const es = new EventSource('/events');
  es.addEventListener('open', () => { status.textContent = 'live'; status.className = 'p-badge p-badge--dot p-badge--ok'; });
  es.addEventListener('error', () => { status.textContent = 'reconnecting'; status.className = 'p-badge p-badge--dot p-badge--wait'; });
  es.addEventListener('lines', ev => {
    let items;
    try { items = JSON.parse(ev.data); } catch (e) { return; }
    const frag = document.createDocumentFragment();
    for (const it of items) frag.appendChild(lineEl(it[0], it[1]));
    log.appendChild(frag);
    while (log.childElementCount > CFG.keep) log.firstElementChild.remove();
    if (query) countHits();
    if (!paused && stuck) toBottom();
    else { pending += items.length; jump.textContent = pending.toLocaleString() + ' new line' + (pending === 1 ? '' : 's') + ' ↓'; jump.hidden = false; }
  });
}

if (CFG.follow) renderTail();
else if (CFG.mode === 'zip') renderZip().catch(e => notice('Could not read this archive: ' + e.message, 'error'));
else showSource(mainSource(), view, toolsEl);
</script>
</body>
</html>"""


class ViewHandler(HardenedHandlerMixin, BaseHTTPRequestHandler):
    """Serves one file. Configure a subclass with make_handler()."""

    protocol_version = 'HTTP/1.1'

    file_path = None                 # str, resolved at startup
    name = ''
    mode = 'text'
    mime = 'text/plain'
    lang = ''
    follow = False
    follower = None
    sse_slots = None
    heartbeat = TAIL_HEARTBEAT
    max_text = MAX_TEXT_BYTES
    max_json = MAX_JSON_BYTES
    max_table_bytes = MAX_TABLE_BYTES
    max_table_rows = MAX_TABLE_ROWS
    max_diff = MAX_DIFF_BYTES
    zip_max_entries = ZIP_MAX_ENTRIES
    zip_max_entry_bytes = ZIP_MAX_ENTRY_BYTES
    zip_max_ratio = ZIP_MAX_RATIO
    zip_ratio_floor = ZIP_RATIO_FLOOR

    def log_message(self, format, *args):
        method = args[0] if args else ''
        if isinstance(method, str) and method.startswith(('GET', 'HEAD')):
            return
        sys.stderr.write(f"[viewserver] {self.address_string()} - {format % args}\n")

    # -- responses ---------------------------------------------------------

    def _send(self, status, body, ctype, csp=SANDBOX_CSP, headers=(), cache='no-store'):
        if isinstance(body, str):
            body = body.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', cache)
        if csp:
            self.send_header('Content-Security-Policy', csp)
        for k, v in headers:
            self.send_header(k, v)
        security_headers(self)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def _json(self, obj, status=200):
        self._send(status, json.dumps(obj, separators=(',', ':')), 'application/json; charset=utf-8')

    def _error(self, status, message):
        self._json({'error': message}, status)

    def _not_found(self):
        self._send(404, 'Not found\n', 'text/plain; charset=utf-8')

    # -- the shared file ---------------------------------------------------

    def _read(self, cap):
        """(first `cap` bytes, total size) of the shared file."""
        fh, st = _open_regular(self.file_path)
        with fh:
            return fh.read(cap), st.st_size

    def _limits(self):
        return {'max_bytes': self.zip_max_entry_bytes, 'max_ratio': self.zip_max_ratio,
                'ratio_floor': self.zip_ratio_floor}

    def _source(self, entry, cap):
        """(data, total, name) for the shared file or one zip entry."""
        if entry is None:
            data, total = self._read(cap)
            return data, total, os.path.basename(self.file_path)
        if self.mode != 'zip':
            raise EntryRefused(404, 'not an archive')
        info, data = read_zip_entry(self.file_path, entry, self.zip_max_entries, **self._limits())
        return data[:cap], len(data), entry

    def _filename(self, name):
        return sanitize_filename(os.path.basename(name)) or 'download'

    # -- routes ------------------------------------------------------------

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if serve_asset(self, head=self.command == 'HEAD'):
            return
        try:
            parts = urllib.parse.urlsplit(self.path)
            q = urllib.parse.parse_qs(parts.query, max_num_fields=8)
        except ValueError:
            return self._not_found()
        path = parts.path
        entry = q.get('e', [None])[0]
        try:
            if path == '/':
                return self._page()
            if path in STATIC_FILES:
                return self._static(path)
            if path == '/raw':
                return self._raw()
            if path == '/file':
                return self._inline()
            if path == '/content':
                return self._content(entry, q.get('as', [''])[0])
            if path == '/table':
                return self._table(entry, q.get('d', ['auto'])[0])
            if path == '/diff':
                return self._diff(entry)
            if path == '/zip/list' and self.mode == 'zip':
                return self._json(zip_listing(self.file_path, self.zip_max_entries, **self._limits()))
            if path == '/zip/meta' and self.mode == 'zip' and entry is not None:
                return self._zip_meta(entry)
            if path.startswith('/zip/e/') and self.mode == 'zip':
                return self._zip_entry(urllib.parse.unquote(path[len('/zip/e/'):]),
                                       q.get('dl', [''])[0] == '1')
            if path == '/events' and self.follower is not None:
                return self._events()
        except EntryRefused as e:
            return self._error(e.status, str(e))
        except (zipfile.BadZipFile, zipfile.LargeZipFile) as e:
            return self._error(422, f'not a readable zip: {e}')
        except OSError as e:
            if isinstance(e, (BrokenPipeError, ConnectionResetError)):
                raise
            return self._error(410, 'the shared file is gone or unreadable')
        return self._not_found()

    def _page(self):
        nonce = csp_nonce()
        try:
            size = os.lstat(self.file_path).st_size
        except OSError:
            size = 0
        fname = os.path.basename(self.file_path)
        mode = 'tail' if self.follow else self.mode
        cfg = {
            'mode': self.mode, 'file': fname, 'name': self.name, 'size': size,
            'mime': self.mime, 'lang': self.lang, 'follow': self.follow, 'keep': TAIL_KEEP,
            'zipViewable': sorted(ZIP_VIEWABLE),
        }
        # '<' is escaped so no value (a filename) can end the <script> block.
        cfg_json = json.dumps(cfg).replace('<', '\\u003c')
        needs = set()
        if mode in ('markdown', 'zip'):
            needs |= {'hljs', 'marked'}
        if mode in ('code', 'json', 'diff'):
            needs.add('hljs')
        if mode in ('pdf', 'zip'):
            needs.add('pdf')
        scripts = ''.join(s for k, s in (('hljs', SCRIPT_HLJS), ('marked', SCRIPT_MARKED))
                          if k in needs)
        if 'pdf' in needs:
            scripts += PDF_MODULE
        label = MODE_LABELS.get(mode, 'File')
        if mode == 'code' and self.lang:
            label += ' · ' + self.lang
        meta = f"following {fname} live" if self.follow else f"{human_size(size)} · read-only"
        fields = {
            '__PORCH_CSS__': porch_css_tag(),
            '__HEAD_EXTRA__': HLJS_CSS if 'hljs' in needs else '',
            '__MARK__': porch_mark(16),
            # Everything below comes from the command line / file name and is
            # escaped. One re.sub pass: nothing substituted is rescanned, so a
            # filename containing "__SCRIPTS__" stays text.
            '__TITLE__': html.escape(fname),
            '__KICKER__': html.escape(label),
            '__META__': html.escape(meta),
            '__CFG_JSON__': cfg_json,
            '__NONCE__': nonce,
        }
        # Blocks that themselves carry __NONCE__ go in first.
        page = PAGE_HTML.replace('__SCRIPTS__', scripts)
        page = re.sub(r'__(?:PORCH_CSS|HEAD_EXTRA|MARK|TITLE|KICKER|META|CFG_JSON|NONCE)__',
                      lambda m: fields[m.group(0)], page)
        workers = " worker-src 'self';" if 'pdf' in needs else ''
        csp = ("default-src 'none'; "
               f"script-src 'self' 'nonce-{nonce}'; {porch_style_src(nonce)}; "
               "img-src 'self' data: blob:; media-src 'self'; connect-src 'self';"
               f"{workers} form-action 'none'; base-uri 'none'; frame-ancestors 'none'")
        self._send(200, page, 'text/html; charset=utf-8', csp=csp)

    def _static(self, path):
        fname, ctype = STATIC_FILES[path]
        body = _static_cache.get(fname)
        if body is None:
            try:
                body = (VENDOR_DIR / fname).read_bytes()
            except OSError:
                return self._not_found()
            _static_cache[fname] = body
        self._send(200, body, ctype, csp=None, cache='public, max-age=86400')

    def _check_file(self):
        st = os.lstat(self.file_path)
        if not stat.S_ISREG(st.st_mode):
            raise OSError('not a regular file')
        return st

    def _stream(self, ctype, disposition):
        """stream_file() of the shared file as opened now with O_NOFOLLOW: it
        reads /proc/self/fd/N, the inode we checked, so a symlink swapped in
        between the check and the read is never followed."""
        fh, st = _open_regular(self.file_path)
        with fh:
            target = f'/proc/self/fd/{fh.fileno()}'
            if not os.path.exists(target):        # no procfs (macOS): lstat-checked path
                self._check_file()
                target = self.file_path
            # stream_file adds the sandbox CSP; nosniff via security_headers.
            stream_file(self, target, st.st_size, ctype, disposition,
                        self._filename(self.file_path), cache='no-store')

    def _raw(self):
        self._stream('application/octet-stream', 'attachment')

    def _inline(self):
        if self.mode not in ('image', 'video', 'audio', 'pdf'):
            return self._not_found()
        if self.mode == 'image' and self.mime not in SAFE_IMAGE_MIMES:
            return self._not_found()
        if not (self.mime.startswith(('image/', 'video/', 'audio/')) or self.mime == 'application/pdf'):
            return self._not_found()
        self._stream(self.mime, 'inline')

    def _content(self, entry, as_):
        is_json = as_ == 'json' or (entry is None and self.mode == 'json')
        cap = self.max_json if is_json else self.max_text
        data, total, _ = self._source(entry, cap)
        if is_json and total > cap:
            return self._error(413, f'This JSON is {human_size(total)}; the viewer opens up to '
                                    f'{human_size(cap)}. Download it instead.')
        text = decode_text(data)
        headers = [('X-Porch-Total', str(total))]
        if total > cap:
            headers.append(('X-Porch-Truncated', '1'))
        self._send(200, text, 'text/plain; charset=utf-8', headers=headers)

    def _table(self, entry, hint):
        data, total, _ = self._source(entry, self.max_table_bytes)
        if entry is None and self.mode == 'tsv' and hint == 'auto':
            hint = 'tab'
        out = parse_table(data, table_delimiter(data, hint), self.max_table_rows,
                          cut=total > len(data))
        self._json(out)

    def _diff(self, entry):
        data, total, _ = self._source(entry, self.max_diff)
        out = parse_diff(decode_text(data))
        out['truncated'] = out['truncated'] or total > len(data)
        self._json(out)

    def _zip_meta(self, entry):
        info, head = read_zip_entry(self.file_path, entry, self.zip_max_entries,
                                    head=SNIFF_BYTES + 1, **self._limits())
        s = sniff_bytes(head, entry, complete=len(head) <= SNIFF_BYTES)
        self._json({'name': entry, 'mode': s.mode, 'mime': s.mime, 'lang': s.lang,
                    'size': info.file_size})

    def _zip_entry(self, entry, download):
        info, data = read_zip_entry(self.file_path, entry, self.zip_max_entries, **self._limits())
        s = sniff_bytes(data[:SNIFF_BYTES], entry, complete=len(data) <= SNIFF_BYTES)
        if download:
            ctype, disp = 'application/octet-stream', 'attachment'
        elif s.mode == 'image' and s.mime in SAFE_IMAGE_MIMES:
            ctype, disp = s.mime, 'inline'
        elif s.mode == 'pdf':
            ctype, disp = 'application/pdf', 'inline'
        elif s.mode in TEXT_MODES:
            ctype, disp = 'text/plain; charset=utf-8', 'inline'
        else:
            ctype, disp = 'application/octet-stream', 'attachment'
        self._send(200, data, ctype, headers=[
            ('Content-Disposition', f'{disp}; filename="{self._filename(entry)}"')])

    def _events(self):
        f = self.follower
        if not self.sse_slots.acquire(blocking=False):
            return self._send(503, 'Too many live viewers; try again shortly.\n',
                              'text/plain; charset=utf-8', headers=[('Retry-After', '10')])
        try:
            self.close_connection = True
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Accel-Buffering', 'no')
            self.send_header('Connection', 'close')
            self.send_header('Content-Security-Policy', SANDBOX_CSP)
            security_headers(self)
            self.end_headers()
            if self.command == 'HEAD':
                return
            raw = (self.headers.get('Last-Event-ID') or '').strip()
            sent = int(raw) if raw.isdigit() and len(raw) <= 15 else 0
            if sent > f.seq:
                sent = 0                     # we restarted: send the backlog again
            self.wfile.write(b'retry: 3000\n\n')
            while not f.stopped:
                items, skipped = f.since(sent, TAIL_BATCH)
                if skipped:
                    items = [(items[0][0] if items else sent, 'n',
                              f'{skipped} lines were skipped (this viewer fell behind)')] + items
                if items:
                    sent = items[-1][0]
                    data = json.dumps([[k, t] for _, k, t in items], separators=(',', ':'))
                    self.wfile.write(f'id: {sent}\nevent: lines\ndata: {data}\n\n'.encode('utf-8'))
                    continue
                if not f.wait(sent, self.heartbeat):
                    self.wfile.write(b': ping\n\n')
        except (BrokenPipeError, ConnectionResetError, socket.timeout, OSError):
            pass
        finally:
            self.sse_slots.release()


def make_handler(path, name='view', mode=None, follow=False, start_follower=True, **attrs):
    """A ViewHandler subclass for one file. `mode` overrides the sniffed one
    (one of MODES); attrs override limits (tests use small ones)."""
    real = os.path.realpath(path)
    st = os.stat(real)
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f'not a regular file: {path}')
    s = sniff_file(real)
    use_mode = mode or s.mode
    lang = s.lang
    if mode and mode != s.mode:
        lang = LANG_BY_EXT.get(_ext(real), '') if mode in ('code', 'text') else ''
    cls = type('BoundViewHandler', (ViewHandler,), dict({
        'file_path': real, 'name': name, 'mode': use_mode, 'mime': s.mime, 'lang': lang,
        'follow': bool(follow),
        'sse_slots': threading.BoundedSemaphore(attrs.pop('max_clients', TAIL_MAX_CLIENTS)),
    }, **attrs))
    if follow and start_follower:
        cls.follower = Follower(real).start()
    return cls


def main(argv=None):
    p = argparse.ArgumentParser(description='Read-only viewer for one file')
    p.add_argument('--port', type=int, required=True)
    p.add_argument('--file', required=True)
    p.add_argument('--name', default='view')
    p.add_argument('--as', dest='as_mode', choices=MODES)
    p.add_argument('--follow', action='store_true', help='live log view (SSE)')
    p.add_argument('--bind', default='127.0.0.1')
    p.add_argument('--max-connections', type=int, default=None)
    args = p.parse_args(argv)
    try:
        handler = make_handler(args.file, args.name, args.as_mode, args.follow)
    except (OSError, ValueError) as e:
        sys.stderr.write(f"[viewserver] {e}\n")
        return 2
    server = make_server(handler, args.port, args.bind, tag='viewserver',
                         max_connections=args.max_connections)
    what = 'following' if args.follow else f'viewing ({handler.mode})'
    sys.stderr.write(f"[viewserver] Listening on :{args.port}, {what} {handler.file_path}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
    return 0


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3

"""Music-collect / player server (used by bin/music).

Mirrors lib/photoserver.py: a tunnel-exposed collection with an ordered
sidecar (.order.json), add/delete/reorder, and a public listing. The
differences:

  * Audio files instead of images (no thumbnails, no PIL dependency).
  * GET /track/<name> supports HTTP Range requests so the browser <audio>
    element can seek.
  * GET /peaks/<name> serves a server-computed waveform + duration (ffmpeg,
    cached in .peaks/), so the page never downloads whole tracks to draw it.
  * The player page (GET /) is PUBLIC and play-only. The write endpoints
    (/upload, /delete, /reorder) require the owner's credential, checked by
    lib/porch_auth.py: the host-only porch_host cookie (or, during the
    migration, the legacy cush_auth cookie).
    Recipients of the bare share link can play & download but not mutate.

Security posture (this thing is exposed to the public internet by a tunnel):

  * Uploads stream to disk with the size cap enforced *during* the write. The
    old code did `body = self.rfile.read(Content-Length)` and checked
    afterwards, which made a 100MB allocation per request.
  * The stored name is generated here from a sanitized stem plus the
    extension; every lookup path re-resolves and containment-checks it.
  * Writes require the owner cookie *and* a same-origin Origin/Referer. The
    cookie alone is not enough: legacy cush_auth is scoped to .cush.rocks, so every
    other *.cush.rocks page — including a paste of someone else's text — is
    "same-site" and would otherwise carry the cookie on a cross-origin POST.
  * Tracks go out with nosniff and a lockdown CSP, so a file whose bytes are
    really HTML cannot execute on this origin.
  * Range headers are parsed defensively and clamped to the file size.
"""

import argparse
import array
from html import escape as html_escape
import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import porch_auth  # noqa: E402  (the one owner check: porch_host + legacy cush_auth)
import porch_config  # noqa: E402  (domain config, for the enrol link)
from porch_http import (  # noqa: E402  (shared HTTP core)
    DEFAULT_MAX_CONNECTIONS, DEFAULT_MIN_FREE_MB, HardenedHandlerMixin, JobGate,
    MultipartError, MultipartStreamer, Quota,
    UploadRejected, UploadSlots, client_ip, content_length, drop_tmp,
    fresh_against, human_size, install_sigterm_cleanup, limit_child,
    make_server, multipart_boundary, name_candidates, new_tmp, parse_range,
    place_unique, read_json_body, safe_child, safe_stem, same_origin,
    sanitize_filename, security_headers, stream_file, sweep_stale_parts,
    touch_marker, atomic_write_json,
    csp_nonce, porch_css_tag, porch_mark, porch_style_src, serve_asset,
)
from porch_http import BoundedThreadingHTTPServer  # noqa: E402,F401  (re-exported)


MAX_FILE_SIZE = 100 * 1024 * 1024
MAX_TOTAL_SIZE = 8 * 1024 * 1024 * 1024   # per-collection disk ceiling
MAX_TRACKS = 2000                          # per-collection file count ceiling
MAX_JSON_BODY = 1024 * 1024                # /delete + /reorder bodies are tiny

ALLOWED_EXTENSIONS = {
    '.mp3', '.wav', '.flac', '.m4a', '.aac', '.ogg', '.oga',
    '.opus', '.weba', '.aiff', '.aif', '.alac', '.wma',
}

EXT_MIME = {
    '.mp3': 'audio/mpeg',
    '.wav': 'audio/wav',
    '.flac': 'audio/flac',
    '.m4a': 'audio/mp4',
    '.aac': 'audio/aac',
    '.ogg': 'audio/ogg',
    '.oga': 'audio/ogg',
    '.opus': 'audio/ogg',
    '.weba': 'audio/webm',
    '.aiff': 'audio/aiff',
    '.aif': 'audio/aiff',
    '.alac': 'audio/mp4',
    '.wma': 'audio/x-ms-wma',
}

ORDER_FILE = '.order.json'

# Guards every read-modify-write of the order sidecar.
_order_lock = threading.Lock()

# Owner check: see is_owner_token() in the shared block above. The host is
# deliberately NOT in HAProxy's protected_apps, so the public can still load
# and play the page; only writes need the owner's cush_auth cookie.


SNIFF_BYTES = 64


def looks_like_markup(head):
    """True if the payload opens like SVG / HTML / XML.

    Audio never starts with '<'. Markup served from this origin would execute
    in a visitor's session, so it never gets stored no matter what extension it
    arrived under.
    """
    probe = head.lstrip(b'\xef\xbb\xbf \t\r\n')[:16].lower()
    return probe.startswith(b'<')


def sniff_audio(head):
    """Best-effort audio container from magic bytes; None if unrecognised.

    Used one way only: to *downgrade* a file whose bytes clearly aren't audio.
    An unrecognised head is not proof of anything (ALAC/WMA/odd MP3 framings
    exist), so it never rejects on its own.
    """
    if len(head) < 12:
        return None
    if head.startswith(b'ID3') or (head[0] == 0xFF and (head[1] & 0xE0) == 0xE0):
        return 'audio/mpeg'
    if head.startswith(b'fLaC'):
        return 'audio/flac'
    if head.startswith(b'OggS'):
        return 'audio/ogg'
    if head.startswith(b'RIFF') and head[8:12] == b'WAVE':
        return 'audio/wav'
    if head.startswith(b'FORM') and head[8:12] in (b'AIFF', b'AIFC'):
        return 'audio/aiff'
    if head[4:8] == b'ftyp':
        return 'audio/mp4'
    if head.startswith(b'\x1a\x45\xdf\xa3'):
        return 'audio/webm'
    if head.startswith(b'\x30\x26\xb2\x75'):     # ASF header GUID
        return 'audio/x-ms-wma'
    return None


def is_audio_name(name):
    return os.path.splitext(name)[1].lower() in ALLOWED_EXTENSIONS


def _disk_tracks(directory):
    """Audio files currently on disk (excludes sidecars, partials, symlinks)."""
    out = []
    try:
        entries = list(directory.iterdir())
    except OSError:
        return out
    for entry in entries:
        if entry.name.startswith('.') or entry.name.endswith('.part'):
            continue
        # is_file() follows symlinks; a link planted in the directory would be
        # listed even though _safe_target() refuses to serve it. Skip links
        # outright so the listing only ever names real files we own.
        if entry.is_symlink() or not entry.is_file():
            continue
        if is_audio_name(entry.name):
            if entry.name != sanitize_filename(entry.name):
                entry = _adopt_name(directory, entry)
                if entry is None:
                    continue
            out.append(entry)
    return out


def _adopt_name(directory, entry):
    """Rename a track dropped in out of band ('Golden Hour.mp3') to the
    sanitized name every route looks it up by ('Golden_Hour.mp3'), never
    over an existing file. None if that fails (the track stays unlisted)."""
    stem, ext = os.path.splitext(sanitize_filename(entry.name))
    for name in name_candidates(stem, ext):
        try:
            os.link(entry, directory / name)
        except FileExistsError:
            continue
        except OSError:
            return None
        try:
            os.unlink(entry)
        except OSError:
            pass
        return directory / name
    return None


def load_order(directory):
    """Read .order.json, reconcile against disk, return list of names.

    - Missing/corrupt sidecar => start empty.
    - Drop names whose file no longer exists.
    - Append any on-disk track not already listed, mtime ascending, so
      out-of-band additions self-heal at the end of the order.
    """
    order_path = directory / ORDER_FILE
    stored = []
    try:
        with open(order_path) as f:
            data = json.load(f)
        if isinstance(data, list):
            stored = [n for n in data if isinstance(n, str)]
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        stored = []

    on_disk = {e.name: e for e in _disk_tracks(directory)}

    reconciled = [n for n in stored if n in on_disk]
    seen = set(reconciled)
    extras = [e for n, e in on_disk.items() if n not in seen]
    extras.sort(key=lambda e: e.stat().st_mtime)
    reconciled.extend(e.name for e in extras)
    return reconciled


def save_order(directory, names):
    """Atomic write of the order sidecar (unique temp file + os.replace)."""
    atomic_write_json(directory / ORDER_FILE, names)


def collection_usage(directory):
    """(bytes, tracks) currently in the collection."""
    total = count = 0
    for entry in _disk_tracks(directory):
        try:
            total += entry.stat().st_size
            count += 1
        except OSError:
            pass
    return total, count


# ---- server-side waveform + duration ----------------------------------------
# The page used to download each whole track and decodeAudioData() it for the
# waveform, plus a hidden <audio> per row just to learn durations: on a phone
# that is the entire collection over cellular. Now ffmpeg decodes once, here,
# into 320 peaks + a duration, cached in .peaks/<name>.json; the page fetches
# a few hundred bytes of JSON. Without ffmpeg the page says "waveform n/a".

PEAKS_DIR = '.peaks'
PEAK_BUCKETS = 320
PEAK_RATE = 8000                    # Hz; plenty for a 320-bar overview
PEAK_MAX_SECONDS = 3 * 3600         # decode at most this much of a track
PEAK_WALL_SECONDS = 120
_ffmpeg_bin = shutil.which('ffmpeg')
_peaks_gate = JobGate(max_jobs=1)

# ffmpeg demuxer per sniffed container: forced, so a file is only ever parsed
# as what its magic bytes say it is.
AUDIO_DEMUXER = {
    'audio/mpeg': 'mp3',
    'audio/flac': 'flac',
    'audio/ogg': 'ogg',
    'audio/wav': 'wav',
    'audio/aiff': 'aiff',
    'audio/mp4': 'mov',
    'audio/webm': 'matroska',
    'audio/x-ms-wma': 'asf',
}


def peaks_paths(music_dir, name):
    d = music_dir / PEAKS_DIR
    return d / (name + '.json'), d / (name + '.fail')


def _decode_peaks(src, demuxer):
    """Run ffmpeg -> mono s16le PCM and reduce it to (peaks, duration)."""
    cmd = [
        _ffmpeg_bin, '-nostdin', '-hide_banner', '-loglevel', 'error',
        '-protocol_whitelist', 'file',
        '-f', demuxer, '-i', 'file:' + str(src),
        '-vn', '-sn', '-dn', '-threads', '1',
        '-t', str(PEAK_MAX_SECONDS),
        '-ac', '1', '-ar', str(PEAK_RATE), '-acodec', 'pcm_s16le', '-f', 's16le', 'pipe:1',
    ]
    proc = subprocess.Popen(cmd, shell=False, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            preexec_fn=limit_child)
    killer = threading.Timer(PEAK_WALL_SECONDS, proc.kill)
    killer.daemon = True
    killer.start()
    block = PEAK_RATE // 50                 # 20ms per block
    blocks = []
    pending = array.array('h')
    total = 0
    leftover = b''
    try:
        while True:
            data = proc.stdout.read(64 * 1024)
            if not data:
                break
            data = leftover + data
            cut = len(data) - (len(data) % 2)
            leftover = data[cut:]
            samples = array.array('h')
            samples.frombytes(data[:cut])
            if sys.byteorder == 'big':
                samples.byteswap()
            total += len(samples)
            pending.extend(samples)
            full = len(pending) - (len(pending) % block)
            for i in range(0, full, block):
                seg = pending[i:i + block]
                blocks.append(max(max(seg), -min(seg)))
            del pending[:full]
        if len(pending):
            blocks.append(max(max(pending), -min(pending)))
        rc = proc.wait(timeout=10)
    finally:
        killer.cancel()
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    if rc != 0 or total == 0:
        return None
    n = len(blocks)
    peaks = []
    for i in range(PEAK_BUCKETS):
        lo = i * n // PEAK_BUCKETS
        hi = max(lo + 1, (i + 1) * n // PEAK_BUCKETS)
        peaks.append(max(blocks[lo:hi]) if lo < n else 0)
    top = max(peaks) or 1
    return [round(p / top, 3) for p in peaks], round(total / PEAK_RATE, 2)


def compute_peaks(music_dir, name):
    """Return the cached {'peaks','duration'} for a track, computing it if needed.

    None when it can't be had (no ffmpeg, undecodable, unknown container);
    the failure is remembered until the track changes. JobGate.BUSY when
    another decode holds the only slot.
    """
    src = music_dir / name
    cache, fail = peaks_paths(music_dir, name)
    if fresh_against(cache, src):
        try:
            with open(cache) as f:
                return json.load(f)
        except (OSError, ValueError):
            pass
    if not _ffmpeg_bin or fresh_against(fail, src):
        return None

    def build():
        if fresh_against(cache, src):
            try:
                with open(cache) as f:
                    return json.load(f)
            except (OSError, ValueError):
                pass
        if fresh_against(fail, src):
            return None
        try:
            (music_dir / PEAKS_DIR).mkdir(exist_ok=True)
        except OSError:
            return None
        try:
            with open(src, 'rb') as f:
                demuxer = AUDIO_DEMUXER.get(sniff_audio(f.read(SNIFF_BYTES)))
        except OSError:
            demuxer = None
        result = None
        if demuxer:
            try:
                result = _decode_peaks(src, demuxer)
            except Exception as e:
                sys.stderr.write(f"[musicserver] waveform failed for {name}: {e}\n")
                result = None
        if not result:
            touch_marker(fail)
            return None
        out = {'peaks': result[0], 'duration': result[1]}
        tmp = cache.with_name(cache.name + '.' + secrets.token_hex(4) + '.part')
        try:
            with open(tmp, 'w') as f:
                json.dump(out, f)
            os.replace(tmp, cache)
        except OSError:
            try:
                tmp.unlink()
            except OSError:
                pass
        return out

    return _peaks_gate.run(name, build, wait=10)


def cached_duration(music_dir, name):
    cache, _ = peaks_paths(music_dir, name)
    if not fresh_against(cache, music_dir / name):
        return None
    try:
        with open(cache) as f:
            return json.load(f).get('duration')
    except (OSError, ValueError, AttributeError):
        return None


class PeaksWarmer:
    """One background thread that pre-computes waveforms (and so durations)
    for tracks the listing has seen without one. Strictly sequential and
    shares the decode slot, so it never competes with more than one job."""

    def __init__(self, music_dir):
        self.music_dir = music_dir
        self._lock = threading.Lock()
        self._queued = set()
        self._q = []
        self._cv = threading.Condition(self._lock)
        self._thread = None

    def want(self, name):
        if not _ffmpeg_bin:
            return
        with self._cv:
            if name in self._queued:
                return
            self._queued.add(name)
            self._q.append(name)
            if self._thread is None:
                self._thread = threading.Thread(target=self._run, name='peaks-warmer',
                                                daemon=True)
                self._thread.start()
            self._cv.notify()

    def _run(self):
        while True:
            with self._cv:
                while not self._q:
                    self._cv.wait()
                name = self._q.pop(0)
            try:
                if (self.music_dir / name).is_file():
                    compute_peaks(self.music_dir, name)
            except Exception:
                pass
            finally:
                with self._cv:
                    self._queued.discard(name)


PLAYER_HTML = r"""<!DOCTYPE html>
<html lang="en" data-app="music">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
__PORCH_CSS__
<style nonce="__NONCE__">
.p-shell{gap:16px;padding-bottom:40px}
/* ---- now playing card ---- */
.np{display:flex;flex-direction:column;gap:14px;padding:18px;border-radius:22px}
.np-top{display:flex;gap:14px;align-items:center}
.cover{width:84px;height:84px;flex:0 0 84px;border-radius:var(--r-xl);position:relative;overflow:hidden;background:var(--raised)}
.cover canvas{width:100%;height:100%;display:block}
.cover .play-glyph{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;
  font-size:22px;color:#fff;text-shadow:0 2px 8px rgba(0,0,0,.6);opacity:0;transition:opacity .2s}
.np-meta{flex:1;min-width:0;display:flex;flex-direction:column;gap:4px}
.np-title{font:500 20px/1.2 var(--font-display);letter-spacing:-.01em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.np-sub{color:var(--muted);font-size:13px}
/* waveform */
.wave-wrap{position:relative;cursor:pointer;height:56px}
.wave-wrap canvas{width:100%;height:56px;display:block}
.wave-load{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;
  color:var(--muted);font-size:12px;pointer-events:none}
.times{display:flex;justify-content:space-between;font:400 12px var(--font-mono);color:var(--muted);font-variant-numeric:tabular-nums}
/* transport */
.transport{display:flex;align-items:center;gap:24px;justify-content:center}
.tbtn{width:48px;height:48px;border-radius:50%;background:none;border:0;color:var(--text);cursor:pointer;
  display:flex;align-items:center;justify-content:center;-webkit-tap-highlight-color:transparent}
.tbtn:hover{background:var(--veil)}
.tbtn svg{width:24px;height:24px;fill:currentColor}
.tbtn.play{width:64px;height:64px;background:var(--accent);color:var(--on-accent)}
.tbtn.play:hover{background:var(--accent);filter:brightness(1.08)}
.tbtn.play svg{width:24px;height:24px}
.tbtn:disabled{opacity:.35;cursor:default}
/* ---- track list ---- */
.list-head{display:flex;justify-content:space-between;align-items:baseline;padding:8px 4px 0;font-size:13px;color:var(--muted)}
#list{display:flex;flex-direction:column;gap:2px}
.row{display:flex;align-items:center;gap:12px;padding:10px 12px;border-radius:var(--r-md);cursor:pointer;
  transition:background .15s;-webkit-tap-highlight-color:transparent;user-select:none}
/* touch-action:none only on the owner's drag grip: on the whole row it
   swallowed vertical swipes, so nobody could scroll the list on a phone. */
.grip{width:22px;flex:0 0 22px;align-self:stretch;display:flex;align-items:center;justify-content:center;
  color:var(--muted);cursor:grab;touch-action:none}
.grip svg{width:14px;height:14px;fill:currentColor}
.status-msg:empty{display:none}
.status-msg.err{background:var(--danger-soft);border-color:var(--danger-line)}
.status-msg.ok{background:var(--ok-soft);border-color:var(--ok-line)}
.row:hover{background:var(--veil)}
.row.active{background:var(--accent-soft)}
.row.active .row-title{font-weight:600}
.row.dragging{opacity:.4}
.row-cover{width:40px;height:40px;flex:0 0 40px;border-radius:var(--r-sm);overflow:hidden}
.row-cover canvas{width:100%;height:100%;display:block}
.row-num{width:22px;text-align:center;font:500 13px var(--font-mono);color:var(--muted);font-variant-numeric:tabular-nums}
.row.active .row-num,.row.playing .row-num{color:var(--accent-ink)}
.row-main{flex:1;min-width:0}
.row-title{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:15px}
.row-sub{color:var(--muted);font-size:12px;margin-top:1px}
.row-dur{font:400 13px var(--font-mono);color:var(--muted);font-variant-numeric:tabular-nums}
.row-actions{display:flex;gap:4px;align-items:center}
.icon-btn{background:none;border:0;color:var(--muted);cursor:pointer;width:36px;height:36px;border-radius:var(--r-sm);
  display:flex;align-items:center;justify-content:center}
.icon-btn:hover{color:var(--text);background:var(--veil)}
.icon-btn.del:hover{color:var(--danger);background:var(--danger-soft)}
.icon-btn svg{width:16px;height:16px;fill:currentColor}
.eq{display:inline-flex;gap:2px;align-items:flex-end;height:14px}
.eq span{width:3px;background:var(--accent);border-radius:1px;animation:eq .9s ease-in-out infinite}
.eq span:nth-child(2){animation-delay:.2s}
.eq span:nth-child(3){animation-delay:.4s}
@keyframes eq{0%,100%{height:4px}50%{height:14px}}
/* ---- dropzone (owner only) ---- */
.dropzone{padding:22px 16px;gap:12px;cursor:default}
.dz-hint{font-size:14px;color:var(--muted)}
.pbtn{position:relative}
.pbtn input{position:absolute;width:1px;height:1px;opacity:0;pointer-events:none}
.pbtn:focus-within{outline:2px solid var(--accent);outline-offset:2px}
.progress-wrap{display:none;width:100%;flex-direction:column;gap:8px;text-align:left}
.progress-wrap.active{display:flex}
.progress-text{font-size:13px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.error-msg{color:var(--danger);font-size:13px}
.error-msg:empty{display:none}
</style>
</head>
<body>
<main class="p-shell">
  <header class="p-head head">
    <div class="p-kicker">__MARK__<span id="kicker">music on a porch</span></div>
    <h1 class="p-title">__TITLE__</h1>
  </header>

  <div class="p-drop dropzone" id="dropzone" hidden>
    <div class="dz-hint">Drop tracks here, or</div>
    <label class="p-btn pbtn">Choose tracks
      <input type="file" id="fileInput" accept="audio/*,.flac,.m4a,.aac,.opus,.aiff,.wav" multiple>
    </label>
    <div class="progress-wrap" id="progressWrap">
      <div class="progress-text" id="progressText">0%</div>
      <div class="p-progress"><div class="p-progress-fill progress-fill" id="progressFill"></div></div>
    </div>
    <div class="error-msg" id="errorMsg"></div>
    <button type="button" class="p-btn p-btn--ghost p-btn--sm retry-btn" id="retryBtn" hidden>Retry failed uploads</button>
  </div>
  <p class="p-notice status-msg" id="statusMsg" role="status" aria-live="polite"></p>

  <section class="p-card np" aria-label="Now playing">
    <div class="np-top">
      <div class="cover" id="npCover"><canvas width="192" height="192"></canvas>
        <div class="play-glyph" id="npGlyph">&#9654;</div>
      </div>
      <div class="np-meta">
        <div class="np-title" id="npTitle">Nothing playing</div>
        <div class="np-sub" id="npSub">pick a track below</div>
      </div>
    </div>
    <div class="wave-wrap" id="waveWrap">
      <canvas id="wave" width="1200" height="112"></canvas>
      <div class="wave-load" id="waveLoad"></div>
    </div>
    <div class="times"><span id="curTime">0:00</span><span id="durTime">0:00</span></div>
    <div class="transport">
      <button class="tbtn" id="prevBtn" title="Previous" aria-label="Previous track" disabled>
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6h2v12H6zm3.5 6l8.5 6V6z"/></svg>
      </button>
      <button class="tbtn play" id="playBtn" title="Play" aria-label="Play" disabled>
        <svg viewBox="0 0 24 24" id="playIcon" aria-hidden="true"><path d="M8 5v14l11-7z"/></svg>
      </button>
      <button class="tbtn" id="nextBtn" title="Next" aria-label="Next track" disabled>
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M16 6h2v12h-2zm-2 6L5.5 6v12z"/></svg>
      </button>
    </div>
  </section>

  <div class="list-head">
    <span class="lbl">Tracks</span>
    <span class="lbl" id="trackCount">0</span>
  </div>
  <div id="list"></div>
  <div class="p-empty empty" id="empty" hidden>
    <div class="p-empty-title">No tracks yet</div>
    <div class="p-empty-text" id="emptyText">Nothing has been put on this porch yet.</div>
  </div>
  <footer class="p-foot">played through porch</footer>
</main>

<audio id="audio" preload="metadata"></audio>

<script nonce="__NONCE__">window.__ADMIN__ = __ADMIN_FLAG__; window.__maxFile = __MAXFILE__;</script>
<script nonce="__NONCE__">
const ALLOWED = new Set(['.mp3','.wav','.flac','.m4a','.aac','.ogg','.oga','.opus','.weba','.aiff','.aif','.alac','.wma']);
// Set server-side from the cush_auth cookie: true only for the owner's enrolled
// browser. Visitors see the play-only view; the server re-checks on every write.
const ADMIN = (window.__ADMIN__ === true);

const audio = document.getElementById('audio');
const list = document.getElementById('list');
const emptyEl = document.getElementById('empty');
const trackCount = document.getElementById('trackCount');
const npTitle = document.getElementById('npTitle');
const npSub = document.getElementById('npSub');
const npGlyph = document.getElementById('npGlyph');
const npCanvas = document.querySelector('#npCover canvas');
const playBtn = document.getElementById('playBtn');
const playIcon = document.getElementById('playIcon');
const prevBtn = document.getElementById('prevBtn');
const nextBtn = document.getElementById('nextBtn');
const curTimeEl = document.getElementById('curTime');
const durTimeEl = document.getElementById('durTime');
const waveCanvas = document.getElementById('wave');
const waveWrap = document.getElementById('waveWrap');
const waveLoad = document.getElementById('waveLoad');

let tracks = [];      // [{name,size,modified}]
let current = -1;     // index into tracks
const peaksCache = {};   // name -> Float32Array of peaks
const durCache = {};     // name -> seconds

const PLAY_SVG = '<path d="M8 5v14l11-7z"/>';
const PAUSE_SVG = '<path d="M6 5h4v14H6zm8 0h4v14h-4z"/>';

function getExt(name){const i=name.lastIndexOf('.');return i>0?name.slice(i).toLowerCase():'';}
function prettyTitle(name){
  let t = name.replace(/\.[^.]+$/,'');         // strip extension
  t = t.replace(/^\d+\s*[-_.)]\s*/,'');         // strip leading track number
  t = t.replace(/[_]+/g,' ').replace(/\s+/g,' ').trim();
  return t || name;
}
function fmtTime(s){
  if(!isFinite(s)||s<0) return '0:00';
  s=Math.floor(s); const m=Math.floor(s/60); const r=s%60;
  return m+':'+(r<10?'0':'')+r;
}

/* ---- generative cover art (hash filename -> gradient + bars) ---- */
function hashStr(s){let h=2166136261;for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,16777619);}return h>>>0;}
function drawCover(canvas, name){
  const h = hashStr(name);
  const ctx = canvas.getContext('2d');
  const w = canvas.width, ht = canvas.height;
  const hue1 = h % 360, hue2 = (hue1 + 60 + (h>>8)%120) % 360;
  const g = ctx.createLinearGradient(0,0,w,ht);
  g.addColorStop(0,`hsl(${hue1} 75% 55%)`);
  g.addColorStop(1,`hsl(${hue2} 70% 42%)`);
  ctx.fillStyle = g; ctx.fillRect(0,0,w,ht);
  // a few translucent bars for texture
  ctx.globalAlpha = 0.18;
  let r = h;
  for(let i=0;i<5;i++){
    r = (r*1103515245 + 12345) & 0x7fffffff;
    const bw = w*(0.12 + (r%30)/100);
    const bx = (r>>4) % w;
    ctx.fillStyle = (i%2) ? '#ffffff' : '#000000';
    ctx.fillRect(bx,0,bw,ht);
  }
  ctx.globalAlpha = 1;
}

/* ---- networking ---- */
const statusEl = document.getElementById('statusMsg');
let listFailing = false, lastSig = '';
function setStatus(text, kind){
  statusEl.textContent = text;            // textContent: names are untrusted
  statusEl.className = 'p-notice status-msg' + (kind ? ' '+kind : '');
  if(text) setTimeout(()=>{ if(statusEl.textContent===text){ statusEl.textContent=''; statusEl.className='p-notice status-msg'; } }, 6000);
}
function refresh(){
  return fetch('/list').then(r=>{ if(!r.ok) throw new Error('HTTP '+r.status); return r.json(); }).then(out=>{
    if(listFailing){ listFailing=false; setStatus('Back online'); }
    const next = Array.isArray(out)?out:[];
    for(const t of next){ if(typeof t.duration === 'number') durCache[t.name] = t.duration; }
    const sig = JSON.stringify(next.map(t=>[t.name,t.size,t.modified,t.duration||0]));
    if(sig === lastSig) return;           // nothing changed: leave the DOM alone
    lastSig = sig;
    const playingName = current>=0 && tracks[current] ? tracks[current].name : null;
    tracks = next;
    if(playingName){ current = tracks.findIndex(t=>t.name===playingName); }
    render();
  }).catch(e=>{
    // Shown once in the live region rather than silently swallowed.
    if(!listFailing){ listFailing=true; setStatus('Could not refresh the track list ('+e.message+') — retrying', 'err'); }
  });
}

function render(){
  list.innerHTML='';
  trackCount.textContent = tracks.length;
  emptyEl.hidden = tracks.length > 0;
  tracks.forEach((t, idx)=>{
    const row = document.createElement('div');
    row.className='row'+(idx===current?' active':'');
    if(idx===current && !audio.paused) row.classList.add('playing');
    row.dataset.name = t.name;

    let grip = null;
    if(ADMIN){
      grip = document.createElement('div');
      grip.className='grip'; grip.title='Drag to reorder';
      grip.setAttribute('aria-hidden','true');
      grip.innerHTML='<svg viewBox="0 0 24 24"><path d="M9 5h2v2H9zm4 0h2v2h-2zM9 11h2v2H9zm4 0h2v2h-2zM9 17h2v2H9zm4 0h2v2h-2z"/></svg>';
      grip.addEventListener('click', e=>e.stopPropagation());
    }

    const cov = document.createElement('div');
    cov.className='row-cover';
    const cc = document.createElement('canvas'); cc.width=84; cc.height=84;
    cov.appendChild(cc); drawCover(cc, t.name);

    const num = document.createElement('div');
    num.className='row-num';
    if(idx===current && !audio.paused){
      num.innerHTML='<span class="eq"><span></span><span></span><span></span></span>';
    }else{ num.textContent = idx+1; }

    const main = document.createElement('div');
    main.className='row-main';
    const ti = document.createElement('div'); ti.className='row-title'; ti.textContent=prettyTitle(t.name);
    const sub = document.createElement('div'); sub.className='row-sub'; sub.textContent=humanSize(t.size);
    main.appendChild(ti); main.appendChild(sub);

    const dur = document.createElement('div');
    dur.className='row-dur';
    // Durations come from the server (/list), computed once by ffmpeg; no
    // hidden <audio> per row fetching every track's headers any more.
    dur.textContent = durCache[t.name] ? fmtTime(durCache[t.name]) : '--:--';

    const actions = document.createElement('div');
    actions.className='row-actions';
    const dl = document.createElement('a');
    dl.href='/track/'+encodeURIComponent(t.name); dl.setAttribute('download', t.name);
    dl.className='icon-btn'; dl.title='Download';
    dl.innerHTML='<svg viewBox="0 0 24 24"><path d="M12 16l-5-5h3V4h4v7h3zM5 18h14v2H5z"/></svg>';
    dl.addEventListener('click', e=>e.stopPropagation());
    actions.appendChild(dur);
    actions.appendChild(dl);
    if(ADMIN){
      const del = document.createElement('button');
      del.className='icon-btn del'; del.title='Delete';
      del.innerHTML='<svg viewBox="0 0 24 24"><path d="M6 7h12l-1 13H7zM9 4h6l1 2H8z"/></svg>';
      del.addEventListener('click', e=>{e.stopPropagation(); del.disabled=true; deleteTrack(t.name);});
      actions.appendChild(del);
    }

    if(grip) row.appendChild(grip);
    row.appendChild(cov);
    row.appendChild(num);
    row.appendChild(main);
    row.appendChild(actions);
    // Everyone plays by tapping the row; only the owner's grip starts a drag.
    row.addEventListener('click',()=>{ const i=tracks.findIndex(x=>x.name===t.name); if(i>=0) play(i); });
    if(grip) attachDrag(grip, row);
    list.appendChild(row);
  });
}

function humanSize(n){
  const u=['B','KB','MB','GB']; let i=0; n=n||0;
  while(n>=1024&&i<u.length-1){n/=1024;i++;}
  return (i===0?n:n.toFixed(1))+' '+u[i];
}

function updateRowDur(name){
  const row = [...list.children].find(r=>r.dataset.name===name);
  if(row){ const d=row.querySelector('.row-dur'); if(d) d.textContent=fmtTime(durCache[name]); }
}

/* ---- playback ---- */
function play(idx){
  if(idx<0||idx>=tracks.length) return;
  const t = tracks[idx];
  if(idx!==current){
    current = idx;
    audio.src='/track/'+encodeURIComponent(t.name);
    npTitle.textContent = prettyTitle(t.name);
    npSub.textContent = humanSize(t.size);
    drawCover(npCanvas, t.name);
    loadWaveform(t.name);
  }
  audio.play().catch(()=>{});
}
function togglePlay(){
  if(current<0){ if(tracks.length) play(0); return; }
  if(audio.paused) audio.play().catch(()=>{}); else audio.pause();
}
playBtn.addEventListener('click', togglePlay);
prevBtn.addEventListener('click', ()=>{ if(current>0) play(current-1); else if(tracks.length) play(0); });
nextBtn.addEventListener('click', ()=>{ if(current<tracks.length-1) play(current+1); });
npGlyph.parentElement.addEventListener('click', togglePlay);

audio.addEventListener('play', ()=>{ playIcon.innerHTML=PAUSE_SVG; npGlyph.style.opacity='1'; npGlyph.innerHTML='&#10074;&#10074;'; syncRowStates(); });
audio.addEventListener('pause', ()=>{ playIcon.innerHTML=PLAY_SVG; npGlyph.innerHTML='&#9654;'; syncRowStates(); });
audio.addEventListener('ended', ()=>{ if(current<tracks.length-1) play(current+1); else { audio.currentTime=0; syncRowStates(); } });
audio.addEventListener('loadedmetadata', ()=>{ durTimeEl.textContent=fmtTime(audio.duration); if(current>=0&&tracks[current]){durCache[tracks[current].name]=audio.duration; updateRowDur(tracks[current].name);} });
audio.addEventListener('timeupdate', ()=>{ curTimeEl.textContent=fmtTime(audio.currentTime); drawWave(); });

function syncRowStates(){
  [...list.children].forEach((row,idx)=>{
    row.classList.toggle('active', idx===current);
    const playing = idx===current && !audio.paused;
    row.classList.toggle('playing', playing);
    const num=row.querySelector('.row-num');
    if(num){
      if(playing) num.innerHTML='<span class="eq"><span></span><span></span><span></span></span>';
      else num.textContent = idx+1;
    }
  });
}

/* ---- waveform: server-computed peaks (a few hundred bytes of JSON) ---- */
function loadWaveform(name, attempt){
  attempt = attempt || 0;
  const ctx = waveCanvas.getContext('2d');
  ctx.clearRect(0,0,waveCanvas.width,waveCanvas.height);
  if(peaksCache[name]){ waveLoad.textContent=''; drawWave(); return; }
  waveLoad.textContent='analyzing…';
  fetch('/peaks/'+encodeURIComponent(name)).then(r=>{
    if(r.status===503) throw new Error('busy');
    if(!r.ok) throw new Error('na');
    return r.json();
  }).then(j=>{
    if(!j || !Array.isArray(j.peaks)) throw new Error('na');
    peaksCache[name]=Float32Array.from(j.peaks);
    if(typeof j.duration==='number'){ durCache[name]=j.duration; updateRowDur(name); }
    if(current>=0 && tracks[current] && tracks[current].name===name){ waveLoad.textContent=''; drawWave(); }
  }).catch(e=>{
    const still = current>=0 && tracks[current] && tracks[current].name===name;
    if(e.message==='busy' && attempt<5 && still){ setTimeout(()=>loadWaveform(name, attempt+1), 3000); return; }
    if(still) waveLoad.textContent='waveform n/a';
  });
}
function drawWave(){
  const name = current>=0 ? tracks[current] && tracks[current].name : null;
  const peaks = name && peaksCache[name];
  const ctx = waveCanvas.getContext('2d');
  const W=waveCanvas.width, H=waveCanvas.height;
  ctx.clearRect(0,0,W,H);
  if(!peaks){ return; }
  const prog = audio.duration ? audio.currentTime/audio.duration : 0;
  const css = getComputedStyle(document.documentElement);
  const waveOn = css.getPropertyValue('--accent').trim() || '#F06A8A';
  const waveOff = css.getPropertyValue('--line-strong').trim() || 'rgba(255,240,220,.22)';
  const n = peaks.length;
  const bw = W/n;
  const gap = Math.max(1, bw*0.32);
  for(let i=0;i<n;i++){
    const h = Math.max(2, peaks[i]*H*0.92);
    const x = i*bw;
    const y = (H-h)/2;
    ctx.fillStyle = (i/n) <= prog ? waveOn : waveOff;
    ctx.fillRect(x, y, bw-gap, h);
  }
}
function seekFromEvent(e){
  if(current<0||!audio.duration) return;
  const rect = waveWrap.getBoundingClientRect();
  const x = (e.clientX!=null?e.clientX:e.touches[0].clientX) - rect.left;
  const frac = Math.min(1,Math.max(0,x/rect.width));
  audio.currentTime = frac*audio.duration;
  drawWave();
}
waveWrap.addEventListener('click', seekFromEvent);

/* enable transport once tracks exist */
function syncTransport(){
  const has = tracks.length>0;
  playBtn.disabled = !has;
  prevBtn.disabled = !(current>0);
  nextBtn.disabled = !(current>=0 && current<tracks.length-1);
}
const _origRender = render;

/* ---- admin: upload / delete / reorder ---- */
function showError(msg){const em=document.getElementById('errorMsg'); if(!em)return; em.textContent=msg; setTimeout(()=>{if(em.textContent===msg)em.textContent='';},5000);}

/* One request per track, in order, with per-file progress, errors and retry. */
const MAX_FILE = window.__maxFile;
const upQueue = [];
let upFailed = [];
let uploading = false, upTotal = 0, upIndex = 0, upOk = 0;
function upload(fileList){
  const em=document.getElementById('errorMsg'); if(em)em.textContent='';
  for(const f of fileList){
    const ext=getExt(f.name);
    if(!ALLOWED.has(ext)){ upFailed.push({file:f, error:'not an audio file', retry:false}); continue; }
    if(f.size>MAX_FILE){ upFailed.push({file:f, error:'larger than the '+humanSize(MAX_FILE)+' per-file limit', retry:false}); continue; }
    upQueue.push(f); upTotal++;
  }
  syncUpFailed();
  pumpUploads();
}
function sendTrack(f){
  const pf=document.getElementById('progressFill');
  const pt=document.getElementById('progressText');
  return new Promise(resolve=>{
    const fd=new FormData(); fd.append('file', f, f.name);
    const xhr=new XMLHttpRequest();
    xhr.upload.onprogress=function(e){ if(e.lengthComputable){const p=Math.round(e.loaded/e.total*100); pf.style.width=p+'%'; pt.textContent=(upTotal>1?upIndex+' of '+upTotal+' · ':'')+f.name+' · '+p+'%';} };
    xhr.onload=function(){
      let r=null; try{r=JSON.parse(xhr.responseText);}catch(e){}
      const saved = r && Array.isArray(r.files) ? r.files : [];
      if(xhr.status>=200 && xhr.status<300 && saved.length){ resolve({ok:true}); return; }
      const rej = r && Array.isArray(r.rejected) && r.rejected.length ? r.rejected[0].reason : null;
      resolve({ok:false, error: rej || (r&&(r.message||r.error)) || ('HTTP '+xhr.status),
               retry: xhr.status===0 || xhr.status===503 || xhr.status>=500});
    };
    xhr.onerror=function(){ resolve({ok:false, error:'network error', retry:true}); };
    xhr.open('POST','/upload');
    xhr.send(fd);
  });
}
function pumpUploads(){
  if(uploading) return;
  const pw=document.getElementById('progressWrap');
  const pf=document.getElementById('progressFill');
  const f=upQueue.shift();
  if(!f){
    pw.classList.remove('active');
    if(upTotal){ const bad=upTotal-upOk; setStatus(bad ? bad+' of '+upTotal+' upload(s) failed' : 'Added '+upOk+' track'+(upOk===1?'':'s'), bad?'err':''); }
    upTotal=upIndex=upOk=0;
    return;
  }
  uploading=true; upIndex++;
  pw.classList.add('active'); pf.style.width='0%';
  sendTrack(f).then(res=>{
    uploading=false;
    if(res.ok) upOk++; else upFailed.push({file:f, error:res.error, retry:res.retry!==false});
    syncUpFailed();
    refresh();
    pumpUploads();
  });
}
function syncUpFailed(){
  const btn=document.getElementById('retryBtn');
  if(btn) btn.hidden = !upFailed.some(x=>x.retry);
  if(upFailed.length){ const last=upFailed[upFailed.length-1]; showError(last.file.name+': '+last.error); }
}
function deleteTrack(name){
  fetch('/delete',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name})}).then(r=>r.json().then(j=>({ok:r.ok,j}))).then(({ok,j})=>{
      if(!ok){ showError((j&&j.message)||'Delete failed'); refresh(); return; }
      if(current>=0 && tracks[current] && tracks[current].name===name){ audio.pause(); audio.removeAttribute('src'); audio.load(); current=-1; npTitle.textContent='Nothing playing'; npSub.textContent='pick a track below'; }
      refresh();
    }).catch(()=>showError('Delete failed'));
}
function sendReorder(){
  const order=[...list.children].map(r=>r.dataset.name);
  const playingName = current>=0 && tracks[current] ? tracks[current].name : null;
  fetch('/reorder',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({order})}).then(r=>r.json()).then(()=>{
      return fetch('/list').then(r=>r.json());
    }).then(out=>{
      tracks=Array.isArray(out)?out:[];
      lastSig='';
      if(playingName){ const ni=tracks.findIndex(t=>t.name===playingName); if(ni>=0) current=ni; }
      render(); syncRowStates();
    }).catch(()=>{showError('Reorder failed');refresh();});
}

/* pointer drag reorder (owner), started from the row's grip only */
const DRAG_THRESHOLD=8;
function attachDrag(grip, row){ grip.addEventListener('pointerdown', e=>onDown(e, row)); }
let drag=null;
function onDown(e, row){
  if(e.button!==undefined && e.button!==0) return;
  const grip=e.currentTarget;
  drag={row,grip,startX:e.clientX,startY:e.clientY,moved:false,pointerId:e.pointerId};
  try{ grip.setPointerCapture(e.pointerId); }catch(_){}
  grip.addEventListener('pointermove',onMove);
  grip.addEventListener('pointerup',onUp);
  grip.addEventListener('pointercancel',onUp);
}
function onMove(e){
  if(!drag) return;
  const dx=e.clientX-drag.startX, dy=e.clientY-drag.startY;
  if(!drag.moved && Math.hypot(dx,dy)<DRAG_THRESHOLD) return;
  if(!drag.moved){ drag.moved=true; drag.row.classList.add('dragging'); }
  e.preventDefault();
  const target=rowUnder(e.clientX,e.clientY);
  if(target && target!==drag.row){
    const rows=[...list.querySelectorAll('.row')];
    const di=rows.indexOf(drag.row), ti=rows.indexOf(target);
    if(di<ti) list.insertBefore(drag.row, target.nextSibling);
    else list.insertBefore(drag.row, target);
  }
}
function rowUnder(x,y){const el=document.elementFromPoint(x,y);return el?el.closest('.row'):null;}
function onUp(e){
  if(!drag) return;
  const g=drag.grip;
  g.removeEventListener('pointermove',onMove);
  g.removeEventListener('pointerup',onUp);
  g.removeEventListener('pointercancel',onUp);
  try{g.releasePointerCapture(drag.pointerId);}catch(_){}
  const moved=drag.moved;
  if(moved){ drag.row.classList.remove('dragging'); }
  drag=null;
  if(moved) sendReorder();
}

/* wrap render to keep transport state in sync */
render = function(){ _origRender(); syncTransport(); };

/* ---- wiring ---- */
if(ADMIN){
  document.getElementById('dropzone').hidden=false;
  document.getElementById('kicker').textContent='your music · only you can add or remove';
  document.getElementById('emptyText').textContent='Drop the first track above. Anyone with the link can listen.';
  const fi=document.getElementById('fileInput');
  const dz=document.getElementById('dropzone');
  fi.addEventListener('change',()=>{if(fi.files.length)upload(fi.files);fi.value='';});
  document.getElementById('retryBtn').addEventListener('click',()=>{
    const again=upFailed.filter(x=>x.retry).map(x=>x.file);
    upFailed=upFailed.filter(x=>!x.retry);
    for(const f of again){ upQueue.push(f); upTotal++; }
    syncUpFailed(); pumpUploads();
  });
  dz.addEventListener('dragover',e=>{e.preventDefault();dz.classList.add('dragover');});
  dz.addEventListener('dragleave',()=>dz.classList.remove('dragover'));
  dz.addEventListener('drop',e=>{e.preventDefault();dz.classList.remove('dragover');if(e.dataTransfer.files.length)upload(e.dataTransfer.files);});
}

refresh();
// Paused mid-drag (a re-render would yank the row away), while uploading, and
// while the tab is hidden.
setInterval(()=>{ if(!drag && !uploading && !document.hidden) refresh(); }, 15000);
</script>
__SIGNIN__
</body>
</html>"""


class MusicHandler(HardenedHandlerMixin, BaseHTTPRequestHandler):

    protocol_version = 'HTTP/1.1'

    music_dir = Path('.')
    devices_path = ''
    title = 'Music'
    max_file = MAX_FILE_SIZE
    max_total = MAX_TOTAL_SIZE
    max_files = MAX_TRACKS
    min_free = DEFAULT_MIN_FREE_MB * 1024 * 1024
    upload_slots = UploadSlots(total=4, per_ip=2)

    _quota = None
    _warmer = None
    _quota_lock = threading.Lock()

    @classmethod
    def quota(cls):
        """The collection's shared Quota, created on first use (one per class)."""
        with cls._quota_lock:
            q = cls.__dict__.get('_quota')
            if q is None:
                q = Quota(cls.music_dir, lambda: collection_usage(cls.music_dir),
                          cls.max_total, cls.max_files, cls.min_free,
                          label='collection', item_word='tracks')
                cls._quota = q
            return q

    @classmethod
    def warmer(cls):
        with cls._quota_lock:
            w = cls.__dict__.get('_warmer')
            if w is None:
                w = PeaksWarmer(cls.music_dir)
                cls._warmer = w
            return w

    def log_message(self, format, *args):
        method = args[0] if args else ''
        if isinstance(method, str) and method.startswith('GET'):
            return
        sys.stderr.write(f"[musicserver] {self.address_string()} - {format % args}\n")

    def _security_headers(self):
        """nosniff (a track labelled audio/mpeg is never re-sniffed as HTML),
        no-referrer, DENY framing: porch_http.security_headers."""
        security_headers(self)

    def send_json(self, data, status=200, headers=None):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        headers = dict(headers or {})
        self.send_header('Cache-Control', headers.pop('Cache-Control', 'no-store'))
        for k, v in headers.items():
            self.send_header(k, v)
        if self.close_connection:
            # We are answering without draining the request body (an upload we
            # refused), so the connection can't be reused — say so explicitly.
            self.send_header('Connection', 'close')
        self._security_headers()
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def _err(self, message, status=400, headers=None):
        self.send_json({'status': 'error', 'message': message}, status, headers)

    def _is_admin(self):
        """True iff porch_auth accepts this request's owner credential: a
        porch_host cookie for this host (or, during the migration, a legacy
        cush_auth cookie) of a live admin device. No registry => nobody."""
        return porch_auth.request_is_owner(self, self.devices_path)

    def _signin_html(self):
        """The small "Owner? Sign in" link for a visitor who is not the owner,
        pointing at this host's /__porch/start handoff. '' when the visitor
        is the owner or no owner registry is configured."""
        url = porch_auth.signin_url(self, self.devices_path)
        if not url:
            return ''
        return (f'<a class="porch-signin" href="{html_escape(url, quote=True)}" '
                'rel="nofollow">Owner? Sign in</a>')

    def _same_origin(self):
        """CSRF check for writes (porch_http.same_origin). The cookie alone is
        not enough: the legacy cush_auth cookie is issued for the whole
        .cush.rocks domain, so a SameSite=Lax cookie rides along on a POST from
        any sibling cush tool. This pins a write to this collection's page."""
        return same_origin(self)

    def _safe_target(self, raw):
        """Sanitized name + symlink-refusing containment check in music_dir."""
        return safe_child(self.music_dir, raw)

    def _parse_range(self, header, size):
        return parse_range(header, size)

    def _serve_type(self, target, name):
        """(content_type, disposition) for a stored track.

        Files can also be dropped into the directory out of band, so the first
        bytes are re-sniffed on the way out. Anything that opens like markup —
        or that sniffs as some other, non-audio type — goes out as an opaque
        download instead of something the browser will render.
        """
        declared = EXT_MIME.get(os.path.splitext(name)[1].lower())
        try:
            with open(target, 'rb') as f:
                head = f.read(SNIFF_BYTES)
        except OSError:
            head = b''
        if not declared or looks_like_markup(head):
            return 'application/octet-stream', 'attachment'
        return declared, 'inline'

    # ---- ranged streaming (so <audio> can seek) ----
    def _stream_track(self, target, name):
        try:
            size = target.stat().st_size
        except OSError:
            self._err('Not found', 404)
            return
        ctype, disp = self._serve_type(target, name)
        # `name` is [a-zA-Z0-9._-] only (sanitize_filename): header-safe.
        stream_file(self, target, size, ctype, disp, name, cache='private, max-age=300')

    def _serve_peaks(self, raw):
        target, name = self._safe_target(raw)
        if target is None or not target.is_file() or not is_audio_name(name):
            self._err('Not found', 404)
            return
        result = compute_peaks(self.music_dir, name)
        if result is JobGate.BUSY:
            self._err('Busy, try again', 503, {'Retry-After': '3'})
            return
        if not result:
            # Cacheable: until the track changes the answer won't either.
            self._err('waveform n/a', 404, {'Cache-Control': 'private, max-age=3600'})
            return
        self.send_json(result, 200, {'Cache-Control': 'private, max-age=300'})

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if serve_asset(self, head=self.command == 'HEAD'):
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip('/')

        if path == '' or path == '/':
            # html.escape: --title comes from the tunnel name on the command
            # line, which is not a trusted string, and it lands in both <title>
            # and <h1>. Substituting it raw was an injection waiting to happen.
            nonce = csp_nonce()
            html = PLAYER_HTML.replace('__PORCH_CSS__', porch_css_tag())
            html = html.replace('__MARK__', porch_mark(16))
            html = html.replace('__NONCE__', nonce)
            html = html.replace('__TITLE__', html_escape(self.title))
            html = html.replace('__ADMIN_FLAG__', 'true' if self._is_admin() else 'false')
            html = html.replace('__MAXFILE__', str(int(self.max_file)))
            html = html.replace('__SIGNIN__', self._signin_html())
            body = html.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            # The page loads porch.css and its fonts from this origin and
            # nothing else, plus its own nonced inline style/script; 'none'
            # everywhere else kills base-tag and clickjacking tricks outright.
            self.send_header('Content-Security-Policy', (
                f"default-src 'none'; {porch_style_src(nonce)}; "
                f"script-src 'nonce-{nonce}'; media-src 'self'; "
                "connect-src 'self'; base-uri 'none'; form-action 'none'; "
                "frame-ancestors 'none'"
            ))
            self._security_headers()
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(body)
            return

        if path == '/list':
            # Read-only: the reconciled order is never written back here; only
            # upload, delete and reorder write .order.json.
            with _order_lock:
                names = load_order(self.music_dir)
            out = []
            warmer = self.warmer()
            for name in names:
                target = self.music_dir / name
                try:
                    st = target.stat()
                except OSError:
                    continue
                if not target.is_file():
                    continue
                entry = {'name': name, 'size': st.st_size, 'modified': st.st_mtime}
                dur = cached_duration(self.music_dir, name)
                if dur is not None:
                    entry['duration'] = dur
                else:
                    warmer.want(name)
                out.append(entry)
            self.send_json(out)
            return

        if path.startswith('/peaks/'):
            self._serve_peaks(urllib.parse.unquote(path[len('/peaks/'):]))
            return

        if path.startswith('/track/'):
            raw = urllib.parse.unquote(path[len('/track/'):])
            target, name = self._safe_target(raw)
            if target is None or not target.is_file() or not is_audio_name(name):
                self._err('Not found', 404)
                return
            self._stream_track(target, name)
            return

        self._err('Not found', 404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip('/')

        # Every mutating endpoint is same-origin-only. Checked before anything
        # reads the body, so a cross-site POST costs us nothing — and before
        # the owner check, so a cross-site probe learns nothing either.
        if not self._same_origin():
            self.close_connection = True
            self._err('Cross-origin request refused', 403)
            return

        # All write endpoints require the owner's cush_auth cookie. The body is
        # never drained on refusal, so the connection can't be reused — hang up
        # rather than let the undrained upload be parsed as the next request.
        if not self._is_admin():
            self.close_connection = True
            self._err('Forbidden — enroll this browser at '
                      f'https://{porch_config.get().auth_host}/auth/', 403)
            return
        slot_ip = None
        if path == '/upload':
            slot_ip = client_ip(self)
            if not self.upload_slots.acquire(slot_ip):
                self.close_connection = True
                self._err('Too many uploads in progress, try again shortly', 503,
                          {'Retry-After': '5'})
                return
        try:
            if path == '/upload':
                self._handle_upload()
            elif path == '/delete':
                self._handle_delete()
            elif path == '/reorder':
                self._handle_reorder()
            else:
                self._err('Not found', 404)
        except MultipartError as e:
            sys.stderr.write(f"[musicserver] malformed upload: {e}\n")
            self.close_connection = True
            try:
                self._err('Malformed upload', 400)
            except Exception:
                pass
        except Exception as e:
            sys.stderr.write(f"[musicserver] {path} failed: {e}\n")
            self.close_connection = True
            try:
                # Generic text only: internal exception strings carry filesystem
                # paths, and this used to echo str(e) straight to the caller.
                self._err('Server error', 500)
            except Exception:
                pass
        finally:
            if slot_ip is not None:
                self.upload_slots.release(slot_ip)

    def _content_length(self):
        return content_length(self)

    def _read_json_body(self):
        return read_json_body(self, MAX_JSON_BODY)

    def _handle_upload(self):
        boundary, bad = multipart_boundary(self.headers.get('Content-Type', ''))
        if bad:
            self._err(*bad)
            return

        length = self._content_length()
        if length <= 0:
            # No Content-Length (e.g. chunked) — BaseHTTPRequestHandler does
            # not de-chunk, and reading an unbounded body is precisely the DoS
            # we are avoiding, so refuse it.
            self._err('Content-Length required', 411)
            return
        # First cap: refuse an oversized body before reading a single byte. A
        # batch may hold several tracks, so the request ceiling is a multiple of
        # the per-file cap (the page sends one track per request).
        max_request = min(self.max_total, self.max_file * 8) + 64 * 1024
        if length > max_request:
            self.close_connection = True
            self._err(f'Upload request is larger than the {human_size(max_request)} '
                      f'request limit', 413)
            return

        quota = self.quota()
        streamer = MultipartStreamer(self.rfile, boundary, length, self.transferred)
        saved, rejected = [], []
        aborted = None

        try:
            for filename, chunks in streamer.parts():
                if not filename:
                    # Non-file field: drain it so the parser lands on the next part.
                    for _ in chunks:
                        pass
                    continue
                result = self._spool_part(filename, chunks, quota)
                if result.get('ok'):
                    saved.append({'name': result['name'], 'size': result['size']})
                    sys.stderr.write(
                        f"[musicserver] Saved: {result['name']} "
                        f"({human_size(result['size'])})\n")
                    self.warmer().want(result['name'])
                else:
                    rejected.append({'name': safe_stem(filename), 'reason': result['reason']})
        except UploadRejected as e:
            # Stop reading the body entirely and hang up after replying.
            aborted = e
            self.close_connection = True
            rejected.append({'name': 'upload', 'reason': e.reason})

        if saved:
            with _order_lock:
                names = load_order(self.music_dir)
                for s in saved:
                    if s['name'] not in names:
                        names.append(s['name'])
                save_order(self.music_dir, names)
            status = aborted.status if aborted else 200
            self.send_json({'status': 'ok', 'files': saved, 'rejected': rejected}, status)
            return

        if not rejected:
            self._err('No files found in upload', 400)
            return
        reason = rejected[0]['reason']
        status = aborted.status if aborted else (
            413 if ('limit' in reason or 'full' in reason) else 400)
        self.send_json({'status': 'error', 'message': reason,
                        'files': [], 'rejected': rejected}, status)

    def _spool_part(self, filename, chunks, quota):
        """Stream one uploaded part to disk, validating as it arrives.

        Returns {'ok': True, 'name', 'size'} or {'ok': False, 'reason'}. The
        part iterator is always drained so the parser stays in sync even when
        we throw the data away. Bytes are reserved against the shared Quota
        chunk by chunk (the track slot up front), so concurrent uploads can't
        jointly overshoot the caps or the free-disk floor.
        """
        raw_ext = os.path.splitext(
            str(filename).replace('\\', '/').split('/')[-1])[1].lower()
        if raw_ext not in ALLOWED_EXTENSIONS:
            for _ in chunks:        # keep the parser in sync; nothing is stored
                pass
            return {'ok': False,
                    'reason': f'file type {raw_ext or "(none)"} is not an allowed audio file'}

        refusal = quota.begin()
        if refusal:
            raise UploadRejected(refusal)
        # Everything after begin() runs inside the try, so every begin() has
        # its end(): new_tmp() raising used to leak the item slot for good.
        tmp = None
        head = b''
        written = 0          # == bytes reserved against the quota
        kept = False
        try:
            tmp = new_tmp(self.music_dir)
            with open(tmp, 'wb') as out:
                for chunk in chunks:
                    if len(head) < SNIFF_BYTES:
                        head += chunk[:SNIFF_BYTES - len(head)]
                    # Second cap, enforced mid-stream: a lying Content-Length
                    # buys no more disk than the per-file limit allows.
                    if written + len(chunk) > self.max_file:
                        raise UploadRejected(
                            f'over the {human_size(self.max_file)} per-file limit')
                    refusal = quota.add(len(chunk))
                    if refusal:
                        raise UploadRejected(refusal)
                    written += len(chunk)
                    out.write(chunk)

            if written == 0:
                return {'ok': False, 'reason': 'empty file'}
            # The extension is attacker-controlled, so it is not by itself proof
            # of anything: a payload that opens like markup is refused outright,
            # whatever it claims to be.
            if looks_like_markup(head):
                return {'ok': False, 'reason': 'that is not an audio file'}

            name = place_unique(tmp, self.music_dir,
                                name_candidates(safe_stem(filename), raw_ext))
            kept = True
            return {'ok': True, 'name': name, 'size': written}
        finally:
            quota.end(written, kept)
            if not kept and tmp is not None:
                drop_tmp(tmp)

    def _handle_delete(self):
        data = self._read_json_body()
        if data is None:
            self._err('Invalid JSON body', 400)
            return
        target, name = self._safe_target(data.get('name', ''))
        if target is None or not target.is_file() or not is_audio_name(name):
            self._err('Not found', 404)
            return
        try:
            size = target.stat().st_size
            target.unlink()
        except OSError:
            self._err('Not found', 404)
            return
        self.quota().removed(size)
        for side in peaks_paths(self.music_dir, name):
            try:
                side.unlink()
            except OSError:
                pass
        with _order_lock:
            names = [n for n in load_order(self.music_dir) if n != name]
            save_order(self.music_dir, names)
        sys.stderr.write(f"[musicserver] Deleted: {name}\n")
        self.send_json({'status': 'ok'})

    def _handle_reorder(self):
        data = self._read_json_body()
        if data is None:
            self._err('Invalid JSON body', 400)
            return
        requested = data.get('order', [])
        if not isinstance(requested, list) or len(requested) > self.max_files:
            self._err('order must be a list of names', 400)
            return
        with _order_lock:
            seen = set()
            cleaned = []
            for raw in requested:
                if not isinstance(raw, str):
                    continue
                name = sanitize_filename(raw)
                if name in seen:
                    continue
                target = (self.music_dir / name)
                if target.is_file() and is_audio_name(name):
                    cleaned.append(name)
                    seen.add(name)
            for entry in _disk_tracks(self.music_dir):
                if entry.name not in seen:
                    cleaned.append(entry.name)
                    seen.add(entry.name)
            save_order(self.music_dir, cleaned)
        self.send_json({'status': 'ok', 'order': cleaned})


def main():
    parser = argparse.ArgumentParser(description='Music collect / player server')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--dir', type=str, required=True)
    parser.add_argument('--devices', type=str, default='',
                        help='path to cush-auth devices.json; owners (enrolled '
                             'browsers) get upload/delete/reorder rights')
    parser.add_argument('--title', type=str, default='Music')
    parser.add_argument('--max-file-mb', type=int, default=MAX_FILE_SIZE // (1024 * 1024))
    parser.add_argument('--max-total-mb', type=int, default=MAX_TOTAL_SIZE // (1024 * 1024))
    parser.add_argument('--max-files', type=int, default=MAX_TRACKS)
    parser.add_argument('--min-free-mb', type=int, default=DEFAULT_MIN_FREE_MB,
                        help='refuse uploads that would leave less free disk than this')
    parser.add_argument('--max-uploads', type=int, default=4)
    parser.add_argument('--max-connections', type=int, default=DEFAULT_MAX_CONNECTIONS)
    # Loopback by default: frpc reaches us on 127.0.0.1, and nothing else on
    # the LAN should be able to reach the player around the tunnel.
    parser.add_argument('--bind', type=str, default='127.0.0.1')
    args = parser.parse_args()

    music_dir = Path(args.dir).resolve()
    music_dir.mkdir(parents=True, exist_ok=True)
    MusicHandler.music_dir = music_dir
    MusicHandler.devices_path = os.path.abspath(args.devices) if args.devices else ''
    MusicHandler.title = args.title
    MusicHandler.max_file = max(1, args.max_file_mb) * 1024 * 1024
    MusicHandler.max_total = max(1, args.max_total_mb) * 1024 * 1024
    MusicHandler.max_files = max(1, args.max_files)
    MusicHandler.min_free = max(0, args.min_free_mb) * 1024 * 1024
    MusicHandler.upload_slots = UploadSlots(total=max(1, args.max_uploads),
                                            per_ip=min(2, max(1, args.max_uploads)))

    swept = sweep_stale_parts(music_dir, subdirs=(PEAKS_DIR,))
    if swept:
        sys.stderr.write(f"[musicserver] removed {swept} stale partial file(s)\n")
    install_sigterm_cleanup('musicserver')

    server = make_server(MusicHandler, args.port, args.bind, tag='musicserver',
                         max_connections=max(4, args.max_connections))
    sys.stderr.write(f"[musicserver] Listening on {args.bind}:{args.port}, tracks in "
                     f"{music_dir}"
                     f"{'' if _ffmpeg_bin else ' (no ffmpeg: waveform n/a)'}\n")
    try:
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        sys.stderr.write("\n[musicserver] Shutting down.\n")
    finally:
        server.server_close()


if __name__ == '__main__':
    main()

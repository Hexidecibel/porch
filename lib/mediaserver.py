#!/usr/bin/env python3

"""Media-collect / gallery server (used by bin/media and bin/photos).

This is the old photoserver.py grown up: one gallery that holds **images and
video together**, with the owner/guest split that lib/musicserver.py pioneered.

Two launchers share it, with the same owner/guest split:

  * bin/photos  -> --kinds image --devices data/devices.json
  * bin/media   -> --kinds image,video --devices data/devices.json
        Anyone with the link can view, download and *add*; only the owner — a
        browser whose porch_host cookie (or, during the migration, legacy
        cush_auth cookie) lib/porch_auth.py accepts as a live admin device in
        data/devices.json, the same rule music and drop apply — can delete or
        reorder. Guests never see a delete affordance and the server
        re-checks on every write, so hiding the button is cosmetic.

With no --devices the server **fails closed**: nobody is an owner, so the
gallery is view+add only. --open (every visitor is the owner) still exists as
an explicit, loudly-warned opt-in; no launcher passes it any more.

--view-only (bin/media --view-only) takes guests down to watching: /upload
answers 403, the forced-download path (?dl=) answers 403, and their page is
rendered without the add controls or the download button. Inline ranged
streaming is untouched, since playback and seeking depend on it. The owner
keeps everything. Combined with the fail-closed rule above, a view-only
gallery with no registry accepts no uploads from anyone. This deters casual
saving; it cannot stop someone with dev tools or a screen recorder.

--no-guest-upload (what `porch share` uses for photos and video) is the
milder lock: guests can watch and download but not add (/upload and /tus/
answer 403, the add controls are not rendered). The owner keeps everything.

Security posture (this thing is exposed to the public internet by a tunnel):

  * Filenames from clients are hostile. The stored name is *generated* here:
    the client's name is only a hint for the stem, and the extension comes
    from the sniffed content type, never from the client.
  * Uploads are validated by magic bytes, not extension, and anything that
    smells like markup (SVG/HTML/XML) is rejected outright.
  * Uploads stream to disk with the size cap enforced *during* the write.
  * Every path that takes a filename re-resolves and containment-checks it.
  * Range requests are parsed defensively and clamped to the file size.
  * State-changing POSTs require a same-origin Origin/Referer.
  * Quota (bytes, items, free-disk floor) is a shared running total with
    per-chunk reservation; concurrent uploads are capped.
  * Thumbnails/previews: one job per file, two overall, failures cached;
    ffmpeg runs with a forced demuxer, file-only protocols and rlimits.
  * /tus/ (resumable uploads, lib/porch_tus.py; the page's first choice)
    keeps /upload's gates in /upload's order and sniffs the first 64 bytes
    the moment they arrive; partials live in .tus/ and are never listed.
  * Light copies (LightCopies): one background ffmpeg worker, its own
    rlimits, never on a request thread; off without ffmpeg + ffprobe.
  * Binds 127.0.0.1 by default; bounded connections + transfer deadlines.
"""

import argparse
import html
import json
import os
import queue
import secrets
import shutil
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import porch_auth  # noqa: E402  (the one owner check: porch_host + legacy cush_auth)
import porch_tus  # noqa: E402  (resumable uploads at /tus/)
from porch_http import (  # noqa: E402  (shared HTTP core)
    DEFAULT_MAX_CONNECTIONS, DEFAULT_MIN_FREE_MB, HardenedHandlerMixin, JobGate,
    child_limits,
    MultipartError, MultipartStreamer, Quota,
    UploadRejected, UploadSlots, client_ip, content_length, drop_tmp,
    fresh_against, human_size, install_sigterm_cleanup, limit_child,
    make_server, multipart_boundary, name_candidates, new_tmp, parse_range,
    place_unique, read_json_body, safe_child, safe_stem, same_origin,
    sanitize_filename, security_headers, stream_file, sweep_stale_parts,
    touch_marker, atomic_write_json, csp_nonce,
    porch_css_tag, porch_mark, porch_style_src, serve_asset,
)
from porch_http import BoundedThreadingHTTPServer  # noqa: E402,F401  (re-exported)


try:
    from PIL import Image, ImageOps
    HAVE_PIL = True
except ImportError:  # pragma: no cover - Pillow is a repo dependency
    HAVE_PIL = False

# A 40000x40000 PNG decompresses to ~6GB of pixels. Pillow only *warns* above
# MAX_IMAGE_PIXELS and raises at twice that, so the limit is also checked
# explicitly (open_checked) to make it a hard error at the real number.
MAX_PIXELS = 64_000_000  # ~64MP, comfortably above any phone
if HAVE_PIL:
    Image.MAX_IMAGE_PIXELS = MAX_PIXELS

HAVE_HEIF = False
if HAVE_PIL:
    try:  # optional: lets Pillow decode HEIC/HEIF (iPhone photos)
        from pillow_heif import register_heif_opener
        register_heif_opener()
        HAVE_HEIF = True
    except Exception:
        HAVE_HEIF = False

# ---- limits -----------------------------------------------------------------
# Defaults; both are overridable from the CLI. The per-file cap is checked
# twice: once against the declared Content-Length (so a huge body is refused
# before a single byte is read) and again byte-by-byte while spooling to disk
# (so a lying Content-Length buys nothing).
DEFAULT_MAX_FILE_MB = 512
DEFAULT_MAX_TOTAL_MB = 8192
MAX_FILES = 2000            # per-gallery file count ceiling
MAX_JSON_BODY = 1024 * 1024  # /delete + /reorder bodies are tiny; cap them

ORDER_FILE = '.order.json'
THUMBS_DIR = '.thumbs'
THUMB_LONG_EDGE = 480

# ---- type tables ------------------------------------------------------------
# NOTE: SVG is deliberately absent. It is an "image" that can carry <script>,
# and serving it inline from the same origin as the gallery would be stored
# XSS. sniff_mime() also rejects any file whose head starts with '<', so an
# SVG renamed to .png can't sneak in either.
IMAGE_EXT_MIME = {
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.gif': 'image/gif',
    '.webp': 'image/webp',
    '.heic': 'image/heic',
    '.heif': 'image/heic',
    '.bmp': 'image/bmp',
    '.tif': 'image/tiff',
    '.tiff': 'image/tiff',
    '.avif': 'image/avif',
}

VIDEO_EXT_MIME = {
    '.mp4': 'video/mp4',
    '.m4v': 'video/mp4',
    '.mov': 'video/quicktime',
    '.webm': 'video/webm',
    '.mkv': 'video/x-matroska',
    '.ogv': 'video/ogg',
    '.avi': 'video/x-msvideo',
    '.3gp': 'video/3gpp',
}

EXT_MIME = dict(IMAGE_EXT_MIME)
EXT_MIME.update(VIDEO_EXT_MIME)

# Canonical extension per sniffable type. The stored filename's extension is
# taken from *this* table keyed by the sniffed content type, so a client that
# uploads "invoice.php" containing a JPEG gets "invoice.jpg" on disk and a
# client that uploads "cat.png" containing an ELF binary gets rejected.
MIME_EXT = {
    'image/jpeg': '.jpg',
    'image/png': '.png',
    'image/gif': '.gif',
    'image/webp': '.webp',
    'image/bmp': '.bmp',
    'image/tiff': '.tif',
    'image/heic': '.heic',
    'image/avif': '.avif',
    'video/mp4': '.mp4',
    'video/quicktime': '.mov',
    'video/webm': '.webm',
    'video/x-matroska': '.mkv',
    'video/ogg': '.ogv',
    'video/x-msvideo': '.avi',
    'video/3gpp': '.3gp',
}

SNIFF_BYTES = 64  # enough for every magic below, including the ISO-BMFF ftyp box


def kind_of_mime(mime):
    """'image' / 'video' / None from a full mime type."""
    if not mime:
        return None
    top = mime.split('/', 1)[0]
    return top if top in ('image', 'video') else None


def ext_mime(name):
    return EXT_MIME.get(os.path.splitext(name)[1].lower())


def looks_like_markup(head):
    """True if the payload opens like SVG / HTML / XML.

    Belt-and-braces on top of the allowlist: markup served from the gallery's
    own origin executes in the visitor's session, so it never gets stored no
    matter what extension it arrived under.
    """
    probe = head.lstrip(b'\xef\xbb\xbf \t\r\n')[:16].lower()
    return probe.startswith(b'<')


# ISO-BMFF brands we accept. Any other brand (an unknown or audio-only
# container wearing an ftyp box) is refused instead of being waved through as
# "probably mp4".
AVIF_BRANDS = {b'avif', b'avis'}
HEIF_BRANDS = {b'heic', b'heix', b'heim', b'heis', b'hevc', b'hevx', b'mif1', b'msf1'}
AUDIO_BRANDS = {b'M4A ', b'M4B ', b'M4P ', b'F4A ', b'F4B '}
VIDEO_BRANDS = {
    b'isom', b'iso2', b'iso3', b'iso4', b'iso5', b'iso6', b'iso7', b'iso8', b'iso9',
    b'mp41', b'mp42', b'mp71', b'avc1', b'av01', b'hvc1', b'M4V ', b'M4VH', b'M4VP',
    b'qt  ', b'3gp4', b'3gp5', b'3gp6', b'3gp7', b'3gp8', b'3gp9', b'3g2a', b'3g2b',
    b'3g2c', b'3ge6', b'3ge7', b'3gg6', b'dash', b'msnv', b'MSNV', b'mmp4', b'f4v ',
    b'XAVC', b'CAEP', b'MiPr',
}
BMP_DIB_SIZES = {12, 40, 52, 56, 64, 108, 124}


def _ftyp_brands(head):
    """(major, {all brands}) from an ftyp box, or None if it is malformed."""
    size = int.from_bytes(head[0:4], 'big')
    if size < 16 or size % 4 or len(head) < 16:
        return None
    major = head[8:12]
    brands = {major}
    end = min(size, len(head))
    for i in range(16, end - 3, 4):
        brands.add(head[i:i + 4])
    return major, brands


def _bmp_ok(head):
    """A real BITMAPFILEHEADER: zero reserved words, a known DIB header size,
    and a pixel-data offset that lies just past the headers."""
    if len(head) < 26:
        return False
    file_size, reserved, offset, dib = struct.unpack_from('<IIII', head, 2)
    if reserved != 0 or dib not in BMP_DIB_SIZES:
        return False
    if offset < 14 + dib or offset > 14 + dib + 64 * 1024:
        return False
    if file_size and file_size < offset:
        return False
    return True


def sniff_mime(head):
    """Content type from magic bytes, or None if we don't recognise it.

    The extension is attacker-controlled; the first bytes of the file are the
    only thing worth trusting about its type. Every branch checks a structure,
    not just two letters, so random bytes that happen to start 'BM' or carry
    an 'ftyp' at offset 4 are refused.
    """
    if len(head) < 12 or looks_like_markup(head):
        return None

    # --- images ---
    if head.startswith(b'\xff\xd8\xff'):
        return 'image/jpeg'
    if head.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'image/png'
    if head.startswith(b'GIF87a') or head.startswith(b'GIF89a'):
        return 'image/gif'
    if head.startswith(b'BM'):
        return 'image/bmp' if _bmp_ok(head) else None
    if head.startswith(b'II*\x00') or head.startswith(b'MM\x00*'):
        return 'image/tiff'
    if head.startswith(b'RIFF'):
        # RIFF is a container family: the form type at offset 8 disambiguates.
        form = head[8:12]
        if form == b'WEBP':
            return 'image/webp'
        if form == b'AVI ':
            return 'video/x-msvideo'
        return None

    # --- ISO base media (mp4 / mov / 3gp / heic / avif) ---
    if head[4:8] == b'ftyp':
        parsed = _ftyp_brands(head)
        if not parsed:
            return None
        major, brands = parsed
        if major in AUDIO_BRANDS:
            return None                       # m4a/m4b: audio belongs to bin/music
        if brands & AVIF_BRANDS:
            return 'image/avif'
        if brands & HEIF_BRANDS:
            return 'image/heic'
        if major == b'qt  ':
            return 'video/quicktime'
        if major.startswith(b'3g') and major in VIDEO_BRANDS:
            return 'video/3gpp'
        if brands & VIDEO_BRANDS:
            return 'video/mp4'
        return None

    # --- Matroska / WebM (both EBML; the DocType tells them apart) ---
    if head.startswith(b'\x1a\x45\xdf\xa3'):
        if b'webm' in head[:SNIFF_BYTES]:
            return 'video/webm'
        if b'matroska' in head[:SNIFF_BYTES]:
            return 'video/x-matroska'
        return None

    # --- Ogg: video only here (Theora); Vorbis/Opus audio belongs to bin/music ---
    if head.startswith(b'OggS'):
        return 'video/ogg' if b'theora' in head[:SNIFF_BYTES] else None

    return None


# ffmpeg demuxer per sniffed video type. Forcing it (instead of letting
# ffmpeg probe) means a file can only ever be parsed as what we sniffed.
VIDEO_DEMUXER = {
    'video/mp4': 'mov',
    'video/quicktime': 'mov',
    'video/3gpp': 'mov',
    'video/webm': 'matroska',
    'video/x-matroska': 'matroska',
    'video/x-msvideo': 'avi',
    'video/ogg': 'ogg',
}

# Types browsers can't show natively: the lightbox asks for a server-made
# JPEG preview instead (Pillow; HEIC needs pillow-heif).
PREVIEW_MIMES = {'image/heic', 'image/tiff'}


# Guards every read-modify-write of the order sidecar.
_order_lock = threading.Lock()


# ---- filenames ---------------------------------------------------------------

# ---- listing + order sidecar -------------------------------------------------

def _disk_media(directory, kinds):
    """Media files currently on disk (skips sidecars, thumbs, partials)."""
    out = []
    try:
        entries = list(directory.iterdir())
    except OSError:
        return out
    for entry in entries:
        if entry.name.startswith('.'):
            continue
        if entry.name.endswith('.part'):
            continue
        # is_file() follows symlinks; a link planted in the directory would be
        # listed even though _safe_target() refuses to serve it. Skip links
        # outright so the listing only ever names real files we own.
        if entry.is_symlink() or not entry.is_file():
            continue
        mime = ext_mime(entry.name)
        if mime and kind_of_mime(mime) in kinds:
            out.append(entry)
    return out


def load_order(directory, kinds):
    """Read .order.json, reconcile against disk, return list of names.

    - Missing/corrupt sidecar => start empty.
    - Drop names whose file no longer exists.
    - Append any on-disk item not already listed, mtime ascending, so
      out-of-band additions (Claude dropping files straight into the dir)
      self-heal at the end of the order.
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

    on_disk = {e.name: e for e in _disk_media(directory, kinds)}

    reconciled = [n for n in stored if n in on_disk]
    seen = set(reconciled)
    extras = [e for n, e in on_disk.items() if n not in seen]
    extras.sort(key=lambda e: e.stat().st_mtime)
    reconciled.extend(e.name for e in extras)
    return reconciled


def save_order(directory, names):
    """Atomic write of the order sidecar (unique temp file + os.replace)."""
    atomic_write_json(directory / ORDER_FILE, names)


def gallery_usage(directory, kinds):
    """(bytes, items) currently in the gallery."""
    total = count = 0
    for entry in _disk_media(directory, kinds):
        try:
            total += entry.stat().st_size
            count += 1
        except OSError:
            pass
    return total, count


# ---- streaming multipart parser ---------------------------------------------

# ---- thumbnails --------------------------------------------------------------

_ffmpeg_bin = shutil.which('ffmpeg')

PREVIEW_LONG_EDGE = 2048
THUMB_FAIL_MAX_AGE = 3600     # browsers may cache "no thumbnail" this long
# Thumbnails and previews are CPU-heavy: one job per file, two overall.
_thumb_gate = JobGate(max_jobs=2)


def open_checked(src):
    """Image.open, with MAX_PIXELS as a hard error at the real limit."""
    img = Image.open(src)
    try:
        w, h = img.size
    except Exception:
        img.close()
        raise
    if w * h > MAX_PIXELS:
        img.close()
        raise ValueError(f'image is {w}x{h}, over the {MAX_PIXELS} pixel limit')
    return img


def _image_render(src, dst_tmp, long_edge, quality):
    if not HAVE_PIL:
        return False
    with open_checked(src) as img:
        try:
            img.draft('RGB', (long_edge * 2, long_edge * 2))   # fast JPEG downscale
        except Exception:
            pass
        img = ImageOps.exif_transpose(img)
        img.thumbnail((long_edge, long_edge))
        img = img.convert('RGB')
        img.save(dst_tmp, 'JPEG', quality=quality)
    return True


def _image_thumb(src, dst_tmp):
    return _image_render(src, dst_tmp, THUMB_LONG_EDGE, 82)


def _image_preview(src, dst_tmp):
    return _image_render(src, dst_tmp, PREVIEW_LONG_EDGE, 86)


def _sniff_file(path):
    try:
        with open(path, 'rb') as f:
            return sniff_mime(f.read(SNIFF_BYTES))
    except OSError:
        return None


def _video_thumb(src, dst_tmp):
    """Grab a poster frame with ffmpeg, if ffmpeg is installed.

    Degrades to False when ffmpeg is absent or the file has no decodable
    frame; the page then draws its own generative poster, so a box without
    ffmpeg still gets a complete-looking gallery.

    Hardening: argv form, shell=False, server-generated absolute paths; the
    demuxer is forced from the sniffed type (no format probing), only the
    file protocol is allowed (no playlist/concat tricks reaching the
    network), audio/subtitle/data streams are dropped, and ffmpeg runs
    niced under CPU/memory/file-size rlimits as well as a wall-clock timeout.
    """
    if not _ffmpeg_bin:
        return False
    demuxer = VIDEO_DEMUXER.get(_sniff_file(src))
    if not demuxer:
        return False
    for seek in ('1', '0'):  # 1s in usually beats a black first frame
        cmd = [
            _ffmpeg_bin, '-nostdin', '-hide_banner', '-loglevel', 'error',
            '-protocol_whitelist', 'file',
            '-f', demuxer,
            '-ss', seek, '-i', 'file:' + str(src),
            '-an', '-sn', '-dn', '-threads', '1',
            '-frames:v', '1',
            '-vf', f'scale={THUMB_LONG_EDGE}:-2:force_original_aspect_ratio=decrease',
            '-f', 'image2', '-y', 'file:' + str(dst_tmp),
        ]
        try:
            proc = subprocess.run(
                cmd, shell=False, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=25,
                preexec_fn=limit_child,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        if proc.returncode == 0 and dst_tmp.is_file() and dst_tmp.stat().st_size > 0:
            return True
    return False


def sidecar_paths(media_dir, name):
    """Every derived file for a stored item (thumb, preview, light copy and
    their failure / not-needed markers)."""
    t = media_dir / THUMBS_DIR
    return [t / (name + '.jpg'), t / (name + '.fail'),
            t / (name + '.view.jpg'), t / (name + '.view.fail'),
            t / (name + LIGHT_SUFFIX), t / (name + LIGHT_FAIL), t / (name + LIGHT_NO)]


# ---- light copies (adaptive video) -------------------------------------------
#
# A 4K phone clip at 40 Mbps stalls on a phone over cellular. When ffmpeg and
# ffprobe are installed, every video that is taller than 720p (short edge, so
# portrait clips count too), heavier than LIGHT_MIN_BITRATE, or in a codec
# browsers don't all play gets a "light" copy: H.264 + AAC in MP4, short edge
# <= 720, ~3 Mbps, faststart. It lives next to the thumbnails as
# .thumbs/<name>.light.mp4; the lightbox picks it on a phone or a slow link.
# The original is never touched and downloads always get the original.
#
# One background worker does all of it (probe + transcode), so a request
# thread never waits on ffmpeg; the queue is bounded and new uploads go before
# the startup backlog. Failure leaves .light.fail, "not needed" leaves
# .light.no, both re-checked against the original's mtime. Without ffmpeg or
# ffprobe the feature is off and nothing else changes.

LIGHT_SUFFIX = '.light.mp4'
LIGHT_FAIL = '.light.fail'
LIGHT_NO = '.light.no'
LIGHT_MAX_EDGE = 720                 # short edge of the light copy
LIGHT_MIN_BITRATE = 5_000_000        # bits/s above which a copy is made anyway
LIGHT_MAXRATE = '3M'
LIGHT_BUFSIZE = '6M'
LIGHT_QUEUE_MAX = 256
# Codecs every current browser plays in <video>; anything else (HEVC from an
# iPhone in Chrome, MPEG-4 Part 2 in an .avi, ...) gets a light copy too.
BROWSER_CODECS = {'h264', 'vp8', 'vp9', 'av1'}

_ffprobe_bin = shutil.which('ffprobe')


def light_enabled():
    return bool(_ffmpeg_bin and _ffprobe_bin)


def probe_video(src):
    """{'width','height','codec','bitrate','duration'} from ffprobe, or None.

    Same hardening as _video_thumb: argv, forced demuxer from the sniffed
    type, file protocol only, rlimits and a wall-clock timeout.
    """
    if not _ffprobe_bin:
        return None
    demuxer = VIDEO_DEMUXER.get(_sniff_file(src))
    if not demuxer:
        return None
    cmd = [_ffprobe_bin, '-v', 'error', '-protocol_whitelist', 'file', '-f', demuxer,
           '-select_streams', 'v:0',
           '-show_entries', 'stream=width,height,codec_name,bit_rate:format=duration,bit_rate',
           '-of', 'json', 'file:' + str(src)]
    try:
        proc = subprocess.run(cmd, shell=False, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=30, preexec_fn=limit_child)
        if proc.returncode != 0:
            return None
        data = json.loads(proc.stdout.decode('utf-8', 'replace') or '{}')
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None
    streams = data.get('streams') or []
    if not streams:
        return None
    st, fmt = streams[0], data.get('format') or {}

    def num(v, cast=int):
        try:
            return cast(v)
        except (TypeError, ValueError):
            return 0
    return {
        'width': num(st.get('width')),
        'height': num(st.get('height')),
        'codec': str(st.get('codec_name') or ''),
        'bitrate': num(st.get('bit_rate')) or num(fmt.get('bit_rate')),
        'duration': num(fmt.get('duration'), float),
    }


def needs_light(probe):
    """True iff a probed video deserves a light copy (see the block above)."""
    if not probe or not probe.get('width') or not probe.get('height'):
        return False
    if min(probe['width'], probe['height']) > LIGHT_MAX_EDGE:
        return True
    if probe.get('bitrate', 0) > LIGHT_MIN_BITRATE:
        return True
    return probe.get('codec', '') not in BROWSER_CODECS


# Short edge to <= 720, the other edge keeps the aspect; both even (yuv420p).
_LIGHT_SCALE = (
    "scale=w='if(gt(iw,ih),-2,trunc(min(iw,{e})/2)*2)'"
    ":h='if(gt(iw,ih),trunc(min(ih,{e})/2)*2,-2)'".format(e=LIGHT_MAX_EDGE))


def transcode_light(src, dst_tmp, probe):
    """Write the light copy of src to dst_tmp. True on success.

    nice'd, with its own rlimits: CPU time generous and scaled to the clip's
    length (a 10-minute clip legitimately burns minutes of CPU), output size
    bounded by twice the original (a light copy is smaller in every sane
    case), plus a wall-clock timeout on top.
    """
    demuxer = VIDEO_DEMUXER.get(_sniff_file(src))
    if not (_ffmpeg_bin and demuxer):
        return False
    try:
        size = src.stat().st_size
    except OSError:
        return False
    duration = max(1.0, float(probe.get('duration') or 0) or size / 625_000)
    cpu = int(min(6 * 3600, 120 + duration * 12))
    fsize = max(64 * 1024 * 1024, 2 * size)
    cmd = [
        _ffmpeg_bin, '-nostdin', '-hide_banner', '-loglevel', 'error',
        '-protocol_whitelist', 'file', '-f', demuxer, '-i', 'file:' + str(src),
        '-map', '0:v:0', '-map', '0:a:0?', '-sn', '-dn', '-map_metadata', '-1',
        '-vf', _LIGHT_SCALE + ',format=yuv420p',
        '-c:v', 'libx264', '-preset', 'veryfast', '-profile:v', 'high', '-crf', '23',
        '-maxrate', LIGHT_MAXRATE, '-bufsize', LIGHT_BUFSIZE,
        '-c:a', 'aac', '-b:a', '128k', '-ac', '2',
        '-movflags', '+faststart', '-threads', '2',
        '-f', 'mp4', '-y', 'file:' + str(dst_tmp),
    ]
    try:
        proc = subprocess.run(
            cmd, shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, timeout=cpu + 120,
            preexec_fn=child_limits(cpu, fsize, mem_bytes=2 * 1024 * 1024 * 1024, niceness=15))
    except (OSError, subprocess.TimeoutExpired):
        return False
    if proc.returncode != 0:
        sys.stderr.write(f"[mediaserver] light copy failed for {src.name}: "
                         f"{proc.stderr.decode('utf-8', 'replace')[-300:].strip()}\n")
        return False
    return dst_tmp.is_file() and dst_tmp.stat().st_size > 0


def _identity(path):
    """(inode, size, mtime_ns) of a file, or None: what 'the same original'
    means across a transcode that runs for minutes."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_ino, st.st_size, st.st_mtime_ns)


class LightCopies:
    """The single background worker that probes videos and makes light copies.

    enqueue() never blocks: a full queue drops the job, and the next /list
    scan offers it again. Priority 0 (fresh uploads) goes before 1 (backlog).
    """

    def __init__(self, media_dir, tag='mediaserver'):
        self.media_dir = media_dir
        self.tag = tag
        self._q = queue.PriorityQueue(maxsize=LIGHT_QUEUE_MAX)
        self._lock = threading.Lock()
        self._pending = set()
        self._seq = 0
        self._thread = None
        self._scanned = False
        self._current_tmp = None

    def paths(self, name):
        t = self.media_dir / THUMBS_DIR
        return t / (name + LIGHT_SUFFIX), t / (name + LIGHT_FAIL), t / (name + LIGHT_NO)

    def ready(self, name):
        """The light copy's path if it is there and current, else None."""
        light, _, _ = self.paths(name)
        return light if fresh_against(light, self.media_dir / name) else None

    def pending(self, name):
        with self._lock:
            return name in self._pending

    def _settled(self, name):
        src = self.media_dir / name
        return any(fresh_against(p, src) for p in self.paths(name))

    def enqueue(self, name, priority=0):
        if not light_enabled() or kind_of_mime(ext_mime(name)) != 'video':
            return False
        if self._settled(name):
            return False
        with self._lock:
            if name in self._pending:
                return True
            self._seq += 1
            try:
                self._q.put_nowait((priority, self._seq, name))
            except queue.Full:
                # Dropped: let the next /list scan offer the backlog again.
                self._scanned = False
                return False
            self._pending.add(name)
            if self._thread is None:
                self._thread = threading.Thread(target=self._run, name='light-copies',
                                                daemon=True)
                self._thread.start()
        return True

    def ensure_scanned(self, names):
        """Queue every listed video that has no light-copy decision yet (once
        per process), at backlog priority; drop light copies whose original
        is gone."""
        with self._lock:
            if self._scanned or not light_enabled():
                return
            self._scanned = True
        for name in names:
            self.enqueue(name, priority=1)
        try:
            entries = list((self.media_dir / THUMBS_DIR).iterdir())
        except OSError:
            entries = []
        for e in entries:
            try:
                if e.name.endswith('.part') and LIGHT_SUFFIX + '.' in e.name:
                    # A transcode a crash or SIGKILL interrupted.
                    with self._lock:
                        busy = self._current_tmp == e
                    if not busy:
                        e.unlink()
                    continue
                for suf in (LIGHT_SUFFIX, LIGHT_FAIL, LIGHT_NO):
                    if e.name.endswith(suf) and not (self.media_dir / e.name[:-len(suf)]).exists():
                        e.unlink()
                        break
            except OSError:
                pass

    def _run(self):
        while True:
            _, _, name = self._q.get()
            again = False
            try:
                again = self._make(name)
            except Exception as e:      # the worker must outlive any one file
                sys.stderr.write(f"[{self.tag}] light copy of {name} failed: {e}\n")
            finally:
                with self._lock:
                    self._pending.discard(name)
            if again:
                # Its enqueue() was swallowed while this name was in progress.
                self.enqueue(name, priority=0)

    def _make(self, name):
        src = self.media_dir / name
        if not src.is_file() or self._settled(name):
            return
        light, fail, no = self.paths(name)
        try:
            (self.media_dir / THUMBS_DIR).mkdir(exist_ok=True)
        except OSError:
            return
        before = _identity(src)
        probe = probe_video(src)
        if _identity(src) != before:
            return _identity(src) is not None   # replaced: probe it again
        if probe is None:
            touch_marker(fail)
            return
        if not needs_light(probe):
            touch_marker(no)
            return
        tmp = light.with_name(light.name + '.' + secrets.token_hex(4) + '.part')
        with self._lock:
            self._current_tmp = tmp
        t0 = time.monotonic()
        try:
            ok = transcode_light(src, tmp, probe)
            if ok and _identity(src) == before:
                os.replace(tmp, light)
        finally:
            with self._lock:
                self._current_tmp = None
            try:
                tmp.unlink()
            except OSError:
                pass
        if _identity(src) != before:
            # Deleted (or deleted and replaced by a new upload under the same
            # name) while we worked: this copy belongs to neither. A
            # replacement gets its own pass (True: queue it again).
            if _identity(src) is None:
                for p in (light, fail, no):
                    try:
                        p.unlink()
                    except OSError:
                        pass
                return False
            return True
        if not ok:
            touch_marker(fail)
            return
        sys.stderr.write(
            f"[{self.tag}] light copy: {name} {probe['width']}x{probe['height']} "
            f"{probe['bitrate'] // 1000}kb/s {probe['codec']} -> "
            f"{human_size(light.stat().st_size)} in {time.monotonic() - t0:.0f}s\n")


# The add controls and the lightbox download button are spliced into PAGE_HTML
# per request, so a view-only guest's page doesn't carry them at all rather
# than carrying them hidden. Everyone else gets exactly these bytes back.
UPLOAD_UI_HTML = r"""  <div class="p-drop dropzone" id="dropzone">
    <div class="dz-hint" id="dzHint">Drop files here, or</div>
    <div class="btn-row">
      <label class="p-btn pbtn">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3l5 5h-3v6h-4V8H7zM5 18h14v2H5z"/></svg>
        <span id="chooseLabel">Choose Files</span>
        <input type="file" id="fileInput" multiple>
      </label>
      <label class="p-btn p-btn--ghost pbtn">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 4h6l1.2 2H20a1 1 0 011 1v12a1 1 0 01-1 1H4a1 1 0 01-1-1V7a1 1 0 011-1h3.8zm3 4a5 5 0 100 10 5 5 0 000-10z"/></svg>
        <span>Take Photo</span>
        <input type="file" id="camInput" accept="image/*" capture="environment">
      </label>
      <label class="p-btn p-btn--ghost pbtn" id="vidBtn">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 6h11a1 1 0 011 1v3.2l4-2.6v8.8l-4-2.6V17a1 1 0 01-1 1H4a1 1 0 01-1-1V7a1 1 0 011-1z"/></svg>
        <span>Record Video</span>
        <input type="file" id="vcamInput" accept="video/*" capture="environment">
      </label>
    </div>
    <div class="progress-wrap" id="progressWrap" hidden>
      <div class="progress-text" id="progressText">0%</div>
      <div class="p-progress"><div class="p-progress-fill progress-fill" id="progressFill"></div></div>
    </div>
  </div>
  <div class="p-notice p-notice--error failed" id="failed" hidden>
    <ul class="failed-list" id="failedList"></ul>
    <button type="button" class="p-btn p-btn--ghost p-btn--sm" id="retryBtn">Retry failed</button>
  </div>
  <div class="limits" id="limits"></div>
"""

DOWNLOAD_BTN_HTML = r"""    <a id="lbDownload" href="#" download>
      <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 16l-5-5h3V4h4v7h3zM5 18h14v2H5z"/></svg>Download</a>
"""

PAGE_HTML = r"""<!DOCTYPE html>
<html lang="en" data-app="media">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="dark light">
<meta name="referrer" content="no-referrer">
<title>__TITLE__</title>
__PORCH_CSS__
<style nonce="__NONCE__">
body{padding-bottom:env(safe-area-inset-bottom)}
.p-shell{gap:18px}
.head{gap:8px}
.head .p-title{font-size:clamp(30px,8vw,40px)}
.head-meta{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px}
.badge.guest{background:var(--veil);color:var(--muted)}

/* ---- upload ---- */
.dropzone{padding:22px 16px;gap:14px;cursor:default}
.dz-hint{font-size:14px;color:var(--muted)}
.btn-row{display:flex;gap:10px;justify-content:center;flex-wrap:wrap;width:100%}
.pbtn{position:relative}
.pbtn svg{width:18px;height:18px;fill:currentColor;flex:0 0 18px}
.pbtn input{position:absolute;inset:auto auto 0 0;width:1px;height:1px;opacity:0;overflow:hidden}
.pbtn:focus-within{outline:2px solid var(--accent);outline-offset:2px}
.progress-wrap{width:100%;display:flex;flex-direction:column;gap:8px;text-align:left}
.progress-wrap[hidden]{display:none}
.progress-text{font-size:13px;color:var(--muted);font-variant-numeric:tabular-nums;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.failed{display:flex;flex-direction:column;gap:10px;align-items:flex-start}
.failed-list{list-style:none;margin:0;padding:0;font:13px/1.5 var(--font-mono);color:var(--danger)}
.limits{text-align:center;font-size:13px;color:var(--muted)}
.limits:empty{display:none}
.msg:empty{display:none}
.msg{display:block}
.msg.err{background:var(--danger-soft);border-color:var(--danger-line)}
.msg.ok{background:var(--ok-soft);border-color:var(--ok-line)}

/* ---- grid ---- */
.count{font-size:14px;color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px}
@media (max-width:520px){.grid{grid-template-columns:repeat(3,minmax(0,1fr));gap:4px}}
.tile{position:relative;aspect-ratio:1/1;border-radius:var(--r-md);overflow:hidden;
  background:var(--raised);-webkit-tap-highlight-color:transparent;
  transition:transform .16s ease,box-shadow .16s ease}
@media (max-width:520px){.tile{border-radius:6px}}
@media (hover:hover){.tile:hover{transform:translateY(-2px);box-shadow:var(--shadow)}}
/* The whole tile is one keyboard-reachable control, laid over the artwork —
   a real <button>, not a click handler on a div, and never nested inside
   another button (which the HTML parser would hoist right back out). */
.tile-open{position:absolute;inset:0;z-index:1;border:0;padding:0;background:none;cursor:pointer;
  font:inherit;color:inherit;-webkit-tap-highlight-color:transparent}
.tile-open:focus-visible{outline:none}
.tile:focus-within{outline:3px solid var(--accent);outline-offset:2px}
.tile.reorderable{touch-action:none;user-select:none;-webkit-user-select:none}
.tile img,.tile canvas{width:100%;height:100%;object-fit:cover;display:block;pointer-events:none}
.tile.dragging{opacity:.35;outline:2px dashed var(--accent)}
.tile .kind{position:absolute;left:6px;bottom:6px;display:inline-flex;align-items:center;gap:4px;
  padding:2px 7px;border-radius:6px;background:rgba(18,16,20,.72);color:#F3ECE4;
  font:500 11px var(--font-mono);pointer-events:none}
.tile .kind svg{width:9px;height:9px;fill:currentColor}
.tile-del{position:absolute;top:6px;right:6px;width:30px;height:30px;border-radius:50%;
  border:0;background:rgba(18,16,20,.72);color:#FFB4AE;font-size:18px;line-height:1;cursor:pointer;
  z-index:2;display:flex;align-items:center;justify-content:center}
.tile-del:hover{background:#C23A33;color:#fff}

/* ---- lightbox (always night, whatever the theme) ---- */
.lb{position:fixed;inset:0;z-index:100;background:rgba(12,10,14,.95);
  display:none;align-items:center;justify-content:center;color:#F3ECE4;
  padding:calc(60px + env(safe-area-inset-top)) 12px calc(88px + env(safe-area-inset-bottom))}
.lb.active{display:flex}
/* The stage needs a DEFINITE size: a percentage max-height against an
   auto-height parent resolves to nothing, so a 9:16 clip overflowed the
   screen. Filling the padded box lets the media below shrink to fit any
   aspect ratio. */
.lb-stage{width:100%;height:100%;min-width:0;min-height:0;display:flex;align-items:center;justify-content:center}
.lb-img,.lb-video{max-width:100%;max-height:100%;border-radius:var(--r-md);background:#000;box-shadow:0 0 70px rgba(0,0,0,.6)}
.lb-img{object-fit:contain}
/* Let the video keep its intrinsic size, shrinking to fit — forcing a width
   upscales a phone clip into a blurry mess. */
.lb-video{width:auto;height:auto;object-fit:contain}
.lb-close,.lb-nav{position:absolute;display:flex;align-items:center;justify-content:center;cursor:pointer;
  color:#F3ECE4;background:#262129;border:1px solid rgba(255,240,220,.18);line-height:1}
.lb-close{top:calc(10px + env(safe-area-inset-top));right:12px;width:44px;height:44px;border-radius:var(--r-md);font-size:26px}
.lb-nav{top:50%;transform:translateY(-50%);width:44px;height:64px;border-radius:var(--r-md);font-size:28px}
.lb-prev{left:8px}
.lb-next{right:8px}
.lb-close:hover,.lb-nav:hover{background:#322B36}
.lb-caption{position:absolute;top:calc(22px + env(safe-area-inset-top));left:16px;right:70px;
  color:#A79E95;font:13px var(--font-mono);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.lb-bar{position:absolute;bottom:calc(18px + env(safe-area-inset-bottom));left:50%;transform:translateX(-50%);display:flex;gap:10px}
.lb-bar a,.lb-bar button{display:inline-flex;align-items:center;gap:8px;min-height:44px;padding:0 18px;
  border-radius:var(--r-md);border:1px solid rgba(255,240,220,.18);background:#262129;color:#F3ECE4;
  font:500 14px var(--font-ui);text-decoration:none;cursor:pointer;white-space:nowrap}
.lb-bar a:hover,.lb-bar button:hover{background:#322B36}
.lb-bar button.del{background:transparent;border-color:rgba(240,96,90,.45);color:#F0605A}
.lb-bar button.del:hover{background:rgba(240,96,90,.14)}
.lb-bar svg{width:16px;height:16px;fill:currentColor}
.lb :focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.lb-na{color:#F3ECE4;text-align:center;font-size:15px;padding:28px 22px;
  border:1.5px dashed rgba(255,240,220,.22);border-radius:var(--r-lg);max-width:340px}
.lb-na small{display:block;margin-top:8px;color:#A79E95;font-size:13px}
@media (prefers-reduced-motion:reduce){.tile:hover{transform:none}}
</style>
</head>
<body>
<main class="p-shell p-shell--wide">
  <header class="p-head head">
    <div class="p-kicker">__MARK__<span>__SUBTITLE__</span></div>
    <h1 class="p-title">__TITLE__</h1>
    <div class="head-meta">
      <span class="count" id="count">0 items</span>
      <span class="p-badge p-badge--dot p-badge--accent badge" id="roleBadge"><span id="roleText">owner</span></span>
    </div>
  </header>

__UPLOAD_UI__  <p class="p-notice msg" id="msg" role="status" aria-live="polite"></p>

  <div class="grid" id="grid"></div>
  <div class="p-empty empty" id="empty" hidden>
    <svg width="40" height="40" viewBox="0 0 40 40" fill="none" aria-hidden="true"><path d="M6 18 L20 7 L34 18" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/><path d="M11 17 V33 H29 V17" stroke="currentColor" stroke-width="2.5" stroke-linejoin="round"/><circle cx="20" cy="14" r="2.5" class="p-mark-light"/></svg>
    <div class="p-empty-title">Nothing on the porch yet</div>
    <div class="p-empty-text" id="emptyText">Add the first photo. Everyone with the link will see it.</div>
  </div>
  <footer class="p-foot">shared through porch</footer>
</main>

<div class="lb" id="lightbox" role="dialog" aria-modal="true" aria-label="Media viewer">
  <div class="lb-caption" id="lbCaption"></div>
  <button class="lb-close" id="lbClose" aria-label="Close viewer">&times;</button>
  <button class="lb-nav lb-prev" id="lbPrev" aria-label="Previous item">&#8249;</button>
  <div class="lb-stage" id="lbStage"></div>
  <button class="lb-nav lb-next" id="lbNext" aria-label="Next item">&#8250;</button>
  <div class="lb-bar">
__DOWNLOAD_BTN__    <button class="del" id="lbDelete" hidden>
      <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 7h12l-1 13H7zM9 4h6l1 2H8z"/></svg>Delete</button>
  </div>
</div>

<!-- Server-rendered config. It lives in a JSON script block (not a JS string
     literal) and every '<' is <-escaped server-side, so no value in here
     can close the tag or inject script. -->
<script type="application/json" id="cfg">__CFG_JSON__</script>
<script nonce="__NONCE__">
"use strict";
const CFG = JSON.parse(document.getElementById('cfg').textContent);
const OWNER = CFG.owner === true;     // server re-checks every write; this only hides UI
// View-only guests get a page without the add or download controls; the
// server refuses their uploads and ?dl= fetches regardless.
const CAN_UPLOAD = CFG.canUpload !== false;
const CAN_DOWNLOAD = CFG.canDownload !== false;
const ALLOWED = new Set(CFG.allowed);
const VIDEO_EXT = new Set(CFG.videoExt);
const PREVIEW_EXT = new Set(CFG.previewExt || []);

const $ = (id) => document.getElementById(id);
const dz = $('dropzone'), grid = $('grid'), countEl = $('count'), emptyEl = $('empty');
const msgEl = $('msg'), pw = $('progressWrap'), pf = $('progressFill'), pt = $('progressText');

let items = [];      // ordered [{name,size,modified,kind}]
let busy = false;    // suppresses the poll while an upload is in flight
let listFailing = false;

/* ---- helpers ---- */
function getExt(name){const i=name.lastIndexOf('.');return i>0?name.slice(i).toLowerCase():'';}
function isVideo(name){return VIDEO_EXT.has(getExt(name));}
function humanSize(n){
  const u=['B','KB','MB','GB']; let i=0; n=n||0;
  while(n>=1024&&i<u.length-1){n/=1024;i++;}
  return (i===0?n+' B':n.toFixed(1)+' '+u[i]);
}
function say(text, kind){
  msgEl.textContent = text;                 // textContent, never innerHTML:
  msgEl.className = 'p-notice msg' + (kind?' '+kind:'');   // filenames are untrusted text
  if(text) setTimeout(()=>{ if(msgEl.textContent===text){msgEl.textContent=''; msgEl.className='p-notice msg';} }, 6000);
}
function mediaURL(name, dl){
  return '/media/' + encodeURIComponent(name) + (dl ? '?dl=1' : '');
}
function lightURL(name){ return '/light/' + encodeURIComponent(name); }
/* The phone-sized copy (720p, ~3 Mbps) suits a phone or a slow link; a
   desktop on a good connection gets the original. */
function preferLight(){
  const c = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
  if(c){
    if(c.saveData) return true;
    if(/2g|3g/.test(c.effectiveType || '')) return true;
    if(typeof c.downlink === 'number' && c.downlink > 0 && c.downlink < 8) return true;
  }
  try{
    if(matchMedia('(pointer:coarse)').matches && Math.min(screen.width, screen.height) <= 900) return true;
  }catch(e){}
  return false;
}

/* Deterministic poster for videos we couldn't thumbnail (no ffmpeg on the
   host). Same generative idea as the music player's cover art. */
function hashStr(s){let h=2166136261;for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,16777619);}return h>>>0;}
function drawPoster(canvas, name){
  const h=hashStr(name), ctx=canvas.getContext('2d');
  const w=canvas.width, ht=canvas.height;
  const hue1=h%360, hue2=(hue1+55+(h>>8)%110)%360;
  const g=ctx.createLinearGradient(0,0,w,ht);
  g.addColorStop(0,'hsl('+hue1+' 62% 44%)');
  g.addColorStop(1,'hsl('+hue2+' 58% 28%)');
  ctx.fillStyle=g; ctx.fillRect(0,0,w,ht);
  ctx.globalAlpha=.16; let r=h;
  for(let i=0;i<5;i++){
    r=(r*1103515245+12345)&0x7fffffff;
    ctx.fillStyle=(i%2)?'#fff':'#000';
    ctx.fillRect((r>>4)%w, 0, w*(0.10+(r%28)/100), ht);
  }
  ctx.globalAlpha=1;
}

/* ---- upload ----
   One request per file, sequentially. Each file gets its own progress line,
   its own (correct) error message, and a retry — so one oversized clip no
   longer fails the whole batch with a misleading "per-file limit" error. */
const queue = [];
let failed = [];          // [{file, error, retry}]
let sending = false, batchTotal = 0, batchIndex = 0, batchOk = 0;

function upload(fileList){
  let skipped = 0;
  for(const f of fileList){
    // Client-side triage only — the server re-validates by magic bytes.
    if(!ALLOWED.has(getExt(f.name))){ skipped++; continue; }
    if(f.size > CFG.maxFile){
      failed.push({file:f, error:'larger than the ' + humanSize(CFG.maxFile) + ' per-file limit', retry:false});
      continue;
    }
    queue.push(f); batchTotal++;
  }
  if(skipped) say(skipped + ' file(s) skipped: unsupported type', 'err');
  renderFailed();
  pump();
}

__TUS_JS__
function showProgress(f, sent, total){
  const pct = total ? Math.round(sent/total*100) : 0;
  pf.style.width = pct+'%';
  pt.textContent = (batchTotal>1 ? batchIndex+' of '+batchTotal+' · ' : '') + f.name + ' · ' + pct + '%';
}
/* Resumable (tus) first: a phone whose screen locks mid-upload picks up
   where it stopped. Servers without /tus/ get the one-shot multipart POST. */
function sendOne(f){
  return PorchTus.upload(f, {endpoint:'/tus/', onProgress:(s,t)=>showProgress(f, s, t)})
    .then((res)=>res.fallback ? sendMultipart(f) : res)
    .catch(()=>sendMultipart(f));
}
function sendMultipart(f){
  return new Promise((resolve)=>{
    const fd = new FormData();
    fd.append('file', f, f.name);
    const xhr = new XMLHttpRequest();
    xhr.upload.onprogress = (e)=>{
      if(!e.lengthComputable) return;
      showProgress(f, e.loaded, e.total);
    };
    xhr.onload = ()=>{
      let r = null;
      try{ r = JSON.parse(xhr.responseText); }catch(e){}
      const saved = (r && Array.isArray(r.files)) ? r.files : [];
      if(xhr.status >= 200 && xhr.status < 300 && saved.length){ resolve({ok:true}); return; }
      const rej = (r && Array.isArray(r.rejected) && r.rejected.length) ? r.rejected[0].reason : null;
      resolve({ok:false, error: rej || (r && r.message) || ('HTTP ' + xhr.status),
               retry: xhr.status === 0 || xhr.status === 503 || xhr.status >= 500});
    };
    xhr.onerror = ()=>resolve({ok:false, error:'network error', retry:true});
    xhr.open('POST','/upload');
    xhr.send(fd);
  });
}

function pump(){
  if(sending) return;
  const f = queue.shift();
  if(!f){
    busy = false; pw.hidden = true;
    if(batchTotal){
      const bad = batchTotal - batchOk;
      if(bad) say(bad + ' of ' + batchTotal + ' upload' + (batchTotal===1?'':'s') + ' failed — see below', 'err');
      else say('Added ' + batchOk + ' item' + (batchOk===1?'':'s'), 'ok');
    }
    batchTotal = batchIndex = batchOk = 0;
    return;
  }
  sending = true; busy = true; batchIndex++;
  pw.hidden = false; pf.style.width = '0%';
  pt.textContent = (batchTotal>1 ? batchIndex+' of '+batchTotal+' · ' : '') + f.name;
  sendOne(f).then((res)=>{
    sending = false;
    if(res.ok) batchOk++;
    else failed.push({file:f, error:res.error, retry:res.retry !== false});
    renderFailed();
    refresh();               // diffed, so new items appear as each file lands
    pump();
  });
}

function renderFailed(){
  const box = $('failed');
  if(!box) return;
  const ul = $('failedList');
  ul.replaceChildren(...failed.map((x)=>{
    const li = document.createElement('li');
    li.textContent = x.file.name + ': ' + x.error;   // textContent: names are untrusted
    return li;
  }));
  box.hidden = failed.length === 0;
  $('retryBtn').hidden = !failed.some((x)=>x.retry);
}

/* ---- listing ---- */
function refresh(){
  return fetch('/list', {credentials:'same-origin'})
    .then((r)=>{ if(!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
    .then((list)=>{
      if(listFailing){ listFailing = false; say('Back online', 'ok'); }
      items = Array.isArray(list) ? list : [];
      render();
    })
    .catch((e)=>{
      // Surface it (once) in the live region instead of swallowing it.
      if(!listFailing){ listFailing = true; say('Could not refresh the gallery (' + e.message + ') — retrying', 'err'); }
    });
}

function sigOf(it){ return it.name + '|' + it.size + '|' + it.modified; }

function buildTile(it){
  const video = isVideo(it.name);
  const tile = document.createElement('div');
  tile.className = 'tile' + (OWNER ? ' reorderable' : '');
  tile.dataset.name = it.name;
  tile.dataset.sig = sigOf(it);

  const img = document.createElement('img');
  img.loading = 'lazy';
  img.decoding = 'async';
  img.alt = '';                          // decorative: the button carries the label
  img.src = '/thumb/' + encodeURIComponent(it.name) + '?v=' + encodeURIComponent(it.modified);
  img.addEventListener('error', ()=>{
    // No server-side thumbnail (video on a host without ffmpeg, or an
    // image Pillow can't decode) -> draw a generative poster instead.
    const c = document.createElement('canvas');
    c.width = 300; c.height = 300;
    drawPoster(c, it.name);
    if(img.parentNode) img.parentNode.replaceChild(c, img);
  });
  tile.appendChild(img);

  if(video){
    const kind = document.createElement('span');
    kind.className = 'kind';
    kind.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 5v14l11-7z"/></svg>';
    kind.appendChild(document.createTextNode('video'));
    tile.appendChild(kind);
  }

  const open = document.createElement('button');
  open.type = 'button';
  open.className = 'tile-open';
  // setAttribute/textContent everywhere: a filename is untrusted text and
  // never gets near innerHTML.
  open.setAttribute('aria-label',
    (video ? 'Play video ' : 'View photo ') + it.name + ', ' + humanSize(it.size));
  open.addEventListener('click', ()=>{
    // A drag ends with a pointerup that the browser also turns into a click
    // on this overlay; a short timestamp guard tells the two apart.
    if(Date.now() - lastDragEnd < 300) return;
    const idx = items.findIndex(x=>x.name===it.name);
    if(idx>=0) openLightbox(idx);
  });
  tile.appendChild(open);

  if(OWNER){
    const del = document.createElement('button');
    del.type = 'button';
    del.className = 'tile-del';
    del.title = 'Delete';
    del.setAttribute('aria-label', 'Delete ' + it.name);
    del.textContent = '×';
    del.addEventListener('pointerdown', e=>e.stopPropagation());
    del.addEventListener('click', e=>{ e.stopPropagation(); e.preventDefault(); removeItem(it.name); });
    tile.appendChild(del);
    attachDrag(tile);
  }
  return tile;
}

/* Diff the grid instead of rebuilding it: unchanged tiles (same name, size
   and mtime) keep their DOM node and their already-loaded <img>, so the
   10s poll costs nothing when nothing changed and never re-requests every
   thumbnail. */
function render(){
  countEl.textContent = items.length + (items.length===1 ? ' item' : ' items');
  emptyEl.hidden = items.length > 0;
  const existing = new Map();
  for(const t of grid.children) existing.set(t.dataset.name, t);
  const want = items.map((it)=>{
    const t = existing.get(it.name);
    return (t && t.dataset.sig === sigOf(it)) ? t : buildTile(it);
  });
  const cur = Array.from(grid.children);
  const same = cur.length === want.length && cur.every((t, i)=>t === want[i]);
  if(!same) grid.replaceChildren(...want);
}

/* ---- mutations (owner only; the server enforces it regardless) ---- */
function removeItem(name){
  fetch('/delete', {
    method:'POST', credentials:'same-origin',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({name})
  }).then(r=>r.json().then(j=>({ok:r.ok, j}))).then(({ok,j})=>{
    if(!ok){ say((j && j.message) || 'Delete failed', 'err'); return; }
    if(lbIndex>=0 && items[lbIndex] && items[lbIndex].name===name) closeLightbox();
    refresh();
  }).catch(()=>say('Delete failed','err'));
}

function sendReorder(){
  const order = Array.from(grid.querySelectorAll('.tile')).map(t=>t.dataset.name);
  fetch('/reorder', {
    method:'POST', credentials:'same-origin',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({order})
  }).then(r=>{ if(!r.ok) say('Reorder failed','err'); return refresh(); })
    .catch(()=>{ say('Reorder failed','err'); refresh(); });
}

/* ---- pointer drag reorder (mouse + touch), owner only ---- */
const DRAG_THRESHOLD = 8;   // px before a press counts as a drag, not a tap
let drag = null, lastDragEnd = 0;
function attachDrag(tile){ tile.addEventListener('pointerdown', onDown); }
function onDown(e){
  if(e.button !== undefined && e.button !== 0) return;
  const tile = e.currentTarget;
  drag = {tile, x:e.clientX, y:e.clientY, moved:false, pointerId:e.pointerId};
  // Capture only once a drag actually starts (onMove): capturing here
  // retargets the plain tap's click from .tile-open to the tile, so the
  // owner could never open the lightbox.
  tile.addEventListener('pointermove', onMove);
  tile.addEventListener('pointerup', onUp);
  tile.addEventListener('pointercancel', onUp);
}
function onMove(e){
  if(!drag) return;
  if(!drag.moved && Math.hypot(e.clientX-drag.x, e.clientY-drag.y) < DRAG_THRESHOLD) return;
  if(!drag.moved){
    drag.moved = true;
    drag.tile.classList.add('dragging');
    try{ drag.tile.setPointerCapture(drag.pointerId); }catch(_){}
  }
  e.preventDefault();
  const target = elTileUnder(e.clientX, e.clientY);
  if(target && target !== drag.tile){
    const tiles = Array.from(grid.querySelectorAll('.tile'));
    if(tiles.indexOf(drag.tile) < tiles.indexOf(target)) grid.insertBefore(drag.tile, target.nextSibling);
    else grid.insertBefore(drag.tile, target);
  }
}
function elTileUnder(x,y){ const el=document.elementFromPoint(x,y); return el?el.closest('.tile'):null; }
function onUp(){
  if(!drag) return;
  const t = drag.tile;
  t.removeEventListener('pointermove', onMove);
  t.removeEventListener('pointerup', onUp);
  t.removeEventListener('pointercancel', onUp);
  try{ t.releasePointerCapture(drag.pointerId); }catch(_){}
  if(drag.moved){ t.classList.remove('dragging'); lastDragEnd = Date.now(); sendReorder(); }
  drag = null;
}

/* ---- lightbox ---- */
const lb = $('lightbox'), lbStage = $('lbStage'), lbCaption = $('lbCaption');
const lbDownload = $('lbDownload'), lbDelete = $('lbDelete');
let lbIndex = -1, lastFocus = null;

function openLightbox(idx){
  const it = items[idx];
  if(!it) return;
  lbIndex = idx;
  if(!lb.classList.contains('active')) lastFocus = document.activeElement;
  lbStage.replaceChildren();
  if(isVideo(it.name)){
    const v = document.createElement('video');
    v.className = 'lb-video';
    v.controls = true;
    v.playsInline = true;               // iOS: play in place instead of fullscreen
    v.preload = 'metadata';
    v.poster = '/thumb/' + encodeURIComponent(it.name);
    // ranged either way, so seeking works on iOS Safari. If the chosen
    // source fails, try the other one once (the light copy also rescues an
    // original whose codec this browser can't play).
    const useLight = it.light === true && preferLight();
    v.src = useLight ? lightURL(it.name) : mediaURL(it.name);
    let swapped = false;
    v.addEventListener('error', ()=>{
      if(swapped || !v.isConnected) return;
      if(useLight){ swapped = true; v.src = mediaURL(it.name); }
      else if(it.light === true){ swapped = true; v.src = lightURL(it.name); }
    });
    v.addEventListener('loadedmetadata', ()=>fitVideo(v));
    if(!CAN_DOWNLOAD){
      // Drop the browser's own save paths. A deterrent, not a lock: the
      // stream itself still has to reach the browser to play.
      v.setAttribute('controlsList', 'nodownload');
      v.disablePictureInPicture = true;
      v.addEventListener('contextmenu', e=>e.preventDefault());
    }
    lbStage.appendChild(v);
  }else{
    const img = document.createElement('img');
    img.className = 'lb-img';
    img.alt = it.name;
    // HEIC/TIFF don't render in most browsers: ask for a server-made JPEG.
    const needsPreview = PREVIEW_EXT.has(getExt(it.name));
    img.src = needsPreview ? '/preview/' + encodeURIComponent(it.name) : mediaURL(it.name);
    img.addEventListener('error', ()=>{
      // A clear state instead of a broken-image icon.
      const na = document.createElement('div');
      na.className = 'lb-na';
      na.textContent = 'Preview not available for this file';
      const hint = document.createElement('small');
      hint.textContent = CAN_DOWNLOAD ? 'Use Download to open the original.' : 'This format can\'t be shown in the browser.';
      na.appendChild(hint);
      if(img.parentNode) img.parentNode.replaceChild(na, img);
    });
    if(!CAN_DOWNLOAD){
      img.draggable = false;
      img.addEventListener('contextmenu', e=>e.preventDefault());
    }
    lbStage.appendChild(img);
  }
  lbCaption.textContent = it.name + '  ·  ' + humanSize(it.size);
  if(lbDownload){
    lbDownload.href = mediaURL(it.name, true);
    lbDownload.setAttribute('download', it.name);
  }
  lbDelete.hidden = !OWNER;
  lb.classList.add('active');
  document.body.style.overflow = 'hidden';
  $('lbClose').focus();
}
// Chrome sizes an auto-sized <video> by its POSTER (a 480px thumb), not the
// video, so a landscape clip sat postage-stamp small on a desktop screen.
// Once the real dimensions are known, fit them to the stage by hand: scale
// down to fit, never up (upscaling a phone clip just blurs it).
function fitVideo(v){
  if(!v.videoWidth || !v.isConnected) return;
  const r = lbStage.getBoundingClientRect();
  const k = Math.min(1, r.width / v.videoWidth, r.height / v.videoHeight);
  v.style.width = Math.floor(v.videoWidth * k) + 'px';
  v.style.height = Math.floor(v.videoHeight * k) + 'px';
}
window.addEventListener('resize', ()=>{
  const v = lbStage.querySelector('.lb-video');
  if(v) fitVideo(v);
});
function closeLightbox(){
  lb.classList.remove('active');
  lbStage.replaceChildren();     // drops the <video>, stopping any download
  lbIndex = -1;
  document.body.style.overflow = '';
  if(lastFocus && lastFocus.focus) lastFocus.focus();
}
function lbStep(d){
  if(!items.length) return;
  openLightbox((lbIndex + d + items.length) % items.length);
}
$('lbClose').addEventListener('click', closeLightbox);
$('lbPrev').addEventListener('click', e=>{e.stopPropagation(); lbStep(-1);});
$('lbNext').addEventListener('click', e=>{e.stopPropagation(); lbStep(1);});
lbDelete.addEventListener('click', e=>{
  e.stopPropagation();
  const it = items[lbIndex];
  if(it) removeItem(it.name);
});
lb.addEventListener('click', e=>{ if(e.target === lb || e.target === lbStage) closeLightbox(); });
document.addEventListener('keydown', e=>{
  if(!lb.classList.contains('active')) return;
  if(e.key === 'Escape'){ closeLightbox(); }
  else if(e.key === 'ArrowLeft'){ lbStep(-1); }
  else if(e.key === 'ArrowRight'){ lbStep(1); }
  else if(e.key === 'Tab'){
    // Keep focus inside the dialog while it is open.
    const f = [...lb.querySelectorAll('button:not([hidden]),a[href],video')].filter(el=>el.offsetParent!==null||el.tagName==='VIDEO');
    if(!f.length) return;
    const first = f[0], last = f[f.length-1];
    if(e.shiftKey && document.activeElement === first){ e.preventDefault(); last.focus(); }
    else if(!e.shiftKey && document.activeElement === last){ e.preventDefault(); first.focus(); }
  }
});
/* touch swipe between items */
let touchX = null, touchY = null;
lb.addEventListener('touchstart', e=>{
  if(e.target.closest('video')) return;   // let the native controls own the gesture
  touchX = e.changedTouches[0].clientX; touchY = e.changedTouches[0].clientY;
}, {passive:true});
lb.addEventListener('touchend', e=>{
  if(touchX === null) return;
  const dx = e.changedTouches[0].clientX - touchX;
  const dy = e.changedTouches[0].clientY - touchY;
  touchX = null;
  if(Math.abs(dx) > 55 && Math.abs(dx) > Math.abs(dy)*1.5) lbStep(dx < 0 ? 1 : -1);
}, {passive:true});

/* ---- wiring ---- */
if(CAN_UPLOAD){
  const fi = $('fileInput'), cam = $('camInput'), vcam = $('vcamInput');
  fi.accept = CFG.accept;
  fi.addEventListener('change', ()=>{ if(fi.files.length) upload(fi.files); fi.value=''; });
  cam.addEventListener('change', ()=>{ if(cam.files.length) upload(cam.files); cam.value=''; });
  vcam.addEventListener('change', ()=>{ if(vcam.files.length) upload(vcam.files); vcam.value=''; });
  if(!CFG.video) $('vidBtn').hidden = true;
  $('chooseLabel').textContent = CFG.video ? 'Choose Photos & Video' : 'Choose Photos';
  $('dzHint').textContent = CFG.video ? 'Drop photos or video here, or' : 'Drop photos here, or';
  $('limits').textContent = 'up to ' + humanSize(CFG.maxFile) + ' per file · ' + humanSize(CFG.maxTotal) + ' per gallery';

  $('retryBtn').addEventListener('click', ()=>{
    const again = failed.filter((x)=>x.retry).map((x)=>x.file);
    failed = failed.filter((x)=>!x.retry);
    for(const f of again){ queue.push(f); batchTotal++; }
    renderFailed();
    pump();
  });

  dz.addEventListener('dragover', e=>{e.preventDefault(); dz.classList.add('dragover');});
  dz.addEventListener('dragleave', ()=>dz.classList.remove('dragover'));
  dz.addEventListener('drop', e=>{
    e.preventDefault(); dz.classList.remove('dragover');
    if(e.dataTransfer.files.length) upload(e.dataTransfer.files);
  });
}
$('roleText').textContent = OWNER ? 'Owner · full control' : (CAN_UPLOAD ? 'Look and add' : 'View only');
if(!OWNER) $('roleBadge').classList.add('guest');
if(!CAN_UPLOAD) $('emptyText').textContent = 'Nothing has been shared here yet.';
else if(CFG.accept === 'image/*,video/*') $('emptyText').textContent = 'Add the first photo or clip. Everyone with the link will see it.';

refresh();
// Live updates: someone else adding to the gallery shows up without a reload.
// Paused while uploading, while the owner is mid-drag (a re-render would yank
// the tile out from under the pointer), when hidden, and in the lightbox.
setInterval(()=>{ if(!busy && !drag && !document.hidden && !lb.classList.contains('active')) refresh(); }, 10000);
</script>
__SIGNIN__
</body>
</html>"""


class MediaHandler(HardenedHandlerMixin, BaseHTTPRequestHandler):

    protocol_version = 'HTTP/1.1'

    media_dir = Path('.')
    devices_path = ''
    open_mode = False       # True => everyone is the owner (legacy bin/photos)
    view_only = False       # True => guests may watch, not upload or download
    no_guest_upload = False  # True => guests may watch and download, not upload
    kinds = ('image',)
    title = 'Gallery'
    subtitle = 'photos on a porch'
    max_file = DEFAULT_MAX_FILE_MB * 1024 * 1024
    max_total = DEFAULT_MAX_TOTAL_MB * 1024 * 1024
    max_files = MAX_FILES
    min_free = DEFAULT_MIN_FREE_MB * 1024 * 1024
    upload_slots = UploadSlots(total=4, per_ip=2)
    tag = 'mediaserver'

    _quota = None
    _quota_lock = threading.Lock()
    _tus = None
    _tus_lock = threading.Lock()
    _light = None
    _light_lock = threading.Lock()

    @classmethod
    def quota(cls):
        """The gallery's shared Quota, created on first use (one per class).
        Unfinished resumable uploads count as if they had landed."""
        with cls._quota_lock:
            q = cls.__dict__.get('_quota')
            if q is None:
                def scan():
                    used, items = gallery_usage(cls.media_dir, cls.kinds)
                    p_used, p_items = cls.tus().pending_usage()
                    return used + p_used, items + p_items
                q = Quota(cls.media_dir, scan,
                          cls.max_total, cls.max_files, cls.min_free,
                          label='gallery', item_word='items')
                cls._quota = q
            return q

    @classmethod
    def tus(cls):
        """The gallery's resumable-upload endpoint (/tus/), one per class."""
        with cls._tus_lock:
            t = cls.__dict__.get('_tus')
            if t is None:
                t = porch_tus.TusServer(
                    cls.media_dir, quota=cls.quota, max_size=cls.max_file,
                    finalize=cls._tus_finalize, on_head=cls._tus_on_head,
                    on_create=cls._tus_on_create, tag=cls.tag)
                cls._tus = t
            return t

    @classmethod
    def light(cls):
        """The gallery's light-copy worker, one per class."""
        with cls._light_lock:
            lc = cls.__dict__.get('_light')
            if lc is None:
                lc = LightCopies(cls.media_dir, cls.tag)
                cls._light = lc
            return lc

    # ---- plumbing -----------------------------------------------------------

    def log_message(self, format, *args):
        method = args[0] if args else ''
        if isinstance(method, str) and method.startswith('GET'):
            return
        sys.stderr.write(f"[{self.tag}] {self.address_string()} - {format % args}\n")

    def _security_headers(self):
        """nosniff (so an upload labelled image/png is never re-sniffed as
        HTML), no-referrer, DENY framing: porch_http.security_headers."""
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

    # ---- auth ---------------------------------------------------------------

    def _is_owner(self):
        """True iff this request may delete/reorder.

        porch_auth decides: a porch_host cookie minted for this host by a live
        admin device, or (while the migration runs) a live owner's cush_auth
        cookie. No registry means no owners, never "everyone". --open
        (explicit opt-in, loudly warned about at startup) is the one
        exception: it makes every visitor the owner.
        """
        if self.open_mode:
            return True
        return porch_auth.request_is_owner(self, self.devices_path)

    def _signin_html(self):
        """The small "Owner? Sign in" link for a visitor who is not the owner,
        pointing at this host's /__porch/start handoff. '' when the visitor
        is the owner or no owner registry is configured."""
        if self.open_mode:
            return ''
        url = porch_auth.signin_url(self, self.devices_path)
        if not url:
            return ''
        return (f'<a class="porch-signin" href="{html.escape(url, quote=True)}" '
                'rel="nofollow">Owner? Sign in</a>')

    def _guest_locked(self):
        """True iff --view-only applies to this request (a non-owner).

        The owner keeps upload and download in view-only mode. With no
        devices registry nobody is the owner, so nobody can upload at all.
        """
        return self.view_only and not self._is_owner()

    def _upload_locked(self):
        """True iff this request may not add media: --view-only or
        --no-guest-upload, for a non-owner."""
        return (self.view_only or self.no_guest_upload) and not self._is_owner()

    def _same_origin(self):
        """CSRF check for writes (porch_http.same_origin). /upload has no
        cookie requirement at all, so this Origin/Referer-vs-Host check is the
        only thing between a random site and this disk."""
        return same_origin(self)

    # ---- path safety --------------------------------------------------------

    def _safe_target(self, raw):
        """Sanitized name + symlink-refusing containment check in media_dir."""
        return safe_child(self.media_dir, raw)

    def _is_listable(self, name):
        mime = ext_mime(name)
        return bool(mime) and kind_of_mime(mime) in self.kinds

    # ---- serving media ------------------------------------------------------

    def _serve_types(self, target, name):
        """(content_type, disposition) for a stored file.

        The stored extension was chosen by us from sniffed content, but a file
        could also have been dropped into the directory out of band, so the
        first bytes are re-sniffed on the way out. Anything whose content and
        extension disagree — or that we can't identify at all — goes out as
        an opaque download instead of something the browser will render.
        """
        declared = ext_mime(name)
        try:
            with open(target, 'rb') as f:
                head = f.read(SNIFF_BYTES)
        except OSError:
            head = b''
        sniffed = sniff_mime(head)
        if not declared or not sniffed or kind_of_mime(sniffed) != kind_of_mime(declared):
            return 'application/octet-stream', 'attachment'
        return sniffed, 'inline'

    def _parse_range(self, header, size):
        return parse_range(header, size)

    def _stream(self, target, name, force_download=False, cache='private, max-age=300'):
        try:
            size = target.stat().st_size
        except OSError:
            self._err('Not found', 404)
            return
        ctype, disp = self._serve_types(target, name)
        if force_download:
            disp = 'attachment'
        # `name` is [A-Za-z0-9._-] only (sanitize_filename): header-safe.
        stream_file(self, target, size, ctype, disp, name, cache=cache)

    # ---- thumbnails ---------------------------------------------------------

    def _serve_thumb(self, raw):
        self._serve_derived(raw, 'thumb')

    def _serve_preview(self, raw):
        self._serve_derived(raw, 'preview')

    def _serve_derived(self, raw, which):
        """Serve a cached thumbnail ('thumb') or lightbox preview ('preview').

        Generation is CPU-heavy and reachable by anyone with the link, so:
          * one job per file at a time (a burst of requests for the same
            thumbnail waits for the first instead of starting N decoders);
          * at most two jobs overall (JobGate); a request that can't get a
            slot gets 503 + Retry-After instead of queueing forever;
          * a failure is remembered in a marker file and answered with a
            cacheable 404 until the source changes, so an undecodable upload
            isn't re-decoded on every page load.
        """
        target, name = self._safe_target(raw)
        if target is None or not target.is_file() or not self._is_listable(name):
            self._err('Not found', 404)
            return
        mime = ext_mime(name)
        if which == 'preview' and mime not in PREVIEW_MIMES:
            self._err('Not found', 404)
            return

        thumbs = self.media_dir / THUMBS_DIR
        try:
            thumbs.mkdir(exist_ok=True)
        except OSError:
            self._err('Not found', 404)
            return
        # `name` is already sanitized, so these paths stay inside .thumbs.
        suffix = '.jpg' if which == 'thumb' else '.view.jpg'
        cache = thumbs / (name + suffix)
        fail = thumbs / (name + ('.fail' if which == 'thumb' else '.view.fail'))
        no_thumb_headers = {'Cache-Control': f'private, max-age={THUMB_FAIL_MAX_AGE}'}

        if not fresh_against(cache, target):
            if fresh_against(fail, target):
                self._err('No thumbnail', 404, no_thumb_headers)
                return

            def build():
                if fresh_against(cache, target):      # someone else just made it
                    return True
                if fresh_against(fail, target):
                    return False
                tmp = thumbs / (name + '.' + secrets.token_hex(4) + '.part')
                ok = False
                try:
                    if which == 'preview':
                        ok = _image_preview(target, tmp)
                    elif kind_of_mime(mime) == 'video':
                        ok = _video_thumb(target, tmp)
                    else:
                        ok = _image_thumb(target, tmp)
                    if ok:
                        os.replace(tmp, cache)
                except Exception as e:
                    # Pillow can't decode HEIC without pillow-heif, ffmpeg may be
                    # missing entirely. Either way the client draws its own poster.
                    sys.stderr.write(f"[{self.tag}] {which} failed for {name}: {e}\n")
                    ok = False
                finally:
                    try:
                        tmp.unlink()
                    except OSError:
                        pass
                if not ok:
                    touch_marker(fail)
                return ok

            result = _thumb_gate.run(str(cache), build)
            if result is JobGate.BUSY:
                self._err('Busy, try again', 503, {'Retry-After': '3'})
                return
            if not result:
                self._err('No thumbnail', 404, no_thumb_headers)
                return

        try:
            size = cache.stat().st_size
        except OSError:
            self._err('No thumbnail', 404)
            return
        self.send_response(200)
        self.send_header('Content-Type', 'image/jpeg')
        self.send_header('Content-Length', str(size))
        self.send_header('Cache-Control', 'private, max-age=300')
        self.send_header('Content-Security-Policy', "default-src 'none'; sandbox")
        self._security_headers()
        self.end_headers()
        if self.command == 'HEAD':
            return
        with open(cache, 'rb') as f:
            while chunk := f.read(65536):
                try:
                    self.wfile.write(chunk)
                except (BrokenPipeError, ConnectionResetError):
                    self.close_connection = True
                    return
                self.transferred(len(chunk))

    # ---- page ---------------------------------------------------------------

    def _serve_page(self):
        owner = self._is_owner()
        locked = self.view_only and not owner
        upload_locked = (self.view_only or self.no_guest_upload) and not owner
        allowed = sorted(e for e, m in EXT_MIME.items() if kind_of_mime(m) in self.kinds)
        video = 'video' in self.kinds
        cfg = {
            'owner': owner,
            'video': video,
            'allowed': allowed,
            'videoExt': sorted(VIDEO_EXT_MIME),
            'previewExt': sorted(e for e, m in IMAGE_EXT_MIME.items() if m in PREVIEW_MIMES),
            'accept': 'image/*,video/*' if video else 'image/*',
            'maxFile': self.max_file,
            'maxTotal': self.max_total,
        }
        if self.view_only or self.no_guest_upload:
            cfg['canUpload'] = not upload_locked
            cfg['canDownload'] = not locked
        # '<' is escaped so no config value can terminate the <script> block.
        cfg_json = json.dumps(cfg).replace('<', '\\u003c')
        nonce = csp_nonce()

        # Blocks first, so nothing substituted later can smuggle in a marker.
        html_out = PAGE_HTML
        html_out = html_out.replace('__UPLOAD_UI__', '' if upload_locked else UPLOAD_UI_HTML)
        html_out = html_out.replace('__DOWNLOAD_BTN__', '' if locked else DOWNLOAD_BTN_HTML)
        html_out = html_out.replace('__TUS_JS__', porch_tus.TUS_CLIENT_JS)
        html_out = html_out.replace('__MARK__', porch_mark(16))
        html_out = html_out.replace('__PORCH_CSS__', porch_css_tag())
        # html.escape on both title substitutions: the title comes from the
        # tunnel name on the command line, which is not a trusted string.
        html_out = html_out.replace('__TITLE__', html.escape(self.title))
        html_out = html_out.replace('__SUBTITLE__', html.escape(self.subtitle))
        html_out = html_out.replace('__CFG_JSON__', cfg_json)
        html_out = html_out.replace('__SIGNIN__', self._signin_html())
        html_out = html_out.replace('__NONCE__', nonce)
        body = html_out.encode()

        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        # Nonced inline script/style, nothing else may load or run. 'none' for
        # object/base/frame-ancestors kills plugin, base-tag and clickjacking
        # tricks outright.
        self.send_header('Content-Security-Policy', (
            "default-src 'none'; "
            f"script-src 'nonce-{nonce}'; {porch_style_src(nonce)}; "
            "img-src 'self' data:; media-src 'self'; connect-src 'self'; "
            "form-action 'none'; base-uri 'none'; frame-ancestors 'none'"
        ))
        self._security_headers()
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    # ---- routing ------------------------------------------------------------

    def do_HEAD(self):
        if self._tus_path():
            self._tus_request()
            return
        self.do_GET()

    def do_OPTIONS(self):
        if self._tus_path():
            self._tus_request()
            return
        self._err('Not found', 404)

    def do_PATCH(self):
        if self._tus_path():
            self._tus_request()
            return
        self.close_connection = True
        self._err('Not found', 404)

    def do_DELETE(self):
        if self._tus_path():
            self._tus_request()
            return
        self._err('Not found', 404)

    def _tus_path(self):
        return self.tus().owns(urllib.parse.urlparse(self.path).path)

    def _tus_request(self):
        """/tus/: the same gates as /upload, in the same order: same-origin
        for writes, then the view-only lock, then an upload slot for every
        request that carries bytes (POST, PATCH)."""
        method = self.command
        if method in ('POST', 'PATCH', 'DELETE') and not self._same_origin():
            self.close_connection = True
            self._err('Cross-origin request refused', 403)
            return
        if method != 'OPTIONS' and self._upload_locked():
            self.close_connection = True
            self._err('Forbidden — guests cannot add to this gallery', 403)
            return
        slot_ip = None
        if method in ('POST', 'PATCH'):
            slot_ip = client_ip(self)
            if not self.upload_slots.acquire(slot_ip):
                self.close_connection = True
                self._err('Too many uploads in progress, try again shortly', 503,
                          {'Retry-After': '5'})
                return
        try:
            self.tus().handle(self)
        except Exception as e:
            sys.stderr.write(f"[{self.tag}] tus {method} failed: {e}\n")
            self.close_connection = True
            try:
                self._err('Server error', 500)
            except Exception:
                pass
        finally:
            if slot_ip is not None:
                self.upload_slots.release(slot_ip)

    def do_GET(self):
        if serve_asset(self, head=self.command == 'HEAD'):
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip('/')
        query = urllib.parse.parse_qs(parsed.query)

        if path in ('', '/'):
            self._serve_page()
            return

        if path == '/list':
            # Read-only: the reconciled order is computed, never written back
            # here. Only an upload, delete or reorder writes .order.json.
            with _order_lock:
                names = load_order(self.media_dir, self.kinds)
            light = self.light() if light_enabled() else None
            if light:
                light.ensure_scanned(names)
            out = []
            for name in names:
                target = self.media_dir / name
                try:
                    st = target.stat()
                except OSError:
                    continue
                mime = ext_mime(name)
                item = {
                    'name': name,
                    'size': st.st_size,
                    'modified': st.st_mtime,
                    'kind': kind_of_mime(mime),
                }
                if light and item['kind'] == 'video':
                    if light.ready(name):
                        item['light'] = True
                    elif light.pending(name):
                        item['light_pending'] = True
                out.append(item)
            self.send_json(out)
            return

        if path.startswith('/light/'):
            # The phone-sized copy of a video (see LightCopies). Inline and
            # ranged like /media/; it is never offered as a download.
            target, name = self._safe_target(urllib.parse.unquote(path[len('/light/'):]))
            if target is None or not target.is_file() or not self._is_listable(name) \
                    or kind_of_mime(ext_mime(name)) != 'video':
                self._err('Not found', 404)
                return
            light = self.light().ready(name)
            try:
                size = light.stat().st_size if light else -1
            except OSError:
                size = -1
            if size < 0:
                self._err('Not found', 404)
                return
            stem = os.path.splitext(name)[0]
            stream_file(self, light, size, 'video/mp4', 'inline', stem + '.light.mp4')
            return

        if path.startswith('/thumb/'):
            self._serve_thumb(urllib.parse.unquote(path[len('/thumb/'):]))
            return

        if path.startswith('/preview/'):
            self._serve_preview(urllib.parse.unquote(path[len('/preview/'):]))
            return

        # /photo/ is the pre-rename alias; keep it so old links still resolve.
        for prefix in ('/media/', '/photo/'):
            if path.startswith(prefix):
                raw = urllib.parse.unquote(path[len(prefix):])
                target, name = self._safe_target(raw)
                if target is None or not target.is_file() or not self._is_listable(name):
                    self._err('Not found', 404)
                    return
                force_download = bool(query.get('dl'))
                if force_download and self._guest_locked():
                    # Inline (ranged) streaming stays open: playback and
                    # seeking need it. Only the save-to-disk path is refused.
                    self._err('Downloads are disabled for this gallery', 403)
                    return
                self._stream(target, name, force_download=force_download)
                return

        self._err('Not found', 404)

    def do_POST(self):
        if self._tus_path():
            self._tus_request()
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip('/')

        # Every mutating endpoint is same-origin-only. Checked before anything
        # reads the body, so a cross-site POST costs us nothing.
        if not self._same_origin():
            self.close_connection = True
            self._err('Cross-origin request refused', 403)
            return

        if path in ('/delete', '/reorder') and not self._is_owner():
            # Guests may add, never remove or rearrange. The body is unread,
            # so the connection can't be reused.
            self.close_connection = True
            self._err('Forbidden — only the gallery owner can do that', 403)
            return

        if path == '/upload' and self._upload_locked():
            # Refused before the body is read; the connection can't be reused.
            self.close_connection = True
            self._err('Forbidden — guests cannot add to this gallery', 403)
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
            sys.stderr.write(f"[{self.tag}] malformed upload: {e}\n")
            self.close_connection = True
            try:
                self._err('Malformed upload', 400)
            except Exception:
                pass
        except Exception as e:
            sys.stderr.write(f"[{self.tag}] {path} failed: {e}\n")
            self.close_connection = True
            try:
                # Generic text only: internal exception strings can carry paths.
                self._err('Server error', 500)
            except Exception:
                pass
        finally:
            if slot_ip is not None:
                self.upload_slots.release(slot_ip)

    # ---- bodies -------------------------------------------------------------

    def _content_length(self):
        return content_length(self)

    def _read_json_body(self):
        return read_json_body(self, MAX_JSON_BODY)

    # ---- upload -------------------------------------------------------------

    def _handle_upload(self):
        boundary, bad = multipart_boundary(self.headers.get('Content-Type', ''))
        if bad:
            self._err(*bad)
            return

        length = self._content_length()
        if length <= 0:
            # No Content-Length (e.g. chunked) — BaseHTTPRequestHandler does
            # not de-chunk, and reading an unbounded body is the DoS we are
            # avoiding, so refuse it.
            self._err('Content-Length required', 411)
            return
        # First cap: refuse an oversized body before reading a single byte.
        # A batch may hold several files, so the request ceiling is a multiple
        # of the per-file cap, still bounded by what the gallery can hold. The
        # page sends one file per request, so in practice this is per-file.
        max_request = min(self.max_total, self.max_file * 8) + 64 * 1024
        if length > max_request:
            self.close_connection = True
            if length <= self.max_file + 64 * 1024:
                msg = f'Upload is larger than this gallery can hold ({human_size(self.max_total)})'
            else:
                msg = f'Upload request is larger than the {human_size(max_request)} request limit'
            self._err(msg, 413)
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
                        f"[{self.tag}] Saved: {result['name']} ({human_size(result['size'])})"
                        f" from {client_ip(self)}\n")
                else:
                    rejected.append({'name': safe_stem(filename), 'reason': result['reason']})
        except UploadRejected as e:
            # Stop reading the body entirely and hang up after replying.
            aborted = e
            self.close_connection = True
            rejected.append({'name': 'upload', 'reason': e.reason})

        if saved:
            self._after_saved([s['name'] for s in saved])
            status = aborted.status if aborted else 200
            self.send_json({'status': 'ok', 'files': saved, 'rejected': rejected}, status)
            return

        if not rejected:
            self._err('No files found in upload', 400)
            return
        # Nothing landed: surface the first reason with a fitting status.
        reason = rejected[0]['reason']
        status = aborted.status if aborted else (
            413 if ('limit' in reason or 'full' in reason) else 400)
        self.send_json({'status': 'error', 'message': reason,
                        'files': [], 'rejected': rejected}, status)

    @classmethod
    def _reject_reason(cls, head):
        """None if `head` is an acceptable payload, else why it isn't.

        Everything here keys off the magic bytes. The client's extension is
        never consulted, so renaming shell.php to cat.jpg (or hiding an SVG
        with a <script> inside behind .png) changes nothing.
        """
        mime = sniff_mime(head)
        if not mime:
            return 'unrecognised or unsafe file type'
        kind = kind_of_mime(mime)
        if kind not in cls.kinds:
            return f'{kind or "this kind of"} files are not accepted here'
        if mime not in MIME_EXT:
            return 'unsupported file type'
        return None

    def _verify_image(self, path, mime):
        """None if Pillow agrees the stored bytes are an image, else a reason.

        Magic bytes only prove the first few bytes; verify() walks the file's
        structure. Formats this Pillow can't open at all (HEIC without
        pillow-heif, AVIF on older Pillow) are accepted on the sniff alone.
        """
        if not HAVE_PIL:
            return None
        try:
            with open_checked(path) as img:
                img.verify()
        except ValueError as e:
            if 'pixel limit' in str(e):
                return 'image is too large'
            return 'that file is not a valid image'
        except Image.DecompressionBombError:
            return 'image is too large'
        except Exception as e:
            if mime in ('image/heic', 'image/avif') and 'cannot identify' in str(e):
                return None
            return 'that file is not a valid image'
        return None

    def _spool_part(self, filename, chunks, quota):
        """Stream one uploaded part to disk, validating as it arrives.

        Returns {'ok': True, 'name', 'size'} or {'ok': False, 'reason'}. The
        part iterator is always drained so the parser stays in sync even when
        we throw the data away. Bytes are reserved against the gallery's
        shared Quota chunk by chunk (and the item slot up front), so
        concurrent uploads can't jointly overshoot the caps or the free-disk
        floor; a hard limit raises UploadRejected and abandons the request.
        """
        refusal = quota.begin()
        if refusal:
            raise UploadRejected(refusal)
        # Everything after begin() runs inside the try, so every begin() has
        # its end(): new_tmp() raising used to leak the item slot for good.
        tmp = None
        head = b''
        written = 0          # == bytes reserved against the quota
        bad_type = None
        kept = False
        try:
            tmp = new_tmp(self.media_dir)
            with open(tmp, 'wb') as out:
                for chunk in chunks:
                    if len(head) < SNIFF_BYTES:
                        head += chunk[:SNIFF_BYTES - len(head)]
                        if len(head) >= SNIFF_BYTES and bad_type is None:
                            # Type is knowable from the first bytes: decide now
                            # so a wrong-typed file stops consuming disk after
                            # 64 bytes instead of after 512MB. The remaining
                            # chunks are still drained (bounded by max_file) so
                            # sibling parts in the same batch still upload.
                            bad_type = self._reject_reason(head)
                    # Second cap, enforced mid-stream: a lying Content-Length
                    # can't buy more disk than the per-file limit allows.
                    if written + len(chunk) > self.max_file:
                        raise UploadRejected(
                            f'over the {human_size(self.max_file)} per-file limit')
                    if bad_type is None:
                        refusal = quota.add(len(chunk))
                        if refusal:
                            raise UploadRejected(refusal)
                        written += len(chunk)
                        out.write(chunk)

            if written == 0 and bad_type is None:
                return {'ok': False, 'reason': 'empty file'}
            # Short files never reached the SNIFF_BYTES trigger above.
            reason = bad_type if bad_type is not None else self._reject_reason(head)
            if reason:
                return {'ok': False, 'reason': reason}

            name, reason = self._place_media(tmp, head, filename)
            if reason:
                return {'ok': False, 'reason': reason}
            kept = True
            return {'ok': True, 'name': name, 'size': written}
        finally:
            quota.end(written, kept)
            if not kept and tmp is not None:
                drop_tmp(tmp)

    def _place_media(self, tmp, head, filename):
        """(name, None) once a fully written, sniff-approved file is verified
        and placed under a server-chosen name, else (None, reason). Shared by
        the multipart path and the tus finalize hook."""
        mime = sniff_mime(head)
        if kind_of_mime(mime) == 'image':
            reason = self._verify_image(tmp, mime)
            if reason:
                return None, reason
        ext = MIME_EXT[mime]
        name = place_unique(tmp, self.media_dir, name_candidates(safe_stem(filename), ext))
        return name, None

    def _after_saved(self, names):
        """Append new items to the order sidecar; queue video light copies."""
        with _order_lock:
            order = load_order(self.media_dir, self.kinds)
            for n in names:
                if n not in order:
                    order.append(n)
            save_order(self.media_dir, order)
        for n in names:
            self.light().enqueue(n, priority=0)

    # ---- resumable uploads (porch_tus hooks) --------------------------------

    @classmethod
    def _tus_on_head(cls, head):
        """Reject a resumable upload by its first bytes, before it costs disk."""
        return cls._reject_reason(head)

    @classmethod
    def _tus_on_create(cls, meta, length, handler):
        return None          # nothing to check before the bytes: the sniff decides

    @classmethod
    def _tus_finalize(cls, part, up, handler):
        try:
            with open(part, 'rb') as f:
                head = f.read(SNIFF_BYTES)
        except OSError:
            raise porch_tus.TusRejected('upload vanished', 500)
        reason = cls._reject_reason(head)
        if reason:
            raise porch_tus.TusRejected(reason)
        name, reason = handler._place_media(part, head, up.metadata.get('filename') or 'upload')
        if reason:
            raise porch_tus.TusRejected(reason)
        handler._after_saved([name])
        return name

    # ---- delete / reorder ---------------------------------------------------

    def _handle_delete(self):
        data = self._read_json_body()
        if data is None:
            self._err('Invalid JSON body', 400)
            return
        target, name = self._safe_target(data.get('name', ''))
        if target is None or not target.is_file() or not self._is_listable(name):
            self._err('Not found', 404)
            return
        try:
            size = target.stat().st_size
            target.unlink()
        except OSError:
            self._err('Not found', 404)
            return
        self.quota().removed(size)
        for side in sidecar_paths(self.media_dir, name):
            try:
                side.unlink()
            except OSError:
                pass
        with _order_lock:
            names = [n for n in load_order(self.media_dir, self.kinds) if n != name]
            save_order(self.media_dir, names)
        sys.stderr.write(f"[{self.tag}] Deleted: {name}\n")
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
                if (self.media_dir / name).is_file() and self._is_listable(name):
                    cleaned.append(name)
                    seen.add(name)
            # Append anything on disk the client didn't mention (self-heal).
            for entry in _disk_media(self.media_dir, self.kinds):
                if entry.name not in seen:
                    cleaned.append(entry.name)
                    seen.add(entry.name)
            save_order(self.media_dir, cleaned)
        self.send_json({'status': 'ok', 'order': cleaned})


OPEN_WARNING = """
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! --open: EVERY VISITOR IS THE OWNER. Anyone with the link can DELETE and   !!
!! REORDER everything in this gallery. Only use this on a link you would     !!
!! hand a co-owner. bin/photos and bin/media never pass it.                  !!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
"""


def main():
    parser = argparse.ArgumentParser(description='Media collect / gallery server')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--dir', type=str, required=True)
    parser.add_argument('--kinds', type=str, default='image',
                        help='comma-separated media kinds: image, video')
    parser.add_argument('--devices', type=str, default='',
                        help='path to cush-auth devices.json; enrolled browsers '
                             'become the gallery owner (delete + reorder)')
    parser.add_argument('--open', action='store_true',
                        help='DANGEROUS explicit opt-in: treat every visitor as the '
                             'owner (anyone with the link can delete). No launcher uses it.')
    parser.add_argument('--view-only', action='store_true',
                        help='guests may watch but not upload or download; '
                             'the owner keeps full control')
    parser.add_argument('--no-guest-upload', action='store_true',
                        help='guests may watch and download but not upload; '
                             'the owner keeps full control')
    parser.add_argument('--title', type=str, default='')
    parser.add_argument('--subtitle', type=str, default='')
    parser.add_argument('--max-file-mb', type=int, default=0)
    parser.add_argument('--max-total-mb', type=int, default=DEFAULT_MAX_TOTAL_MB)
    parser.add_argument('--max-files', type=int, default=MAX_FILES)
    parser.add_argument('--min-free-mb', type=int, default=DEFAULT_MIN_FREE_MB,
                        help='refuse uploads that would leave less free disk than this')
    parser.add_argument('--max-uploads', type=int, default=4,
                        help='concurrent uploads (each client address gets at most 2)')
    parser.add_argument('--max-connections', type=int, default=DEFAULT_MAX_CONNECTIONS)
    # Loopback by default: frpc reaches us on 127.0.0.1, and nothing else on
    # the LAN should be able to reach the gallery around the tunnel.
    parser.add_argument('--bind', type=str, default='127.0.0.1')
    args = parser.parse_args()

    kinds = tuple(k.strip() for k in args.kinds.split(',') if k.strip() in ('image', 'video'))
    if not kinds:
        parser.error('--kinds must name at least one of: image, video')

    media_dir = Path(args.dir).resolve()
    media_dir.mkdir(parents=True, exist_ok=True)

    video = 'video' in kinds
    max_file_mb = args.max_file_mb or (DEFAULT_MAX_FILE_MB if video else 100)

    MediaHandler.media_dir = media_dir
    MediaHandler.kinds = kinds
    MediaHandler.devices_path = os.path.abspath(args.devices) if args.devices else ''
    MediaHandler.open_mode = bool(args.open)
    MediaHandler.view_only = bool(args.view_only)
    MediaHandler.no_guest_upload = bool(args.no_guest_upload)
    MediaHandler.title = args.title or ('Media Gallery' if video else 'Photo Collect')
    MediaHandler.subtitle = args.subtitle or (
        'photos and clips on a porch' if video else 'photos on a porch')
    MediaHandler.max_file = max_file_mb * 1024 * 1024
    MediaHandler.max_total = max(1, args.max_total_mb) * 1024 * 1024
    MediaHandler.max_files = max(1, args.max_files)
    MediaHandler.min_free = max(0, args.min_free_mb) * 1024 * 1024
    MediaHandler.upload_slots = UploadSlots(total=max(1, args.max_uploads),
                                            per_ip=min(2, max(1, args.max_uploads)))
    MediaHandler.tag = 'mediaserver' if video else 'photoserver'
    tag = MediaHandler.tag

    if args.open:
        sys.stderr.write(OPEN_WARNING)
    if args.open and args.devices:
        sys.stderr.write(f"[{tag}] --open overrides --devices: every visitor is the owner\n")
    if args.open and args.view_only:
        sys.stderr.write(f"[{tag}] --view-only has no effect with --open: "
                         "every visitor is the owner\n")
    elif args.view_only and not args.devices:
        sys.stderr.write(f"[{tag}] --view-only with no --devices: nobody is "
                         "the owner, so nobody can upload\n")
    if not HAVE_HEIF:
        sys.stderr.write(f"[{tag}] pillow-heif not installed: HEIC uploads are kept but "
                         "show 'preview not available'\n")

    swept = sweep_stale_parts(media_dir, subdirs=(THUMBS_DIR,))
    if swept:
        sys.stderr.write(f"[{tag}] removed {swept} stale partial file(s)\n")
    install_sigterm_cleanup(tag)
    # Reads unfinished resumable uploads back in (sweeping expired ones).
    pending = MediaHandler.tus().pending_count()
    if pending:
        sys.stderr.write(f"[{tag}] {pending} resumable upload(s) waiting to be resumed\n")
    if video and light_enabled():
        # Backlog of existing heavy videos, behind any fresh upload.
        with _order_lock:
            names = load_order(media_dir, kinds)
        MediaHandler.light().ensure_scanned(names)

    server = make_server(MediaHandler, args.port, args.bind, tag=tag,
                         max_connections=max(4, args.max_connections))
    mode = 'OPEN (everyone is owner)' if args.open else (
        'cush-auth owner gate' if args.devices else 'view+add only (no owner configured)')
    if args.view_only and not args.open:
        mode = ('cush-auth owner gate, view-only for guests' if args.devices
                else 'view only (no owner configured)')
    elif args.no_guest_upload and not args.open:
        mode = ('cush-auth owner gate, no guest uploads' if args.devices
                else 'view+download only (no owner configured)')
    sys.stderr.write(
        f"[{tag}] Listening on {args.bind}:{args.port}, "
        f"{'+'.join(kinds)} in {media_dir} [{mode}]"
        f"{'' if _ffmpeg_bin else ' (no ffmpeg: video posters drawn client-side)'}"
        f"{' (light copies for phones: on)' if video and light_enabled() else ''}\n")
    try:
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        sys.stderr.write(f"\n[{tag}] Shutting down.\n")
    finally:
        server.server_close()


if __name__ == '__main__':
    main()

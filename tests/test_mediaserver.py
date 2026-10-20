"""Tests for lib/mediaserver.py (bin/media + bin/photos) and the shared
hardening block it carries. Stdlib unittest; temp dirs; servers on ephemeral
127.0.0.1 ports in threads. Never touches ~/media, ~/photos or data/.
"""

import hashlib
import http.client
import importlib.util
import io
import json
import os
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest

import mobile_markup  # tests/ helper

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "mediaserver", os.path.join(_HERE, "..", "lib", "mediaserver.py"))
ms = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ms)
ph = sys.modules["porch_http"]   # the shared core mediaserver imports

OWNER_TOKEN = "o" * 64
EXPIRED_TOKEN = "e" * 64
GUEST_TOKEN = "g" * 64


def sha(t):
    return hashlib.sha256(t.encode()).hexdigest()


def iso(epoch):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def write_devices(path, extra=()):
    devices = [
        {"name": "owner", "type": "browser", "role": "admin", "token_sha256": sha(OWNER_TOKEN)},
        {"name": "lapsed", "type": "browser", "role": "admin", "token_sha256": sha(EXPIRED_TOKEN),
         "expires_at": iso(time.time() - 60)},
        {"name": "guest", "type": "browser", "role": "guest", "token_sha256": sha(GUEST_TOKEN)},
    ]
    devices.extend(extra)
    with open(path, "w") as f:
        json.dump({"devices": devices}, f)


def png_bytes(w=32, h=32, noise=False):
    from PIL import Image
    if noise:
        img = Image.frombytes("RGB", (w, h), os.urandom(w * h * 3))
    else:
        img = Image.new("RGB", (w, h), (200, 30, 90))
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def multipart(files, boundary="porchtestboundary"):
    out = b""
    for name, data in files:
        out += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
                f"filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                ).encode() + data + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return out, f"multipart/form-data; boundary={boundary}"


class ServerCase(unittest.TestCase):
    kinds = ("image", "video")
    open_mode = False

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="porch-media-")
        self.dir = os.path.join(self.tmp, "gallery")
        os.mkdir(self.dir)
        self.devices = os.path.join(self.tmp, "devices.json")
        write_devices(self.devices)
        attrs = dict(media_dir=ms.Path(self.dir), devices_path=self.devices,
                     kinds=self.kinds, open_mode=self.open_mode, min_free=0,
                     max_total=50 * 1024 * 1024, max_file=10 * 1024 * 1024,
                     upload_slots=ms.UploadSlots(total=32, per_ip=32))
        attrs.update(self.handler_attrs())
        self.H = type("H", (ms.MediaHandler,), attrs)
        self.server = ms.BoundedThreadingHTTPServer(("127.0.0.1", 0), self.H)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def handler_attrs(self):
        return {}

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def req(self, method, path, body=None, token=None, ctype=None, origin=True, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = dict(headers or {})
        if origin:
            h["Origin"] = f"http://127.0.0.1:{self.port}"
        if token:
            h["Cookie"] = f"cush_auth={token}"
        if ctype:
            h["Content-Type"] = ctype
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r, data

    def upload(self, files, token=None):
        body, ctype = multipart(files)
        return self.req("POST", "/upload", body, token=token, ctype=ctype)


# ---- sniffing ----------------------------------------------------------------

class SniffTests(unittest.TestCase):

    def test_bmp_needs_a_real_header(self):
        self.assertIsNone(ms.sniff_mime(b"BM" + os.urandom(62)))
        self.assertIsNone(ms.sniff_mime(b"BMjunkjunkjunkjunkjunkjunkjunkjunk"))
        from PIL import Image
        buf = io.BytesIO()
        Image.new("RGB", (4, 4)).save(buf, "BMP")
        self.assertEqual(ms.sniff_mime(buf.getvalue()[:64]), "image/bmp")
        # Right shape, wrong DIB header size
        bad = bytearray(buf.getvalue()[:64])
        struct.pack_into("<I", bad, 14, 99)
        self.assertIsNone(ms.sniff_mime(bytes(bad)))

    def ftyp(self, major, compat=(), size=None):
        body = major + b"\x00\x00\x02\x00" + b"".join(compat)
        size = size or 8 + len(body)
        return (struct.pack(">I", size) + b"ftyp" + body + b"\x00" * 64)[:64]

    def test_ftyp_requires_known_brand(self):
        self.assertIsNone(ms.sniff_mime(self.ftyp(b"abcd")))
        self.assertIsNone(ms.sniff_mime(self.ftyp(b"zzzz", (b"yyyy",))))
        self.assertIsNone(ms.sniff_mime(self.ftyp(b"M4A ", (b"isom",))), "m4a audio")
        self.assertIsNone(ms.sniff_mime(b"\x00\x00\x00\x07ftypisom" + b"\x00" * 52),
                          "malformed box size")
        self.assertEqual(ms.sniff_mime(self.ftyp(b"isom", (b"iso2", b"avc1"))), "video/mp4")
        self.assertEqual(ms.sniff_mime(self.ftyp(b"qt  ")), "video/quicktime")
        self.assertEqual(ms.sniff_mime(self.ftyp(b"3gp5")), "video/3gpp")
        self.assertEqual(ms.sniff_mime(self.ftyp(b"heic", (b"mif1",))), "image/heic")
        self.assertEqual(ms.sniff_mime(self.ftyp(b"avif", (b"mif1",))), "image/avif")
        # an unknown major brand is fine if a compatible brand is known
        self.assertEqual(ms.sniff_mime(self.ftyp(b"wxyz", (b"mp42",))), "video/mp4")

    def test_random_junk_is_rejected(self):
        for _ in range(200):
            junk = os.urandom(64)
            mime = ms.sniff_mime(junk)
            if mime:
                # Only formats whose magic is a plain prefix can match random
                # bytes, and those prefixes are 3+ bytes; never BMP/ftyp/ogg.
                self.assertIn(mime, ("image/jpeg",), junk)

    def test_ogg_and_ebml_need_their_codec_markers(self):
        self.assertIsNone(ms.sniff_mime(b"OggS" + b"\x00" * 24 + b"\x01vorbis" + b"\x00" * 30))
        self.assertEqual(ms.sniff_mime(b"OggS" + b"\x00" * 24 + b"\x80theora" + b"\x00" * 30),
                         "video/ogg")
        self.assertIsNone(ms.sniff_mime(b"\x1a\x45\xdf\xa3" + b"\x00" * 60))


# ---- owner check / expiry ----------------------------------------------------

class OwnerTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="porch-owner-")
        self.path = os.path.join(self.tmp, "devices.json")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_expired_device_is_not_owner(self):
        write_devices(self.path)
        self.assertTrue(ms.porch_auth.is_owner_token(OWNER_TOKEN, self.path))
        self.assertFalse(ms.porch_auth.is_owner_token(EXPIRED_TOKEN, self.path))
        self.assertFalse(ms.porch_auth.is_owner_token(GUEST_TOKEN, self.path))
        self.assertFalse(ms.porch_auth.is_owner_token("nope", self.path))
        self.assertFalse(ms.porch_auth.is_owner_token("", self.path))

    def test_expiry_is_checked_at_call_time_not_cache_time(self):
        soon = time.time() + 100
        write_devices(self.path, [{"type": "browser", "role": "admin",
                                   "token_sha256": sha("t" * 64), "expires_at": iso(soon)}])
        self.assertTrue(ms.porch_auth.is_owner_token("t" * 64, self.path))
        # Same cached registry, later clock: no file change needed to lapse.
        self.assertFalse(ms.porch_auth.is_owner_token("t" * 64, self.path, now=soon + 1))

    def test_garbled_expiry_and_revoked_fail_closed(self):
        write_devices(self.path, [
            {"type": "browser", "role": "admin", "token_sha256": sha("x" * 64),
             "expires_at": "not a date"},
            {"type": "browser", "role": "admin", "token_sha256": sha("r" * 64), "revoked": True},
            {"type": "tunnel", "role": "admin", "token_sha256": sha("u" * 64)},
        ])
        for t in ("x", "r", "u"):
            self.assertFalse(ms.porch_auth.is_owner_token(t * 64, self.path), t)

    def test_legacy_registry_without_roles(self):
        with open(self.path, "w") as f:
            json.dump({"devices": [
                {"type": "browser", "apps": ["*"], "token_sha256": sha("l" * 64)},
                {"type": "browser", "apps": ["a.cush.rocks"], "token_sha256": sha("s" * 64)},
            ]}, f)
        self.assertTrue(ms.porch_auth.is_owner_token("l" * 64, self.path))
        self.assertFalse(ms.porch_auth.is_owner_token("s" * 64, self.path))

    def test_missing_registry_means_nobody(self):
        self.assertFalse(ms.porch_auth.is_owner_token(OWNER_TOKEN, os.path.join(self.tmp, "absent.json")))
        self.assertFalse(ms.porch_auth.is_owner_token(OWNER_TOKEN, ""))


# ---- shared primitives -------------------------------------------------------

class SharedBlockTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="porch-shared-")
        self.dir = ms.Path(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_resync_ignores_a_scan_that_raced_an_upload(self):
        # An upload that begins and ends while the (unlocked) disk scan runs
        # must not be forgotten when the stale scan result comes back.
        state = {"q": None, "racing": False}

        def scan():
            q = state["q"]
            if q is not None and not state["racing"]:
                state["racing"] = True
                self.assertIsNone(q.begin())
                self.assertIsNone(q.add(10))
                q.end(10, True)
            return (0, 0)

        q = ms.Quota(self.dir, scan, max_bytes=1000, max_items=1000, min_free=0)
        state["q"] = q
        q.resync()
        self.assertEqual((q.used, q.items), (10, 1))

    def test_quota_reservation_under_concurrency(self):
        # The fake disk scan reports what is really "on disk": kept files are
        # recorded before end(), as the server writes the file before
        # committing. A scan of (0, 0) let resync() forget committed bytes
        # whenever no upload was in flight, which made this test flaky.
        kept = []
        q = ms.Quota(self.dir, lambda: (sum(kept), len(kept)), max_bytes=1000, max_items=1000, min_free=0)

        def worker():
            if q.begin():
                return
            got = 0
            ok = True
            for _ in range(10):
                if q.add(10):
                    ok = False
                    break
                got += 10
                time.sleep(0.001)
            if ok:
                kept.append(got)
            q.end(got, ok)

        threads = [threading.Thread(target=worker) for _ in range(40)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertLessEqual(sum(kept), 1000)
        self.assertEqual(q.used, sum(kept))
        self.assertEqual(q.items, len(kept))
        self.assertEqual(q.inflight, 0)

    def test_quota_item_cap_and_release(self):
        q = ms.Quota(self.dir, lambda: (0, 0), max_bytes=10 ** 9, max_items=2, min_free=0)
        self.assertIsNone(q.begin())
        self.assertIsNone(q.begin())
        self.assertIn("full", q.begin())
        q.end(0, False)               # one failed -> slot handed back
        self.assertIsNone(q.begin())

    def test_quota_free_space_floor(self):
        q = ms.Quota(self.dir, lambda: (0, 0), max_bytes=10 ** 15, max_items=10,
                     min_free=10 ** 18)
        self.assertIn("disk", q.begin())

    def test_place_unique_never_clobbers(self):
        names = []
        lock = threading.Lock()

        def worker(i):
            tmp = ms.new_tmp(self.dir)
            tmp.write_bytes(str(i).encode())
            n = ms.place_unique(tmp, self.dir, ms.name_candidates("same", ".jpg"))
            with lock:
                names.append(n)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(25)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(set(names)), 25)
        contents = sorted(int((self.dir / n).read_text()) for n in names)
        self.assertEqual(contents, list(range(25)))
        self.assertEqual([p for p in os.listdir(self.tmp) if p.endswith(".part")], [])

    def test_sweep_stale_parts(self):
        old = self.dir / ".upload-old.part"
        new = self.dir / ".upload-new.part"
        keep = self.dir / "photo.part"         # not ours: only .upload-* at top level
        (self.dir / ".thumbs").mkdir()
        thumb = self.dir / ".thumbs" / "x.jpg.abcd.part"
        for p in (old, new, keep, thumb):
            p.write_bytes(b"x")
        past = time.time() - 3600
        for p in (old, keep, thumb):
            os.utime(p, (past, past))
        self.assertEqual(ms.sweep_stale_parts(self.dir, subdirs=(".thumbs",)), 2)
        self.assertFalse(old.exists())
        self.assertFalse(thumb.exists())
        self.assertTrue(new.exists())
        self.assertTrue(keep.exists())

    def test_client_ip_trusts_xff_only_from_loopback(self):
        class H:
            pass
        h = H()
        h.headers = {"X-Forwarded-For": "6.6.6.6, 203.0.113.9"}
        h.client_address = ("127.0.0.1", 5555)
        self.assertEqual(ms.client_ip(h), "203.0.113.9")
        h.client_address = ("10.0.0.7", 5555)
        self.assertEqual(ms.client_ip(h), "10.0.0.7")
        h.client_address = ("127.0.0.1", 5555)
        h.headers = {"X-Forwarded-For": "<script>"}
        self.assertEqual(ms.client_ip(h), "127.0.0.1")

    def test_upload_slots(self):
        s = ms.UploadSlots(total=3, per_ip=2)
        self.assertTrue(s.acquire("a"))
        self.assertTrue(s.acquire("a"))
        self.assertFalse(s.acquire("a"))
        self.assertTrue(s.acquire("b"))
        self.assertFalse(s.acquire("c"))
        s.release("a")
        self.assertTrue(s.acquire("c"))

    def test_job_gate_one_job_per_key(self):
        gate = ms.JobGate(max_jobs=4)
        running = []
        peak = []
        lock = threading.Lock()

        def job():
            with lock:
                running.append(1)
                peak.append(len(running))
            time.sleep(0.05)
            with lock:
                running.pop()
            return True

        threads = [threading.Thread(target=gate.run, args=("k", job)) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(max(peak), 1)


class SlowClientTests(unittest.TestCase):
    """Header deadline and the connection cap (shared block)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="porch-slow-")
        self._saved = ph.HEADER_DEADLINE
        ph.HEADER_DEADLINE = 1

    def tearDown(self):
        ph.HEADER_DEADLINE = self._saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def start(self, max_connections=64):
        H = type("H", (ms.MediaHandler,), dict(media_dir=ms.Path(self.tmp), devices_path=""))
        S = type("S", (ms.BoundedThreadingHTTPServer,), {"max_connections": max_connections})
        server = S(("127.0.0.1", 0), H)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def test_slowloris_headers_are_cut_off(self):
        port = self.start()
        s = socket.create_connection(("127.0.0.1", port))
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n")      # never finishes the headers
        s.settimeout(10)
        t0 = time.monotonic()
        while True:
            try:
                if not s.recv(1024):
                    break
            except (ConnectionResetError, socket.timeout):
                break
        self.assertLess(time.monotonic() - t0, 5)
        s.close()

    def test_connection_cap_answers_503(self):
        port = self.start(max_connections=2)
        idle = [socket.create_connection(("127.0.0.1", port)) for _ in range(2)]
        time.sleep(0.2)
        extra = socket.create_connection(("127.0.0.1", port))
        extra.settimeout(5)
        self.assertIn(b"503", extra.recv(256))
        for s in idle + [extra]:
            s.close()


# ---- HTTP behaviour ----------------------------------------------------------

class GalleryHTTPTests(ServerCase):

    def test_upload_valid_png_and_reject_fake(self):
        r, d = self.upload([("cat.png", png_bytes())])
        self.assertEqual(r.status, 200, d)
        self.assertEqual(json.loads(d)["files"][0]["name"], "cat.png")
        # PNG magic followed by garbage: passes the sniff, fails Pillow verify
        r, d = self.upload([("fake.png", b"\x89PNG\r\n\x1a\n" + os.urandom(2000))])
        self.assertEqual(r.status, 400, d)
        self.assertIn("not a valid image", d.decode())
        r, d = self.upload([("junk.bmp", b"BM" + os.urandom(4000))])
        self.assertEqual(r.status, 400, d)
        self.assertEqual(sorted(os.listdir(self.dir)), [".order.json", "cat.png"])

    def test_get_list_does_not_write_order_file(self):
        with open(os.path.join(self.dir, "oob.png"), "wb") as f:
            f.write(png_bytes())
        r, d = self.req("GET", "/list")
        self.assertEqual(r.status, 200)
        self.assertEqual([x["name"] for x in json.loads(d)], ["oob.png"])
        order = os.path.join(self.dir, ".order.json")
        self.assertFalse(os.path.exists(order))
        self.upload([("b.png", png_bytes())])
        self.assertTrue(os.path.exists(order))
        before = os.stat(order).st_mtime_ns
        time.sleep(0.02)
        self.req("GET", "/list")
        self.assertEqual(os.stat(order).st_mtime_ns, before)

    def test_range_edge_cases(self):
        data = bytes(range(256)) * 4
        path = os.path.join(self.dir, "clip.mp4")
        with open(path, "wb") as f:
            # a structurally valid ftyp head so it serves inline
            f.write(struct.pack(">I", 24) + b"ftypisom" + b"\x00\x00\x02\x00isomavc1")
            f.write(data)
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            full = f.read()
        cases = [
            ("bytes=0-0", 206, full[0:1]),
            ("bytes=-1", 206, full[-1:]),
            ("bytes=10-", 206, full[10:]),
            ("bytes=5-9999999", 206, full[5:]),
            (f"bytes={size}-", 416, b""),
            ("bytes=-0", 416, b""),
            ("bytes=9-3", 416, b""),
            ("bytes=0-1,4-5", 200, full),
            ("bytes=abc", 200, full),
            ("items=0-5", 200, full),
            ("bytes=" + "9" * 40 + "-", 200, full),
        ]
        for rng, status, body in cases:
            r, d = self.req("GET", "/media/clip.mp4", headers={"Range": rng})
            self.assertEqual(r.status, status, rng)
            self.assertEqual(d, body, rng)
            if status == 206:
                self.assertTrue(r.getheader("Content-Range").startswith("bytes "), rng)
            if status == 416:
                self.assertEqual(r.getheader("Content-Range"), f"bytes */{size}")
        r, _ = self.req("GET", "/media/clip.mp4")
        self.assertEqual(r.getheader("Content-Type"), "video/mp4")

    def test_quota_holds_under_concurrent_uploads(self):
        self.H.max_total = 300 * 1024
        self.H._quota = None
        blob = png_bytes(140, 140, noise=True)      # ~60KB of incompressible PNG
        self.assertGreater(len(blob), 50 * 1024)
        results = []

        def go(i):
            r, d = self.upload([(f"p{i}.png", blob)])
            results.append(r.status)

        threads = [threading.Thread(target=go, args=(i,)) for i in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        stored = [n for n in os.listdir(self.dir) if n.endswith(".png")]
        total = sum(os.path.getsize(os.path.join(self.dir, n)) for n in stored)
        self.assertLessEqual(total, 300 * 1024)
        self.assertEqual(len(stored), results.count(200))
        self.assertGreaterEqual(results.count(413), 1)
        self.assertEqual([n for n in os.listdir(self.dir) if n.endswith(".part")], [])

    def test_item_cap_under_concurrent_uploads(self):
        self.H.max_files = 3
        self.H._quota = None
        blob = png_bytes()

        threads = [threading.Thread(target=self.upload, args=([(f"c{i}.png", blob)],))
                   for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        stored = [n for n in os.listdir(self.dir) if n.endswith(".png")]
        self.assertEqual(len(stored), 3)

    def test_symlink_is_never_served(self):
        secret = os.path.join(self.tmp, "secret.png")
        with open(secret, "wb") as f:
            f.write(png_bytes())
        os.symlink(secret, os.path.join(self.dir, "link.png"))
        for path in ("/media/link.png", "/thumb/link.png", "/preview/link.png"):
            r, _ = self.req("GET", path)
            self.assertEqual(r.status, 404, path)

    def test_thumbnail_failure_is_cached(self):
        with open(os.path.join(self.dir, "broken.jpg"), "wb") as f:
            f.write(b"\xff\xd8\xff" + os.urandom(500))
        calls = []
        real = ms._image_thumb

        def counting(src, dst):
            calls.append(src)
            return real(src, dst)

        ms._image_thumb = counting
        try:
            r1, _ = self.req("GET", "/thumb/broken.jpg")
            r2, _ = self.req("GET", "/thumb/broken.jpg")
        finally:
            ms._image_thumb = real
        self.assertEqual((r1.status, r2.status), (404, 404))
        self.assertIn("max-age=3600", r2.getheader("Cache-Control"))
        self.assertEqual(len(calls), 1)
        self.assertTrue(os.path.exists(os.path.join(self.dir, ".thumbs", "broken.jpg.fail")))
        self.assertEqual([n for n in os.listdir(os.path.join(self.dir, ".thumbs"))
                          if n.endswith(".part")], [])

    def test_thumbnail_ok(self):
        self.upload([("ok.png", png_bytes(600, 300))])
        r, d = self.req("GET", "/thumb/ok.png")
        self.assertEqual(r.status, 200)
        self.assertEqual(d[:3], b"\xff\xd8\xff")

    def test_tiff_preview_and_heic_fallback(self):
        from PIL import Image
        Image.new("RGB", (50, 40), (1, 2, 3)).save(os.path.join(self.dir, "scan.tif"), "TIFF")
        r, d = self.req("GET", "/preview/scan.tif")
        self.assertEqual(r.status, 200)
        self.assertEqual(r.getheader("Content-Type"), "image/jpeg")
        # previews are only for formats browsers can't show
        self.upload([("p.png", png_bytes())])
        r, _ = self.req("GET", "/preview/p.png")
        self.assertEqual(r.status, 404)
        if not ms.HAVE_HEIF:
            with open(os.path.join(self.dir, "phone.heic"), "wb") as f:
                f.write(struct.pack(">I", 24) + b"ftypheic\x00\x00\x00\x00mif1heic" + os.urandom(64))
            r, _ = self.req("GET", "/preview/phone.heic")
            self.assertEqual(r.status, 404)
            self.assertIn("max-age", r.getheader("Cache-Control"))

    def test_pixel_limit_is_a_hard_error(self):
        saved = ms.MAX_PIXELS
        ms.MAX_PIXELS = 100
        try:
            r, d = self.upload([("big.png", png_bytes(20, 20))])   # 400 px > 100
        finally:
            ms.MAX_PIXELS = saved
        self.assertEqual(r.status, 400)
        self.assertIn("too large", d.decode())

    def test_cross_origin_post_refused(self):
        body, ctype = multipart([("a.png", png_bytes())])
        r, _ = self.req("POST", "/upload", body, ctype=ctype, origin=False)
        self.assertEqual(r.status, 403)

    @unittest.skipUnless(ms._ffmpeg_bin, "ffmpeg not installed")
    def test_video_poster_with_forced_demuxer(self):
        import subprocess
        src = os.path.join(self.tmp, "v.mp4")
        subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-f", "lavfi", "-i",
                        "testsrc=size=160x120:rate=10", "-t", "2", "-pix_fmt", "yuv420p",
                        src], check=True)
        with open(src, "rb") as f:
            r, d = self.upload([("v.mp4", f.read())])
        self.assertEqual(r.status, 200, d)
        r, d = self.req("GET", "/thumb/v.mp4")
        self.assertEqual(r.status, 200)
        self.assertEqual(d[:3], b"\xff\xd8\xff")


class PhotosOwnerGateTests(ServerCase):
    """bin/photos now runs --kinds image --devices: guests view + add only."""

    kinds = ("image",)

    def setUp(self):
        super().setUp()
        r, d = self.upload([("one.png", png_bytes())])
        self.assertEqual(r.status, 200, d)
        self.upload([("two.png", png_bytes())])

    def delete(self, token):
        return self.req("POST", "/delete", json.dumps({"name": "one.png"}).encode(),
                        token=token, ctype="application/json")

    def test_guest_can_add_but_not_delete_or_reorder(self):
        r, _ = self.upload([("guest.png", png_bytes())])
        self.assertEqual(r.status, 200)
        for token in (None, GUEST_TOKEN, EXPIRED_TOKEN, "bogus"):
            r, _ = self.delete(token)
            self.assertEqual(r.status, 403, token)
            r, _ = self.req("POST", "/reorder", json.dumps({"order": ["two.png"]}).encode(),
                            token=token, ctype="application/json")
            self.assertEqual(r.status, 403, token)
        self.assertTrue(os.path.exists(os.path.join(self.dir, "one.png")))

    def test_owner_can_delete(self):
        r, _ = self.delete(OWNER_TOKEN)
        self.assertEqual(r.status, 200)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "one.png")))

    def test_page_reflects_role(self):
        _, guest = self.req("GET", "/")
        _, owner = self.req("GET", "/", token=OWNER_TOKEN)
        self.assertIn(b'"owner": false', guest)
        self.assertIn(b'"owner": true', owner)

    def test_launcher_no_longer_passes_open(self):
        with open(os.path.join(_HERE, "..", "bin", "photos")) as f:
            text = f.read()
        launch = text[text.index('python3 "$TUNNEL_DIR/lib/mediaserver.py"'):]
        launch = launch[:launch.index("&\n")]
        self.assertNotIn("--open", launch)
        self.assertIn("--devices", launch)
        self.assertIn("--bind 127.0.0.1", launch)


# ---- resumable uploads (tus) + light copies ----------------------------------

def jpeg_bytes(w=48, h=32):
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (w, h), (10, 120, 200)).save(buf, "JPEG")
    return buf.getvalue()


def make_clip(path, size="160x120", seconds=1, rate=10, extra=()):
    import subprocess
    subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-f", "lavfi", "-i",
                    f"testsrc=size={size}:rate={rate}", "-t", str(seconds),
                    "-pix_fmt", "yuv420p", *extra, path], check=True)
    with open(path, "rb") as f:
        return f.read()


class TusMixin:
    def tus_upload(self, data, filename, chunk=None, token=None, origin=True):
        """Create + PATCH (in chunks); returns (last response, stored name)."""
        import base64
        h = {"Tus-Resumable": "1.0.0", "Upload-Length": str(len(data)),
             "Upload-Metadata": "filename " + base64.b64encode(filename.encode()).decode()}
        r, d = self.req("POST", "/tus/", headers=h, token=token, origin=origin)
        if r.status != 201:
            return r, None
        loc = r.getheader("Location")
        chunk = chunk or len(data)
        off = 0
        while off < len(data):
            r, d = self.req("PATCH", loc, data[off:off + chunk], token=token,
                            ctype="application/offset+octet-stream",
                            headers={"Tus-Resumable": "1.0.0", "Upload-Offset": str(off)})
            if r.status != 204:
                return r, None
            off = int(r.getheader("Upload-Offset"))
        return r, r.getheader("Porch-Upload-Name")


class MediaTusTests(TusMixin, ServerCase):

    def test_tus_jpeg_gets_sniffed_extension_and_order(self):
        data = jpeg_bytes()
        r, name = self.tus_upload(data, "evil.php", chunk=40)
        self.assertEqual(r.status, 204)
        self.assertEqual(name, "evil.jpg")
        with open(os.path.join(self.dir, name), "rb") as f:
            self.assertEqual(f.read(), data)
        r, d = self.req("GET", "/list")
        self.assertEqual([x["name"] for x in json.loads(d)], ["evil.jpg"])
        self.assertFalse(os.listdir(os.path.join(self.dir, ".tus")))

    @unittest.skipUnless(ms._ffmpeg_bin, "ffmpeg not installed")
    def test_tus_mp4(self):
        data = make_clip(os.path.join(self.tmp, "c.mp4"))
        r, name = self.tus_upload(data, "clip.mov", chunk=len(data) // 3 + 1)
        self.assertEqual(r.status, 204)
        self.assertEqual(name, "clip.mp4")

    def test_non_media_first_chunk_rejected_at_once(self):
        import base64
        r, _ = self.req("POST", "/tus/", headers={
            "Tus-Resumable": "1.0.0", "Upload-Length": str(5 * 1024 * 1024),
            "Upload-Metadata": "filename " + base64.b64encode(b"x.jpg").decode()})
        loc = r.getheader("Location")
        r, d = self.req("PATCH", loc, b"<svg onload=alert(1)>" + b" " * 200,
                        ctype="application/offset+octet-stream",
                        headers={"Tus-Resumable": "1.0.0", "Upload-Offset": "0"})
        self.assertEqual(r.status, 415)
        self.assertIn("unsafe", json.loads(d)["message"])
        r, _ = self.req("HEAD", loc, headers={"Tus-Resumable": "1.0.0"})
        self.assertEqual(r.status, 404)
        self.assertEqual(self.H.quota().used, 0)

    def test_tus_cross_origin_refused(self):
        r, _ = self.tus_upload(jpeg_bytes(), "a.jpg", origin=False)
        self.assertEqual(r.status, 403)

    def test_tus_over_per_file_cap(self):
        r, _ = self.req("POST", "/tus/", headers={
            "Tus-Resumable": "1.0.0", "Upload-Length": str(self.H.max_file + 1)})
        self.assertEqual(r.status, 413)

    def test_page_carries_tus_client(self):
        _, page = self.req("GET", "/")
        self.assertIn(b"PorchTus", page)
        self.assertNotIn(b"__TUS_JS__", page)

    def test_picker_is_a_native_label_activated_input(self):
        _, page = self.req("GET", "/")
        page = page.decode()
        mobile_markup.check_pickers(self, page, multiple=("fileInput",))
        # The camera buttons are separate inputs; the chooser never captures.
        self.assertIn('id="camInput" accept="image/*" capture="environment"', page)
        mobile_markup.check_responsive(self, page)

    def test_light_route_ranges_and_delete_cleans_sidecars(self):
        clip = os.path.join(self.dir, "clip.mp4")
        with open(clip, "wb") as f:
            f.write(b"\0" * 100)
        os.utime(clip, (time.time() - 100, time.time() - 100))
        self.assertEqual(self.req("GET", "/light/clip.mp4")[0].status, 404)
        thumbs = os.path.join(self.dir, ".thumbs")
        os.makedirs(thumbs, exist_ok=True)
        light = os.path.join(thumbs, "clip.mp4.light.mp4")
        with open(light, "wb") as f:
            f.write(bytes(range(256)) * 4)
        for marker in ("clip.mp4.light.fail", "clip.mp4.light.no"):
            open(os.path.join(thumbs, marker), "w").close()
        r, d = self.req("GET", "/light/clip.mp4", headers={"Range": "bytes=10-19"})
        self.assertEqual(r.status, 206)
        self.assertEqual(d, bytes(range(10, 20)))
        self.assertEqual(r.getheader("Content-Type"), "video/mp4")
        self.assertIn("sandbox", r.getheader("Content-Security-Policy"))
        self.assertEqual(self.req("GET", "/light/..%2f..%2fetc%2fpasswd")[0].status, 404)
        r, d = self.req("GET", "/list")
        if ms.light_enabled():
            self.assertTrue(json.loads(d)[0].get("light"))
        # A stale light copy (older than the original) is not served.
        os.utime(light, (time.time() - 1000, time.time() - 1000))
        self.assertEqual(self.req("GET", "/light/clip.mp4")[0].status, 404)
        os.utime(light, None)
        r, _ = self.req("POST", "/delete", json.dumps({"name": "clip.mp4"}).encode(),
                        token=OWNER_TOKEN, ctype="application/json")
        self.assertEqual(r.status, 200)
        self.assertEqual(os.listdir(thumbs), [])


class MediaViewOnlyTusTests(TusMixin, ServerCase):

    def handler_attrs(self):
        return {"view_only": True}

    def test_guest_locked_refuses_tus(self):
        r, _ = self.tus_upload(jpeg_bytes(), "a.jpg")
        self.assertEqual(r.status, 403)
        r, _ = self.req("HEAD", "/tus/" + "A" * 22, headers={"Tus-Resumable": "1.0.0"})
        self.assertEqual(r.status, 403)

    def test_owner_may_still_use_tus(self):
        r, name = self.tus_upload(jpeg_bytes(), "a.jpg", token=OWNER_TOKEN)
        self.assertEqual((r.status, name), (204, "a.jpg"))


class MediaNoGuestUploadTests(TusMixin, ServerCase):
    """--no-guest-upload: guests watch and download, only the owner adds."""

    def handler_attrs(self):
        return {"no_guest_upload": True}

    def test_guest_cannot_add(self):
        r, _ = self.upload([("a.jpg", jpeg_bytes())])
        self.assertEqual(r.status, 403)
        r, _ = self.tus_upload(jpeg_bytes(), "a.jpg")
        self.assertEqual(r.status, 403)

    def test_guest_can_download_and_page_has_no_add_ui(self):
        r, _ = self.upload([("a.jpg", jpeg_bytes())], token=OWNER_TOKEN)
        self.assertEqual(r.status, 200)
        r, data = self.req("GET", "/media/a.jpg?dl=1")
        self.assertEqual(r.status, 200)
        self.assertIn("attachment", r.getheader("Content-Disposition", ""))
        r, page = self.req("GET", "/")
        self.assertIn(b'"canUpload": false', page)
        self.assertIn(b'"canDownload": true', page)

    def test_owner_keeps_uploads(self):
        r, name = self.tus_upload(jpeg_bytes(), "b.jpg", token=OWNER_TOKEN)
        self.assertEqual((r.status, name), (204, "b.jpg"))


class LightDecisionTests(unittest.TestCase):

    def p(self, w, h, br=2_000_000, codec="h264", dur=10.0):
        return {"width": w, "height": h, "bitrate": br, "codec": codec, "duration": dur}

    def test_needs_light(self):
        self.assertTrue(ms.needs_light(self.p(1920, 1080)))
        self.assertTrue(ms.needs_light(self.p(1080, 1920)))       # portrait counts
        self.assertTrue(ms.needs_light(self.p(3840, 2160, 45_000_000)))
        self.assertFalse(ms.needs_light(self.p(1280, 720)))
        self.assertFalse(ms.needs_light(self.p(720, 1280)))
        self.assertTrue(ms.needs_light(self.p(1280, 720, 8_000_000)))   # heavy 720p
        self.assertTrue(ms.needs_light(self.p(640, 480, codec="hevc")))  # not playable everywhere
        self.assertFalse(ms.needs_light(self.p(640, 480, codec="vp9")))
        self.assertFalse(ms.needs_light(None))
        self.assertFalse(ms.needs_light(self.p(0, 0)))

    def test_disabled_without_ffmpeg(self):
        saved = ms._ffprobe_bin
        try:
            ms._ffprobe_bin = None
            self.assertFalse(ms.light_enabled())
            lc = ms.LightCopies(ms.Path(tempfile.mkdtemp(prefix="porch-light-")))
            self.assertFalse(lc.enqueue("a.mp4"))
        finally:
            ms._ffprobe_bin = saved


@unittest.skipUnless(ms.light_enabled(), "ffmpeg/ffprobe not installed")
class LightTranscodeTests(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="porch-light-")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_real_transcode_and_skip(self):
        make_clip(os.path.join(self.dir, "big.mp4"), size="1920x1080", seconds=1, rate=10,
                  extra=("-c:v", "libx264", "-preset", "ultrafast"))
        make_clip(os.path.join(self.dir, "small.mp4"))
        lc = ms.LightCopies(ms.Path(self.dir), "test")
        lc._make("big.mp4")
        lc._make("small.mp4")
        light = lc.ready("big.mp4")
        self.assertIsNotNone(light)
        probe = ms.probe_video(light)
        self.assertEqual((probe["width"], probe["height"]), (1280, 720))
        self.assertEqual(probe["codec"], "h264")
        with open(light, "rb") as f:
            head = f.read(64)
        self.assertEqual(ms.sniff_mime(head), "video/mp4")
        # faststart: the moov box comes before mdat
        with open(light, "rb") as f:
            blob = f.read()
        self.assertLess(blob.find(b"moov"), blob.find(b"mdat"))
        self.assertIsNone(lc.ready("small.mp4"))
        self.assertTrue(os.path.exists(os.path.join(self.dir, ".thumbs", "small.mp4.light.no")))
        self.assertFalse(lc.enqueue("small.mp4"))        # settled: not queued again


    def test_replaced_mid_encode_discards_copy_and_requeues(self):
        make_clip(os.path.join(self.dir, "a.mp4"), size="1920x1080", seconds=1, rate=10,
                  extra=("-c:v", "libx264", "-preset", "ultrafast"))
        lc = ms.LightCopies(ms.Path(self.dir), "test")
        real = ms.transcode_light

        def swap(src, dst, probe):
            ok = real(src, dst, probe)
            # A delete + new upload under the same name while ffmpeg ran.
            os.unlink(src)
            make_clip(str(src))
            return ok
        try:
            ms.transcode_light = swap
            self.assertTrue(lc._make("a.mp4"))           # True: queue it again
        finally:
            ms.transcode_light = real
        self.assertIsNone(lc.ready("a.mp4"))
        thumbs = os.path.join(self.dir, ".thumbs")
        self.assertEqual([n for n in os.listdir(thumbs) if ".light" in n], [])

    def test_deleted_mid_encode_leaves_nothing(self):
        make_clip(os.path.join(self.dir, "b.mp4"), size="1920x1080", seconds=1, rate=10,
                  extra=("-c:v", "libx264", "-preset", "ultrafast"))
        lc = ms.LightCopies(ms.Path(self.dir), "test")
        real = ms.transcode_light

        def gone(src, dst, probe):
            ok = real(src, dst, probe)
            os.unlink(src)
            return ok
        try:
            ms.transcode_light = gone
            self.assertFalse(lc._make("b.mp4"))
        finally:
            ms.transcode_light = real
        thumbs = os.path.join(self.dir, ".thumbs")
        self.assertEqual([n for n in os.listdir(thumbs) if ".light" in n], [])


class LightQueueTests(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="porch-lightq-")
        self.saved = (ms._ffmpeg_bin, ms._ffprobe_bin)
        ms._ffmpeg_bin = ms._ffprobe_bin = "/bin/true"

    def tearDown(self):
        ms._ffmpeg_bin, ms._ffprobe_bin = self.saved
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_full_queue_lets_the_next_scan_offer_again(self):
        lc = ms.LightCopies(ms.Path(self.dir), "test")
        lc._q = ms.queue.PriorityQueue(maxsize=1)
        lc._thread = object()                 # no worker: the queue stays full
        for n in ("a.mp4", "b.mp4"):
            open(os.path.join(self.dir, n), "wb").close()
        lc.ensure_scanned(["a.mp4", "b.mp4"])
        self.assertTrue(lc.pending("a.mp4"))
        self.assertFalse(lc.pending("b.mp4"))
        self.assertFalse(lc._scanned)         # b was dropped: rescan next /list

    def test_scan_sweeps_interrupted_transcodes_and_orphans_only(self):
        thumbs = os.path.join(self.dir, ".thumbs")
        os.makedirs(thumbs)
        open(os.path.join(self.dir, "kept.mp4"), "wb").close()
        names = ["kept.mp4.light.mp4", "gone.mp4.light.mp4", "gone.mp4.light.fail",
                 "kept.mp4.light.mp4.1a2b3c4d.part", "kept.mp4.jpg"]
        for n in names:
            open(os.path.join(thumbs, n), "wb").close()
        lc = ms.LightCopies(ms.Path(self.dir), "test")
        lc._thread = object()
        lc.ensure_scanned([])
        self.assertEqual(sorted(os.listdir(thumbs)), ["kept.mp4.jpg", "kept.mp4.light.mp4"])


if __name__ == "__main__":
    unittest.main()

"""Tests for lib/porch_tus.py: the tus 1.0.0 core against a minimal mounted
handler. Stdlib unittest; temp dirs; a server on an ephemeral 127.0.0.1 port.
"""

import base64
import http.client
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "lib"))
import porch_http as ph  # noqa: E402
import porch_tus as pt  # noqa: E402


def b64(s):
    return base64.b64encode(s.encode()).decode()


class TusCase(unittest.TestCase):
    max_size = 1024 * 1024
    max_total = 4 * 1024 * 1024
    chunk_max = 256 * 1024
    max_per_ip = 3

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="porch-tus-")
        self.dir = Path(self.tmp)
        self.finalized = []
        case = self

        def scan():
            used = items = 0
            for e in self.dir.iterdir():
                if e.is_file() and not e.name.startswith("."):
                    used += e.stat().st_size
                    items += 1
            p_used, p_items = case.tus.pending_usage()
            return used + p_used, items + p_items

        self.tus = None
        self.quota_obj = None

        def quota():
            if case.quota_obj is None:
                case.quota_obj = ph.Quota(self.dir, scan, self.max_total, 100, min_free=0)
            return case.quota_obj

        def finalize(part, up, handler):
            name = up.metadata.get("filename") or "upload"
            if name == "refuse-me":
                raise pt.TusRejected("refused by the app")
            case.finalized.append(name)
            return ph.place_unique(part, self.dir, ph.name_candidates(ph.safe_stem(name), ".bin"))

        def on_head(head):
            return "bad magic" if head.startswith(b"EVIL") else None

        self.make_tus = lambda: pt.TusServer(
            self.dir, quota=quota, max_size=self.max_size, finalize=finalize,
            on_head=on_head, chunk_max=self.chunk_max, max_per_ip=self.max_per_ip,
            tag="test-tus")
        self.tus = self.make_tus()
        self.quota = quota

        class H(ph.HardenedHandlerMixin, BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _route(self):
                if not case.tus.owns(self.path.split("?")[0]):
                    self.send_error(404)
                    return
                if self.command in ("POST", "PATCH", "DELETE") and not ph.same_origin(self):
                    self.close_connection = True
                    self.send_error(403)
                    return
                case.tus.handle(self)

            do_OPTIONS = do_POST = do_HEAD = do_PATCH = do_DELETE = _route

        self.server = ph.BoundedThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def req(self, method, path, body=None, headers=None, tus=True, origin=True):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        h = {}
        if tus:
            h["Tus-Resumable"] = "1.0.0"
        if origin:
            h["Origin"] = f"http://127.0.0.1:{self.port}"
        h.update(headers or {})
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r, data

    def create(self, length, name="file.dat", extra=None):
        h = {"Upload-Length": str(length), "Upload-Metadata": "filename " + b64(name)}
        h.update(extra or {})
        return self.req("POST", "/tus/", headers=h)

    def patch(self, loc, offset, data, ctype=pt.OCTET):
        return self.req("PATCH", loc, data, {"Upload-Offset": str(offset),
                                             "Content-Type": ctype})

    def head(self, loc):
        return self.req("HEAD", loc, origin=False)


class ProtocolTests(TusCase):

    def test_options_discovery(self):
        r, _ = self.req("OPTIONS", "/tus/", tus=False, origin=False)
        self.assertEqual(r.status, 204)
        self.assertEqual(r.getheader("Tus-Version"), "1.0.0")
        self.assertIn("termination", r.getheader("Tus-Extension"))
        self.assertIn("creation", r.getheader("Tus-Extension"))
        self.assertEqual(r.getheader("Tus-Max-Size"), str(self.max_size))

    def test_tus_resumable_required(self):
        r, _ = self.req("POST", "/tus/", headers={"Upload-Length": "10"}, tus=False)
        self.assertEqual(r.status, 412)
        self.assertEqual(r.getheader("Tus-Version"), "1.0.0")

    def test_method_override_refused(self):
        r, _ = self.req("POST", "/tus/", headers={"Upload-Length": "10",
                                                  "X-HTTP-Method-Override": "PATCH"})
        self.assertEqual(r.status, 400)

    def test_full_upload_in_chunks(self):
        data = os.urandom(300_000)
        r, _ = self.create(len(data), "holiday clip.mov")
        self.assertEqual(r.status, 201)
        loc = r.getheader("Location")
        self.assertRegex(loc, r"^/tus/[A-Za-z0-9_-]{22}$")
        uid = loc.rsplit("/", 1)[1]
        part = self.dir / ".tus" / (uid + ".part")
        self.assertEqual(oct(part.stat().st_mode & 0o777), "0o600")
        self.assertEqual(oct((self.dir / ".tus").stat().st_mode & 0o777), "0o700")
        r, _ = self.head(loc)
        self.assertEqual((r.status, r.getheader("Upload-Offset"), r.getheader("Upload-Length")),
                         (200, "0", str(len(data))))
        self.assertEqual(r.getheader("Cache-Control"), "no-store")
        self.assertTrue(r.getheader("Upload-Expires"))
        r, _ = self.patch(loc, 0, data[:200_000])
        self.assertEqual((r.status, r.getheader("Upload-Offset")), (204, "200000"))
        self.assertIsNone(r.getheader("Porch-Upload-Name"))
        r, _ = self.patch(loc, 200_000, data[200_000:])
        self.assertEqual((r.status, r.getheader("Upload-Offset")), (204, str(len(data))))
        name = r.getheader("Porch-Upload-Name")
        self.assertEqual(name, "holiday_clip.bin")
        self.assertEqual((self.dir / name).read_bytes(), data)
        self.assertEqual(self.finalized, ["holiday clip.mov"])
        self.assertFalse(any((self.dir / ".tus").iterdir()))
        r, _ = self.head(loc)
        self.assertEqual(r.status, 404)

    def test_interrupted_patch_resumes(self):
        data = os.urandom(200_000)
        r, _ = self.create(len(data))
        loc = r.getheader("Location")
        # Promise 150000 bytes, send 70000, hang up.
        s = socket.create_connection(("127.0.0.1", self.port))
        s.sendall((f"PATCH {loc} HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\n"
                   f"Origin: http://127.0.0.1:{self.port}\r\nTus-Resumable: 1.0.0\r\n"
                   f"Content-Type: {pt.OCTET}\r\nUpload-Offset: 0\r\n"
                   f"Content-Length: 150000\r\n\r\n").encode() + data[:70_000])
        time.sleep(0.3)
        s.close()
        offset = None
        for _ in range(50):
            r, _ = self.head(loc)
            offset = int(r.getheader("Upload-Offset"))
            if offset == 70_000:
                break
            time.sleep(0.1)
        self.assertEqual(offset, 70_000)
        r, _ = self.patch(loc, offset, data[offset:])
        self.assertEqual(r.status, 204)
        name = r.getheader("Porch-Upload-Name")
        self.assertEqual((self.dir / name).read_bytes(), data)

    def test_offset_mismatch_is_409(self):
        r, _ = self.create(1000)
        loc = r.getheader("Location")
        self.patch(loc, 0, b"x" * 100)
        r, _ = self.patch(loc, 0, b"y" * 100)
        self.assertEqual(r.status, 409)
        self.assertEqual(r.getheader("Upload-Offset"), "100")

    def test_too_large(self):
        r, _ = self.create(self.max_size + 1)
        self.assertEqual(r.status, 413)
        r, _ = self.create(self.max_size)
        loc = r.getheader("Location")
        r, _ = self.patch(loc, 0, b"z" * (self.chunk_max + 1))
        self.assertEqual(r.status, 413)
        r, _ = self.create(10)
        r, _ = self.patch(r.getheader("Location"), 0, b"z" * 11)
        self.assertEqual(r.status, 413)

    def test_length_required_and_no_defer(self):
        r, _ = self.req("POST", "/tus/", headers={"Upload-Defer-Length": "1"})
        self.assertEqual(r.status, 400)
        r, _ = self.req("POST", "/tus/")
        self.assertEqual(r.status, 400)
        r, _ = self.create(0)
        self.assertEqual(r.status, 400)

    def test_wrong_content_type_is_415(self):
        r, _ = self.create(10)
        r, _ = self.patch(r.getheader("Location"), 0, b"0123456789",
                          ctype="application/octet-stream")
        self.assertEqual(r.status, 415)

    def test_on_head_rejects_at_once(self):
        r, _ = self.create(500_000)
        loc = r.getheader("Location")
        r, body = self.patch(loc, 0, b"EVIL" + b"\0" * 200_000)
        self.assertEqual(r.status, 415)
        self.assertIn("bad magic", json.loads(body)["message"])
        self.assertEqual(self.head(loc)[0].status, 404)
        self.assertEqual(self.quota().used, 0)
        self.assertFalse(any((self.dir / ".tus").iterdir()))

    def test_on_head_sees_bytes_split_across_patches(self):
        r, _ = self.create(1000)
        loc = r.getheader("Location")
        self.assertEqual(self.patch(loc, 0, b"EV")[0].status, 204)
        r, _ = self.patch(loc, 2, b"IL" + b"\0" * 100)
        self.assertEqual(r.status, 415)

    def test_short_upload_completed_by_empty_patch_is_still_sniffed(self):
        # The bytes reached disk without on_head judging them (written by a
        # crashed run); the empty PATCH that completes it must sniff first.
        r, _ = self.create(20)
        loc = r.getheader("Location")
        uid = loc.rsplit("/", 1)[1]
        (self.dir / ".tus" / (uid + ".part")).write_bytes(b"EVIL" + b"\0" * 16)
        r, body = self.patch(loc, 20, b"")
        self.assertEqual(r.status, 415)
        self.assertEqual(self.finalized, [])
        self.assertEqual(self.quota().used, 0)

    def test_finalize_refusal_releases(self):
        r, _ = self.create(20, "refuse-me")
        r, body = self.patch(r.getheader("Location"), 0, b"a" * 20)
        self.assertEqual(r.status, 422)
        self.assertEqual(self.quota().used, 0)
        self.assertEqual([e for e in self.dir.iterdir() if e.is_file()], [])

    def test_termination(self):
        r, _ = self.create(1000)
        loc = r.getheader("Location")
        self.patch(loc, 0, b"q" * 10)
        r, _ = self.req("DELETE", loc, origin=True)
        self.assertEqual(r.status, 204)
        self.assertEqual(self.head(loc)[0].status, 404)
        self.assertEqual(self.req("DELETE", loc)[0].status, 404)

    def test_unknown_and_malformed_ids(self):
        self.assertEqual(self.head("/tus/" + "A" * 22)[0].status, 404)
        self.assertEqual(self.head("/tus/../../etc")[0].status, 404)
        self.assertEqual(self.req("PATCH", "/tus/x")[0].status, 404)

    def test_creation_with_upload(self):
        data = b"hello tus world"
        r, _ = self.create(len(data), "inline.txt",
                           extra={"Content-Type": pt.OCTET})  # header only
        self.assertEqual(r.status, 201)
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        c.request("POST", "/tus/", body=data, headers={
            "Tus-Resumable": "1.0.0", "Origin": f"http://127.0.0.1:{self.port}",
            "Upload-Length": str(len(data)), "Content-Type": pt.OCTET,
            "Upload-Metadata": "filename " + b64("inline.txt")})
        r = c.getresponse()
        r.read()
        c.close()
        self.assertEqual(r.status, 201)
        self.assertTrue(r.getheader("Location"))
        self.assertEqual(r.getheader("Upload-Offset"), str(len(data)))
        self.assertEqual((self.dir / r.getheader("Porch-Upload-Name")).read_bytes(), data)


class QuotaAndCapTests(TusCase):

    def test_quota_held_across_patches_and_released(self):
        r, _ = self.create(3 * 1024 * 1024 // 4)        # 768KB reserved
        a = r.getheader("Location")
        self.assertEqual(self.quota().used, 3 * 1024 * 1024 // 4)
        self.patch(a, 0, b"a" * 1000)
        self.assertEqual(self.quota().used, 3 * 1024 * 1024 // 4)
        # A resync (nothing in flight) still counts the reservation.
        self.quota().resync()
        self.assertEqual(self.quota().used, 3 * 1024 * 1024 // 4)
        self.assertEqual(self.quota().items, 1)
        self.tus.max_per_ip = 100
        for _ in range(3):
            self.assertEqual(self.create(1024 * 1024)[0].status, 201)
        # Full now: 768K + 3 x 1M = 3.75M; another 1M does not fit.
        self.assertEqual(self.create(1024 * 1024)[0].status, 413)
        # DELETE releases.
        self.assertEqual(self.req("DELETE", a)[0].status, 204)
        self.assertEqual(self.quota().used, 3 * 1024 * 1024)
        self.assertEqual(self.create(512 * 1024)[0].status, 201)

    def test_finish_keeps_bytes_counted_once(self):
        r, _ = self.create(5000)
        loc = r.getheader("Location")
        self.patch(loc, 0, b"b" * 5000)
        self.assertEqual(self.quota().used, 5000)
        self.quota().resync()
        self.assertEqual((self.quota().used, self.quota().items), (5000, 1))

    def test_sweep_expires_idle_and_releases(self):
        r, _ = self.create(4000)
        loc = r.getheader("Location")
        self.patch(loc, 0, b"c" * 100)
        r2, _ = self.create(4000)          # never gets a byte
        self.assertEqual(self.quota().used, 8000)
        now = time.time()
        self.assertEqual(self.tus.sweep(now=now + 600), 0)
        self.assertEqual(self.tus.sweep(now=now + pt.EXPIRE_EMPTY + 10), 1)
        self.assertEqual(self.head(r2.getheader("Location"))[0].status, 404)
        self.assertEqual(self.quota().used, 4000)
        self.assertEqual(self.tus.sweep(now=now + pt.EXPIRE_IDLE + 10), 1)
        self.assertEqual(self.head(loc)[0].status, 404)
        self.assertEqual(self.quota().used, 0)
        self.assertFalse(any((self.dir / ".tus").iterdir()))

    def test_restart_reloads_pending(self):
        r, _ = self.create(4000, "later.bin")
        loc = r.getheader("Location")
        self.patch(loc, 0, b"d" * 1500)
        self.tus = self.make_tus()            # a "restarted" server
        self.assertEqual(self.tus.pending_usage(), (4000, 1))
        r, _ = self.head(loc)
        self.assertEqual(r.getheader("Upload-Offset"), "1500")
        r, _ = self.patch(loc, 1500, b"d" * 2500)
        self.assertEqual(r.status, 204)
        self.assertEqual(r.getheader("Porch-Upload-Name"), "later.bin")

    def test_per_ip_cap(self):
        for _ in range(self.max_per_ip):
            self.assertEqual(self.create(10)[0].status, 201)
        r, _ = self.create(10)
        self.assertEqual(r.status, 429)
        self.assertTrue(r.getheader("Retry-After"))

    def test_total_cap(self):
        self.tus.max_per_ip = 100
        self.tus.max_total = 2
        self.create(10)
        self.create(10)
        self.assertEqual(self.create(10)[0].status, 503)


class MetadataTests(unittest.TestCase):

    def test_parse(self):
        self.assertEqual(pt.parse_metadata(None), {})
        self.assertEqual(pt.parse_metadata("filename " + b64("a b.jpg") + ",is_confidential"),
                         {"filename": "a b.jpg", "is_confidential": ""})
        self.assertEqual(pt.parse_metadata("filename " + b64("café")),
                         {"filename": "café"})

    def test_limits(self):
        bad = [
            "filename notbase64!",
            "filename " + b64("x") + ",filename " + b64("y"),
            "fi/le " + b64("x"),
            "a b c",
            ",".join(f"k{i} {b64('v')}" for i in range(pt.MAX_METADATA_PAIRS + 1)),
            "big " + base64.b64encode(b"x" * (pt.MAX_METADATA_VALUE + 1)).decode(),
            "x" * (pt.MAX_METADATA_HEADER + 1),
        ]
        for raw in bad:
            with self.assertRaises(pt.MetadataError, msg=raw[:40]):
                pt.parse_metadata(raw)

    def test_http_metadata_errors_are_400(self):
        case = TusCase("run")
        case.setUp()
        try:
            r, _ = case.req("POST", "/tus/", headers={"Upload-Length": "10",
                                                      "Upload-Metadata": "filename !!"})
            self.assertEqual(r.status, 400)
        finally:
            case.tearDown()


if __name__ == "__main__":
    unittest.main()

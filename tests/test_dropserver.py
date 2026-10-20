"""Tests for lib/dropserver.py (bin/drop). Stdlib unittest; temp dirs;
servers on ephemeral 127.0.0.1 ports in threads (plus one subprocess for the
SIGTERM test). Never touches ~/drops or data/.
"""

import hashlib
import http.client
import importlib.util
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import mobile_markup  # tests/ helper

_HERE = os.path.dirname(os.path.abspath(__file__))
_LIB = os.path.join(_HERE, "..", "lib", "dropserver.py")
_spec = importlib.util.spec_from_file_location("dropserver", _LIB)
dr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dr)

OWNER = "o" * 64
EXPIRED = "e" * 64
GUEST = "g" * 64


def sha(t):
    return hashlib.sha256(t.encode()).hexdigest()


def iso(epoch):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def multipart(files, boundary="porchdropboundary"):
    out = b""
    for name, data in files:
        out += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
                f"filename=\"{name}\"\r\n\r\n").encode() + data + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return out, f"multipart/form-data; boundary={boundary}"


class DropCase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="porch-drop-")
        self.dir = os.path.join(self.tmp, "drop")
        os.mkdir(self.dir)
        self.devices = os.path.join(self.tmp, "devices.json")
        with open(self.devices, "w") as f:
            json.dump({"devices": [
                {"type": "browser", "role": "admin", "token_sha256": sha(OWNER)},
                {"type": "browser", "role": "admin", "token_sha256": sha(EXPIRED),
                 "expires_at": iso(time.time() - 5)},
                {"type": "browser", "role": "guest", "token_sha256": sha(GUEST)},
            ]}, f)
        self.H = type("H", (dr.DropHandler,), dict(
            upload_dir=dr.Path(self.dir), devices_path=self.devices, min_free=0,
            upload_slots=dr.UploadSlots(total=32, per_ip=32)))
        self.server = dr.BoundedThreadingHTTPServer(("127.0.0.1", 0), self.H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def req(self, method, path, body=None, token=None, ctype=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = {"Origin": f"http://127.0.0.1:{self.port}"}
        if token:
            h["Cookie"] = f"cush_auth={token}"
        if ctype:
            h["Content-Type"] = ctype
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        d = r.read()
        c.close()
        return r, d

    def upload(self, files, token=None):
        body, ctype = multipart(files)
        return self.req("POST", "/upload", body, token=token, ctype=ctype)

    def test_listing_and_download_are_owner_only(self):
        r, d = self.upload([("report.pdf", b"%PDF-1.4 hello")])
        self.assertEqual(r.status, 200, d)
        for token in (None, GUEST, EXPIRED, "bogus"):
            r, _ = self.req("GET", "/files", token=token)
            self.assertEqual(r.status, 403, token)
            r, _ = self.req("GET", "/files/report.pdf", token=token)
            self.assertEqual(r.status, 403, token)
        r, d = self.req("GET", "/files", token=OWNER)
        self.assertEqual(r.status, 200)
        self.assertEqual([f["name"] for f in json.loads(d)], ["report.pdf"])
        r, d = self.req("GET", "/files/report.pdf", token=OWNER)
        self.assertEqual((r.status, d), (200, b"%PDF-1.4 hello"))
        self.assertEqual(r.getheader("Content-Type"), "application/octet-stream")

    def test_no_registry_means_nobody_lists(self):
        self.H.devices_path = ""
        r, _ = self.req("GET", "/files", token=OWNER)
        self.assertEqual(r.status, 403)

    def test_page_carries_server_blocklist_and_role(self):
        _, guest = self.req("GET", "/")
        _, owner = self.req("GET", "/", token=OWNER)
        cfg = json.loads(guest.split(b'id="cfg">')[1].split(b"</script>")[0])
        self.assertEqual(cfg["blocked"], sorted(dr.BLOCKED_EXTENSIONS))
        self.assertFalse(cfg["owner"])
        self.assertIn(b'"owner": true', owner)
        self.assertNotIn(b"new Set(['.exe'", guest)    # no hand-kept client copy

    def test_blocked_extension_rejected(self):
        r, d = self.upload([("evil.exe", b"MZ" + b"\x00" * 100)])
        self.assertEqual(r.status, 400)
        self.assertEqual(os.listdir(self.dir), [])

    def test_total_cap_under_concurrent_uploads(self):
        self.H.max_total = 20 * 1024
        self.H._quota = None
        blob = os.urandom(6 * 1024)
        results = []
        threads = [threading.Thread(target=lambda i=i: results.append(
            self.upload([(f"f{i}.bin", blob)])[0].status)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        stored = [n for n in os.listdir(self.dir) if not n.startswith(".")]
        total = sum(os.path.getsize(os.path.join(self.dir, n)) for n in stored)
        self.assertLessEqual(total, 20 * 1024)
        self.assertEqual(len(stored), results.count(200))
        self.assertEqual(len(stored), 3)
        self.assertEqual([n for n in os.listdir(self.dir) if n.endswith(".part")], [])

    def test_free_space_floor(self):
        self.H.min_free = 10 ** 18
        self.H._quota = None
        r, d = self.upload([("a.txt", b"hi")])
        self.assertEqual(r.status, 413)
        self.assertIn("disk space", d.decode())

    def test_same_name_concurrent_uploads_never_clobber(self):
        payloads = [os.urandom(3000) for _ in range(12)]
        threads = [threading.Thread(target=self.upload, args=([("same.txt", p)],))
                   for p in payloads]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        stored = sorted(os.listdir(self.dir))
        self.assertEqual(len(stored), 12)
        got = sorted(dr.Path(self.dir, n).read_bytes() for n in stored)
        self.assertEqual(got, sorted(payloads))

    def test_symlink_not_listed_or_served(self):
        secret = os.path.join(self.tmp, "secret.txt")
        with open(secret, "w") as f:
            f.write("s")
        os.symlink(secret, os.path.join(self.dir, "link.txt"))
        r, d = self.req("GET", "/files", token=OWNER)
        self.assertEqual(json.loads(d), [])
        r, _ = self.req("GET", "/files/link.txt", token=OWNER)
        self.assertEqual(r.status, 404)

    def test_upload_slots_cap(self):
        self.H.upload_slots = dr.UploadSlots(total=1, per_ip=1)
        self.assertTrue(self.H.upload_slots.acquire("127.0.0.1"))
        try:
            r, _ = self.upload([("a.txt", b"x")])
        finally:
            self.H.upload_slots.release("127.0.0.1")
        self.assertEqual(r.status, 503)
        self.assertEqual(r.getheader("Retry-After"), "5")


class DropTusTests(DropCase):

    def tus(self, data, filename, chunk=None, origin=True):
        import base64
        h = {"Origin": f"http://127.0.0.1:{self.port}"} if origin else {}
        h.update({"Tus-Resumable": "1.0.0", "Upload-Length": str(len(data)),
                  "Upload-Metadata": "filename " + base64.b64encode(filename.encode()).decode()})
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        c.request("POST", "/tus/", headers=h)
        r = c.getresponse()
        r.read()
        if r.status != 201:
            c.close()
            return r, None
        loc = r.getheader("Location")
        chunk = chunk or len(data)
        off = 0
        while off < len(data):
            c.request("PATCH", loc, body=data[off:off + chunk], headers=dict(
                h, **{"Content-Type": "application/offset+octet-stream",
                      "Upload-Offset": str(off)}))
            r = c.getresponse()
            r.read()
            if r.status != 204:
                break
            off = int(r.getheader("Upload-Offset"))
        c.close()
        return r, r.getheader("Porch-Upload-Name")

    def test_tus_upload_sanitizes_filename(self):
        data = os.urandom(50_000)
        r, name = self.tus(data, "../../etc/my report (final).pdf", chunk=20_000)
        self.assertEqual(r.status, 204)
        self.assertNotIn("/", name)
        self.assertTrue(name.endswith(".pdf"))
        with open(os.path.join(self.dir, name), "rb") as f:
            self.assertEqual(f.read(), data)
        r, d = self.req("GET", "/files", token=OWNER)
        self.assertEqual([x["name"] for x in json.loads(d)], [name])
        # Same name again never clobbers.
        r, name2 = self.tus(b"second", "../../etc/my report (final).pdf")
        self.assertNotEqual(name2, name)

    def test_tus_blocked_extension_refused_at_creation(self):
        r, _ = self.tus(b"MZ" + b"\0" * 100, "setup.exe")
        self.assertEqual(r.status, 400)
        self.assertFalse(os.path.exists(os.path.join(self.dir, ".tus")))

    def test_trailing_dot_or_space_does_not_dodge_the_blocklist(self):
        for name in ("setup.exe.", "setup.exe. .", "run.BAT "):
            self.assertTrue(dr._blocked_ext(name), name)
            r, _ = self.tus(b"MZ" + b"\0" * 100, name)
            self.assertEqual(r.status, 400, name)
        self.assertEqual(dr._blocked_ext("notes.txt."), "")

    def test_tus_cross_origin_refused(self):
        r, _ = self.tus(b"hello", "a.txt", origin=False)
        self.assertEqual(r.status, 403)

    def test_partial_not_listed_and_quota_reserved(self):
        import base64
        r, _ = self.req("GET", "/files", token=OWNER)
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        c.request("POST", "/tus/", headers={
            "Origin": f"http://127.0.0.1:{self.port}", "Tus-Resumable": "1.0.0",
            "Upload-Length": "100000",
            "Upload-Metadata": "filename " + base64.b64encode(b"big.bin").decode()})
        r = c.getresponse()
        r.read()
        c.close()
        self.assertEqual(r.status, 201)
        r, d = self.req("GET", "/files", token=OWNER)
        self.assertEqual(json.loads(d), [])
        self.assertEqual(self.H.quota().used, 100000)

    def test_page_carries_tus_client(self):
        _, page = self.req("GET", "/")
        self.assertIn(b"PorchTus", page)

    def test_picker_is_a_native_label_activated_input(self):
        # iOS Safari offers Photo Library only on a native activation of a
        # real file input: the whole drop zone is its <label>.
        _, page = self.req("GET", "/")
        page = page.decode()
        mobile_markup.check_pickers(self, page, multiple=("fileInput", "photoInput"))
        # Android opens its photo picker only for an image/video-only input
        self.assertIn('id="photoInput" accept="image/*,video/*" multiple', page)
        self.assertIn('<label class="p-drop dropzone" id="dropzone" for="fileInput">', page)
        mobile_markup.check_responsive(self, page)


class SigtermTests(unittest.TestCase):

    def test_sigterm_removes_in_flight_part(self):
        tmp = tempfile.mkdtemp(prefix="porch-drop-term-")
        self.addCleanup(shutil.rmtree, tmp, True)
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        proc = subprocess.Popen([sys.executable, "-B", _LIB, "--port", str(port),
                                 "--dir", tmp, "--min-free-mb", "0"],
                                stderr=subprocess.PIPE)
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        deadline = time.time() + 10
        while True:
            try:
                c = socket.create_connection(("127.0.0.1", port))
                break
            except OSError:
                if time.time() > deadline:
                    self.fail("server did not start")
                time.sleep(0.05)
        boundary = "b0undary"
        head = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
                f"filename=\"big.bin\"\r\n\r\n").encode()
        c.sendall((f"POST /upload HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                   f"Origin: http://127.0.0.1:{port}\r\n"
                   f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
                   f"Content-Length: 10000000\r\n\r\n").encode() + head + b"x" * 300000)
        deadline = time.time() + 10
        while not [n for n in os.listdir(tmp) if n.endswith(".part")]:
            if time.time() > deadline:
                self.fail("no partial upload appeared")
            time.sleep(0.05)
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)
        c.close()
        self.assertEqual([n for n in os.listdir(tmp) if n.endswith(".part")], [])
        err = proc.stderr.read()
        proc.stderr.close()
        self.assertIn(b"SIGTERM", err)


if __name__ == "__main__":
    unittest.main()

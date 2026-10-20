"""Tests for lib/musicserver.py (bin/music). Stdlib unittest; temp dirs;
servers on ephemeral 127.0.0.1 ports in threads. Never touches ~/music or
data/.
"""

import hashlib
import http.client
import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "musicserver", os.path.join(_HERE, "..", "lib", "musicserver.py"))
mu = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mu)

OWNER = "o" * 64
EXPIRED = "e" * 64


def sha(t):
    return hashlib.sha256(t.encode()).hexdigest()


def iso(epoch):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def multipart(files, boundary="porchmusicboundary"):
    out = b""
    for name, data in files:
        out += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
                f"filename=\"{name}\"\r\n\r\n").encode() + data + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return out, f"multipart/form-data; boundary={boundary}"


FAKE_MP3 = b"ID3\x03\x00\x00\x00\x00\x00\x00" + b"\x00" * 2000


class MusicCase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="porch-music-")
        self.dir = os.path.join(self.tmp, "mix")
        os.mkdir(self.dir)
        self.devices = os.path.join(self.tmp, "devices.json")
        with open(self.devices, "w") as f:
            json.dump({"devices": [
                {"type": "browser", "role": "admin", "token_sha256": sha(OWNER)},
                {"type": "browser", "role": "admin", "token_sha256": sha(EXPIRED),
                 "expires_at": iso(time.time() - 5)},
            ]}, f)
        self.H = type("H", (mu.MusicHandler,), dict(
            music_dir=mu.Path(self.dir), devices_path=self.devices, min_free=0,
            upload_slots=mu.UploadSlots(total=32, per_ip=32)))
        self.server = mu.BoundedThreadingHTTPServer(("127.0.0.1", 0), self.H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def req(self, method, path, body=None, token=None, ctype=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        h = {"Origin": f"http://127.0.0.1:{self.port}"}
        h.update(headers or {})
        if token:
            h["Cookie"] = f"cush_auth={token}"
        if ctype:
            h["Content-Type"] = ctype
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        d = r.read()
        c.close()
        return r, d

    def upload(self, files, token=OWNER):
        body, ctype = multipart(files)
        return self.req("POST", "/upload", body, token=token, ctype=ctype)

    def test_only_live_owner_can_upload(self):
        for token in (None, EXPIRED, "bogus"):
            r, _ = self.upload([("a.mp3", FAKE_MP3)], token=token)
            self.assertEqual(r.status, 403, token)
        r, d = self.upload([("a.mp3", FAKE_MP3)])
        self.assertEqual(r.status, 200, d)
        _, page = self.req("GET", "/", token=EXPIRED)
        self.assertIn(b"window.__ADMIN__ = false", page)
        _, page = self.req("GET", "/", token=OWNER)
        self.assertIn(b"window.__ADMIN__ = true", page)
        self.assertRegex(page.decode(), r"window\.__maxFile = \d+;")

    def test_get_list_does_not_write_order_file(self):
        with open(os.path.join(self.dir, "oob.mp3"), "wb") as f:
            f.write(FAKE_MP3)
        r, d = self.req("GET", "/list")
        self.assertEqual([t["name"] for t in json.loads(d)], ["oob.mp3"])
        self.assertFalse(os.path.exists(os.path.join(self.dir, ".order.json")))

    def test_out_of_band_name_with_spaces_plays(self):
        # Dropped straight into the folder: renamed to the name every route
        # looks up, never over an existing track.
        for n in ("Golden Hour.mp3", "Golden_Hour.mp3"):
            with open(os.path.join(self.dir, n), "wb") as f:
                f.write(FAKE_MP3)
        r, d = self.req("GET", "/list")
        names = sorted(t["name"] for t in json.loads(d))
        self.assertEqual(len(names), 2)
        self.assertIn("Golden_Hour.mp3", names)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "Golden Hour.mp3")))
        for n in names:
            self.assertEqual(self.req("GET", "/track/" + n)[0].status, 200, n)

    def test_symlink_track_is_not_served(self):
        secret = os.path.join(self.tmp, "secret.mp3")
        with open(secret, "wb") as f:
            f.write(FAKE_MP3)
        os.symlink(secret, os.path.join(self.dir, "link.mp3"))
        r, _ = self.req("GET", "/track/link.mp3")
        self.assertEqual(r.status, 404)
        r, _ = self.req("GET", "/peaks/link.mp3")
        self.assertEqual(r.status, 404)

    def test_track_count_cap_under_concurrency(self):
        self.H.max_files = 2
        self.H._quota = None
        threads = [threading.Thread(target=self.upload, args=([(f"t{i}.mp3", FAKE_MP3)],))
                   for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        tracks = [n for n in os.listdir(self.dir) if n.endswith(".mp3")]
        self.assertEqual(len(tracks), 2)

    def test_byte_cap_under_concurrency(self):
        self.H.max_total = 10 * 1024
        self.H._quota = None
        blob = FAKE_MP3 + b"\x00" * 2000          # ~4KB
        threads = [threading.Thread(target=self.upload, args=([(f"b{i}.mp3", blob)],))
                   for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        total = sum(os.path.getsize(os.path.join(self.dir, n))
                    for n in os.listdir(self.dir) if n.endswith(".mp3"))
        self.assertLessEqual(total, 10 * 1024)

    def test_range_still_works(self):
        with open(os.path.join(self.dir, "r.mp3"), "wb") as f:
            f.write(FAKE_MP3)
        r, d = self.req("GET", "/track/r.mp3", headers={"Range": "bytes=0-2"})
        self.assertEqual((r.status, d), (206, b"ID3"))
        r, _ = self.req("GET", "/track/r.mp3", headers={"Range": "bytes=99999-"})
        self.assertEqual(r.status, 416)

    def test_rows_scroll_on_mobile(self):
        css = mu.PLAYER_HTML
        row_rule = re.search(r"\n\.row\{[^}]*\}", css).group(0)
        self.assertNotIn("touch-action", row_rule)
        self.assertIn("touch-action:none", re.search(r"\.grip\{[^}]*\}", css).group(0))
        self.assertNotIn("decodeAudioData", css)
        self.assertNotIn("new Audio(", css)

    def test_peaks_unavailable_without_ffmpeg(self):
        with open(os.path.join(self.dir, "x.mp3"), "wb") as f:
            f.write(FAKE_MP3)
        saved = mu._ffmpeg_bin
        mu._ffmpeg_bin = None
        try:
            r, d = self.req("GET", "/peaks/x.mp3")
        finally:
            mu._ffmpeg_bin = saved
        self.assertEqual(r.status, 404)
        self.assertIn("max-age", r.getheader("Cache-Control"))

    @unittest.skipUnless(mu._ffmpeg_bin, "ffmpeg not installed")
    def test_server_side_peaks_and_duration(self):
        src = os.path.join(self.dir, "tone.mp3")
        subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-f", "lavfi", "-i",
                        "sine=frequency=440", "-t", "3", src], check=True)
        r, d = self.req("GET", "/peaks/tone.mp3")
        self.assertEqual(r.status, 200, d)
        j = json.loads(d)
        self.assertEqual(len(j["peaks"]), mu.PEAK_BUCKETS)
        self.assertAlmostEqual(j["duration"], 3.0, delta=0.3)
        self.assertTrue(os.path.exists(os.path.join(self.dir, ".peaks", "tone.mp3.json")))
        r, d = self.req("GET", "/list")
        self.assertAlmostEqual(json.loads(d)[0]["duration"], 3.0, delta=0.3)
        # junk with an mp3 name: cached failure, not re-decoded
        with open(os.path.join(self.dir, "junk.mp3"), "wb") as f:
            f.write(os.urandom(4000))
        r, _ = self.req("GET", "/peaks/junk.mp3")
        self.assertEqual(r.status, 404)

    def test_delete_removes_peaks_sidecar(self):
        self.upload([("d.mp3", FAKE_MP3)])
        os.makedirs(os.path.join(self.dir, ".peaks"), exist_ok=True)
        side = os.path.join(self.dir, ".peaks", "d.mp3.json")
        with open(side, "w") as f:
            f.write("{}")
        r, _ = self.req("POST", "/delete", json.dumps({"name": "d.mp3"}).encode(),
                        token=OWNER, ctype="application/json")
        self.assertEqual(r.status, 200)
        self.assertFalse(os.path.exists(side))


if __name__ == "__main__":
    unittest.main()

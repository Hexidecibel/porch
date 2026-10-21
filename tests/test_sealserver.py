"""Tests for lib/sealserver.py (bin/seal): the sealed-share door.

Real servers on 127.0.0.1:<ephemeral> in daemon threads; door state in a temp
dir; the closer is a recorder (nothing is killed). Covers Range on /blob, the
page's CSP and headers, that no key ever reaches the server (node's
PorchSeal.open drives a recording server), burn counting complete downloads
across Range requests (never partial ones, never the owner), owned-file
deletion, the door proxy leaving seal doors' opens alone, and bin/seal's
argument checks.
"""

import hashlib
import http.client
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import mobile_markup  # tests/ helper
from unittest import mock

LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib")
sys.path.insert(0, LIB)

import door_state  # noqa: E402
import doorproxy  # noqa: E402
import porch_seal as ps  # noqa: E402
import sealserver as ss  # noqa: E402
from porch_http import make_server  # noqa: E402

NODE = shutil.which("node")
NEEDS_CRYPTO = unittest.skipUnless(ps.available(), "python3-cryptography is not installed")
BIN_SEAL = os.path.join(LIB, "..", "bin", "seal")
NAME = "sealtest"
HOST = f"{NAME}.tunnel.cush.rocks"


class Closer:
    def __init__(self):
        self.calls = 0
        self.event = threading.Event()

    def __call__(self):
        self.calls += 1
        self.event.set()


@NEEDS_CRYPTO
class SealCase(unittest.TestCase):
    rules = {}
    size = 300000
    owned = True

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.plain = os.urandom(self.size)
        self.sealed = os.path.join(self.tmp, "f.pseal")
        self.key = ps.seal_file(io.BytesIO(self.plain), self.sealed, "photo.jpg", "image/jpeg")
        with open(self.sealed, "rb") as f:
            self.ct = f.read()
        self.state_path = os.path.join(self.tmp, f"{NAME}.json")
        door_state.write_state_atomic(self.state_path, {
            "name": NAME, "type": "seal", "pid": os.getpid(), "port": 1,
            "started": int(time.time()), "expires": int(time.time()) + 3600,
            "rules": self.rules, "opens": 0, "last_open": None, "opens_by": "app"})
        quiet = mock.patch("sys.stderr", io.StringIO())     # "download limit reached" notes
        quiet.start()
        self.addCleanup(quiet.stop)
        self.closer = Closer()
        self.seen = []
        handler = ss.make_handler(self.sealed, NAME, state_dir=self.tmp, owned=self.owned,
                                  grace=0.2, closer=self.closer)
        seen = self.seen

        class Recording(handler):
            def parse_request(self):
                ok = super().parse_request()
                seen.append(self.requestline + "\n" + str(self.headers))
                return ok

            def log_message(self, *a):
                pass
        self.handler = Recording
        self.srv = make_server(Recording, 0, tag="sealtest")
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    def get(self, path="/", headers=None, method="GET", port=None):
        h = {"Host": HOST}
        h.update(headers or {})
        c = http.client.HTTPConnection("127.0.0.1", port or self.port, timeout=10)
        try:
            c.request(method, path, headers=h)
            r = c.getresponse()
            return r.status, dict(r.getheaders()), r.read()
        finally:
            c.close()

    def rng(self, a, b, ip=None, port=None):
        h = {"Range": f"bytes={a}-{b}"}
        if ip:
            h["X-Forwarded-For"] = ip
        return self.get("/blob", h, port=port)

    def opens(self, want=None):
        """The open count; with `want`, waits briefly for it (the server
        counts right after its last write, so the client can be faster)."""
        deadline = time.time() + 3
        while True:
            n = door_state.read_state(self.state_path).get("opens", 0)
            if want is None or n >= want or time.time() > deadline:
                return n
            time.sleep(0.02)


class BlobTests(SealCase):

    def test_range_and_headers(self):
        st, h, body = self.rng(10, 99)
        self.assertEqual(st, 206)
        self.assertEqual(body, self.ct[10:100])
        self.assertEqual(h["Content-Range"], f"bytes 10-99/{len(self.ct)}")
        self.assertEqual(h["Content-Type"], "application/octet-stream")
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")
        self.assertEqual(h["Cache-Control"], "no-store")
        self.assertEqual(h["Accept-Ranges"], "bytes")
        self.assertTrue(h["Content-Disposition"].startswith("attachment"))
        self.assertIn("sandbox", h["Content-Security-Policy"])
        st, h, body = self.get("/blob")
        self.assertEqual((st, body), (200, self.ct))
        st, h, _ = self.rng(len(self.ct) + 5, len(self.ct) + 9)
        self.assertEqual(st, 416)
        st, h, body = self.get("/blob", method="HEAD")
        self.assertEqual((st, body, h["Content-Length"]), (200, b"", str(len(self.ct))))

    def test_page_headers_and_no_key(self):
        st, h, body = self.get("/")
        self.assertEqual(st, 200)
        csp = h["Content-Security-Policy"]
        for d in ("default-src 'none'", "script-src 'self' 'nonce-", "connect-src 'self'",
                  "worker-src 'self'", "img-src 'self' blob:", "media-src 'self' blob:",
                  "frame-ancestors 'none'", "form-action 'none'", "base-uri 'none'"):
            self.assertIn(d, csp)
        self.assertNotIn("unsafe", csp)
        self.assertEqual(h["Referrer-Policy"], "no-referrer")
        self.assertEqual(h["Cache-Control"], "no-store")
        page = body.decode()
        self.assertIn('data-app="secret"', page)
        self.assertIn('<script src="/static/seal.js"></script>', page)
        self.assertNotIn(self.key, page)
        self.assertNotIn("photo.jpg", page)              # the name is inside the ciphertext
        self.assertNotIn("innerHTML", page)
        self.assertNotIn("style=", page)
        self.assertIn('"mode": "key"', page)

    def test_page_is_phone_friendly(self):
        _, _, body = self.get("/")
        page = body.decode()
        _, css = mobile_markup.check_responsive(self, page)
        self.assertIn("viewport-fit=cover", page)            # porch.css pads the safe areas
        self.assertIn(".p-kicker{flex-wrap:wrap", css)       # the badges wrap at 320px
        self.assertNotIn("80vh", css)                        # iOS vh is the large viewport
        self.assertIn("70svh", css)
        self.assertIn(".stage--image,.stage--video{padding:0", css)   # flush with the text
        # The size/type line flows under the title: no footer pinned to the bottom.
        self.assertNotIn("p-foot", page)
        self.assertIn('<p class="meta" id="meta">', page)

    def test_static(self):
        st, h, body = self.get("/static/seal.js")
        self.assertEqual(st, 200)
        self.assertIn(b"PorchSeal", body)
        self.assertTrue(h["Content-Type"].startswith("text/javascript"))
        st, _, _ = self.get("/static/pdfjs/pdf.min.mjs")
        self.assertEqual(st, 200)
        self.assertEqual(self.get("/static/../porch_seal.py")[0], 404)
        self.assertEqual(self.get("/nope")[0], 404)

    def test_partial_downloads_do_not_count(self):
        half = len(self.ct) // 2
        for _ in range(3):
            self.assertEqual(self.rng(0, half)[0], 206)
        self.assertEqual(self.opens(), 0)
        # another client fetching the other half does not complete this one
        self.assertEqual(self.rng(half + 1, len(self.ct) - 1, ip="203.0.113.7")[0], 206)
        self.assertEqual(self.opens(), 0)

    def test_complete_download_counts_without_limit(self):
        self.assertEqual(self.get("/blob")[0], 200)
        self.assertEqual(self.get("/blob")[0], 200)
        self.assertEqual(self.opens(2), 2)
        self.assertFalse(self.closer.event.wait(0.4))
        self.assertTrue(os.path.exists(self.sealed))

    @unittest.skipUnless(NODE, "node is not installed")
    def test_server_never_sees_the_key(self):
        script = (
            "const P=require(process.env.SEAL_JS);"
            "(async()=>{const r=await P.open(process.argv[1],{key:process.argv[2],batch:2});"
            "let n=0;for await(const c of r.chunks)n+=c.length;"
            "console.log(JSON.stringify({meta:r.meta,n}));})()"
            ".catch(e=>{console.log('ERR '+e.kind);process.exit(3)})")
        p = subprocess.run([NODE, "-e", script, f"http://127.0.0.1:{self.port}/blob", self.key],
                           capture_output=True, text=True, timeout=60,
                           env=dict(os.environ, SEAL_JS=os.path.join(LIB, "seal.js")))
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        out = json.loads(p.stdout)
        self.assertEqual(out["n"], self.size)
        self.assertEqual(out["meta"]["name"], "photo.jpg")
        self.assertGreater(len(self.seen), 2)               # several Range requests
        self.get("/")
        raw_key = ps.unb64url(self.key)
        for req in self.seen:
            self.assertNotIn(self.key, req)
            self.assertNotIn(raw_key.hex(), req)
        self.assertEqual(self.opens(1), 1)                   # node's download was complete


class BurnTests(SealCase):
    rules = {"max_opens": 1}

    def test_burn_after_complete_download_across_ranges(self):
        n = len(self.ct)
        cuts = [0, 4160, 70000, 140000, n]
        for a, b in zip(cuts, cuts[1:-1] + [n]):
            st, _, body = self.rng(a, b - 1)
            self.assertEqual(st, 206)
        self.assertEqual(self.opens(1), 1)
        st, _, _ = self.rng(0, 10)
        self.assertEqual(st, 410)
        self.assertFalse(os.path.exists(self.sealed))       # owned: deleted at once
        self.assertTrue(self.closer.event.wait(5))          # door stopped after the grace
        self.assertEqual(self.closer.calls, 1)
        self.assertEqual(self.get("/")[0], 200)             # the page still loads (assets)
        self.assertEqual(self.get("/static/seal.js")[0], 200)

    def test_overlapping_and_repeated_ranges(self):
        n = len(self.ct)
        self.rng(0, 1000)
        self.rng(500, 1500)
        self.rng(0, 1500)
        self.assertEqual(self.opens(), 0)
        self.rng(1400, n - 2)
        self.assertEqual(self.opens(), 0)                   # one byte short
        self.rng(n - 1, n - 1)
        self.assertEqual(self.opens(1), 1)

    def test_owner_is_never_counted(self):
        with mock.patch.object(ss.SealHandler, "_is_owner", return_value=True):
            self.assertEqual(self.get("/blob")[0], 200)
        self.assertEqual(self.opens(), 0)
        self.assertTrue(os.path.exists(self.sealed))

    def test_limit_raised_live(self):
        door_state.update_state(self.state_path, lambda s: s["rules"].update(max_opens=2))
        self.get("/blob", {"X-Forwarded-For": "198.51.100.1"})
        self.assertEqual(self.opens(1), 1)
        self.assertEqual(self.get("/blob", {"X-Forwarded-For": "198.51.100.2"})[0], 200)
        self.assertEqual(self.opens(2), 2)
        self.assertEqual(self.rng(0, 1)[0], 410)


class NotOwnedTests(SealCase):
    rules = {"max_opens": 1}
    owned = False

    def test_not_owned_file_is_kept(self):
        self.get("/blob")
        self.assertEqual(self.opens(1), 1)
        self.assertEqual(self.get("/blob")[0], 410)
        self.assertTrue(os.path.exists(self.sealed))
        self.assertTrue(self.closer.event.wait(5))


class ProxyIntegration(SealCase):
    """doorproxy in front of a seal door: page views never count or close it."""
    rules = {"max_opens": 1}

    def setUp(self):
        super().setUp()
        self.pcloser = Closer()
        self.door = doorproxy.Door(NAME, self.tmp, self.port, grace=0.2, closer=self.pcloser)
        self.proxy = doorproxy.build_server(self.door, 0)
        self.pport = self.proxy.server_address[1]
        threading.Thread(target=self.proxy.serve_forever, daemon=True).start()
        self.addCleanup(self.proxy.server_close)
        self.addCleanup(self.proxy.shutdown)
        quiet = (doorproxy.log, doorproxy.DoorHandler.log_message)
        doorproxy.log = lambda m: None
        doorproxy.DoorHandler.log_message = lambda *a: None
        self.addCleanup(lambda: (setattr(doorproxy, "log", quiet[0]),
                                 setattr(doorproxy.DoorHandler, "log_message", quiet[1])))

    def test_page_views_free_download_burns(self):
        for _ in range(3):
            st, _, _ = self.get("/", {"Sec-Fetch-Dest": "document"}, port=self.pport)
            self.assertEqual(st, 200)
        self.assertEqual(self.opens(), 0)
        self.assertFalse(self.pcloser.event.wait(0.4))
        half = len(self.ct) // 2
        self.assertEqual(self.rng(0, half, port=self.pport)[0], 206)
        self.assertEqual(self.rng(half + 1, len(self.ct) - 1, port=self.pport)[0], 206)
        self.assertEqual(self.opens(1), 1)
        self.assertEqual(self.rng(0, 1, port=self.pport)[0], 410)
        # the proxy still serves the page during the grace (it never closes the door itself)
        self.assertEqual(self.get("/", {"Sec-Fetch-Dest": "document"}, port=self.pport)[0], 200)
        self.assertTrue(self.closer.event.wait(5))
        self.assertEqual(self.pcloser.calls, 0)


class DoorStateTests(unittest.TestCase):

    def test_count_open_and_set_opens_by(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "x.json")
        door_state.write_state_atomic(p, {"name": "x", "rules": {"max_opens": 3}, "opens": 1})
        self.assertEqual(door_state.count_open(p, now=5), (2, 3))
        self.assertEqual(door_state.read_state(p)["last_open"], 5)
        self.assertEqual(door_state.main(["set-opens-by", p, "app"]), 0)
        self.assertTrue(door_state.app_counts_opens(door_state.read_state(p)))
        self.assertEqual(door_state.main(["set-opens-by", p, "proxy"]), 0)
        self.assertFalse(door_state.app_counts_opens(door_state.read_state(p)))
        with mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(door_state.main(["set-opens-by", p, "bogus"]), 2)
        with self.assertRaises(FileNotFoundError):
            door_state.count_open(os.path.join(d, "gone.json"))

    def test_coverage(self):
        c = ss.Coverage()
        for a, b in ((10, 20), (30, 40), (15, 35), (0, 5), (5, 10)):
            c.add(a, b)
        self.assertEqual(c.spans, [(0, 40)])
        self.assertEqual(c.covered(), 40)
        c.add(50, 50)
        self.assertEqual(c.covered(), 40)

    def test_burner_bounds_clients(self):
        b = ss.Burner(100, max_clients=3)
        for i in range(10):
            b.served(f"ip{i}", 0, 50)
        self.assertEqual(len(b.clients), 3)
        self.assertTrue(b.served("ip9", 50, 100))
        self.assertEqual(b.completed, 1)


class LauncherTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        run = os.path.join(self.tmp, "run")
        os.mkdir(run, 0o700)
        self.env = dict(os.environ, PORCH_CONFIG="none", XDG_RUNTIME_DIR=run)

    def seal(self, args):
        return subprocess.run([BIN_SEAL, *args, "--bg"], capture_output=True, text=True,
                              env=self.env, stdin=subprocess.DEVNULL, timeout=30)

    def test_refuses_non_sealed_file(self):
        p = os.path.join(self.tmp, "plain.txt")
        with open(p, "w") as f:
            f.write("not sealed")
        r = self.seal([p, "seal-x"])
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("not a sealed file", r.stderr)

    @NEEDS_CRYPTO
    def test_owned_file_rules(self):
        sealed = os.path.join(self.tmp, "x.pseal")
        ps.seal_file(io.BytesIO(b"hi"), sealed, "x", "text/plain")
        r = self.seal([sealed, "seal-x", "--owned-file"])
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("--owned-file only applies", r.stderr)
        loose = os.path.join(self.tmp, "loose")
        os.mkdir(loose)
        os.chmod(loose, 0o777)
        r = self.seal([sealed, "seal-x", "--owned-file", "--owned-dir", loose])
        self.assertEqual(r.returncode, 2)
        self.assertIn("not group/world writable", r.stderr)
        other = os.path.join(self.tmp, "other")
        os.mkdir(other, 0o700)
        r = self.seal([sealed, "seal-x", "--owned-file", "--owned-dir", other])
        self.assertEqual(r.returncode, 2)
        self.assertIn("only applies", r.stderr)
        r = self.seal([sealed, "seal-x", "--owned-dir", other])
        self.assertEqual(r.returncode, 2)
        self.assertIn("only makes sense with --owned-file", r.stderr)
        self.assertTrue(os.path.exists(sealed))
        r = self.seal([sealed, "seal-x", "--password=x"])
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()

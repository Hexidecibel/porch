"""Tests for lib/serveserver.py (bin/serve). Stdlib unittest; temp dirs only."""

import http.client
import importlib.util
import os
import shutil
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "serveserver", os.path.join(_HERE, "..", "lib", "serveserver.py"))
ss = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ss)
ss.ServeHandler.log_message = lambda *a, **k: None     # keep test output quiet


class ServeTests(unittest.TestCase):

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.root = os.path.join(self.base, "site")
        self.outside = os.path.join(self.base, "outside")
        os.makedirs(os.path.join(self.root, ".git"))
        os.makedirs(os.path.join(self.root, "sub"))
        os.makedirs(os.path.join(self.root, "noindex"))
        os.makedirs(self.outside)
        self._w("site/index.html", "<h1>hi</h1>")
        self._w("site/.env", "SECRET=1")
        self._w("site/.git/config", "[core]")
        self._w("site/sub/file.txt", "hello")
        self._w("site/noindex/a.txt", "a")
        self._w("outside/secret.txt", "TOP SECRET")
        os.symlink(os.path.join(self.outside, "secret.txt"), os.path.join(self.root, "escape.txt"))
        os.symlink(self.outside, os.path.join(self.root, "escdir"))
        os.symlink(os.path.join(self.root, ".git"), os.path.join(self.root, "notes"))
        os.symlink(os.path.join(self.root, "sub", "file.txt"), os.path.join(self.root, "inside.txt"))
        self.start()

    def start(self, **kw):
        H = ss.make_handler(self.root, **kw)
        self.H = H
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.base, ignore_errors=True)

    def _w(self, rel, text):
        with open(os.path.join(self.base, rel), "w") as f:
            f.write(text)

    def get(self, path, method="GET"):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request(method, path)
        r = c.getresponse()
        body = r.read()
        c.close()
        return r, body

    def test_denies_dotfiles(self):
        for p in ("/.env", "/.git/config", "/.git/", "/%2eenv", "/sub/../.env",
                  "/notes/config", "/.", "/sub/.hidden"):
            r, body = self.get(p)
            self.assertEqual(r.status, 404, p)
            self.assertNotIn(b"SECRET", body)
            self.assertNotIn(b"[core]", body)

    def test_denies_traversal_and_symlink_escape(self):
        for p in ("/../outside/secret.txt", "/%2e%2e/outside/secret.txt",
                  "/sub/%2e%2e/%2e%2e/outside/secret.txt", "/escape.txt",
                  "/escdir/secret.txt", "/escdir/", "/sub%2f..%2f..%2foutside%2fsecret.txt",
                  "/..%5coutside%5csecret.txt"):
            r, body = self.get(p)
            self.assertEqual(r.status, 404, p)
            self.assertNotIn(b"TOP SECRET", body)

    def test_serves_normal_files_with_headers(self):
        r, body = self.get("/sub/file.txt")
        self.assertEqual(r.status, 200)
        self.assertEqual(body, b"hello")
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
        r, body = self.get("/")
        self.assertEqual((r.status, body), (200, b"<h1>hi</h1>"))
        self.assertIn("sandbox", r.getheader("Content-Security-Policy"))
        r, _ = self.get("/inside.txt")          # symlink that stays inside
        self.assertEqual(r.status, 200)
        r, _ = self.get("/sub")
        self.assertEqual((r.status, r.getheader("Location")), (301, "/sub/"))

    def test_sandbox_only_on_active_types(self):
        for name in ("v.mp4", "a.mp3", "p.png", "d.pdf", "f.woff2", "s.css", "t.txt"):
            self._w("site/" + name, "x")
            r, _ = self.get("/" + name)
            self.assertEqual(r.status, 200, name)
            csp = r.getheader("Content-Security-Policy")
            self.assertNotIn("sandbox", csp, name)
            self.assertIn("object-src 'none'", csp, name)
            self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff", name)
        for name in ("i.svg", "x.xml", "x.xhtml", "page.html", "blob.unknownext"):
            self._w("site/" + name, "x")
            r, _ = self.get("/" + name)
            self.assertIn("sandbox", r.getheader("Content-Security-Policy"), name)
        self.assertEqual(self.get("/v.mp4")[0].getheader("Content-Type"), "video/mp4")
        # Errors and redirects keep the sandbox.
        self.assertIn("sandbox", self.get("/nope")[0].getheader("Content-Security-Policy"))

    def test_compressed_files_are_served_as_themselves(self):
        for name, want in (("a.tar.gz", "application/gzip"), ("b.tgz", "application/gzip"),
                           ("c.svgz", "application/gzip"), ("d.bz2", "application/x-bzip2"),
                           ("e.xz", "application/x-xz")):
            self._w("site/" + name, "x")
            r, body = self.get("/" + name)
            self.assertEqual(r.status, 200, name)
            self.assertIsNone(r.getheader("Content-Encoding"), name)
            self.assertEqual(r.getheader("Content-Type"), want, name)
            self.assertEqual(body, b"x")

    def test_redirect_never_protocol_relative(self):
        os.makedirs(os.path.join(self.root, "evil.com"))
        for path in ("//evil.com", "///evil.com", "/%2Fevil.com"):
            r, _ = self.get(path)
            loc = r.getheader("Location") or ""
            self.assertFalse(loc.startswith("//"), (path, loc))
            if r.status == 301 and "%" not in path:
                self.assertEqual(loc, "/evil.com/")

    def test_no_listing_by_default(self):
        r, _ = self.get("/noindex/")
        self.assertEqual(r.status, 404)

    def test_listing_with_flag_hides_dotfiles(self):
        self.server.shutdown()
        self.server.server_close()
        self.start(allow_list=True)
        os.makedirs(os.path.join(self.root, "noindex", ".git"))
        r, body = self.get("/noindex/")
        self.assertEqual(r.status, 200)
        self.assertIn(b"a.txt", body)
        self.assertNotIn(b".git", body)

    def test_allow_scripts_drops_sandbox(self):
        self.server.shutdown()
        self.server.server_close()
        self.start(allow_scripts=True)
        r, _ = self.get("/")
        self.assertNotIn("sandbox", r.getheader("Content-Security-Policy"))

    def test_get_head_only(self):
        r, _ = self.get("/", method="POST")
        self.assertEqual(r.status, 405)
        r, body = self.get("/sub/file.txt", method="HEAD")
        self.assertEqual((r.status, body), (200, b""))


if __name__ == "__main__":
    unittest.main()

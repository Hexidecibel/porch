"""Unit tests for lib/porch_http.py, the shared HTTP core. Stdlib only;
temp dirs and ephemeral 127.0.0.1 ports."""

import email.message
import io
import json
import os
import socket
import sys
import tempfile
import threading
import types
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path

_LIB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib")
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
import porch_http as ph  # noqa: E402


def hdrs(pairs):
    m = email.message.Message()
    for k, v in pairs:
        m[k] = v
    return m


def fake(headers=(), peer="127.0.0.1", body=b""):
    return types.SimpleNamespace(headers=hdrs(headers), client_address=(peer, 1234),
                                 rfile=io.BytesIO(body))


class ClientIpTest(unittest.TestCase):
    def test_xff_only_from_loopback(self):
        h = [("X-Forwarded-For", "6.6.6.6, 1.2.3.4, 127.0.0.1")]
        self.assertEqual(ph.client_ip(fake(h)), "1.2.3.4")          # right-most non-loopback
        self.assertEqual(ph.client_ip(fake(h, peer="5.5.5.5")), "5.5.5.5")
        self.assertEqual(ph.client_ip(fake()), "127.0.0.1")
        self.assertEqual(ph.client_ip(fake([("X-Forwarded-For", "<script>")])), "127.0.0.1")


class ContentLengthTest(unittest.TestCase):
    def test_values(self):
        self.assertEqual(ph.content_length(fake()), 0)
        self.assertEqual(ph.content_length(fake([("Content-Length", "42")])), 42)
        self.assertEqual(ph.content_length(fake([("Content-Length", "")])), 0)
        for bad in ("-1", "+5", "5_0", "abc", "1" * 40, "0x10"):
            self.assertEqual(ph.content_length(fake([("Content-Length", bad)])), -1, bad)
        self.assertEqual(ph.content_length(fake([("Content-Length", "5"), ("Content-Length", "6")])), -1)
        self.assertEqual(ph.content_length(fake([("Content-Length", "5"), ("Content-Length", "5")])), 5)

    def test_read_json_body(self):
        b = json.dumps({"a": 1}).encode()
        self.assertEqual(ph.read_json_body(fake([("Content-Length", str(len(b)))], body=b), 100), {"a": 1})
        self.assertIsNone(ph.read_json_body(fake([("Content-Length", str(len(b)))], body=b), 3))
        self.assertEqual(ph.read_json_body(fake(), 100), {})
        self.assertIsNone(ph.read_json_body(fake([("Content-Length", "2")], body=b"[]"), 100))


class SameOriginTest(unittest.TestCase):
    def test_rules(self):
        H = ("Host", "a.example.com")
        self.assertTrue(ph.same_origin(fake([H, ("Origin", "https://a.example.com")])))
        self.assertTrue(ph.same_origin(fake([H, ("Referer", "https://a.example.com/x")])))
        self.assertFalse(ph.same_origin(fake([H, ("Origin", "https://b.example.com")])))
        self.assertFalse(ph.same_origin(fake([H, ("Origin", "null")])))
        self.assertFalse(ph.same_origin(fake([H])))
        self.assertFalse(ph.same_origin(fake([("Origin", "https://a.example.com")])))


class RangeTest(unittest.TestCase):
    def test_parse(self):
        p = ph.parse_range
        self.assertEqual(p("bytes=0-9", 100), (0, 9))
        self.assertEqual(p("bytes=90-", 100), (90, 99))
        self.assertEqual(p("bytes=-10", 100), (90, 99))
        self.assertEqual(p("bytes=50-1000", 100), (50, 99))
        self.assertEqual(p("bytes=100-", 100), "unsatisfiable")
        self.assertEqual(p("bytes=-0", 100), "unsatisfiable")
        self.assertEqual(p("bytes=9-3", 100), "unsatisfiable")
        self.assertIsNone(p("bytes=0-1,5-6", 100))
        self.assertIsNone(p("bytes=" + "9" * 40 + "-", 100))
        self.assertIsNone(p("items=0-1", 100))
        self.assertIsNone(p(None, 100))
        self.assertIsNone(p("bytes=0-1", 0))


class FilenameTest(unittest.TestCase):
    def test_safe_stem_and_sanitize(self):
        self.assertEqual(ph.safe_stem("..\\..\\etc\\passwd.jpg"), "passwd")
        self.assertEqual(ph.safe_stem("-rf .x"), "rf")
        self.assertEqual(ph.safe_stem(".-a b.c.jpg"), "a_b.c")
        self.assertEqual(ph.safe_stem("\x00"), "upload")
        self.assertEqual(ph.sanitize_filename("../../.ssh/id_rsa"), "id_rsa")
        self.assertEqual(ph.sanitize_filename(".env"), "upload_env")
        self.assertEqual(ph.sanitize_filename("a b<c>.txt"), "a_b_c_.txt")
        self.assertEqual(len(ph.sanitize_filename("x" * 300, 120)), 120)

    def test_safe_child_refuses_symlinks(self):
        d = Path(tempfile.mkdtemp())
        (d / "ok.txt").write_text("hi")
        os.symlink("/etc/passwd", d / "link.txt")
        self.assertEqual(ph.safe_child(d, "ok.txt")[0], (d / "ok.txt").resolve())
        self.assertIsNone(ph.safe_child(d, "link.txt")[0])


class MultipartTest(unittest.TestCase):
    def body(self, parts, boundary=b"XyZ"):
        out = b""
        for name, data in parts:
            out += (b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"f\"; filename=\""
                    + name.encode() + b"\"\r\n\r\n" + data + b"\r\n")
        return out + b"--" + boundary + b"--\r\n"

    def test_parts_stream(self):
        data = os.urandom(200 * 1024)
        raw = self.body([("a.bin", data), ("b.txt", b"hello")])
        seen = []
        s = ph.MultipartStreamer(io.BytesIO(raw), b"XyZ", len(raw), seen.append)
        got = [(fn, b"".join(it)) for fn, it in s.parts()]
        self.assertEqual(got, [("a.bin", data), ("b.txt", b"hello")])
        self.assertEqual(sum(seen), len(raw))

    def test_truncated_and_huge_headers(self):
        raw = self.body([("a", b"x" * 1000)])[:-30]
        s = ph.MultipartStreamer(io.BytesIO(raw), b"XyZ", len(raw))
        with self.assertRaises(ph.MultipartError):
            for _, it in s.parts():
                b"".join(it)
        raw = b"--XyZ\r\n" + b"H" * 40000
        s = ph.MultipartStreamer(io.BytesIO(raw), b"XyZ", len(raw))
        with self.assertRaises(ph.MultipartError):
            list(s.parts())

    def test_boundary(self):
        self.assertEqual(ph.multipart_boundary("multipart/form-data; boundary=abc")[0], b"abc")
        self.assertEqual(ph.multipart_boundary("text/plain")[1][1], 400)
        self.assertEqual(ph.multipart_boundary("multipart/form-data; boundary=" + "a" * 201)[1][0],
                         "Bad multipart boundary")


class AtomicWriteTest(unittest.TestCase):
    def test_replace_and_no_leftovers(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "x.json")
        ph.atomic_write_json(p, [1, 2])
        ph.atomic_write_json(p, [3])
        with open(p) as f:
            self.assertEqual(json.load(f), [3])
        self.assertEqual(os.listdir(d), ["x.json"])
        ph.atomic_write_bytes(p, b"s", mode=0o600)
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)


class ServerTest(unittest.TestCase):
    """make_server + stream_file + the header helpers, over a real socket."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.f = self.d / "f.bin"
        self.f.write_bytes(bytes(range(256)) * 4)

        test = self

        class H(ph.HardenedHandlerMixin, BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_GET(self):
                ph.stream_file(self, test.f, test.f.stat().st_size, "application/octet-stream",
                               "attachment", "f.bin")

        self.srv = ph.make_server(H, 0, "127.0.0.1", max_connections=2)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    def get(self, extra=b""):
        s = socket.create_connection(self.srv.server_address, timeout=5)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n" + extra + b"\r\n")
        data = b""
        while True:
            c = s.recv(65536)
            if not c:
                break
            data += c
        s.close()
        head, _, body = data.partition(b"\r\n\r\n")
        return head.decode(), body

    def test_full_range_and_416(self):
        head, body = self.get()
        self.assertIn(" 200 ", head.split("\r\n")[0])
        self.assertEqual(len(body), 1024)
        self.assertIn("X-Content-Type-Options: nosniff", head)
        self.assertIn("Content-Security-Policy: default-src 'none'; sandbox", head)
        head, body = self.get(b"Range: bytes=10-19\r\n")
        self.assertIn(" 206 ", head.split("\r\n")[0])
        self.assertIn("Content-Range: bytes 10-19/1024", head)
        self.assertEqual(body, bytes(range(10, 20)))
        head, _ = self.get(b"Range: bytes=5000-\r\n")
        self.assertIn(" 416 ", head.split("\r\n")[0])

    def test_max_connections_per_server(self):
        self.assertEqual(self.srv.max_connections, 2)
        self.assertEqual(ph.BoundedThreadingHTTPServer.max_connections, ph.DEFAULT_MAX_CONNECTIONS)

    def test_non_loopback_bind_warns(self):
        err = io.StringIO()
        saved, sys.stderr = sys.stderr, err
        try:
            srv = ph.make_server(BaseHTTPRequestHandler, 0, "0.0.0.0", tag="t")
            srv.server_close()
        finally:
            sys.stderr = saved
        self.assertIn("WARNING", err.getvalue())


class CspTest(unittest.TestCase):
    def test_page_csp(self):
        n = ph.csp_nonce()
        self.assertGreaterEqual(len(n), 16)
        self.assertNotEqual(n, ph.csp_nonce())
        c = ph.page_csp(n)
        self.assertIn(f"script-src 'nonce-{n}'", c)
        self.assertIn("frame-ancestors 'none'", c)

    def test_cookies(self):
        self.assertEqual(ph.parse_cookies("a=1; b=2; a=3"), {"a": "3", "b": "2"})
        self.assertEqual(ph.parse_cookies(""), {})


class AssetRouteTest(unittest.TestCase):
    """/__porch-assets/: porch.css + fonts, exact-path table, immutable."""

    def setUp(self):
        class H(ph.HardenedHandlerMixin, BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_GET(self):
                if ph.serve_asset(self):
                    return
                self.send_response(299)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_HEAD(self):
                if not ph.serve_asset(self, head=True):
                    self.send_response(299)
                    self.send_header("Content-Length", "0")
                    self.end_headers()

        self.srv = ph.make_server(H, 0, "127.0.0.1", tag="t")
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    def req(self, path, method="GET", extra=b""):
        s = socket.create_connection(self.srv.server_address, timeout=5)
        s.sendall(f"{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n".encode()
                  + extra + b"\r\n")
        data = b""
        while True:
            c = s.recv(65536)
            if not c:
                break
            data += c
        s.close()
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.decode().split("\r\n")
        hdrs = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(":")
            hdrs[k.strip().lower()] = v.strip()
        return int(lines[0].split()[1]), hdrs, body

    def test_prefix_is_not_the_auth_handoff_path(self):
        # HAProxy routes path_beg /__porch/ to the auth server on every host.
        self.assertFalse(ph.ASSET_PREFIX.startswith("/__porch/"))
        self.assertTrue(ph.PORCH_CSS_PATH.startswith(ph.ASSET_PREFIX))

    def test_css_served_hashed_and_immutable(self):
        code, h, body = self.req(ph.PORCH_CSS_PATH)
        self.assertEqual(code, 200)
        self.assertEqual(h["content-type"], "text/css; charset=utf-8")
        self.assertEqual(h["cache-control"], "public, max-age=31536000, immutable")
        self.assertEqual(h["x-content-type-options"], "nosniff")
        self.assertEqual(int(h["content-length"]), len(body))
        import hashlib
        self.assertIn(hashlib.sha256(body).hexdigest()[:12], ph.PORCH_CSS_PATH)
        self.assertIn(b"--ground:#121014", body)
        # every font url() was rewritten to a hashed path that is served
        import re
        fonts = re.findall(rb'url\("([^"]+)"\)', body)
        self.assertEqual(len(fonts), 7)
        for f in fonts:
            # relative to the stylesheet, so a path prefix carries over
            self.assertTrue(f.startswith(b"fonts/"), f)
            code, h2, fb = self.req(ph.ASSET_PREFIX + f.decode())
            self.assertEqual(code, 200, f)
            self.assertEqual(h2["content-type"], "font/woff2")
            self.assertEqual(fb[:4], b"wOF2")
            self.assertIn("immutable", h2["cache-control"])

    def test_head_and_etag(self):
        code, h, body = self.req(ph.PORCH_CSS_PATH, "HEAD")
        self.assertEqual((code, body), (200, b""))
        code, h2, body = self.req(ph.PORCH_CSS_PATH, extra=f"If-None-Match: {h['etag']}\r\n".encode())
        self.assertEqual((code, body), (304, b""))

    def test_unknown_stale_and_traversal_are_404(self):
        bad = [
            "/__porch-assets/porch.css",                    # unhashed
            "/__porch-assets/porch.000000000000.css",       # stale hash
            "/__porch-assets/fonts/geist-400.woff2",
            "/__porch-assets/../porch_http.py",
            "/__porch-assets/%2e%2e/porch_http.py",
            "/__porch-assets/fonts/../../porch.css",
            "/__porch-assets/..%2fauth.css",
            "/__porch-assets/",
            "/__porch-assets//etc/passwd",
        ]
        for path in bad:
            code, h, body = self.req(path)
            self.assertEqual(code, 404, path)
            self.assertEqual(h["content-type"], "text/plain; charset=utf-8")
            self.assertIn("sandbox", h["content-security-policy"])

    def test_other_paths_fall_through(self):
        for path in ("/", "/__porch/start", "/__porch-assetsx/a", "/x/__porch-assets/porch.css"):
            self.assertEqual(self.req(path)[0], 299, path)

    def test_query_string_ignored(self):
        self.assertEqual(self.req(ph.PORCH_CSS_PATH + "?v=1")[0], 200)

    def test_style_src_is_narrow(self):
        self.assertEqual(ph.porch_style_src("abc"), "style-src 'self' 'nonce-abc'; font-src 'self'")
        self.assertEqual(ph.porch_style_src(), "style-src 'self'; font-src 'self'")
        c = ph.page_csp("n1")
        self.assertIn("default-src 'none'", c)
        self.assertIn("style-src 'self' 'nonce-n1'", c)
        self.assertIn("font-src 'self'", c)
        self.assertNotIn("unsafe-inline", c)
        self.assertNotIn("*", c)
        self.assertNotIn("https:", c)
        self.assertNotIn("script-src 'self'", c)

    def test_base_prefix(self):
        class FakeHandler:
            def __init__(self, path):
                self.path = path
        # wrong or missing base: not ours, caller keeps routing (and 404s)
        self.assertFalse(ph.serve_asset(FakeHandler(ph.PORCH_CSS_PATH), base="/tok"))
        self.assertFalse(ph.serve_asset(FakeHandler("/other" + ph.PORCH_CSS_PATH), base="/tok"))
        self.assertIn('href="/tok/__porch-assets/', ph.porch_css_tag(base="/tok"))

    def test_css_tag(self):
        self.assertEqual(ph.porch_css_tag(), f'<link rel="stylesheet" href="{ph.PORCH_CSS_PATH}">')


if __name__ == "__main__":
    unittest.main()

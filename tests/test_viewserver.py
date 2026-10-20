"""Tests for lib/viewserver.py, the read-only viewer door (bin/view).

Stdlib unittest; real servers on 127.0.0.1:<ephemeral> in daemon threads, no
network. The markdown sanitizer runs in node when node is on PATH.
"""

import http.client
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile

LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib")
sys.path.insert(0, LIB)

import porch_http as ph  # noqa: E402
import viewserver as vs  # noqa: E402

PNG = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00"
       b"\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02\xfe\xa7"
       b"5\x81\x84\x00\x00\x00\x00IEND\xaeB`\x82")
PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"

GIT_DIFF = """\
From 0123456789abcdef0123456789abcdef01234567 Mon Sep 17 00:00:00 2001
Subject: [PATCH] demo

diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,4 +1,4 @@
 import os
--- a removed line that looks like a header
+print("hi")
 x = 1
 y = 2
diff --git a/new.txt b/new.txt
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/new.txt
@@ -0,0 +1,2 @@
+one
+two
diff --git a/gone.txt b/gone.txt
deleted file mode 100644
--- a/gone.txt
+++ /dev/null
@@ -1 +0,0 @@
-bye
\\ No newline at end of file
diff --git a/old.md b/renamed.md
similarity index 100%
rename from old.md
rename to renamed.md
"""

PLAIN_DIFF = """\
--- a.txt\t2024-01-01
+++ a.txt\t2024-01-02
@@ -1,2 +1,2 @@
-a
+A
 b
--- b.txt
+++ b.txt
@@ -3 +3,2 @@
 c
+d
"""


def serve(testcase, handler):
    srv = ph.make_server(handler, 0, "127.0.0.1", tag="t")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    testcase.addCleanup(srv.server_close)
    testcase.addCleanup(srv.shutdown)
    return srv.server_address[1]


def get(port, path, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("GET", path, headers=headers or {})
    r = c.getresponse()
    body = r.read()
    c.close()
    return r, body


class Base(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)

    def write(self, name, data):
        p = os.path.join(self.dir, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())
        return p

    def up(self, name, data, **kw):
        H = vs.make_handler(self.write(name, data), "t", **kw)
        H.log_message = lambda *a: None
        return serve(self, H), H


class SniffTests(unittest.TestCase):

    def test_magic_beats_extension(self):
        self.assertEqual(vs.sniff_bytes(PNG, "notes.txt").mode, "image")
        self.assertEqual(vs.sniff_bytes(PDF, "readme.md").mode, "pdf")
        self.assertEqual(vs.sniff_bytes(b"PK\x03\x04rest", "x.json").mode, "zip")
        self.assertEqual(vs.sniff_bytes(b"ID3\x03\x00", "song.txt").mode, "audio")
        self.assertEqual(vs.sniff_bytes(b"\x00\x00\x00\x18ftypmp42", "a.md").mime, "video/mp4")
        self.assertEqual(vs.sniff_bytes(b"\x00\x00\x00\x18ftypM4A ", "a").mode, "audio")

    def test_text_by_extension_and_content(self):
        self.assertEqual(vs.sniff_bytes(b"# hi", "a.md").mode, "markdown")
        self.assertEqual(vs.sniff_bytes(b"a,b\n1,2", "a.csv").mode, "csv")
        self.assertEqual(vs.sniff_bytes(b"x=1", "a.py"), vs.Sniff("code", "text/plain", "python"))
        self.assertEqual(vs.sniff_bytes(b"plain", "a.log").mode, "text")
        self.assertEqual(vs.sniff_bytes(b'{"a": 1}', "data", complete=True).mode, "json")
        self.assertEqual(vs.sniff_bytes(b'{"a": 1', "data", complete=False).mode, "text")
        self.assertEqual(vs.sniff_bytes(GIT_DIFF.encode(), "change").mode, "diff")
        self.assertEqual(vs.sniff_bytes(b"\x00\x01\x02binary", "a.txt").mode, "other")
        self.assertEqual(vs.sniff_bytes(b"<svg onload=x>", "a.svg").mode, "code")


class PageTests(Base):

    def check_page(self, port, worker=False):
        r, body = get(port, "/")
        self.assertEqual(r.status, 200)
        self.assertIn(b'data-app="serve"', body)
        csp = r.getheader("Content-Security-Policy")
        self.assertIn("default-src 'none'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn("unsafe-eval", csp)
        self.assertNotIn("*", csp)
        self.assertEqual("worker-src 'self'" in csp, worker)
        nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
        for tag in re.findall(rb"<(?:style|script)(?![^>]*\bsrc=)[^>]*>", body):
            if b'type="application/json"' in tag:
                continue
            self.assertIn(f'nonce="{nonce}"'.encode(), tag)
        self.assertNotIn(b' style="', body)
        self.assertIn(ph.porch_css_tag().encode(), body)
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
        cfg = json.loads(re.search(rb'<script type="application/json" id="cfg">(.*?)</script>',
                                   body, re.S).group(1))
        return body, cfg

    def test_each_mode_renders(self):
        cases = [
            ("a.md", "# hi", "markdown", [b"marked.min.js", b"highlight.min.js"], False),
            ("a.py", "x = 1\n", "code", [b"highlight.min.js"], False),
            ("a.txt", "hello\n", "text", [], False),
            ("a.pdf", PDF, "pdf", [b"pdf.min.mjs"], True),
            ("a.csv", "a,b\n1,2\n", "csv", [], False),
            ("a.tsv", "a\tb\n1\t2\n", "tsv", [], False),
            ("a.json", '{"a": 1}', "json", [b"highlight.min.js"], False),
            ("a.diff", GIT_DIFF, "diff", [], False),
            ("a.png", PNG, "image", [], False),
            ("a.bin", b"\x00\x01\x02", "other", [], False),
        ]
        for name, data, mode, scripts, worker in cases:
            with self.subTest(name=name):
                port, _ = self.up(name, data)
                body, cfg = self.check_page(port, worker)
                self.assertEqual(cfg["mode"], mode)
                for s in scripts:
                    self.assertIn(s, body)
                if mode not in ("markdown", "zip"):
                    self.assertNotIn(b"marked.min.js", body)

    def test_zip_page(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("a.txt", "x")
        port, _ = self.up("a.zip", buf.getvalue())
        body, cfg = self.check_page(port, worker=True)
        self.assertEqual(cfg["mode"], "zip")
        self.assertIn(b"pdf.min.mjs", body)

    def test_follow_page(self):
        port, H = self.up("app.log", "x\n", follow=True, start_follower=False)
        body, cfg = self.check_page(port)
        self.assertTrue(cfg["follow"])
        self.assertIn(b"Live log", body)

    def test_hostile_filename_stays_text(self):
        name = 'x__SCRIPTS__</script><img src=x onerror=1>.txt'
        port, _ = self.up(name.replace("/", "_"), "hi")
        body, cfg = self.check_page(port)
        self.assertNotIn(b"<img src=x", body)
        self.assertIn(b"x__SCRIPTS__", body)                # never substituted
        self.assertIn("onerror", cfg["file"])               # JSON carries it as data

    def test_as_override(self):
        port, H = self.up("notes.txt", "# not markdown by name", mode="markdown")
        _, cfg = self.check_page(port)
        self.assertEqual(cfg["mode"], "markdown")

    def test_static_files(self):
        port, _ = self.up("a.txt", "x")
        for path in vs.STATIC_FILES:
            r, body = get(port, path)
            self.assertEqual(r.status, 200, path)
            self.assertTrue(body)
        r, _ = get(port, "/static/pdfjs/pdf.worker.min.mjs")
        self.assertTrue(r.getheader("Content-Type").startswith("text/javascript"))

    def test_pdf_cmaps_and_standard_fonts(self):
        cmaps = [p for p in vs.STATIC_FILES if p.startswith(vs.PDF_CMAPS)]
        fonts = [p for p in vs.STATIC_FILES if p.startswith(vs.PDF_STD_FONTS)]
        self.assertGreater(len(cmaps), 150)
        self.assertIn(vs.PDF_CMAPS + "UniJIS-UCS2-H.bcmap", cmaps)
        self.assertIn(vs.PDF_STD_FONTS + "FoxitSerif.pfb", fonts)
        self.assertIn(vs.PDF_STD_FONTS + "LiberationSans-Regular.ttf", fonts)
        self.assertFalse([p for p in cmaps + fonts if "LICENSE" in p])
        port, _ = self.up("a.pdf", PDF)
        r, body = get(port, vs.PDF_STD_FONTS + "LiberationSans-Regular.ttf")
        self.assertEqual((r.status, r.getheader("Content-Type")), (200, "font/ttf"))
        r, _ = get(port, vs.PDF_CMAPS + "Adobe-Japan1-UCS2.bcmap")
        self.assertEqual((r.status, r.getheader("Content-Type")), (200, "application/octet-stream"))
        self.assertEqual(get(port, vs.PDF_CMAPS + "../pdf.min.mjs")[0].status, 404)
        page = get(port, "/")[1].decode()
        self.assertIn("cMapUrl: new URL('/static/pdfjs/cmaps/'", page)
        self.assertIn("standardFontDataUrl: new URL('/static/pdfjs/standard_fonts/'", page)

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_markdown_sanitizer(self):
        page = vs.PAGE_HTML
        block = page[page.index("// BEGIN markdown-sanitize"):page.index("// END markdown-sanitize")]
        script = (
            "globalThis.location = {href: 'https://v.example/', origin: 'https://v.example'};\n"
            f"const marked = require({json.dumps(os.path.join(LIB, 'vendor', 'marked.min.js'))});\n"
            + block +
            "\nconst R = s => renderMd(s, 'https://v.example/zip/e/docs/a.md');\n"
            "console.log(JSON.stringify({\n"
            "  script: R('<script>alert(1)</script>'),\n"
            "  inline: R('a <img src=x onerror=alert(1)> b'),\n"
            "  banner: R('<p align=\"center\"><a href=\"#x\"><b>Get started</b></a></p>'),\n"
            "  amp: R('<span>R&D &nbsp; x</span>'),\n"
            "  js: R('[c](javascript:alert(1))'),\n"
            "  jsTab: R('[c](java\\tscript:alert(1))'),\n"
            "  data: R('[c](data:text/html,x)'),\n"
            "  auto: R('<javascript:alert(1)>'),\n"
            "  imgJs: R('![x](javascript:alert(1))'),\n"
            "  imgFar: R('![x](https://evil.example/t.png)'),\n"
            "  imgRel: R('![pic](img.png)'),\n"
            "  ok: R('[ok](https://example.com/a?b=\"c\")'),\n"
            "  mail: R('[m](mailto:a@example.com)'),\n"
            "  code: R('```\\n<b>x</b>\\n```'),\n"
            "}));\n"
        )
        out = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        c = json.loads(out.stdout)
        self.assertNotIn("<script", c["script"])
        self.assertNotIn("alert", c["script"])                # dropped with its tag
        self.assertNotIn("<img", c["inline"])
        self.assertNotIn("onerror", c["inline"])
        self.assertIn("Get started", c["banner"])
        self.assertNotIn("<p", c["banner"])
        self.assertNotIn("<a", c["banner"])
        self.assertIn("&amp;", c["amp"])
        self.assertIn("&nbsp;", c["amp"])
        for k in ("js", "jsTab", "data", "auto", "imgJs"):
            self.assertNotIn("href", c[k], k)
            self.assertNotIn("<img", c[k], k)
        self.assertNotIn("<img", c["imgFar"])
        self.assertIn('src="https://v.example/zip/e/docs/img.png"', c["imgRel"])
        self.assertIn('href="https://example.com/a?b=%22c%22"', c["ok"])
        self.assertIn('rel="noopener noreferrer nofollow"', c["ok"])
        self.assertIn('href="mailto:a@example.com"', c["mail"])
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", c["code"])


class RawAndConfinementTests(Base):

    def test_raw_headers(self):
        port, _ = self.up('we"ird name.md', "# hi\n")
        r, body = get(port, "/raw")
        self.assertEqual(r.status, 200)
        self.assertEqual(body, b"# hi\n")
        self.assertEqual(r.getheader("Content-Type"), "application/octet-stream")
        self.assertEqual(r.getheader("Content-Disposition"), 'attachment; filename="we_ird_name.md"')
        self.assertEqual(r.getheader("Content-Security-Policy"), ph.SANDBOX_CSP)
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")

    def test_inline_file_only_for_media(self):
        port, _ = self.up("a.png", PNG)
        r, body = get(port, "/file")
        self.assertEqual((r.status, r.getheader("Content-Type")), (200, "image/png"))
        self.assertEqual(r.getheader("Content-Security-Policy"), ph.SANDBOX_CSP)
        port, _ = self.up("b.html", "<script>x</script>")
        self.assertEqual(get(port, "/file")[0].status, 404)
        port, _ = self.up("c.svg", "<svg/>", mode="image")      # never served as an image
        self.assertEqual(get(port, "/file")[0].status, 404)

    def test_content_and_caps(self):
        port, H = self.up("a.txt", "0123456789abcdef", max_text=10)
        r, body = get(port, "/content")
        self.assertEqual(body, b"0123456789")
        self.assertEqual(r.getheader("X-Porch-Truncated"), "1")
        self.assertEqual(r.getheader("X-Porch-Total"), "16")
        self.assertEqual(r.getheader("Content-Security-Policy"), ph.SANDBOX_CSP)
        port, _ = self.up("a.json", json.dumps({"k": "v" * 200}), max_json=100)
        r, body = get(port, "/content")
        self.assertEqual(r.status, 413)
        self.assertIn("Download", json.loads(body)["error"])
        port, _ = self.up("b.json", '{"k": 1}')
        r, body = get(port, "/content")
        self.assertEqual((r.status, body), (200, b'{"k": 1}'))

    def test_table_caps(self):
        rows = "name,qty\n" + "".join(f"item{i},{i}\n" for i in range(20))
        port, _ = self.up("a.csv", rows, max_table_rows=5)
        d = json.loads(get(port, "/table")[1])
        self.assertEqual(d["header"], ["name", "qty"])
        self.assertEqual(len(d["rows"]), 5)
        self.assertTrue(d["truncated"])
        port, _ = self.up("b.tsv", "a\tb\n1\t2,3\n")
        d = json.loads(get(port, "/table")[1])
        self.assertEqual((d["delimiter"], d["rows"]), ("\t", [["1", "2,3"]]))
        self.assertFalse(d["truncated"])
        port, _ = self.up("c.csv", rows, max_table_bytes=40)       # cut mid-file
        d = json.loads(get(port, "/table")[1])
        self.assertTrue(d["truncated"])
        self.assertTrue(all(len(r) == 2 for r in d["rows"]))

    def test_paths_outside_never_served(self):
        secret = self.write("secret.txt", "TOPSECRET")
        port, _ = self.up("shared.txt", "public")
        for path in ("/raw/../secret.txt", "/../secret.txt", "/secret.txt", "/%2e%2e/secret.txt",
                     "/static/../viewserver.py", "/static/pdfjs/../../viewserver.py",
                     "/static/highlight.min.js/../../porch_http.py", "/file/../secret.txt",
                     "/zip/list", "/zip/e/secret.txt", "/events", "/content?e=secret.txt",
                     "/__porch-assets/../viewserver.py"):
            r, body = get(port, path)
            self.assertIn(r.status, (403, 404), path)
            self.assertNotIn(b"TOPSECRET", body, path)
            self.assertNotIn(b"import ", body, path)
        # The shared file swapped for a symlink after start: refused, not followed.
        shared = os.path.join(self.dir, "shared.txt")
        os.unlink(shared)
        os.symlink(secret, shared)
        for path in ("/raw", "/content", "/table"):
            r, body = get(port, path)
            self.assertNotIn(b"TOPSECRET", body, path)
            self.assertEqual(r.status, 410, path)

    def test_inline_and_zip_never_follow_a_swapped_symlink(self):
        other = self.make_secret_zip()
        port, _ = self.up("shared.png", PNG)
        shared = os.path.join(self.dir, "shared.png")
        os.unlink(shared)
        os.symlink(self.write("secret.png", PNG + b"TOPSECRET"), shared)
        r, body = get(port, "/file")
        self.assertEqual(r.status, 410)
        self.assertNotIn(b"TOPSECRET", body)
        # a zip door whose archive becomes a link to another archive
        H = vs.make_handler(self.write("pub.zip", self.zip_bytes([("ok.txt", "public")])), "z")
        H.log_message = lambda *a: None
        port = serve(self, H)
        self.assertEqual(get(port, "/zip/e/ok.txt")[1], b"public")
        os.unlink(os.path.join(self.dir, "pub.zip"))
        os.symlink(other, os.path.join(self.dir, "pub.zip"))
        for path in ("/zip/list", "/zip/e/secret.txt", "/content?e=secret.txt"):
            r, body = get(port, path)
            self.assertEqual(r.status, 410, path)
            self.assertNotIn(b"secret", body, path)

    def zip_bytes(self, entries):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for item in entries:
                z.writestr(*item)
        return buf.getvalue()

    def make_secret_zip(self):
        return self.write("other.zip", self.zip_bytes([("secret.txt", "TOPSECRET")]))

    def test_directory_refused(self):
        with self.assertRaises(ValueError):
            vs.make_handler(self.dir)


class DiffTests(unittest.TestCase):

    def test_git_diff(self):
        d = vs.parse_diff(GIT_DIFF)
        self.assertIn("Subject: [PATCH] demo", d["preamble"])
        files = {f["new"] or f["old"]: f for f in d["files"]}
        self.assertEqual(len(d["files"]), 4)
        app = files["app.py"]
        self.assertEqual((app["status"], app["adds"], app["dels"]), ("modified", 1, 1))
        lines = app["hunks"][0]["lines"]
        self.assertEqual(lines[1], ["-", 2, None, "-- a removed line that looks like a header"])
        self.assertEqual(lines[2], ["+", None, 2, 'print("hi")'])
        self.assertEqual(lines[-1], [" ", 4, 4, "y = 2"])
        self.assertEqual(files["new.txt"]["status"], "added")
        self.assertEqual(files["new.txt"]["adds"], 2)
        gone = files["gone.txt"]
        self.assertEqual(gone["status"], "deleted")
        self.assertEqual(gone["hunks"][0]["lines"][-1][0], "\\")
        ren = files["renamed.md"]
        self.assertEqual((ren["status"], ren["old"]), ("renamed", "old.md"))

    def test_plain_unified(self):
        d = vs.parse_diff(PLAIN_DIFF)
        self.assertEqual([f["old"] for f in d["files"]], ["a.txt", "b.txt"])
        self.assertEqual(d["files"][1]["hunks"][0]["lines"], [[" ", 3, 3, "c"], ["+", None, 4, "d"]])

    def test_huge_git_header_is_linear(self):
        t0 = time.monotonic()
        d = vs.parse_diff("diff --git " + "a " * 200000 + "\n@@ -1 +1 @@\n-x\n+y\n")
        self.assertLess(time.monotonic() - t0, 2)
        self.assertEqual(len(d["files"]), 1)
        self.assertEqual(d["files"][0]["adds"], 1)

    def test_line_cap(self):
        self.assertTrue(vs.parse_diff(PLAIN_DIFF, max_lines=3)["truncated"])


class ZipTests(Base):

    def make_zip(self, entries, name="a.zip", encrypt=()):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for item in entries:
                z.writestr(*item)
        data = bytearray(buf.getvalue())
        # zipfile cannot write encrypted entries: set the "encrypted" flag bit
        # in the local header and the central directory record by hand.
        for n in encrypt:
            fn = n.encode()
            i = data.find(b"PK\x03\x04")
            while i >= 0:
                if data[i + 30:i + 30 + len(fn)] == fn:
                    data[i + 6] |= 1
                i = data.find(b"PK\x03\x04", i + 4)
            i = data.find(b"PK\x01\x02")
            while i >= 0:
                if data[i + 46:i + 46 + len(fn)] == fn:
                    data[i + 8] |= 1
                i = data.find(b"PK\x01\x02", i + 4)
        return self.write(name, bytes(data))

    def up_zip(self, entries, encrypt=(), **kw):
        H = vs.make_handler(self.make_zip(entries, encrypt=encrypt), "z", **kw)
        H.log_message = lambda *a: None
        return serve(self, H)

    def test_listing_and_entries(self):
        port = self.up_zip([
            ("docs/a.md", "# Title\n![p](img.png)"), ("docs/img.png", PNG), ("data.csv", "a,b\n1,2\n"),
            ("change.diff", PLAIN_DIFF), ("notes.txt", "hello"), ("prog.bin", b"\x00\x01"),
            ("../evil.txt", "x"), ("/abs.txt", "x"), ("dir\\win.txt", "x"), ("C:/drive.txt", "x"),
            ("locked.txt", "secret data"), ("bomb.bin", b"\x00" * (2 * 1024 * 1024)),
        ], encrypt=["locked.txt"])
        d = json.loads(get(port, "/zip/list")[1])
        by = {e["name"]: e for e in d["entries"]}
        self.assertFalse(d["truncated"])
        for bad in ("../evil.txt", "/abs.txt", "dir\\win.txt", "C:/drive.txt"):
            self.assertTrue(by[bad].get("unsafe"), bad)
        self.assertEqual(by["locked.txt"]["refused"], "encrypted")
        self.assertEqual(by["bomb.bin"]["refused"], "compression ratio too high")
        self.assertNotIn("refused", by["docs/a.md"])

        r, body = get(port, "/zip/e/docs/a.md")
        self.assertEqual((r.status, r.getheader("Content-Type")), (200, "text/plain; charset=utf-8"))
        self.assertEqual(r.getheader("Content-Security-Policy"), ph.SANDBOX_CSP)
        r, body = get(port, "/zip/e/docs/img.png")
        self.assertEqual((r.getheader("Content-Type"), body), ("image/png", PNG))
        r, _ = get(port, "/zip/e/docs/img.png?dl=1")
        self.assertEqual(r.getheader("Content-Type"), "application/octet-stream")
        self.assertTrue(r.getheader("Content-Disposition").startswith("attachment"))
        r, _ = get(port, "/zip/e/prog.bin")
        self.assertTrue(r.getheader("Content-Disposition").startswith("attachment"))
        meta = json.loads(get(port, "/zip/meta?e=docs%2Fa.md")[1])
        self.assertEqual((meta["mode"], meta["size"]), ("markdown", 21))
        self.assertEqual(json.loads(get(port, "/zip/meta?e=docs/img.png")[1])["mode"], "image")
        self.assertEqual(get(port, "/content?e=notes.txt")[1], b"hello")
        self.assertEqual(json.loads(get(port, "/table?e=data.csv")[1])["rows"], [["1", "2"]])
        self.assertEqual(len(json.loads(get(port, "/diff?e=change.diff")[1])["files"]), 2)

        for path, status in (("/zip/e/../evil.txt", 403), ("/zip/e/%2e%2e/evil.txt", 403),
                             ("/zip/e//abs.txt", 403), ("/zip/e/locked.txt", 403),
                             ("/zip/e/bomb.bin", 413), ("/zip/e/missing", 404),
                             ("/content?e=../evil.txt", 403), ("/zip/meta?e=locked.txt", 403)):
            r, body = get(port, path)
            self.assertEqual(r.status, status, path)
            self.assertNotIn(b"secret data", body)

    def test_entry_count_cap(self):
        port = self.up_zip([(f"f{i}.txt", str(i)) for i in range(5)], zip_max_entries=3)
        d = json.loads(get(port, "/zip/list")[1])
        self.assertTrue(d["truncated"])
        self.assertEqual((d["total"], len(d["entries"])), (5, 3))
        self.assertEqual(get(port, "/zip/e/f1.txt")[1], b"1")
        self.assertEqual(get(port, "/zip/e/f4.txt")[0].status, 404)

    def test_entry_size_cap(self):
        port = self.up_zip([("big.txt", "x" * 5000), ("small.txt", "ok")],
                           zip_max_entry_bytes=1000)
        by = {e["name"]: e for e in json.loads(get(port, "/zip/list")[1])["entries"]}
        self.assertEqual(by["big.txt"]["refused"], "too large to view")
        self.assertEqual(get(port, "/zip/e/big.txt")[0].status, 413)
        self.assertEqual(get(port, "/zip/e/small.txt")[1], b"ok")

    def test_central_directory_cap(self):
        entries = [(f"f{i}.txt", "x") for i in range(30)]
        H = vs.make_handler(self.make_zip(entries), "z")
        H.log_message = lambda *a: None
        port = serve(self, H)
        self.assertEqual(get(port, "/zip/list")[0].status, 200)
        with self.assertRaises(vs.EntryRefused) as cm:
            with vs._OpenZip(H.file_path, max_cd_entries=10):
                pass
        self.assertEqual(cm.exception.status, 413)
        with self.assertRaises(vs.EntryRefused):
            with vs._OpenZip(H.file_path, max_cd_bytes=100):
                pass
        with self.assertRaises(vs.EntryRefused):
            with vs._OpenZip(self.write("not.zip", b"PK\x03\x04 nope")):
                pass
        # every slot came back
        for _ in range(vs.ZIP_PARSERS + 1):
            with vs._OpenZip(H.file_path):
                pass

    def test_lying_header_refused(self):
        # An entry whose header claims a small size but inflates to more.
        info = zipfile.ZipInfo("x.txt")
        with self.assertRaises(vs.EntryRefused):
            p = self.make_zip([("x.txt", "y" * 4000)])
            with zipfile.ZipFile(p) as z:
                info = z.getinfo("x.txt")
            vs.read_zip_entry(p, "x.txt", max_bytes=100)
        self.assertIsNotNone(info)

    def test_unsafe_names(self):
        for n in ("../x", "a/../../x", "/x", "\\x", "a\\b", "C:x", "a\x00b", "a\nb", ""):
            self.assertTrue(vs.unsafe_zip_name(n), repr(n))
        for n in ("a.txt", "dir/a.txt", "dir/", "..a/b", "a..b"):
            self.assertFalse(vs.unsafe_zip_name(n), n)


class SSEClient:
    """Reads an SSE stream line by line from a raw socket."""

    def __init__(self, port, last_id=None, timeout=5):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        extra = f"Last-Event-ID: {last_id}\r\n" if last_id is not None else ""
        self.sock.sendall(f"GET /events HTTP/1.1\r\nHost: x\r\n{extra}\r\n".encode())
        self.f = self.sock.makefile("rb")
        self.status = int(self.f.readline().split()[1])
        self.headers = {}
        while True:
            line = self.f.readline().decode().strip()
            if not line:
                break
            k, v = line.split(":", 1)
            self.headers[k.lower()] = v.strip()

    def next_event(self):
        """('lines', id, [[kind, text], ...]) or ('ping', None, None)."""
        ev = {}
        while True:
            line = self.f.readline()
            if not line:
                raise EOFError
            line = line.decode().rstrip("\n")
            if line.startswith(": ping"):
                return ("ping", None, None)
            if line.startswith("retry:"):
                continue
            if line == "":
                if ev:
                    return (ev.get("event"), int(ev["id"]), json.loads(ev["data"]))
                continue
            k, v = line.split(": ", 1)
            ev[k] = v

    def lines_until(self, pred, limit=50):
        got = []
        for _ in range(limit):
            kind, _, data = self.next_event()
            if kind == "lines":
                got.extend(data)
                if pred(got):
                    return got
        raise AssertionError(f"never saw it: {got}")

    def close(self):
        try:
            self.f.close()
            self.sock.close()
        except OSError:
            pass


class FollowTests(Base):

    def start(self, initial="first\nsecond\n", **kw):
        self.log = self.write("app.log", initial)
        H = vs.make_handler(self.log, "f", follow=True, start_follower=False, **kw)
        H.log_message = lambda *a: None
        H.follower = vs.Follower(self.log, poll=0.05).start()
        self.addCleanup(H.follower.stop)
        return serve(self, H), H

    def append(self, text):
        with open(self.log, "a") as f:
            f.write(text)

    def test_backlog_append_truncate_rotate(self):
        port, H = self.start(heartbeat=5)
        c = SSEClient(port)
        self.addCleanup(c.close)
        self.assertEqual(c.status, 200)
        self.assertEqual(c.headers["content-type"], "text/event-stream; charset=utf-8")
        self.assertEqual(c.headers["cache-control"], "no-store")
        got = c.lines_until(lambda g: len(g) >= 2)
        self.assertEqual(got[:2], [["l", "first"], ["l", "second"]])
        self.append("third\npart")
        got = c.lines_until(lambda g: ["l", "third"] in g)
        self.assertNotIn(["l", "part"], got)                 # no newline yet
        self.append("ial\n")
        c.lines_until(lambda g: ["l", "partial"] in g)
        with open(self.log, "w") as f:
            f.write("fresh\n")
        got = c.lines_until(lambda g: ["l", "fresh"] in g)
        self.assertTrue(any(k == "n" and "truncated" in t for k, t in got), got)
        os.rename(self.log, self.log + ".1")
        self.append("rotated-in\n")
        got = c.lines_until(lambda g: ["l", "rotated-in"] in g)
        self.assertTrue(any(k == "n" and "rotated" in t for k, t in got), got)

    def test_resume_with_last_event_id(self):
        port, H = self.start()
        c = SSEClient(port)
        self.addCleanup(c.close)
        kind, last, data = c.next_event()
        self.assertEqual(kind, "lines")
        c.close()
        self.append("after\n")
        time.sleep(0.3)
        c2 = SSEClient(port, last_id=last)
        self.addCleanup(c2.close)
        self.assertEqual(c2.lines_until(lambda g: True), [["l", "after"]])

    def test_heartbeat(self):
        port, H = self.start(heartbeat=0.2)
        c = SSEClient(port)
        self.addCleanup(c.close)
        c.next_event()                                       # the backlog
        self.assertEqual(c.next_event()[0], "ping")

    def test_client_cap(self):
        port, H = self.start(max_clients=1, heartbeat=0.2)
        c = SSEClient(port)
        self.addCleanup(c.close)
        c.next_event()
        r, _ = get(port, "/events")
        self.assertEqual(r.status, 503)
        c.close()                     # the slot frees when a heartbeat hits the closed socket
        deadline = time.time() + 5
        while time.time() < deadline:
            c2 = SSEClient(port)
            if c2.status == 200:
                c2.close()
                break
            c2.close()
            time.sleep(0.2)
        else:
            self.fail("slot never freed")

    def test_ring_bounded(self):
        f = vs.Follower(self.write("big.log", "".join(f"{i}\n" for i in range(50))),
                        keep=10, poll=10).start()
        self.addCleanup(f.stop)
        items, skipped = f.since(0, 100)
        self.assertEqual([t for _, _, t in items], [str(i) for i in range(40, 50)])
        f._push([("l", f"more{i}") for i in range(20)])     # evicts seq 1..20
        items, skipped = f.since(1, 100)
        self.assertEqual(skipped, 19)
        self.assertEqual(items[0][2], "more10")

    def test_file_growing_faster_than_we_read_skips_ahead(self):
        log = self.write("fast.log", "")
        f = vs.Follower(log, keep=100, poll=10, backlog=1000, max_drain=64 * 1024).start()
        self.addCleanup(f.stop)
        with open(log, "a") as fh:
            fh.write("".join(f"line {i:06d}\n" for i in range(50000)))    # ~600 KB
        f.poll_once()
        items, _ = f.since(0, 1000)
        notes = [t for _, k, t in items if k == "n"]
        self.assertTrue(any("grew too fast" in t for t in notes), notes)
        self.assertEqual([t for _, k, t in items if k == "l"][-1], "line 049999")

    def test_clean_line(self):
        self.assertEqual(vs.clean_line("\x1b[31mred\x1b[0m"), "\x1b[31mred\x1b[0m")
        self.assertEqual(vs.clean_line("a\x1b[2Kb\x1b]0;title\x07c\rd\x07e"), "abcde")
        self.assertEqual(vs.clean_line("x\x1bcy\x1b"), "xy")
        self.assertEqual(len(vs.clean_line("z" * 20000)), vs.TAIL_MAX_LINE)


if __name__ == "__main__":
    unittest.main()

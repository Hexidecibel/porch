"""Porch's HAProxy error pages (lib/porch_errors.py, bin/haproxy-errors):
valid errorfiles (raw HTTP, headers, size), a CSP that names exactly their
inline style and script, nothing fetched from elsewhere, accepted by
`haproxy -c` and served by a throwaway HAProxy, and the installer's config
rewrite (dry run on a temp config)."""

import base64
import hashlib
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "lib"))
import porch_errors  # noqa: E402

REPO = os.path.join(_HERE, "..")
HAPROXY = shutil.which("haproxy")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class BuildTest(unittest.TestCase):
    def setUp(self):
        self.pages = porch_errors.build()

    def test_every_code_parses_and_fits_the_buffer(self):
        self.assertEqual(sorted(self.pages), [400, 403, 408, 429, 500, 502, 503, 504])
        for code, raw in self.pages.items():
            status, h, body = porch_errors.parse(raw)
            self.assertEqual(status, code)
            self.assertLess(len(raw), porch_errors.MAX_BYTES)
            self.assertLess(len(raw), 16384 - 1024)      # default bufsize - maxrewrite
            self.assertEqual(h["content-type"], "text/html; charset=utf-8")
            self.assertEqual(h["cache-control"], "no-store")
            self.assertEqual(h["x-content-type-options"], "nosniff")
            self.assertEqual(int(h["content-length"]), len(body))
            self.assertEqual("retry-after" in h, code == 429)
            self.assertTrue(raw.startswith(f"HTTP/1.1 {code} ".encode()))

    def test_csp_names_exactly_the_inline_style_and_script(self):
        for code, raw in self.pages.items():
            _, h, body = porch_errors.parse(raw)
            text = body.decode("utf-8")
            csp = h["content-security-policy"]
            self.assertNotIn("unsafe-inline", csp)
            self.assertIn("default-src 'none'", csp)
            for tag, directive in (("style", "style-src"), ("script", "script-src")):
                blocks = re.findall(rf"<{tag}>(.*?)</{tag}>", text, re.S)
                self.assertEqual(len(blocks), 1, (code, tag))
                digest = base64.b64encode(hashlib.sha256(blocks[0].encode()).digest()).decode()
                self.assertIn(f"{directive} 'sha256-{digest}'", csp)

    def test_self_contained_and_host_agnostic(self):
        for code, raw in self.pages.items():
            text = porch_errors.parse(raw)[2].decode("utf-8")
            self.assertNotRegex(text, r'(src|href)="(https?:)?//')
            self.assertNotIn("url(", text)
            self.assertNotIn("@import", text)
            self.assertNotIn("innerHTML", text)
            self.assertNotIn("cush.rocks", text)
            self.assertNotRegex(text, r"__[A-Z]+__")
            self.assertIn("location.hostname", text)
            self.assertIn(f'data-code="{code}"', text)

    def test_copy_and_modes(self):
        get = lambda c: porch_errors.parse(self.pages[c])[2].decode()  # noqa: E731
        for c in (502, 503):
            self.assertIn("Lights on, nobody home.", get(c))
            self.assertIn('data-mode="retry"', get(c))
        self.assertIn('data-mode="retry"', get(504))
        self.assertIn('data-mode="wait"', get(429))
        self.assertIn("Easy there.", get(429))
        self.assertIn('data-lamp="off"', get(403))

    def test_brand_is_escaped(self):
        raw = porch_errors.response(503, brand="A&B <x>")
        self.assertIn(b"A&amp;B &lt;x&gt;", raw)

    def test_check_dir(self):
        with tempfile.TemporaryDirectory() as d:
            porch_errors.write(d)
            self.assertEqual(porch_errors.check_dir(d), [])
            with open(os.path.join(d, "503.http"), "ab") as f:
                f.write(b"extra")
            self.assertTrue(porch_errors.check_dir(d))

    def test_too_big_is_refused(self):
        with open(porch_errors.TEMPLATE, encoding="utf-8") as f:
            tpl = f.read()
        big = tpl.replace("</main>", "<p>" + "x" * 20000 + "</p></main>")
        with self.assertRaises(porch_errors.ErrorPageError):
            porch_errors.response(503, template=big)


@unittest.skipUnless(HAPROXY, "haproxy not installed")
class HaproxyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.errs = os.path.join(self.tmp, "errors")
        porch_errors.write(self.errs)

    def config(self, port):
        lines = ["global", "\tlog stdout format raw local0 emerg", "defaults", "\tmode http",
                 "\ttimeout connect 1s", "\ttimeout client 5s", "\ttimeout server 5s"]
        lines += [f"\terrorfile {c} {self.errs}/{c}.http" for c in porch_errors.CODES]
        lines += ["frontend f", f"\tbind 127.0.0.1:{port}",
                  "\thttp-request deny deny_status 429 if { path /limit }",
                  "\thttp-request deny deny_status 403 if { path /forbid }",
                  "\tdefault_backend b", "backend b", f"\tserver s 127.0.0.1:{free_port()}"]
        p = os.path.join(self.tmp, "h.cfg")
        with open(p, "w") as f:
            f.write("\n".join(lines) + "\n")
        return p

    def test_haproxy_accepts_them(self):
        p = subprocess.run([HAPROXY, "-c", "-f", self.config(free_port())],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_a_throwaway_haproxy_serves_them(self):
        port = free_port()
        proc = subprocess.Popen([HAPROXY, "-db", "-f", self.config(port)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(proc.wait)
        self.addCleanup(proc.terminate)
        deadline = time.time() + 10
        while True:
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                break
            except OSError:
                if time.time() > deadline:
                    self.fail("haproxy did not start")
                time.sleep(0.1)
        for path, code in (("/", 503), ("/limit", 429), ("/forbid", 403)):
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5)
            e = cm.exception
            body = e.read()
            self.assertEqual(e.code, code)
            self.assertEqual(body, porch_errors.parse(porch_errors.response(code))[2])
            self.assertIn("sha256-", e.headers["Content-Security-Policy"])
            self.assertEqual(e.headers["Cache-Control"], "no-store")


@unittest.skipUnless(HAPROXY, "haproxy not installed")
class InstallerDryRunTest(unittest.TestCase):
    STOCK = """global
\tlog /dev/log local0
defaults
\tmode http
\ttimeout connect 5s
\ttimeout client 5s
\ttimeout server 5s

\terrorfile 400 /etc/haproxy/errors/400.http
\terrorfile 403 /etc/haproxy/errors/403.http
\terrorfile 404 {tmp}/404.http
\terrorfile 503 /etc/haproxy/errors/503.http

frontend f
\tbind 127.0.0.1:{port}
\tdefault_backend b
backend b
\tserver s 127.0.0.1:1
"""

    def run_dry(self, text):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "404.http"), "wb") as f:
                f.write(b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            cfg = os.path.join(d, "haproxy.cfg")
            with open(cfg, "w") as f:
                f.write(text.format(tmp=d, port=free_port()))
            env = dict(os.environ, PORCH_HAPROXY_CFG=cfg)
            return subprocess.run([os.path.join(REPO, "bin", "haproxy-errors"), "--dry-run"],
                                  capture_output=True, text=True, env=env, timeout=60), d

    def test_rewrites_the_block_adds_429_keeps_others(self):
        p, d = self.run_dry(self.STOCK)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        added = [ln[1:].strip() for ln in p.stdout.splitlines() if ln.startswith("+\t")]
        self.assertEqual(added[:8], [f"errorfile {c} /etc/haproxy/errors/porch/{c}.http"
                                     for c in porch_errors.CODES])
        # The custom 404 line stays (kept after ours, never dropped).
        removed = [ln[1:].strip() for ln in p.stdout.splitlines() if ln.startswith("-\t")]
        self.assertFalse([r for r in removed if r.startswith("errorfile 404 ")]
                         and not [a for a in added if a.startswith("errorfile 404 ")])
        self.assertIn("✓ candidate validates", p.stdout)
        self.assertIn("dry run: nothing installed", p.stdout)

    def test_live_only_with_dry_run(self):
        env = dict(os.environ, PORCH_HAPROXY_CFG="/nonexistent")
        p = subprocess.run([os.path.join(REPO, "bin", "haproxy-errors")],
                           capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(p.returncode, 2)

    def test_no_errorfiles_yet(self):
        text = self.STOCK.replace("\terrorfile 400 /etc/haproxy/errors/400.http\n", "") \
            .replace("\terrorfile 403 /etc/haproxy/errors/403.http\n", "") \
            .replace("\terrorfile 404 {tmp}/404.http\n", "") \
            .replace("\terrorfile 503 /etc/haproxy/errors/503.http\n", "")
        p, _ = self.run_dry(text)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        added = [ln[1:].strip() for ln in p.stdout.splitlines() if ln.startswith("+\t")]
        self.assertEqual(len(added), 8)


if __name__ == "__main__":
    unittest.main()

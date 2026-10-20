"""Tests for the text apps: exchange, paste, chat, snap, form, tunnel, qr.

Stdlib unittest; no network (DNS is faked), no tunnels. The chat link
sanitizer is exercised in node when node is on PATH (skipped otherwise).
"""

import http.client
import importlib.util
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
_LIB = os.path.join(_ROOT, "lib")
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_LIB, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


exchange = _load("exchangeserver")
paste = _load("pasteserver")
chat = _load("chatserver")
snap = _load("snapserver")
form = _load("formserver")


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _get(port, path):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", path)
    r = c.getresponse()
    body = r.read()
    c.close()
    return r, body


class ExchangeTemplateTests(unittest.TestCase):

    def test_content_with_placeholder_tokens_survives(self):
        content = "keep EXCHANGE_NAME and EXCHANGE_FOOTER and EXCHANGE_CONTENT literally"
        page = exchange.render_send_html(content, "myname")
        self.assertIn(content, page)
        self.assertIn(">myname<", page)
        self.assertNotIn("EXCHANGE_NAME</div>", page)

    def test_content_is_escaped(self):
        page = exchange.render_send_html("</textarea><script>x()</script>", "n")
        self.assertNotIn("<script>x()", page)


class PasteTests(unittest.TestCase):

    def setUp(self):
        fields = {
            "PASTE_CONTENT": "has CSP_NONCE and PASTE_NAME inside",
            "PASTE_NAME": "nm",
            "PASTE_LANG": "language-python",
            "PASTE_FOOTER": "f",
        }
        paste.PasteHandler.paste_parts = paste.render_paste_parts(fields)
        paste.PasteHandler.log_message = lambda *a, **k: None
        self.srv = _serve(paste.PasteHandler)
        self.port = self.srv.server_address[1]

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_page_csp_allows_vendored_highlight(self):
        r, body = _get(self.port, "/")
        csp = r.getheader("Content-Security-Policy")
        self.assertIn("script-src 'self' 'nonce-", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn(b"cdnjs", body)
        self.assertIn(b'src="/static/highlight.min.js"', body)
        # Paste body containing the nonce/name placeholders is untouched.
        self.assertIn(b"has CSP_NONCE and PASTE_NAME inside", body)
        r, js = _get(self.port, "/static/highlight.min.js")
        self.assertEqual(r.status, 200)
        self.assertIn(b"Highlight.js v11", js)
        r, _ = _get(self.port, "/static/atom-one-dark.min.css")
        self.assertEqual(r.status, 200)


class ChatTests(unittest.TestCase):

    def test_page_has_no_cdn_or_inline_handlers(self):
        html = chat.CHAT_HTML
        self.assertNotIn("cdnjs", html)
        self.assertNotIn("onclick=", html)
        self.assertEqual(html.count("CSP_NONCE"), 2)

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_link_sanitizer_strips_javascript(self):
        html = chat.CHAT_HTML
        start = html.index("// BEGIN markdown-sanitize")
        end = html.index("// END markdown-sanitize")
        block = html[start:end]
        marked_path = os.path.join(_LIB, "vendor", "marked.min.js")
        script = (
            "globalThis.location = {href: 'https://chat.example/'};\n"
            f"const marked = require({json.dumps(marked_path)});\n"
            + block +
            "\nconst cases = {\n"
            "  js: marked.parse('[click](javascript:alert(1))'),\n"
            "  jsTab: marked.parse('[c](java\\tscript:alert(1))'),\n"
            "  jsUpper: marked.parse('[c](JAVASCRIPT:alert(1))'),\n"
            "  data: marked.parse('[c](data:text/html,<script>alert(1)</script>)'),\n"
            "  auto: marked.parse('<javascript:alert(1)>'),\n"
            "  img: marked.parse('![x](javascript:alert(1))'),\n"
            "  ok: marked.parse('[ok](https://example.com/a?b=\"c\")'),\n"
            "  mail: marked.parse('[m](mailto:a@example.com)'),\n"
            "  raw: marked.parse('<img src=x onerror=alert(1)>'),\n"
            "};\n"
            "console.log(JSON.stringify(cases));\n"
        )
        out = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        cases = json.loads(out.stdout)
        for k in ("js", "jsTab", "jsUpper", "data", "auto", "img"):
            self.assertNotIn("<a ", cases[k], (k, cases[k]))
            self.assertNotIn("href", cases[k], (k, cases[k]))
            self.assertNotIn("<img", cases[k], (k, cases[k]))
        self.assertIn('href="https://example.com/a?b=%22c%22"', cases["ok"])
        self.assertIn('rel="noopener noreferrer nofollow"', cases["ok"])
        self.assertIn('href="mailto:a@example.com"', cases["mail"])
        self.assertNotIn("onerror", cases["raw"])


class SnapURLTests(unittest.TestCase):

    @staticmethod
    def fake_resolver(mapping):
        def resolve(host, port, family=0, type_=0, *a):
            if host not in mapping:
                raise socket.gaierror("nope")
            return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "",
                     (ip, port)) for ip in mapping[host]]
        return resolve

    def test_rejects_private_metadata_and_schemes(self):
        for url in ("http://127.0.0.1/", "http://127.0.0.1:9471/api", "http://169.254.169.254/latest/meta-data/",
                    "http://[::1]/", "http://10.0.0.5/", "http://192.168.1.1/", "http://100.64.1.1/",
                    "http://0.0.0.0/", "http://[::ffff:127.0.0.1]/", "file:///etc/passwd",
                    "javascript:alert(1)", "ftp://example.com/", "data:text/html,hi", "http:///nohost"):
            with self.assertRaises(snap.UnsafeURLError, msg=url):
                snap.check_url(url, resolver=self.fake_resolver({}))

    def test_hostname_resolving_private_rejected(self):
        res = self.fake_resolver({"evil.example": ["93.184.216.34", "127.0.0.1"],
                                  "meta.example": ["169.254.169.254"]})
        for url in ("https://evil.example/", "http://meta.example/"):
            with self.assertRaises(snap.UnsafeURLError, msg=url):
                snap.check_url(url, resolver=res)

    def test_public_allowed_and_pinned(self):
        res = self.fake_resolver({"example.com": ["2606:2800::1", "93.184.216.34"]})
        self.assertEqual(snap.check_url("https://example.com/x", resolver=res),
                         ("example.com", "93.184.216.34"))

    def test_allow_private(self):
        self.assertEqual(snap.check_url("http://127.0.0.1:8080/", allow_private=True),
                         ("127.0.0.1", None))
        with self.assertRaises(snap.UnsafeURLError):
            snap.check_url("file:///etc/passwd", allow_private=True)


class FormTests(unittest.TestCase):

    def test_rate_limiter(self):
        now = [0.0]
        rl = form.RateLimiter(count=3, window=60, clock=lambda: now[0])
        self.assertEqual([rl.allow("a") for _ in range(4)], [True, True, True, False])
        self.assertTrue(rl.allow("b"))
        now[0] = 61
        self.assertTrue(rl.allow("a"))

    def test_peer_address_trusts_xff_only_from_loopback(self):
        h = {"X-Forwarded-For": "6.6.6.6, 1.2.3.4, 127.0.0.1"}
        self.assertEqual(form.peer_address("127.0.0.1", h), "1.2.3.4")
        self.assertEqual(form.peer_address("5.5.5.5", h), "5.5.5.5")
        self.assertEqual(form.peer_address("127.0.0.1", {}), "127.0.0.1")

    def test_append_submission_private_files(self):
        d = tempfile.mkdtemp()
        try:
            out = os.path.join(d, "f.json")
            victim = os.path.join(d, "victim")
            with open(victim, "w") as f:
                f.write("x")
            os.symlink(victim, out + ".lock")
            with self.assertRaises(OSError):         # O_NOFOLLOW on the lock
                form.append_submission(out, {"a": 1})
            os.unlink(out + ".lock")
            self.assertEqual(form.append_submission(out, {"a": 1}), 1)
            self.assertEqual(form.append_submission(out, {"a": 2}), 2)
            self.assertEqual(os.stat(out).st_mode & 0o777, 0o600)
            with open(victim) as f:
                self.assertEqual(f.read(), "x")
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TunnelArgTests(unittest.TestCase):

    def run_tunnel(self, *args):
        return subprocess.run([os.path.join(_ROOT, "bin", "tunnel"), *args],
                              capture_output=True, text=True, timeout=10,
                              stdin=subprocess.DEVNULL)

    def test_rejects_bad_port_and_type(self):
        for args in (("abc", "porch-test"), ("0", "porch-test"), ("65536", "porch-test"),
                     ("80\nx", "porch-test"), ("80", "porch-test", 'http"\nx'),
                     ("80", "porch-test", "stcp")):
            r = self.run_tunnel(*args)
            self.assertEqual(r.returncode, 2, (args, r.stdout, r.stderr))


class QRStdinTests(unittest.TestCase):

    def test_terminal_mode_reads_stdin(self):
        try:
            import qrcode  # noqa: F401
        except ImportError:
            self.skipTest("qrcode not installed")
        r = subprocess.run([os.path.join(_ROOT, "bin", "qr"), "--terminal", "-"],
                           input="WIFI:T:WPA;S:x;P:secret;;", capture_output=True,
                           text=True, timeout=20)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("█", r.stdout)


if __name__ == "__main__":
    unittest.main()

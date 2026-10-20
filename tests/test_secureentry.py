"""Tests for lib/secureentry.py. Stdlib unittest only; run with bin/test.

The secrets backend is never called: a fake `cush_secrets` module is placed
in sys.modules, and disk output goes to a temp dir.
"""

import http.client
import importlib.util
import io
import json
import os
import socket
import stat
import sys
import tempfile
import threading
import time
import types
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
_LIB = os.path.join(_HERE, "..", "lib")
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
_spec = importlib.util.spec_from_file_location("secureentry", os.path.join(_LIB, "secureentry.py"))
se = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(se)

TOKEN = "T0kenT0kenT0kenT0ken_-xyz"
SECRET = "hunter2-super-secret-value"


class FakeBackend:
    def __init__(self, delay=0.0, fail=None):
        self.delay = delay
        self.fail = fail or set()      # refs (or field suffixes) that raise
        self.calls = []
        self.lock = threading.Lock()

    def module(self):
        mod = types.ModuleType("cush_secrets")
        mod.item_upsert = self.item_upsert
        mod.join_multi_field_ref = lambda parent, field: f"{parent}/{field}"
        return mod

    def item_upsert(self, ref, value, concealed=True):
        time.sleep(self.delay)
        with self.lock:
            self.calls.append((ref, value))
        for f in self.fail:
            if ref.endswith(f):
                raise RuntimeError(
                    f"op: [ERROR] vault 'Private' item 'acct@example.com' rejected value {value}")


class SecureEntryCase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.chmod(self.tmp, 0o700)
        H = se.SecureEntryHandler
        H.token = TOKEN
        H.received = False
        H.claimed = False
        H.saved_fields = None
        H.label = "test"
        H.save_to_op = None
        H.keep_disk = False
        H.signal_file = None
        H.entry_type = "string"
        H.fields = None
        H.output_file = Path(self.tmp) / "test"
        H.output_dir = None
        H.server_ref = None          # never schedule a shutdown timer
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self._saved_modules = sys.modules.get("cush_secrets")
        self._stderr = sys.stderr
        self.log = io.StringIO()
        sys.stderr = self.log

    def tearDown(self):
        sys.stderr = self._stderr
        self.server.shutdown()
        self.server.server_close()
        if self._saved_modules is None:
            sys.modules.pop("cush_secrets", None)
        else:
            sys.modules["cush_secrets"] = self._saved_modules
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ── helpers ────────────────────────────────────────────────────────────

    def use_backend(self, backend, ref="op://V/I/f"):
        sys.modules["cush_secrets"] = backend.module()
        se.SecureEntryHandler.save_to_op = ref

    def request(self, method, path, body=None, headers=None, origin=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = dict(headers or {})
        if origin:
            h.setdefault("Origin", f"http://127.0.0.1:{self.port}")
        conn.request(method, path, body=body, headers=h)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp, data

    def post_secret(self, value=SECRET, headers=None, **kw):
        body = "content=" + value
        h = {"Content-Type": "application/x-www-form-urlencoded"}
        h.update(headers or {})
        return self.request("POST", f"/{TOKEN}/submit", body=body, headers=h, **kw)

    # ── routing / token ────────────────────────────────────────────────────

    def test_wrong_token_404(self):
        for path in ("/", "/submit", "/nope/", "/" + TOKEN[:-1] + "/", "/" + TOKEN + "x/"):
            resp, _ = self.request("GET", path)
            self.assertEqual(resp.status, 404, path)
        resp, _ = self.request("POST", "/submit", body="content=x",
                               headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(resp.status, 404)
        self.assertFalse(se.SecureEntryHandler.received)

    def test_right_token_serves_form_with_headers(self):
        resp, body = self.request("GET", f"/{TOKEN}/")
        self.assertEqual(resp.status, 200)
        csp = resp.getheader("Content-Security-Policy")
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("'nonce-", csp)
        self.assertNotIn("unsafe-inline", csp)
        nonce = csp.split("'nonce-")[1].split("'")[0]
        self.assertIn(f'nonce="{nonce}"'.encode(), body)
        self.assertNotIn(b"CSP_NONCE", body)
        self.assertNotIn(b"onclick=", body)
        self.assertEqual(resp.getheader("X-Frame-Options"), "DENY")
        self.assertEqual(resp.getheader("Cache-Control"), "no-store")
        self.assertEqual(resp.getheader("Referrer-Policy"), "no-referrer")
        self.assertEqual(resp.getheader("X-Content-Type-Options"), "nosniff")
        self.assertIn(b'spellcheck="false"', body)
        self.assertIn(b'autocomplete="off"', body)
        resp, _ = self.request("GET", f"/{TOKEN}")
        self.assertEqual(resp.status, 301)
        self.assertEqual(resp.getheader("Location"), f"/{TOKEN}/")

    # ── origin / body limits ───────────────────────────────────────────────

    def test_cross_origin_post_rejected(self):
        resp, _ = self.post_secret(headers={"Origin": "https://evil.example"})
        self.assertEqual(resp.status, 403)
        resp, _ = self.post_secret(origin=False)
        self.assertEqual(resp.status, 403)
        self.assertFalse(se.SecureEntryHandler.received)
        self.assertFalse((Path(self.tmp) / "test").exists())

    def _raw(self, headers_blob, body=b""):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        try:
            s.sendall(headers_blob + body)
            s.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                c = s.recv(65536)
                if not c:
                    break
                chunks.append(c)
            return b"".join(chunks)
        finally:
            s.close()

    def test_bad_content_length(self):
        origin = f"Origin: http://127.0.0.1:{self.port}\r\nHost: 127.0.0.1:{self.port}\r\n"
        for cl, want in (("abc", b" 400 "), ("-5", b" 400 "), (str(10 ** 12), b" 413 ")):
            t0 = time.monotonic()
            out = self._raw(
                (f"POST /{TOKEN}/submit HTTP/1.1\r\n{origin}"
                 f"Content-Type: application/x-www-form-urlencoded\r\n"
                 f"Content-Length: {cl}\r\n\r\n").encode(), b"content=x")
            self.assertLess(time.monotonic() - t0, 4, cl)
            self.assertIn(want, out.split(b"\r\n", 1)[0], cl)
        self.assertFalse(se.SecureEntryHandler.received)

    # ── one-shot under concurrency ─────────────────────────────────────────

    def test_concurrent_posts_exactly_one_accepted(self):
        backend = FakeBackend(delay=0.3)
        self.use_backend(backend)
        results = []
        lock = threading.Lock()

        def go(i):
            resp, body = self.post_secret(value=f"{SECRET}-{i}")
            with lock:
                results.append(resp.status)

        threads = [threading.Thread(target=go, args=(i,)) for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(15)
        self.assertEqual(results.count(200), 1, results)
        self.assertEqual(results.count(409), 5, results)
        self.assertEqual(len(backend.calls), 1)
        self.assertTrue(se.SecureEntryHandler.received)

    # ── error hygiene ──────────────────────────────────────────────────────

    def test_backend_failure_generic_and_retryable(self):
        backend = FakeBackend(fail={"/f"})
        self.use_backend(backend)
        resp, body = self.post_secret()
        self.assertEqual(resp.status, 502)
        msg = json.loads(body)["message"]
        self.assertEqual(msg, se.GENERIC_SAVE_ERROR)
        for leak in ("vault", "Private", "acct@example.com", SECRET):
            self.assertNotIn(leak, body.decode())
        log = self.log.getvalue()
        self.assertIn("secrets write failed", log)
        self.assertNotIn(SECRET, log)
        # Claim released: a retry may succeed.
        self.assertFalse(se.SecureEntryHandler.received)
        backend.fail = set()
        resp, body = self.post_secret()
        self.assertEqual(resp.status, 200)
        self.assertTrue(se.SecureEntryHandler.received)
        resp, _ = self.post_secret()
        self.assertEqual(resp.status, 409)

    # ── disk write ─────────────────────────────────────────────────────────

    def test_disk_write_0600_and_symlink_not_followed(self):
        victim = Path(self.tmp) / "victim"
        victim.write_text("original")
        os.symlink(victim, Path(self.tmp) / "test")
        resp, _ = self.post_secret()
        self.assertEqual(resp.status, 200)
        out = Path(self.tmp) / "test"
        self.assertFalse(out.is_symlink())
        self.assertEqual(out.read_text(), SECRET)
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
        self.assertEqual(victim.read_text(), "original")

    # ── multi-field partial save ───────────────────────────────────────────

    def _multipart(self, fields):
        boundary = "----porchtestboundary"
        parts = []
        for k, v in fields.items():
            parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n")
        parts.append(f"--{boundary}--\r\n")
        return "".join(parts).encode(), f"multipart/form-data; boundary={boundary}"

    def test_multi_partial_save_reports_and_retries_only_failed(self):
        backend = FakeBackend(fail={"/b"})
        self.use_backend(backend, ref="op://V/I")
        se.SecureEntryHandler.fields = [("a", "string"), ("b", "string"), ("c", "string")]
        body, ctype = self._multipart({"a": "va-secret", "b": "vb-secret", "c": "vc-secret"})
        resp, data = self.request("POST", f"/{TOKEN}/submit", body=body,
                                  headers={"Content-Type": ctype})
        self.assertEqual(resp.status, 502)
        d = json.loads(data)
        self.assertEqual(d["saved"], ["a", "c"])
        self.assertEqual(d["failed"], ["b"])
        self.assertNotIn("vb-secret", data.decode())
        self.assertNotIn("vb-secret", self.log.getvalue())
        self.assertFalse(se.SecureEntryHandler.received)
        # The form now shows the saved state.
        resp, page = self.request("GET", f"/{TOKEN}/")
        self.assertIn(b"Already saved: a, c", page)
        # Retry: only the failed field is sent and written.
        backend.fail = set()
        backend.calls.clear()
        body, ctype = self._multipart({"b": "vb-secret"})
        resp, data = self.request("POST", f"/{TOKEN}/submit", body=body,
                                  headers={"Content-Type": ctype})
        self.assertEqual(resp.status, 200, data)
        self.assertEqual([r for r, _ in backend.calls], ["op://V/I/b"])
        self.assertTrue(se.SecureEntryHandler.received)


    def test_claim_released_before_a_failure_answer(self):
        # The flaky one: the 502 went out while this thread still held the
        # claim, so an immediate retry could get 409 already_received.
        H = se.SecureEntryHandler
        seen = []
        real = H.send_json

        def send_json(h, data, status=200):
            seen.append((status, H.claimed))
            return real(h, data, status)
        H.send_json = send_json
        self.addCleanup(setattr, H, "send_json", real)
        self.use_backend(FakeBackend(fail={"/b"}), ref="op://V/I")
        H.fields = [("a", "string"), ("b", "string")]
        body, ctype = self._multipart({"a": "va", "b": "vb"})
        resp, _ = self.request("POST", f"/{TOKEN}/submit", body=body, headers={"Content-Type": ctype})
        self.assertEqual(resp.status, 502)
        self.assertIn((502, False), seen)
        self.use_backend(FakeBackend(fail={"op://V/I/f"}))
        H.fields = None
        seen.clear()
        resp, _ = self.post_secret()
        self.assertEqual(resp.status, 502)
        self.assertEqual(seen, [(502, False)])

    def test_release_only_drops_its_own_claim(self):
        H = se.SecureEntryHandler
        a, b = object.__new__(H), object.__new__(H)
        self.assertTrue(a._claim())
        a._release(success=False)
        self.assertTrue(b._claim())
        a._release(success=False)          # a's late `finally`
        self.assertTrue(H.claimed)
        self.assertFalse(object.__new__(H)._claim())
        b._release(success=False)
        self.assertFalse(H.claimed)


class RundirTests(unittest.TestCase):

    def test_tool_dir_private_and_refuses_foreign(self):
        import rundir
        tmp = tempfile.mkdtemp()
        os.chmod(tmp, 0o700)
        old = os.environ.get("XDG_RUNTIME_DIR")
        os.environ["XDG_RUNTIME_DIR"] = tmp
        try:
            d = rundir.tool_dir("exchange")
            self.assertEqual(d, os.path.join(tmp, "porch", "exchange"))
            self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o700)
            # A symlinked tool dir is refused.
            os.rmdir(d)
            os.symlink(tempfile.mkdtemp(), d)
            with self.assertRaises(rundir.UnsafeDirError):
                rundir.tool_dir("exchange")
        finally:
            if old is None:
                os.environ.pop("XDG_RUNTIME_DIR", None)
            else:
                os.environ["XDG_RUNTIME_DIR"] = old


if __name__ == "__main__":
    unittest.main()

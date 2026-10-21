"""Tests for lib/auth_client.py against a fake porch-auth on a loopback thread
server (never the live one)."""

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
import auth_client  # noqa: E402

TOKEN_A = "tok-A-" + "a" * 40
TOKEN_B = "tok-B-" + "b" * 40


class Fake(BaseHTTPRequestHandler):
    """Accepts exactly `server.token`; records every request."""

    def log_message(self, *a):
        pass

    def _answer(self, code, data):
        body = data if isinstance(data, bytes) else json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_one(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n)) if n else None
        srv = self.server
        srv.seen.append({"method": self.command, "path": self.path, "body": body,
                         "headers": {k.lower(): v for k, v in self.headers.items()}})
        if self.path == "/healthz":
            return self._answer(200, {"ok": True})
        if self.headers.get(auth_client.CLI_TOKEN_HEADER) != srv.token:
            return self._answer(401, {"error": "unauthorized"})
        if self.path == "/auth/admin/state":
            return self._answer(200, {"devices": [{"id": "d1"}]})
        if self.path == "/auth/admin/verify-password":
            if body.get("password") == "right-password":
                return self._answer(200, {"ok": True})
            if body.get("password") == "busy":
                return self._answer(429, {"error": "too many attempts"})
            return self._answer(401, {"error": "invalid password"})
        if self.path == "/auth/admin/notjson":
            return self._answer(200, b"<html>")
        if self.path == "/auth/admin/approve":
            return self._answer(400, {"error": "a web pairing needs apps"})
        return self._answer(404, {"error": "not found"})

    do_GET = do_POST = handle_one


class ClientTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(lambda: [os.unlink(os.path.join(self.dir, f))
                                 for f in os.listdir(self.dir)] and os.rmdir(self.dir))
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
        self.srv.token, self.srv.seen = TOKEN_A, []
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.write_token(TOKEN_A)
        self.c = auth_client.Client(self.dir, self.url)

    def write_token(self, tok):
        path = os.path.join(self.dir, auth_client.CLI_TOKEN_FILENAME)
        tmp = path + ".new"
        with open(tmp, "w") as f:
            f.write(tok + "\n")
        os.replace(tmp, path)     # a restart writes a new file: new inode

    def test_token_from_file_and_header(self):
        self.assertEqual(self.c.state(), {"devices": [{"id": "d1"}]})
        h = self.srv.seen[-1]["headers"]
        self.assertEqual(h[auth_client.CLI_TOKEN_HEADER.lower()], TOKEN_A)
        for bad in ("origin", "x-forwarded-for", "forwarded", "via"):
            self.assertNotIn(bad, h)

    def test_stale_token_retries_once_with_the_new_file(self):
        self.c.state()                       # caches TOKEN_A
        self.srv.token = TOKEN_B
        self.write_token(TOKEN_B)
        # Same mtime/size could fool a stat cache; the 401 forces a re-read.
        self.srv.seen.clear()
        self.assertEqual(self.c.state()["devices"][0]["id"], "d1")
        toks = [s["headers"][auth_client.CLI_TOKEN_HEADER.lower()] for s in self.srv.seen]
        self.assertIn(TOKEN_B, toks)
        self.assertLessEqual(len(toks), 2)

    def test_401_with_an_unchanged_token_is_not_retried(self):
        self.srv.token = TOKEN_B             # server restarted, file not yet rewritten
        self.srv.seen.clear()
        with self.assertRaises(auth_client.AuthError) as c:
            self.c.state()
        self.assertEqual((c.exception.status, c.exception.message), (401, "unauthorized"))
        self.assertEqual(len(self.srv.seen), 1)

    def test_token_never_in_errors(self):
        self.srv.token = TOKEN_B
        errs = []
        for call in (self.c.state, lambda: self.c.request("POST", "/auth/admin/approve", {}),
                     lambda: self.c.request("GET", "/auth/admin/notjson")):
            try:
                call()
            except Exception as e:  # noqa: BLE001
                errs.append(e)
        self.srv.token = TOKEN_A
        for call in (lambda: self.c.request("POST", "/auth/admin/approve", {}),
                     lambda: self.c.request("GET", "/auth/admin/notjson")):
            try:
                call()
            except Exception as e:  # noqa: BLE001
                errs.append(e)
        dead = auth_client.Client(self.dir, "http://127.0.0.1:9")
        try:
            dead.state()
        except auth_client.AuthDown as e:
            errs.append(e)
        self.assertEqual(len(errs), 6)
        self.assertEqual([e.status for e in errs[:3]], [401, 401, 401])
        self.assertEqual(errs[3].message, "a web pairing needs apps")
        self.assertIsInstance(errs[4], auth_client.BadReply)
        self.assertIsInstance(errs[5], auth_client.AuthDown)
        for e in errs:
            for blob in (str(e), repr(e), repr(getattr(e, "__dict__", {})),
                         repr(e.__cause__), repr(e.__context__)):
                self.assertNotIn(TOKEN_A, blob)
                self.assertNotIn(TOKEN_B, blob)
            self.assertIsNone(e.__cause__)

    def test_no_proxy_from_the_environment(self):
        saved = {k: os.environ.get(k) for k in ("http_proxy", "HTTP_PROXY", "no_proxy",
                                                "NO_PROXY")}

        def restore():
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        self.addCleanup(restore)
        for k in ("no_proxy", "NO_PROXY"):
            os.environ.pop(k, None)
        os.environ["http_proxy"] = os.environ["HTTP_PROXY"] = "http://127.0.0.1:9"
        c = auth_client.Client(self.dir, self.url)
        self.assertEqual(c.state()["devices"][0]["id"], "d1")

    def test_missing_and_empty_token_file(self):
        os.unlink(os.path.join(self.dir, auth_client.CLI_TOKEN_FILENAME))
        with self.assertRaises(auth_client.TokenError) as c:
            self.c.state()
        self.assertIn("is porch-auth running?", c.exception.message)
        self.write_token("")
        with self.assertRaises(auth_client.TokenError) as c:
            self.c.state()
        self.assertIn("is empty", c.exception.message)

    def test_verify_password(self):
        self.assertTrue(self.c.verify_password("right-password", "198.51.100.1"))
        self.assertEqual(self.srv.seen[-1]["body"], {"password": "right-password",
                                                      "ip": "198.51.100.1"})
        self.assertFalse(self.c.verify_password("wrong"))
        with self.assertRaises(auth_client.AuthError) as c:
            self.c.verify_password("busy")
        self.assertEqual(c.exception.status, 429)
        # A stale token is an error, never "wrong password".
        self.srv.token = TOKEN_B
        with self.assertRaises(auth_client.AuthError):
            self.c.verify_password("right-password")

    def test_answers_and_down(self):
        self.assertTrue(self.c.answers())
        dead = auth_client.Client(self.dir, "http://127.0.0.1:9")
        self.assertFalse(dead.answers())
        with self.assertRaises(auth_client.AuthDown) as c:
            dead.state()
        self.assertIn("could not reach authserver at http://127.0.0.1:9", str(c.exception))

    def test_env_url_read_at_call_time(self):
        saved = os.environ.get("PORCH_AUTH_URL")
        self.addCleanup(lambda: os.environ.pop("PORCH_AUTH_URL") if saved is None
                        else os.environ.__setitem__("PORCH_AUTH_URL", saved))
        os.environ["PORCH_AUTH_URL"] = self.url
        self.assertEqual(auth_client.Client(self.dir).state()["devices"][0]["id"], "d1")
        os.environ["PORCH_AUTH_URL"] = "http://127.0.0.1:9"
        t = time.time()
        with self.assertRaises(auth_client.AuthDown):
            auth_client.Client(self.dir).state()
        self.assertLess(time.time() - t, 10)


if __name__ == "__main__":
    unittest.main()

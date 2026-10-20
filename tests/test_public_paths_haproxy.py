"""Public paths, end to end through a real HAProxy.

A throwaway haproxy (foreground, loopback port in 9400-9900, its own admin
socket in a temp dir) runs the edge-gate fragments of
config/templates/haproxy.cfg.tmpl in front of a header-echo backend, with temp
map files. It checks what the gate really does: a public prefix or exact path
reaches the app, path tricks and everything else get the login redirect, and
no identity header reaches the app on a public hit, even for the owner. The
runtime map swap is driven by lib/authserver.py's own _haproxy_swap_map.

Skipped without haproxy/openssl. Never touches the system HAProxy, /etc or
port 443.
"""

import hashlib
import http.client
import http.server
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "lib"))

import porch_config  # noqa: E402
from porch_setup import render  # noqa: E402
import test_authserver as ta  # noqa: E402

authserver = ta.authserver
CFG = porch_config.load(env={"PORCH_CONFIG": "none"})
HOST = "promo.cush.rocks"
OPEN_HOST = "open.cush.rocks"
TOKEN = "owner-cookie-token-for-tests"
TOKEN_SHA = hashlib.sha256(TOKEN.encode()).hexdigest()


def free_port():
    for port in range(9400, 9901):
        if port == 9877:
            continue
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            continue
        finally:
            s.close()
        return port
    raise unittest.SkipTest("no free port in 9400-9900")


class Echo(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"path": self.path,
                           "headers": {k.lower(): v for k, v in self.headers.items()}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@unittest.skipUnless(shutil.which("haproxy") and shutil.which("openssl"), "needs haproxy + openssl")
class GateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        d = cls.tmp
        key, crt, cls.pem = (os.path.join(d, n) for n in ("k.pem", "c.pem", "t.pem"))
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                        "ec_paramgen_curve:prime256v1", "-nodes", "-subj", "/CN=t", "-days", "1",
                        "-keyout", key, "-out", crt], check=True, capture_output=True)
        with open(cls.pem, "w") as f, open(crt) as c, open(key) as k:
            f.write(c.read() + k.read())
        cls.maps = {n: os.path.join(d, f"cush-{n}.map")
                    for n in ("grants", "protected", "identity", "public", "public-exact")}
        cls.write_map("protected", f"{HOST} 1\n")
        cls.write_map("grants", f"{TOKEN_SHA}:* dev_owner\n")
        cls.write_map("identity", f"{TOKEN_SHA} dev_owner|admin|Owner%20Laptop\n")
        cls.write_map("public", f"{HOST}/s/ pp_00000001\n{OPEN_HOST}/s/ pp_00000009\n")
        cls.write_map("public-exact", f"{HOST}/robots.txt pp_00000002\n")

        cls.echo = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Echo)
        threading.Thread(target=cls.echo.serve_forever, daemon=True).start()
        cls.port = free_port()
        cls.sock = os.path.join(d, "admin.sock")

        opts = render.options(CFG, "adopt", maps_dir=d, cert_path=cls.pem)
        frags = render.fragments()
        vars_ = render.variables(CFG, opts)
        part = {n: render._subst(frags[n], vars_, n) for n in
                ("frontend_headers", "acls_core", "gate_acls", "routing_auth", "gate",
                 "cookie_strip")}
        echo = f"127.0.0.1:{cls.echo.server_address[1]}"
        cls.cfg_text = (
            f"global\n\tstats socket {cls.sock} mode 600 level admin\n"
            "defaults\n\tmode http\n\ttimeout connect 5s\n\ttimeout client 10s\n"
            "\ttimeout server 10s\n\ttimeout http-request 10s\n"
            f"frontend www-https\n\tbind 127.0.0.1:{cls.port} ssl crt {cls.pem}\n"
            + part["frontend_headers"] + part["acls_core"] + part["gate_acls"]
            + part["routing_auth"] + part["gate"] + part["cookie_strip"]
            + "\tdefault_backend app\n"
            f"backend app\n\tserver app {echo}\n"
            f"backend cush_auth\n\thttp-request return status 299\n"
            f"backend letsencrypt-backend\n\tserver le {echo}\n"
        )
        cls.cfg = os.path.join(d, "haproxy.cfg")
        with open(cls.cfg, "w") as f:
            f.write(cls.cfg_text)
        check = subprocess.run(["haproxy", "-c", "-f", cls.cfg], capture_output=True, text=True)
        if check.returncode != 0:
            raise AssertionError("haproxy -c failed:\n" + check.stderr + check.stdout)
        cls.proc = subprocess.Popen(["haproxy", "-db", "-f", cls.cfg],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=0.2).close()
                break
            except OSError:
                if cls.proc.poll() is not None:
                    raise AssertionError("haproxy exited: " + cls.proc.stderr.read().decode())
                time.sleep(0.05)
        else:
            raise AssertionError("haproxy did not start")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "proc", None):
            cls.proc.terminate()
            try:
                cls.proc.wait(5)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
            cls.proc.stderr.close()
        if getattr(cls, "echo", None):
            cls.echo.shutdown()
            cls.echo.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def write_map(cls, name, text):
        with open(cls.maps[name], "w") as f:
            f.write(text)

    def get(self, path, host=HOST, headers=None):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection("127.0.0.1", self.port, timeout=10, context=ctx)
        try:
            # http.client sends the path exactly as given (no dot-segment cleanup).
            conn.request("GET", path, headers={"Host": host, **(headers or {})})
            r = conn.getresponse()
            body = r.read()
            return r.status, dict(r.getheaders()), body
        finally:
            conn.close()

    def assertGated(self, path, host=HOST, headers=None):
        status, hdrs, _ = self.get(path, host, headers)
        self.assertEqual(status, 302, path)
        self.assertTrue(hdrs["location"].startswith(f"https://{CFG.auth_host}/login?rd="), path)

    def assertReaches(self, path, host=HOST, headers=None):
        status, _, body = self.get(path, host, headers)
        self.assertEqual(status, 200, path)
        return json.loads(body)

    def test_gate_still_holds(self):
        for p in ("/", "/admin", "/s", "/sx", "/sx/y", "/robots.txt/x", "/robots.txtx",
                  "/robots", "/S/x"):
            self.assertGated(p)

    def test_public_prefix_and_exact_reach_the_app(self):
        self.assertEqual(self.assertReaches("/s/abc")["path"], "/s/abc")
        self.assertReaches("/s/")
        self.assertReaches("/s/a/b.png?x=1")
        self.assertReaches("/robots.txt")
        self.assertReaches("/s/x", host="PROMO.cush.rocks")

    def test_path_tricks_fall_back_to_the_gate(self):
        for p in ("/s/../x", "/s/..", "/s//x", "/s/%2e%2e/x", "/s/%2E%2E/x", "/s/.%2e/x",
                  "/s/%2fx", "/s/%5cx", "/s/a;b", "/s/..;/x", "//s/x"):
            self.assertGated(p)
        # A raw backslash (single-quoted in the acl, so a literal one).
        self.assertGated("/s/a\\b")

    def test_ungated_host_is_untouched(self):
        # A public entry on a host that is not gated changes nothing.
        self.assertReaches("/anything", host=OPEN_HOST)

    def test_no_identity_on_a_public_hit(self):
        owner = {"Cookie": f"cush_auth={TOKEN}"}
        # Sanity: the owner's cookie passes the gate and carries identity.
        seen = self.assertReaches("/admin", headers=owner)["headers"]
        self.assertEqual(seen.get("x-cush-device"), "dev_owner")
        self.assertEqual(seen.get("x-cush-role"), "admin")
        self.assertNotIn("cush_auth", seen.get("cookie", ""))
        # On a public path: no X-Cush-* at all, and no cookie token either.
        seen = self.assertReaches("/s/x", headers=owner)["headers"]
        self.assertFalse([k for k in seen if k.startswith("x-cush-")], seen)
        self.assertNotIn("cush_auth", seen.get("cookie", ""))

    def test_client_sent_identity_is_stripped(self):
        forged = {"X-Cush-Role": "admin", "X-Cush-Device": "dev_owner",
                  "X-Cush-Device-Name": "Owner"}
        seen = self.assertReaches("/s/x", headers=forged)["headers"]
        self.assertFalse([k for k in seen if k.startswith("x-cush-")], seen)
        self.assertGated("/admin", headers=forged)

    def test_runtime_swap_switches_a_path_off_and_on(self):
        saved = authserver.HAPROXY_SOCK, authserver.log
        self.addCleanup(lambda: (setattr(authserver, "HAPROXY_SOCK", saved[0]),
                                 setattr(authserver, "log", saved[1])))
        authserver.HAPROXY_SOCK = self.sock
        logs = []
        authserver.log = logs.append
        path = self.maps["public"]
        # Swapping in an EMPTY map works (prepare + commit, no adds).
        self.assertIs(authserver._haproxy_swap_map(path, []), True, logs)
        self.assertGated("/s/x")
        self.assertIs(authserver._haproxy_swap_map(
            path, [(f"{HOST}/s/", "pp_00000001"), (f"{OPEN_HOST}/s/", "pp_00000009")]), True, logs)
        self.assertReaches("/s/x")
        # The exact map too.
        exact = self.maps["public-exact"]
        self.assertIs(authserver._haproxy_swap_map(exact, []), True, logs)
        self.assertGated("/robots.txt")
        self.assertIs(authserver._haproxy_swap_map(exact, [(f"{HOST}/robots.txt", "pp_00000002")]),
                      True, logs)
        self.assertReaches("/robots.txt")


@unittest.skipUnless(shutil.which("haproxy") and shutil.which("openssl"), "needs haproxy + openssl")
class HaproxyPorchStepCTest(unittest.TestCase):
    """bin/haproxy-porch c --dry-run against a config shaped like the live one
    before step c (PORCH_HAPROXY_CFG: never /etc)."""

    SCRIPT = os.path.join(_HERE, "..", "bin", "haproxy-porch")

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        key, crt, pem = (os.path.join(self.d, n) for n in ("k.pem", "c.pem", "t.pem"))
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                        "ec_paramgen_curve:prime256v1", "-nodes", "-subj", "/CN=t", "-days", "1",
                        "-keyout", key, "-out", crt], check=True, capture_output=True)
        with open(pem, "w") as f, open(crt) as c, open(key) as k:
            f.write(c.read() + k.read())
        for m in ("grants", "protected", "identity"):
            open(os.path.join(self.d, f"cush-{m}.map"), "w").close()
        # Render with errorfiles that exist anywhere: drop them.
        full = render.render_haproxy(CFG, "adopt", maps_dir=self.d, cert_path=pem)
        full = "".join(l for l in full.splitlines(True) if "errorfile" not in l)
        self.applied = full
        before = [l for l in full.splitlines(True)
                  if not any(k in l for k in ("public_path", "odd_path", "public_ok var",
                                              "cush_path", "cush_hp", "cush_public",
                                              "# Public paths on gated", "matched with map_beg",
                                              "path with a dot-dot", "is never public"))]
        self.before = "".join(before).replace(" !public_ok", "")
        self.assertNotIn("public", self.before)
        self.cfg = os.path.join(self.d, "haproxy.cfg")

    def run_step(self, text):
        with open(self.cfg, "w") as f:
            f.write(text)
        env = dict(os.environ, PORCH_HAPROXY_CFG=self.cfg, PORCH_CONFIG="none")
        return subprocess.run(["bash", self.SCRIPT, "c", "--dry-run"], capture_output=True,
                              text=True, env=env, timeout=60)

    def test_refuses_without_the_maps(self):
        r = self.run_step(self.before)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("run bin/auth-deploy first", r.stdout + r.stderr)

    def test_adds_exactly_the_template_lines(self):
        for m in ("public", "public-exact"):
            open(os.path.join(self.d, f"cush-{m}.map"), "w").close()
        r = self.run_step(self.before)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("candidate validates", r.stdout)
        added = sorted(l[1:] for l in r.stdout.splitlines()
                       if l.startswith("+") and not l.startswith("+++"))
        removed = sorted(l[1:] for l in r.stdout.splitlines()
                         if l.startswith("-") and not l.startswith("---"))
        want_added = sorted(set(self.applied.splitlines()) - set(self.before.splitlines()))
        self.assertEqual(added, want_added)
        self.assertEqual(len(removed), 4)                 # 3 X-Cush-* lines + the redirect
        # Idempotent.
        r = self.run_step(self.applied)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("step c already applied", r.stdout)


if __name__ == "__main__":
    unittest.main()

"""Web setup wizard (lib/porch_setup/web.py, webio.py, cmd_web.py).

No network, no root, no ports below 1024: servers bind 127.0.0.1:0, the
engine runs fake steps, certbot is a FakeRunner, privilege drop uses a fake
os module. TLS tests need openssl and are skipped without it.
"""

import http.client
import io
import json
import os
import re
import shutil
import ssl
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import porch_config  # noqa: E402
import porch_http as ph  # noqa: E402
from porch_setup import acme, cmd_web, web  # noqa: E402
from porch_setup.engine import Input, Step, StepError  # noqa: E402
from porch_setup.io import MissingInput, SecretAnswer  # noqa: E402
from porch_setup.redact import Redactor  # noqa: E402
from porch_setup.runner import FakeRunner, Runner  # noqa: E402
from porch_setup.webio import WebIO  # noqa: E402

SECRET = "tok-SUPERSECRET-9f8e7d"
HAVE_OPENSSL = shutil.which("openssl") is not None


class Alpha(Step):
    id = "alpha"
    title = "Alpha step"
    INPUTS = (Input("domain", "text", "Your domain?", flag="--domain",
                    validate=lambda v: None if "." in v else "need a dot"),
              Input("token", "secret", "API token", flag="--token-ref", env="PORCH_T_TOKEN"))

    def apply(self, ctx):
        tok = ctx.secret("token")
        ctx.log(f"using token {tok} for {ctx.input('domain')}")
        ctx.emit("check", step=self.id, ok=True, code="alpha.tok", message=f"token {tok}", hint="")
        return {"echo": tok}

    def verify(self, ctx):
        return []


class Beta(Step):
    id = "beta"
    title = "Beta step"

    def apply(self, ctx):
        if not ctx.confirm("Proceed with beta?", default=False):
            raise StepError("beta.no", "not confirmed")
        return {}


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def wait_for(pred, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        v = pred()
        if v:
            return v
        time.sleep(0.02)
    raise AssertionError("timed out waiting")


class Base(unittest.TestCase):
    steps = (Alpha(), Beta())

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.redactor = Redactor()
        self.ctx_kwargs = dict(runner=FakeRunner(), data_dir=os.path.join(self.tmp, "data"),
                               cfg=porch_config.load(env={"PORCH_CONFIG": "none"}),
                               redactor=self.redactor, secrets_dir=os.path.join(self.tmp, "secrets"),
                               sleep=lambda s: None)
        self.clock = Clock()

    def wizard(self, **kw):
        kw.setdefault("ctx_kwargs", self.ctx_kwargs)
        kw.setdefault("env", {"PORCH_CONFIG": "none"})
        w = web.Wizard(list(self.steps), **kw)
        self.addCleanup(w.stop)
        return w

    def serve(self, wiz):
        srv = ph.make_server(web.Handler, 0, server_class=ph.BoundedThreadingHTTPServer)
        srv.wizard = wiz
        srv.sse_ping = 0.2
        t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        t.start()

        def stop():
            wiz.io.close()
            srv.shutdown()
            srv.server_close()
        self.addCleanup(stop)
        return Client(srv.server_address[1])


class Client:
    def __init__(self, port):
        self.port = port
        self.host = f"127.0.0.1:{port}"
        self.cookie = None
        self.csrf = None

    def req(self, method, path, body=None, headers=None, origin=True, csrf=True):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = dict(headers or {})
        if self.cookie:
            h["Cookie"] = self.cookie
        if method == "POST":
            if origin:
                h.setdefault("Origin", f"http://{self.host}")
            if csrf and self.csrf:
                h.setdefault("X-Porch-CSRF", self.csrf)
            h["Content-Type"] = "application/json"
        data = json.dumps(body or {}).encode() if method == "POST" else None
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        raw = r.read()
        c.close()
        try:
            js = json.loads(raw)
        except ValueError:
            js = None
        return r, js, raw

    def login(self, key):
        r, js, _ = self.req("POST", "/api/session", {"key": key})
        if r.status == 200:
            self.cookie = r.getheader("Set-Cookie").split(";", 1)[0]
            self.csrf = js["csrf"]
        return r, js


# ---- auth -----------------------------------------------------------------------

class TestAuth(Base):
    def test_key_single_use_and_cookie_flags(self):
        wiz = self.wizard()
        c = self.serve(wiz)
        self.assertGreaterEqual(len(wiz.key), 43)        # 32 bytes urlsafe
        r, js = c.login(wiz.key)
        self.assertEqual(r.status, 200)
        sc = r.getheader("Set-Cookie")
        for flag in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(flag, sc)
        self.assertNotIn("Domain", sc)
        self.assertTrue(sc.startswith(web.COOKIE + "="))
        r, js, _ = c.req("GET", "/api/state")
        self.assertEqual(r.status, 200)
        self.assertEqual(js["csrf"], c.csrf)
        # the same key again (another browser) is refused
        other = Client(c.port)
        r2, _ = other.login(wiz.key)
        self.assertEqual(r2.status, 403)
        self.assertIsNone(other.cookie)
        r3, _, _ = other.req("GET", "/api/state")
        self.assertEqual(r3.status, 401)

    def test_lockout_after_five_wrong_keys(self):
        wiz = self.wizard(clock=self.clock)
        c = self.serve(wiz)
        for _ in range(5):
            r, _ = c.login("wrong-" + "x" * 40)
            self.assertEqual(r.status, 403)
        r, js = c.login(wiz.key)
        self.assertEqual(r.status, 429)
        self.assertEqual(js["error"], "locked")
        self.clock.t += web.LOCKOUT - 1
        self.assertEqual(c.login(wiz.key)[0].status, 429)
        self.clock.t += 2
        self.assertEqual(c.login(wiz.key)[0].status, 200)

    def test_csrf_and_origin(self):
        wiz = self.wizard()
        c = self.serve(wiz)
        r, _, _ = c.req("POST", "/api/run", {"mode": "dry-run"})
        self.assertEqual(r.status, 401)                 # no session
        c.login(wiz.key)
        r, _, _ = c.req("POST", "/api/run", {"mode": "dry-run"}, csrf=False)
        self.assertEqual(r.status, 403)
        r, _, _ = c.req("POST", "/api/run", {"mode": "dry-run"}, headers={"X-Porch-CSRF": "nope"})
        self.assertEqual(r.status, 403)
        r, _, _ = c.req("POST", "/api/run", {"mode": "dry-run"},
                        headers={"Origin": "https://evil.example"})
        self.assertEqual(r.status, 403)
        r, _, _ = c.req("POST", "/api/run", {"mode": "dry-run"}, origin=False)
        self.assertEqual(r.status, 403)
        self.assertFalse(wiz.running())
        r, js, _ = c.req("POST", "/api/run", {"mode": "bogus"})
        self.assertEqual(r.status, 400)

    def test_page_csp_and_fragment_flow(self):
        wiz = self.wizard()
        c = self.serve(wiz)
        r, _, raw = c.req("GET", "/")
        self.assertEqual(r.status, 200)
        policy = r.getheader("Content-Security-Policy")
        m = re.search(r"script-src 'nonce-([A-Za-z0-9_-]+)'", policy)
        self.assertTrue(m, policy)
        self.assertIn("default-src 'none'", policy)
        self.assertIn("frame-ancestors 'none'", policy)
        self.assertNotIn("unsafe-inline", policy)
        self.assertNotIn("unsafe-eval", policy)
        html = raw.decode()
        self.assertIn(f'nonce="{m.group(1)}" src="/static/wizard.js"', html)
        self.assertNotIn(wiz.key, html)
        self.assertNotIn("{{", html)
        self.assertIn(ph.PORCH_CSS_PATH, html)
        self.assertNotRegex(html, r"<script(?![^>]*\bsrc=)")    # no inline script
        self.assertNotIn("style=", html)
        self.assertEqual(r.getheader("Cache-Control"), "no-store")
        self.assertEqual(r.getheader("X-Frame-Options"), "DENY")
        r, _, js = c.req("GET", "/static/wizard.js")
        self.assertEqual(r.status, 200)
        js = js.decode()
        self.assertIn("history.replaceState", js)
        self.assertIn("k=", js)
        self.assertIn("/api/session", js)
        self.assertIn("X-Porch-CSRF", js)
        self.assertNotIn("innerHTML", js)
        self.assertNotIn("insertAdjacentHTML", js)
        self.assertEqual(c.req("GET", "/static/wizard.css")[0].status, 200)
        self.assertEqual(c.req("GET", ph.PORCH_CSS_PATH)[0].status, 200)
        self.assertEqual(c.req("GET", "/static/../web.py")[0].status, 404)
        self.assertEqual(c.req("GET", "/api/nope")[0].status, 401)


# ---- WebIO ------------------------------------------------------------------------

class TestWebIO(Base):
    def test_replay_buffer_and_sse(self):
        wiz = self.wizard()
        c = self.serve(wiz)
        c.login(wiz.key)
        for i in range(3):
            wiz.io.event("log", message=f"m{i}", level="info", step=None)
        conn = http.client.HTTPConnection("127.0.0.1", c.port, timeout=5)
        conn.request("GET", "/api/events?since=0", headers={"Cookie": c.cookie})
        r = conn.getresponse()
        self.assertEqual(r.status, 200)
        self.assertTrue(r.getheader("Content-Type").startswith("text/event-stream"))
        got = []
        while len(got) < 3:
            line = r.fp.readline().decode()
            if line.startswith("data: "):
                got.append(json.loads(line[6:]))
        self.assertEqual([g["data"]["message"] for g in got], ["m0", "m1", "m2"])
        conn.close()
        # reconnect with Last-Event-ID: only what came after
        wiz.io.event("log", message="m3", level="info", step=None)
        conn = http.client.HTTPConnection("127.0.0.1", c.port, timeout=5)
        conn.request("GET", "/api/events", headers={"Cookie": c.cookie, "Last-Event-ID": "2"})
        r = conn.getresponse()
        ids, msgs = [], []
        while len(msgs) < 2:
            line = r.fp.readline().decode()
            if line.startswith("id: "):
                ids.append(int(line[4:]))
            if line.startswith("data: "):
                msgs.append(json.loads(line[6:])["data"]["message"])
        conn.close()
        self.assertEqual(msgs, ["m2", "m3"])
        self.assertEqual(ids, [3, 4])
        # without a session: 401, no stream
        self.assertEqual(Client(c.port).req("GET", "/api/events")[0].status, 401)

    def test_buffer_bounded(self):
        w = WebIO(buffer=5)
        for i in range(12):
            w.event("log", message=str(i), level="info", step=None)
        evs = w.events_since(0)
        self.assertEqual(len(evs), 5)
        self.assertEqual(evs[0][0], 8)
        self.assertEqual(w.wait_events(12, timeout=0.05), [])

    def test_prompt_timeout_and_cancel(self):
        w = WebIO(timeout=0.2)
        inp = Input("x", "text", "X?")
        with self.assertRaises(MissingInput):
            w.ask(inp, None)
        self.assertIsNone(w.pending())
        w2 = WebIO(timeout=10)
        box = {}

        def run():
            try:
                w2.ask(inp, None)
            except MissingInput:
                box["missing"] = True
        t = threading.Thread(target=run)
        t.start()
        p = wait_for(w2.pending)
        self.assertTrue(w2.cancel(p["id"]))
        t.join(5)
        self.assertTrue(box.get("missing"))

    def test_confirm_timeout_is_no(self):
        w = WebIO(timeout=0.1)
        self.assertFalse(w.confirm("Really?", default=True))

    def test_preset_flags_and_env(self):
        w = WebIO(redactor=self.redactor, preset={"domain": "x.example", "token": "file://~/.config/porch/secrets/t"},
                  env={"PORCH_T_TOKEN": SECRET})
        a, tok = Alpha.INPUTS
        self.assertTrue(w.has(a))
        self.assertEqual(w.ask(a, None), "x.example")
        self.assertEqual(w.ask_secret(tok, None), SecretAnswer(ref="file://~/.config/porch/secrets/t"))
        w2 = WebIO(redactor=self.redactor, env={"PORCH_T_TOKEN": SECRET})
        self.assertEqual(w2.ask_secret(tok, None).value, SECRET)
        self.assertIn(SECRET, self.redactor)

    def test_bad_ref_not_echoed(self):
        w = WebIO(redactor=self.redactor)
        tok = Alpha.INPUTS[1]
        with self.assertRaises(Exception) as cm:
            w._secret_answer(tok, {"ref": SECRET})
        self.assertNotIn(SECRET, str(cm.exception))


# ---- full run over HTTP ---------------------------------------------------------------

class TestRun(Base):
    def _pending(self, c, kind="inputs"):
        def p():
            js = c.req("GET", "/api/state")[1]
            pend = js.get("pending")
            return pend if pend and pend["type"] == kind else None
        return wait_for(p)

    def test_full_run_with_inputs_confirm_and_no_secret_leaks(self):
        wiz = self.wizard(exit_grace=0)
        c = self.serve(wiz)
        c.login(wiz.key)
        r, js, _ = c.req("POST", "/api/run", {"mode": "run"})
        self.assertEqual(r.status, 202)
        # a second run while one is going is refused nicely
        r2, js2, _ = c.req("POST", "/api/run", {"mode": "run"})
        self.assertEqual(r2.status, 409)
        self.assertEqual(js2["code"], "web.busy")

        p = self._pending(c)
        self.assertEqual(p["step"], "alpha")
        names = [f["name"] for f in p["fields"]]
        self.assertEqual(names, ["domain", "token"])          # one form for the step
        tokf = p["fields"][1]
        self.assertEqual(tokf["kind"], "secret")
        self.assertNotIn("default", tokf)
        self.assertEqual(tokf["flag"], "--token-ref")
        self.assertEqual(tokf["env"], "PORCH_T_TOKEN")

        # stale prompt id / wrong step
        r, _, _ = c.req("POST", "/api/inputs/beta", {"prompt": p["id"], "values": {}})
        self.assertEqual(r.status, 409)
        # validation errors come back inline; nothing is queued
        r, js, _ = c.req("POST", "/api/inputs/alpha",
                         {"prompt": p["id"], "values": {"domain": "nodot", "token": {"value": ""}}})
        self.assertEqual(r.status, 422)
        self.assertEqual(js["errors"]["domain"], "need a dot")
        self.assertIn("token", js["errors"])
        r, js, _ = c.req("POST", "/api/inputs/alpha",
                         {"prompt": p["id"], "values": {"domain": "example.com",
                                                        "token": {"value": SECRET}}})
        self.assertEqual(r.status, 200, js)

        cp = self._pending(c, "confirm")
        self.assertEqual(cp["prompt"], "Proceed with beta?")
        r, _, _ = c.req("POST", "/api/confirm", {"prompt": cp["id"], "answer": True})
        self.assertEqual(r.status, 200)

        wait_for(lambda: wiz.last_result is not None and not wiz.running())
        self.assertTrue(wiz.last_result["ok"], wiz.last_result)
        self.assertTrue(wiz.complete)
        self.assertEqual(wiz.should_exit(), "complete")
        js = c.req("GET", "/api/state")[1]
        self.assertEqual({s["id"]: s["status"] for s in js["steps"]}, {"alpha": "done", "beta": "done"})
        fin = [d for _, n, d in wiz.io.events_since(0) if n == "run_finished"][-1]
        self.assertTrue(fin["complete"])
        self.assertTrue(fin["urls"]["admin"].startswith("https://"))
        # the ready page: Pocket's URL, its sign-in QR target, the next command
        self.assertTrue(fin["urls"]["pocket"].startswith("https://pocket."))
        self.assertIn("/__porch/start?rd=%2F", fin["ready"]["pocket_signin"])
        self.assertEqual(js["ready"]["pocket_signin"], fin["ready"]["pocket_signin"])
        self.assertTrue(any("bin/tunnel" in n["command"] for n in fin["ready"]["next"]))
        r, qj, _ = c.req("GET", "/api/qr?for=ready")
        if web.qr_matrix("x") is None:
            self.assertEqual(r.status, 404)
        else:
            self.assertEqual(r.status, 200)
            self.assertEqual(len(qj["rows"]), qj["size"])

        # the secret went to the store, and nowhere else
        data = self.ctx_kwargs["data_dir"]
        with open(os.path.join(self.tmp, "secrets", "token")) as f:
            self.assertEqual(f.read().strip(), SECRET)
        for name in ("porch-setup.json", "porch-setup.log"):
            with open(os.path.join(data, name)) as f:
                text = f.read()
            self.assertNotIn(SECRET, text, name)
        with open(os.path.join(data, "porch-setup.log")) as f:
            self.assertIn("[redacted]", f.read())
        evtext = json.dumps([list(e) for e in wiz.io.events_since(0)], default=str)
        self.assertNotIn(SECRET, evtext)
        self.assertIn("[redacted]", evtext)
        self.assertNotIn(SECRET, json.dumps(c.req("GET", "/api/state")[1]))
        with open(os.path.join(data, "porch-setup.json")) as f:
            st = json.load(f)
        self.assertEqual(st["secret_refs"]["token"], "file://~/.config/porch/secrets/token")

    def test_confirm_no_fails_step_and_resume(self):
        wiz = self.wizard()
        c = self.serve(wiz)
        c.login(wiz.key)
        c.req("POST", "/api/run", {"mode": "run"})
        p = self._pending(c)
        c.req("POST", "/api/inputs/alpha", {"prompt": p["id"], "values": {
            "domain": "example.com", "token": {"value": SECRET}}})
        cp = self._pending(c, "confirm")
        c.req("POST", "/api/confirm", {"prompt": cp["id"], "answer": False})
        wait_for(lambda: wiz.last_result is not None and not wiz.running())
        self.assertFalse(wiz.last_result["ok"])
        self.assertEqual(wiz.last_result["failed_step"], "beta")
        self.assertFalse(wiz.complete)
        # resume starts at beta (alpha is done; its secret ref is not asked again)
        r, _, _ = c.req("POST", "/api/run", {"mode": "resume"})
        self.assertEqual(r.status, 202)
        cp = self._pending(c, "confirm")
        c.req("POST", "/api/confirm", {"prompt": cp["id"], "answer": True})
        wait_for(lambda: not wiz.running() and wiz.last_result["mode"] == "resume")
        self.assertTrue(wiz.last_result["ok"], wiz.last_result)

    def test_cancel_prompt_fails_step(self):
        wiz = self.wizard()
        c = self.serve(wiz)
        c.login(wiz.key)
        c.req("POST", "/api/run", {"mode": "run"})
        p = self._pending(c)
        r, _, _ = c.req("POST", "/api/cancel", {"prompt": p["id"]})
        self.assertEqual(r.status, 200)
        wait_for(lambda: wiz.last_result is not None and not wiz.running())
        self.assertEqual(wiz.last_result["error"]["code"], "engine.missing_input")

    def test_dry_run_persists_nothing(self):
        wiz = self.wizard(preset={"domain": "example.com"}, env={"PORCH_CONFIG": "none",
                                                                 "PORCH_T_TOKEN": SECRET})
        c = self.serve(wiz)
        c.login(wiz.key)
        r, _, _ = c.req("POST", "/api/run", {"mode": "dry-run"})
        self.assertEqual(r.status, 202)
        wait_for(lambda: wiz.last_result is not None and not wiz.running())
        self.assertTrue(wiz.last_result["ok"], wiz.last_result)
        self.assertTrue(wiz.last_result["dry_run"])
        self.assertFalse(wiz.complete)
        self.assertFalse(os.path.exists(os.path.join(self.ctx_kwargs["data_dir"], "porch-setup.json")))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "secrets", "token")))
        # nothing persisted, but the page still sees what was planned
        js = c.req("GET", "/api/state")[1]
        self.assertEqual({s["id"]: s["status"] for s in js["steps"]}, {"alpha": "planned", "beta": "planned"})
        names = [n for _, n, _ in wiz.io.events_since(0)]
        self.assertEqual(names[0], "run_started")
        self.assertNotIn(SECRET, json.dumps([list(e) for e in wiz.io.events_since(0)], default=str))

    def test_engine_lock_held_elsewhere(self):
        from porch_setup.state import LOCK_NAME, StateLock
        os.makedirs(self.ctx_kwargs["data_dir"], exist_ok=True)
        lock = StateLock(os.path.join(self.ctx_kwargs["data_dir"], LOCK_NAME))
        lock.acquire()
        self.addCleanup(lock.release)
        wiz = self.wizard()
        c = self.serve(wiz)
        c.login(wiz.key)
        c.req("POST", "/api/run", {"mode": "run"})
        wait_for(lambda: wiz.last_result is not None and not wiz.running())
        self.assertEqual(wiz.last_result["error"]["code"], "engine.locked")
        self.assertIn("another porch setup", wiz.last_result["error"]["message"])

    def test_rollback(self):
        wiz = self.wizard()
        c = self.serve(wiz)
        c.login(wiz.key)
        r, _, _ = c.req("POST", "/api/rollback", {"to": "../x"})
        self.assertEqual(r.status, 400)
        r, _, _ = c.req("POST", "/api/rollback", {"dry_run": True})
        self.assertEqual(r.status, 202)
        wait_for(lambda: wiz.last_result is not None and not wiz.running())
        self.assertTrue(wiz.last_result["ok"])
        self.assertEqual(wiz.last_result["kind"], "rollback")


# ---- lifetime ---------------------------------------------------------------------

class TestLifetime(Base):
    def test_idle_exit(self):
        wiz = self.wizard(clock=self.clock, idle_timeout=60)
        self.assertIsNone(wiz.should_exit())
        self.clock.t += 59
        self.assertIsNone(wiz.should_exit())
        wiz.touch()
        self.clock.t += 61
        self.assertEqual(wiz.should_exit(), "idle")

    def test_not_idle_while_running(self):
        wiz = self.wizard(clock=self.clock, idle_timeout=1)

        class Alive:
            def is_alive(self):
                return True
        wiz.thread = Alive()
        self.clock.t += 100
        self.assertIsNone(wiz.should_exit())

    def test_serve_returns_on_stop(self):
        wiz = self.wizard()
        srv = ph.make_server(web.Handler, 0)
        threading.Timer(0.2, wiz.stop).start()
        self.assertEqual(wiz.serve(srv, poll=0.05), "stopped")


# ---- privilege drop -----------------------------------------------------------------

class FakeOS:
    def __init__(self, euid=0):
        self.euid = self.egid = euid
        self.calls = []
        self.can_regain = False

    def geteuid(self):
        return self.euid

    def getegid(self):
        return self.egid

    def getgrouplist(self, name, gid):
        self.calls.append(("getgrouplist", name, gid))
        return [gid, 27]

    def setgroups(self, g):
        self.calls.append(("setgroups", list(g)))

    def setresgid(self, *a):
        self.calls.append(("setresgid",) + a)
        self.egid = a[1]

    def setresuid(self, *a):
        self.calls.append(("setresuid",) + a)
        self.euid = a[1]

    def setuid(self, u):
        self.calls.append(("setuid", u))
        if not self.can_regain:
            raise PermissionError("nope")


class FakePwd:
    class PW:
        pw_name = "porch"
        pw_dir = "/home/porch"

    def getpwuid(self, uid):
        return self.PW()


class TestPrivDrop(unittest.TestCase):
    def test_noop_when_not_root(self):
        f = FakeOS(euid=1000)
        self.assertIsNone(web.drop_privileges({}, os_mod=f, pwd_mod=FakePwd()))
        self.assertEqual(f.calls, [])

    def test_drops_to_sudo_user_groups_first(self):
        f = FakeOS()
        env = {"SUDO_UID": "1000", "SUDO_GID": "1001", "SUDO_USER": "porch", "HOME": "/root"}
        self.assertEqual(web.drop_privileges(env, os_mod=f, pwd_mod=FakePwd()), 1000)
        names = [c[0] for c in f.calls]
        self.assertEqual(names, ["getgrouplist", "setgroups", "setresgid", "setresuid", "setuid"])
        self.assertEqual(f.calls[2], ("setresgid", 1001, 1001, 1001))
        self.assertEqual(f.calls[3], ("setresuid", 1000, 1000, 1000))
        self.assertEqual(f.calls[4], ("setuid", 0))
        self.assertEqual(env["HOME"], "/home/porch")
        self.assertNotIn("SUDO_UID", env)

    def test_refuses_without_sudo_ids_or_as_root(self):
        for env in ({}, {"SUDO_UID": "0", "SUDO_GID": "0"}, {"SUDO_UID": "x", "SUDO_GID": "1"}):
            f = FakeOS()
            with self.assertRaises(web.WebError):
                web.drop_privileges(env, os_mod=f, pwd_mod=FakePwd())
            self.assertFalse(any(c[0].startswith("setres") for c in f.calls))

    def test_refuses_if_root_can_be_regained(self):
        f = FakeOS()
        f.can_regain = True
        with self.assertRaises(web.WebError):
            web.drop_privileges({"SUDO_UID": "1000", "SUDO_GID": "1000"}, os_mod=f, pwd_mod=FakePwd())


# ---- certificates -------------------------------------------------------------------

class Ctx:
    def __init__(self, runner, env=None, repo_dir="/repo"):
        self.run = runner
        self.env = env or {}
        self.repo_dir = repo_dir


class TestIPCert(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_argv(self):
        r = FakeRunner().on(["certbot", "--version"], stdout="certbot 5.8.0")
        ctx = Ctx(r, env={"PORCH_ACME_DIR": self.tmp + "/acme"})
        lin = acme.issue_ip_cert(ctx, "1.1.1.1", webroot="/w", staging=True)
        argv = r.argvs()[-1]
        self.assertEqual(argv[:2], ["certbot", "certonly"])
        joined = " ".join(argv)
        for want in ("--manual", "--preferred-challenges http", "--ip-address 1.1.1.1",
                     "--required-profile shortlived", "--cert-name porch-bootstrap-ip",
                     "--non-interactive", "--agree-tos", "--test-cert",
                     "--register-unsafely-without-email",
                     f"--config-dir {self.tmp}/acme/config", "--manual-auth-hook /repo/bin/porch-acme-http-hook auth",
                     "--manual-cleanup-hook /repo/bin/porch-acme-http-hook cleanup"):
            self.assertIn(want, joined)
        self.assertNotIn("sudo", argv)
        self.assertEqual(r.calls[-1]["sudo"], False)
        self.assertTrue(lin["fullchain"].endswith("live/porch-bootstrap-ip/fullchain.pem"))
        prod = acme.ip_certonly_argv("2606:4700::1", base="/b", repo_dir="/repo", email="a@b.c")
        self.assertNotIn("--test-cert", prod)
        self.assertIn("a@b.c", prod)
        self.assertEqual(acme.ip_cert_delete_argv(base="/b")[:2], ["certbot", "delete"])

    def test_refuses_private_ip_and_reports_failure(self):
        r = FakeRunner().on(["certbot", "--version"], stdout="certbot 5.8.0")
        ctx = Ctx(r, env={"PORCH_ACME_DIR": self.tmp})
        for ip in ("192.168.1.2", "10.0.0.1", "127.0.0.1", "nope"):
            with self.assertRaises(acme.AcmeError):
                acme.issue_ip_cert(ctx, ip, webroot="/w")
        r.on(["certbot", "certonly"], returncode=1, stderr="Error: profile not offered")
        with self.assertRaises(acme.AcmeError) as cm:
            acme.issue_ip_cert(ctx, "1.1.1.1", webroot="/w")
        self.assertEqual(cm.exception.code, "cert.ip_issue")
        self.assertIn("profile not offered", cm.exception.message)

    def test_http_hook_and_challenge_server(self):
        root = os.path.join(self.tmp, "wr")
        os.mkdir(root)
        env = {"PORCH_ACME_WEBROOT": root, "CERTBOT_TOKEN": "abc_DEF-1", "CERTBOT_VALIDATION": "abc.xyz"}
        self.assertEqual(acme.http_hook_main("auth", env, out=io.StringIO()), 0)
        with open(os.path.join(root, "abc_DEF-1")) as f:
            self.assertEqual(f.read(), "abc.xyz")
        bad = dict(env, CERTBOT_TOKEN="../../etc/x")
        self.assertEqual(acme.http_hook_main("auth", bad, out=io.StringIO()), 2)
        self.assertEqual(acme.http_hook_main("bogus", env, out=io.StringIO()), 2)
        srv = web.bind_acme(("127.0.0.1", 0), root)
        t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        t.start()
        try:
            port = srv.server_address[1]
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", "/.well-known/acme-challenge/abc_DEF-1")
            r = c.getresponse()
            self.assertEqual((r.status, r.read()), (200, b"abc.xyz"))
            for path in ("/.well-known/acme-challenge/..%2fx", "/", "/.well-known/acme-challenge/nope"):
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                c.request("GET", path)
                self.assertEqual(c.getresponse().status, 404)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(acme.http_hook_main("cleanup", env, out=io.StringIO()), 0)
        self.assertFalse(os.path.exists(os.path.join(root, "abc_DEF-1")))


@unittest.skipUnless(HAVE_OPENSSL, "openssl not installed")
class TestTLS(Base):
    def test_self_signed_and_https(self):
        d = os.path.join(self.tmp, "tls")
        cert, key, fp = web.make_self_signed(Runner(), d, extra_ips=["192.0.2.7"])
        self.assertEqual(os.stat(key).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(d).st_mode & 0o777, 0o700)
        self.assertRegex(fp, r"^([0-9A-F]{2}:){31}[0-9A-F]{2}$")
        wiz = self.wizard()
        srv = web.make_tls_server(wiz, ("127.0.0.1", 0), cert, key)
        t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        t.start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        cctx = ssl.create_default_context(cafile=cert)
        c = http.client.HTTPSConnection("localhost", srv.server_address[1], context=cctx, timeout=10)
        c.request("GET", "/")
        r = c.getresponse()
        self.assertEqual(r.status, 200)
        self.assertIn("Strict-Transport-Security", dict(r.getheaders()))
        der = c.sock.getpeercert(True)
        import hashlib
        h = hashlib.sha256(der).hexdigest().upper()
        self.assertEqual(fp.replace(":", ""), h)
        c.close()
        # a plain-HTTP client on the TLS port gets nowhere, and the server lives on
        import socket
        s = socket.create_connection(("127.0.0.1", srv.server_address[1]), timeout=5)
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        s.recv(100)
        s.close()
        c = http.client.HTTPSConnection("localhost", srv.server_address[1], context=cctx, timeout=10)
        c.request("GET", "/static/wizard.css")
        self.assertEqual(c.getresponse().status, 200)
        c.close()

    def test_cmd_web_self_signed_banner(self):
        out = io.StringIO()
        rc = cmd_web.main(["--tls", "self-signed", "--port", "0", "--no-qr", "--domain", "example.com"],
                          steps=list(self.steps), env={"PORCH_CONFIG": "none"}, out=out, serve=False,
                          ctx_kwargs=self.ctx_kwargs)
        text = out.getvalue()
        self.assertEqual(rc, 0, text)
        self.assertRegex(text, r"https://localhost:\d+/#k=[A-Za-z0-9_-]{43}")
        self.assertRegex(text, r"([0-9A-F]{2}:){31}[0-9A-F]{2}")
        self.assertIn("ssh -L", text)


class TestCmdWeb(Base):
    def test_low_port_needs_root(self):
        out = io.StringIO()
        rc = cmd_web.main(["--tls", "self-signed", "--port", "443"], steps=list(self.steps),
                          env={}, out=out, serve=False, os_mod=FakeOS(euid=1000))
        self.assertEqual(rc, 2)
        self.assertIn("need root", out.getvalue())

    def test_root_without_sudo_ids_refused_before_anything(self):
        out = io.StringIO()
        runner = FakeRunner(strict=True)
        rc = cmd_web.main(["--tls", "self-signed", "--port", "0"], steps=list(self.steps),
                          env={}, out=out, serve=False, os_mod=FakeOS(euid=0), runner=runner)
        self.assertEqual(rc, 2)
        self.assertIn("SUDO_UID", out.getvalue())
        self.assertEqual(runner.calls, [])

    def test_host_ip_takes_first_of_list(self):
        # net.probe.host_public_ipv4 returns a list; the wizard needs one address
        self.assertEqual(cmd_web._host_ip(lambda: ["51.15.20.7", "51.15.20.8"]), "51.15.20.7")
        self.assertIsNone(cmd_web._host_ip(lambda: []))

    @unittest.skipUnless(HAVE_OPENSSL, "needs openssl")
    def test_ip_mode_requests_cert_for_a_single_address(self):
        out = io.StringIO()
        runner = FakeRunner().on(["certbot", "--version"], stdout="certbot 1.0.0\n")
        runner.on(lambda a: a[0] == "openssl", func=lambda argv, **kw: Runner().run(argv))
        cmd_web.main(["--tls", "ip", "--port", "0", "--http-port", "0", "--no-qr"],
                     steps=list(self.steps), env={"PORCH_CONFIG": "none"}, out=out, serve=False,
                     os_mod=FakeOS(euid=1000), runner=runner, ctx_kwargs=self.ctx_kwargs,
                     host_ip=lambda: ["51.15.20.7"])
        text = out.getvalue()
        self.assertIn("certificate for 51.15.20.7 ", text)
        self.assertIn("Falling back to a self-signed certificate", text)
        self.assertRegex(text, r"https://51\.15\.20\.7:\d+/#k=")
        self.assertNotIn("['", text)

    @unittest.skipUnless(HAVE_OPENSSL, "needs openssl")
    def test_acme_webroot_made_after_privilege_drop(self):
        # The http-01 hook runs as the sudo user; a webroot created while
        # still root is not writable for it (found on a fresh VPS).
        from unittest import mock
        order = []
        real_tmp = web.private_tempdir

        def tmpdir(prefix="porch-web-"):
            order.append(("tmp", prefix))
            return real_tmp(prefix)

        runner = FakeRunner().on(["certbot", "--version"], stdout="certbot 1.0.0\n")
        runner.on(lambda a: a[0] == "openssl", func=lambda argv, **kw: Runner().run(argv))
        with mock.patch.object(web, "private_tempdir", tmpdir), \
                mock.patch.object(web, "drop_privileges", lambda *a, **k: order.append(("drop",))):
            cmd_web.main(["--tls", "ip", "--port", "0", "--http-port", "0", "--no-qr"],
                         steps=list(self.steps), env={"PORCH_CONFIG": "none"}, out=io.StringIO(),
                         serve=False, os_mod=FakeOS(euid=1000), runner=runner,
                         ctx_kwargs=self.ctx_kwargs, host_ip=lambda: ["51.15.20.7"])
        self.assertIn(("tmp", "porch-acme-"), order)
        self.assertLess(order.index(("drop",)), order.index(("tmp", "porch-acme-")))

    def test_ip_mode_never_takes_443_by_default(self):
        # The setup it drives installs HAProxy on :443 (found on a fresh VPS:
        # preflight refused because the wizard itself held 443).
        from unittest import mock
        seen = []

        def bind_tls(addr):
            seen.append(addr)
            raise OSError(98, "stop here")
        with mock.patch.object(web, "bind_tls", bind_tls):
            rc = cmd_web.main(["--tls", "ip", "--no-qr"], steps=list(self.steps),
                              env={"PORCH_CONFIG": "none"}, out=io.StringIO(), serve=False,
                              os_mod=FakeOS(euid=0), runner=FakeRunner(),
                              ctx_kwargs=self.ctx_kwargs, host_ip=lambda: ["51.15.20.7"])
        self.assertEqual(rc, 2)
        self.assertEqual(seen, [("0.0.0.0", cmd_web.DEFAULT_SELF_PORT)])

    # -- restart after the haproxy step: reuse the domain certificate --------------
    def _domain_setup(self, status="done", home=None):
        cfg = self.ctx_kwargs["cfg"]
        os.makedirs(self.ctx_kwargs["data_dir"], exist_ok=True)
        with open(os.path.join(self.ctx_kwargs["data_dir"], "porch-setup.json"), "w") as f:
            json.dump({"version": 1, "steps": {"certificate": {"status": status}}}, f)
        certs = os.path.join(home, ".local/share/porch/certs") if home else os.path.join(self.tmp, "certs")
        os.makedirs(certs, exist_ok=True)
        pem = os.path.join(certs, acme.cert_name_for(cfg.root) + ".pem")
        cert, key, _ = web.make_self_signed(Runner(), os.path.join(self.tmp, "ss"))
        with open(pem, "w") as f, open(cert) as c, open(key) as k:
            f.write(c.read() + k.read())
        return pem, cfg, certs

    @unittest.skipUnless(HAVE_OPENSSL, "needs openssl")
    def test_restart_after_haproxy_serves_the_domain_cert(self):
        pem, cfg, certs = self._domain_setup()
        from unittest import mock
        seen = []
        real_ctx = web.server_context

        def sctx(c, k):
            seen.append((c, k))
            return real_ctx(c, k)
        out = io.StringIO()
        runner = FakeRunner(strict=True)
        with mock.patch.object(web, "server_context", sctx):
            rc = cmd_web.main(["--port", "0", "--no-qr"], steps=list(self.steps),
                              env={"PORCH_CONFIG": "none", "PORCH_CERT_DIR": certs}, out=out,
                              serve=False, os_mod=FakeOS(euid=1000), runner=runner,
                              ctx_kwargs=self.ctx_kwargs, host_ip=lambda: ["51.15.20.7"])
        text = out.getvalue()
        self.assertEqual(rc, 0, text)
        self.assertEqual(seen, [(pem, pem)])
        self.assertRegex(text, r"https://" + re.escape(cfg.auth_host) + r":\d+/#k=")
        self.assertNotIn("Let's Encrypt", text)
        self.assertNotIn("fingerprint", text)
        self.assertEqual(runner.calls, [])     # no certbot, no openssl

    def test_restart_binds_all_interfaces_on_8443_without_root(self):
        _, _, certs = self._domain_setup()
        from unittest import mock
        seen = []

        def bind_tls(addr):
            seen.append(addr)
            raise OSError(98, "stop here")
        with mock.patch.object(web, "bind_tls", bind_tls):
            rc = cmd_web.main(["--no-qr"], steps=list(self.steps),
                              env={"PORCH_CONFIG": "none", "PORCH_CERT_DIR": certs},
                              out=io.StringIO(), serve=False, os_mod=FakeOS(euid=1000),
                              runner=FakeRunner(strict=True), ctx_kwargs=self.ctx_kwargs)
        self.assertEqual(rc, 2)    # not "ports below 1024 need root"
        self.assertEqual(seen, [("0.0.0.0", cmd_web.DEFAULT_SELF_PORT)])

    def test_domain_cert_needs_the_step_done_and_the_pem(self):
        pem, cfg, certs = self._domain_setup(status="failed")
        env = {"PORCH_CONFIG": "none", "PORCH_CERT_DIR": certs}
        self.assertIsNone(cmd_web.domain_cert(env, self.ctx_kwargs, FakeOS(euid=1000)))
        self._domain_setup(status="done")
        self.assertEqual(cmd_web.domain_cert(env, self.ctx_kwargs, FakeOS(euid=1000)),
                         (pem, cfg.auth_host))
        os.unlink(pem)
        self.assertIsNone(cmd_web.domain_cert(env, self.ctx_kwargs, FakeOS(euid=1000)))
        self.assertIsNone(cmd_web.domain_cert(env, dict(self.ctx_kwargs, data_dir=self.tmp + "/no"),
                                              FakeOS(euid=1000)))

    def test_domain_cert_under_sudo_looks_in_the_sudo_users_home(self):
        import types
        home = os.path.join(self.tmp, "home-porch")
        pem, cfg, _ = self._domain_setup(home=home)
        pw = types.SimpleNamespace(getpwuid=lambda uid: types.SimpleNamespace(pw_dir=home))
        env = {"PORCH_CONFIG": "none", "HOME": "/root", "SUDO_UID": "1001", "SUDO_GID": "1001"}
        self.assertEqual(cmd_web.domain_cert(env, self.ctx_kwargs, FakeOS(euid=0), pw),
                         (pem, cfg.auth_host))

    @unittest.skipUnless(HAVE_OPENSSL, "needs openssl")
    def test_explicit_flags_win_over_the_domain_cert(self):
        pem, cfg, certs = self._domain_setup()
        env = {"PORCH_CONFIG": "none", "PORCH_CERT_DIR": certs}
        out = io.StringIO()
        rc = cmd_web.main(["--tls", "self-signed", "--port", "0", "--no-qr"], steps=list(self.steps),
                          env=env, out=out, serve=False, os_mod=FakeOS(euid=1000),
                          ctx_kwargs=self.ctx_kwargs)
        self.assertEqual(rc, 0)
        self.assertIn("fingerprint", out.getvalue())
        self.assertNotIn(cfg.auth_host, out.getvalue())
        out = io.StringIO()
        rc = cmd_web.main(["--port", "0", "--no-qr", "--host", "setup.example.net", "--bind", "127.0.0.1"],
                          steps=list(self.steps), env=env, out=out, serve=False,
                          os_mod=FakeOS(euid=1000), ctx_kwargs=self.ctx_kwargs)
        self.assertEqual(rc, 0)
        self.assertRegex(out.getvalue(), r"https://setup\.example\.net:\d+/#k=")

    def test_unknown_flag(self):
        out = io.StringIO()
        rc = cmd_web.main(["--bogus"], steps=list(self.steps), env={}, out=out, serve=False)
        self.assertEqual(rc, 2)

    def test_preset_from_step_flags(self):
        self.assertEqual(cmd_web._preset(["--domain", "x.example", "--token-ref", "inf://p/x/Y"],
                                         list(self.steps)),
                         {"domain": "x.example", "token": "inf://p/x/Y"})

    def test_qr_text(self):
        art = web.qr_text("https://1.2.3.4/#k=abc")
        if web.qr_matrix("x") is None:
            self.assertEqual(art, "")
        else:
            self.assertGreater(len(art.splitlines()), 10)

    def test_qr_matrix_level_h_without_border_for_the_logo(self):
        # /api/qr asks for H (the page knocks out the centre for the mark)
        # and no quiet zone (the page pads it): H needs more modules than L.
        if web.qr_matrix("x") is None:
            self.skipTest("python-qrcode not installed")
        url = "https://porch-reach-7f3k2.tunnel.example.com/n/8Hq2xZ"
        low, high = web.qr_matrix(url), web.qr_matrix(url, ec="H", border=0)
        self.assertGreater(len(high), len(low) - 4)
        self.assertTrue(all(high[0][:7]))          # finder starts at the edge


if __name__ == "__main__":
    unittest.main()

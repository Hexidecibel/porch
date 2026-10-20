"""Tests for lib/statusserver.py. Stdlib unittest only; run with bin/test.

Everything runs against temp dirs: a temp devices.json, history file and
tunnel-state dir. Nothing is launched or killed: _run_launch is replaced by a
recorder and frpc matching runs against a fake /proc.
"""

import hashlib
import http.client
import importlib.util
import json
import os
import stat
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "statusserver", os.path.join(_HERE, "..", "lib", "statusserver.py")
)
ss = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ss)

OWNER = "owner-cookie-value"
GUEST = "guest-cookie-value"


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class StatusCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = Path(self.tmp.name)
        self.devices = d / "devices.json"
        self.history = d / "history.jsonl"
        self.state = d / "state"
        self.state.mkdir()
        self.write_devices([
            {"id": "dev_o", "type": "browser", "role": "admin", "token_sha256": sha(OWNER)},
            {"id": "dev_g", "type": "browser", "role": "guest", "token_sha256": sha(GUEST)},
        ])
        saved = (ss.StatusHandler.state_dir, ss.StatusHandler.devices_path,
                 ss.StatusHandler.history_path)
        self.addCleanup(lambda: setattr(ss.StatusHandler, "state_dir", saved[0]) or
                        setattr(ss.StatusHandler, "devices_path", saved[1]) or
                        setattr(ss.StatusHandler, "history_path", saved[2]))
        ss.porch_auth.reset_cache()
        ss._history_cache["key"] = None
        self.launches = []
        test = self

        class H(ss.StatusHandler):
            state_dir = self.state
            devices_path = str(self.devices)
            history_path = str(self.history)
            # launch recipes and reopen asks: temp dirs, never data/ or the run dir
            doors_dir = str(d / "doors")
            reopen_store = ss.reopen_requests.Store(str(d / "requests.json"))

            def log_message(self, *a):
                pass

            def _run_launch(self, argv, cwd, name, rtype, stdin=None, log_path=None,
                            timeout=20):
                test.launches.append({"argv": argv, "cwd": cwd, "log": log_path})
                self.send_json({"status": "ok"})

        self.httpd = ss.StatusServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        t.start()
        self.addCleanup(t.join)
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def write_devices(self, devices):
        with open(self.devices, "w") as f:
            json.dump({"devices": devices}, f)
        # mtime resolution: make sure a rewrite is seen as a change.
        st = os.stat(self.devices)
        os.utime(self.devices, ns=(st.st_atime_ns, st.st_mtime_ns + 10_000_000))

    def req(self, method, path, body=None, cookie=OWNER, cookie_name="cush_auth",
            host=None, raw=None):
        hdrs = {}
        if cookie:
            hdrs["Cookie"] = f"{cookie_name}={cookie}"
            hdrs["X-CSRF-Token"] = ss.csrf_token_for(cookie)
        if host:
            hdrs["Host"] = host
        payload = raw if raw is not None else (json.dumps(body) if body is not None else None)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=payload, headers=hdrs)
            resp = conn.getresponse()
            data = resp.read()
            try:
                data = json.loads(data)
            except ValueError:
                pass
            return resp.status, data
        finally:
            conn.close()


class OwnerTest(StatusCase):
    def test_owner_and_guest(self):
        self.assertTrue(self.req("GET", "/api/me")[1]["owner"])
        self.assertFalse(self.req("GET", "/api/me", cookie=GUEST)[1]["owner"])
        self.assertEqual(self.req("GET", "/api/tunnels", cookie=GUEST)[0], 403)

    def test_expired_owner_is_not_owner(self):
        now = time.time()
        self.write_devices([{"id": "dev_o", "type": "browser", "role": "admin",
                             "token_sha256": sha(OWNER), "expires_at": iso(now + 3600)}])
        self.assertTrue(self.req("GET", "/api/me")[1]["owner"])
        # Expiry passes with no change to the file: still enforced.
        self.assertFalse(ss.porch_auth.is_owner_token(OWNER, str(self.devices), now + 7200))
        self.write_devices([{"id": "dev_o", "type": "browser", "role": "admin",
                             "token_sha256": sha(OWNER), "expires_at": iso(now - 1)}])
        self.assertFalse(self.req("GET", "/api/me")[1]["owner"])
        self.write_devices([{"id": "dev_o", "type": "browser", "role": "admin",
                             "token_sha256": sha(OWNER), "expires_at": "garbage"}])
        self.assertFalse(self.req("GET", "/api/me")[1]["owner"])

    def test_porch_host_cookie_is_bound_to_its_host(self):
        now = time.time()
        self.write_devices([{"id": "dev_o", "type": "browser", "role": "admin",
                             "token_sha256": sha(OWNER),
                             "host_tokens": [{"sha256": sha("HT"), "host": "tunnel.cush.rocks",
                                              "expires_at": iso(now + 600)}]}])
        ok = self.req("GET", "/api/me", cookie="HT", cookie_name="porch_host",
                      host="tunnel.cush.rocks")
        self.assertTrue(ok[1]["owner"])
        other = self.req("GET", "/api/me", cookie="HT", cookie_name="porch_host",
                         host="grab.cush.rocks")
        self.assertFalse(other[1]["owner"])
        self.write_devices([{"id": "dev_o", "type": "browser", "role": "admin",
                             "revoked": True, "token_sha256": sha(OWNER),
                             "host_tokens": [{"sha256": sha("HT"), "host": "tunnel.cush.rocks",
                                              "expires_at": iso(now + 600)}]}])
        self.assertFalse(self.req("GET", "/api/me", cookie="HT", cookie_name="porch_host",
                                  host="tunnel.cush.rocks")[1]["owner"])

    def test_non_object_body_is_400(self):
        for raw in ("[]", "1", '"x"'):
            self.assertEqual(self.req("POST", "/api/launch", raw=raw)[0], 400, raw)


class ReviveTest(StatusCase):
    def hist(self, *recs):
        with open(self.history, "w") as f:
            for r in recs:
                f.write(json.dumps(r) + "\n")

    def test_stored_cmd_cwd_and_log_are_ignored(self):
        self.hist({"event": "start", "name": "pics", "type": "drop",
                   "cmd": ["/bin/sh", "-c", "touch /tmp/pwned"], "cwd": "/",
                   "log": "/etc/shadow", "ts": 1})
        code, _ = self.req("POST", "/api/history/pics/revive")
        self.assertEqual(code, 200)
        (launch,) = self.launches
        self.assertEqual(launch["argv"], [str(ss.REPO_ROOT / "bin" / "drop"), "pics", "--bg"])
        self.assertEqual(launch["cwd"], str(ss.REPO_ROOT))
        self.assertEqual(launch["log"], str(ss.REPO_ROOT / "logs" / "pics.log"))

    def test_types_and_flags_are_allowlisted(self):
        self.hist(
            {"event": "start", "name": "srv", "type": "serve", "cmd": ["x"], "ts": 1},
            {"event": "start", "name": "bad", "type": "../../bin/sh", "ts": 2},
            {"event": "start", "name": "reel", "type": "media",
             "flags": ["--view-only", "--evil"], "ts": 3},
            {"event": "start", "name": "entry-key", "type": "secure-entry", "ts": 4},
        )
        self.assertEqual(self.req("POST", "/api/history/srv/revive")[0], 400)
        self.assertEqual(self.req("POST", "/api/history/bad/revive")[0], 400)
        self.assertEqual(self.req("POST", "/api/history/reel/revive")[0], 200)
        self.assertEqual(self.launches[-1]["argv"][1:], ["reel", "--view-only", "--bg"])
        self.assertEqual(self.req("POST", "/api/history/entry-key/revive")[0], 200)
        self.assertEqual(self.launches[-1]["argv"][1:], ["key", "--bg"])
        items = {i["name"]: i for i in self.req("GET", "/api/history")[1]}
        self.assertFalse(items["srv"]["revivable"])
        self.assertTrue(items["reel"]["revivable"])
        self.assertNotIn("cwd", items["reel"])

    def test_history_is_private_and_capped(self):
        ss.ensure_private_file(str(self.history))
        self.assertEqual(stat.S_IMODE(os.stat(self.history).st_mode), 0o600)
        recs = [{"event": "start", "name": f"n{i}", "type": "drop", "ts": i}
                for i in range(ss.HISTORY_MAX + 5)]
        self.hist(*recs)
        out = ss.read_history(str(self.history))
        self.assertEqual(len(out), ss.HISTORY_KEEP)
        self.assertEqual(out[-1]["name"], recs[-1]["name"])
        with open(self.history) as f:
            self.assertEqual(sum(1 for _ in f), ss.HISTORY_KEEP)
        self.assertEqual(stat.S_IMODE(os.stat(self.history).st_mode), 0o600)
        # Cached: an unchanged file is not re-parsed.
        first = ss.read_history(str(self.history))
        self.assertEqual(ss._history_cache["key"][1], os.stat(self.history).st_size)
        self.assertEqual(first, ss.read_history(str(self.history)))


class StateFileTest(StatusCase):
    def test_write_state_atomic_unique_temp_and_no_leftovers(self):
        p = self.state / "x.json"
        ss.write_state_atomic(p, {"name": "x", "pid": 1})
        self.assertEqual(json.loads(p.read_text())["name"], "x")
        self.assertEqual(sorted(os.listdir(self.state)), ["x.json"])

    def test_corrupt_state_file_is_a_409_not_a_crash(self):
        (self.state / "bad.json").write_text("{nope")
        for action in ("extend", "keep-alive"):
            code, data = self.req("POST", f"/api/tunnels/bad/{action}")
            self.assertEqual(code, 409, action)
            self.assertIn("unreadable", data["message"])


class DoorFieldsTest(StatusCase):
    """Door rules / opens / exact expiry in the API, and POST .../expire."""

    def door(self, **extra):
        st = {"name": "door1", "type": "serve", "pid": os.getpid(), "port": 1,
              "started": int(time.time()), "expires": int(time.time()) + 600,
              "keep_alive": False, "opens": 3, "last_open": int(time.time()) - 5,
              "rules": {"password": ss.door_state.hash_password("hunter22"),
                        "guest": "G" * 32, "max_opens": 5},
              "proxy": {"port": 1, "pid": 1}}
        st.update(extra)
        ss.write_state_atomic(self.state / "door1.json", st)

    def test_listing_shows_rules_never_the_secrets(self):
        self.door()
        code, data = self.req("GET", "/api/tunnels")
        self.assertEqual(code, 200)
        t = [x for x in data if x.get("name") == "door1"][0]
        self.assertEqual(t["rules"], {"password": True, "guest_link": True, "max_opens": 5})
        self.assertEqual(t["opens"], 3)
        self.assertIsInstance(t["last_open"], int)
        self.assertFalse(t["never"])
        raw = json.dumps(data)
        self.assertNotIn("scrypt$", raw)
        self.assertNotIn("G" * 32, raw)
        self.assertNotIn("proxy", t)

    def test_never_is_null_expires(self):
        self.door(expires=None, keep_alive=True)
        t = [x for x in self.req("GET", "/api/tunnels")[1] if x.get("name") == "door1"][0]
        self.assertIsNone(t["expires"])
        self.assertTrue(t["never"])
        self.assertIsNone(t["time_remaining"])

    def test_expire_endpoint(self):
        self.door()
        now = int(time.time())
        code, data = self.req("POST", "/api/tunnels/door1/expire", {"at": now + 7200})
        self.assertEqual((code, data["expires"]), (200, now + 7200))
        code, data = self.req("POST", "/api/tunnels/door1/expire", {"at": "+30m"})
        self.assertEqual(code, 200)
        self.assertAlmostEqual(data["expires"], now + 1800, delta=5)
        code, data = self.req("POST", "/api/tunnels/door1/expire", {"at": "never"})
        self.assertEqual(code, 200)
        self.assertTrue(data["never"])
        st = json.loads((self.state / "door1.json").read_text())
        self.assertIsNone(st["expires"])
        self.assertTrue(st["keep_alive"])
        # The rest of the state (rules, opens) survives the edit.
        self.assertEqual(st["opens"], 3)
        self.assertIn("password", st["rules"])
        # Extend does nothing to a never-expiring door; keep-alive puts it back on a timer.
        self.assertTrue(self.req("POST", "/api/tunnels/door1/extend")[1]["never"])
        code, data = self.req("POST", "/api/tunnels/door1/keep-alive")
        self.assertFalse(data["never"])
        self.assertAlmostEqual(data["expires"], now + 3600, delta=5)
        for bad in ({"at": now - 10}, {"at": "soonish"}, {"at": True}, {}, {"at": "400d"}):
            self.assertEqual(self.req("POST", "/api/tunnels/door1/expire", bad)[0], 400, bad)
        self.assertEqual(self.req("POST", "/api/tunnels/nope/expire", {"at": "1h"})[0], 404)

    def test_expire_is_owner_and_csrf_gated(self):
        self.door()
        self.assertEqual(self.req("POST", "/api/tunnels/door1/expire", {"at": "never"},
                                  cookie=GUEST)[0], 403)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/api/tunnels/door1/expire", body='{"at": "never"}',
                     headers={"Cookie": f"cush_auth={OWNER}"})
        self.assertEqual(conn.getresponse().status, 403)
        conn.close()
        self.assertFalse(json.loads((self.state / "door1.json").read_text())["keep_alive"])

    def test_console_has_expiry_controls(self):
        code, html = self.req("GET", "/")
        self.assertEqual(code, 200)
        for needle in ("/expire", "fillRules", "datetime-local", "never expires"):
            self.assertIn(needle.encode(), html)


class FrpcMatchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def proc(self, pid, *argv):
        d = os.path.join(self.tmp.name, str(pid))
        os.makedirs(d)
        with open(os.path.join(d, "cmdline"), "wb") as f:
            f.write(b"\0".join(a.encode() for a in argv) + b"\0")

    def test_exact_config_name_only(self):
        self.proc(10, "/repo/bin/frpc", "-c", "/tmp/frpc-c-AbC12.toml")
        self.proc(11, "/repo/bin/frpc", "-c", "/tmp/frpc-chat-Zx9Q1.toml")
        self.proc(12, "/repo/bin/frpc", "-c", "/tmp/frpc-c-sp-Zx9Q1.toml")
        self.proc(13, "vim", "/tmp/frpc-c-AbC12.toml")
        self.proc(14, "/repo/bin/frpc", "-c", "/tmp/frpc-c-.toml")
        self.assertEqual(ss.frpc_pids_for("c", proc=self.tmp.name), [10])
        self.assertEqual(ss.frpc_pids_for("chat", proc=self.tmp.name), [11])
        self.assertEqual(ss.frpc_pids_for("c-sp", proc=self.tmp.name), [12])


class SecureEntryLaunchTest(StatusCase):
    """The real _run_launch against a fake bin/secure-entry: the response must
    carry the launcher's token URL on the entry-<name> host."""

    def setUp(self):
        super().setUp()
        root = Path(self.tmp.name) / "repo"
        (root / "bin").mkdir(parents=True)
        (root / "logs").mkdir()
        fake = root / "bin" / "secure-entry"
        fake.write_text(
            "#!/bin/sh\n"
            "echo \"argv: $*\" >> \"$(dirname \"$0\")/../calls\"\n"
            "[ \"$1\" = noline ] && exit 0\n"
            "echo \"Secure entry: https://entry-$1.tunnel.cush.rocks/Tok_en-123456789abc/\"\n"
            "echo \"Secret will be saved to: /tmp/x\"\n")
        fake.chmod(0o755)
        self.root = root
        self._saved_root = ss.REPO_ROOT
        ss.REPO_ROOT = root
        self.addCleanup(lambda: setattr(ss, "REPO_ROOT", self._saved_root))
        test = self

        class Real(ss.StatusHandler):
            state_dir = test.state
            devices_path = str(test.devices)
            history_path = str(test.history)

            def log_message(self, *a):
                pass

        self.httpd.RequestHandlerClass = Real

    def test_launch_returns_token_url_on_entry_host(self):
        code, body = self.req("POST", "/api/launch", {"type": "secure-entry", "name": "apikey"})
        self.assertEqual(code, 200, body)
        self.assertEqual(body["url"], "https://entry-apikey.tunnel.cush.rocks/Tok_en-123456789abc/")
        self.assertEqual(body["name"], "entry-apikey")
        self.assertIn("argv: apikey --bg", (self.root / "calls").read_text())

    def test_launch_refuses_when_entry_state_exists(self):
        (self.state / "entry-apikey.json").write_text("{}")
        code, body = self.req("POST", "/api/launch", {"type": "secure-entry", "name": "apikey"})
        self.assertEqual(code, 409)
        self.assertFalse((self.root / "calls").exists())

    def test_missing_url_line_is_an_error_not_a_bare_host(self):
        code, body = self.req("POST", "/api/launch", {"type": "secure-entry", "name": "noline"})
        self.assertEqual(code, 500)
        self.assertNotIn("url", body)

    def test_revive_returns_token_url(self):
        with open(self.history, "w") as f:
            f.write(json.dumps({"event": "start", "name": "entry-apikey", "type": "secure-entry",
                                "ts": time.time()}) + "\n")
        code, body = self.req("POST", "/api/history/entry-apikey/revive")
        self.assertEqual(code, 200, body)
        self.assertEqual(body["url"], "https://entry-apikey.tunnel.cush.rocks/Tok_en-123456789abc/")


import sys  # noqa: E402
sys.path.insert(0, os.path.join(_HERE, "..", "lib"))
import porch_config  # noqa: E402


class DomainTest(StatusCase):
    def use(self, **env):
        e = {"PORCH_CONFIG": "none"}
        e.update(env)
        saved = ss.DOMAIN
        ss.DOMAIN = porch_config.load(env=e)
        self.addCleanup(setattr, ss, "DOMAIN", saved)

    def test_secure_entry_url_rejects_lookalikes(self):
        ok = "Secure entry: https://entry-k.tunnel.cush.rocks/Tok_123/"
        self.assertEqual(ss.secure_entry_url(ok, "entry-k"),
                         "https://entry-k.tunnel.cush.rocks/Tok_123/")
        for bad in ("https://entry-k.tunnel.cush.rocks.evil.com/Tok_123/",
                    "https://entry-k.eviltunnel.cush.rocks/Tok_123/",
                    "https://entry-k.tunnelXcush.rocks/Tok_123/",
                    "https://entry-k.tunnel.example.org/Tok_123/"):
            self.assertIsNone(ss.secure_entry_url("Secure entry: " + bad, "entry-k"), bad)

    def test_other_domain(self):
        self.use(PORCH_DOMAIN="example.org")
        self.assertEqual(ss.tunnel_url("drop"), "https://drop.tunnel.example.org")
        self.assertEqual(ss.secure_entry_url(
            "Secure entry: https://entry-k.tunnel.example.org/T_1/", "entry-k"),
            "https://entry-k.tunnel.example.org/T_1/")
        self.assertIsNone(ss.secure_entry_url(
            "Secure entry: https://entry-k.tunnel.cush.rocks/T_1/", "entry-k"))
        code, body = self.req("GET", "/")
        self.assertEqual(code, 200)
        body = body.decode()
        self.assertIn("var HOST_SUFFIX = '.tunnel.example.org';", body)
        self.assertIn('href="https://auth.example.org/auth/"', body)
        self.assertNotIn("cush.rocks", body)
        self.assertNotIn("__PORCH_", body)
        code, body = self.req("GET", "/", cookie=GUEST)
        self.assertEqual(code, 403)
        body = body.decode()
        self.assertIn('href="https://auth.example.org/auth/"', body)
        self.assertNotIn("__PORCH_", body)
        code, body = self.req("GET", "/api/tunnels", cookie=GUEST)
        self.assertIn("https://auth.example.org/auth/", body["message"])


if __name__ == "__main__":
    unittest.main()

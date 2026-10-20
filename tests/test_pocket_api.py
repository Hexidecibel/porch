"""Pocket's control-plane API (lib/pocket_doors.py, lib/pocket_people.py,
lib/pocket_audit.py, the route table in lib/pocketserver.py): doors over a
temp state dir with fake launchers, the inspector on a temp store, people
through a fake cush-auth, AuthWatcher diffs with an injected clock and a
fake push, CSRF, the CLI token refused, nothing secret in the logs."""

import json
import re
import os
import socket
import time
import unittest

import pocket_harness as ph
from pocket_harness import ps

ORIGIN_HDR = "Origin"


class Base(unittest.TestCase):
    watcher = False

    def setUp(self):
        self.fx = ph.PocketFixture(watcher=self.watcher).start()

    def tearDown(self):
        self.fx.stop()

    def door(self, name="pt-drop", **kw):
        return ph.write_door(self.fx.state_dir, name, self.fx.sleepers.pid(), **kw)


# ---- the route table's gate --------------------------------------------------------

NEW_GETS = ["/api/app", "/api/activity", "/api/doors", "/api/doors/history", "/api/requests",
            "/api/people", "/api/people/public-paths", "/api/passkeys",
            "/api/doors/pt-drop/requests",
            "/api/doors/pt-drop/requests/1", "/api/doors/pt-drop/requests/events"]
NEW_POSTS = ["/api/doors/stop-all", "/api/doors/launch", "/api/doors/pt-drop/extend",
             "/api/doors/pt-drop/expire", "/api/doors/pt-drop/stop", "/api/doors/pt-drop/rules",
             "/api/doors/history/pt-drop/reopen", "/api/doors/history/pt-drop/revive",
             "/api/doors/history/pt-drop/forget", "/api/doors/pt-drop/requests/1/replay",
             "/api/requests/pairings/ABCD-1234/approve", "/api/requests/pairings/ABCD-1234/reject",
             "/api/people/devices/dev_box/revoke", "/api/people/devices/dev_box/role",
             "/api/people/devices/dev_box/apps", "/api/people/devices/dev_box/rename",
             "/api/people/invites", "/api/people/invites/inv_1/revoke", "/api/people/apps",
             "/api/people/password", "/api/people/public-paths",
             "/api/people/public-paths/pp_0000beef/on", "/api/people/public-paths/pp_0000beef/off",
             "/api/people/public-paths/pp_0000beef/remove", "/api/stepup/options", "/api/stepup/passkey",
             "/api/stepup/password", "/api/stepup/end", "/api/passkeys/register/options",
             "/api/passkeys/register", "/api/passkeys/" + "A" * 20 + "/rename",
             "/api/passkeys/" + "A" * 20 + "/delete", "/api/push/topics"]


class GateTests(Base):

    def test_every_new_route_is_owner_only(self):
        self.door()
        for token in (None, ph.GUEST_TOKEN, "nope"):
            for path in NEW_GETS:
                r, _ = self.fx.get(path, token=token)
                self.assertEqual(r.status, 403, (token, path))
            for path in NEW_POSTS:
                r, _ = self.fx.post(path, {}, token=token)
                self.assertEqual(r.status, 403, (token, path))

    def test_cli_token_never_passes_a_new_route(self):
        h = {ps.CLI_TOKEN_HEADER: ph.CLI_TOKEN}
        for path in NEW_GETS:
            r, _ = self.fx.get(path, token=None, origin=False, headers=h)
            self.assertEqual(r.status, 403, path)
        for path in NEW_POSTS:
            r, _ = self.fx.post(path, {}, token=None, origin=False, headers=h)
            self.assertEqual(r.status, 403, path)
        # ... while the old routes still take it.
        r, _ = self.fx.get("/api/clip", token=None, origin=False, headers=h)
        self.assertEqual(r.status, 200)

    def test_writes_need_same_origin(self):
        self.door()
        r, out = self.fx.post("/api/doors/pt-drop/extend", {}, origin=False)
        self.assertEqual((r.status, out["code"]), (403, "csrf"))
        r, out = self.fx.post("/api/doors/pt-drop/extend", {}, origin=False,
                              headers={"Origin": "https://evil.tunnel.cush.rocks"})
        self.assertEqual((r.status, out["code"]), (403, "csrf"))
        r, out = self.fx.post("/api/doors/pt-drop/extend", {}, origin=False,
                              headers={"Origin": "null"})
        self.assertEqual(r.status, 403)

    def test_writes_need_json(self):
        self.door()
        for ctype in ("text/plain", "application/x-www-form-urlencoded", "multipart/form-data",
                      None):
            r, out = self.fx.post("/api/doors/pt-drop/extend", b"{}", ctype=ctype)
            self.assertEqual((r.status, out["code"]), (415, "bad_content_type"), ctype)
        r, _ = self.fx.post("/api/doors/pt-drop/extend", b"{}",
                            ctype="application/json; charset=utf-8")
        self.assertEqual(r.status, 200)

    def test_body_caps_and_shape(self):
        self.door()
        r, out = self.fx.post("/api/doors/pt-drop/extend", b"x" * 9000)
        self.assertEqual((r.status, out["code"]), (413, "too_large"))
        r, out = self.fx.post("/api/doors/pt-drop/extend", b"[1]")
        self.assertEqual((r.status, out["code"]), (400, "bad_request"))
        r, out = self.fx.post("/api/doors/pt-drop/extend", b"{nope")
        self.assertEqual(r.status, 400)

    def test_permissions_policy_on_pages(self):
        r, _ = self.fx.get("/")
        pp = r.getheader("Permissions-Policy")
        self.assertIn("publickey-credentials-get=(self)", pp)
        self.assertIn("publickey-credentials-create=(self)", pp)
        self.assertIn("camera=()", pp)
        r, _ = self.fx.get("/", token=None)
        self.assertIn("geolocation=()", r.getheader("Permissions-Policy"))

    def test_app_shell_served(self):
        r, out = self.fx.get("/")
        self.assertEqual(r.status, 200)
        self.assertIn(b'id="app"', out)
        self.assertIsNone(re.search(rb"__[A-Z][A-Za-z0-9_.]*__", re.sub(rb"<!--.*?-->", b"", out, flags=re.S)))


# ---- /api/app + activity ------------------------------------------------------------

class AppTests(Base):

    def test_app(self):
        self.door()
        r, out = self.fx.get("/api/app")
        self.assertEqual(r.status, 200)
        self.assertEqual(out["pocket"], {"name": "pocket", "title": "Porch", "host": ph.RP_ID,
                                         "origin": ph.RP_ORIGIN})
        self.assertEqual(out["me"], {"device_id": "dev_owner", "device_name": "My iPhone"})
        self.assertEqual(out["stepup"], {"active": False, "expires_at": None, "method": None})
        self.assertEqual(out["passkeys"]["count"], 0)
        self.assertEqual(out["passkeys"]["rp_id"], ph.RP_ID)
        self.assertEqual(out["counts"]["doors"], 1)
        self.assertIn(out["auth"]["state"], ("ok", "stale", "down", "old"))
        self.assertIn("supported", out["push"])
        tok = self.fx.password_stepup()
        _, out = self.fx.get("/api/app", stepup=tok)
        self.assertTrue(out["stepup"]["active"])
        self.assertEqual(out["stepup"]["method"], "password")

    def test_activity_lists_privileged_actions_newest_first(self):
        self.door()
        self.fx.post("/api/doors/pt-drop/extend", {})
        self.fx.post("/api/doors/pt-drop/expire", {"at": "never"})
        r, out = self.fx.get("/api/activity?limit=5")
        self.assertEqual(r.status, 200)
        self.assertEqual([x["action"] for x in out], ["door.expire", "door.extend"])
        self.assertEqual(out[0]["target"], "pt-drop")
        self.assertEqual(out[0]["ip"], "127.0.0.1")
        st = os.stat(os.path.join(self.fx.base, ".audit.jsonl"))
        self.assertEqual(st.st_mode & 0o777, 0o600)


class AuditTests(unittest.TestCase):

    def test_ring_and_no_secrets(self):
        import tempfile
        d = tempfile.mkdtemp()
        log = ps.AuditLog(os.path.join(d, "a.jsonl"), keep=10, compact_at=15)
        for i in range(40):
            log.append("x", f"t{i}", detail="password=hunter2" if i == 39 else "fine")
        recs = log.recent(100)
        self.assertLessEqual(len(recs), 15)
        self.assertEqual(recs[0]["target"], "t39")
        self.assertNotIn("detail", recs[0])          # secret-looking detail dropped
        with open(os.path.join(d, "a.jsonl")) as f:
            self.assertNotIn("hunter2", f.read())
        log.append("y", "multi\nline\x00")
        self.assertEqual(log.recent(1)[0]["target"], "multi line ")


# ---- doors -----------------------------------------------------------------------------

class DoorTests(Base):

    def test_list_shows_guest_url_rules_and_self(self):
        import door_state
        self.door("pt-drop", rules={"guest": "T" * 22, "max_opens": 3,
                                    "password": door_state.hash_password("door-pw-1")}, opens=1)
        self.door("pocket", type="pocket")
        self.door("pk-file-1a2b", type="view", pocket={"name": "pocket", "kind": "inbox",
                                                         "label": "a.pdf"})
        r, out = self.fx.get("/api/doors")
        self.assertEqual(r.status, 200)
        by = {d["name"]: d for d in out["doors"]}
        d = by["pt-drop"]
        self.assertEqual(d["guest_url"], "https://pt-drop.tunnel.cush.rocks/?k=" + "T" * 22)
        self.assertEqual(d["rules"], {"password": True, "guest": True, "max_opens": 3})
        self.assertEqual((d["opens"], d["self"], d["unmanaged"], d["pocket"]), (1, False, False, None))
        self.assertTrue(by["pocket"]["self"])
        self.assertEqual(by["pk-file-1a2b"]["pocket"], {"kind": "inbox", "label": "a.pdf"})
        self.assertNotIn("scrypt", json.dumps(out))
        self.assertNotIn("door-pw-1", json.dumps(out))
        for k in ("url", "expires", "never", "time_remaining", "inspect", "inspect_raw",
                  "capture", "started", "last_open", "type"):
            self.assertIn(k, d)

    def test_extend_expire_never(self):
        self.door(expires=int(time.time()) + 60)
        r, out = self.fx.post("/api/doors/pt-drop/extend", {"seconds": 86400})
        self.assertEqual(r.status, 200)
        self.assertGreater(out["time_remaining"], 86000)
        r, out = self.fx.post("/api/doors/pt-drop/extend", {"seconds": 5})
        self.assertEqual(r.status, 400)
        r, out = self.fx.post("/api/doors/pt-drop/expire", {"at": "never"})
        self.assertEqual((r.status, out["never"]), (200, True))
        r, out = self.fx.post("/api/doors/pt-drop/expire", {"at": "+2h"})
        self.assertEqual((r.status, out["never"]), (200, False))
        r, out = self.fx.post("/api/doors/nope/extend", {})
        self.assertEqual((r.status, out["code"]), (404, "not_found"))
        r, out = self.fx.post("/api/doors/Bad_Name/extend", {})
        self.assertEqual(r.status, 404)            # not a route at all

    def test_stop_and_own_door_refused(self):
        self.door("pt-drop")
        self.door("pocket", type="pocket")
        r, out = self.fx.post("/api/doors/pocket/stop")
        self.assertEqual((r.status, out["code"]), (409, "conflict"))
        self.assertTrue(os.path.exists(os.path.join(self.fx.state_dir, "pocket.json")))
        r, out = self.fx.post("/api/doors/pt-drop/stop")
        self.assertEqual(r.status, 200)
        self.assertFalse(os.path.exists(os.path.join(self.fx.state_dir, "pt-drop.json")))

    def test_stop_all_needs_stepup_and_spares_pocket(self):
        self.door("pt-a")
        self.door("pt-b")
        self.door("pocket", type="pocket")
        self.door("pk2", type="pocket")
        r, out = self.fx.post("/api/doors/stop-all")
        self.assertEqual((r.status, out["code"]), (401, "step_up"))
        tok = self.fx.password_stepup()
        r, out = self.fx.post("/api/doors/stop-all", stepup=tok)
        self.assertEqual(r.status, 200)
        self.assertEqual(sorted(out["stopped"]), ["pt-a", "pt-b"])
        self.assertEqual(sorted(s["name"] for s in out["skipped"]), ["pk2", "pocket"])

    def test_rules_add_without_stepup_remove_needs_it(self):
        import door_state
        self.door("pt-drop", rules={"password": door_state.hash_password("door-pw-1"), "max_opens": 5},
                  proxy={"port": 1, "pid": self.fx.sleepers.pid()})
        with ph.CaptureStderr() as cap:
            r, out = self.fx.post("/api/doors/pt-drop/rules", {"guest": "new", "max_opens": 2})
        self.assertEqual(r.status, 200, out)
        self.assertEqual(out["rules"], {"password": True, "guest": True, "max_opens": 2})
        self.assertTrue(out["guest_url"].startswith("https://pt-drop.tunnel.cush.rocks/?k="))
        self.assertFalse(out["live_switch"])
        r, out = self.fx.post("/api/doors/pt-drop/rules", {"password": "a-new-secret-pw"})
        self.assertEqual(r.status, 200)
        # Widening: remove the password / the limit.
        for body in ({"password": None}, {"max_opens": None}):
            r, out = self.fx.post("/api/doors/pt-drop/rules", body)
            self.assertEqual((r.status, out["code"]), (401, "step_up"), body)
        tok = self.fx.password_stepup()
        r, out = self.fx.post("/api/doors/pt-drop/rules", {"password": None, "max_opens": None},
                              stepup=tok)
        self.assertEqual(r.status, 200)
        self.assertEqual(out["rules"], {"password": False, "guest": True, "max_opens": None})
        self.assertNotIn("a-new-secret-pw", cap.text)
        self.assertNotIn("a-new-secret-pw", open(os.path.join(self.fx.base, ".audit.jsonl")).read())

    def test_rules_validation_and_relaunch_needed(self):
        self.door("pt-drop")                          # no proxy, no tunnel_pid
        r, out = self.fx.post("/api/doors/pt-drop/rules", {"password": "short"})
        self.assertEqual(r.status, 400)
        r, out = self.fx.post("/api/doors/pt-drop/rules", {"guest": True})
        self.assertEqual(r.status, 400)
        r, out = self.fx.post("/api/doors/pt-drop/rules", {})
        self.assertEqual(r.status, 400)
        r, out = self.fx.post("/api/doors/pt-drop/rules", {"max_opens": 3})
        self.assertEqual((r.status, out["code"]), (409, "relaunch_needed"))
        self.assertIn("--max-opens 3", out["command"])
        # The command comes from Pocket's own --history, not data/history.jsonl.
        with open(self.fx.history, "a") as f:
            f.write(json.dumps({"event": "start", "name": "pt-drop", "type": "drop",
                                "cmd": ["/x/bin/drop", "pt-drop", "--bg"],
                                "cwd": "/srv/here"}) + "\n")
        r, out = self.fx.post("/api/doors/pt-drop/rules", {"max_opens": 3})
        self.assertIn("/srv/here", out["command"])
        self.assertIn("/x/bin/drop pt-drop", out["command"])

    def test_launch_with_rules_password_only_in_env(self):
        with ph.CaptureStderr() as cap:
            r, out = self.fx.post("/api/doors/launch", {
                "type": "drop", "name": "pt-new", "expires": "24h",
                "rules": {"password": "door-pass-xyz", "guest": True, "max_opens": 4}})
        self.assertEqual(r.status, 200, out)
        self.assertEqual((out["name"], out["type"]), ("pt-new", "drop"))
        self.assertTrue(out["guest_url"].startswith("https://pt-new.tunnel.cush.rocks/?k="))
        call = self.fx.runner.calls[0]
        self.assertNotIn("door-pass-xyz", " ".join(call["argv"]))
        self.assertEqual(call["env"]["PORCH_DOOR_PASSWORD"], "door-pass-xyz")
        for flag in ("--password", "--guest-link", "--expires", "24h", "--max-opens", "4"):
            self.assertIn(flag, call["argv"])
        self.assertNotIn("door-pass-xyz", cap.text)
        r, out = self.fx.post("/api/doors/launch", {"type": "drop", "name": "pt-new"})
        self.assertEqual(r.status, 409)
        r, out = self.fx.post("/api/doors/launch", {"type": "shell", "name": "pt-x"})
        self.assertEqual(r.status, 400)
        r, out = self.fx.post("/api/doors/launch", {"type": "drop", "name": "pt-y", "expires": "1y"})
        self.assertEqual(r.status, 400)

    def test_launch_failure_and_busy(self):
        self.fx.runner.rc = 1
        r, out = self.fx.post("/api/doors/launch", {"type": "drop", "name": "pt-z"})
        self.assertEqual(r.status, 500)
        self.assertIn("boom", out["message"])
        self.fx.runner.rc = 0
        self.fx.H.launch_lock.acquire()
        try:
            r, out = self.fx.post("/api/doors/launch", {"type": "drop", "name": "pt-z"})
            self.assertEqual((r.status, out["code"]), (409, "conflict"))
        finally:
            self.fx.H.launch_lock.release()

    def test_history_reopen_revive_forget(self):
        with open(self.fx.history, "w") as f:
            for name in ("pt-old", "pt-gone"):
                f.write(json.dumps({"event": "start", "name": name, "type": "drop", "ts": 1,
                                    "started": 1, "cmd": ["bin/drop", name]}) + "\n")
        r, out = self.fx.get("/api/doors/history")
        self.assertEqual(r.status, 200)
        names = {it["name"]: it for it in out}
        self.assertEqual(set(names), {"pt-old", "pt-gone"})
        self.assertEqual(set(names["pt-old"]), {"name", "type", "started", "url", "revivable",
                                                "reopenable", "reopen_why", "closed", "reason"})
        self.assertTrue(names["pt-old"]["revivable"])
        r, out = self.fx.post("/api/doors/history/pt-old/reopen", {"expires": "1h"})
        self.assertEqual(r.status, 200)
        self.assertEqual(self.fx.reopened, [("pt-old", "1h")])
        r, out = self.fx.post("/api/doors/history/pt-old/reopen", {"expires": "2d"})
        self.assertEqual(r.status, 400)
        r, out = self.fx.post("/api/doors/history/pt-old/revive")
        self.assertEqual(r.status, 200, out)
        self.assertEqual(os.path.basename(self.fx.runner.calls[-1]["argv"][0]), "drop")
        r, out = self.fx.post("/api/doors/history/pt-gone/forget")
        self.assertEqual(r.status, 200)
        _, out = self.fx.get("/api/doors/history")
        self.assertNotIn("pt-gone", [it["name"] for it in out])


# ---- inspector ---------------------------------------------------------------------

def write_records(store, n):
    with open(store, "w") as f:
        for i in range(1, n + 1):
            f.write(json.dumps({"id": i, "ts": 1, "method": "POST", "target": f"/hook/{i}",
                                "status": 200, "ms": 3, "req_headers": [["X-A", "1"]],
                                "req_body": {"kind": "text", "text": "hello"}}) + "\n")


class InspectorTests(Base):

    def setUp(self):
        super().setUp()
        self.door("pt-hook", type="hook", inspect={"raw": False})
        self.door("pt-plain")
        import inspect_store
        self.store = inspect_store.store_path("pt-hook", self.fx.inspect_base)
        write_records(self.store, 5)

    def test_list_detail_and_not_inspected(self):
        r, out = self.fx.get("/api/doors/pt-hook/requests")
        self.assertEqual(r.status, 200)
        self.assertEqual([x["id"] for x in out["records"]], [1, 2, 3, 4, 5])
        self.assertEqual(out["last"], 5)
        r, out = self.fx.get("/api/doors/pt-hook/requests?since=3&limit=1")
        self.assertEqual(([x["id"] for x in out["records"]], out["more"]), ([4], True))
        r, out = self.fx.get("/api/doors/pt-hook/requests/2")
        self.assertEqual((r.status, out["record"]["target"]), (200, "/hook/2"))
        r, out = self.fx.get("/api/doors/pt-hook/requests/99")
        self.assertEqual(r.status, 404)
        r, out = self.fx.get("/api/doors/pt-plain/requests")
        self.assertEqual(r.status, 404)

    def test_replay_without_proxy_is_409(self):
        r, out = self.fx.post("/api/doors/pt-hook/requests/1/replay")
        self.assertEqual(r.status, 409)

    def test_events_stream_and_cap(self):
        s = socket.create_connection(("127.0.0.1", self.fx.port), timeout=10)
        s.sendall((f"GET /api/doors/pt-hook/requests/events?since=3 HTTP/1.1\r\n"
                   f"Host: 127.0.0.1:{self.fx.port}\r\nCookie: cush_auth={ph.OWNER_TOKEN}\r\n\r\n"
                   ).encode())
        f = s.makefile("rb")
        buf = b""
        while b"id: 5" not in buf:
            line = f.readline()
            if not line:
                break
            buf += line
        self.assertIn(b"event: request", buf)
        self.assertIn(b"id: 4", buf)
        self.assertNotIn(b"id: 3\n", buf)
        # Two streams at most (its own semaphore): the third is refused.
        s2 = socket.create_connection(("127.0.0.1", self.fx.port), timeout=10)
        s2.sendall((f"GET /api/doors/pt-hook/requests/events HTTP/1.1\r\nHost: x\r\n"
                    f"Cookie: cush_auth={ph.OWNER_TOKEN}\r\n\r\n").encode())
        s2.makefile("rb").readline()
        r, out = self.fx.get("/api/doors/pt-hook/requests/events")
        self.assertEqual((r.status, out["code"]), (429, "rate_limited"))
        # Closing the door ends the stream with `closed`.
        os.unlink(os.path.join(self.fx.state_dir, "pt-hook.json"))
        rest = b""
        while b"event: closed" not in rest:
            line = f.readline()
            if not line:
                break
            rest += line
        self.assertIn(b"event: closed", rest)
        s.close()
        s2.close()


# ---- people + requests ---------------------------------------------------------------

class PeopleTests(Base):

    def test_people_is_rebuilt_from_a_whitelist(self):
        r, out = self.fx.get("/api/people")
        self.assertEqual(r.status, 200)
        self.assertNotIn("LEAK-ME-NOT", json.dumps(out))
        me = next(d for d in out["devices"] if d["id"] == "dev_owner")
        self.assertTrue(me["this"])
        box = next(d for d in out["devices"] if d["id"] == "dev_box")
        self.assertEqual((box["type"], box["tunnel_admin"], box["this"], box["run_ids"]),
                         ("tunnel", False, False, ["r1"]))
        self.assertEqual(out["apps"], [{"host": "music.tunnel.cush.rocks", "protected": True},
                                       {"host": "trendlab.cush.rocks", "protected": False}])
        self.assertEqual(out["invites"][0]["id"], "inv_1")
        # The CLI token went only in its header, from loopback, with no Origin.
        seen = self.fx.auth.seen[-1]
        self.assertEqual(seen["headers"][ "x-cush-cli-token"], ph.AUTH_TOKEN)
        self.assertNotIn("origin", seen["headers"])
        self.assertNotIn("x-forwarded-for", seen["headers"])

    def test_requests(self):
        self.fx.H.reopen_store.ask("pt-old", "Sam", "1.2.3.4", True)
        r, out = self.fx.get("/api/requests")
        self.assertEqual(r.status, 200)
        self.assertEqual(len(out["reopen"]), 1)
        self.assertEqual([p["code"] for p in out["pairings"]], ["ABCD-1234", "WEBB-5678"])
        self.assertEqual(out["pairings"][1]["kind"], "web")
        self.assertEqual(out["accepts"], [])
        self.assertEqual(out["auth"]["state"], "ok")

    def test_auth_down(self):
        self.fx.auth.shutdown()
        self.fx.auth.server_close()
        self.fx.auth = None
        r, out = self.fx.get("/api/people")
        self.assertEqual((r.status, out["code"]), (503, "auth_down"))
        r, out = self.fx.get("/api/requests")
        self.assertEqual((r.status, out["auth"]["state"]), (200, "down"))

    def test_star_routes_need_stepup(self):
        for path, body in (("/api/requests/pairings/ABCD-1234/approve", {}),
                           ("/api/people/devices/dev_box/revoke", {}),
                           ("/api/people/devices/dev_box/role", {"role": "admin"}),
                           ("/api/people/devices/dev_owner2/apps", {"apps": ["a.example.com"]}),
                           ("/api/people/invites", {"apps": ["a.example.com"]}),
                           ("/api/people/apps", {"host": "a.example.com", "action": "protect"}),
                           ("/api/people/password", {"current": "x", "new": "y" * 12}),
                           ("/api/people/invites/inv_1/revoke", {"revoke_devices": True})):
            r, out = self.fx.post(path, body)
            self.assertEqual((r.status, out["code"]), (401, "step_up"), path)
            self.assertEqual(out["methods"], ["password"])
        n = len(self.fx.auth.seen)
        self.assertFalse([s for s in self.fx.auth.seen[:n] if s["path"] != "/auth/admin/state"])

    def test_non_star_people_routes(self):
        r, out = self.fx.post("/api/requests/pairings/ABCD-1234/reject")
        self.assertEqual(r.status, 200)
        r, out = self.fx.post("/api/people/devices/dev_box/rename", {"name": "  build box "})
        self.assertEqual((r.status, out["name"]), (200, "build box"))
        r, out = self.fx.post("/api/people/devices/dev_box/rename", {"name": ""})
        self.assertEqual(r.status, 400)
        r, out = self.fx.post("/api/people/devices/dev_missing/rename", {"name": "x"})
        self.assertEqual((r.status, out["code"]), (404, "not_found"))
        r, out = self.fx.post("/api/people/invites/inv_1/revoke", {"revoke_devices": False})
        self.assertEqual(r.status, 200)
        self.fx.auth.missing.add("/auth/admin/device-rename")
        r, out = self.fx.post("/api/people/devices/dev_box/rename", {"name": "x"})
        self.assertEqual((r.status, out["code"]), (501, "auth_old"))

    def test_approve_tunnel_admin_and_web_scope(self):
        tok = self.fx.password_stepup()
        r, out = self.fx.post("/api/requests/pairings/ABCD-1234/approve", {"tunnel_admin": True},
                              stepup=tok)
        self.assertEqual(r.status, 200, out)
        self.assertEqual((out["kind"], out["tunnel_admin"]), ("tunnel", True))
        paths = [s["path"] for s in self.fx.auth.seen]
        self.assertIn("/auth/admin/device-role", paths)
        role = next(s for s in self.fx.auth.seen if s["path"] == "/auth/admin/device-role")
        self.assertEqual(role["body"], {"device_id": "dev_new", "role": "admin"})
        # Web pairing: apps required; ["*"] needs confirm_all.
        r, out = self.fx.post("/api/requests/pairings/WEBB-5678/approve", {}, stepup=tok)
        self.assertEqual(r.status, 400)
        r, out = self.fx.post("/api/requests/pairings/WEBB-5678/approve", {"apps": ["*"]},
                              stepup=tok)
        self.assertEqual((r.status, out["code"]), (400, "confirm_all"))
        r, out = self.fx.post("/api/requests/pairings/WEBB-5678/approve",
                              {"apps": ["*"], "confirm_all": True}, stepup=tok)
        self.assertEqual(r.status, 200)
        r, out = self.fx.post("/api/requests/pairings/ZZZZ-0000/approve", {}, stepup=tok)
        self.assertEqual(r.status, 404)
        r, out = self.fx.post("/api/requests/pairings/abcd-1234/approve", {}, stepup=tok)
        self.assertEqual(r.status, 404)            # not a route

    def test_revoke_self_needs_confirm(self):
        tok = self.fx.password_stepup()
        r, out = self.fx.post("/api/people/devices/dev_owner/revoke", {}, stepup=tok)
        self.assertEqual((r.status, out["code"]), (400, "confirm_self"))
        r, out = self.fx.post("/api/people/devices/dev_owner/revoke", {"confirm_self": True},
                              stepup=tok)
        self.assertEqual(r.status, 200)
        r, out = self.fx.post("/api/people/devices/dev_box/revoke", {}, stepup=tok)
        self.assertEqual(r.status, 200)

    def test_invite_url_once_never_logged(self):
        tok = self.fx.password_stepup()
        with ph.CaptureStderr() as cap:
            r, out = self.fx.post("/api/people/invites",
                                  {"note": "Sam", "apps": ["trendlab.cush.rocks"],
                                   "expires_hours": 24, "max_uses": 1}, stepup=tok)
        self.assertEqual(r.status, 201, out)
        self.assertEqual(out["url"], self.fx.auth.invite_url)
        self.assertNotIn("LEAK-ME-NOT", json.dumps(out))
        self.assertNotIn("INVITE-SECRET", cap.text)
        with open(os.path.join(self.fx.base, ".audit.jsonl")) as f:
            self.assertNotIn("INVITE-SECRET", f.read())
        _, act = self.fx.get("/api/activity")
        self.assertEqual(act[0]["action"], "invite.create")
        r, out = self.fx.post("/api/people/invites", {"apps": ["*"]}, stepup=tok)
        self.assertEqual(r.status, 400)
        r, out = self.fx.post("/api/people/invites", {"apps": ["a.example.com"],
                                                      "max_uses": "3"}, stepup=tok)
        self.assertEqual(r.status, 400)

    def test_apps_and_password_change(self):
        tok = self.fx.password_stepup()
        r, out = self.fx.post("/api/people/apps", {"host": "Music.tunnel.cush.rocks",
                                                   "action": "unprotect"}, stepup=tok)
        self.assertEqual((r.status, out["host"]), (200, "music.tunnel.cush.rocks"))
        r, out = self.fx.post("/api/people/apps", {"host": "x", "action": "drop"}, stepup=tok)
        self.assertEqual(r.status, 400)
        with ph.CaptureStderr() as cap:
            r, out = self.fx.post("/api/people/password",
                                  {"current": "wrong-wrong-wrong", "new": "n" * 14}, stepup=tok)
            self.assertEqual(r.status, 401)
            r, out = self.fx.post("/api/people/password",
                                  {"current": ph.ADMIN_PASSWORD, "new": "short"}, stepup=tok)
            self.assertEqual(r.status, 400)
            r, out = self.fx.post("/api/people/password",
                                  {"current": ph.ADMIN_PASSWORD, "new": "brand-new-pass-99"},
                                  stepup=tok)
            self.assertEqual(r.status, 200)
        sp = next(s for s in self.fx.auth.seen if s["path"] == "/auth/admin/set-password")
        self.assertEqual(sp["body"], {"new": "brand-new-pass-99"})
        for secret in ("brand-new-pass-99", ph.ADMIN_PASSWORD, "wrong-wrong-wrong", ph.AUTH_TOKEN):
            self.assertNotIn(secret, cap.text)
        with open(os.path.join(self.fx.base, ".audit.jsonl")) as f:
            audit = f.read()
        self.assertIn("password.change", audit)
        self.assertNotIn("brand-new-pass-99", audit)


class PublicPathTests(Base):

    def test_listed_in_people_and_its_own_route(self):
        _, out = self.fx.get("/api/people")
        self.assertEqual([(p["id"], p["path"], p["active"]) for p in out["public_paths"]],
                         [("pp_0000beef", "/s/", True)])
        r, out = self.fx.get("/api/people/public-paths")
        self.assertEqual(r.status, 200)
        self.assertEqual(out["public_paths"][0]["app"], "promo-studio")
        self.assertEqual(out["max"], 100)

    def test_open_and_on_need_stepup_off_and_remove_do_not(self):
        add = {"host": "music.tunnel.cush.rocks", "path": "/hook", "app": "ci", "why": "webhook"}
        for path, body in (("/api/people/public-paths", add),
                           ("/api/people/public-paths/pp_0000beef/on", {})):
            r, out = self.fx.post(path, body)
            self.assertEqual((r.status, out["code"]), (401, "step_up"), path)
        self.assertFalse([s for s in self.fx.auth.seen if s["path"] == "/auth/admin/public-paths"])
        r, out = self.fx.post("/api/people/public-paths/pp_0000beef/off", {})
        self.assertEqual(r.status, 200)
        self.assertEqual((out["entry"]["enabled"], out["entry"]["inactive"]),
                         (False, "switched off"))
        self.assertEqual(self.fx.auth.seen[-1]["body"],
                         {"action": "disable", "id": "pp_0000beef", "by": "pocket"})
        tok = self.fx.password_stepup()
        r, out = self.fx.post("/api/people/public-paths/pp_0000beef/on", {}, stepup=tok)
        self.assertEqual((r.status, out["entry"]["active"]), (200, True))
        r, out = self.fx.post("/api/people/public-paths", add, stepup=tok)
        self.assertEqual(r.status, 201)
        self.assertEqual((out["entry"]["kind"], out["entry"]["created_by"]), ("exact", "pocket"))
        self.assertEqual(out["haproxy"], "ok")
        self.assertNotIn("LEAK-ME-NOT", json.dumps(out))
        self.assertEqual(self.fx.auth.seen[-1]["body"],
                         {"action": "add", "host": "music.tunnel.cush.rocks", "path": "/hook",
                          "app": "ci", "why": "webhook", "by": "pocket"})
        new_id = out["entry"]["id"]
        r, out = self.fx.post(f"/api/people/public-paths/{new_id}/remove", {})
        self.assertEqual((r.status, out["entry"]), (200, None))
        _, act = self.fx.get("/api/activity")
        self.assertEqual([a["action"] for a in act if a["action"].startswith("public.")],
                         ["public.remove", "public.add", "public.on", "public.off"])
        self.assertEqual(act[1]["target"], "music.tunnel.cush.rocks/hook")
        self.assertEqual(act[1]["method"], "password")

    def test_refusals(self):
        tok = self.fx.password_stepup()
        for body in ({"host": "x y", "path": "/s/", "app": "a"},
                     {"host": "a.example.com", "path": "s/", "app": "a"},
                     {"host": "a.example.com", "path": "/s/", "app": ""},
                     {"host": "a.example.com", "path": "/s/", "app": "a", "why": "w" * 121}):
            r, out = self.fx.post("/api/people/public-paths", body, stepup=tok)
            self.assertEqual(r.status, 400, body)
        # cush-auth's own refusal comes back as its message.
        r, out = self.fx.post("/api/people/public-paths",
                              {"host": "a.example.com", "path": "/", "app": "a"}, stepup=tok)
        self.assertEqual(r.status, 400)
        self.assertIn("whole site", out["message"])
        r, out = self.fx.post("/api/people/public-paths/nope_123/off", {})
        self.assertEqual(r.status, 400)
        r, out = self.fx.post("/api/people/public-paths/pp_ffffffff/off", {})
        self.assertEqual((r.status, out["code"]), (404, "not_found"))

    def test_old_cush_auth(self):
        self.fx.auth.missing.add("/auth/admin/public-paths")
        r, out = self.fx.post("/api/people/public-paths/pp_0000beef/off", {})
        self.assertEqual((r.status, out["code"]), (501, "auth_old"))

    def test_home_count(self):
        _, out = self.fx.get("/api/app")
        self.assertEqual(out["counts"]["public_paths"], 0)     # no watcher snapshot yet
        self.fx.H.watcher = ps.AuthWatcher(self.fx.client, clock=self.fx.clock)
        self.fx.H.watcher.poll_once()
        _, out = self.fx.get("/api/app")
        self.assertEqual(out["counts"]["public_paths"], 1)


class PushTopicTests(Base):

    def test_topics(self):
        import porch_push
        if not porch_push.available():
            self.skipTest("python3-cryptography missing")
        store = porch_push.SubStore(os.path.join(self.fx.base, ".push.json"))
        ep = "https://fcm.googleapis.com/fcm/send/abc"
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        pub = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        store.add({"endpoint": ep, "keys": {"p256dh": porch_push.b64u(pub),
                                             "auth": porch_push.b64u(b"\x02" * 16)}}, "Phone")
        r, out = self.fx.post("/api/push/topics", {"endpoint": ep, "topics": ["pairing"]})
        self.assertEqual((r.status, out["topics"]), (200, ["pairing"]))
        r, out = self.fx.post("/api/push/topics", {"id": porch_push.sub_id(ep),
                                                   "topics": ["reopen", "invite"]})
        self.assertEqual((r.status, out["topics"]), (200, ["reopen", "invite"]))
        r, out = self.fx.post("/api/push/topics", {"endpoint": ep, "topics": ["spam"]})
        self.assertEqual(r.status, 400)
        r, out = self.fx.post("/api/push/topics", {"endpoint": ep + "x", "topics": []})
        self.assertEqual(r.status, 404)
        r, out = self.fx.get("/api/push")
        self.assertIsNone(out["this_endpoint_hint"])
        self.assertEqual(out["subscriptions"][0]["topics"], ["reopen", "invite"])


# ---- AuthWatcher ---------------------------------------------------------------------

class FakeClient:
    def __init__(self):
        self.state_value = ph.fake_auth_state()
        self.down = False
        self.missing = set()

    def state(self):
        import auth_client
        if self.down:
            raise auth_client.AuthDown("http://x", "refused")
        return json.loads(json.dumps(self.state_value))

    def request(self, method, path, body=None):
        import auth_client
        if path in self.missing:
            raise auth_client.AuthError(404, "not found")
        raise auth_client.AuthError(400, "JSON body must be an object")


class WatcherTests(unittest.TestCase):

    def setUp(self):
        self.client = FakeClient()
        self.clock = ph.Clock()
        self.pushes, self.bumps, self.logs = [], [], []
        self.w = ps.AuthWatcher(self.client, bump=lambda: self.bumps.append(1),
                                push=lambda p, t: self.pushes.append((t, p)), clock=self.clock,
                                log=self.logs.append)

    def test_first_poll_only_seeds(self):
        self.assertTrue(self.w.poll_once())
        self.assertEqual(self.pushes, [])
        self.assertEqual(len(self.bumps), 1)
        self.assertEqual(self.w.auth_state(), "ok")
        self.assertIn("auth watcher: ok", self.logs)

    def test_new_pairing_pushes_once(self):
        self.w.poll_once()
        self.client.state_value["pairings"].append(
            {"code": "NEWW-0001", "device_name": "laptop", "kind": "tunnel",
             "expires_at": 1, "created_at": 1})
        self.w.poll_once()
        self.assertEqual(len(self.pushes), 1)
        topic, p = self.pushes[0]
        self.assertEqual((topic, p["t"], p["code"], p["kind"]), ("pairing", "pairing", "NEWW-0001",
                                                                 "tunnel"))
        self.w.poll_once()
        self.assertEqual(len(self.pushes), 1)

    def test_invite_use_pushes_and_records_accept(self):
        self.w.poll_once()
        inv = self.client.state_value["invites"][0]
        inv["uses"] = 1
        inv["devices"] = [{"id": "dev_sam", "name": "Sam's Pixel"}]
        self.clock.advance(5)
        self.w.poll_once()
        self.assertEqual(len(self.pushes), 1)
        topic, p = self.pushes[0]
        self.assertEqual((topic, p["t"], p["invite_id"], p["device_name"]),
                         ("invite", "invite", "inv_1", "Sam's Pixel"))
        acc = self.w.recent_accepts()
        self.assertEqual(acc[0]["invite_id"], "inv_1")
        self.assertEqual(acc[0]["at"], int(self.clock()))

    def test_digest_ignores_last_seen(self):
        self.w.poll_once()
        n = len(self.bumps)
        self.client.state_value["devices"][0]["last_seen"] = 999
        self.client.state_value["devices"][1]["run_id_history"] = ["r1", "r2"]
        self.w.poll_once()
        self.assertEqual(len(self.bumps), n)
        self.client.state_value["devices"][1]["name"] = "renamed"
        self.w.poll_once()
        self.assertEqual(len(self.bumps), n + 1)

    def test_down_stale_old(self):
        self.client.down = True
        self.assertFalse(self.w.poll_once())
        self.assertEqual(self.w.auth_state(), "down")
        self.client.down = False
        # First good poll after a failed start still only seeds.
        self.client.state_value["pairings"].append(
            {"code": "LATE-0001", "device_name": "x", "kind": "tunnel", "expires_at": 1,
             "created_at": 1})
        self.w.poll_once()
        self.assertEqual(self.pushes, [])
        self.clock.advance(200)
        self.assertEqual(self.w.auth_state(), "stale")
        self.client.missing.add("/auth/admin/verify-password")
        self.w.probed = None
        self.w.poll_once()
        self.assertEqual(self.w.auth_state(), "old")

    def test_push_failure_never_stops_it(self):
        def boom(p, t):
            raise OSError("no")
        self.w.push = boom
        self.w.poll_once()
        self.client.state_value["pairings"].append(
            {"code": "NEWW-0002", "device_name": "x", "kind": "web", "expires_at": 1,
             "created_at": 1})
        self.assertTrue(self.w.poll_once())


class EventTests(Base):
    watcher = True

    def read_until(self, f, needles, limit=400):
        buf = b""
        for _ in range(limit):
            line = f.readline()
            if not line:
                break
            buf += line
            if all(n in buf for n in needles):
                break
        return buf

    def open_stream(self, cookie=f"cush_auth={ph.OWNER_TOKEN}", extra=""):
        s = socket.create_connection(("127.0.0.1", self.fx.port), timeout=10)
        s.sendall((f"GET /api/events HTTP/1.1\r\nHost: 127.0.0.1:{self.fx.port}\r\n"
                   f"Cookie: {cookie}\r\n{extra}\r\n").encode())
        return s, s.makefile("rb")

    def test_new_events(self):
        self.fx.H.watcher.poll_once()
        self.door("pt-a")
        s, f = self.open_stream()
        buf = self.read_until(f, [b"event: doors", b"event: history", b"event: people",
                                  b"event: stepup"])
        self.assertIn(b"pt-a", buf)
        self.assertIn(b'"pairings"', buf)
        # A new door file -> `doors`.
        self.door("pt-b")
        buf = self.read_until(f, [b"pt-b"])
        self.assertIn(b"event: doors", buf)
        # A step-up -> `stepup` active; ending it -> inactive.
        tok = self.fx.password_stepup()
        buf = self.read_until(f, [b'"active": true'])
        self.assertIn(b"event: stepup", buf)
        self.fx.post("/api/stepup/end", stepup=tok)
        buf = self.read_until(f, [b'"active": false'])
        self.assertIn(b"event: stepup", buf)
        # The watcher's bump -> `people`.
        self.fx.H.watcher.client = FakeClient()
        self.fx.H.watcher.client.state_value["devices"][1]["name"] = "renamed-box"
        self.fx.H.watcher.bump = lambda: self.fx.hub.bump("people")
        self.fx.H.watcher.poll_once()
        buf = self.read_until(f, [b"renamed-box"])
        self.assertIn(b"event: people", buf)
        s.close()

    def test_cli_token_stream_gets_no_control_plane(self):
        s, f = self.open_stream(cookie="x=y", extra=f"{ps.CLI_TOKEN_HEADER}: {ph.CLI_TOKEN}\r\n")
        buf = self.read_until(f, [b"event: requests"])
        buf += self.read_until(f, [b": ping"], limit=20)
        self.assertIn(b"event: clip", buf)
        for ev in (b"event: doors", b"event: people", b"event: history", b"event: stepup"):
            self.assertNotIn(ev, buf)
        s.close()


if __name__ == "__main__":
    unittest.main()

"""Pocket's side of Ask for access (lib/pocket_people.py): the requests list,
Allow (★ step-up) / Deny through the fake cush-auth, the counts, the
watcher's `access` push, and nothing secret passed through."""

import json
import unittest

import pocket_harness as ph
from pocket_harness import ps
from test_pocket_api import FakeClient

RID = "acc0000000000001"


class PocketAccessTests(unittest.TestCase):
    def setUp(self):
        self.fx = ph.PocketFixture().start()

    def tearDown(self):
        self.fx.stop()

    def test_requests_list_whitelists(self):
        r, out = self.fx.get("/api/requests")
        self.assertEqual(r.status, 200)
        a = out["access"][0]
        self.assertEqual((a["id"], a["host"], a["note"], a["kind"], a["state"]),
                         (RID, "trendlab.cush.rocks", "Robin", "stranger", "pending"))
        self.assertNotIn("LEAK-ME-NOT", json.dumps(out))
        self.assertNotIn("invite_url", a)

    def test_counts_include_pending_access(self):
        self.fx.H.watcher = ps.AuthWatcher(self.fx.client, clock=self.fx.clock)
        self.fx.H.watcher.poll_once()
        r, out = self.fx.get("/api/app")
        self.assertEqual(r.status, 200)
        # Two pending pairings + one pending access ask in the fake state.
        self.assertEqual(out["counts"]["requests"], 3)

    def test_allow_needs_stepup_deny_does_not(self):
        r, out = self.fx.post(f"/api/requests/access/{RID}/allow", {})
        self.assertEqual((r.status, out["code"]), (401, "step_up"))
        self.assertFalse([s for s in self.fx.auth.seen if "access" in s["path"]])
        tok = self.fx.password_stepup()
        r, out = self.fx.post(f"/api/requests/access/{RID}/allow", {"device_ttl_minutes": 0},
                              stepup=tok)
        self.assertEqual(r.status, 400)
        r, out = self.fx.post(f"/api/requests/access/{RID}/allow", {"device_ttl_minutes": 1440},
                              stepup=tok)
        self.assertEqual(r.status, 200, out)
        self.assertEqual((out["request"]["state"], out["request"]["how"]), ("approved", "invite"))
        self.assertNotIn("LEAK-ME-NOT", json.dumps(out))
        sent = next(s for s in self.fx.auth.seen if s["path"].endswith("/decide"))
        self.assertEqual(sent["body"], {"id": RID, "decision": "allow",
                                        "device_ttl_minutes": 1440})
        r, out = self.fx.post(f"/api/requests/access/{RID}/allow", {}, stepup=tok)
        self.assertEqual((r.status, out["code"]), (404, "not_found"))
        r, out = self.fx.get("/api/activity")
        self.assertIn("access.allow", json.dumps(out))

    def test_deny_is_a_plain_tap(self):
        r, out = self.fx.post(f"/api/requests/access/{RID}/deny", {})
        self.assertEqual(r.status, 200, out)
        self.assertEqual(out["request"]["state"], "denied")

    def test_old_cush_auth(self):
        self.fx.auth.missing.add("/auth/admin/access-requests/decide")
        r, out = self.fx.post(f"/api/requests/access/{RID}/deny", {})
        self.assertEqual((r.status, out["code"]), (501, "auth_old"))

    def test_owner_only(self):
        for token in (None, ph.GUEST_TOKEN):
            r, _ = self.fx.post(f"/api/requests/access/{RID}/deny", {}, token=token)
            self.assertIn(r.status, (401, 403))


class AccessWatcherTests(unittest.TestCase):
    def setUp(self):
        self.client = FakeClient()
        self.pushes = []
        self.w = ps.AuthWatcher(self.client, bump=lambda: None,
                                push=lambda p, t: self.pushes.append((t, p)),
                                clock=ph.Clock(), log=lambda m: None)

    def test_new_access_ask_pushes_once_on_its_topic(self):
        self.w.poll_once()
        self.assertEqual(self.pushes, [])
        self.client.state_value["access_requests"].append(
            {"id": "acc0000000000002", "host": "grab.cush.rocks", "note": "Kim",
             "kind": "device", "device_id": "dev_k", "device_name": "Kim's Mac",
             "ip": "198.51.100.4", "state": "pending", "created": 1, "until": 2, "waiting": 1})
        self.w.poll_once()
        self.assertEqual(len(self.pushes), 1)
        topic, p = self.pushes[0]
        self.assertEqual((topic, p["t"], p["id"], p["host"]),
                         ("access", "access", "acc0000000000002", "grab.cush.rocks"))
        self.assertIn("Kim on Kim's Mac", p["body"])
        self.w.poll_once()
        self.assertEqual(len(self.pushes), 1)
        # A decided one appearing never pushes.
        self.client.state_value["access_requests"].append(
            {"id": "acc0000000000003", "host": "grab.cush.rocks", "state": "denied"})
        self.w.poll_once()
        self.assertEqual(len(self.pushes), 1)

    def test_access_is_a_push_topic(self):
        import porch_push
        self.assertIn("access", porch_push.TOPICS)
        self.assertEqual(porch_push.clean_topics(["access", "reopen"]), ["reopen", "access"])
        self.assertTrue(porch_push.wants({"topics": None}, "access"))
        self.assertFalse(porch_push.wants({"topics": ["reopen"]}, "access"))


if __name__ == "__main__":
    unittest.main()

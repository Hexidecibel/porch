"""Ask to reopen, end to end: the request store (lib/reopen_requests.py), the
public statusserver endpoints the closed-door page uses (CORS, identical
answers, limits, polling), the owner's decisions in the panel and in Pocket
(owner gate, same-origin, the service worker's Allow buttons, /reopen/<id>,
push subscribe + a test push to a fake push service), and real launchers
(bin/view, bin/seal, bin/paste) closing, keeping or shredding their files and
reopening under the same name with the same guest link.

The launcher tests run a copy of bin/ and lib/ in a temp dir with a fake frpc
and its own state dir, so nothing reaches frps, /tmp/tunnel-state or data/.
"""
import hashlib
import http.client
import importlib.util
import json
import re
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(_HERE)
_LIB = os.path.join(REPO, "lib")
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
import door_recipe  # noqa: E402
import porch_push  # noqa: E402
import reopen_requests as rr  # noqa: E402


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_LIB, f"{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ss = _load("statusserver")
ps = _load("pocketserver")

OWNER = "o" * 64
GUEST = "g" * 64
NOW = 1_800_000_000
TB = "tunnel.cush.rocks"


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def devices_file(path):
    with open(path, "w") as f:
        json.dump({"devices": [
            {"id": "o", "name": "owner", "type": "browser", "role": "admin", "token_sha256": sha(OWNER)},
            {"id": "g", "name": "guest", "type": "browser", "role": "guest", "token_sha256": sha(GUEST)},
        ]}, f)


def http_req(port, method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        try:
            data = json.loads(data)
        except ValueError:
            pass
        return r.status, dict(r.getheaders()), data
    finally:
        c.close()


class StoreTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="porch-reopen-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.store = rr.Store(os.path.join(self.tmp, "requests.json"))

    def test_note_and_host(self):
        self.assertEqual(rr.clean_note("  Sam\x00\n‮  the\tgreat  "), "Sam the great")
        self.assertEqual(len(rr.clean_note("x" * 500)), rr.NOTE_MAX)
        self.assertEqual(rr.clean_note(None), "")
        self.assertEqual(rr.door_for_host("Deck.Tunnel.Cush.Rocks", TB), "deck")
        for bad in ("tunnel.cush.rocks", "a.b.tunnel.cush.rocks", "-x.tunnel.cush.rocks",
                    "x.tunnel.cush.rocks.evil", "x_y.tunnel.cush.rocks", "", None):
            self.assertIsNone(rr.door_for_host(bad, TB), bad)

    def test_ask_join_status(self):
        rid, tok, rec, joined = self.store.ask("deck", "Sam", "1.2.3.4", True, now=NOW)
        self.assertFalse(joined)
        self.assertEqual(self.store.status(rid, tok, now=NOW + 10), "pending")
        rid2, tok2, _, joined2 = self.store.ask("deck", "Kim", "5.6.7.8", True, now=NOW + 20)
        self.assertEqual((rid2, joined2), (rid, True))           # one pending per door
        self.assertEqual(self.store.status(rid, tok2, now=NOW + 20), "pending")
        self.assertIsNone(self.store.status(rid, "x" * 32, now=NOW))   # wrong token = unknown
        self.assertIsNone(self.store.status("A" * 16, tok, now=NOW))
        self.assertEqual(self.store.status(rid, tok, now=NOW + rr.TTL + 1), "expired")
        self.assertIsNone(self.store.status(rid, tok, now=NOW + rr.TTL + rr.KEEP + 2))  # pruned
        with open(self.store.path) as fh:
            raw = fh.read()
        self.assertNotIn(tok, raw)                              # only hashes are kept
        self.assertEqual(os.stat(self.store.path).st_mode & 0o777, 0o600)

    def test_caps(self):
        for i in range(rr.MAX_TOKENS - 1):
            self.store.ask("deck", "", "ip", True, now=NOW)
        self.store.ask("deck", "", "ip", True, now=NOW)
        with self.assertRaises(rr.Refused):
            self.store.ask("deck", "", "ip", True, now=NOW)
        for i in range(rr.MAX_PENDING - 1):
            self.store.ask(f"d{i}", "", "ip", i % 2 == 0, now=NOW)
        with self.assertRaises(rr.Refused) as cm:
            self.store.ask("one-more", "", "ip", False, now=NOW)
        self.assertEqual(cm.exception.status, 503)

    def test_decide(self):
        rid, tok, _, _ = self.store.ask("deck", "Sam", "ip", True, now=NOW)
        fid, ftok, _, _ = self.store.ask("fake", "", "ip", False, now=NOW)
        with self.assertRaises(LookupError):                    # dummies can't be decided
            self.store.decide(fid, "allow", "1h", now=NOW)
        with self.assertRaises(ValueError):
            self.store.decide(rid, "allow", "7d", now=NOW)
        with self.assertRaises(ValueError):
            self.store.decide(rid, "maybe", now=NOW)

        def boom(name, exp):
            raise RuntimeError("frpc down")
        with self.assertRaisesRegex(RuntimeError, "frpc down"):
            self.store.decide(rid, "allow", "1h", boom, now=NOW)
        self.assertEqual(self.store.status(rid, tok, now=NOW), "pending")   # back to waiting
        calls = []
        rec = self.store.decide(rid, "allow", "24h", lambda n, e: calls.append((n, e)), now=NOW)
        self.assertEqual((rec["state"], rec["expires"], calls), ("approved", "24h", [("deck", "24h")]))
        self.assertEqual(self.store.status(rid, tok, now=NOW), "approved")
        with self.assertRaises(LookupError):
            self.store.decide(rid, "deny", now=NOW)
        self.assertEqual([r["name"] for r in self.store.pending(now=NOW)], [])
        self.assertEqual([r["name"] for r in self.store.recent(now=NOW)], ["deck"])

    def test_push_payload(self):
        _, _, rec, _ = self.store.ask("deck", "Sam", "1.2.3.4", True,
                                      {"closed": NOW - 7200, "reason": "expired"}, now=NOW)
        p = rr.push_payload(rec, now=NOW)
        self.assertEqual(p["title"], 'Reopen "deck"?')
        self.assertIn("From Sam.", p["body"])
        self.assertIn("expired 2 h ago", p["body"])
        self.assertIn("1.2.3.4", p["body"])
        self.assertEqual(p["url"], f"/reopen/{rec['id']}")


class StatusIntakeTests(unittest.TestCase):
    """The public endpoints statusserver serves to the closed-door page."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="porch-intake-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        d = Path(self.tmp)
        (d / "state").mkdir()
        devices_file(d / "devices.json")
        ss.porch_auth.reset_cache()
        self.doors = str(d / "doors")
        self.pushed, self.reopened = [], []
        test = self
        env = mock.patch.dict(os.environ, {"PORCH_DOORS_DIR": self.doors, "HOME": self.tmp})
        env.start()
        self.addCleanup(env.stop)

        class H(ss.StatusHandler):
            state_dir = d / "state"
            devices_path = str(d / "devices.json")
            history_path = str(d / "history.jsonl")
            doors_dir = test.doors
            reopen_store = rr.Store(str(d / "requests.json"))
            reopen_limit = rr.RateLimit(*rr.PER_IP)
            notifier = staticmethod(lambda rec, root: test.pushed.append(rec))

            @staticmethod
            def reopener(name, exp):
                test.reopened.append((name, exp))

            def log_message(self, *a):
                pass
        self.H = H
        self.httpd = ss.StatusServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        # a reopenable door: a closed drop with a recipe
        door_recipe.write("deck", "drop", 999999, {"expires": None, "rules": {}})
        door_recipe.mark_closed("deck", "expired")

    def ask(self, host="deck.tunnel.cush.rocks", note="Sam", origin=None, xff="203.0.113.5", raw=None):
        h = {"Content-Type": "text/plain;charset=UTF-8", "X-Forwarded-For": xff,
             "Origin": origin if origin is not None else f"https://{host}"}
        body = raw if raw is not None else json.dumps({"host": host, "note": note})
        return http_req(self.port, "POST", "/api/reopen-requests", body, h)

    def owner(self, method, path, body=None):
        h = {"Cookie": f"cush_auth={OWNER}", "X-CSRF-Token": ss.csrf_token_for(OWNER)}
        return http_req(self.port, method, path, json.dumps(body) if body is not None else None, h)

    def test_ask_answers_and_cors(self):
        st, hdr, data = self.ask()
        self.assertEqual(st, 201)
        self.assertEqual(set(data), {"id", "token", "poll"})
        self.assertEqual(hdr["Access-Control-Allow-Origin"], "https://deck.tunnel.cush.rocks")
        self.assertNotIn("Access-Control-Allow-Credentials", hdr)
        self.assertEqual(hdr["Vary"], "Origin")
        for _ in range(50):
            if self.pushed:
                break
            time.sleep(0.02)
        self.assertEqual([r["name"] for r in self.pushed], ["deck"])
        self.assertEqual(self.pushed[0]["ip"], "203.0.113.5")
        self.assertEqual(self.pushed[0]["note"], "Sam")

    def test_identical_answer_for_any_door(self):
        a = self.ask(xff="198.51.100.1")
        b = self.ask(host="no-such-door.tunnel.cush.rocks", xff="198.51.100.2")
        self.assertEqual((a[0], sorted(a[2])), (b[0], sorted(b[2])))
        self.assertEqual(len(a[2]["token"]), len(b[2]["token"]))
        self.assertEqual(len(a[2]["id"]), len(b[2]["id"]))
        time.sleep(0.1)
        self.assertEqual([r["name"] for r in self.pushed], ["deck"])   # nobody hears of the fake one
        st, _, poll = http_req(self.port, "GET", f"/api/reopen-requests/{b[2]['id']}?t={b[2]['token']}")
        self.assertEqual((st, poll["state"]), (200, "pending"))
        # the owner sees only the real one
        st, _, lst = self.owner("GET", "/api/reopen-requests")
        self.assertEqual([r["name"] for r in lst], ["deck"])
        self.assertEqual(lst[0]["note"], "Sam")
        self.assertNotIn("tokens", lst[0])

    def test_refusals(self):
        self.assertEqual(self.ask(origin="https://evil.example")[0], 403)
        self.assertEqual(self.ask(origin="https://other.tunnel.cush.rocks")[0], 403)
        self.assertEqual(self.ask(origin="")[0], 403)
        self.assertEqual(self.ask(host="tunnel.cush.rocks")[0], 400)
        self.assertEqual(self.ask(host="a.b.tunnel.cush.rocks")[0], 400)
        self.assertEqual(self.ask(raw="not json")[0], 400)
        self.assertEqual(self.ask(raw=json.dumps({"host": "deck.tunnel.cush.rocks",
                                                  "note": "x" * 2000}))[0], 413)
        st, hdr, _ = self.ask(origin="https://evil.example")
        self.assertNotIn("Access-Control-Allow-Origin", hdr)

    def test_rate_limit_per_client(self):
        for i in range(rr.PER_IP[0]):
            self.assertEqual(self.ask(host=f"d{i}.tunnel.cush.rocks", xff="192.0.2.9")[0], 201)
        self.assertEqual(self.ask(xff="192.0.2.9")[0], 429)
        # a forged left-most hop doesn't help (the right-most non-loopback one counts)
        self.assertEqual(self.ask(xff="10.9.9.9, 192.0.2.9")[0], 429)
        self.assertEqual(self.ask(xff="192.0.2.10")[0], 201)

    def test_note_sanitised(self):
        self.ask(note="<b>Sam</b>\u0007\n" + "y" * 80)
        rec = self.owner("GET", "/api/reopen-requests")[2][0]
        self.assertEqual(rec["note"], ("<b>Sam</b> " + "y" * 80)[:40])

    def test_preflight(self):
        st, hdr, _ = http_req(self.port, "OPTIONS", "/api/reopen-requests",
                              headers={"Origin": "https://deck.tunnel.cush.rocks"})
        self.assertEqual((st, hdr["Access-Control-Allow-Origin"]), (204, "https://deck.tunnel.cush.rocks"))
        for evil in ("https://deck.tunnel.cush.rocks:8443", "http://deck.tunnel.cush.rocks",
                     "https://tunnel.cush.rocks", "https://DECK.tunnel.cush.rocks", "null"):
            st, hdr, _ = http_req(self.port, "OPTIONS", "/api/reopen-requests", headers={"Origin": evil})
            self.assertNotIn("Access-Control-Allow-Origin", hdr, evil)

    def test_poll_and_decide_in_the_panel(self):
        _, _, a = self.ask()
        q = f"/api/reopen-requests/{a['id']}?t={a['token']}"
        self.assertEqual(http_req(self.port, "GET", q)[2]["state"], "pending")
        self.assertEqual(http_req(self.port, "GET", q.replace("t=", "t=x"))[0], 404)
        self.assertEqual(http_req(self.port, "GET", f"/api/reopen-requests/{a['id']}")[0], 404)
        # decide needs the owner and CSRF
        st, _, _ = http_req(self.port, "POST", f"/api/reopen-requests/{a['id']}/decide",
                            json.dumps({"decision": "allow", "expires": "1h"}),
                            {"Cookie": f"cush_auth={GUEST}", "X-CSRF-Token": ss.csrf_token_for(GUEST)})
        self.assertEqual(st, 403)
        st, _, _ = http_req(self.port, "POST", f"/api/reopen-requests/{a['id']}/decide",
                            json.dumps({"decision": "allow", "expires": "1h"}),
                            {"Cookie": f"cush_auth={OWNER}"})
        self.assertEqual(st, 403)
        st, _, out = self.owner("POST", f"/api/reopen-requests/{a['id']}/decide",
                                {"decision": "allow", "expires": "1h"})
        self.assertEqual((st, out["request"]["state"]), (200, "approved"))
        self.assertEqual(self.reopened, [("deck", "1h")])
        self.assertEqual(http_req(self.port, "GET", q)[2]["state"], "approved")
        self.assertEqual(self.owner("POST", f"/api/reopen-requests/{a['id']}/decide",
                                    {"decision": "deny"})[0], 409)

    def test_deny(self):
        _, _, a = self.ask()
        self.owner("POST", f"/api/reopen-requests/{a['id']}/decide", {"decision": "deny"})
        st, _, p = http_req(self.port, "GET", f"/api/reopen-requests/{a['id']}?t={a['token']}")
        self.assertEqual(p["state"], "denied")
        self.assertEqual(self.reopened, [])

    def test_history_offers_reopen(self):
        with open(self.H.history_path, "w") as f:
            for n, t in (("deck", "drop"), ("old", "exchange")):
                f.write(json.dumps({"event": "start", "name": n, "type": t, "started": NOW,
                                    "ts": NOW, "cmd": [], "port": 1}) + "\n")
        ss._history_cache["key"] = None
        st, _, items = self.owner("GET", "/api/history")
        by = {i["name"]: i for i in items}
        self.assertTrue(by["deck"]["reopenable"])
        self.assertEqual(by["deck"]["reason"], "expired")
        self.assertFalse(by["old"]["reopenable"])
        st, _, out = self.owner("POST", "/api/history/deck/reopen", {"expires": "24h"})
        self.assertEqual((st, self.reopened), (200, [("deck", "24h")]))
        self.assertEqual(self.owner("POST", "/api/history/deck/reopen", {"expires": "7d"})[0], 400)


class PocketReopenTests(unittest.TestCase):
    """Pocket's side: the Requests list, decisions, /reopen/<id>, push."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="porch-pkreopen-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        base = os.path.join(self.tmp, "pocket")
        os.makedirs(os.path.join(base, "inbox"))
        dev = os.path.join(self.tmp, "devices.json")
        devices_file(dev)
        ps.porch_auth.reset_cache()
        self.store = rr.Store(os.path.join(self.tmp, "requests.json"))
        self.reopened = []
        test = self

        def reopener(name, exp):
            if name == "broken":
                raise RuntimeError("broken did not reopen: the file is gone")
            test.reopened.append((name, exp))
        self.H = type("H", (ps.PocketHandler,), dict(
            base_dir=ps.Path(base), inbox_dir=ps.Path(base, "inbox"), devices_path=dev,
            store=ps.ClipStore(os.path.join(base, ".clip.json")), hub=ps.Hub(), min_free=0,
            reopen_store=self.store, reopener=staticmethod(reopener),
            push_claim="https://tunnel.cush.rocks/", state_dir=os.path.join(self.tmp, "state")))
        self.server = ps.BoundedThreadingHTTPServer(("127.0.0.1", 0), self.H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.rid, self.tok, _, _ = self.store.ask("deck", "Sam", "203.0.113.5", True,
                                                  {"type": "view", "closed": int(time.time()) - 60,
                                                   "reason": "expired"})

    def req(self, method, path, body=None, cookie=OWNER, origin=True, headers=None):
        h = dict(headers or {})
        if cookie:
            h["Cookie"] = f"cush_auth={cookie}"
        if origin:
            h["Origin"] = f"http://127.0.0.1:{self.port}"
        if body is not None:
            h["Content-Type"] = "application/json"
            body = json.dumps(body)
        return http_req(self.port, method, path, body, h)

    def test_listing_is_the_owners(self):
        st, _, lst = self.req("GET", "/api/reopen")
        self.assertEqual((st, [r["name"] for r in lst]), (200, ["deck"]))
        self.assertEqual(self.req("GET", "/api/reopen", cookie=GUEST)[0], 403)
        self.assertEqual(self.req("GET", "/api/reopen", cookie=None)[0], 403)

    def test_decide_gates(self):
        allow = {"decision": "allow", "expires": "1h"}
        self.assertEqual(self.req("POST", f"/api/reopen/{self.rid}", allow, cookie=GUEST)[0], 403)
        self.assertEqual(self.req("POST", f"/api/reopen/{self.rid}", allow, origin=False)[0], 403)
        self.assertEqual(self.req("POST", f"/api/reopen/{self.rid}", allow,
                                  headers={"Origin": "https://evil.example"}, origin=False)[0], 403)
        self.assertEqual(self.reopened, [])
        self.assertEqual(self.req("POST", f"/api/reopen/{self.rid}", {"decision": "allow",
                                                                      "expires": "1y"})[0], 400)
        self.assertEqual(self.req("POST", "/api/reopen/short", allow)[0], 400)

    def test_service_worker_action_path(self):
        # What the SW's Allow 1h button sends: same-origin POST, cookie,
        # Referer = the SW script (Origin as Chrome sends it).
        st, _, out = self.req("POST", f"/api/reopen/{self.rid}", {"decision": "allow", "expires": "1h"},
                              headers={"Referer": f"http://127.0.0.1:{self.port}/sw.js"})
        self.assertEqual((st, out["request"]["state"]), (200, "approved"))
        self.assertTrue(out["url"].startswith("https://deck."))
        self.assertEqual(self.reopened, [("deck", "1h")])
        self.assertEqual(self.store.status(self.rid, self.tok), "approved")
        self.assertEqual(self.req("POST", f"/api/reopen/{self.rid}", {"decision": "deny"})[0], 409)
        _, _, sw = http_req(self.port, "GET", "/sw.js")
        sw = sw.decode() if isinstance(sw, bytes) else sw
        for needle in ("addEventListener('push'", "addEventListener('notificationclick'",
                       "'allow-1h'", "'allow-24h'", "'/api/reopen/' + d.id", "credentials: 'same-origin'",
                       "openWindow", "'/reopen/' + d.id"):
            self.assertIn(needle, sw)

    def test_failed_reopen_keeps_it_pending(self):
        rid, tok, _, _ = self.store.ask("broken", "", "ip", True)
        st, _, out = self.req("POST", f"/api/reopen/{rid}", {"decision": "allow", "expires": "24h"})
        self.assertEqual(st, 502)
        self.assertIn("file is gone", out["message"])
        self.assertEqual(self.store.status(rid, tok), "pending")

    def test_reopen_page(self):
        st, hdr, page = self.req("GET", f"/reopen/{self.rid}", origin=False)
        page = page.decode()
        self.assertEqual(st, 200)
        self.assertIn("default-src 'none'", hdr["Content-Security-Policy"])
        for t in ("Allow 1 hour", "Allow 24 hours", "Deny", '"name": "deck"', '"note": "Sam"'):
            self.assertIn(t, page)
        self.assertNotIn("innerHTML", page)
        st, _, page = self.req("GET", f"/reopen/{self.rid}", cookie=GUEST, origin=False)
        self.assertEqual(st, 403)
        self.assertNotIn(b"Sam", page)
        self.assertEqual(self.req("GET", "/reopen/AAAAAAAAAAAAAAAA", origin=False)[0], 404)
        # a note can't break out of the JSON block
        rid, _, _, _ = self.store.ask("x", "</script><img src=x onerror=1>", "ip", True)
        page = self.req("GET", f"/reopen/{rid}", origin=False)[2].decode()
        self.assertNotIn("</script><img", page)

    def test_main_page_has_the_cards(self):
        # The Porch app: Home's "Waiting on you" cards answer asks inline,
        # You > Notifications has the switch and the test; both live in the
        # page's hashed scripts.
        page = self.req("GET", "/", origin=False)[2].decode()
        import pocket_assets
        bundle = "\n".join([page] + [
            pocket_assets.lookup(u)[0].decode() for u in
            re.findall(r'src="(/static/[^"]+)"', page) if pocket_assets.lookup(u)])
        for t in ("Waiting on you", "'/api/reopen/'", "role', 'switch'", "Send a test",
                  "Add to Home Screen", "/api/push/subscribe", "requestPermission",
                  "P.on('requests'"):
            self.assertIn(t, bundle)

    @unittest.skipUnless(porch_push.available(), "python3-cryptography is not installed")
    def test_push_subscribe_and_test(self):
        from test_porch_push import FakePushService, browser
        b = browser()
        svc = FakePushService({"/sub/p": b[:2]})
        self.addCleanup(svc.close)
        porch_push.allow_test_endpoint(f"http://127.0.0.1:{svc.port}/")
        self.addCleanup(porch_push._test_prefixes.clear)
        st, _, info = self.req("GET", "/api/push")
        self.assertTrue(info["supported"])
        self.assertEqual(len(porch_push.unb64u(info["public_key"])), 65)
        sub = dict(b[2], endpoint=f"http://127.0.0.1:{svc.port}/sub/p")
        self.assertEqual(self.req("POST", "/api/push/subscribe", {"subscription": sub}, cookie=GUEST)[0], 403)
        self.assertEqual(self.req("POST", "/api/push/subscribe", {"subscription": sub}, origin=False)[0], 403)
        bad = dict(sub, endpoint="https://evil.example/x")
        self.assertEqual(self.req("POST", "/api/push/subscribe", {"subscription": bad})[0], 400)
        st, _, out = self.req("POST", "/api/push/subscribe", {"subscription": sub})
        self.assertEqual((st, len(out["subscriptions"])), (200, 1))
        st, _, out = self.req("POST", "/api/push/test", {})
        self.assertEqual((st, out["sent"]), (200, 1))
        self.assertEqual(svc.got[0]["payload"]["t"], "test")
        self.assertEqual(svc.got[0]["k"], porch_push.unb64u(info["public_key"]))
        # statusserver's fan-out reaches the same subscription
        out = porch_push.notify_all(rr.push_payload(self.store.get(self.rid) | {"id": self.rid}),
                                    "https://tunnel.cush.rocks/", root=self.tmp)
        self.assertEqual(out["sent"], 1)
        self.assertEqual(svc.got[1]["payload"]["title"], 'Reopen "deck"?')
        self.req("POST", "/api/push/unsubscribe", {"endpoint": sub["endpoint"]})
        self.assertEqual(self.req("GET", "/api/push")[2]["subscriptions"], [])


# ---- real launchers in a sandboxed copy of the repo ------------------------------

# Stands in for frpc: stays up and connects nowhere, with argv[0] ending in
# frpc and the config path in its argv, like the real one (door_state's stop
# path matches exactly that).
FAKE_FRPC = ("#!/bin/bash\n"
             "exec -a \"$0\" python3 -c 'import time; time.sleep(10 ** 6)' \"$@\"\n")


class LauncherFlowTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="porch-reopen-e2e-")
        cls.repo = os.path.join(cls.tmp, "repo")
        os.makedirs(os.path.join(cls.repo, "data"))
        os.makedirs(os.path.join(cls.repo, "logs"))
        shutil.copytree(os.path.join(REPO, "lib"), os.path.join(cls.repo, "lib"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        os.makedirs(os.path.join(cls.repo, "bin"))
        for b in ("tunnel", "view", "seal", "paste", "status", "porch"):
            shutil.copy2(os.path.join(REPO, "bin", b), os.path.join(cls.repo, "bin", b))
        with open(os.path.join(cls.repo, "bin", "frpc"), "w") as f:
            f.write(FAKE_FRPC)
        os.chmod(os.path.join(cls.repo, "bin", "frpc"), 0o755)
        cls.state = os.path.join(cls.tmp, "state")
        for rel, old, new in (("lib/tunnel-state.sh", 'TUNNEL_STATE_DIR="/tmp/tunnel-state"',
                               f'TUNNEL_STATE_DIR="{cls.state}"'),
                              ("bin/status", 'TUNNEL_STATE_DIR="/tmp/tunnel-state"',
                               f'TUNNEL_STATE_DIR="{cls.state}"'),
                              ("lib/door_state.py", "STATE_DIR = '/tmp/tunnel-state'",
                               f"STATE_DIR = '{cls.state}'")):
            p = os.path.join(cls.repo, rel)
            with open(p) as fh:
                src = fh.read()
            assert old in src, rel
            with open(p, "w") as f:
                f.write(src.replace(old, new))
        run = os.path.join(cls.tmp, "run")
        os.mkdir(run, 0o700)
        cls.doors = os.path.join(cls.tmp, "doors")
        cls.env = {k: v for k, v in os.environ.items()
                   if not k.startswith(("PORCH_", "_CUSH", "CUSH_", "_PORCH")) and k != "TUNNEL_NO_STATE"}
        cls.env.update(PORCH_CONFIG="none", XDG_RUNTIME_DIR=run, HOME=cls.tmp,
                       PORCH_DOORS_DIR=cls.doors, PORCH_HISTORY_FILE=os.path.join(cls.tmp, "h.jsonl"),
                       PORCH_HOME_TOKEN_FILE=os.path.join(cls.tmp, "none"))
        cls.share = os.path.join(run, "porch", "share")
        os.makedirs(cls.share, 0o700)
        os.chmod(os.path.join(run, "porch"), 0o700)

    @classmethod
    def tearDownClass(cls):
        for fn in os.listdir(cls.state) if os.path.isdir(cls.state) else []:
            if fn.endswith(".json"):
                cls._close(fn[:-5])
        # Watchdog subshells sleep up to 30s before noticing their door is
        # gone: end everything that runs from this sandbox now.
        for pid in os.listdir("/proc"):
            if not pid.isdigit() or int(pid) == os.getpid():
                continue
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    if cls.tmp.encode() in f.read():
                        os.kill(int(pid), signal.SIGTERM)
            except OSError:
                pass
        shutil.rmtree(cls.tmp, True)

    @classmethod
    def _close(cls, name):
        subprocess.run([os.path.join(cls.repo, "bin", "status"), "close", name], env=cls.env,
                       capture_output=True, timeout=60)

    def run_bin(self, *argv, env=None):
        e = dict(self.env, **(env or {}))
        r = subprocess.run([os.path.join(self.repo, "bin", argv[0]), *argv[1:]], env=e,
                           capture_output=True, text=True, timeout=90, stdin=subprocess.DEVNULL)
        if r.returncode == 0 and argv[0] in ("view", "paste", "porch"):
            self.wait_up(argv[3] if argv[0] == "porch" else argv[2 if argv[0] == "view" else 1])
        return r

    def wait_up(self, name, t=30):
        """The launcher returns once the state file is there; its bin/tunnel
        starts frpc a moment later. Closing before that would leave it up."""
        import door_state
        end = time.time() + t
        while time.time() < end and not door_state.frpc_pids_for(name):
            time.sleep(0.2)

    def recipe(self, name):
        with mock.patch.dict(os.environ, {"PORCH_DOORS_DIR": self.doors}):
            return door_recipe.load(name)

    def state_of(self, name):
        try:
            with open(os.path.join(self.state, f"{name}.json")) as f:
                return json.load(f)
        except OSError:
            return None

    def wait_gone(self, pid, t=30):
        end = time.time() + t
        while time.time() < end:
            try:
                os.kill(pid, 0)
            except OSError:
                return True
            time.sleep(0.2)
        return False

    def close_and_wait(self, name):
        pid = self.state_of(name)["pid"]
        self._close(name)
        self.assertTrue(self.wait_gone(pid), f"{name} launcher did not exit")
        time.sleep(0.3)

    def stop(self, name, reason):
        import door_state
        pid = self.state_of(name)["pid"]
        with mock.patch.dict(os.environ, {"PORCH_DOORS_DIR": self.doors,
                                          "XDG_RUNTIME_DIR": self.env["XDG_RUNTIME_DIR"]}):
            door_state.stop_door(name, self.state, reason)
        gone = self.wait_gone(pid)
        if not gone:
            print(subprocess.run(["ps", "-eo", "pid,pgid,ppid,stat,args"], capture_output=True,
                                 text=True).stdout, file=sys.stderr)
        self.assertTrue(gone, f"{name} launcher did not exit")

    def test_view_closed_keeps_file_and_reopens_with_the_same_guest_link(self):
        f = os.path.join(self.share, "stdin-note")
        with open(f, "w") as fh:
            fh.write("# hello\n")
        r = self.run_bin("view", f, "rv-note", "--owned-file", "--guest-link", "--expires", "30m", "--bg")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        st = self.state_of("rv-note")
        guest = st["rules"]["guest"]
        rec = self.recipe("rv-note")
        self.assertEqual((rec["type"], rec["inputs"]["owned"], rec["rules"]["guest"]),
                         ("view", [os.path.realpath(f)], guest))
        with open(os.path.join(self.state, ".rv-note.secret")) as fh:
            self.assertEqual(fh.read(), rec["secret"])
        self.close_and_wait("rv-note")
        rec = self.recipe("rv-note")
        self.assertEqual(rec["reason"], "closed")
        self.assertTrue(os.path.exists(f), "an owner-closed door keeps its file")
        # reopen from the recipe (as porch door reopen / Pocket do)
        r = self.run_bin("porch", "door", "reopen", "rv-note", "--expires", "24h")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        st2 = self.state_of("rv-note")
        self.assertNotEqual(st2["pid"], st["pid"])
        self.assertEqual(st2["rules"]["guest"], guest)
        self.assertEqual(st2["opens"], 0)
        self.assertGreater(st2["expires"] - time.time(), 23 * 3600)
        rec2 = self.recipe("rv-note")
        self.assertEqual((rec2["secret"], rec2["reopens"], rec2["reason"]), (rec["secret"], 1, None))
        self.assertIn("guest link:", r.stdout)
        # used up (the door proxy's closer): shredded at once, and it stays closed
        self.stop("rv-note", "used-up")
        self.assertFalse(os.path.exists(f), "a used-up door's file is shredded")
        self.assertIsNone(self.recipe("rv-note"))
        r = self.run_bin("porch", "door", "reopen", "rv-note")
        self.assertEqual(r.returncode, 3)

    def test_paste_and_rule_flags_with_reopen(self):
        r = subprocess.run([os.path.join(self.repo, "bin", "paste"), "rv-paste", "--bg"],
                           input="some text\n", env=self.env, capture_output=True, text=True, timeout=90)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.wait_up("rv-paste")
        rec = self.recipe("rv-paste")
        captured = rec["inputs"]["path"]
        self.assertEqual(rec["inputs"]["owned"], [captured])
        self.close_and_wait("rv-paste")
        self.assertTrue(os.path.exists(captured))
        # --reopen takes the recipe's rules: a rule flag next to it is refused
        r = self.run_bin("paste", "rv-paste", captured, "--reopen", "--burn", "--bg")
        self.assertEqual(r.returncode, 2)
        self.assertIn("only --expires", r.stderr)
        r = self.run_bin("porch", "door", "reopen", "rv-paste")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        # the reopened paste owns its capture again; burned = gone
        self.stop("rv-paste", "burned")
        self.assertFalse(os.path.exists(captured))

    def test_no_recipe_means_no_reopen(self):
        r = self.run_bin("view", "/etc/hostname", "rv-x", "--reopen", "--bg")
        self.assertEqual(r.returncode, 2)
        self.assertIn("no launch recipe", r.stderr)


if __name__ == "__main__":
    unittest.main()

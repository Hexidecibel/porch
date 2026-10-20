"""Gate pages (lib/gate_pages.py) and Ask for access (lib/access_requests.py)
on the auth server: page per cookie state, the public ask/poll endpoints and
their limits, the owner's decide (device grant + stranger invite)."""

import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import access_requests  # noqa: E402
from test_authserver import AUTH, GRAB, TREND, PassCase, authserver  # noqa: E402


def view_of(html):
    m = re.search(r'var V = (\{.*?\});\n', html)
    return json.loads(m.group(1)) if m else None


class GateCase(PassCase):
    def setUp(self):
        super().setUp()
        saved = (authserver.ACCESS, authserver.ACCESS_LIMIT)
        self.addCleanup(lambda: setattr(authserver, "ACCESS", saved[0])
                        or setattr(authserver, "ACCESS_LIMIT", saved[1]))
        authserver.ACCESS = access_requests.Store(clock=self.clock.time)
        authserver.ACCESS_LIMIT = access_requests.RateLimit(
            *access_requests.PER_IP, clock=self.clock.time)

    def mint(self, apps=None, name="Sam's phone", expires_at=None, role="guest"):
        handler = authserver.AuthHandler.__new__(authserver.AuthHandler)
        with authserver.STATE_LOCK:
            dev, cookie = handler._mint_browser_device_locked(
                name, apps or [TREND], role, expires_at)
        return dev, cookie

    def page(self, path, cookie=None, host=AUTH):
        import http.client
        hdrs = {"Host": host}
        if cookie:
            hdrs["Cookie"] = f"cush_auth={cookie}"
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("GET", path, headers=hdrs)
            r = conn.getresponse()
            return r.status, r.read().decode("utf-8"), {k.lower(): v for k, v in r.getheaders()}
        finally:
            conn.close()

    def login(self, rd, cookie=None, extra=""):
        return self.page("/login?rd=" + authserver.quote(rd, safe="") + extra, cookie)

    def ask(self, host=GRAB, note="", cookie=None, ip="203.0.113.5", origin=None, body=None,
            req_host=AUTH):
        hdrs = {"Host": req_host, "X-Forwarded-For": ip}
        if cookie:
            hdrs["Cookie"] = f"cush_auth={cookie}"
        if origin:
            hdrs["Origin"] = origin
        payload = body if body is not None else {"host": host, "note": note,
                                                 "rd": f"https://{host}/inbox"}
        return self.req("POST", "/auth/access-requests", payload, hdrs, cli=False)

    def poll(self, rid, token):
        return self.req("GET", f"/auth/access-requests/{rid}?t={token}",
                        headers={"Host": AUTH}, cli=False)

    def decide(self, rid, decision, **extra):
        return self.req("POST", "/auth/admin/access-requests/decide",
                        {"id": rid, "decision": decision, **extra})

    def listing(self):
        code, data, _ = self.req("GET", "/auth/admin/access-requests")
        self.assertEqual(code, 200)
        return data["requests"]


class GatePageTest(GateCase):
    def test_no_rd_or_owner_flag_is_the_password_page(self):
        for path in ("/login", "/login?owner=1&rd=" + authserver.quote(f"https://{GRAB}/", safe="")):
            code, html, _ = self.page(path)
            self.assertEqual(code, 200, path)
            self.assertIn("Enroll this browser", html)

    def test_rd_on_auth_host_or_ungated_host_is_the_password_page(self):
        for rd in (f"https://{AUTH}/auth/handoff?host=x", "https://other.cush.rocks/",
                   "https://evil.example/", f"https://{GRAB}/<script>"):
            code, html, _ = self.login(rd)
            self.assertEqual(code, 200, rd)
            self.assertIn("Enroll this browser", html, rd)

    def test_stranger_gets_private(self):
        code, html, h = self.login(f"https://{GRAB}/inbox")
        self.assertEqual(code, 403)
        v = view_of(html)
        self.assertEqual(v["state"], "private")
        self.assertEqual(v["host"], GRAB)
        self.assertEqual(v["rd"], f"https://{GRAB}/inbox")
        self.assertTrue(v["can_ask"])
        self.assertTrue(v["owner_url"].startswith("/login?owner=1&rd="))
        self.assertIn("This one's private", html)
        csp = h["content-security-policy"]
        nonce = re.search(r"'nonce-([0-9a-f]+)'", csp).group(1)
        self.assertIn(f'<script nonce="{nonce}">', html)
        self.assertNotIn("unsafe-inline", csp)
        self.assertIn("noindex", h["x-robots-tag"])
        self.assertNotIn("innerHTML", html)
        # Fonts from the auth server's own asset path.
        self.assertIn("/auth/__porch-assets/fonts/", html)

    def test_unknown_cookie_is_private(self):
        code, html, _ = self.login(f"https://{GRAB}/", cookie="nope" * 10)
        self.assertEqual(view_of(html)["state"], "private")

    def test_device_without_host_is_scope_with_its_name(self):
        _, cookie = self.mint(name="Sam's <phone>")
        code, html, _ = self.login(f"https://{GRAB}/", cookie)
        self.assertEqual(code, 403)
        v = view_of(html)
        self.assertEqual(v["state"], "scope")
        self.assertEqual(v["device"], "Sam's <phone>")
        self.assertNotIn("<phone>", html)          # escaped in the JSON literal

    def test_revoked_and_expired_are_expired(self):
        dev, cookie = self.mint()
        dev["revoked"] = True
        self.assertEqual(view_of(self.login(f"https://{GRAB}/", cookie)[1])["state"], "expired")
        dev2, cookie2 = self.mint(expires_at=self.clock.time() + 60)
        self.assertEqual(view_of(self.login(f"https://{GRAB}/", cookie2)[1])["state"], "scope")
        self.clock.advance(120)
        self.assertEqual(view_of(self.login(f"https://{GRAB}/", cookie2)[1])["state"], "expired")

    def test_ran_out_pass_for_this_host_is_expired(self):
        dev, cookie = self.mint()
        dev["pass"] = {"invite_id": "inv_00000000", "apps": [GRAB],
                       "expires_at": authserver.iso_from_epoch(self.clock.time() + 60)}
        self.assertEqual(view_of(self.login(f"https://{GRAB}/", cookie)[1])["state"], "in")
        self.clock.advance(120)
        self.assertEqual(view_of(self.login(f"https://{GRAB}/", cookie)[1])["state"], "expired")

    def test_device_with_host_is_in(self):
        _, cookie = self.mint(apps=[GRAB])
        code, html, _ = self.login(f"https://{GRAB}/x", cookie)
        self.assertEqual(code, 200)
        self.assertEqual(view_of(html)["state"], "in")

    def test_handoff_out_of_scope_is_the_scope_page(self):
        _, cookie = self.mint(apps=[TREND])
        code, html, _ = self.page(f"/auth/handoff?host={GRAB}&state={'S' * 32}", cookie)
        self.assertEqual(code, 403)
        v = view_of(html)
        self.assertEqual((v["state"], v["host"], v["device"]), ("scope", GRAB, "Sam's phone"))

    def test_handoff_tunnel_host_cannot_ask(self):
        _, cookie = self.mint(apps=[TREND])
        code, html, _ = self.page(
            f"/auth/handoff?host=deck.tunnel.cush.rocks&state={'S' * 32}", cookie)
        self.assertEqual(code, 403)
        self.assertFalse(view_of(html)["can_ask"])


class AccessAskTest(GateCase):
    def test_ask_answers_id_token_poll_and_lists_for_the_owner(self):
        code, data, _ = self.ask(note="Sam\x07  Smith")
        self.assertEqual(code, 201, data)
        self.assertEqual(set(data), {"id", "token", "poll"})
        rows = self.listing()
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual((r["host"], r["note"], r["kind"], r["state"], r["ip"]),
                         (GRAB, "Sam Smith", "stranger", "pending", "203.0.113.5"))
        self.assertNotIn("tokens", r)
        self.assertEqual(self.state()["access_requests"][0]["id"], r["id"])
        self.assertTrue(any(f"access ask {r['id']}" in m for m in self.logs))
        self.assertFalse(any("Sam" in m for m in self.logs))
        self.assertEqual(self.poll(data["id"], data["token"])[1]["state"], "pending")

    def test_unknown_host_answers_the_same_and_is_never_listed(self):
        a = self.ask(host="nothing.cush.rocks")
        b = self.ask(host="x" * 200 + ".example", ip="203.0.113.6")
        for code, data, _ in (a, b):
            self.assertEqual(code, 201)
            self.assertEqual(set(data), {"id", "token", "poll"})
        self.assertEqual(self.listing(), [])
        self.assertEqual(self.poll(a[1]["id"], a[1]["token"])[1]["state"], "pending")
        self.clock.advance(access_requests.TTL + 1)
        self.assertEqual(self.poll(a[1]["id"], a[1]["token"])[1]["state"], "expired")

    def test_device_that_has_the_host_is_not_real(self):
        _, cookie = self.mint(apps=[GRAB])
        self.assertEqual(self.ask(cookie=cookie)[0], 201)
        self.assertEqual(self.listing(), [])

    def test_only_on_the_auth_host_same_origin_and_small(self):
        self.assertEqual(self.ask(req_host=GRAB)[0], 404)
        self.assertEqual(self.ask(origin="https://evil.cush.rocks")[0], 403)
        self.assertEqual(self.ask(origin=f"https://{AUTH}")[0], 201)
        self.assertEqual(self.ask(body={"host": GRAB, "note": "x" * 2000}, ip="198.51.100.9")[0], 413)
        self.assertEqual(self.ask(body={"host": 5}, ip="198.51.100.9")[0], 400)

    def test_three_asks_per_address_per_hour(self):
        for i in range(3):
            self.assertEqual(self.ask(host=[GRAB, TREND, "a.cush.rocks"][i])[0], 201)
        code, data, h = self.ask(host=TREND)
        self.assertEqual(code, 429)
        self.assertEqual(self.ask(ip="203.0.113.77")[0], 201)
        self.clock.advance(3601)
        self.assertEqual(self.ask(host=TREND)[0], 201)

    def test_second_ask_joins_the_pending_one(self):
        a = self.ask(note="Sam")[1]
        b = self.ask(note="")[1]
        self.assertEqual(a["id"], b["id"])
        self.assertNotEqual(a["token"], b["token"])
        self.assertEqual(self.listing()[0]["waiting"], 2)
        # A device's ask is keyed by the device, not the address.
        _, cookie = self.mint()
        c = self.ask(cookie=cookie)[1]
        self.assertNotEqual(c["id"], a["id"])
        self.assertEqual(len(self.listing()), 2)

    def test_pending_cap(self):
        real = access_requests.MAX_PENDING
        access_requests.MAX_PENDING = 2
        self.addCleanup(setattr, access_requests, "MAX_PENDING", real)
        self.assertEqual(self.ask(ip="192.0.2.1")[0], 201)
        self.assertEqual(self.ask(ip="192.0.2.2")[0], 201)
        self.assertEqual(self.ask(ip="192.0.2.3")[0], 503)
        # Joining an existing one is still fine.
        self.assertEqual(self.ask(ip="192.0.2.1")[0], 201)

    def test_poll_needs_the_right_token(self):
        a = self.ask()[1]
        b = self.ask(ip="203.0.113.9", host=TREND)[1]
        self.assertEqual(self.poll(a["id"], b["token"])[0], 404)
        self.assertEqual(self.poll("A" * 16, a["token"])[0], 404)
        self.assertEqual(self.poll("../x", a["token"])[0], 404)
        self.assertEqual(self.req("GET", f"/auth/access-requests/{a['id']}",
                                  headers={"Host": AUTH}, cli=False)[0], 404)

    def test_admin_routes_need_the_cli_token_or_a_session(self):
        self.assertEqual(self.req("GET", "/auth/admin/access-requests", cli=False)[0], 401)
        self.assertEqual(self.req("POST", "/auth/admin/access-requests/decide",
                                  {"id": "A" * 16, "decision": "deny"}, cli=False)[0], 401)


class AccessDecideTest(GateCase):
    def test_deny(self):
        a = self.ask()[1]
        code, data, _ = self.decide(a["id"], "deny")
        self.assertEqual(code, 200)
        self.assertEqual(data["request"]["state"], "denied")
        self.assertEqual(self.poll(a["id"], a["token"])[1], {"state": "denied", "poll": 4})
        self.assertEqual(self.decide(a["id"], "allow")[0], 404)

    def test_allow_device_adds_the_host_to_its_scope(self):
        dev, cookie = self.mint(apps=[TREND])
        a = self.ask(cookie=cookie)[1]
        row = self.listing()[0]
        self.assertEqual((row["kind"], row["device_id"], row["device_name"]),
                         ("device", dev["id"], "Sam's phone"))
        self.assertNotIn(self.key(cookie, GRAB), self.grants())
        code, data, _ = self.decide(a["id"], "allow")
        self.assertEqual(code, 200, data)
        self.assertEqual(data["request"]["how"], "device")
        self.assertEqual(dev["apps"], sorted([GRAB, TREND]))
        self.assertIn(self.key(cookie, GRAB), self.grants())
        self.assertEqual(self.poll(a["id"], a["token"])[1],
                         {"state": "approved", "rd": f"https://{GRAB}/inbox", "poll": 4})
        self.assertEqual(self.state()["invites"], [])
        # And the gate page now says "in".
        self.assertEqual(view_of(self.login(f"https://{GRAB}/", cookie)[1])["state"], "in")

    def test_allow_stranger_mints_a_single_use_invite_only_the_visitor_sees(self):
        a = self.ask(note="Sam")[1]
        code, data, _ = self.decide(a["id"], "allow")
        self.assertEqual(code, 200, data)
        rec = data["request"]
        self.assertEqual(rec["how"], "invite")
        self.assertTrue(rec["invite_id"].startswith("inv_"))
        inv = self.invite_row(rec["invite_id"])
        self.assertEqual((inv["apps"], inv["max_uses"], inv["standing"], inv["landing"]),
                         ([GRAB], 1, False, GRAB))
        self.assertEqual(inv["note"], "Asked for access: Sam")
        self.assertLessEqual(inv["expires_at"] - self.clock.time(), 3601)
        out = self.poll(a["id"], a["token"])[1]
        self.assertEqual(out["state"], "approved")
        url = out["invite"]
        self.assertTrue(url.startswith(f"https://{AUTH}/i/"))
        token = url.rsplit("/", 1)[1]
        # Nowhere else: not the owner's views, not the logs.
        blob = json.dumps([self.listing(), self.state(), data])
        self.assertNotIn(token, blob)
        self.assertFalse(any(token in m for m in self.logs))
        # It enrolls this browser for exactly that host, once.
        code, body, cookie, _ = self.accept(token)
        self.assertEqual(code, 200, body)
        self.assertEqual(self.device(cookie)["apps"], [GRAB])
        self.assertEqual(self.accept(token)[0], 410)

    def test_expired_device_gets_an_invite(self):
        dev, cookie = self.mint()
        dev["revoked"] = True
        a = self.ask(cookie=cookie)[1]
        self.assertEqual(self.listing()[0]["kind"], "expired")
        self.assertIsNone(self.listing()[0]["device_id"])
        self.assertEqual(self.decide(a["id"], "allow")[1]["request"]["how"], "invite")
        self.assertIn("invite", self.poll(a["id"], a["token"])[1])

    def test_device_gone_by_then_falls_back_to_an_invite(self):
        dev, cookie = self.mint()
        a = self.ask(cookie=cookie)[1]
        dev["revoked"] = True
        self.assertEqual(self.decide(a["id"], "allow")[1]["request"]["how"], "invite")

    def test_device_ttl_for_the_invite(self):
        a = self.ask()[1]
        rec = self.decide(a["id"], "allow", device_ttl_minutes=60)[1]["request"]
        self.assertEqual(self.invite_row(rec["invite_id"])["device_ttl_minutes"], 60)
        b = self.ask(host=TREND)[1]
        self.assertEqual(self.decide(b["id"], "allow", device_ttl_minutes=0)[0], 400)

    def test_host_no_longer_gated_refuses_and_stays_pending(self):
        a = self.ask()[1]
        authserver.STATE["protected_apps"].remove(GRAB)
        code, data, _ = self.decide(a["id"], "allow")
        self.assertEqual(code, 409)
        self.assertEqual(self.listing()[0]["state"], "pending")

    def test_bad_decisions(self):
        a = self.ask()[1]
        self.assertEqual(self.decide(a["id"], "maybe")[0], 400)
        self.assertEqual(self.decide("nope", "deny")[0], 400)
        self.assertEqual(self.decide("B" * 16, "deny")[0], 404)

    def test_runs_out_after_thirty_minutes(self):
        a = self.ask()[1]
        self.clock.advance(access_requests.TTL + 1)
        self.assertEqual(self.poll(a["id"], a["token"])[1]["state"], "expired")
        self.assertEqual(self.listing()[0]["state"], "expired")
        self.assertEqual(self.decide(a["id"], "allow")[0], 404)
        self.clock.advance(access_requests.KEEP + 1)
        self.assertEqual(self.poll(a["id"], a["token"])[0], 404)
        self.assertEqual(self.listing(), [])


class AccessCliTest(GateCase):
    ADMIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin", "auth-admin")

    def run_cli(self, *args):
        import subprocess
        env = dict(os.environ, CUSH_AUTH_URL=f"http://127.0.0.1:{self.port}")
        return subprocess.run([sys.executable, self.ADMIN, "--data", self.tmp.name, *args],
                              capture_output=True, text=True, env=env, timeout=60)

    def test_ls_allow_deny(self):
        r = self.run_cli("access", "ls")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("No one is asking", r.stdout)
        a = self.ask(note="Sam")[1]
        _, cookie = self.mint()
        b = self.ask(cookie=cookie, host=GRAB, ip="198.51.100.2")[1]
        r = self.run_cli("access", "ls")
        self.assertIn("Sam", r.stdout)
        self.assertIn("device Sam's phone", r.stdout)
        r = self.run_cli("access", "allow", a["id"], "--hours", "24")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("one-time invite", r.stdout)
        url = self.poll(a["id"], a["token"])[1]["invite"]
        self.assertNotIn(url.rsplit("/", 1)[1], r.stdout + r.stderr)
        r = self.run_cli("access", "deny", b["id"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.poll(b["id"], b["token"])[1]["state"], "denied")
        r = self.run_cli("access", "ls", "--all", "--json")
        self.assertEqual({x["state"] for x in json.loads(r.stdout)}, {"approved", "denied"})
        r = self.run_cli("access", "deny", b["id"])
        self.assertNotEqual(r.returncode, 0)


class StoreUnitTest(unittest.TestCase):
    def test_push_payload(self):
        p = access_requests.push_payload({"id": "A" * 16, "host": GRAB, "note": "Sam",
                                          "kind": "device", "device_name": "Pixel",
                                          "ip": "203.0.113.5"})
        self.assertEqual(p["t"], "access")
        self.assertEqual(p["title"], f"Let someone into {GRAB}?")
        self.assertIn("Sam on Pixel", p["body"])
        self.assertIn("203.0.113.5", p["body"])
        p = access_requests.push_payload({"id": "A" * 16, "host": GRAB, "kind": "stranger"})
        self.assertEqual(p["body"], "Someone is asking for access.")

    def test_grant_failure_puts_it_back(self):
        st = access_requests.Store()
        rid, tok, _, _ = st.ask(GRAB, "", "1.2.3.4", True)

        def boom(rec):
            raise RuntimeError("nope")
        with self.assertRaises(RuntimeError):
            st.decide(rid, "allow", grant=boom)
        self.assertEqual(st.get(rid)["state"], "pending")
        self.assertEqual(st.decide(rid, "allow", grant=lambda r: {"how": "device"})["state"],
                         "approved")


if __name__ == "__main__":
    unittest.main()

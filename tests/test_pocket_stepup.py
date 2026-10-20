"""Pocket step-up and passkeys (lib/pocket_stepup.py) at the HTTP level, with
the software authenticator (tests/webauthn_soft.py) and a fake cush-auth for
the password path. Clocks are injected; nothing touches ~/pocket or the live
auth server."""

import json
import os
import unittest

import pocket_harness as ph
from pocket_harness import ps

try:
    import webauthn_soft as soft
    HAVE_CRYPTO = True
except ImportError:          # python3-cryptography missing
    HAVE_CRYPTO = False

import porch_webauthn as wa

# Every ★ route (always step-up) with a body that is otherwise valid.
STAR = [
    ("/api/doors/stop-all", {}),
    ("/api/requests/pairings/ABCD-1234/approve", {}),
    ("/api/people/devices/dev_box/revoke", {}),
    ("/api/people/devices/dev_box/role", {"role": "admin"}),
    ("/api/people/devices/dev_box/apps", {"apps": ["a.example.com"]}),
    ("/api/people/invites", {"apps": ["trendlab.cush.rocks"]}),
    ("/api/people/apps", {"host": "a.example.com", "action": "protect"}),
    ("/api/people/password", {"current": ph.ADMIN_PASSWORD, "new": "another-pass-77"}),
    ("/api/passkeys/register/options", {}),
    ("/api/passkeys/" + "A" * 20 + "/delete", {}),
]


def b64d(s):
    return wa.unb64u(s, 4096)


class Base(unittest.TestCase):

    def setUp(self):
        self.fx = ph.PocketFixture().start()

    def tearDown(self):
        self.fx.stop()

    def register_passkey(self, tok, auth=None, label="My iPhone"):
        auth = auth or soft.SoftAuthenticator()
        r, out = self.fx.post("/api/passkeys/register/options", stepup=tok)
        self.assertEqual(r.status, 200, out)
        pk = out["publicKey"]
        self.assertEqual(pk["rp"]["id"], ph.RP_ID)
        self.assertEqual(pk["authenticatorSelection"]["userVerification"], "required")
        auth.user_handle = b64d(pk["user"]["id"])
        cred = auth.register(b64d(pk["challenge"]), ph.RP_ORIGIN, ph.RP_ID)
        r, out = self.fx.post("/api/passkeys/register", {"credential": cred, "label": label},
                              stepup=tok)
        self.assertEqual(r.status, 201, out)
        return auth, out["passkey"]

    def passkey_stepup(self, auth, **knobs):
        r, out = self.fx.post("/api/stepup/options")
        self.assertEqual(r.status, 200, out)
        pk = out["publicKey"]
        self.assertEqual(pk["userVerification"], "required")
        self.assertTrue(pk["allowCredentials"])
        cred = auth.assertion(b64d(pk["challenge"]), knobs.pop("origin", ph.RP_ORIGIN),
                              knobs.pop("rp_id", ph.RP_ID), **knobs)
        r, self.last = self.fx.post("/api/stepup/passkey", {"credential": cred})
        return r, cred


class GuardTests(Base):

    def test_every_star_route_needs_stepup_then_works(self):
        for path, body in STAR:
            r, out = self.fx.post(path, body)
            self.assertEqual((r.status, out.get("code")), (401, "step_up"), path)
            self.assertEqual(out["methods"], ["password"])
            self.assertEqual(out["passkeys"], 0)
        tok = self.fx.password_stepup()
        ph.write_door(self.fx.state_dir, "pt-a", self.fx.sleepers.pid())
        for path, body in STAR:
            r, out = self.fx.post(path, body, stepup=tok)
            self.assertNotEqual(out.get("code"), "step_up", path)
            self.assertNotEqual(r.status, 401, (path, out))

    def test_stepup_bound_to_owner_cookie_and_device(self):
        tok = self.fx.password_stepup()
        # The other owner device's cookie with this step-up cookie: refused.
        r, out = self.fx.post("/api/people/apps", {"host": "a.example.com", "action": "protect"},
                              token=ph.OWNER2_TOKEN, stepup=tok)
        self.assertEqual((r.status, out["code"]), (401, "step_up"))
        # No owner cookie at all: not even the owner.
        r, out = self.fx.post("/api/people/apps", {"host": "a.example.com", "action": "protect"},
                              token=None, stepup=tok)
        self.assertEqual(r.status, 403)
        # A forged cookie value.
        r, out = self.fx.post("/api/people/apps", {"host": "a.example.com", "action": "protect"},
                              stepup="A" * 43)
        self.assertEqual((r.status, out["code"]), (401, "step_up"))
        r, out = self.fx.post("/api/people/apps", {"host": "a.example.com", "action": "protect"},
                              stepup=tok)
        self.assertEqual(r.status, 200)

    def test_window_is_fixed_five_minutes(self):
        tok = self.fx.password_stepup()
        self.fx.clock.advance(299)
        r, _ = self.fx.post("/api/people/apps", {"host": "a.example.com", "action": "protect"},
                            stepup=tok)
        self.assertEqual(r.status, 200)
        self.fx.clock.advance(2)
        r, out = self.fx.post("/api/people/apps", {"host": "a.example.com", "action": "protect"},
                              stepup=tok)
        self.assertEqual((r.status, out["code"]), (401, "step_up"))

    def test_cookie_attributes_and_end(self):
        r, out = self.fx.post("/api/stepup/password", {"password": ph.ADMIN_PASSWORD})
        self.assertEqual((r.status, out["method"]), (200, "password"))
        self.assertEqual(out["expires_at"], int(self.fx.clock()) + 300)
        sc = r.getheader("Set-Cookie")
        for attr in ("__Host-pocket_stepup=", "Secure", "HttpOnly", "SameSite=Strict", "Path=/",
                     "Max-Age=300"):
            self.assertIn(attr, sc)
        self.assertNotIn("Domain", sc)
        tok = ph.cookie_value(r)
        r, out = self.fx.post("/api/stepup/end", stepup=tok)
        self.assertEqual(r.status, 200)
        self.assertIn("Max-Age=0", r.getheader("Set-Cookie"))
        r, out = self.fx.post("/api/doors/stop-all", stepup=tok)
        self.assertEqual((r.status, out["code"]), (401, "step_up"))

    def test_a_new_stepup_replaces_the_old_one(self):
        old = self.fx.password_stepup()
        new = self.fx.password_stepup()
        r, _ = self.fx.post("/api/doors/stop-all", stepup=old)
        self.assertEqual(r.status, 401)
        r, _ = self.fx.post("/api/doors/stop-all", stepup=new)
        self.assertEqual(r.status, 200)

    def test_cli_token_never_steps_up(self):
        h = {ps.CLI_TOKEN_HEADER: ph.CLI_TOKEN}
        for path in ("/api/stepup/password", "/api/stepup/options", "/api/stepup/end"):
            r, _ = self.fx.post(path, {"password": ph.ADMIN_PASSWORD}, token=None, origin=False,
                                headers=h)
            self.assertEqual(r.status, 403, path)
        self.assertFalse([s for s in self.fx.auth.seen if "verify" in s["path"]])

    def test_csrf_on_stepup(self):
        r, out = self.fx.post("/api/stepup/password", {"password": ph.ADMIN_PASSWORD},
                              origin=False, headers={"Origin": "https://evil.tunnel.cush.rocks"})
        self.assertEqual(r.status, 403)
        r, out = self.fx.post("/api/stepup/password",
                              json.dumps({"password": ph.ADMIN_PASSWORD}).encode(),
                              ctype="text/plain")
        self.assertEqual(r.status, 415)


class PasswordTests(Base):

    def test_wrong_password_then_rate_limited(self):
        with ph.CaptureStderr() as cap:
            for _ in range(5):
                r, out = self.fx.post("/api/stepup/password", {"password": "nope-nope-nope"})
                self.assertEqual((r.status, out["code"]), (401, "stepup_failed"))
            r, out = self.fx.post("/api/stepup/password", {"password": ph.ADMIN_PASSWORD})
        self.assertEqual((r.status, out["code"]), (429, "rate_limited"))
        self.assertGreater(out["retry_after"], 0)
        self.assertEqual(r.getheader("Retry-After"), str(out["retry_after"]))
        # Blocked before any verification work: five checks reached cush-auth, not six.
        n = len([s for s in self.fx.auth.seen if s["path"] == "/auth/admin/verify-password"])
        self.assertEqual(n, 5)
        self.assertNotIn("nope-nope-nope", cap.text)
        self.assertNotIn(ph.ADMIN_PASSWORD, cap.text)
        _, act = self.fx.get("/api/activity")
        self.assertEqual(act[0]["result"], "failed")
        self.assertEqual(act[0]["code"], "bad_password")

    def test_ip_sent_to_cush_auth(self):
        self.fx.password_stepup()
        v = next(s for s in self.fx.auth.seen if s["path"] == "/auth/admin/verify-password")
        self.assertEqual(v["body"], {"password": ph.ADMIN_PASSWORD, "ip": "127.0.0.1"})
        self.assertNotIn("origin", v["headers"])

    def test_old_and_down_cush_auth(self):
        self.fx.auth.missing.add("/auth/admin/verify-password")
        r, out = self.fx.post("/api/stepup/password", {"password": ph.ADMIN_PASSWORD})
        self.assertEqual((r.status, out["code"]), (501, "auth_old"))
        self.assertIn("bin/auth-deploy", out["message"])
        self.fx.auth.shutdown()
        self.fx.auth.server_close()
        self.fx.auth = None
        r, out = self.fx.post("/api/stepup/password", {"password": ph.ADMIN_PASSWORD})
        self.assertEqual((r.status, out["code"]), (503, "auth_down"))


@unittest.skipUnless(HAVE_CRYPTO and wa.available(), "needs python3-cryptography")
class PasskeyTests(Base):

    def test_register_then_stepup_with_passkey(self):
        tok = self.fx.password_stepup()
        auth, pk = self.register_passkey(tok)
        self.assertEqual(pk["label"], "My iPhone")
        self.assertFalse(pk["unusable"])
        st = os.stat(os.path.join(self.fx.base, ".passkeys.json"))
        self.assertEqual(st.st_mode & 0o777, 0o600)
        r, lst = self.fx.get("/api/passkeys")
        self.assertEqual([p["id"] for p in lst], [pk["id"]])
        self.assertEqual(set(lst[0]), {"id", "short_id", "label", "created_at", "last_used_at",
                                       "synced", "transports", "unusable"})
        self.fx.post("/api/stepup/end", stepup=tok)
        # The guard now offers both methods.
        r, out = self.fx.post("/api/doors/stop-all")
        self.assertEqual((out["methods"], out["passkeys"]), (["passkey", "password"], 1))
        r, cred = self.passkey_stepup(auth)
        self.assertEqual(r.status, 200, cred)
        tok2 = ph.cookie_value(r)
        r, out = self.fx.post("/api/doors/stop-all", stepup=tok2)
        self.assertEqual(r.status, 200)
        _, out = self.fx.get("/api/app", stepup=tok2)
        self.assertEqual(out["stepup"]["method"], "passkey")
        _, lst = self.fx.get("/api/passkeys")
        self.assertEqual(lst[0]["last_used_at"], int(self.fx.clock()))

    def test_first_passkey_needs_password_method(self):
        ctx_tok, _ = self.fx.H.stepups.create("dev_owner", ph.sha(ph.OWNER_TOKEN), "passkey")
        r, out = self.fx.post("/api/passkeys/register/options", stepup=ctx_tok)
        self.assertEqual((r.status, out["code"]), (401, "step_up_password"))
        self.assertEqual(out["methods"], ["password"])

    def test_register_needs_fresh_stepup_and_own_challenge(self):
        tok = self.fx.password_stepup()
        r, out = self.fx.post("/api/passkeys/register/options", stepup=tok)
        pk = out["publicKey"]
        auth = soft.SoftAuthenticator()
        cred = auth.register(b64d(pk["challenge"]), ph.RP_ORIGIN, ph.RP_ID)
        self.fx.clock.advance(301)                 # step-up gone
        r, out = self.fx.post("/api/passkeys/register", {"credential": cred})
        self.assertEqual((r.status, out["code"]), (401, "step_up"))
        tok = self.fx.password_stepup()
        # A challenge issued to the other device can't be used here.
        tok2 = self.fx.password_stepup(token=ph.OWNER2_TOKEN)
        r, out = self.fx.post("/api/passkeys/register/options", stepup=tok2, token=ph.OWNER2_TOKEN)
        cred = auth.register(b64d(out["publicKey"]["challenge"]), ph.RP_ORIGIN, ph.RP_ID)
        r, out = self.fx.post("/api/passkeys/register", {"credential": cred}, stepup=tok)
        self.assertEqual((r.status, out["code"]), (401, "stepup_failed"))
        # Wrong origin.
        r, out = self.fx.post("/api/passkeys/register/options", stepup=tok)
        cred = auth.register(b64d(out["publicKey"]["challenge"]), "https://evil.tunnel.cush.rocks",
                             ph.RP_ID)
        r, out = self.fx.post("/api/passkeys/register", {"credential": cred}, stepup=tok)
        self.assertEqual((r.status, out["code"]), (401, "stepup_failed"))
        self.assertEqual(out["message"], "That passkey didn't check out")
        _, act = self.fx.get("/api/activity")
        self.assertEqual(act[0]["code"], "origin_mismatch")

    def test_challenge_single_use_and_expiry(self):
        tok = self.fx.password_stepup()
        auth, _ = self.register_passkey(tok)
        r, cred = self.passkey_stepup(auth)
        self.assertEqual(r.status, 200)
        r, out = self.fx.post("/api/stepup/passkey", {"credential": cred})     # replay
        self.assertEqual((r.status, out["code"]), (401, "stepup_failed"))
        r, out = self.fx.post("/api/stepup/options")
        cred = auth.assertion(b64d(out["publicKey"]["challenge"]), ph.RP_ORIGIN, ph.RP_ID)
        self.fx.clock.advance(121)
        r, out = self.fx.post("/api/stepup/passkey", {"credential": cred})
        self.assertEqual((r.status, out["code"]), (401, "stepup_failed"))

    def test_bad_assertions_fail_and_count(self):
        tok = self.fx.password_stepup()
        auth, _ = self.register_passkey(tok)
        cases = [dict(origin="https://evil.tunnel.cush.rocks"), dict(rp_id="tunnel.cush.rocks"),
                 dict(flags=soft.UP), dict(flip_sig=True), dict(user_handle=b"x" * 16)]
        codes = []
        for knobs in cases:
            r, _ = self.passkey_stepup(auth, **knobs)
            self.assertEqual(r.status, 401, knobs)
            _, act = self.fx.get("/api/activity")
            codes.append(act[0]["code"])
        self.assertEqual(codes, ["origin_mismatch", "rp_mismatch", "no_uv", "bad_signature",
                                 "user_mismatch"])
        # That was 5 failures from this IP: blocked now, even with a good one.
        r, out = self.fx.post("/api/stepup/options")
        cred = auth.assertion(b64d(out["publicKey"]["challenge"]), ph.RP_ORIGIN, ph.RP_ID)
        r, out = self.fx.post("/api/stepup/passkey", {"credential": cred})
        self.assertEqual((r.status, out["code"]), (429, "rate_limited"))

    def test_counter_regression_refused(self):
        tok = self.fx.password_stepup()
        auth = soft.SoftAuthenticator(sign_count=5)
        auth, _ = self.register_passkey(tok, auth)
        r, _ = self.passkey_stepup(auth)               # count 6
        self.assertEqual(r.status, 200)
        with ph.CaptureStderr() as cap:
            r, _ = self.passkey_stepup(auth, count=3)
        self.assertEqual(r.status, 401)
        self.assertIn("possible cloned", cap.text)
        _, act = self.fx.get("/api/activity")
        self.assertEqual(act[0]["code"], "counter_regressed")

    def test_zero_counts_accepted(self):
        tok = self.fx.password_stepup()
        auth, _ = self.register_passkey(tok, soft.SoftAuthenticator(sign_count=0))
        for _ in range(2):
            r, _ = self.passkey_stepup(auth, count=0)
            self.assertEqual(r.status, 200)

    def test_rename_not_star_delete_star(self):
        tok = self.fx.password_stepup()
        _, pk = self.register_passkey(tok)
        self.fx.post("/api/stepup/end", stepup=tok)
        r, out = self.fx.post(f"/api/passkeys/{pk['id']}/rename", {"label": "Face ID\n phone"})
        self.assertEqual((r.status, out["passkey"]["label"]), (200, "Face ID phone"))
        r, out = self.fx.post(f"/api/passkeys/{pk['id']}/rename", {"label": " "})
        self.assertEqual(r.status, 400)
        r, out = self.fx.post(f"/api/passkeys/{pk['id']}/delete")
        self.assertEqual((r.status, out["code"]), (401, "step_up"))
        tok = self.fx.password_stepup()
        r, out = self.fx.post(f"/api/passkeys/{pk['id']}/delete", stepup=tok)
        self.assertEqual((r.status, out["passkeys"]), (200, []))
        r, out = self.fx.post(f"/api/passkeys/{pk['id']}/delete", stepup=tok)
        self.assertEqual(r.status, 404)

    def test_rp_rename_makes_passkeys_unusable(self):
        tok = self.fx.password_stepup()
        self.register_passkey(tok)
        self.fx.H.passkeys = ps.PasskeyStore(os.path.join(self.fx.base, ".passkeys.json"),
                                             "renamed.test", self.fx.clock)
        _, lst = self.fx.get("/api/passkeys")
        self.assertTrue(lst[0]["unusable"])
        r, out = self.fx.post("/api/stepup/options")
        self.assertEqual(out, {"status": "ok", "passkeys": 0})
        _, app = self.fx.get("/api/app")
        self.assertEqual((app["passkeys"]["count"], app["passkeys"]["unusable"]), (0, 1))

    def test_options_rate_limit(self):
        tok = self.fx.password_stepup()
        self.register_passkey(tok)
        codes = [self.fx.post("/api/stepup/options")[0].status for _ in range(31)]
        self.assertEqual(codes[-1], 429)

    def test_no_secret_in_logs(self):
        with ph.CaptureStderr() as cap:
            r, _ = self.fx.post("/api/stepup/password", {"password": ph.ADMIN_PASSWORD})
            tok = ph.cookie_value(r)
            auth, _ = self.register_passkey(tok)
            r, cred = self.passkey_stepup(auth)
            tok2 = ph.cookie_value(r)
        text = cap.text
        for secret in (ph.ADMIN_PASSWORD, tok, tok2, ph.AUTH_TOKEN, ph.OWNER_TOKEN,
                       cred["response"]["signature"]):
            self.assertNotIn(secret, text)
        with open(os.path.join(self.fx.base, ".audit.jsonl")) as f:
            audit = f.read()
        for secret in (ph.ADMIN_PASSWORD, tok, tok2):
            self.assertNotIn(secret, audit)


class StoreUnitTests(unittest.TestCase):

    def test_challenge_store_caps(self):
        clock = ph.Clock()
        cs = ps.ChallengeStore(clock, per_device=2, total=3)
        a = cs.issue("stepup", "d1", "o")
        cs.issue("stepup", "d1", "o")
        cs.issue("stepup", "d1", "o")              # evicts a
        self.assertEqual(len([e for e in cs.items.values() if e["device_id"] == "d1"]), 2)
        import hashlib
        self.assertNotIn(hashlib.sha256(a).hexdigest(), cs.items)
        cs.issue("stepup", "d2", "o")
        cs.issue("stepup", "d3", "o")
        self.assertLessEqual(len(cs.items), 3)

    def test_stepup_store_cap(self):
        st = ps.StepUpStore(ph.Clock(), total=2)
        for i in range(5):
            st.create(f"d{i}", "o", "password")
        self.assertEqual(len(st.items), 2)


if __name__ == "__main__":
    unittest.main()

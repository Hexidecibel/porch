"""Tests for lib/porch_push.py: RFC 8291 (aes128gcm) against its Appendix A
vector, VAPID (RFC 8292) JWTs a push service would accept, the push-service
allowlist, subscriptions, and delivery to a local fake push service that
decrypts with the subscription's private key (404/410 drop the subscription).
"""
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib")
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
import porch_push as pp  # noqa: E402

HAVE = pp.available()

# RFC 8291, Appendix A
A = {
    "plaintext": b"When I grow up, I want to be a watermelon",
    "as_private": "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw",
    "as_public": "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8",
    "ua_private": "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94",
    "ua_public": "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
    "salt": "DGv6ra1nlYgDCS1FRnbzlw",
    "auth": "BTBZMqHH6r4Tts7J_aSIgg",
    "body": ("DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCY"
             "LocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLW"
             "youBWLVWGNWQexSgSxsj_Qulcy4a-fN"),
}


class FakePushService:
    """A loopback push service: records each POST, decrypts it with the
    browser's key, checks VAPID, answers `status` (per endpoint path)."""

    def __init__(self, browsers):
        self.browsers = browsers          # path -> (ua private key, auth bytes)
        self.got = []
        self.status = {}
        svc = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                ep = f"http://127.0.0.1:{svc.port}{self.path}"
                rec = {"path": self.path, "headers": dict(self.headers), "body": body}
                ua, auth = svc.browsers[self.path]
                rec["claims"], rec["k"] = pp.verify_vapid(self.headers["Authorization"], ep)
                rec["payload"] = json.loads(pp.decrypt(body, ua, auth))
                svc.got.append(rec)
                self.send_response(svc.status.get(self.path, 201))
                self.send_header("Content-Length", "0")
                self.end_headers()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def browser():
    """A fake browser subscription: (private key, auth, PushSubscription JSON
    with endpoint filled in later)."""
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    auth = os.urandom(16)
    return key, auth, {"keys": {"p256dh": pp.b64u(pp.public_bytes(key)), "auth": pp.b64u(auth)}}


@unittest.skipUnless(HAVE, "python3-cryptography is not installed")
class CryptoTests(unittest.TestCase):

    def test_rfc8291_appendix_a(self):
        as_key = pp.private_from_bytes(pp.unb64u(A["as_private"]))
        ua_key = pp.private_from_bytes(pp.unb64u(A["ua_private"]))
        self.assertEqual(pp.b64u(pp.public_bytes(as_key)), A["as_public"])
        self.assertEqual(pp.b64u(pp.public_bytes(ua_key)), A["ua_public"])
        body = pp.encrypt(A["plaintext"], pp.unb64u(A["ua_public"]), pp.unb64u(A["auth"]),
                          salt=pp.unb64u(A["salt"]), as_private=as_key)
        self.assertEqual(pp.b64u(body), A["body"])
        self.assertEqual(pp.decrypt(pp.unb64u(A["body"]), ua_key, pp.unb64u(A["auth"])),
                         A["plaintext"])

    def test_fresh_salt_and_key_each_time(self):
        key, auth, sub = browser()
        a = pp.encrypt(b"x", pp.public_bytes(key), auth)
        b = pp.encrypt(b"x", pp.public_bytes(key), auth)
        self.assertNotEqual(a[:16], b[:16])
        self.assertNotEqual(a[21:86], b[21:86])
        self.assertEqual(pp.decrypt(a, key, auth), b"x")
        with self.assertRaises(Exception):
            pp.decrypt(a, key, os.urandom(16))          # wrong auth secret

    def test_payload_cap(self):
        key, auth, _ = browser()
        body = pp.encrypt(b"y" * pp.MAX_PAYLOAD, pp.public_bytes(key), auth)
        self.assertLessEqual(len(body), 4096)
        with self.assertRaises(ValueError):
            pp.encrypt(b"y" * (pp.MAX_PAYLOAD + 1), pp.public_bytes(key), auth)

    def test_vapid_jwt_verifies(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, ".vapid.pem")
        key = pp.load_or_create_vapid(path)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(pp.public_bytes(pp.load_or_create_vapid(path)), pp.public_bytes(key))
        ep = "https://fcm.googleapis.com/fcm/send/abc"
        h = pp.vapid_header(key, ep, "https://tunnel.cush.rocks/", now=1_000)
        claims, k = pp.verify_vapid(h, ep, now=1_000)
        self.assertEqual(claims["aud"], "https://fcm.googleapis.com")
        self.assertEqual(claims["exp"], 1_000 + pp.JWT_TTL)
        self.assertEqual(k, pp.public_bytes(key))
        with self.assertRaises(ValueError):
            pp.verify_vapid(h, "https://web.push.apple.com/x", now=1_000)    # wrong aud
        with self.assertRaises(ValueError):
            pp.verify_vapid(h, ep, now=1_000 + pp.JWT_TTL + 1)               # expired
        other = pp.load_or_create_vapid(os.path.join(tmp, "other.pem"))
        forged = h.split(", k=")[0] + ", k=" + pp.b64u(pp.public_bytes(other))
        with self.assertRaises(ValueError):
            pp.verify_vapid(forged, ep, now=1_000)


class AllowlistTests(unittest.TestCase):

    def test_endpoints(self):
        ok = ["https://fcm.googleapis.com/fcm/send/x", "https://updates.push.services.mozilla.com/wpush/v2/x",
              "https://web.push.apple.com/QK", "https://wns2-par02p.notify.windows.com/w/?token=x",
              "https://fcm.googleapis.com:443/x"]
        bad = ["http://fcm.googleapis.com/x", "https://fcm.googleapis.com.evil.com/x",
               "https://evil.com/fcm.googleapis.com", "https://127.0.0.1/x", "https://localhost/x",
               "https://fcm.googleapis.com:8443/x", "https://user:pw@fcm.googleapis.com/x",
               "https://notify.windows.com.evil/x", "https://fcm.googleapis.com/x y", None, 5,
               "https://" + "a" * 3000 + ".push.apple.com/"]
        for u in ok:
            self.assertTrue(pp.endpoint_allowed(u), u)
        for u in bad:
            self.assertFalse(pp.endpoint_allowed(u), u)

    @unittest.skipUnless(HAVE, "python3-cryptography is not installed")
    def test_clean_subscription(self):
        key, auth, sub = browser()
        sub["endpoint"] = "https://fcm.googleapis.com/fcm/send/abc"
        self.assertEqual(pp.clean_subscription(sub)["auth"], pp.b64u(auth))
        for broken in ({**sub, "endpoint": "https://example.com/x"},
                       {**sub, "keys": {"p256dh": "AAAA", "auth": sub["keys"]["auth"]}},
                       {**sub, "keys": {"p256dh": sub["keys"]["p256dh"], "auth": "AAAA"}},
                       {"endpoint": sub["endpoint"]}, "nope"):
            with self.assertRaises(ValueError):
                pp.clean_subscription(broken)


@unittest.skipUnless(HAVE, "python3-cryptography is not installed")
class DeliveryTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="porch-push-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.pocket = os.path.join(self.tmp, "pocket", "pocket")
        os.makedirs(self.pocket)
        self.b1, self.b2 = browser(), browser()
        self.svc = FakePushService({"/sub/one": self.b1[:2], "/sub/two": self.b2[:2]})
        self.addCleanup(self.svc.close)
        pp.allow_test_endpoint(f"http://127.0.0.1:{self.svc.port}/")
        self.addCleanup(pp._test_prefixes.clear)
        store = pp.SubStore(os.path.join(self.pocket, ".push.json"))
        pp.load_or_create_vapid(os.path.join(self.pocket, ".vapid.pem"))
        for path, b in (("/sub/one", self.b1), ("/sub/two", self.b2)):
            store.add(dict(b[2], endpoint=f"http://127.0.0.1:{self.svc.port}{path}"), "Phone")
        self.store = store

    def test_deliver_encrypts_signs_and_drops_gone(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.store.path).st_mode), 0o600)
        self.svc.status["/sub/two"] = 410
        out = pp.notify_all({"t": "test", "title": "hi"}, "https://tunnel.cush.rocks/",
                            root=os.path.dirname(self.pocket))
        self.assertEqual(out, {"sent": 1, "failed": 0, "dropped": 1})
        self.assertEqual(len(self.svc.got), 2)
        for rec in self.svc.got:
            self.assertEqual(rec["payload"], {"t": "test", "title": "hi"})
            self.assertEqual(rec["headers"]["Content-Encoding"], "aes128gcm")
            self.assertEqual(rec["headers"]["Urgency"], "high")
            self.assertEqual(rec["headers"]["TTL"], "1800")
            self.assertEqual(rec["claims"]["sub"], "https://tunnel.cush.rocks/")
        self.assertEqual([s["endpoint"].rsplit("/", 1)[1] for s in self.store.load()], ["one"])

    def test_without_the_test_hook_a_loopback_endpoint_is_refused(self):
        pp._test_prefixes.clear()
        self.assertEqual(self.store.load(), [])       # not loaded, never sent to
        with self.assertRaises(ValueError):
            pp.send({"endpoint": f"http://127.0.0.1:{self.svc.port}/sub/one",
                     "p256dh": "x", "auth": "y"}, {}, None, "mailto:x@y")

    def test_store_dedupes_and_caps(self):
        key, auth, sub = browser()
        sub["endpoint"] = "https://fcm.googleapis.com/fcm/send/same"
        self.store.add(sub)
        self.store.add(sub)
        self.assertEqual(sum(1 for s in self.store.load() if s["endpoint"].endswith("/same")), 1)
        for i in range(pp.MAX_SUBS + 3):
            self.store.add(dict(sub, endpoint=f"https://fcm.googleapis.com/fcm/send/{i}"))
        self.assertEqual(len(self.store.load()), pp.MAX_SUBS)
        self.assertEqual(self.store.remove("https://fcm.googleapis.com/fcm/send/0"), 0)  # rolled off
        self.assertNotIn("endpoint", json.dumps(self.store.public()).replace("endpoint_host", ""))

    def test_topics(self):
        one = f"http://127.0.0.1:{self.svc.port}/sub/one"
        two = f"http://127.0.0.1:{self.svc.port}/sub/two"
        # No topics yet: everything.
        self.assertEqual([p["topics"] for p in self.store.public()], [list(pp.TOPICS)] * 2)
        self.assertEqual(self.store.set_topics(two, ["invite", "pairing", "invite"]),
                         ["pairing", "invite"])
        self.assertIsNone(self.store.set_topics("https://fcm.googleapis.com/x", ["reopen"]))
        with self.assertRaises(ValueError):
            self.store.set_topics(one, ["nope"])
        with self.assertRaises(ValueError):
            self.store.set_topics(one, "reopen")
        root = os.path.dirname(self.pocket)
        out = pp.notify_all({"t": "reopen", "title": "r"}, "https://tunnel.cush.rocks/", root=root)
        self.assertEqual(out["sent"], 1)
        self.assertEqual([r["path"] for r in self.svc.got], ["/sub/one"])
        self.svc.got.clear()
        out = pp.deliver(self.pocket, {"t": "pairing"}, "https://tunnel.cush.rocks/",
                         topic="pairing")
        self.assertEqual(sorted(r["path"] for r in self.svc.got), ["/sub/one", "/sub/two"])
        self.svc.got.clear()
        self.store.set_topics(one, [])
        pp.deliver(self.pocket, {"t": "invite"}, "https://tunnel.cush.rocks/", topic="invite")
        self.assertEqual([r["path"] for r in self.svc.got], ["/sub/two"])
        self.svc.got.clear()
        # A test (no topic) reaches everyone, even a subscription with none.
        pp.deliver(self.pocket, {"t": "test"}, "https://tunnel.cush.rocks/")
        self.assertEqual(len(self.svc.got), 2)
        # Re-subscribing keeps the choice; public() shows ids, never endpoints.
        self.store.add(dict(self.b1[2], endpoint=one), "Phone")
        pub = {p["id"]: p for p in self.store.public()}
        self.assertEqual(pub[pp.sub_id(one)]["topics"], [])
        self.assertEqual(pub[pp.sub_id(two)]["topics"], ["pairing", "invite"])
        self.assertNotIn("/sub/", json.dumps(self.store.public()))


if __name__ == "__main__":
    unittest.main()

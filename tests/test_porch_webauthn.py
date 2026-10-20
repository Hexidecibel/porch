"""Tests for lib/porch_webauthn.py: the strict CBOR subset, authenticatorData,
COSE keys, registration and assertion checks (one failing test per rule),
the options builders, and a registration + assertion captured from real
Chrome (virtual authenticator, tests/fixtures/webauthn/capture.mjs).
"""
import hashlib
import json
import os
import struct
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(_HERE, "..", "lib"), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import porch_webauthn as wa  # noqa: E402

HAVE = wa.available()
if HAVE:
    import webauthn_soft as soft  # noqa: E402
    from webauthn_soft import AT, BE, BS, ED, UP, UV, cbor_encode  # noqa: E402

RP = "pocket.tunnel.cush.rocks"
ORIGIN = "https://pocket.tunnel.cush.rocks"
CHAL = bytes(range(32))
FIXTURE = os.path.join(_HERE, "fixtures", "webauthn", "chrome-es256.json")


class Err:
    def assertCode(self, code, fn, *a, **kw):
        with self.assertRaises(wa.WebAuthnError) as cm:
            fn(*a, **kw)
        self.assertEqual(cm.exception.code, code, str(cm.exception))


class TestCBOR(Err, unittest.TestCase):
    def test_round_trips(self):
        if not HAVE:
            self.skipTest("cryptography")
        for v in (0, 23, 24, 255, 256, 65535, 65536, 2**32, 2**64 - 1, -1, -24, -25, -2**64,
                  b"", b"\x00" * 300, "", "héllo", [], [1, [2, [3]]], {}, {1: 2, -3: "x", "k": b"v"},
                  True, False, None, {"fmt": "none", "attStmt": {}, "authData": b"\x01" * 40}):
            self.assertEqual(wa.cbor_decode(cbor_encode(v)), v, v)

    def test_known_bytes(self):
        self.assertEqual(wa.cbor_decode(bytes.fromhex("a201020326")), {1: 2, 3: -7})
        self.assertEqual(wa.cbor_decode(bytes.fromhex("1a00010000")), 65536)
        self.assertEqual(wa.cbor_decode(bytes.fromhex("3bffffffffffffffff")), -2**64)

    def test_rejects_indefinite(self):
        for h in ("5f4101ff", "7f6161ff", "9f01ff", "bf0101ff"):
            self.assertCode("malformed_cbor", wa.cbor_decode, bytes.fromhex(h))

    def test_rejects_reserved_info(self):
        for h in ("1c", "1d", "1e", "5c"):
            self.assertCode("malformed_cbor", wa.cbor_decode, bytes.fromhex(h))

    def test_rejects_trailing(self):
        self.assertCode("malformed_cbor", wa.cbor_decode, bytes.fromhex("0100"))
        self.assertEqual(wa.cbor_decode_prefix(bytes.fromhex("0100"), 0), (1, 1))
        self.assertEqual(wa.cbor_decode_prefix(bytes.fromhex("ff01a0"), 1), (1, 2))

    def test_depth(self):
        self.assertEqual(wa.cbor_decode(b"\x81" * 8 + b"\x01"), [[[[[[[[1]]]]]]]])
        self.assertCode("malformed_cbor", wa.cbor_decode, b"\x81" * 9 + b"\x01")
        self.assertCode("malformed_cbor", wa.cbor_decode, b"\xa1\x01" * 9 + b"\x01")

    def test_item_limit(self):
        self.assertEqual(len(wa.cbor_decode(b"\x99\x01\xff" + b"\x00" * 511)), 511)
        self.assertCode("malformed_cbor", wa.cbor_decode, b"\x99\x02\x00" + b"\x00" * 512)

    def test_length_past_buffer(self):
        for h in ("430102", "6361", "83 01 02".replace(" ", ""), "a20102", "5affffffff00",
                  "9bffffffffffffffff00", "19ff", "1a0000"):
            self.assertCode("malformed_cbor", wa.cbor_decode, bytes.fromhex(h))

    def test_duplicate_keys(self):
        self.assertCode("malformed_cbor", wa.cbor_decode, bytes.fromhex("a201020103"))
        self.assertCode("malformed_cbor", wa.cbor_decode, bytes.fromhex("a2616101616102"))
        self.assertEqual(wa.cbor_decode(bytes.fromhex("a2010261310a")), {1: 2, "1": 10})

    def test_map_key_types(self):
        for h in ("a14101 01".replace(" ", ""), "a1f501", "a18001", "a1a001"):
            self.assertCode("malformed_cbor", wa.cbor_decode, bytes.fromhex(h))

    def test_tags_floats_simple(self):
        for h in ("c11a514b67b0", "d8184101", "f93c00", "fa3f800000", "fb3ff0000000000000",
                  "f7", "f0", "f820", "ff"):
            self.assertCode("malformed_cbor", wa.cbor_decode, bytes.fromhex(h))

    def test_bad_utf8(self):
        self.assertCode("malformed_cbor", wa.cbor_decode, bytes.fromhex("62c328"))

    def test_not_bytes(self):
        self.assertCode("malformed_cbor", wa.cbor_decode, "a0")


@unittest.skipUnless(HAVE, "python3-cryptography")
class TestAuthData(Err, unittest.TestCase):
    def setUp(self):
        self.a = soft.SoftAuthenticator(sign_count=7)

    def test_plain(self):
        ad = wa.parse_auth_data(self.a.auth_data(RP, UP | UV | BE | BS, 7))
        self.assertEqual(ad["rp_id_hash"], hashlib.sha256(RP.encode()).digest())
        self.assertEqual(ad["sign_count"], 7)
        self.assertTrue(ad["up"] and ad["uv"] and ad["be"] and ad["bs"])
        self.assertIsNone(ad["credential_id"])

    def test_attested(self):
        ad = wa.parse_auth_data(self.a.auth_data(RP, UP | UV | AT, 1, attested=True))
        self.assertEqual(ad["credential_id"], self.a.cred_id)
        self.assertEqual(ad["aaguid"], bytes(range(16)))
        self.assertEqual(ad["cose_key"], self.a.cose())
        self.assertEqual(ad["cose_raw"], cbor_encode(self.a.cose()))

    def test_attested_with_extensions(self):
        raw = self.a.auth_data(RP, UP | UV | AT | ED, 1, attested=True, extensions={"credProtect": 2})
        ad = wa.parse_auth_data(raw)
        self.assertEqual(ad["extensions"], {"credProtect": 2})
        self.assertEqual(ad["credential_id"], self.a.cred_id)

    def test_extensions_only(self):
        ad = wa.parse_auth_data(self.a.auth_data(RP, UP | ED, 1, extensions={"x": True}))
        self.assertEqual(ad["extensions"], {"x": True})

    def test_truncated(self):
        full = self.a.auth_data(RP, UP | UV | AT, 1, attested=True)
        self.assertCode("bad_auth_data", wa.parse_auth_data, full[:36])
        self.assertCode("bad_auth_data", wa.parse_auth_data, full[:37 + 10])
        self.assertCode("bad_auth_data", wa.parse_auth_data, full[:37 + 18 + 5])
        self.assertCode("malformed_cbor", wa.parse_auth_data, full[:-1])

    def test_trailing(self):
        self.assertCode("bad_auth_data", wa.parse_auth_data,
                        self.a.auth_data(RP, UP, 1, trailing=b"\x00"))
        self.assertCode("bad_auth_data", wa.parse_auth_data,
                        self.a.auth_data(RP, UP | AT, 1, attested=True, trailing=b"\xa0"))

    def test_ed_flag_without_map(self):
        self.assertCode("malformed_cbor", wa.parse_auth_data, self.a.auth_data(RP, UP | ED, 1))
        self.assertCode("bad_auth_data", wa.parse_auth_data,
                        self.a.auth_data(RP, UP | ED, 1, trailing=b"\x01"))

    def test_cred_id_length(self):
        base = hashlib.sha256(RP.encode()).digest() + bytes([UP | AT]) + struct.pack(">I", 0) + bytes(16)
        self.assertCode("bad_auth_data", wa.parse_auth_data,
                        base + struct.pack(">H", 1024) + b"\x00" * 1024 + cbor_encode(self.a.cose()))
        self.assertCode("bad_auth_data", wa.parse_auth_data,
                        base + struct.pack(">H", 0) + cbor_encode(self.a.cose()))
        ok = base + struct.pack(">H", 1023) + b"\x01" * 1023 + cbor_encode(self.a.cose())
        self.assertEqual(len(wa.parse_auth_data(ok)["credential_id"]), 1023)


@unittest.skipUnless(HAVE, "python3-cryptography")
class TestCose(Err, unittest.TestCase):
    def test_es256_and_rs256(self):
        self.assertEqual(wa.parse_cose_key(soft.SoftAuthenticator().cose())[0], -7)
        self.assertEqual(wa.parse_cose_key(soft.SoftAuthenticator(alg=-257).cose())[0], -257)

    def test_point_not_on_curve(self):
        k = soft.SoftAuthenticator().cose()
        k[-3] = bytes(31) + b"\x05"
        self.assertCode("unsupported_alg", wa.parse_cose_key, k)

    def test_unknown(self):
        for k in ({1: 1, 3: -8, -1: 6, -2: b"\x00" * 32},  # Ed25519
                  {1: 2, 3: -35, -1: 2, -2: b"\x00" * 48, -3: b"\x00" * 48},
                  {1: 2, 3: -7, -1: 2, -2: b"\x00" * 32, -3: b"\x00" * 32},
                  {1: 2, 3: -7, -1: 1, -2: b"\x00" * 31, -3: b"\x00" * 32},
                  {1: 3, 3: -37}, {}, []):
            self.assertCode("unsupported_alg", wa.parse_cose_key, k)

    def test_rsa_under_2048(self):
        self.assertCode("unsupported_alg", wa.parse_cose_key,
                        soft.SoftAuthenticator(alg=-257, rsa_bits=1024).cose())
        k = soft.SoftAuthenticator(alg=-257).cose()
        k[-1] = b"\x00" + k[-1][1:]          # leading zero: under 2048 bits
        self.assertCode("unsupported_alg", wa.parse_cose_key, k)


@unittest.skipUnless(HAVE, "python3-cryptography")
class TestRegistration(Err, unittest.TestCase):
    def reg(self, a=None, **kw):
        a = a or soft.SoftAuthenticator()
        return wa.verify_registration(a.register(CHAL, ORIGIN, RP, **kw), CHAL, ORIGIN, RP)

    def test_es256(self):
        a = soft.SoftAuthenticator()
        r = wa.verify_registration(a.register(CHAL, ORIGIN, RP), CHAL, ORIGIN, RP)
        self.assertEqual(r["id"], soft.b64u(a.cred_id))
        self.assertEqual(r["alg"], -7)
        self.assertEqual(r["sign_count"], 0)
        self.assertEqual(r["aaguid"], "00010203-0405-0607-0809-0a0b0c0d0e0f")
        self.assertEqual(r["transports"], ["internal"])
        self.assertFalse(r["be"] or r["bs"])
        json.dumps(r)
        wa.load_public_key(r["alg"], r["public_key"])

    def test_rs256(self):
        r = self.reg(soft.SoftAuthenticator(alg=-257))
        self.assertEqual(r["alg"], -257)

    def test_be_bs_and_transports_filtered(self):
        r = self.reg(flags=UP | UV | AT | BE | BS, transports=["hybrid", "bogus", "internal"])
        self.assertTrue(r["be"] and r["bs"])
        self.assertEqual(r["transports"], ["hybrid", "internal"])

    def test_packed_attstmt_ignored(self):
        r = self.reg(fmt="packed", att_stmt={"alg": -7, "sig": b"\x00" * 70, "x5c": [b"junk"]})
        self.assertEqual(r["alg"], -7)

    def test_extensions(self):
        self.assertEqual(self.reg(extensions={"credProtect": 1})["alg"], -7)

    def test_wrong_type(self):
        self.assertCode("bad_client_data", self.reg, client={"type": "webauthn.get"})

    def test_client_data_not_json(self):
        self.assertCode("bad_client_data", self.reg, client_raw=b"{nope")
        self.assertCode("bad_client_data", self.reg, client_raw=b"\xff\xfe")
        self.assertCode("bad_client_data", self.reg, client_raw=b"[]")

    def test_challenge(self):
        self.assertCode("challenge_mismatch", self.reg, client={"challenge": soft.b64u(b"x" * 32)})
        self.assertCode("challenge_mismatch", self.reg, client={"challenge": 5})
        a = soft.SoftAuthenticator()
        self.assertCode("challenge_mismatch", wa.verify_registration,
                        a.register(CHAL, ORIGIN, RP), b"", ORIGIN, RP)

    def test_origin(self):
        self.assertCode("origin_mismatch", self.reg, client={"origin": "https://evil.tunnel.cush.rocks"})
        self.assertCode("origin_mismatch", self.reg, client={"origin": ORIGIN + "/"})

    def test_cross_origin(self):
        self.assertCode("origin_mismatch", self.reg, client={"crossOrigin": True})
        self.assertEqual(self.reg(client={"crossOrigin": ...})["alg"], -7)

    def test_top_origin(self):
        self.assertCode("origin_mismatch", self.reg, client={"topOrigin": ORIGIN})

    def test_rp_id_hash(self):
        self.assertCode("rp_mismatch", self.reg, rp_id_hash=hashlib.sha256(b"tunnel.cush.rocks").digest())

    def test_rp_id_param(self):
        a = soft.SoftAuthenticator()
        self.assertCode("rp_mismatch", wa.verify_registration,
                        a.register(CHAL, ORIGIN, RP), CHAL, ORIGIN, "cush.rocks")

    def test_up_off(self):
        self.assertCode("no_up", self.reg, flags=UV | AT)

    def test_uv_off(self):
        self.assertCode("no_uv", self.reg, flags=UP | AT)

    def test_at_off(self):
        self.assertCode("bad_auth_data", self.reg, flags=UP | UV)

    def test_unknown_alg(self):
        self.assertCode("unsupported_alg", self.reg, cose={1: 1, 3: -8, -1: 6, -2: b"\x00" * 32})

    def test_rsa_under_2048(self):
        self.assertCode("unsupported_alg", self.reg, soft.SoftAuthenticator(alg=-257, rsa_bits=1024))

    def test_shape(self):
        self.assertCode("bad_credential", self.reg, type_="password")
        self.assertCode("bad_credential", self.reg, raw_id=soft.b64u(b"other"))
        self.assertCode("bad_credential", self.reg, raw_id="not base64!")
        self.assertCode("bad_credential", self.reg, cred_id=b"different-id")
        a = soft.SoftAuthenticator()
        c = a.register(CHAL, ORIGIN, RP)
        del c["rawId"]
        self.assertCode("bad_credential", wa.verify_registration, c, CHAL, ORIGIN, RP)
        c = a.register(CHAL, ORIGIN, RP)
        del c["response"]["attestationObject"]
        self.assertCode("bad_credential", wa.verify_registration, c, CHAL, ORIGIN, RP)
        self.assertCode("bad_credential", wa.verify_registration, None, CHAL, ORIGIN, RP)

    def test_attestation_object_shape(self):
        a = soft.SoftAuthenticator()
        c = a.register(CHAL, ORIGIN, RP)
        c["response"]["attestationObject"] = soft.b64u(cbor_encode({"fmt": "none", "attStmt": {}}))
        self.assertCode("malformed_cbor", wa.verify_registration, c, CHAL, ORIGIN, RP)
        c["response"]["attestationObject"] = soft.b64u(cbor_encode([1]) + b"\x00")
        self.assertCode("malformed_cbor", wa.verify_registration, c, CHAL, ORIGIN, RP)


@unittest.skipUnless(HAVE, "python3-cryptography")
class TestAssertion(Err, unittest.TestCase):
    def setUp(self):
        self.a = soft.SoftAuthenticator()
        self.rec = wa.verify_registration(self.a.register(CHAL, ORIGIN, RP), CHAL, ORIGIN, RP)
        self.ch = os.urandom(32)

    def check(self, cred=None, rec=None, **kw):
        cred = cred or self.a.assertion(self.ch, ORIGIN, RP, **kw)
        return wa.verify_assertion(cred, self.rec if rec is None else rec, self.ch, ORIGIN, RP,
                                   self.a.user_handle)

    def test_es256(self):
        r = self.check()
        self.assertEqual(r, {"id": self.rec["id"], "sign_count": 1, "be": False, "bs": False})

    def test_rs256(self):
        self.a = soft.SoftAuthenticator(alg=-257)
        self.rec = wa.verify_registration(self.a.register(CHAL, ORIGIN, RP), CHAL, ORIGIN, RP)
        self.assertEqual(self.check()["sign_count"], 1)

    def test_list_of_records(self):
        other = dict(self.rec, id=soft.b64u(b"zzz"))
        self.assertEqual(self.check(rec=[other, self.rec])["sign_count"], 1)

    def test_unknown_credential(self):
        self.assertCode("unknown_credential", self.check, rec=[])
        self.assertCode("unknown_credential", self.check, cred_id=b"nope")

    def test_wrong_type(self):
        self.assertCode("bad_client_data", self.check, client={"type": "webauthn.create"})

    def test_challenge(self):
        cred = self.a.assertion(os.urandom(32), ORIGIN, RP)
        self.assertCode("challenge_mismatch", self.check, cred)

    def test_origin(self):
        self.assertCode("origin_mismatch", self.check, client={"origin": "https://pocket.tunnel.cush.rocks:8443"})
        self.assertCode("origin_mismatch", self.check, client={"crossOrigin": True})
        self.assertCode("origin_mismatch", self.check, client={"topOrigin": "https://x"})

    def test_rp_id_hash(self):
        self.assertCode("rp_mismatch", self.check, rp_id_hash=bytes(32))

    def test_up_uv(self):
        self.assertCode("no_up", self.check, flags=UV)
        self.assertCode("no_uv", self.check, flags=UP)

    def test_bad_signature(self):
        self.assertCode("bad_signature", self.check, flip_sig=True)

    def test_rs256_bad_signature(self):
        self.a = soft.SoftAuthenticator(alg=-257)
        self.rec = wa.verify_registration(self.a.register(CHAL, ORIGIN, RP), CHAL, ORIGIN, RP)
        self.assertCode("bad_signature", self.check, flip_sig=True)

    def test_signature_over_other_client_data(self):
        good = self.a.assertion(self.ch, ORIGIN, RP)
        other = self.a.assertion(self.ch, ORIGIN, RP, client={"extra": "x"})
        good["response"]["clientDataJSON"] = other["response"]["clientDataJSON"]
        self.assertCode("bad_signature", self.check, good)

    def test_other_key(self):
        imposter = soft.SoftAuthenticator(cred_id=self.a.cred_id, user_handle=self.a.user_handle)
        self.assertCode("bad_signature", self.check, imposter.assertion(self.ch, ORIGIN, RP))

    def test_counter(self):
        self.rec["sign_count"] = 5
        self.assertCode("counter_regressed", self.check, count=5)
        self.assertCode("counter_regressed", self.check, count=4)
        self.assertCode("counter_regressed", self.check, count=0)
        self.assertEqual(self.check(count=6)["sign_count"], 6)

    def test_counter_zero_zero(self):
        self.rec["sign_count"] = 0
        self.assertEqual(self.check(count=0)["sign_count"], 0)
        self.assertEqual(self.check(count=0)["sign_count"], 0)

    def test_counter_checked_after_signature(self):
        self.rec["sign_count"] = 5
        self.assertCode("bad_signature", self.check, count=1, flip_sig=True)

    def test_user_handle(self):
        self.assertCode("user_mismatch", self.check, user_handle=b"someone-else")
        self.assertEqual(self.check(user_handle=None)["id"], self.rec["id"])
        cred = self.a.assertion(self.ch, ORIGIN, RP)
        self.assertCode("user_mismatch", wa.verify_assertion, cred, self.rec, self.ch, ORIGIN, RP, None)

    def test_stored_key_mismatch(self):
        self.assertCode("unsupported_alg", self.check, rec=dict(self.rec, alg=-257))
        self.assertCode("unsupported_alg", self.check, rec=dict(self.rec, public_key="AAAA"))

    def test_shape(self):
        cred = self.a.assertion(self.ch, ORIGIN, RP)
        cred["response"]["signature"] = "%%%"
        self.assertCode("bad_credential", self.check, cred)
        cred = self.a.assertion(self.ch, ORIGIN, RP)
        cred["type"] = "x"
        self.assertCode("bad_credential", self.check, cred)
        cred = self.a.assertion(self.ch, ORIGIN, RP)
        cred["response"]["authenticatorData"] = soft.b64u(b"\x00" * 20)
        self.assertCode("bad_auth_data", self.check, cred)


class TestOptions(unittest.TestCase):
    def test_creation(self):
        o = wa.creation_options(b"\x01" * 32, RP, b"\x02" * 16, brand="Porch",
                                exclude=["abc", {"id": "def", "transports": ["internal", "x"]}])
        self.assertEqual(o["rp"], {"id": RP, "name": "Porch"})
        self.assertEqual(o["user"], {"id": wa.b64u(b"\x02" * 16), "name": "owner@" + RP,
                                     "displayName": "Porch owner"})
        self.assertEqual(o["challenge"], wa.b64u(b"\x01" * 32))
        self.assertEqual([p["alg"] for p in o["pubKeyCredParams"]], [-7, -257])
        self.assertEqual(o["authenticatorSelection"]["residentKey"], "preferred")
        self.assertEqual(o["authenticatorSelection"]["userVerification"], "required")
        self.assertEqual(o["attestation"], "none")
        self.assertEqual(o["timeout"], 120000)
        self.assertEqual(o["excludeCredentials"], [
            {"type": "public-key", "id": "abc"},
            {"type": "public-key", "id": "def", "transports": ["internal"]}])
        json.dumps(o)

    def test_request(self):
        o = wa.request_options(b"\x03" * 32, RP, allow=["abc"])
        self.assertEqual(o, {"challenge": wa.b64u(b"\x03" * 32), "rpId": RP,
                             "allowCredentials": [{"type": "public-key", "id": "abc"}],
                             "userVerification": "required", "timeout": 120000})

    def test_error_codes(self):
        self.assertIn("counter_regressed", wa.ERROR_CODES)
        with self.assertRaises(AssertionError):
            wa.WebAuthnError("made_up")


@unittest.skipUnless(HAVE, "python3-cryptography")
class TestChromeVector(unittest.TestCase):
    """A real registration + assertion from Chrome's virtual authenticator."""

    def setUp(self):
        with open(FIXTURE) as f:
            self.v = json.load(f)

    def test_verifies(self):
        v = self.v
        reg = wa.verify_registration(v["registration"], wa.unb64u(v["reg_challenge"]),
                                     v["origin"], v["rp_id"])
        self.assertEqual(reg["alg"], -7)
        self.assertIn("internal", reg["transports"])
        r = wa.verify_assertion(v["assertion"], reg, wa.unb64u(v["auth_challenge"]),
                                v["origin"], v["rp_id"], wa.unb64u(v["user_handle"]))
        self.assertEqual(r["id"], reg["id"])
        self.assertTrue(r["sign_count"] > reg["sign_count"] or r["sign_count"] == 0)

    def test_wrong_challenge_fails(self):
        v = self.v
        with self.assertRaises(wa.WebAuthnError) as cm:
            wa.verify_registration(v["registration"], wa.unb64u(v["auth_challenge"]),
                                   v["origin"], v["rp_id"])
        self.assertEqual(cm.exception.code, "challenge_mismatch")


if __name__ == "__main__":
    unittest.main()

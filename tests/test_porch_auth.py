"""Unit tests for lib/porch_auth.py, the one owner/identity check. Stdlib
only; every devices.json is a temp file."""

import email.message
import hashlib
import json
import os
import sys
import tempfile
import time
import types
import unittest
import urllib.parse

_LIB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib")
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
import porch_auth as pa  # noqa: E402

HOST = "wedding.tunnel.cush.rocks"
HTOK = "h" * 43
LEGACY = "l" * 43


def sha(t):
    return hashlib.sha256(t.encode()).hexdigest()


def iso(epoch):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def req(cookies=None, host=HOST, path="/", xfh=None):
    m = email.message.Message()
    if host:
        m["Host"] = host
    if xfh:
        m["X-Forwarded-Host"] = xfh
    if cookies:
        m["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return types.SimpleNamespace(headers=m, path=path, client_address=("127.0.0.1", 1))


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "devices.json")
        pa.reset_cache()
        pa.ACCEPT_LEGACY = None
        self.addCleanup(setattr, pa, "ACCEPT_LEGACY", None)
        self.addCleanup(os.environ.pop, pa.LEGACY_ENV, None)

    def write(self, devices):
        with open(self.path, "w") as f:
            json.dump({"devices": devices}, f) if not isinstance(devices, str) else f.write(devices)
        st = os.stat(self.path)
        os.utime(self.path, ns=(st.st_atime_ns, st.st_mtime_ns + 10_000_000))

    def admin(self, **kw):
        now = time.time()
        d = {"id": "dev_a", "type": "browser", "role": "admin", "token_sha256": sha(LEGACY),
             "host_tokens": [{"sha256": sha(HTOK), "host": HOST,
                              "created_at": iso(now), "expires_at": iso(now + 3600)}]}
        d.update(kw)
        return d

    def owner(self, cookies, **kw):
        return pa.request_is_owner(req(cookies, **kw), self.path)


class PorchHostTest(Case):
    def test_valid(self):
        self.write([self.admin()])
        self.assertTrue(self.owner({"porch_host": HTOK}))
        cred = pa.owner_credential(req({"porch_host": HTOK}), self.path)
        self.assertEqual(cred[0], "porch_host")
        self.assertEqual(pa.owner_cookie(req({"porch_host": HTOK}), self.path), HTOK)
        # Host header with a port still matches; a bad token never does.
        self.assertTrue(self.owner({"porch_host": HTOK}, host=HOST + ":443"))
        self.assertFalse(self.owner({"porch_host": "nope"}))

    def test_wrong_host(self):
        self.write([self.admin()])
        self.assertFalse(self.owner({"porch_host": HTOK}, host="music.tunnel.cush.rocks"))
        self.assertFalse(self.owner({"porch_host": HTOK}, xfh="evil.tunnel.cush.rocks"))
        self.assertFalse(self.owner({"porch_host": HTOK}, host=None))

    def test_expired_token(self):
        now = time.time()
        d = self.admin()
        d["host_tokens"][0]["expires_at"] = iso(now - 1)
        self.write([d])
        self.assertFalse(self.owner({"porch_host": HTOK}))
        # Expiry is re-checked per call, not when the file was cached.
        self.write([self.admin()])
        self.assertTrue(self.owner({"porch_host": HTOK}))
        self.assertFalse(pa.request_is_owner(req({"porch_host": HTOK}), self.path, now=now + 7200))

    def test_expired_device(self):
        self.write([self.admin(expires_at=iso(time.time() - 1))])
        self.assertFalse(self.owner({"porch_host": HTOK}))
        self.write([self.admin(expires_at="garbage")])
        self.assertFalse(self.owner({"porch_host": HTOK}))

    def test_revoked_device(self):
        self.write([self.admin(revoked=True)])
        self.assertFalse(self.owner({"porch_host": HTOK}))
        self.assertFalse(self.owner({"cush_auth": LEGACY}))

    def test_non_admin(self):
        self.write([self.admin(role="guest")])
        self.assertFalse(self.owner({"porch_host": HTOK}))
        # The token is still a valid identity; it just isn't the owner.
        devs = pa.load_devices(self.path)
        self.assertIsNotNone(pa.find_host_token_device(devs, HTOK, HOST))
        self.write([self.admin(type="tunnel")])
        self.assertFalse(self.owner({"porch_host": HTOK}))

    def test_authserver_uses_the_same_validator(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("as_pa", os.path.join(_LIB, "authserver.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertIs(mod.porch_auth, pa)
        self.assertIs(mod.host_token_entry, pa.host_token_entry)
        self.assertIs(mod.epoch_from_iso, pa.epoch_from_iso)
        devs = [self.admin()]
        self.assertIs(mod.find_host_token_device(devs, HTOK, HOST), devs[0])


class LegacyTest(Case):
    def test_flag_on_by_default(self):
        self.write([self.admin()])
        self.assertTrue(pa.accept_legacy())
        self.assertTrue(self.owner({"cush_auth": LEGACY}))
        self.assertEqual(pa.owner_credential(req({"cush_auth": LEGACY}), self.path)[0], "cush_auth")

    def test_flag_off_refuses(self):
        self.write([self.admin()])
        os.environ[pa.LEGACY_ENV] = "0"
        self.assertFalse(pa.accept_legacy())
        self.assertFalse(self.owner({"cush_auth": LEGACY}))
        self.assertTrue(self.owner({"porch_host": HTOK}))     # porch_host unaffected
        os.environ[pa.LEGACY_ENV] = "1"
        self.assertTrue(self.owner({"cush_auth": LEGACY}))
        pa.ACCEPT_LEGACY = False
        self.assertFalse(self.owner({"cush_auth": LEGACY}))

    def test_legacy_rules(self):
        now = time.time()
        self.write([
            self.admin(expires_at=iso(now + 100)),
            {"type": "browser", "role": "guest", "token_sha256": sha("g")},
            {"type": "tunnel", "apps": ["*"], "token_sha256": sha("t")},
            {"type": "browser", "apps": ["*"], "token_sha256": sha("old")},       # predates roles
            {"type": "browser", "apps": ["x.cush.rocks"], "token_sha256": sha("narrow")},
        ])
        self.assertTrue(pa.is_owner_token(LEGACY, self.path))
        self.assertFalse(pa.is_owner_token(LEGACY, self.path, now=now + 101))
        self.assertFalse(pa.is_owner_token("g", self.path))
        self.assertFalse(pa.is_owner_token("t", self.path))
        self.assertTrue(pa.is_owner_token("old", self.path))
        self.assertFalse(pa.is_owner_token("narrow", self.path))
        self.assertFalse(pa.is_owner_token("", self.path))


class FailClosedTest(Case):
    def test_corrupt_missing_or_wrong_shape(self):
        for bad in ("{not json", "[]", '{"devices": "x"}', "\xff\xfe"):
            self.write(bad)
            self.assertFalse(self.owner({"porch_host": HTOK, "cush_auth": LEGACY}), bad)
            self.assertFalse(pa.auth_configured(self.path), bad)
        os.unlink(self.path)
        self.assertFalse(self.owner({"porch_host": HTOK, "cush_auth": LEGACY}))
        self.assertFalse(pa.request_is_owner(req({"cush_auth": LEGACY}), ""))

    def test_corrupt_after_good_drops_the_cache(self):
        self.write([self.admin()])
        self.assertTrue(self.owner({"porch_host": HTOK}))
        self.write("{truncated")
        self.assertFalse(self.owner({"porch_host": HTOK}))


class StartUrlTest(Case):
    def test_start_url(self):
        u = pa.start_url(req(path="/?x=1"))
        self.assertTrue(u.startswith(f"https://{HOST}/__porch/start?rd="))
        rd = urllib.parse.parse_qs(urllib.parse.urlsplit(u).query)["rd"][0]
        self.assertEqual(rd, f"https://{HOST}/?x=1")
        # Hostile paths fall back to "/".
        rd = urllib.parse.parse_qs(urllib.parse.urlsplit(pa.start_url(req(path="//evil.com/")))
                                   .query)["rd"][0]
        self.assertEqual(rd, f"https://{HOST}/")
        for host in ("127.0.0.1:8080", "localhost", "", "a b.com"):
            self.assertIsNone(pa.start_url(req(host=host)), host)
        self.assertIsNone(pa.start_url(req(xfh="other.cush.rocks")))

    def test_signin_url(self):
        self.assertIsNone(pa.signin_url(req(), ""))               # no registry
        self.write([self.admin(role="guest")])
        self.assertIsNone(pa.signin_url(req(), self.path))        # no owner to sign in as
        self.write([self.admin()])
        self.assertIsNotNone(pa.signin_url(req(), self.path))
        self.assertIsNone(pa.signin_url(req({"porch_host": HTOK}), self.path))   # already owner


if __name__ == "__main__":
    unittest.main()

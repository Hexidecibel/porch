"""secretstore.py: inf:// / op:// through cush_secrets (faked), error hygiene, file://."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import cush_secrets  # noqa: E402
from porch_setup.redact import Redactor  # noqa: E402
from porch_setup.secretstore import SecretError, SecretNotFound, SecretStore, default_ref  # noqa: E402

VALUE = "tok-VERY-SECRET-0042"
REF = "inf://prod/porch/DNS_TOKEN"


class FakeBackend:
    def __init__(self):
        self.data = {}
        self.raise_on = {}
        self.calls = []

    def read(self, ref):
        self.calls.append(("read", ref))
        if "read" in self.raise_on:
            raise self.raise_on["read"]
        if ref not in self.data:
            raise cush_secrets.SecretsRefNotFound(f"{ref} not found")
        return self.data[ref]

    def item_upsert(self, ref, value):
        self.calls.append(("upsert", ref))
        if "upsert" in self.raise_on:
            raise self.raise_on["upsert"]
        self.data[ref] = value


class SecretStoreBackendTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.red = Redactor()
        self.be = FakeBackend()
        self.s = SecretStore(redactor=self.red, file_root=self.tmp.name + "/s", backend=self.be)

    def test_put_get_registers_with_redactor(self):
        self.s.put(REF, VALUE)
        self.assertEqual(self.be.data[REF], VALUE)
        self.assertIn(VALUE, self.red)
        fresh_red = Redactor()
        s2 = SecretStore(redactor=fresh_red, file_root=self.tmp.name + "/s", backend=self.be)
        self.assertEqual(s2.get(REF), VALUE)
        self.assertIn(VALUE, fresh_red)
        self.assertTrue(s2.exists(REF))
        self.assertFalse(s2.exists("op://cush/porch/missing"))

    def test_errors_never_echo_ref_or_value(self):
        leaky = f"{REF} {VALUE} stderr: denied"
        cases = [
            ("read", cush_secrets.SecretsRefNotFound(leaky), SecretNotFound, "not found"),
            ("read", cush_secrets.SecretsAuthError(leaky), SecretError, "infisical.env"),
            ("read", cush_secrets.SecretsAccessError(leaky), SecretError, "refused access"),
            ("read", ValueError(leaky), SecretError, "malformed"),
            ("read", RuntimeError(leaky), SecretError, "read failed"),
            ("upsert", cush_secrets.SecretsAuthError(leaky), SecretError, "not authenticated"),
            ("upsert", cush_secrets.SecretsRefNotFound(leaky), SecretError, "write failed"),
        ]
        for op, exc, want, text in cases:
            self.be.raise_on = {op: exc}
            with self.assertRaises(want) as cm:
                if op == "read":
                    self.s.get(REF)
                else:
                    self.s.put(REF, VALUE)
            msg = str(cm.exception)
            self.assertIn(text, msg, (op, exc))
            self.assertNotIn("DNS_TOKEN", msg)
            self.assertNotIn(VALUE, msg)
            self.assertIsNone(cm.exception.__cause__)
        self.be.raise_on = {"read": cush_secrets.SecretsAuthError("x")}
        with self.assertRaises(SecretError) as cm:
            self.s.get("op://cush/porch/token")
        self.assertIn("op.env", str(cm.exception))

    def test_empty_backend_value_is_not_found(self):
        self.be.data[REF] = ""
        with self.assertRaises(SecretNotFound):
            self.s.get(REF)

    def test_remember_shadows_backend(self):
        self.s.remember(REF, VALUE)
        self.assertEqual(self.s.get(REF), VALUE)
        self.assertEqual(self.be.calls, [])

    def test_bad_refs_and_file_errors_dont_echo(self):
        for bad in (VALUE, "http://x/" + VALUE, "file:///etc/" + VALUE):
            with self.assertRaises(SecretError) as cm:
                self.s.get(bad)
            self.assertNotIn(VALUE, str(cm.exception))
        with self.assertRaises(SecretNotFound) as cm:
            self.s.get("file://~/.config/porch/secrets/" + VALUE)
        self.assertNotIn(VALUE, str(cm.exception))

    def test_default_ref(self):
        self.assertEqual(default_ref("dns_token"), "file://~/.config/porch/secrets/dns_token")
        self.assertEqual(default_ref("dns_token", backend="inf"), "inf://prod/porch/DNS_TOKEN")
        with self.assertRaises(SecretError):
            default_ref("../x")

    def test_real_dispatch_module_is_the_default(self):
        s = SecretStore(redactor=self.red, file_root=self.tmp.name + "/s")
        self.assertIs(s._backend_mod(), cush_secrets)


if __name__ == "__main__":
    unittest.main()

"""Tests for lib/porch_setup/haproxy_diff.py."""

import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "lib"))

from porch_setup import haproxy_diff as hd  # noqa: E402

TEMPLATE = """\
frontend www-https
\tbind *:443 ssl crt /etc/ssl/x.pem
\tacl host_auth hdr(host) -i auth.example.org   # the auth host
\thttp-request set-var(txn.t) req.cook(a)
\thttp-request replace-header Cookie '^(.*);x=[^;]*$' '\\1'
\tuse_backend cush_auth if host_auth
\tuse_backend tunnel if tunnel
backend tunnel
\tserver frp_http 127.0.0.1:7080
"""


def live(**repl):
    t = TEMPLATE
    for a, b in repl.items():
        t = t.replace(a.replace("_NL_", "\n"), b)
    return t


class NormalizeTest(unittest.TestCase):
    def test_comments_and_whitespace(self):
        self.assertEqual(hd.normalize("  acl  a   hdr(host) -i x   # c"), "acl a hdr(host) -i x")
        self.assertEqual(hd.normalize("\t# only a comment"), "")
        self.assertEqual(hd.normalize('http-response set-header H "a  #b"'),
                         'http-response set-header H "a  #b"')
        self.assertEqual(hd.normalize("a b#c"), "a b#c")

    def test_key(self):
        self.assertEqual(hd.key("bind *:443 ssl crt x"), "bind *:443")
        self.assertEqual(hd.key("http-request set-header X-A 1"), "http-request set-header X-A")


class DiffTest(unittest.TestCase):
    def test_identical_and_extras_ok(self):
        extra = TEMPLATE.replace("\tuse_backend tunnel if tunnel\n",
                                 "\tacl other hdr(host) -i other\n\tuse_backend o if other\n"
                                 "\tuse_backend tunnel if tunnel\n")
        extra = "global\n\tdaemon\n" + extra + "backend o\n\tserver o 127.0.0.1:1\n"
        r = hd.diff(TEMPLATE, extra)
        self.assertTrue(r.ok, r.text())
        self.assertEqual(r.counts()["checked"], 7)

    def test_missing_different_order(self):
        r = hd.diff(TEMPLATE, live(**{"\tserver frp_http 127.0.0.1:7080\n": "",
                                     "x.pem": "x.pem crt /etc/ssl/y.pem"}))
        self.assertEqual([f.directive for f in r.missing], ["server frp_http 127.0.0.1:7080"])
        self.assertEqual(len(r.different), 1)
        self.assertIn("y.pem", r.different[0].live)
        swapped = live(**{"\tuse_backend cush_auth if host_auth_NL_\tuse_backend tunnel if tunnel\n":
                          "\tuse_backend tunnel if tunnel\n\tuse_backend cush_auth if host_auth\n"})
        r = hd.diff(TEMPLATE, swapped)
        self.assertEqual(len(r.order), 1)
        self.assertFalse(r.ok)
        # gate after strip is an order problem too
        swapped = live(**{"\thttp-request set-var(txn.t) req.cook(a)\n": "",
                          "\tuse_backend cush_auth": "\thttp-request set-var(txn.t) req.cook(a)\n\tuse_backend cush_auth"})
        self.assertEqual(len(hd.diff(TEMPLATE, swapped).order), 1)

    def test_missing_section(self):
        r = hd.diff(TEMPLATE, live(**{"backend tunnel_NL_\tserver frp_http 127.0.0.1:7080\n": ""}))
        self.assertEqual(len(r.missing), 1)
        self.assertEqual(r.missing[0].section, "backend tunnel")

    def test_allowlist(self):
        lv = live(**{"x.pem": "x.pem crt /etc/ssl/y.pem"})
        r = hd.diff(TEMPLATE, lv, ["frontend www-https: bind *:443 ssl crt /etc/ssl/x.pem crt "])
        self.assertTrue(r.ok)
        self.assertEqual(len(r.allowed), 1)
        r = hd.diff(TEMPLATE, lv, ["backend tunnel: bind *:443"])
        self.assertFalse(r.ok)
        self.assertIn("1 different", r.text())

    def test_duplicates_matched_once(self):
        t = "frontend f\n\thttp-request a\n\thttp-request a\n"
        self.assertEqual(len(hd.diff(t, "frontend f\n\thttp-request a\n").missing), 1)
        self.assertTrue(hd.diff(t, "frontend f\n\thttp-request a\n\tx\n\thttp-request a\n").ok)


if __name__ == "__main__":
    unittest.main()

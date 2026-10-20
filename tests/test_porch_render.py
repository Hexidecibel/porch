"""Tests for lib/porch_setup/render.py, cmd_render.py and the templates."""

import io
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "lib"))

import porch_config  # noqa: E402
from porch_setup import cmd_render, haproxy_diff, render  # noqa: E402

CFG = porch_config.load(env={"PORCH_CONFIG": "none"})
# The fresh profile's cert path follows $PORCH_CERT_DIR (else ~/.local/...);
# pin it so the golden file does not depend on whoever runs the tests.
CERT_DIR = "/home/porch/.local/share/porch/certs"
os.environ["PORCH_CERT_DIR"] = CERT_DIR
GOLDEN = os.path.join(_HERE, "fixtures", "haproxy-porch.golden.cfg")


def other_cfg():
    d = tempfile.mkdtemp()
    p = os.path.join(d, "porch.toml")
    with open(p, "w") as f:
        f.write('[domain]\nroot = "porch.example.org"\n')
    try:
        return porch_config.load(path=p, env={})
    finally:
        shutil.rmtree(d)


class HaproxyRenderTest(unittest.TestCase):
    def test_golden_cush_rocks_defaults(self):
        with open(GOLDEN) as f:
            golden = f.read()
        self.assertEqual(render.render_haproxy(CFG), golden,
                         "regenerate: PORCH_CONFIG=none bin/porch render haproxy "
                         "--out tests/fixtures/haproxy-porch.golden.cfg (after checking the diff)")

    def test_fresh_profile_policy(self):
        text = render.render_haproxy(other_cfg())
        self.assertIn('Strict-Transport-Security "max-age=31536000"', text)
        self.assertNotIn("includeSubDomains", text)
        self.assertNotIn("preload", text)
        self.assertNotIn("cush_auth=", text)          # no edge gate / cookie strip
        self.assertNotIn("needs_auth", text)
        self.assertNotIn("acl cushroot", text)        # apex untouched
        self.assertIn("acl landing_auth path_beg /auth/", text)
        self.assertIn("server tunnelroot 127.0.0.1:9473", text)
        self.assertIn("acl tunnel hdr_end(host) -i .tunnel.porch.example.org", text)
        self.assertIn(f"crt {CERT_DIR}/porch-porch.example.org.pem", text)
        self.assertNotIn("cush.rocks", text)
        self.assertNotIn("${", text)

    def test_adopt_profile_and_relay(self):
        text = render.render_haproxy(CFG, "adopt", relay=True)
        for needle in ("acl cushroot hdr(host) -i cush.rocks", "server tunnelroot 127.0.0.1:8091",
                       "needs_auth", "cush_auth=[^;]*$'", "backend cushroot",
                       "bind 127.0.0.1:9477 ssl crt /etc/ssl/ssl-certs/cush.rocks accept-proxy",
                       "bind 127.0.0.1:9476 accept-proxy"):
            self.assertIn(needle, text)
        self.assertNotIn("landing_auth", text)
        # public paths: two maps, odd paths fall back to the gate, no identity headers
        for needle in ("map_beg(/etc/haproxy/maps/cush-public.map)",
                       "map_str(/etc/haproxy/maps/cush-public-exact.map)",
                       "bool(1) if public_path !odd_path",
                       "!letsencrypt-acl !porch_path !public_ok\n"):
            self.assertIn(needle, text)
        self.assertEqual(text.count("-m found } !tunnel !public_ok\n"), 3)
        self.assertLess(text.index("set-var(txn.cush_public)"), text.index("set-header X-Cush-Device "))
        # the gate must come before the cookie strip, both before tunnel routing
        self.assertLess(text.index("set-var(txn.cush_tok)"), text.index("replace-header Cookie"))
        self.assertLess(text.index("replace-header Cookie"), text.index("use_backend tunnel if tunnel"))

    def test_unknown_profile(self):
        with self.assertRaises(render.RenderError):
            render.render_haproxy(CFG, "nope")

    @unittest.skipUnless(shutil.which("haproxy") and shutil.which("openssl"), "needs haproxy + openssl")
    def test_haproxy_accepts_both_profiles(self):
        with tempfile.TemporaryDirectory() as d:
            key, crt, pem = (os.path.join(d, n) for n in ("k.pem", "c.pem", "t.pem"))
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                            "ec_paramgen_curve:prime256v1", "-nodes", "-subj", "/CN=t", "-days", "1",
                            "-keyout", key, "-out", crt], check=True, capture_output=True)
            with open(pem, "w") as f, open(crt) as c, open(key) as k:
                f.write(c.read() + k.read())
            for m in ("cush-grants.map", "cush-protected.map", "cush-identity.map",
                      "cush-public.map", "cush-public-exact.map"):
                open(os.path.join(d, m), "w").close()
            import porch_errors
            errs = os.path.join(d, "errors")
            porch_errors.write(errs)
            for prof in ("fresh", "adopt"):
                cfgf = os.path.join(d, f"{prof}.cfg")
                with open(cfgf, "w") as f:
                    f.write(render.render_haproxy(CFG, prof, cert_path=pem, maps_dir=d, relay=True,
                                                  errors_dir=errs))
                p = subprocess.run(["haproxy", "-c", "-f", cfgf], capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, prof + ": " + p.stderr)


class FrpsAndUnitsTest(unittest.TestCase):
    def test_frps_toml(self):
        text = render.render_frps(other_cfg(), "pw-123456")
        data = tomllib.loads(text)
        self.assertEqual(data["subDomainHost"], "tunnel.porch.example.org")
        self.assertEqual(data["proxyBindAddr"], "127.0.0.1")
        self.assertEqual(data["bindPort"], 7000)
        self.assertEqual(data["webServer"]["addr"], "127.0.0.1")
        self.assertEqual(data["webServer"]["password"], "pw-123456")
        self.assertEqual(data["httpPlugins"][0]["ops"], ["Login", "NewProxy", "NewWorkConn", "Ping"])
        self.assertNotIn("vhostHTTPSPort", data)
        with self.assertRaises(render.RenderError):
            render.render_frps(CFG, 'bad"quote')

    def test_units(self):
        units = render.render_units(other_cfg())
        self.assertEqual(sorted(units), ["porch-auth.service", "porch-frps.service",
                                         "porch-landing.service", "porch-shortener.service",
                                         "porch-status.service"])
        self.assertIn("--port 9512", units["porch-auth.service"])
        self.assertIn("ExecReload=/bin/kill -HUP $MAINPID", units["porch-auth.service"])
        self.assertIn("--port 9473", units["porch-landing.service"])
        self.assertIn("WantedBy=default.target", units["porch-frps.service"])
        self.assertNotIn("porch-landing.service", render.render_units(CFG, "adopt"))
        # fresh: no edge gate, so no maps and no haproxy admin socket for the auth server
        self.assertIn(" --no-maps", units["porch-auth.service"])
        self.assertNotIn("--maps-dir", units["porch-auth.service"])
        self.assertIn("--maps-dir /etc/haproxy/maps",
                      render.render_units(CFG, "adopt")["porch-auth.service"])


class CmdRenderTest(unittest.TestCase):
    def run_cmd(self, argv, cfg=CFG):
        out = io.StringIO()
        rc = cmd_render.main(argv, cfg=cfg, out=out)
        return rc, out.getvalue()

    def test_against_reports_and_exit_codes(self):
        live = render.render_haproxy(CFG, "adopt")
        live = live.replace("\tuse_backend tunnel if tunnel\n",
                            "\tuse_backend radarr if radarr\n\tuse_backend tunnel if tunnel\n")
        live += "\nbackend radarr\n\tserver radarr 127.0.0.1:7878\n"
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "haproxy.cfg")
            with open(p, "w") as f:
                f.write(live)
            rc, out = self.run_cmd(["haproxy", "--profile", "adopt", "--against", p])
            self.assertEqual(rc, 0, out)
            self.assertIn("0 missing, 0 different, 0 out of order", out)
            with open(p, "w") as f:
                f.write(live.replace("\tserver panel 127.0.0.1:9471 check\n", ""))
            rc, out = self.run_cmd(["haproxy", "--profile", "adopt", "--against", p, "--json"])
            self.assertEqual(rc, 5)
            self.assertIn('"missing": 1', out)

    def test_out_files(self):
        with tempfile.TemporaryDirectory() as d:
            rc, _ = self.run_cmd(["frps", "--out", os.path.join(d, "frps.toml")])
            self.assertEqual(rc, 0)
            self.assertEqual(os.stat(os.path.join(d, "frps.toml")).st_mode & 0o777, 0o600)
            rc, out = self.run_cmd(["units", "--out", os.path.join(d, "units")])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(os.path.join(d, "units", "porch-auth.service")))
            rc, out = self.run_cmd(["haproxy"])
            self.assertIn("frontend www-https", out)


if __name__ == "__main__":
    unittest.main()

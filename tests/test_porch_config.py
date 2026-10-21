"""Tests for lib/porch_config.py and lib/porch-config.sh."""

import os
import subprocess
import sys
import tempfile
import tomllib
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_LIB = os.path.join(_HERE, "..", "lib")
sys.path.insert(0, _LIB)
import porch_config  # noqa: E402

NOFILE = {"PORCH_CONFIG": "none"}


class TempConfig:
    def __init__(self, text):
        self.text = text

    def __enter__(self):
        fd, self.path = tempfile.mkstemp(suffix=".toml")
        with os.fdopen(fd, "w") as f:
            f.write(self.text)
        return self.path

    def __exit__(self, *a):
        os.unlink(self.path)


class DefaultsTest(unittest.TestCase):
    def test_defaults_are_cush_rocks(self):
        c = porch_config.load(env=NOFILE)
        self.assertIsNone(c.source)
        self.assertEqual(c.root, "cush.rocks")
        self.assertEqual(c.tunnel_base, "tunnel.cush.rocks")
        self.assertEqual(c.auth_host, "auth.cush.rocks")
        self.assertEqual(c.panel_host, "panel.cush.rocks")
        self.assertEqual(c.landing_host, "tunnel.cush.rocks")
        self.assertEqual(c.cookie_domain, ".cush.rocks")
        self.assertEqual(c.frp_addr, "tunnel.cush.rocks")
        self.assertEqual(c.frp_port, 7000)
        self.assertEqual(c.brand, "Porch")
        self.assertEqual(c.default_rd, "https://grab.cush.rocks/")
        self.assertEqual(c.protected_apps, ("grab.cush.rocks",))
        self.assertIn("velo.cush.rocks", c.known_apps)
        self.assertEqual(c.tunnel_url("drop"), "https://drop.tunnel.cush.rocks")
        self.assertEqual(c.auth_url("/auth/"), "https://auth.cush.rocks/auth/")

    def test_missing_default_file_is_fine(self):
        old = porch_config.DEFAULT_PATH
        porch_config.DEFAULT_PATH = "/nonexistent/porch.toml"
        try:
            self.assertEqual(porch_config.load(env={}).root, "cush.rocks")
        finally:
            porch_config.DEFAULT_PATH = old

    def test_example_equals_defaults(self):
        ex = os.path.join(_HERE, "..", "config", "porch.toml.example")
        self.assertEqual(porch_config.load(path=ex, env={}).as_dict(),
                         porch_config.load(env=NOFILE).as_dict())

    def test_mini_parser_matches_tomllib_on_example(self):
        ex = os.path.join(_HERE, "..", "config", "porch.toml.example")
        with open(ex) as f:
            text = f.read()
        self.assertEqual(porch_config._mini_toml(text), tomllib.loads(text))

    def test_read_only(self):
        c = porch_config.load(env=NOFILE)
        with self.assertRaises(AttributeError):
            c.root = "evil.com"


class FileAndEnvTest(unittest.TestCase):
    def test_root_derives_everything(self):
        with TempConfig('[domain]\nroot = "Example.ORG"\n') as p:
            c = porch_config.load(path=p, env={})
        self.assertEqual(c.root, "example.org")
        self.assertEqual(c.tunnel_base, "tunnel.example.org")
        self.assertEqual(c.auth_host, "auth.example.org")
        self.assertEqual(c.panel_host, "panel.example.org")
        self.assertEqual(c.landing_host, "tunnel.example.org")
        self.assertEqual(c.cookie_domain, ".example.org")
        self.assertEqual(c.frp_addr, "tunnel.example.org")
        # The cush.rocks gated apps do not leak into another domain.
        self.assertEqual(c.protected_apps, ())
        self.assertEqual(c.known_apps, ())
        self.assertEqual(c.default_rd, "https://tunnel.example.org/")

    def test_explicit_keys(self):
        text = ('[domain]\nroot = "example.org"\ntunnel_base = "t.example.org"\n'
                'auth_host = "login.example.org"\n[server]\nfrp_port = 7100\n'
                '[auth]\nprotected_apps = ["wiki.example.org"]\n'
                'default_rd = "https://wiki.example.org"\n')
        with TempConfig(text) as p:
            c = porch_config.load(path=p, env={})
        self.assertEqual(c.tunnel_base, "t.example.org")
        self.assertEqual(c.landing_host, "t.example.org")
        self.assertEqual(c.auth_host, "login.example.org")
        self.assertEqual(c.frp_port, 7100)
        self.assertEqual(c.protected_apps, ("wiki.example.org",))
        self.assertEqual(c.default_rd, "https://wiki.example.org/")

    def test_env_overrides_file(self):
        with TempConfig('[domain]\nroot = "example.org"\n') as p:
            c = porch_config.load(path=p, env={"PORCH_DOMAIN": "example.net",
                                               "PORCH_FRP_PORT": "7001",
                                               "PORCH_TUNNEL_BASE": "x.example.net"})
        self.assertEqual(c.root, "example.net")
        self.assertEqual(c.auth_host, "auth.example.net")
        self.assertEqual(c.tunnel_base, "x.example.net")
        self.assertEqual(c.frp_port, 7001)

    def test_porch_config_env_path(self):
        with TempConfig('[domain]\nroot = "example.org"\n') as p:
            self.assertEqual(porch_config.load(env={"PORCH_CONFIG": p}).root, "example.org")
        with self.assertRaises(porch_config.ConfigError):
            porch_config.load(env={"PORCH_CONFIG": "/nonexistent/x.toml"})

    def test_get_caches_and_reset(self):
        porch_config.reset()
        a = porch_config.get()
        self.assertIs(a, porch_config.get())
        porch_config.reset()


class RejectTest(unittest.TestCase):
    BAD_HOSTS = [
        "https://example.org", "example.org/", "example.org/x", "*.example.org",
        "example.org:443", "example.org.", "localhost", "exa mple.org",
        "-bad.example.org", "bad-.example.org", "1.2.3.4", "example..org",
        "ex_ample.org", "", "a" * 64 + ".org", "exam\nple.org", "évil.org",
    ]

    def test_bad_root(self):
        for h in self.BAD_HOSTS:
            with self.subTest(h=h):
                with self.assertRaises(porch_config.ConfigError):
                    porch_config.load(env={"PORCH_CONFIG": "none", "PORCH_DOMAIN": h or " "})

    def test_bad_hosts_in_file(self):
        for key in ("tunnel_base", "auth_host", "panel_host", "landing_host"):
            for h in ("https://x.cush.rocks", "*.cush.rocks", "x.cush.rocks/a"):
                with self.subTest(key=key, h=h), TempConfig(f'[domain]\n{key} = "{h}"\n') as p:
                    with self.assertRaises(porch_config.ConfigError):
                        porch_config.load(path=p, env={})

    def test_cookie_domain_rules(self):
        for cd in ("cush.rocks", ".*.cush.rocks", ".evil.com", "..cush.rocks", ".rocks/x"):
            with self.subTest(cd=cd), TempConfig(f'[domain]\ncookie_domain = "{cd}"\n') as p:
                with self.assertRaises(porch_config.ConfigError):
                    porch_config.load(path=p, env={})

    def test_auth_host_must_be_under_root(self):
        with TempConfig('[domain]\nroot = "example.org"\nauth_host = "auth.evil.com"\n'
                        'cookie_domain = ".org"\n') as p:
            with self.assertRaises(porch_config.ConfigError):
                porch_config.load(path=p, env={})

    def test_bad_port(self):
        for v in ("0", "65536", "abc", "70 00", "-1"):
            with self.subTest(v=v):
                with self.assertRaises(porch_config.ConfigError):
                    porch_config.load(env={"PORCH_CONFIG": "none", "PORCH_FRP_PORT": v})
        with TempConfig("[server]\nfrp_port = true\n") as p:
            with self.assertRaises(porch_config.ConfigError):
                porch_config.load(path=p, env={})

    def test_unknown_keys_and_sections(self):
        for text in ("[domian]\nroot = \"x.org\"\n", "[domain]\nrooot = \"x.org\"\n",
                     "[domain]\nroot = 5\n", "not toml at all ===\n"):
            with self.subTest(text=text), TempConfig(text) as p:
                with self.assertRaises(porch_config.ConfigError):
                    porch_config.load(path=p, env={})

    def test_auth_lists(self):
        for text in ('[auth]\nprotected_apps = ["grab.evil.com"]\n',
                     '[auth]\nprotected_apps = ["a.b.cush.rocks"]\n',
                     '[auth]\nprotected_apps = ["auth.cush.rocks"]\n',
                     '[auth]\nknown_apps = "grab.cush.rocks"\n',
                     '[auth]\ndefault_rd = "http://grab.cush.rocks/"\n',
                     '[auth]\ndefault_rd = "https://grab.cush.rocks.evil.com/"\n',
                     '[auth]\ndefault_rd = "https://grab.cush.rocks/<script>"\n',
                     '[auth]\ndefault_rd = "https://grab.cush.rocks//evil.com"\n'):
            with self.subTest(text=text), TempConfig(text) as p:
                with self.assertRaises(porch_config.ConfigError):
                    porch_config.load(path=p, env={})

    def test_bad_brand(self):
        for b in ("", "<b>x</b>", "a" * 41, "x\ny"):
            with self.subTest(b=b):
                with self.assertRaises(porch_config.ConfigError):
                    porch_config.load(env={"PORCH_CONFIG": "none", "PORCH_BRAND": b or "\n"})


class AdoptSectionTest(unittest.TestCase):
    def test_defaults_off_and_empty(self):
        c = porch_config.load(env=NOFILE)
        self.assertIs(c.localhost_bypass, False)
        self.assertEqual(c.adopt_allow, ())
        self.assertEqual(c.as_dict()["adopt"], {"localhost_bypass": False, "allow": []})
        self.assertEqual(c.install_mode, "fresh")

    def test_adopt_mode_defaults_bypass_on(self):
        with TempConfig('[install]\nmode = "adopt"\n') as p:
            c = porch_config.load(path=p, env={})
        self.assertEqual((c.install_mode, c.localhost_bypass), ("adopt", True))
        with TempConfig('[install]\nmode = "adopt"\n[adopt]\nlocalhost_bypass = false\n') as p:
            self.assertFalse(porch_config.load(path=p, env={}).localhost_bypass)
        with TempConfig('[install]\nmode = "legacy"\n') as p:
            with self.assertRaises(porch_config.ConfigError):
                porch_config.load(path=p, env={})

    def test_parse_and_reject(self):
        with TempConfig('[adopt]\nlocalhost_bypass = true\nallow = ["backend x: server a"]\n') as p:
            c = porch_config.load(path=p, env={})
        self.assertIs(c.localhost_bypass, True)
        self.assertEqual(c.adopt_allow, ("backend x: server a",))
        for bad in ('[adopt]\nlocalhost_bypass = "yes"\n', '[adopt]\nallow = "x"\n',
                    '[adopt]\nallow = [""]\n', '[adopt]\nother = 1\n'):
            with TempConfig(bad) as p:
                with self.assertRaises(porch_config.ConfigError, msg=bad):
                    porch_config.load(path=p, env={})


class CliTest(unittest.TestCase):
    SCRIPT = os.path.join(_LIB, "porch_config.py")

    def run_cli(self, *args, env=None):
        e = {k: v for k, v in os.environ.items() if not k.startswith("PORCH_")}
        e.update(env or {"PORCH_CONFIG": "none"})
        return subprocess.run([sys.executable, self.SCRIPT, *args], env=e,
                              capture_output=True, text=True)

    def test_get(self):
        r = self.run_cli("get", "domain.tunnel_base")
        self.assertEqual((r.returncode, r.stdout), (0, "tunnel.cush.rocks\n"))
        r = self.run_cli("get", "domain.nope")
        self.assertEqual(r.returncode, 2)

    def test_check_bad_exits_1(self):
        r = self.run_cli("get", "domain.root",
                         env={"PORCH_CONFIG": "none", "PORCH_DOMAIN": "https://x.org"})
        self.assertEqual(r.returncode, 1)
        self.assertIn("bare hostname", r.stderr)

    def test_shell_sourcing(self):
        e = {k: v for k, v in os.environ.items() if not k.startswith("PORCH_")}
        e.update({"PORCH_CONFIG": "none", "PORCH_DOMAIN": "example.org"})
        sh = os.path.join(_LIB, "porch-config.sh")
        r = subprocess.run(["bash", "-c", f'source "{sh}"; echo "$PORCH_TUNNEL_BASE $PORCH_AUTH_HOST $PORCH_FRP_PORT"'],
                           env=e, capture_output=True, text=True)
        self.assertEqual(r.stdout, "tunnel.example.org auth.example.org 7000\n")
        e["PORCH_DOMAIN"] = "bad/domain"
        r = subprocess.run(["bash", "-c", f'source "{sh}"; echo reached'],
                           env=e, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("reached", r.stdout)


class BootstrapDomainTest(unittest.TestCase):
    def setUp(self):
        import importlib.machinery
        import importlib.util
        path = os.path.join(_HERE, "..", "bin", "bootstrap")
        loader = importlib.machinery.SourceFileLoader("bootstrap_mod", path)
        spec = importlib.util.spec_from_loader("bootstrap_mod", loader)
        self.mod = importlib.util.module_from_spec(spec)
        loader.exec_module(self.mod)
        self.mod.log = lambda m: None
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "porch.toml")

    def test_writes_valid_domain(self):
        self.mod.write_domain_config(self.path, {
            "root": "example.org", "tunnel_base": "tunnel.example.org",
            "auth_host": "auth.example.org", "cookie_domain": ".example.org"})
        c = porch_config.load(path=self.path, env={})
        self.assertEqual((c.root, c.tunnel_base), ("example.org", "tunnel.example.org"))

    def test_refuses_bad_or_existing(self):
        self.mod.write_domain_config(self.path, {"root": 'x.org"\n[auth]\nknown_apps = ["a.x.org"]'})
        self.mod.write_domain_config(self.path, {"root": "https://x.org"})
        self.assertFalse(os.path.exists(self.path))
        self.assertFalse(os.path.exists(self.path + ".tmp"))
        with open(self.path, "w") as f:
            f.write("# mine\n")
        self.mod.write_domain_config(self.path, {"root": "example.org"})
        with open(self.path) as f:
            self.assertEqual(f.read(), "# mine\n")


class SiteRenderTest(unittest.TestCase):
    def read_site(self, name):
        with open(os.path.join(_HERE, "..", "site", name)) as f:
            return f.read()

    def test_raw_installers_never_point_at_the_author_box(self):
        porch = self.read_site("porch.sh")
        self.assertNotIn("cush.rocks", porch)
        self.assertIn(f'PORCH_TARBALL="${{PORCH_TARBALL:-{porch_config.RELEASE_TARBALL_URL}}}"', porch)
        self.assertIn(f'INSTALLER_URL="{porch_config.RAW_INSTALLER_URL}"', porch)
        client = self.read_site("install.sh")
        self.assertNotIn("cush.rocks", client)
        self.assertIn(f'PORCH_AUTH_URL="${{PORCH_AUTH_URL:-${{CUSH_AUTH_URL:-{porch_config.LANDING_MARK}}}}}"',
                      client)

    def test_rendered_installers_use_the_landing_host(self):
        o = porch_config.load(env={"PORCH_CONFIG": "none", "PORCH_DOMAIN": "example.org"})
        porch = porch_config.site_render(self.read_site("porch.sh"), o)
        self.assertIn('PORCH_TARBALL="${PORCH_TARBALL:-https://tunnel.example.org/porch.tar.gz}"', porch)
        self.assertIn('INSTALLER_URL="https://tunnel.example.org/porch.sh"', porch)
        client = porch_config.site_render(self.read_site("install.sh"), o)
        self.assertIn('PORCH_AUTH_URL="${PORCH_AUTH_URL:-${CUSH_AUTH_URL:-https://tunnel.example.org}}"', client)
        self.assertIn('PORCH_REPO_TARBALL="${PORCH_REPO_TARBALL:-${CUSH_REPO_TARBALL:-'
                      'https://tunnel.example.org/porch.tar.gz}}"', client)
        # the author's own box renders to its own landing page too
        d = porch_config.load(env=NOFILE)
        self.assertIn("https://tunnel.cush.rocks/porch.tar.gz",
                      porch_config.site_render(self.read_site("porch.sh"), d))

    def test_identity_on_default_and_swap_on_other(self):
        root = os.path.join(_HERE, "..", "site")
        d = porch_config.load(env=NOFILE)
        o = porch_config.load(env={"PORCH_CONFIG": "none", "PORCH_DOMAIN": "example.org"})
        with open(os.path.join(root, "index.html")) as f:
            text = f.read()
        self.assertEqual(porch_config.site_render(text, d), text)
        for name in ("index.html", "install.sh", "porch.sh"):
            with open(os.path.join(root, name)) as f:
                text = f.read()
            out = porch_config.site_render(text, o)
            self.assertNotIn("https://tunnel.cush.rocks", out)
            self.assertNotIn("https://panel.cush.rocks", out)
            self.assertNotIn(porch_config.LANDING_MARK, out)
            self.assertNotIn("github.com/Hexidecibel", out)
            self.assertNotIn("raw.githubusercontent.com", out)
        swapped = porch_config.site_render(
            "https://tunnel.cush.rocks https://panel.cush.rocks https://auth.cush.rocks/x", o)
        self.assertEqual(swapped, "https://tunnel.example.org https://panel.example.org "
                                  "https://auth.example.org/x")


if __name__ == "__main__":
    unittest.main()

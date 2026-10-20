"""An invalid Porch config fails loudly; nothing falls back to a literal domain.

porch_config's built-in defaults (cush.rocks when there is no file) are fine:
what must never happen is a try/except that swaps a broken config for a
hardcoded host (pocket's passkey rpId, push claim, links, guest links,
`porch door ls`).
"""

import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_LIB = os.path.join(_HERE, "..", "lib")
sys.path.insert(0, _LIB)

import door_state  # noqa: E402
import pocket_links  # noqa: E402
import porch_config  # noqa: E402
from porch_setup import cmd_door  # noqa: E402

BAD = '[domain]\nroot = "not a host!"\n'
GOOD = '[domain]\nroot = "example.org"\n'


class ConfigFallbacks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.bad = os.path.join(self.tmp.name, "bad.toml")
        with open(self.bad, "w") as f:
            f.write(BAD)
        self.good = os.path.join(self.tmp.name, "good.toml")
        with open(self.good, "w") as f:
            f.write(GOOD)
        self.addCleanup(porch_config.reset)

    def use(self, path):
        env = {k: v for k, v in os.environ.items() if not k.startswith("PORCH_")}
        env["PORCH_CONFIG"] = path
        p = mock.patch.dict(os.environ, env, clear=True)
        p.start()
        self.addCleanup(p.stop)
        porch_config.reset()
        return env

    def test_bad_config_raises(self):
        self.use(self.bad)
        with self.assertRaises(porch_config.ConfigError):
            door_state.guest_url("d1", "tok")
        with self.assertRaises(porch_config.ConfigError):
            pocket_links.tunnel_url("d1")

    def test_good_config_is_used(self):
        self.use(self.good)
        self.assertEqual(door_state.guest_url("d1", "tok"), "https://d1.tunnel.example.org/?k=tok")
        self.assertEqual(pocket_links.tunnel_url("d1"), "https://d1.tunnel.example.org/")
        self.use("none")   # built-in defaults
        self.assertEqual(door_state.guest_url("d1", "t"), "https://d1.tunnel.cush.rocks/?k=t")

    def test_porch_door_ls_exits_1(self):
        self.use(self.bad)
        err = io.StringIO()
        with redirect_stderr(err):
            rc = cmd_door.main(["--state-dir", self.tmp.name, "ls"], out=io.StringIO())
        self.assertEqual(rc, 1)
        self.assertIn("invalid Porch config", err.getvalue())

    def test_door_state_cli_summary_exits_1(self):
        env = self.use(self.bad)
        env["_PORCH_DOOR_SPEC"] = '{"expires": null, "rules": {"guest": "abcdefghijklmnopqrstuv"}}'
        r = subprocess.run([sys.executable, os.path.join(_LIB, "door_state.py"), "summary", "d1"],
                           env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("invalid Porch config", r.stderr)
        self.assertNotIn("cush.rocks", r.stdout)

    def test_pocketserver_refuses_to_start(self):
        env = self.use(self.bad)
        r = subprocess.run([sys.executable, os.path.join(_LIB, "pocketserver.py"),
                            "--port", "1", "--dir", os.path.join(self.tmp.name, "pk"),
                            "--no-auth-watcher", "--no-cli-token"],
                           env=env, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("invalid Porch config", r.stderr)

    def test_pocket_push_claim_has_no_literal_fallback(self):
        import pocketserver
        self.use(self.bad)

        class H:
            push_claim = None
        with self.assertRaises(porch_config.ConfigError):
            pocketserver.PocketHandler._push_claim(H())
        self.use(self.good)
        self.assertEqual(pocketserver.PocketHandler._push_claim(H()), "https://tunnel.example.org/")


if __name__ == "__main__":
    unittest.main()

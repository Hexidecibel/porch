"""Tests for bin/porch and lib/porch_setup/cli.py."""

import contextlib
import io as stdio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
LIB = os.path.join(_REPO, "lib")
sys.path.insert(0, LIB)

import porch_config  # noqa: E402
from porch_setup import cli  # noqa: E402
from porch_setup.engine import Check, Input, Step  # noqa: E402
from porch_setup.redact import Redactor  # noqa: E402
from porch_setup.runner import FakeRunner  # noqa: E402

PORCH = os.path.join(_REPO, "bin", "porch")
CFG = porch_config.load(env={"PORCH_CONFIG": "none"})
TOKEN = "cli-SECRET-0123456789"


class Rec(Step):
    def __init__(self, sid, seen, requires=()):
        self.id, self.title, self.requires, self.seen = sid, sid, tuple(requires), seen

    def apply(self, ctx):
        self.seen.append(self.id)
        ctx.record_undo("noop", id=self.id)
        return {}

    def verify(self, ctx):
        return [Check(self.id in self.seen, f"{self.id}.ok", "ran")]

    def undo(self, ctx, entry):
        self.seen.append("undo-" + entry["id"])


class Domain(Rec):
    INPUTS = (Input("domain", "text", "Domain?", flag="--domain"),
              Input("apex", "bool", "Apex?", flag="--apex", default=False),
              Input("dns_token", "secret", "DNS token", flag="--dns-token-ref", env="PORCH_DNS_TOKEN"))

    def apply(self, ctx):
        self.seen.append(("domain", ctx.input("domain"), ctx.input("apex"), ctx.secret("dns_token")))
        return super().apply(ctx)


class CliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.env = {"PORCH_SETUP_DIR": os.path.join(self.tmp, "data"), "PORCH_CONFIG": "none"}
        self.seen = []

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def main(self, argv, steps=None, env=None):
        out, err = stdio.StringIO(), stdio.StringIO()
        kw = {"runner": FakeRunner(), "cfg": CFG, "redactor": Redactor(),
              "secrets_dir": os.path.join(self.tmp, "secrets"), "sleep": lambda s: None}
        with contextlib.redirect_stderr(err):
            rc = cli.main(argv, steps=steps, env=env or self.env, out=out, ctx_kwargs=kw)
        return rc, out.getvalue(), err.getvalue()

    def steps(self):
        return [Rec("a", self.seen), Rec("b", self.seen, ("a",)), Rec("c", self.seen, ("b",))]

    def test_run_status_json_and_idempotent(self):
        steps = self.steps()
        rc, out, err = self.main(["setup", "--non-interactive"], steps)
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.seen, ["a", "b", "c"])
        rc, out, _ = self.main(["setup", "--status", "--json"], steps)
        st = json.loads(out)
        self.assertEqual([s["status"] for s in st["steps"]], ["done"] * 3)
        rc, _, _ = self.main(["setup", "--non-interactive"], steps)
        self.assertEqual(rc, 0)
        self.assertEqual(self.seen, ["a", "b", "c"])
        rc, out, _ = self.main(["setup", "--status"], steps)
        self.assertIn("a ", out)
        self.assertIn("done", out)

    def test_only_from_until_rollback_to(self):
        steps = self.steps()
        self.assertEqual(self.main(["setup", "--non-interactive", "--until", "a"], steps)[0], 0)
        self.assertEqual(self.seen, ["a"])
        self.assertEqual(self.main(["setup", "--non-interactive", "--only", "b,c"], steps)[0], 0)
        self.assertEqual(self.seen, ["a", "b", "c"])
        rc, _, err = self.main(["setup", "--to", "b"], steps)
        self.assertEqual(rc, 2)
        self.assertIn("--to needs --rollback", err)
        self.assertEqual(self.main(["setup", "--rollback", "--to", "b"], steps)[0], 0)
        self.assertEqual(self.seen[3:], ["undo-c", "undo-b"])
        rc, _, err = self.main(["setup", "--only", "zzz"], steps)
        self.assertEqual(rc, 2)
        self.assertIn("unknown step", err)

    def test_ready_summary_after_a_complete_run(self):
        steps = [Rec("a", self.seen), Rec("pocket", self.seen, ("a",))]
        rc, out, _ = self.main(["setup", "--dry-run", "--non-interactive"], steps)
        self.assertNotIn("Your porch is ready", out)
        rc, out, err = self.main(["setup", "--non-interactive", "--until", "a"], steps)
        self.assertEqual(rc, 0, err)
        self.assertNotIn("Your porch is ready", out)
        rc, out, err = self.main(["setup", "--non-interactive"], steps)
        self.assertEqual(rc, 0, err)
        self.assertIn("Your porch is ready", out)
        self.assertIn("https://pocket.tunnel.cush.rocks/", out)
        self.assertIn("https://pocket.tunnel.cush.rocks/__porch/start?rd=%2F", out)
        self.assertIn("bin/tunnel 3000 myapp --bg", out)
        from porch_setup import web
        if web.qr_matrix("x") is not None:
            self.assertIn("\u2588", out)          # the terminal QR
        else:
            self.assertIn("python3-qrcode", out)
        # without the pocket step (other step sets) nothing extra is printed
        rc, out, _ = self.main(["setup", "--non-interactive"], self.steps())
        self.assertNotIn("Your porch is ready", out)

    def test_dry_run_changes_nothing(self):
        rc, _, _ = self.main(["setup", "--dry-run", "--non-interactive"], self.steps())
        self.assertEqual(rc, 0)
        self.assertEqual(self.seen, [])
        self.assertFalse(os.path.exists(os.path.join(self.env["PORCH_SETUP_DIR"], "porch-setup.json")))

    def test_input_flags_and_secret_env(self):
        steps = [Domain("d", self.seen)]
        rc, _, err = self.main(["setup", "--non-interactive"], steps)
        self.assertEqual(rc, 2)
        self.assertIn("--domain", err)
        self.assertIn("--dns-token-ref", err)
        self.assertNotIn("--apex", err)  # has a default

        env = dict(self.env, PORCH_DNS_TOKEN=TOKEN)
        rc, _, err = self.main(["setup", "--non-interactive", "--domain", "Example.COM", "--apex"],
                               steps, env=env)
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.seen[0], ("domain", "Example.COM", True, TOKEN))
        with open(os.path.join(self.env["PORCH_SETUP_DIR"], "porch-setup.json")) as f:
            text = f.read()
        self.assertNotIn(TOKEN, text)
        self.assertIn("file://~/.config/porch/secrets/dns_token", text)

    def test_secret_flag_takes_a_ref_never_a_value(self):
        steps = [Domain("d", self.seen)]
        rc, _, err = self.main(["setup", "--non-interactive", "--domain", "x.com",
                                "--dns-token-ref", TOKEN], steps)
        self.assertEqual(rc, 2)
        self.assertEqual(self.seen, [])
        self.assertNotIn(TOKEN, err)
        with open(os.path.join(self.env["PORCH_SETUP_DIR"], "porch-setup.json")) as f:
            self.assertNotIn(TOKEN, f.read())  # a value passed by mistake is not echoed
        p = cli.setup_parser(steps)
        self.assertIn("never the", p.format_help())

    def test_no_steps_installed(self):
        rc, out, _ = self.main(["setup"], [])
        self.assertEqual(rc, 0)
        self.assertIn("no setup steps", out)

    def test_module_commands_not_built(self):
        # Every module command is built now. Never call a real connect mode
        # here (it talks to the live router), and never start the wizard
        # (it would serve): --cert without --key is refused before binding.
        rc, out, err = self.main(["connect", "ipv6"])
        self.assertEqual(rc, 2)
        self.assertIn("coming later", out + err)
        rc, _, err = self.main(["setup", "--web", "--tls", "self-signed", "--cert", "x"], [])
        self.assertEqual(rc, 2)
        self.assertIn("--cert and --key go together", err)

    def test_passthrough(self):
        bin_dir = os.path.join(_REPO, "bin")
        self.assertEqual(cli.passthrough_target(["tunnel", "3000", "app"]),
                         (os.path.join(bin_dir, "tunnel"), [os.path.join(bin_dir, "tunnel"), "3000", "app"]))
        self.assertEqual(cli.passthrough_target(["auth", "list"])[1][1:], ["list"])
        self.assertTrue(cli.passthrough_target(["auth", "list"])[0].endswith("/auth-admin"))
        self.assertTrue(cli.passthrough_target(["server", "start"])[0].endswith("/start-server"))
        path, argv = cli.passthrough_target(["public", "add", "promo.cush.rocks", "/s/", "--app", "p"])
        self.assertTrue(path.endswith("/auth-admin"))
        self.assertEqual(argv[1:], ["public", "add", "promo.cush.rocks", "/s/", "--app", "p"])
        self.assertTrue(cli.passthrough_target(["server", "stop"])[0].endswith("/stop-server"))
        self.assertIsNone(cli.passthrough_target(["server", "reboot"]))
        self.assertIsNone(cli.passthrough_target(["rm"]))
        calls = []
        rc = cli.main(["drop", "photos", "--bg"], execv=lambda p, a: calls.append((p, a)))
        self.assertEqual(rc, 0)
        self.assertEqual(calls[0][1][1:], ["photos", "--bg"])
        for name in cli.PASSTHROUGH:
            self.assertTrue(os.path.exists(os.path.join(bin_dir, name)), name)

    def test_unknown_command(self):
        rc, _, err = self.main(["frobnicate"])
        self.assertEqual(rc, 2)
        self.assertIn("unknown command", err)


class BinPorchTest(unittest.TestCase):
    def run_porch(self, *args, env=None):
        e = dict(os.environ)
        e.update(env or {})
        return subprocess.run([PORCH, *args], capture_output=True, text=True, env=e, timeout=30)

    def test_help_and_status(self):
        p = self.run_porch("--help")
        self.assertEqual(p.returncode, 0)
        self.assertIn("setup", p.stdout)
        with tempfile.TemporaryDirectory() as d:
            p = self.run_porch("setup", "--status", "--json", env={"PORCH_SETUP_DIR": d})
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("steps", json.loads(p.stdout))
            # the built-in steps need --domain on a box without config/porch.toml;
            # the missing-input check runs before any step touches the system
            p = self.run_porch("setup", "--dry-run", "--non-interactive",
                               env={"PORCH_SETUP_DIR": d, "PORCH_CONFIG": "none"})
            self.assertEqual(p.returncode, 2, p.stderr)
            self.assertIn("--domain", p.stderr)
            self.assertEqual(os.listdir(d), [".porch-setup.lock"])
            # Without a terminal or --yes, connect refuses before it probes or
            # touches the router (stdin is not a tty under subprocess.run).
            p = self.run_porch("connect", "upnp", env={"PORCH_SETUP_DIR": d})
            self.assertEqual(p.returncode, 2)
            self.assertIn("--yes", p.stderr)
            self.assertNotIn("porch-setup.json", os.listdir(d))
        self.assertEqual(self.run_porch().returncode, 2)


class DoorCliTest(unittest.TestCase):
    """porch door against a temp state dir (never /tmp/tunnel-state)."""

    def setUp(self):
        import door_state
        from porch_setup import cmd_door
        self.ds, self.cmd = door_state, cmd_door
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "d1.json")
        self.write()

    def write(self, **extra):
        import time
        st = {"name": "d1", "type": "serve", "pid": os.getpid(), "port": 1,
              "started": int(time.time()), "expires": int(time.time()) + 600,
              "keep_alive": False, "rules": {}, "opens": 2, "last_open": None}
        st.update(extra)
        self.ds.write_state_atomic(self.path, st)

    def run_door(self, *argv, env=None):
        out, err = stdio.StringIO(), stdio.StringIO()
        old = {k: os.environ.get(k) for k in (env or {})}
        os.environ.update(env or {})
        try:
            with contextlib.redirect_stderr(err):
                rc = self.cmd.main(["--state-dir", self.dir, *argv], out=out)
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        return rc, out.getvalue(), err.getvalue()

    def state(self):
        return self.ds.read_state(self.path)

    def test_registered(self):
        self.assertIn("door", cli.MODULE_COMMANDS)
        out = stdio.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cli.main(["door"])
        self.assertEqual(rc, 2)
        self.assertIn("expire", out.getvalue())

    def test_ls(self):
        rc, out, _ = self.run_door("ls")
        self.assertEqual(rc, 0)
        self.assertIn("d1", out)
        self.assertIn("expires:", out)
        rc, out, _ = self.run_door("ls", "--json")
        rows = json.loads(out)
        self.assertEqual(rows[0]["name"], "d1")
        self.assertEqual(rows[0]["opens"], 2)
        self.assertFalse(rows[0]["proxy"])

    def test_expire_and_keep(self):
        rc, out, _ = self.run_door("expire", "d1", "2h")
        self.assertEqual(rc, 0, out)
        import time
        self.assertAlmostEqual(self.state()["expires"], time.time() + 7200, delta=10)
        rc, _, _ = self.run_door("keep", "d1")
        self.assertIsNone(self.state()["expires"])
        self.assertTrue(self.state()["keep_alive"])
        rc, _, _ = self.run_door("expire", "d1", "never")
        self.assertIsNone(self.state()["expires"])
        self.assertEqual(self.run_door("expire", "d1", "whenever")[0], 2)
        self.assertEqual(self.run_door("expire", "nope", "1h")[0], 1)
        self.assertEqual(self.run_door("expire", "../x", "1h")[0], 2)

    def test_rules_need_a_proxy(self):
        rc, _, err = self.run_door("rules", "d1", "--burn")
        self.assertEqual(rc, 3)
        self.assertIn("Relaunch", err)
        self.assertEqual(self.state()["rules"], {})

    def test_rules_live_on_a_proxied_door(self):
        self.write(proxy={"port": 1, "pid": os.getpid()}, rules={"max_opens": 2})
        rc, out, _ = self.run_door("rules", "d1", "--password", "--guest-link", "--burn",
                                   env={"PORCH_DOOR_PASSWORD": "door-pass-1"})
        self.assertEqual(rc, 0, out)
        r = self.state()["rules"]
        self.assertTrue(self.ds.verify_password("door-pass-1", r["password"]))
        self.assertEqual(r["max_opens"], 1)
        self.assertIn("?k=" + r["guest"], out)
        rc, out, _ = self.run_door("rules", "d1", "--no-password", "--no-guest-link", "--no-limit")
        self.assertEqual((rc, self.state()["rules"]), (0, {}))
        self.assertIn("none", out)

    def test_refusal_prints_the_exact_relaunch_command(self):
        hist = os.path.join(self.dir, "history.jsonl")
        with open(hist, "w") as f:
            f.write(json.dumps({"event": "start", "name": "d1", "cwd": "/srv/my site",
                                "cmd": ["/bin/bash", "/repo/bin/serve", "/srv/my site/dist",
                                        "d1"]}) + "\n")
        old = os.environ.get("PORCH_HISTORY_FILE")
        os.environ["PORCH_HISTORY_FILE"] = hist
        self.addCleanup(lambda: os.environ.pop("PORCH_HISTORY_FILE") if old is None
                        else os.environ.__setitem__("PORCH_HISTORY_FILE", old))
        rc, _, err = self.run_door("rules", "d1", "--max-opens", "3")
        self.assertEqual(rc, 3)
        self.assertIn("bin/status close d1", err)
        self.assertIn("cd '/srv/my site' && /repo/bin/serve '/srv/my site/dist' d1 "
                      "--max-opens 3 --bg", err)

    def fake_tunnel(self, answers=True):
        """A process named .../tunnel <port> d1 that, on SIGUSR1, records a
        live proxy in the state file the way bin/tunnel + doorproxy do."""
        import subprocess
        import sys as _sys
        script = os.path.join(self.dir, "tunnel")
        with open(script, "w") as f:
            f.write(f"""import json, os, signal, sys, time
sys.path.insert(0, {LIB!r})
import door_state
def on_usr1(*a):
    if {answers!r}:
        door_state.update_state({self.path!r},
            lambda s: s.__setitem__('proxy', {{'port': 1, 'pid': os.getpid()}}))
signal.signal(signal.SIGUSR1, on_usr1)
print('ready', flush=True)
while True:
    time.sleep(0.1)
""")
        p = subprocess.Popen([_sys.executable, script, "9999", "d1"], stdout=subprocess.PIPE)
        self.addCleanup(p.wait)
        self.addCleanup(p.kill)
        p.stdout.readline()
        return p

    def test_first_rule_switches_a_door_to_the_proxy_live(self):
        p = self.fake_tunnel()
        self.write(tunnel_pid=p.pid, proto="http")
        rc, out, err = self.run_door("rules", "d1", "--burn")
        self.assertEqual(rc, 0, err)
        self.assertIn("door proxy started", out)
        self.assertEqual(self.state()["rules"], {"max_opens": 1})

    def test_failed_switch_rolls_the_rules_back(self):
        p = self.fake_tunnel(answers=False)
        self.write(tunnel_pid=p.pid, proto="http")
        old = self.cmd.PROXY_WAIT
        self.cmd.PROXY_WAIT = 0.5
        self.addCleanup(setattr, self.cmd, "PROXY_WAIT", old)
        rc, _, err = self.run_door("rules", "d1", "--guest-link")
        self.assertEqual(rc, 4)
        self.assertIn("rolled back", err)
        self.assertEqual(self.state()["rules"], {})

    def test_no_live_switch_for_a_stranger_pid_or_tcp(self):
        self.write(tunnel_pid=os.getpid(), proto="http")      # alive, but not bin/tunnel
        self.assertEqual(self.run_door("rules", "d1", "--burn")[0], 3)
        p = self.fake_tunnel()
        self.write(tunnel_pid=p.pid, proto="tcp")
        rc, _, err = self.run_door("rules", "d1", "--burn")
        self.assertEqual(rc, 3)
        self.assertIn("tcp", err)
        self.assertEqual(self.state()["rules"], {})


if __name__ == "__main__":
    unittest.main()

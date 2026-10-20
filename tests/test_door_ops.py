"""Tests for lib/door_ops.py (the door control plane shared by the panel,
Pocket and porch door). Temp state dirs only; the "doors" are sleep
processes and a fake bin/tunnel, nothing real is launched or killed."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib")
sys.path.insert(0, LIB)

import door_ops  # noqa: E402
import door_state  # noqa: E402
import porch_config  # noqa: E402

DOMAIN = porch_config.load(env={"PORCH_CONFIG": "none"})
NAME = "dopstest-d1"


def quiet(msg):
    pass


class Case(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)

    def sleeper(self):
        p = subprocess.Popen(["sleep", "60"])
        self.addCleanup(p.wait)
        self.addCleanup(lambda: p.poll() is None and p.kill())
        return p

    def write(self, name=NAME, **extra):
        st = {"name": name, "type": "serve", "pid": os.getpid(), "port": 1,
              "started": int(time.time()), "expires": int(time.time()) + 600,
              "keep_alive": False, "rules": {}, "opens": 0, "last_open": None}
        st.update(extra)
        path = os.path.join(self.dir, f"{name}.json")
        door_state.write_state_atomic(path, st)
        return path

    def state(self, name=NAME):
        return door_state.read_state(os.path.join(self.dir, f"{name}.json"))


class ExpiryTest(Case):
    def test_extend_expire_keep(self):
        self.write()
        r = door_ops.extend(self.dir, NAME, 86400, log=quiet)
        self.assertAlmostEqual(r["expires"], time.time() + 600 + 86400, delta=5)
        r = door_ops.set_expires(self.dir, NAME, "never", log=quiet)
        self.assertTrue(r["never"] and r["keep_alive"])
        self.assertEqual(door_ops.extend(self.dir, NAME, log=quiet)["expires"], None)
        r = door_ops.toggle_keep(self.dir, NAME, log=quiet)
        self.assertFalse(r["never"])
        self.assertAlmostEqual(r["expires"], time.time() + 3600, delta=5)

    def test_refusals(self):
        with self.assertRaises(door_ops.DoorOpError) as c:
            door_ops.extend(self.dir, "nope", log=quiet)
        self.assertEqual((c.exception.status, c.exception.message), (404, "Tunnel not found"))
        with self.assertRaises(door_ops.DoorOpError) as c:
            door_ops.extend(self.dir, "../x", log=quiet)
        self.assertEqual(c.exception.status, 400)
        self.write()
        with self.assertRaises(door_ops.DoorOpError) as c:
            door_ops.set_expires(self.dir, NAME, "whenever", log=quiet)
        self.assertEqual(c.exception.status, 400)
        self.assertEqual(c.exception.reply()["status"], "error")


class StopTest(Case):
    def test_stop_all_excludes(self):
        a, b, c = self.sleeper(), self.sleeper(), self.sleeper()
        self.write("dopstest-a", pid=a.pid)
        self.write("dopstest-own", pid=b.pid)
        self.write("dopstest-pk", pid=c.pid, type="pocket")
        out = door_ops.stop_all(self.dir, exclude=("dopstest-own",), exclude_types=("pocket",),
                                log=quiet)
        self.assertEqual(out["stopped"], ["dopstest-a"])
        self.assertEqual(sorted(s["name"] for s in out["skipped"]),
                         ["dopstest-own", "dopstest-pk"])
        a.wait(5)
        self.assertIsNone(b.poll())
        self.assertIsNone(c.poll())
        self.assertFalse(os.path.exists(os.path.join(self.dir, "dopstest-a.json")))
        self.assertTrue(os.path.exists(os.path.join(self.dir, "dopstest-own.json")))

    def test_stop_without_state_is_unmanaged(self):
        self.assertEqual(door_ops.stop(self.dir, "dopstest-none", log=quiet),
                         {"status": "ok", "killed": 0})

    def test_list_cleans_dead_and_skips_junk(self):
        p = self.sleeper()
        self.write("dopstest-live", pid=p.pid)
        self.write("dopstest-dead", pid=2 ** 22 + 7)
        Path(self.dir, "junk.json").write_text("{not json")
        doors = door_ops.list_doors(self.dir, unmanaged=False, domain=DOMAIN, log=quiet)
        self.assertEqual([d["name"] for d in doors], ["dopstest-live"])
        self.assertEqual(doors[0]["url"], "https://dopstest-live.tunnel.cush.rocks")
        self.assertFalse(os.path.exists(os.path.join(self.dir, "dopstest-dead.json")))


class RulesTest(Case):
    def test_add_and_remove_on_a_proxied_door(self):
        self.write(proxy={"port": 1, "pid": os.getpid()}, rules={"max_opens": 2})
        r = door_ops.set_rules(self.dir, NAME, password="door-pass-1", guest="new", max_opens=1,
                               tunnel_base="tunnel.cush.rocks")
        st = self.state()["rules"]
        self.assertTrue(door_state.verify_password("door-pass-1", st["password"]))
        self.assertEqual(st["max_opens"], 1)
        self.assertEqual(r["rules"], {"password": True, "guest_link": True, "max_opens": 1})
        self.assertEqual(r["guest_url"], f"https://{NAME}.tunnel.cush.rocks/?k={st['guest']}")
        self.assertFalse(r["live_switch"])
        self.assertNotIn("door-pass-1", repr(r))
        # absent = keep
        r = door_ops.set_rules(self.dir, NAME, max_opens=None)
        self.assertEqual(r["rules"], {"password": True, "guest_link": True, "max_opens": None})
        r = door_ops.set_rules(self.dir, NAME, password=None, guest=None)
        self.assertEqual(self.state()["rules"], {})
        self.assertIsNone(r["guest_url"])

    def test_validation(self):
        self.write(proxy={"port": 1, "pid": os.getpid()})
        for kw in ({"password": "short"}, {"max_opens": 0}, {"max_opens": True},
                   {"guest": "yes"}):
            with self.assertRaises(door_ops.DoorOpError) as c:
                door_ops.set_rules(self.dir, NAME, **kw)
            self.assertEqual(c.exception.status, 400, kw)
        with self.assertRaises(door_ops.DoorOpError) as c:
            door_ops.set_rules(self.dir, "dopstest-none", max_opens=1)
        self.assertEqual(c.exception.status, 404)

    def test_relaunch_needed_never_reads_the_password(self):
        self.write()      # no proxy, no tunnel_pid
        asked = []
        with self.assertRaises(door_ops.DoorOpError) as c:
            door_ops.set_rules(self.dir, NAME, password=lambda: asked.append(1) or "pw-123456")
        e = c.exception
        self.assertEqual((e.status, e.code), (409, "relaunch_needed"))
        self.assertIn("--password", e.extra["command"])
        self.assertEqual(asked, [])
        self.assertEqual(self.state()["rules"], {})

    def fake_tunnel(self, path, answers=True):
        script = os.path.join(self.dir, "tunnel")
        with open(script, "w") as f:
            f.write(f"""import os, signal, sys, time
sys.path.insert(0, {LIB!r})
import door_state
def on_usr1(*a):
    if {answers!r}:
        door_state.update_state({path!r},
            lambda s: s.__setitem__('proxy', {{'port': 1, 'pid': os.getpid()}}))
signal.signal(signal.SIGUSR1, on_usr1)
print('ready', flush=True)
while True:
    time.sleep(0.1)
""")
        p = subprocess.Popen([sys.executable, script, "9999", NAME], stdout=subprocess.PIPE)
        self.addCleanup(p.stdout.close)
        self.addCleanup(p.wait)
        self.addCleanup(p.kill)
        p.stdout.readline()
        return p

    def test_live_switch(self):
        path = self.write()
        p = self.fake_tunnel(path)
        self.write(tunnel_pid=p.pid, proto="http")
        r = door_ops.set_rules(self.dir, NAME, max_opens=1, signal_wait=10)
        self.assertTrue(r["live_switch"])
        self.assertEqual(self.state()["rules"], {"max_opens": 1})

    def test_live_switch_rollback(self):
        path = self.write()
        p = self.fake_tunnel(path, answers=False)
        self.write(tunnel_pid=p.pid, proto="http", rules={})
        with self.assertRaises(door_ops.DoorOpError) as c:
            door_ops.set_rules(self.dir, NAME, guest="new", signal_wait=0.5)
        self.assertEqual((c.exception.status, c.exception.code), (502, "switch_failed"))
        self.assertEqual(self.state()["rules"], {})


class LaunchTest(Case):
    root = Path("/repo")

    def test_panel_plan_is_unchanged(self):
        plan = door_ops.launch_plan(self.dir, "drop", "pics", repo_root=self.root)
        self.assertEqual(plan.argv, ["/repo/bin/drop", "pics", "--bg"])
        self.assertEqual((plan.cwd, plan.name, plan.env, plan.timeout), ("/repo", "pics", None, 25))
        self.assertEqual(plan.log_path, "/repo/logs/pics.log")
        plan = door_ops.launch_plan(self.dir, "secure-entry", "k", repo_root=self.root)
        self.assertEqual(plan.name, "entry-k")
        plan = door_ops.launch_plan(self.dir, "paste", "p", content="hi", repo_root=self.root)
        self.assertEqual(plan.stdin, b"hi")

    def test_refusals(self):
        for args, kw, status in ((("tunnel", "x"), {}, 400), (("drop", "Bad"), {}, 400),
                                 (("media", "m"), {"view_only": "false"}, 400),
                                 (("drop", "x"), {"expires": "3d"}, 400),
                                 (("drop", "x"), {"rules": {"password": "123"}}, 400),
                                 (("drop", "x"), {"rules": {"max_opens": 0}}, 400),
                                 (("drop", "x"), {"rules": {"guest": "yes"}}, 400)):
            with self.assertRaises(door_ops.DoorOpError) as c:
                door_ops.launch_plan(self.dir, *args, **kw)
            self.assertEqual(c.exception.status, status, (args, kw))
        self.write("taken")
        with self.assertRaises(door_ops.DoorOpError) as c:
            door_ops.launch_plan(self.dir, "drop", "taken")
        self.assertEqual((c.exception.status, c.exception.message),
                         (409, "taken is already running"))

    def test_rules_flags_and_env_scrub(self):
        saved = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(saved)))
        os.environ.update({"_CUSH_DAEMONIZED": "1", "TUNNEL_NO_STATE": "1",
                           "_PORCH_DOOR_SPEC": "{}", "CUSH_LOG_FILE": "/x",
                           "PORCH_DOOR_PASSWORD": "stale"})
        plan = door_ops.launch_plan(self.dir, "media", "m", view_only=True, expires="24h",
                                    rules={"password": "s3cret-pw", "guest": True,
                                           "max_opens": 3}, repo_root=self.root)
        self.assertEqual(plan.argv, ["/repo/bin/media", "m", "--bg", "--view-only",
                                     "--expires", "24h", "--password", "--guest-link",
                                     "--max-opens", "3"])
        self.assertNotIn("s3cret-pw", " ".join(plan.argv))
        self.assertEqual(plan.env["PORCH_DOOR_PASSWORD"], "s3cret-pw")
        for k in ("_CUSH_DAEMONIZED", "TUNNEL_NO_STATE", "_PORCH_DOOR_SPEC", "CUSH_LOG_FILE"):
            self.assertNotIn(k, plan.env)
        plan = door_ops.launch_plan(self.dir, "drop", "d", expires="never")
        self.assertNotIn("PORCH_DOOR_PASSWORD", plan.env)

    def test_run_launch(self):
        calls = []

        class R:
            def __init__(self, rc, out=b"", err=b""):
                self.returncode, self.stdout, self.stderr = rc, out, err

        def runner(argv, **kw):
            calls.append((argv, kw))
            return R(0)
        plan = door_ops.launch_plan(self.dir, "drop", "d", rules={"password": "pw-123456"})
        r = door_ops.run_launch(plan, runner, domain=DOMAIN, log=quiet)
        self.assertEqual(r, {"status": "ok", "url": "https://d.tunnel.cush.rocks", "name": "d",
                             "type": "drop"})
        self.assertEqual(calls[0][1]["env"]["PORCH_DOOR_PASSWORD"], "pw-123456")
        plan = door_ops.launch_plan(self.dir, "drop", "e")
        door_ops.run_launch(plan, runner, domain=DOMAIN, log=quiet)
        self.assertNotIn("env", calls[1][1])

        with self.assertRaises(door_ops.DoorOpError) as c:
            door_ops.run_launch(plan, lambda a, **k: R(3, err=b"boom"), domain=DOMAIN, log=quiet)
        self.assertEqual((c.exception.status, c.exception.message),
                         (500, "Launch failed (exit 3): boom"))
        se = door_ops.launch_plan(self.dir, "secure-entry", "k")
        out = b"Secure entry: https://entry-k.tunnel.cush.rocks/Tok_1/\n"
        r = door_ops.run_launch(se, lambda a, **k: R(0, out), domain=DOMAIN, log=quiet)
        self.assertEqual(r["url"], "https://entry-k.tunnel.cush.rocks/Tok_1/")
        with self.assertRaises(door_ops.DoorOpError):
            door_ops.run_launch(se, lambda a, **k: R(0, b"nothing"), domain=DOMAIN, log=quiet)

        def slow(argv, **kw):
            raise subprocess.TimeoutExpired(argv, 1)
        with self.assertRaises(door_ops.DoorOpError) as c:
            door_ops.run_launch(plan, slow, domain=DOMAIN, log=quiet)
        self.assertEqual(c.exception.message, "Launch timed out")


class HistoryTest(Case):
    def test_history_revive_forget(self):
        import json
        hist = os.path.join(self.dir, "history.jsonl")
        with open(hist, "w") as f:
            for i, (n, t) in enumerate((("dopstest-h1", "drop"), ("dopstest-h2", "paste"))):
                f.write(json.dumps({"event": "start", "name": n, "type": t, "ts": i}) + "\n")
        doors = os.path.join(self.dir, "doors")
        items = door_ops.history(hist, self.dir, doors, repo_root=Path("/repo"), domain=DOMAIN,
                                 log=quiet)
        self.assertEqual([i["name"] for i in items], ["dopstest-h2", "dopstest-h1"])
        self.assertEqual(items[1]["cmd"], ["bin/drop", "dopstest-h1", "--bg"])
        self.assertFalse(items[0]["revivable"])
        plan = door_ops.revive_plan(hist, self.dir, "dopstest-h1", repo_root=Path("/repo"))
        self.assertEqual(plan.argv, ["/repo/bin/drop", "dopstest-h1", "--bg"])
        with self.assertRaises(door_ops.DoorOpError) as c:
            door_ops.revive_plan(hist, self.dir, "dopstest-h2")
        self.assertEqual(c.exception.status, 400)
        with self.assertRaises(door_ops.DoorOpError) as c:
            door_ops.revive_plan(hist, self.dir, "dopstest-zz")
        self.assertEqual(c.exception.status, 404)
        door_ops.forget(hist, "dopstest-h1", log=quiet)
        self.assertEqual([i["name"] for i in door_ops.history(hist, self.dir, doors, log=quiet)],
                         ["dopstest-h2"])

    def test_reopen_validates_and_maps_errors(self):
        import door_recipe
        with self.assertRaises(door_ops.DoorOpError) as c:
            door_ops.reopen("x", "7d", reopener=lambda n, e: None)
        self.assertEqual(c.exception.status, 400)

        def gone(n, e):
            raise door_recipe.RecipeError("no recipe")
        with self.assertRaises(door_ops.DoorOpError) as c:
            door_ops.reopen("x", "1h", reopener=gone, log=quiet)
        self.assertEqual((c.exception.status, c.exception.message), (409, "no recipe"))
        r = door_ops.reopen("x", "24h", reopener=lambda n, e: None, domain=DOMAIN, log=quiet)
        self.assertEqual(r["url"], "https://x.tunnel.cush.rocks")


if __name__ == "__main__":
    unittest.main()


class UnmanagedTest(unittest.TestCase):
    """A door's frpc is the launcher's child (another pid): it must not show
    up a second time as an unmanaged tunnel, and shells that merely mention
    "frpc -c" are not tunnels."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.bin = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.bin, True)
        self.frpc = os.path.join(self.bin, "frpc")
        shutil.copy("/bin/sleep", self.frpc)

    def spawn(self, name):
        # bash exec -a: a sleep whose command line reads "<dir>/frpc -c <cfg>".
        p = subprocess.Popen(["bash", "-c", f'exec -a "{self.frpc} -c /tmp/frpc-{name}-AbC12.toml" sleep 30'])
        self.addCleanup(lambda: (p.kill(), p.wait()))
        return p

    def names(self):
        return [d["name"] for d in door_ops.find_unmanaged_frpc(self.dir, domain=DOMAIN)
                if d["name"].startswith("dopsun-")]

    def test_child_frpc_of_a_door_is_not_unmanaged(self):
        launcher = subprocess.Popen(["sleep", "30"])
        self.addCleanup(lambda: (launcher.kill(), launcher.wait()))
        Path(self.dir, "dopsun-a.json").write_text(json.dumps({"pid": launcher.pid, "type": "serve"}))
        self.spawn("dopsun-a")
        self.spawn("dopsun-b")
        deadline = time.time() + 5
        while time.time() < deadline and "dopsun-b" not in self.names():
            time.sleep(0.1)
        self.assertEqual(self.names(), ["dopsun-b"])

    def test_shell_mentioning_frpc_is_not_a_tunnel(self):
        sh = subprocess.Popen(["sh", "-c", "sleep 30; echo frpc -c /tmp/frpc-dopsun-c-AbC12.toml"])
        self.addCleanup(lambda: (sh.kill(), sh.wait()))
        time.sleep(0.2)
        self.assertNotIn("dopsun-c", self.names())

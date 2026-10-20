"""Tests for lib/door_recipe.py: launch recipes, close reasons, retention,
the 7-day prune, and the argv a reopen runs. Temp dirs only (PORCH_DOORS_DIR,
XDG_RUNTIME_DIR and HOME point into one); never data/doors or ~/media."""
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

_LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib")
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
import door_recipe as dr  # noqa: E402
import door_state  # noqa: E402
import rundir  # noqa: E402

NOW = 1_800_000_000


class RecipeCase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="porch-recipe-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        run = os.path.join(self.tmp, "run")
        os.mkdir(run, 0o700)
        self.home = os.path.join(self.tmp, "home")
        os.mkdir(self.home)
        self.ddir = os.path.join(self.tmp, "doors")
        self.sdir = os.path.join(self.tmp, "state")
        os.mkdir(self.sdir)
        env = mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": run, "HOME": self.home,
                                           "PORCH_DOORS_DIR": self.ddir})
        env.start()
        self.addCleanup(env.stop)
        self.share = os.path.realpath(rundir.tool_dir("share"))
        self.paste = os.path.realpath(rundir.tool_dir("paste"))

    def file(self, d, name, data=b"hello"):
        p = os.path.join(d, name)
        with open(p, "wb") as f:
            f.write(data)
        return os.path.realpath(p)

    def spec(self, **rules):
        return {"expires": NOW + 3600, "rules": rules}

    def state(self, name, pid=None, **extra):
        st = {"name": name, "pid": pid or os.getpid(), "type": "view", **extra}
        with open(os.path.join(self.sdir, f"{name}.json"), "w") as f:
            json.dump(st, f)
        return st


class WriteAndCheckTests(RecipeCase):

    def test_write_is_private_and_drops_unknown_flags(self):
        f = self.file(self.tmp, "notes.md")
        r = dr.write("notes", "view", 4242, self.spec(guest="g" * 24), path=f,
                     flags=["--as", "markdown", "--follow", "--evil", "--as", "nope"], now=NOW)
        p = os.path.join(self.ddir, "notes.json")
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.ddir).st_mode), 0o700)
        self.assertEqual(r["inputs"]["flags"], ["--as", "markdown", "--follow"])
        self.assertEqual(r["rules"], {"guest": "g" * 24})
        self.assertRegex(r["secret"], r"^[0-9a-f]{64}$")
        self.assertIsNone(r["closed"])
        self.assertEqual(dr.load("notes")["pid"], 4242)

    def test_refuses_bad_names_and_types(self):
        with self.assertRaises(dr.RecipeError):
            dr.write("../x", "view", 1)
        with self.assertRaises(dr.RecipeError):
            dr.write("x", "tunnel", 1)
        self.assertIsNone(dr.load("../../etc/passwd"))

    def test_argv_for_every_type(self):
        f = self.file(self.share, "stdin-a")
        d = os.path.join(self.tmp, "site")
        os.mkdir(d)
        sealed = self.file(self.share, "s.pseal")
        pk = os.path.join(self.tmp, "pk")
        os.mkdir(pk, 0o700)
        pkf = self.file(pk, "a" * 22 + ".pseal")
        pf = self.file(self.paste, "paste-p-abc12")
        cases = {
            "v": ("view", dict(path=f, flags=["--as", "code"], owned=[f]),
                  [f, "v", "--as", "code", "--owned-file"]),
            "s": ("seal", dict(path=sealed, owned=[sealed]), [sealed, "s", "--owned-file"]),
            "k": ("seal", dict(path=pkf, owned=[pkf], owned_dir=pk),
                  [pkf, "k", "--owned-file", "--owned-dir", os.path.realpath(pk)]),
            "w": ("serve", dict(path=d, flags=["--list"]), [os.path.realpath(d), "w", "--list"]),
            "p": ("paste", dict(path=pf, owned=[pf]), ["p", pf]),
            "m": ("media", dict(flags=["--no-guest-upload"]), ["m", "--no-guest-upload"]),
            "ph": ("photos", {}, ["ph"]), "mu": ("music", {}, ["mu"]), "dr": ("drop", {}, ["dr"]),
        }
        for name, (t, kw, want) in cases.items():
            with self.subTest(t=t):
                dr.write(name, t, 1, self.spec(), now=NOW, **kw)
                r = dr.check(name, state_dir=self.sdir, now=NOW)
                argv = dr.argv_for(r, "24h")
                self.assertEqual(argv[0], os.path.join(dr.BIN_DIR, t))
                self.assertEqual(argv[1:], want + ["--reopen", "--expires", "24h", "--bg"])

    def test_check_refuses(self):
        f = self.file(self.share, "x")
        dr.write("gone", "view", 1, self.spec(), path=f, owned=[f], now=NOW)
        os.unlink(f)
        with self.assertRaisesRegex(dr.RecipeError, "is gone"):
            dr.check("gone", now=NOW)
        with self.assertRaisesRegex(dr.RecipeError, "no launch recipe"):
            dr.check("never", now=NOW)
        # an owned file outside its private dir (a hand-edited recipe)
        g = self.file(self.tmp, "elsewhere")
        dr.write("odd", "view", 1, self.spec(), path=g, owned=[g], now=NOW)
        with self.assertRaisesRegex(dr.RecipeError, "outside its private"):
            dr.check("odd", now=NOW)
        # a symlinked path
        real = self.file(self.tmp, "real.txt")
        link = os.path.join(self.tmp, "link.txt")
        os.symlink(real, link)
        dr.write("ln", "view", 1, self.spec(), path=real, now=NOW)
        rec = dr.load("ln")
        rec["inputs"]["path"] = link
        dr._write("ln", rec)
        with self.assertRaises(dr.RecipeError):
            dr.check("ln", now=NOW)
        # a flag that the type does not allow
        rec["inputs"] = {"path": real, "flags": ["--allow-scripts"]}
        dr._write("ln", rec)
        with self.assertRaisesRegex(dr.RecipeError, "flags"):
            dr.check("ln", now=NOW)
        # open already
        dr.write("live", "drop", 1, self.spec(), now=NOW)
        self.state("live")
        with self.assertRaisesRegex(dr.RecipeError, "open already"):
            dr.check("live", state_dir=self.sdir, now=NOW)

    def test_spec_for_reopen_keeps_rules_and_inspector(self):
        f = self.file(self.tmp, "a.txt")
        sp = {"expires": NOW + 60, "rules": {"password": "scrypt$16384$8$1$c2FsdA$a2V5",
                                             "guest": "t" * 30, "max_opens": 3},
              "inspect": {"raw": False}}
        dr.write("a", "view", 1, sp, path=f, now=NOW)
        spec = dr.spec_for_reopen("a", "24h", now=NOW)
        self.assertEqual(spec["expires"], NOW + 86400)
        self.assertEqual(spec["rules"], sp["rules"])
        self.assertEqual(spec["inspect"], {"raw": False})
        self.assertTrue(spec["reopen"])
        with self.assertRaises(door_state.DoorError):
            dr.spec_for_reopen("a", "yesterday", now=NOW)

    def test_reopen_write_carries_the_old_recipe_over(self):
        f = self.file(self.tmp, "a.txt")
        first = dr.write("a", "view", 1, self.spec(), path=f, now=NOW)
        dr.mark_closed("a", "closed", {"name": "a", "pocket": {"name": "pocket", "kind": "inbox"}},
                       now=NOW + 5)
        again = dr.write("a", "view", 2, dict(self.spec(), reopen=True), path=f, now=NOW + 10)
        self.assertEqual(again["secret"], first["secret"])
        self.assertEqual(again["created"], NOW)
        self.assertEqual(again["reopens"], 1)
        self.assertEqual(again["pocket"], {"name": "pocket", "kind": "inbox"})
        self.assertIsNone(again["reason"])
        fresh = dr.write("a", "view", 3, self.spec(), path=f, now=NOW + 20)
        self.assertNotEqual(fresh["secret"], first["secret"])

    def test_launched_installs_the_key_or_drops_a_stale_recipe(self):
        f = self.file(self.share, "own")
        r = dr.write("k", "view", 77, self.spec(), path=f, owned=[f], now=NOW)
        dr.launched("k", 77, state_dir=self.sdir)
        key = os.path.join(self.sdir, ".k.secret")
        with open(key) as fh:
            self.assertEqual(fh.read(), r["secret"])
        self.assertEqual(stat.S_IMODE(os.stat(key).st_mode), 0o600)
        self.assertEqual(door_state.load_or_create_secret(self.sdir, "k").hex(), r["secret"])
        # another door takes the name: the old door's recipe and files go
        dr.launched("k", 78, state_dir=self.sdir)
        self.assertIsNone(dr.load("k"))
        self.assertFalse(os.path.exists(f))


class CloseAndRetainTests(RecipeCase):

    def test_reasons_and_release(self):
        f = self.file(self.share, "keep")
        dr.write("e", "view", 1, self.spec(), path=f, owned=[f], now=NOW)
        dr.mark_closed("e", "expired", now=NOW)
        dr.mark_closed("e", "closed", now=NOW + 1)          # first plain reason wins
        self.assertEqual(dr.load("e")["reason"], "expired")
        self.assertEqual(dr.release("e"), "keep")
        self.assertTrue(os.path.exists(f))
        dr.mark_closed("e", "burned", now=NOW + 2)           # a burn always wins
        self.assertEqual(dr.release("e"), "shred")
        self.assertFalse(os.path.exists(f))
        self.assertIsNone(dr.load("e"))
        self.assertEqual(dr.release("nothing"), "shred")     # no recipe: as before
        dr.mark_closed("e", "bogus")

    def test_release_without_a_reason_is_a_close(self):
        f = self.file(self.share, "k2")
        dr.write("c", "view", 1, self.spec(), path=f, owned=[f], now=NOW)
        self.assertEqual(dr.release("c", now=NOW), "keep")
        self.assertEqual(dr.load("c")["reason"], "closed")
        self.assertEqual(dr.load("c")["closed"], NOW)

    def test_mark_closed_takes_live_rules_and_pocket_tag(self):
        f = self.file(self.tmp, "a")
        dr.write("r", "view", 1, self.spec(max_opens=5), path=f, now=NOW)
        dr.mark_closed("r", "closed", {"name": "r", "rules": {"guest": "n" * 24},
                                       "pocket": {"name": "pocket"}}, now=NOW)
        r = dr.load("r")
        self.assertEqual(r["rules"], {"guest": "n" * 24})
        self.assertEqual(r["pocket"], {"name": "pocket"})

    def test_used_up_refuses_reopen(self):
        f = self.file(self.share, "u")
        dr.write("u", "view", 1, self.spec(max_opens=1), path=f, owned=[f], now=NOW)
        door_state.record_close("u", "used-up")
        with self.assertRaisesRegex(dr.RecipeError, "used-up"):
            dr.check("u", now=NOW)

    def test_stop_door_records_the_reason(self):
        dr.write("sd", "drop", 999999, self.spec(), now=NOW)
        with open(os.path.join(self.sdir, "sd.json"), "w") as f:
            json.dump({"name": "sd", "pid": 999999, "rules": {"guest": "q" * 24}}, f)
        door_state.stop_door("sd", self.sdir)                 # the owner's Stop
        r = dr.load("sd")
        self.assertEqual((r["reason"], r["rules"]), ("closed", {"guest": "q" * 24}))
        # used up (the door proxy's closer): shredded right there, without
        # waiting for the launcher's trap
        f = self.file(self.share, "spent")
        dr.write("sp", "view", 999999, self.spec(), path=f, owned=[f], now=NOW)
        with open(os.path.join(self.sdir, "sp.json"), "w") as fh:
            json.dump({"name": "sp", "pid": 999999}, fh)
        door_state.stop_door("sp", self.sdir, "used-up")
        self.assertIsNone(dr.load("sp"))
        self.assertFalse(os.path.exists(f))

    def test_prune_after_seven_days(self):
        f = self.file(self.share, "old")
        g = self.file(self.share, "new")
        dr.write("old", "view", 999998, self.spec(), path=f, owned=[f], now=NOW)
        dr.write("new", "view", 999998, self.spec(), path=g, owned=[g], now=NOW)
        dr.mark_closed("old", "expired", now=NOW)
        dr.mark_closed("new", "expired", now=NOW + 6 * 86400)
        self.assertEqual(dr.prune(state_dir=self.sdir, now=NOW + dr.RETAIN + 10), 1)
        self.assertFalse(os.path.exists(f))
        self.assertTrue(os.path.exists(g))
        self.assertIsNone(dr.load("old"))
        with self.assertRaisesRegex(dr.RecipeError, "7 days"):
            dr.check("new", now=NOW + 6 * 86400 + dr.RETAIN + 1)

    def test_prune_closes_a_door_that_died_without_its_trap(self):
        f = self.file(self.tmp, "x")
        dr.write("dead", "view", 999997, self.spec(), path=f, now=NOW)
        dr.prune(state_dir=self.sdir, now=NOW + 5)
        self.assertEqual((dr.load("dead")["reason"], dr.load("dead")["closed"]), ("closed", NOW + 5))
        dr.write("busy", "view", os.getpid(), self.spec(), path=f, now=NOW)
        dr.prune(state_dir=self.sdir, now=NOW + 5)
        self.assertIsNone(dr.load("busy")["closed"])        # its launcher is alive

    def test_staged_copies(self):
        d = os.path.join(self.home, "media", "pic")
        os.makedirs(d)
        f = self.file(d, "a.jpg")
        dr.write("pic", "media", 1, self.spec(), flags=["--no-guest-upload"], now=NOW)
        self.assertIsNone(dr.add_staged("pic", self.file(self.tmp, "b.jpg")))   # not its dir
        dr.add_staged("pic", f)
        self.assertEqual(dr.load("pic")["staged"], [f])
        self.assertIn(f, dr.retained_files())
        dr.mark_closed("pic", "used-up", now=NOW)
        self.assertEqual(dr.release("pic"), "shred")
        self.assertFalse(os.path.exists(d))                 # emptied, then removed

    def test_shred_never_leaves_its_dirs(self):
        victim = self.file(self.tmp, "victim")
        dr.write("h", "view", 1, self.spec(), path=victim, now=NOW)
        r = dr.load("h")
        r["inputs"]["owned"] = [victim]
        r["staged"] = [victim, "/etc/passwd"]
        dr.shred(r)
        self.assertTrue(os.path.exists(victim))


class ReopenTests(RecipeCase):

    def test_reopen_runs_the_built_argv_and_retags(self):
        f = self.file(self.share, "own")
        dr.write("ro", "view", 1, self.spec(), path=f, owned=[f], now=NOW)
        dr.mark_closed("ro", "closed", {"name": "ro", "pocket": {"name": "pocket", "kind": "clip"}})
        seen = []

        def runner(argv):
            seen.append(argv)
            self.state("ro", pid=os.getpid())
            return 0, "", ""
        st = dr.reopen("ro", "1h", state_dir=self.sdir, runner=runner)
        self.assertEqual(seen[0][1:], [f, "ro", "--owned-file", "--reopen", "--expires", "1h", "--bg"])
        self.assertEqual(st["pocket"], {"name": "pocket", "kind": "clip"})
        # open already: an error, unless the caller is fine with that
        with self.assertRaises(dr.RecipeError):
            dr.reopen("ro", "1h", state_dir=self.sdir, runner=runner)
        self.assertEqual(dr.reopen("ro", "1h", state_dir=self.sdir, runner=runner,
                                   ok_if_open=True)["name"], "ro")

    def test_reopen_failure_and_bad_expiry(self):
        f = self.file(self.tmp, "a")
        dr.write("rf", "view", 1, self.spec(), path=f, now=NOW)
        with self.assertRaisesRegex(dr.RecipeError, "did not reopen: boom"):
            dr.reopen("rf", "1h", state_dir=self.sdir, runner=lambda a: (1, "", "x\nboom\n"))
        with self.assertRaises(dr.RecipeError):
            dr.reopen("rf", "never ever", state_dir=self.sdir, runner=lambda a: (0, "", ""))

    def test_cli(self):
        f = self.file(self.tmp, "a")
        env = {"_PORCH_DOOR_SPEC": json.dumps(self.spec(guest="z" * 24))}
        with mock.patch.dict(os.environ, env):
            self.assertEqual(dr.main(["write", "--name", "cli", "--type", "view", "--pid", "5",
                                      "--path", f, "--flag", "--follow"]), 0)
        r = dr.load("cli")
        self.assertEqual((r["rules"], r["inputs"]["flags"]), ({"guest": "z" * 24}, ["--follow"]))
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(dr.main(["spec", "cli", "--expires", "1h"]), 0)
        self.assertEqual(json.loads(out.getvalue())["rules"], {"guest": "z" * 24})
        with redirect_stdout(io.StringIO()):
            self.assertEqual(dr.main(["closed", "cli", "expired"]), 0)
            self.assertEqual(dr.main(["release", "cli"]), 0)
        self.assertEqual(dr.load("cli")["reason"], "expired")
        with redirect_stderr(io.StringIO()):
            self.assertEqual(dr.main(["spec", "nope"]), 2)
            self.assertEqual(dr.main(["bogus"]), 2)


if __name__ == "__main__":
    unittest.main()

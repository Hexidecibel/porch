"""Tests for lib/porch_setup: engine, state, io, runner, secretstore, files, registry."""

import json
import os
import shutil
import stat
import sys
import tempfile
import textwrap
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "lib"))

import porch_config  # noqa: E402
from porch_setup import registry, state as pstate  # noqa: E402
from porch_setup.engine import (Action, Check, Engine, Input, Step, StepError,  # noqa: E402
                                make_context, EXIT_APPLY, EXIT_PREFLIGHT, EXIT_USAGE,
                                EXIT_VERIFY, EXIT_ABORTED)
from porch_setup.files import UnmanagedFileError, UserEditedError  # noqa: E402
from porch_setup.io import NullIO, SecretAnswer  # noqa: E402
from porch_setup.redact import Redactor  # noqa: E402
from porch_setup.runner import FakeRunner, Runner  # noqa: E402
from porch_setup.secretstore import SecretError, SecretNotFound, SecretStore  # noqa: E402

CFG = porch_config.load(env={"PORCH_CONFIG": "none"})
TOKEN = "cf-SECRET-token-0123456789abcdef"


class Crash(BaseException):
    """Simulates the process dying mid-apply (the engine only catches Exception)."""


class World:
    """External system the fake steps mutate (stands in for DNS, systemd...)."""

    def __init__(self):
        self.records = {}
        self.creates = 0
        self.log = []


class RecordStep(Step):
    """Creates one record in the World, idempotently, with write-ahead undo."""

    def __init__(self, sid, world, requires=(), crash=False, fail_verify=False):
        self.id, self.title, self.requires = sid, f"step {sid}", tuple(requires)
        self.world, self.crash, self.fail_verify = world, crash, fail_verify
        self.applied = 0

    def plan(self, ctx):
        return [Action("record.create", self.id, "value 1")]

    def apply(self, ctx):
        self.applied += 1
        if self.id not in self.world.records:
            ctx.record_undo("record.delete", id=self.id)
            if self.crash:
                raise Crash()
            ctx.run.run(["create-record", self.id])
            self.world.records[self.id] = 1
            self.world.creates += 1
        return {"record": self.id}

    def verify(self, ctx):
        ok = self.world.records.get(self.id) == 1 and not self.fail_verify
        return [Check(ok, f"{self.id}.present", "record present" if ok else "record missing",
                      hint="" if ok else "look at the record")]

    def undo(self, ctx, entry):
        if entry["kind"] == "record.delete":
            self.world.records.pop(entry["id"], None)
            self.world.log.append(("undo", entry["id"]))
            return
        super().undo(ctx, entry)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.data = os.path.join(self.tmp, "data")
        self.world = World()
        self.red = Redactor()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def ctx(self, io=None, runner=None, **kw):
        return make_context(io=io or NullIO(), runner=runner or FakeRunner(), data_dir=self.data,
                            cfg=CFG, redactor=self.red,
                            secrets_dir=os.path.join(self.tmp, "secrets"),
                            sleep=lambda s: None, **kw)

    def statefile(self):
        with open(os.path.join(self.data, pstate.STATE_NAME)) as f:
            return json.load(f)

    def steps(self, n=3, **kw):
        out, prev = [], ()
        for i in range(n):
            s = RecordStep(f"s{i}", self.world, requires=prev, **kw.get(f"s{i}", {}))
            out.append(s)
            prev = (s.id,)
        return out


class RunTest(Base):
    def test_full_run_persists_done_and_outputs(self):
        steps = self.steps()
        r = Engine(steps, self.ctx()).run()
        self.assertTrue(r.ok, r)
        self.assertEqual(r.statuses, {"s0": "done", "s1": "done", "s2": "done"})
        st = self.statefile()
        self.assertEqual(st["version"], 1)
        self.assertEqual(st["steps"]["s1"]["outputs"], {"record": "s1"})
        self.assertEqual(st["steps"]["s1"]["attempts"], 1)
        mode = stat.S_IMODE(os.stat(os.path.join(self.data, pstate.STATE_NAME)).st_mode)
        self.assertEqual(mode, 0o600)

    def test_second_run_is_noop(self):
        steps = self.steps()
        Engine(steps, self.ctx()).run()
        runner = FakeRunner()
        io = NullIO()
        r = Engine(steps, self.ctx(io=io, runner=runner)).run()
        self.assertTrue(r.ok)
        self.assertEqual(runner.mutating_calls(), [])
        self.assertEqual([s.applied for s in steps], [1, 1, 1])
        self.assertEqual([d["status"] for d in io.kinds("step_done")], ["unchanged"] * 3)

    def test_reapply_when_verify_breaks(self):
        steps = self.steps(1)
        Engine(steps, self.ctx()).run()
        del self.world.records["s0"]
        r = Engine(steps, self.ctx()).run()
        self.assertTrue(r.ok)
        self.assertEqual(steps[0].applied, 2)
        self.assertEqual(self.statefile()["steps"]["s0"]["attempts"], 2)

    def test_stop_then_resume_no_duplicates(self):
        steps = self.steps()
        r = Engine(steps, self.ctx()).run(until="s1")
        self.assertEqual(r.statuses["s2"], "pending")
        # fresh process: new step objects, new context, state reloaded from disk
        steps2 = [RecordStep(s.id, self.world, s.requires) for s in steps]
        runner = FakeRunner()
        r = Engine(steps2, self.ctx(runner=runner)).resume()
        self.assertTrue(r.ok)
        self.assertEqual(self.world.creates, 3)
        self.assertEqual([s.applied for s in steps2], [0, 0, 1])
        self.assertEqual(runner.argvs(), [["create-record", "s2"]])

    def test_only_from_and_requires(self):
        steps = self.steps()
        r = Engine(steps, self.ctx()).run(only=["s1"])
        self.assertFalse(r.ok)
        self.assertEqual(r.exit_code, EXIT_PREFLIGHT)
        self.assertEqual(r.error["code"], "engine.requires")
        Engine(steps, self.ctx()).run(only=["s0"])
        r = Engine(steps, self.ctx()).run(from_="s1")
        self.assertTrue(r.ok)
        r = Engine(steps, self.ctx()).run(only=["nope"])
        self.assertEqual(r.exit_code, EXIT_USAGE)

    def test_unregistered_requires_is_ignored(self):
        s = RecordStep("a", self.world, requires=("not_built_yet",))
        self.assertTrue(Engine([s], self.ctx()).run().ok)

    def test_requires_must_point_backwards(self):
        a = RecordStep("a", self.world, requires=("b",))
        b = RecordStep("b", self.world)
        with self.assertRaises(Exception):
            Engine([a, b], self.ctx())

    def test_not_applicable_is_skipped(self):
        class Never(RecordStep):
            def applicable(self, ctx):
                return False
        s = Never("n", self.world)
        r = Engine([s], self.ctx()).run()
        self.assertTrue(r.ok)
        self.assertEqual(r.statuses["n"], "skipped")
        self.assertEqual(s.applied, 0)


class FailureTest(Base):
    def test_preflight_failure_stops_with_hint(self):
        class Pre(RecordStep):
            def preflight(self, ctx):
                return [Check(True, "a.ok", "fine"),
                        Check(False, "port.443", "Port 443 is used by nginx", "stop nginx")]
        steps = [Pre("p", self.world), RecordStep("q", self.world)]
        io = NullIO()
        r = Engine(steps, self.ctx(io=io)).run()
        self.assertEqual(r.exit_code, EXIT_PREFLIGHT)
        self.assertEqual(r.failed_step, "p")
        self.assertEqual(r.error, {"phase": "preflight", "code": "port.443",
                                   "message": "Port 443 is used by nginx", "hint": "stop nginx"})
        self.assertEqual(r.statuses["q"], "pending")
        self.assertEqual(steps[0].applied, 0)
        self.assertEqual(io.kinds("step_failed")[0]["hint"], "stop nginx")

    def test_apply_exception_and_steperror(self):
        class Boom(RecordStep):
            def apply(self, ctx):
                raise StepError("dns.auth", "token rejected", "needs Zone:DNS:Edit")
        r = Engine([Boom("b", self.world)], self.ctx()).run()
        self.assertEqual(r.exit_code, EXIT_APPLY)
        self.assertEqual(r.error["code"], "dns.auth")
        self.assertEqual(self.statefile()["steps"]["b"]["status"], "failed")

        class Bug(RecordStep):
            def apply(self, ctx):
                raise KeyError("x")
        r = Engine([Bug("c", self.world)], self.ctx()).run()
        self.assertEqual(r.exit_code, EXIT_APPLY)
        self.assertEqual(r.error["code"], "engine.exception")

    def test_verify_failure(self):
        r = Engine([RecordStep("v", self.world, fail_verify=True)], self.ctx()).run()
        self.assertEqual(r.exit_code, EXIT_VERIFY)
        self.assertEqual(r.error["phase"], "verify")
        self.assertEqual(r.error["hint"], "look at the record")

    def test_lock_excludes_second_frontend(self):
        steps = self.steps(1)
        eng = Engine(steps, self.ctx())
        other = pstate.StateLock(os.path.join(self.data, pstate.LOCK_NAME))
        with other:
            r = eng.run()
        self.assertEqual(r.exit_code, EXIT_ABORTED)
        self.assertEqual(r.error["code"], "engine.locked")
        self.assertTrue(eng.run().ok)


class RollbackTest(Base):
    def test_rollback_reverse_order(self):
        steps = self.steps()
        Engine(steps, self.ctx()).run()
        r = Engine(steps, self.ctx()).rollback()
        self.assertTrue(r.ok)
        self.assertEqual(self.world.log, [("undo", "s2"), ("undo", "s1"), ("undo", "s0")])
        self.assertEqual(self.world.records, {})
        st = self.statefile()
        for sid in ("s0", "s1", "s2"):
            self.assertEqual(st["steps"][sid]["status"], "rolled_back")
            self.assertEqual(st["steps"][sid]["undo"], [])

    def test_rollback_to_is_inclusive(self):
        steps = self.steps()
        Engine(steps, self.ctx()).run()
        Engine(steps, self.ctx()).rollback(to_step="s1")
        self.assertEqual(self.world.log, [("undo", "s2"), ("undo", "s1")])
        self.assertEqual(self.statefile()["steps"]["s0"]["status"], "done")

    def test_rollback_skips_adopted(self):
        steps = self.steps(1)
        self.world.records["s0"] = 1
        r = Engine(steps, self.ctx(adopt=True)).run()
        self.assertEqual(r.statuses["s0"], "adopted")
        Engine(steps, self.ctx()).rollback()
        self.assertEqual(self.world.records, {"s0": 1})

    def test_rollback_dry_run_changes_nothing(self):
        steps = self.steps(2)
        Engine(steps, self.ctx()).run()
        io = NullIO()
        Engine(steps, self.ctx(io=io, dry_run=True)).rollback()
        self.assertEqual(self.world.log, [])
        self.assertEqual([a["kind"] for a in io.kinds("action")], ["undo.record.delete"] * 2)
        self.assertEqual(self.statefile()["steps"]["s1"]["status"], "done")


class CrashTest(Base):
    def test_write_ahead_undo_survives_crash(self):
        s = RecordStep("c", self.world, crash=True)
        with self.assertRaises(Crash):
            Engine([s], self.ctx()).run()
        st = self.statefile()
        self.assertEqual(st["steps"]["c"]["status"], "running")
        self.assertEqual(st["steps"]["c"]["undo"], [{"kind": "record.delete", "id": "c"}])

    def test_running_on_resume_is_failed_and_undo_replayable(self):
        s = RecordStep("c", self.world, crash=True)
        with self.assertRaises(Crash):
            Engine([s], self.ctx()).run()
        # the external change happened before the crash point in real life
        self.world.records["c"] = 1
        eng = Engine([RecordStep("c", self.world, fail_verify=True)], self.ctx())
        st = eng.status()
        self.assertEqual(st["steps"][0]["status"], "running")
        r = eng.rollback()
        self.assertTrue(r.ok)
        self.assertEqual(self.world.log, [("undo", "c")])
        self.assertNotIn("c", self.world.records)

    def test_crashed_step_reported_failed_then_retried(self):
        s = RecordStep("c", self.world, crash=True)
        with self.assertRaises(Crash):
            Engine([s], self.ctx()).run()
        ctx = self.ctx()
        eng = Engine([RecordStep("c", self.world)], ctx)
        eng.lock.acquire()
        eng.state.reload()
        eng._recover()
        eng.lock.release()
        e = self.statefile()["steps"]["c"]
        self.assertEqual(e["status"], "failed")
        self.assertEqual(e["error"]["code"], "engine.crashed")
        self.assertEqual(len(e["undo"]), 1)
        r = eng.run()
        self.assertTrue(r.ok)
        self.assertEqual(self.statefile()["steps"]["c"]["attempts"], 2)


class InputTest(Base):
    def _step(self, inputs):
        world = self.world

        class S(RecordStep):
            INPUTS = tuple(inputs)

            def apply(self, ctx):
                world.log.append(("domain", ctx.input("domain")))
                return super().apply(ctx)
        return S("in", world)

    def test_inputs_stored_and_validated(self):
        inp = Input("domain", "text", "Domain?", flag="--domain",
                    validate=lambda v: None if "." in v else "need a dot")
        r = Engine([self._step([inp])], self.ctx(io=NullIO({"domain": " example.com "}))).run()
        self.assertTrue(r.ok, r)
        self.assertEqual(self.statefile()["inputs"]["domain"], "example.com")
        self.assertIn(("domain", "example.com"), self.world.log)

        self.world = World()
        shutil.rmtree(self.data)
        r = Engine([self._step([inp])], self.ctx(io=NullIO({"domain": "nodot"}))).run()
        self.assertEqual(r.exit_code, EXIT_USAGE)
        self.assertEqual(r.error["code"], "engine.invalid_input")

    def test_missing_inputs_listed_non_interactive(self):
        steps = [self._step([Input("domain", "text", "Domain?", flag="--domain"),
                             Input("apex", "bool", "Apex?", flag="--apex", default=False)]),
                 type("T", (RecordStep,), {"INPUTS": (Input("tok", "secret", "Token", flag="--tok-ref"),)})(
                     "t", self.world)]
        r = Engine(steps, self.ctx()).run()
        self.assertEqual(r.exit_code, EXIT_USAGE)
        self.assertEqual(r.missing, ["--domain", "--tok-ref"])
        self.assertEqual(self.world.creates, 0)

    def test_default_used_and_choice_checked(self):
        inp = Input("mode", "choice", "Mode?", choices=lambda ctx: ["upnp", "manual"],
                    default="upnp")
        r = Engine([self._step([inp])], self.ctx()).run()
        self.assertTrue(r.ok)
        self.assertEqual(self.statefile()["inputs"]["mode"], "upnp")
        shutil.rmtree(self.data)
        r = Engine([self._step([inp])], self.ctx(io=NullIO({"mode": "relay"}))).run()
        self.assertEqual(r.error["code"], "engine.invalid_input")

    def test_flag_overrides_stored_answer(self):
        inp = Input("domain", "text", "Domain?", flag="--domain")
        Engine([self._step([inp])], self.ctx(io=NullIO({"domain": "a.com"}))).run()
        Engine([self._step([inp])], self.ctx(io=NullIO({"domain": "b.com"}))).run(only=["in"])
        self.assertEqual(self.statefile()["inputs"]["domain"], "b.com")
        Engine([self._step([inp])], self.ctx()).run()
        self.assertEqual(self.statefile()["inputs"]["domain"], "b.com")

    def test_secret_ref_answer_is_recorded_not_read(self):
        inp = Input("tok", "secret", "Token", flag="--tok-ref")
        io = NullIO({"tok": SecretAnswer(ref="inf://prod/porch/TOK")})
        r = Engine([self._step([inp])], self.ctx(io=io)).run()
        self.assertTrue(r.ok)
        self.assertEqual(self.statefile()["secret_refs"], {"tok": "inf://prod/porch/TOK"})
        shutil.rmtree(self.data)
        r = Engine([self._step([inp])], self.ctx(io=NullIO({"tok": SecretAnswer(ref="http://x")}))).run()
        self.assertEqual(r.exit_code, EXIT_USAGE)


class RedactionTest(Base):
    def test_secret_never_lands_in_state_log_events_or_calls(self):
        class Leaky(Step):
            id, title = "leaky", "leaky"
            INPUTS = (Input("dns_token", "secret", "DNS token", flag="--dns-token-ref",
                            env="PORCH_DNS_TOKEN"),)

            def apply(self, ctx):
                tok = ctx.secret("dns_token")
                ctx.log(f"using token {tok}")
                ctx.run.run(["curl", "-H", f"Authorization: Bearer {tok}", "https://api"],
                            mutating=False)
                ctx.record_undo("dns.delete", id="r1", note=f"made with {tok}")
                ctx.emit("check", step="leaky", ok=True, code="x", message=tok, hint="")
                return {"echo": tok}

            def verify(self, ctx):
                tok = ctx.secret("dns_token")
                return [Check(False, "dns.auth", f"token {tok} rejected", f"rotate {tok}")]

        runner = FakeRunner()
        runner.on(["curl"], stdout=f"you sent {TOKEN}")
        io = NullIO({"dns_token": TOKEN})
        r = Engine([Leaky()], self.ctx(io=io, runner=runner)).run()
        self.assertEqual(r.exit_code, EXIT_VERIFY)

        with open(os.path.join(self.data, pstate.STATE_NAME)) as f:
            state_text = f.read()
        with open(os.path.join(self.data, pstate.LOG_NAME)) as f:
            log_text = f.read()
        self.assertNotIn(TOKEN, state_text)
        self.assertNotIn(TOKEN, log_text)
        self.assertNotIn(TOKEN, json.dumps(io.events))
        self.assertNotIn(TOKEN, json.dumps(runner.calls))
        self.assertNotIn(TOKEN, json.dumps(r.error))
        self.assertIn("[redacted]", log_text)
        self.assertIn("[redacted]", state_text)
        # only the ref is in state, the value is in a 0600 file under the 0700 root
        ref = json.loads(state_text)["secret_refs"]["dns_token"]
        self.assertEqual(ref, "file://~/.config/porch/secrets/dns_token")
        path = os.path.join(self.tmp, "secrets", "dns_token")
        with open(path) as f:
            self.assertEqual(f.read(), TOKEN)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode), 0o700)
        log_mode = stat.S_IMODE(os.stat(os.path.join(self.data, pstate.LOG_NAME)).st_mode)
        self.assertEqual(log_mode, 0o600)

    def test_dry_run_secret_is_not_stored(self):
        class S(Step):
            id = "s"
            INPUTS = (Input("tok", "secret", "Token"),)

            def plan(self, ctx):
                return [Action("use", ctx.secret("tok"))]
        io = NullIO({"tok": TOKEN})
        Engine([S()], self.ctx(io=io, dry_run=True)).run()
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "secrets", "tok")))
        self.assertFalse(os.path.exists(os.path.join(self.data, pstate.STATE_NAME)))
        self.assertNotIn(TOKEN, json.dumps(io.events))


class DryRunAdoptTest(Base):
    def test_dry_run_plans_and_changes_nothing(self):
        steps = self.steps(2)
        io = NullIO()
        r = Engine(steps, self.ctx(io=io, dry_run=True)).run()
        self.assertTrue(r.ok)
        self.assertEqual(self.world.creates, 0)
        self.assertEqual([a["target"] for a in io.kinds("action")], ["s0", "s1"])
        self.assertFalse(os.path.exists(os.path.join(self.data, pstate.STATE_NAME)))

    def test_plan_view(self):
        steps = self.steps(2)
        Engine(steps, self.ctx()).run(only=["s0"])
        p = Engine(steps, self.ctx()).plan()
        self.assertEqual(list(p), ["s1"])
        self.assertEqual(p["s1"][0].kind, "record.create")

    def test_adopt_marks_passing_and_reports_all_failures(self):
        steps = self.steps(3)
        self.world.records.update({"s0": 1, "s2": 1})
        r = Engine(steps, self.ctx(adopt=True)).run()
        self.assertEqual(r.exit_code, EXIT_VERIFY)
        self.assertEqual(r.statuses, {"s0": "adopted", "s1": "failed", "s2": "adopted"})
        self.assertEqual(self.world.creates, 0)
        self.assertEqual(self.statefile()["mode"], "adopt")

    def test_adopt_dry_run_writes_nothing(self):
        steps = self.steps(1)
        self.world.records["s0"] = 1
        r = Engine(steps, self.ctx(adopt=True, dry_run=True)).run()
        self.assertTrue(r.ok)
        self.assertFalse(os.path.exists(os.path.join(self.data, pstate.STATE_NAME)))


class FileManagerTest(Base):
    def _write_step(self, path, content, **kw):
        class W(Step):
            id = "w"

            def apply(self, ctx):
                return {"r": ctx.files.write(path, content, **kw)}

            def verify(self, ctx):
                return [Check(ctx.files.status(path) == "managed", "file", path)]
        return W()

    def test_create_unchanged_and_rollback_deletes(self):
        p = os.path.join(self.tmp, "etc", "frps.toml")
        r = Engine([self._write_step(p, "a=1\n")], self.ctx()).run()
        self.assertTrue(r.ok)
        self.assertEqual(self.statefile()["steps"]["w"]["outputs"], {"r": "created"})
        entry = self.statefile()["files"][p]
        self.assertEqual(entry["step"], "w")
        ctx = self.ctx()
        ctx.step_id = "w"
        self.assertEqual(ctx.files.write(p, "a=1\n"), "unchanged")
        Engine([self._write_step(p, "a=1\n")], self.ctx()).rollback()
        self.assertFalse(os.path.exists(p))
        self.assertNotIn(p, self.statefile()["files"])

    def test_refuses_user_edits(self):
        p = os.path.join(self.tmp, "frps.toml")
        Engine([self._write_step(p, "a=1\n")], self.ctx()).run()
        with open(p, "w") as f:
            f.write("a=1\n# my edit\n")
        ctx = self.ctx()
        ctx.step_id = "w"
        self.assertEqual(ctx.files.status(p), "edited")
        with self.assertRaises(UserEditedError):
            ctx.files.write(p, "a=2\n")
        with open(p) as f:
            self.assertIn("my edit", f.read())
        # rollback also refuses to clobber the edit
        r = Engine([self._write_step(p, "a=1\n")], self.ctx()).rollback()
        self.assertFalse(r.ok)
        with open(p) as f:
            self.assertIn("my edit", f.read())

    def test_unmanaged_refused_take_over_backs_up_and_restores(self):
        p = os.path.join(self.tmp, "mine.conf")
        with open(p, "w") as f:
            f.write("original\n")
        ctx = self.ctx()
        ctx.step_id = "w"
        with self.assertRaises(UnmanagedFileError):
            ctx.files.write(p, "porch\n")
        r = Engine([self._write_step(p, "porch\n", take_over=True)], self.ctx()).run()
        self.assertTrue(r.ok)
        with open(p) as f:
            self.assertEqual(f.read(), "porch\n")
        backup = self.statefile()["files"][p]["backup"]
        self.assertTrue(backup.startswith(os.path.join(self.data, pstate.BACKUP_DIR_NAME)))
        self.assertEqual(stat.S_IMODE(os.stat(backup).st_mode), 0o600)
        Engine([self._write_step(p, "porch\n")], self.ctx()).rollback()
        with open(p) as f:
            self.assertEqual(f.read(), "original\n")

    def test_dry_run_write_touches_nothing(self):
        p = os.path.join(self.tmp, "x.conf")
        ctx = self.ctx(dry_run=True)
        ctx.step_id = "w"
        self.assertEqual(ctx.files.write(p, "x"), "would-create")
        self.assertFalse(os.path.exists(p))


class StateTest(Base):
    def test_migrate_v0_and_refuse_newer(self):
        os.makedirs(self.data)
        path = os.path.join(self.data, pstate.STATE_NAME)
        with open(path, "w") as f:
            json.dump({"steps": {"a": {"status": "done"}}}, f)
        st = pstate.State.load(path)
        self.assertEqual(st.data["version"], 1)
        self.assertEqual(st.steps["a"]["undo"], [])
        self.assertEqual(st.inputs, {})
        with open(path, "w") as f:
            json.dump({"version": 99}, f)
        with self.assertRaises(pstate.StateError):
            pstate.State.load(path)

    def test_loose_mode_tightened_and_symlink_refused(self):
        os.makedirs(self.data)
        path = os.path.join(self.data, pstate.STATE_NAME)
        with open(path, "w") as f:
            json.dump(pstate.new_state(), f)
        os.chmod(path, 0o644)
        pstate.State.load(path)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        os.unlink(path)
        os.symlink("/etc/passwd", path)
        with self.assertRaises(pstate.StateError):
            pstate.State.load(path)


class RunnerTest(unittest.TestCase):
    def test_dry_run_skips_mutating_only(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "made")
            r = Runner(dry_run=True, redactor=Redactor())
            res = r.run(["touch", target])
            self.assertTrue(res.dry_run)
            self.assertFalse(os.path.exists(target))
            res = r.run(["echo", "hi"], mutating=False)
            self.assertEqual(res.stdout, "hi\n")
            self.assertEqual([c["dry_run"] for c in r.calls], [True, False])

    def test_redacts_records_and_rejects_shell_strings(self):
        red = Redactor()
        red.add(TOKEN)
        r = Runner(redactor=red)
        res = r.run(["echo", TOKEN], mutating=False)
        self.assertEqual(res.stdout.strip(), TOKEN)  # caller gets the raw output
        self.assertNotIn(TOKEN, json.dumps(r.calls))
        with self.assertRaises(TypeError):
            r.run("echo hi")
        self.assertEqual(r.run(["/nonexistent/x"], mutating=False).returncode, 127)

    def test_check_raises_redacted(self):
        red = Redactor()
        red.add(TOKEN)
        from porch_setup.runner import RunError
        fr = FakeRunner(redactor=red).on(["x"], returncode=3, stderr=f"bad {TOKEN}")
        with self.assertRaises(RunError) as cm:
            fr.run(["x"], check=True)
        self.assertNotIn(TOKEN, str(cm.exception))

    def test_fake_runner_rules(self):
        fr = FakeRunner(tools={"haproxy": "/usr/sbin/haproxy"})
        fr.on(["haproxy", "-c"], stdout="valid")
        fr.on(lambda a: a[0] == "certbot", returncode=1)
        self.assertEqual(fr.run(["haproxy", "-c", "-f", "x"]).stdout, "valid")
        self.assertEqual(fr.run(["certbot", "renew"]).returncode, 1)
        self.assertEqual(fr.run(["other"]).returncode, 0)
        self.assertEqual(fr.which("haproxy"), "/usr/sbin/haproxy")
        self.assertIsNone(fr.which("nginx"))
        strict = FakeRunner(strict=True)
        with self.assertRaises(AssertionError):
            strict.run(["anything"])


class SecretStoreTest(unittest.TestCase):
    def test_file_backend_confined_to_root(self):
        with tempfile.TemporaryDirectory() as d:
            red = Redactor()
            s = SecretStore(redactor=red, file_root=os.path.join(d, "secrets"))
            ref = "file://~/.config/porch/secrets/relay"
            s.put(ref, "hz-token-1234")
            self.assertIn("hz-token-1234", red)
            self.assertEqual(SecretStore(redactor=red, file_root=os.path.join(d, "secrets")).get(ref),
                             "hz-token-1234")
            abs_ref = "file://" + os.path.join(d, "secrets", "x")
            s.put(abs_ref, "v-abcdef")
            self.assertTrue(s.exists(abs_ref))
            for bad in ("file:///etc/passwd", "file://~/.ssh/id_rsa",
                        "file://" + os.path.join(d, "secrets", "..", "escape"), "http://x/y"):
                with self.assertRaises(SecretError, msg=bad):
                    s.put(bad, "value")
            with self.assertRaises(SecretNotFound):
                s.get("file://~/.config/porch/secrets/missing")
            # inf:// / op:// go to lib/cush_secrets.py (W2); never the real CLI in tests
            class _NoBackend:
                def read(self, ref):
                    raise ValueError(ref)
            s._backend = _NoBackend()
            with self.assertRaises(SecretError):
                s.get("inf://prod/porch/X")


class RegistryTest(unittest.TestCase):
    def test_discovers_by_attribute_and_order(self):
        with tempfile.TemporaryDirectory() as d:
            pkg = os.path.join(d, "fakeporch_reg")
            for sub in ("steps", "dns", "connect"):
                os.makedirs(os.path.join(pkg, sub))
                open(os.path.join(pkg, sub, "__init__.py"), "w").close()
            open(os.path.join(pkg, "__init__.py"), "w").close()
            stepsrc = textwrap.dedent("""
                from porch_setup.engine import Step
                class S(Step):
                    def __init__(self, i): self.id = i
                STEP = S({sid!r}); ORDER = {order}
            """)
            for sid, order in (("zeta", 10), ("alpha", 20), ("beta", 10)):
                with open(os.path.join(pkg, "steps", f"{sid}.py"), "w") as f:
                    f.write(stepsrc.format(sid=sid, order=order))
            with open(os.path.join(pkg, "steps", "helpers.py"), "w") as f:
                f.write("X = 1\n")
            with open(os.path.join(pkg, "dns", "cloudflare.py"), "w") as f:
                f.write("class P:\n    name = 'cloudflare'\nPROVIDER = P\n")
            with open(os.path.join(pkg, "connect", "upnp.py"), "w") as f:
                f.write("class M:\n    name = 'upnp'\nMODE = M()\n")
            with open(os.path.join(pkg, "cmd_dns.py"), "w") as f:
                f.write("def main(argv):\n    return 7\n")
            sys.path.insert(0, d)
            old = registry.PKG
            registry.PKG = "fakeporch_reg"
            try:
                self.assertEqual([s.id for s in registry.steps()], ["beta", "zeta", "alpha"])
                self.assertEqual(list(registry.providers()), ["cloudflare"])
                self.assertEqual(list(registry.modes()), ["upnp"])
                self.assertEqual(registry.command("dns")([]), 7)
                self.assertIsNone(registry.command("cert"))
                self.assertIsNone(registry.command("../x"))
            finally:
                registry.PKG = old
                sys.path.remove(d)
                for m in [m for m in sys.modules if m.startswith("fakeporch_reg")]:
                    del sys.modules[m]

    def test_real_packages_import(self):
        self.assertIsInstance(registry.steps(), list)
        self.assertIsInstance(registry.providers(), dict)
        self.assertIsInstance(registry.modes(), dict)


if __name__ == "__main__":
    unittest.main()

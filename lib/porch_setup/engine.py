"""Porch setup engine: Step contract, Context, Engine.

A step is an object (normally one per module, see registry.py) with:

    class MyStep(Step):
        id = "dns_records"; title = "DNS records"; requires = ("dns_provider",)
        INPUTS = (Input("apex", "bool", "Also point the apex?", default=False,
                        flag="--dns-apex"),)
        def applicable(self, ctx): return True
        def preflight(self, ctx): return [Check(True, "dns.zone", "zone found")]
        def plan(self, ctx):      return [Action("dns.create", "A auth.example.com", "-> 1.2.3.4")]
        def apply(self, ctx):
            ctx.record_undo("dns.delete", id=rid)        # BEFORE acting (write-ahead)
            ...; return {"record_ids": [...]}           # outputs, persisted
        def verify(self, ctx):    return [Check(ok, "dns.resolves", "...", hint="...")]
        def undo(self, ctx, entry): ...                  # one undo entry, see Step.rollback

How the engine runs a step (Engine.run):
  1. not applicable -> "skipped".
  2. already done/adopted -> verify; all ok -> no-op ("unchanged"); else re-apply.
  3. every `requires` step registered in this engine must be done/adopted/skipped.
  4. inputs: collected through ctx.io (an explicit flag wins over a stored
     answer; then the stored answer; then default when non-interactive).
     Plain answers -> state["inputs"][name]; secrets -> secretstore.put, and
     only the ref goes to state["secret_refs"][name].
  5. preflight; any failing Check -> failed/preflight (exit 3), run stops.
  6. --dry-run: emit plan() Actions, change nothing, continue.
  7. status=running (saved), apply() (exception -> failed/apply, exit 4),
     outputs saved, verify() (failing -> failed/verify, exit 5), status=done.
  --adopt: inputs + verify only; passing -> "adopted", failing -> failed/verify,
  and the run continues so every step is reported.

A step found in "running" when a run starts was interrupted (crash, kill):
it becomes failed (code engine.crashed). Its undo list is kept and only
replayed by an explicit rollback.

Exit codes: 0 ok, 2 usage/missing input, 3 preflight, 4 apply, 5 verify, 6 aborted/locked.
"""

import os
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional, Union

from . import io as _io
from . import redact as _redact
from . import state as _state
from .files import FileManager
from .runner import Runner
from .secretstore import SecretStore, SecretError, default_ref, scheme_of

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_PREFLIGHT = 3
EXIT_APPLY = 4
EXIT_VERIFY = 5
EXIT_ABORTED = 6

DONE_LIKE = ("done", "adopted", "skipped")


# ---- data types --------------------------------------------------------------

@dataclass
class Check:
    ok: bool
    code: str           # dotted, stable: "dns.auth", "preflight.port443"
    message: str
    hint: str = ""


@dataclass
class Action:
    kind: str           # "file.write", "dns.create", "run", "systemd.enable", ...
    target: str
    detail: str = ""


@dataclass
class Input:
    name: str                                   # key in state["inputs"] / ["secret_refs"]
    kind: str                                   # "text" | "secret" | "choice" | "bool"
    prompt: str
    default: Any = None                         # value or callable(ctx)
    choices: Union[list, Callable, None] = None # for "choice": list or callable(ctx)
    validate: Optional[Callable[[Any], Optional[str]]] = None  # -> error text or None
    flag: str = ""                              # CLI flag; for secrets a REF flag ("--dns-token-ref")
    env: str = ""                               # env var with the value (secrets: PORCH_DNS_TOKEN)
    secret_ref: Union[str, Callable, None] = None  # where a new secret value is stored
                                                # (str or callable(ctx)); default file://.../<name>
    required: bool = True
    help: str = ""


class StepError(Exception):
    """Raise from apply() for a clean, explained failure."""

    def __init__(self, code, message, hint=""):
        self.code, self.message, self.hint = code, message, hint
        super().__init__(f"{code}: {message}")


class EngineError(Exception):
    pass


@dataclass
class RunResult:
    ok: bool
    exit_code: int
    failed_step: Optional[str] = None
    error: Optional[dict] = None
    statuses: dict = field(default_factory=dict)
    missing: List[str] = field(default_factory=list)   # flags (or names) of missing inputs


# ---- Step --------------------------------------------------------------------

class Step:
    id: str = ""
    title: str = ""
    requires: tuple = ()
    INPUTS: tuple = ()      # static Inputs; bin/porch turns their .flag into CLI options

    def inputs(self, ctx) -> List[Input]:
        return list(self.INPUTS)

    def applicable(self, ctx) -> bool:
        return True

    def preflight(self, ctx) -> List[Check]:
        return []

    def plan(self, ctx) -> List[Action]:
        return []

    def apply(self, ctx) -> dict:
        return {}

    def verify(self, ctx) -> List[Check]:
        return []

    def rollback(self, ctx, outputs: dict) -> None:
        """Default: replay this step's undo list newest-first through undo(),
        dropping each entry once it succeeded (so a failed rollback resumes)."""
        for entry in ctx.undo_entries():
            self.undo(ctx, entry)
            ctx.drop_undo(entry)

    def undo(self, ctx, entry: dict) -> None:
        if entry.get("kind", "").startswith("file."):
            ctx.files.restore(entry)
            return
        raise NotImplementedError(f"step {self.id} cannot undo {entry.get('kind')!r}")

    def __repr__(self):
        return f"<Step {self.id}>"


# ---- Context -----------------------------------------------------------------

class Context:
    """Everything a step touches. Build with make_context().

    Attributes:
      cfg        porch_config.Config (lazy; reload_cfg() after writing porch.toml)
      state      state.State
      io         io.IO implementation
      run        runner.Runner (ctx.run.run([...]))
      files      files.FileManager
      secrets    secretstore.SecretStore
      redactor   redact.Redactor
      dns        resolver (W2's dnsq; None until injected)
      http       urlopen-compatible callable (default urllib.request.urlopen)
      clock      callable -> float seconds (default time.time)
      sleep      callable(seconds) (default time.sleep; tests pass a no-op)
      dry_run, adopt   bools
      env        mapping (default os.environ)
      repo_dir, data_dir, scratch_dir, log_path
      step_id    id of the step currently running (None between steps)
    """

    def __init__(self, *, state, io, run, secrets, redactor, data_dir, cfg=None,
                 dry_run=False, adopt=False, dns=None, http=None, clock=None, sleep=None,
                 env=None, repo_dir=None, scratch_dir=None, log_path=None):
        self.state = state
        self.io = io
        self.run = run
        self.secrets = secrets
        self.redactor = redactor
        self.data_dir = data_dir
        self._cfg = cfg
        self.dry_run = dry_run
        self.adopt = adopt
        self.dns = dns
        self.http = http or urllib.request.urlopen
        self.clock = clock or time.time
        self.sleep = sleep or time.sleep
        self.env = os.environ if env is None else env
        self.repo_dir = repo_dir or _state.REPO_DIR
        self.scratch_dir = scratch_dir or os.path.join(data_dir, "porch-setup-scratch")
        self.log_path = log_path
        self.step_id = None
        self.files = FileManager(self)

    # config
    @property
    def cfg(self):
        if self._cfg is None:
            import porch_config
            self._cfg = porch_config.get()
        return self._cfg

    @property
    def config_path(self):
        """Where config/porch.toml lives for this run ($PORCH_CONFIG wins)."""
        import porch_config
        p = self.env.get("PORCH_CONFIG")
        return p if p and p != "none" else porch_config.DEFAULT_PATH

    def reload_cfg(self, path=None):
        """Re-read the config (after a step wrote it). `path` defaults to
        config_path; a missing default file means the built-in defaults."""
        import porch_config
        porch_config.reset()
        path = path or self.config_path
        self._cfg = porch_config.load(path=path if os.path.exists(path) else None,
                                      env={k: v for k, v in self.env.items() if k != "PORCH_CONFIG"}
                                      | ({"PORCH_CONFIG": "none"} if not os.path.exists(path) else {}))
        return self._cfg

    # inputs / secrets / facts / outputs
    def input(self, name, default=None):
        return self.state.inputs.get(name, default)

    def secret_ref(self, name):
        return self.state.secret_refs.get(name)

    def secret(self, name):
        """The value of secret input `name` (registered for redaction)."""
        ref = self.state.secret_refs.get(name)
        if ref is None:
            raise KeyError(f"no secret {name!r} collected")
        return self.secrets.get(ref)

    @property
    def facts(self):
        return self.state.facts

    def set_fact(self, key, value):
        self.state.facts[key] = value
        self.state.save()

    def outputs(self, step_id):
        e = self.state.steps.get(step_id)
        return dict(e["outputs"]) if e else {}

    # write-ahead undo for the current step
    def _entry(self):
        if not self.step_id:
            raise EngineError("record_undo outside a running step")
        return self.state.step(self.step_id)

    def record_undo(self, kind, **data):
        """Append an undo entry to the current step and save NOW, before the
        caller performs the change. Values must be JSON-serializable and must
        not be secrets (store a ref instead). Returns the entry."""
        entry = {"kind": kind, **data}
        if self.dry_run:
            return entry
        self._entry()["undo"].append(entry)
        self.state.save()
        return entry

    def undo_entries(self):
        """The current step's undo list, newest first (a copy)."""
        return list(reversed(self._entry()["undo"]))

    def drop_undo(self, entry):
        lst = self._entry()["undo"]
        for i in range(len(lst) - 1, -1, -1):
            if lst[i] == entry:
                del lst[i]
                break
        self.state.save()

    # output
    def emit(self, name, /, **data):
        """Send an IO event (see io.py for names); data is redacted first."""
        self.io.event(name, **self.redactor.redact_obj(data))

    def log(self, message, level="info"):
        message = self.redactor.redact(str(message))
        self.io.event("log", message=message, level=level, step=self.step_id)
        if self.log_path:
            try:
                fd = os.open(self.log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND
                             | getattr(os, "O_NOFOLLOW", 0), 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(f"{_state.now_iso(self.clock)} [{self.step_id or '-'}] {level}: {message}\n")
            except OSError:
                pass

    def confirm(self, prompt, default=False):
        return self.io.confirm(self.redactor.redact(prompt), default)


def make_context(*, io=None, runner=None, data_dir=None, cfg=None, dry_run=False, adopt=False,
                 redactor=None, secrets=None, secrets_dir=None, dns=None, http=None,
                 clock=None, sleep=None, env=None, repo_dir=None, log=True):
    """Build a Context with its State loaded from <data_dir>/porch-setup.json.
    Tests: make_context(io=NullIO(...), runner=FakeRunner(), data_dir=tmp,
    cfg=porch_config.load(env={"PORCH_CONFIG": "none"}), redactor=Redactor(),
    secrets_dir=tmp + "/secrets", sleep=lambda s: None)."""
    env = os.environ if env is None else env
    data_dir = data_dir or _state.default_data_dir(env)
    redactor = redactor or _redact.REDACTOR
    st = _state.State.load(os.path.join(data_dir, _state.STATE_NAME), redactor, clock)
    st.persist = not dry_run
    if runner is None:
        runner = Runner(dry_run=dry_run, redactor=redactor)
    else:
        runner.dry_run = dry_run or runner.dry_run
        runner.redactor = redactor
    if secrets is None:
        secrets = SecretStore(redactor=redactor, file_root=secrets_dir)
    ctx = Context(state=st, io=io or _io.NullIO(), run=runner, secrets=secrets, redactor=redactor,
                  data_dir=data_dir, cfg=cfg, dry_run=dry_run, adopt=adopt, dns=dns, http=http,
                  clock=clock, sleep=sleep, env=env, repo_dir=repo_dir,
                  log_path=os.path.join(data_dir, _state.LOG_NAME) if log and not dry_run else None)
    if runner.log is None:
        runner.log = lambda m: ctx.log(m, level="debug")
    return ctx


# ---- Engine ------------------------------------------------------------------

class Engine:
    def __init__(self, steps, ctx):
        self.steps = list(steps)
        self.ctx = ctx
        ids = [s.id for s in self.steps]
        if len(set(ids)) != len(ids) or not all(ids):
            raise EngineError(f"step ids must be unique and non-empty: {ids}")
        self.by_id = {s.id: s for s in self.steps}
        pos = {sid: i for i, sid in enumerate(ids)}
        for s in self.steps:
            for r in s.requires:
                if r in pos and pos[r] > pos[s.id]:
                    raise EngineError(f"step {s.id} requires {r}, which runs after it")
        self.lock = _state.StateLock(os.path.join(ctx.data_dir, _state.LOCK_NAME))
        self._planned = set()  # dry-run: steps whose plan was shown (count as done for requires)

    # ---- helpers -------------------------------------------------------------
    @property
    def state(self):
        return self.ctx.state

    def _statuses(self):
        return {s.id: self.state.status_of(s.id) for s in self.steps}

    def _recover(self):
        changed = False
        for sid, e in self.state.steps.items():
            if e["status"] == "running":
                e["status"] = "failed"
                e["finished_at"] = _state.now_iso(self.ctx.clock)
                e["error"] = {"phase": "apply", "code": "engine.crashed",
                              "message": "interrupted while running",
                              "hint": "re-run to retry, or `porch setup --rollback` to undo "
                                      "its partial changes"}
                changed = True
        if changed:
            self.state.save()

    def _select(self, only=None, from_=None, until=None):
        for x in list(only or []) + [from_, until]:
            if x and x not in self.by_id:
                raise EngineError(f"unknown step {x!r} (known: {', '.join(self.by_id)})")
        ids = [s.id for s in self.steps]
        if only:
            return [self.by_id[i] for i in ids if i in set(only)]
        start = ids.index(from_) if from_ else 0
        end = ids.index(until) + 1 if until else len(ids)
        return self.steps[start:end]

    def _checks(self, step, fn):
        try:
            checks = list(fn(self.ctx) or [])
        except StepError as e:
            checks = [Check(False, e.code, e.message, e.hint)]
        except Exception as e:  # noqa: BLE001 - a buggy check must not kill the run
            checks = [Check(False, "engine.exception", f"{type(e).__name__}: {e}")]
        for c in checks:
            self.ctx.emit("check", step=step.id, ok=c.ok, code=c.code, message=c.message,
                          hint=c.hint)
        return checks

    def _fail(self, step, phase, code, message, hint, exit_code):
        red = self.ctx.redactor.redact
        err = {"phase": phase, "code": code, "message": red(str(message)), "hint": red(str(hint))}
        e = self.state.step(step.id)
        e["status"] = "failed"
        e["error"] = err
        e["finished_at"] = _state.now_iso(self.ctx.clock)
        self.state.save()
        self.ctx.emit("step_failed", step=step.id, **err)
        self.ctx.log(f"failed ({phase}) {code}: {message}", level="error")
        return RunResult(False, exit_code, step.id, err, self._statuses())

    def _fail_checks(self, step, phase, checks, exit_code):
        bad = next(c for c in checks if not c.ok)
        return self._fail(step, phase, bad.code, bad.message, bad.hint, exit_code)

    # ---- inputs --------------------------------------------------------------
    def _step_inputs(self, step):
        try:
            return list(step.inputs(self.ctx) or [])
        except Exception:  # noqa: BLE001
            return list(step.INPUTS)

    def _needs(self, inp):
        """Would this input need a prompt (no flag/env, nothing stored, no default)?"""
        io = self.ctx.io
        if io.has(inp):
            return False
        if inp.kind == "secret":
            return inp.name not in self.state.secret_refs and inp.required
        if inp.name in self.state.inputs:
            return False
        try:
            d = _io.resolve(inp.default, self.ctx)
        except Exception:  # noqa: BLE001
            d = None
        return d is None and inp.required

    def missing_inputs(self, steps=None):
        """[(step_id, Input)] that a non-interactive run would lack."""
        out = []
        for s in steps if steps is not None else self.steps:
            try:
                if not s.applicable(self.ctx) or self.state.status_of(s.id) in DONE_LIKE:
                    continue
            except Exception:  # noqa: BLE001
                pass
            out.extend((s.id, i) for i in self._step_inputs(s) if self._needs(i))
        return out

    def _ask_loop(self, inp, fn):
        error = None
        for _ in range(3):
            raw = fn(inp, self.ctx, error)
            try:
                value = raw if inp.kind == "secret" else _io.coerce(inp, raw, self.ctx)
                check_val = raw.value if inp.kind == "secret" else value
                if check_val is not None and inp.validate:
                    msg = inp.validate(check_val)
                    if msg:
                        raise _io.InvalidInput(msg)
                return value
            except _io.InvalidInput as e:
                error = str(e)
        raise _io.InvalidInput(f"{inp.name}: {error}")

    def _resolve_inputs(self, step):
        """Resolve the step's inputs in order. The list is re-read after each
        one, so a step's later inputs may depend on an earlier answer (the
        connection step adds the chosen mode's inputs)."""
        done = set()
        while True:
            pending = [i for i in self._step_inputs(step) if i.name not in done]
            if not pending:
                return
            done.add(pending[0].name)
            self._resolve_input(step, pending[0])

    def _resolve_input(self, step, inp):
        ctx, st, io = self.ctx, self.state, self.ctx.io
        if inp.kind == "secret":
            if inp.name in st.secret_refs and not io.has(inp):
                return
            if not io.has(inp):
                ctx.emit("needs_input", step=step.id, name=inp.name, kind=inp.kind,
                         prompt=inp.prompt, flag=inp.flag)
            ans = self._ask_loop(inp, io.ask_secret)
            if ans.ref:
                try:
                    scheme_of(ans.ref)
                except SecretError as e:
                    raise _io.InvalidInput(str(e)) from None
                ref = ans.ref
            else:
                ref = _io.resolve(inp.secret_ref, ctx) or default_ref(inp.name)
                if ctx.dry_run:
                    ctx.secrets.remember(ref, ans.value)
                else:
                    ctx.secrets.put(ref, ans.value)
            st.secret_refs[inp.name] = ref
            st.save()
            return
        if io.has(inp):
            value = self._ask_loop(inp, io.ask)
        elif inp.name in st.inputs:
            return
        elif not io.interactive:
            d = _io.resolve(inp.default, ctx)
            if d is None:
                if inp.required:
                    raise _io.MissingInput([inp], step.id)
                return
            value = _io.coerce(inp, d, ctx)
        else:
            ctx.emit("needs_input", step=step.id, name=inp.name, kind=inp.kind,
                     prompt=inp.prompt, flag=inp.flag)
            value = self._ask_loop(inp, io.ask)
        st.inputs[inp.name] = value
        st.save()

    # ---- run -----------------------------------------------------------------
    def run(self, until=None, only=None, from_=None) -> RunResult:
        try:
            selected = self._select(only, from_, until)
        except EngineError as e:
            return RunResult(False, EXIT_USAGE, error={"code": "engine.usage", "message": str(e)})
        try:
            self.lock.acquire()
        except _state.Locked as e:
            return RunResult(False, EXIT_ABORTED, error={"code": "engine.locked", "message": str(e)})
        try:
            self.state.reload()
            self._recover()
            if self.ctx.adopt:
                self.state.mode = "adopt"
                self.state.save()
            if not self.ctx.io.interactive:
                missing = self.missing_inputs(selected)
                if missing:
                    flags = [i.flag or i.name for _, i in missing]
                    return RunResult(False, EXIT_USAGE, missing[0][0],
                                     {"code": "engine.missing_input",
                                      "message": "missing: " + " ".join(flags)},
                                     self._statuses(), flags)
            result = None
            self._planned = set()
            for step in selected:
                r = self._run_step(step)
                if r is not None and not r.ok:
                    if not self.ctx.adopt:
                        result = r
                        break
                    result = result or r
            self.ctx.step_id = None
            if result is None:
                result = RunResult(True, EXIT_OK, statuses=self._statuses())
            else:
                result.statuses = self._statuses()
            self.ctx.emit("done", ok=result.ok, exit_code=result.exit_code,
                          summary=self._summary(result))
            return result
        finally:
            self.ctx.step_id = None
            self.lock.release()

    def resume(self) -> RunResult:
        """Continue from the first step that is not done/adopted/skipped."""
        self.state.reload()
        for s in self.steps:
            if self.state.status_of(s.id) not in DONE_LIKE:
                return self.run(from_=s.id)
        return self.run()

    def _summary(self, result):
        if result.ok:
            return "porch setup: ok" + (" (dry run, nothing changed)" if self.ctx.dry_run else "")
        e = result.error or {}
        return f"porch setup: {result.failed_step or ''} failed: {e.get('code', '')} {e.get('message', '')}".strip()

    def _run_step(self, step):
        ctx = self.ctx
        ctx.step_id = step.id
        entry = self.state.step(step.id)
        ctx.emit("step_started", step=step.id, title=step.title)
        try:
            applicable = step.applicable(ctx)
        except Exception as e:  # noqa: BLE001
            return self._fail(step, "preflight", "engine.exception", f"applicable(): {e}", "",
                              EXIT_PREFLIGHT)
        if not applicable:
            if not ctx.dry_run and entry["status"] != "skipped":
                entry["status"] = "skipped"
                self.state.save()
            ctx.emit("step_done", step=step.id, status="skipped")
            return None

        try:
            self._resolve_inputs(step)
        except _io.MissingInput as e:
            flags = [i.flag or i.name for i in e.inputs]
            r = self._fail(step, "inputs", "engine.missing_input", "missing: " + " ".join(flags),
                           "pass the flag(s) or run interactively", EXIT_USAGE)
            r.missing = flags
            return r
        except _io.InvalidInput as e:
            return self._fail(step, "inputs", "engine.invalid_input", str(e), "", EXIT_USAGE)
        except SecretError as e:
            return self._fail(step, "inputs", "secret.store", str(e), "", EXIT_USAGE)

        if ctx.adopt:
            checks = self._checks(step, step.verify)
            if all(c.ok for c in checks):
                if not ctx.dry_run and entry["status"] != "done":
                    entry["status"] = "adopted"
                    entry["error"] = None
                    entry["finished_at"] = _state.now_iso(ctx.clock)
                    self.state.save()
                ctx.emit("step_done", step=step.id, status="adopted")
                return None
            return self._fail_checks(step, "verify", checks, EXIT_VERIFY)

        if entry["status"] in ("done", "adopted"):
            checks = self._checks(step, step.verify)
            if all(c.ok for c in checks):
                ctx.emit("step_done", step=step.id, status="unchanged")
                return None
            ctx.log("verify no longer passes; applying again")

        for r in step.requires:
            if (r in self.by_id and self.state.status_of(r) not in DONE_LIKE
                    and not (ctx.dry_run and r in self._planned)):
                return self._fail(step, "preflight", "engine.requires",
                                  f"needs step {r} first (it is {self.state.status_of(r)})",
                                  f"run `porch setup --only {r}` or a full `porch setup`",
                                  EXIT_PREFLIGHT)

        checks = self._checks(step, step.preflight)
        if not all(c.ok for c in checks):
            return self._fail_checks(step, "preflight", checks, EXIT_PREFLIGHT)

        if ctx.dry_run:
            try:
                actions = list(step.plan(ctx) or [])
            except Exception as e:  # noqa: BLE001
                actions = [Action("error", step.id, f"plan(): {e}")]
            for a in actions:
                ctx.emit("action", step=step.id, kind=a.kind, target=a.target, detail=a.detail)
            self._planned.add(step.id)
            ctx.emit("step_done", step=step.id, status="planned")
            return None

        entry["status"] = "running"
        entry["attempts"] += 1
        entry["started_at"] = _state.now_iso(ctx.clock)
        entry["finished_at"] = None
        entry["error"] = None
        self.state.save()
        try:
            outputs = step.apply(ctx) or {}
        except StepError as e:
            return self._fail(step, "apply", e.code, e.message, e.hint, EXIT_APPLY)
        except Exception as e:  # noqa: BLE001
            return self._fail(step, "apply", "engine.exception", f"{type(e).__name__}: {e}", "",
                              EXIT_APPLY)
        entry["outputs"] = self.ctx.redactor.redact_obj(outputs)
        self.state.save()

        checks = self._checks(step, step.verify)
        if not all(c.ok for c in checks):
            return self._fail_checks(step, "verify", checks, EXIT_VERIFY)
        entry["status"] = "done"
        entry["finished_at"] = _state.now_iso(ctx.clock)
        self.state.save()
        ctx.emit("step_done", step=step.id, status="done")
        return None

    # ---- rollback --------------------------------------------------------------
    def rollback(self, to_step=None) -> RunResult:
        """Undo done/failed steps in reverse order, down to and including
        `to_step` (default: all). Adopted and skipped steps are left alone."""
        if to_step and to_step not in self.by_id:
            return RunResult(False, EXIT_USAGE, error={"code": "engine.usage",
                                                       "message": f"unknown step {to_step!r}"})
        try:
            self.lock.acquire()
        except _state.Locked as e:
            return RunResult(False, EXIT_ABORTED, error={"code": "engine.locked", "message": str(e)})
        ctx = self.ctx
        try:
            self.state.reload()
            self._recover()
            for sid in self.state.steps:
                if sid not in self.by_id and self.state.steps[sid]["status"] in ("done", "failed"):
                    ctx.log(f"step {sid} is in the state file but not installed; cannot roll it back",
                            level="warn")
            for step in reversed(self.steps):
                entry = self.state.steps.get(step.id)
                if entry and entry["status"] in ("done", "failed"):
                    ctx.step_id = step.id
                    ctx.emit("step_started", step=step.id, title=f"rollback {step.title}")
                    if ctx.dry_run:
                        for u in reversed(entry["undo"]):
                            ctx.emit("action", step=step.id, kind="undo." + u.get("kind", "?"),
                                     target=str(u.get("path") or u.get("id") or ""), detail="")
                        ctx.emit("step_done", step=step.id, status="would-roll-back")
                    else:
                        try:
                            step.rollback(ctx, dict(entry["outputs"]))
                        except Exception as e:  # noqa: BLE001
                            msg = e.message if isinstance(e, StepError) else f"{type(e).__name__}: {e}"
                            r = self._fail(step, "rollback", getattr(e, "code", "engine.rollback"),
                                           msg, getattr(e, "hint", ""), EXIT_APPLY)
                            ctx.emit("done", ok=False, exit_code=r.exit_code, summary=self._summary(r))
                            return r
                        entry["status"] = "rolled_back"
                        entry["outputs"] = {}
                        entry["undo"] = []
                        entry["error"] = None
                        entry["finished_at"] = _state.now_iso(ctx.clock)
                        self.state.save()
                        ctx.emit("step_done", step=step.id, status="rolled_back")
                if step.id == to_step:
                    break
            r = RunResult(True, EXIT_OK, statuses=self._statuses())
            ctx.emit("done", ok=True, exit_code=0, summary="porch setup: rolled back")
            return r
        finally:
            ctx.step_id = None
            self.lock.release()

    # ---- read-only views -------------------------------------------------------
    def plan(self) -> dict:
        """{step id: [Action]} for steps that would do something. Changes nothing."""
        ctx = self.ctx
        persist = self.state.persist
        self.state.persist = False
        out = {}
        try:
            for step in self.steps:
                ctx.step_id = step.id
                try:
                    if not step.applicable(ctx):
                        continue
                    if self.state.status_of(step.id) in ("done", "adopted"):
                        if all(c.ok for c in (step.verify(ctx) or [])):
                            continue
                    out[step.id] = list(step.plan(ctx) or [])
                except Exception as e:  # noqa: BLE001
                    out[step.id] = [Action("error", step.id, f"{type(e).__name__}: {e}")]
        finally:
            ctx.step_id = None
            self.state.persist = persist
        return out

    def status(self) -> dict:
        try:
            self.state.reload()
        except _state.StateError:
            pass
        steps = []
        known = set()
        for s in self.steps:
            known.add(s.id)
            e = self.state.steps.get(s.id) or _state.new_step_entry()
            steps.append({"id": s.id, "title": s.title, "status": e["status"],
                          "attempts": e["attempts"], "started_at": e["started_at"],
                          "finished_at": e["finished_at"], "error": e["error"],
                          "undo": len(e["undo"])})
        for sid, e in self.state.steps.items():
            if sid not in known:
                steps.append({"id": sid, "title": "(not installed)", "status": e["status"],
                              "attempts": e["attempts"], "started_at": e["started_at"],
                              "finished_at": e["finished_at"], "error": e["error"],
                              "undo": len(e["undo"])})
        return {"run_id": self.state.run_id, "mode": self.state.mode,
                "state_path": self.state.path, "steps": steps}

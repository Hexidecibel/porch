"""WebIO: the engine's IO protocol (io.py) driven from a browser.

The engine runs in its own thread. When it needs an answer, `ask` /
`ask_secret` / `confirm` publish a *prompt* and block until the browser
answers over HTTP (web.py calls `submit_inputs` / `submit_confirm`), the
prompt times out, or it is cancelled. Every engine event, plus the prompt
events below, goes into a numbered replay buffer that SSE subscribers read
with `wait_events(since)`, so a reloaded page catches up from 0.

    io = WebIO(redactor=ctx_redactor, steps={s.id: s for s in steps})
    io.submit_inputs(step, prompt_id, {"domain": "example.com",
                                       "dns_token": {"value": "..."}})   # -> {name: error}
    io.submit_confirm(prompt_id, True)
    io.events_since(0); io.wait_events(since, timeout)

Prompt events (besides the engine's own, see io.py):
    prompt          the current prompt (see `pending()`), published when it opens
    prompt_closed   id, reason (answered | timeout | cancelled)

Secrets: a secret answer is {"value": "..."} or {"ref": "inf://..."}. The
value is registered with the redactor the moment it arrives and handed to the
engine as SecretAnswer(value=...), which stores it with secretstore.put and
keeps only the ref. It is never put in a prompt, an event, the buffer or a log.
A prompt carries a secret field's name, prompt and flag, never a value.
"""

import collections
import secrets as _secrets
import threading
import time

from . import io as _io
from .secretstore import SecretError, scheme_of

DEFAULT_TIMEOUT = 3600       # s an unanswered prompt waits before the step fails
BUFFER = 4000                # events kept for replay


class WebIO:
    interactive = True

    def __init__(self, redactor=None, steps=None, preset=None, env=None,
                 timeout=DEFAULT_TIMEOUT, buffer=BUFFER, on_activity=None,
                 clock=time.monotonic):
        self.redactor = redactor
        self.steps = dict(steps or {})        # id -> Step, to build a step's whole form
        self.preset = dict(preset or {})      # CLI flags given to `porch setup --web ...`
        self.env = {} if env is None else env
        self.timeout = timeout
        self.on_activity = on_activity
        self.clock = clock
        self._cv = threading.Condition()
        self._buf = collections.deque(maxlen=buffer)
        self._seq = 0
        self._answers = {}                    # name -> raw value | SecretAnswer
        self._pending = None                  # dict (public view) + private bits
        self._inputs = {}                     # name -> Input for the pending prompt
        self._ctx = None
        self._confirm = {}                    # prompt id -> bool
        self._cancelled = set()
        self.closed = False
        self.phone_url = None
        self.phone_step = None

    # ---- event buffer -------------------------------------------------------
    def _publish(self, name, data):
        with self._cv:
            self._seq += 1
            self._buf.append((self._seq, name, data))
            self._cv.notify_all()
        if self.on_activity:
            self.on_activity()

    @property
    def seq(self):
        with self._cv:
            return self._seq

    def events_since(self, since):
        """[(seq, name, data)] newer than `since` still in the buffer."""
        with self._cv:
            return [e for e in self._buf if e[0] > since]

    def wait_events(self, since, timeout):
        """Block until there are events newer than `since` (or timeout / close)."""
        end = self.clock() + timeout
        with self._cv:
            while not self.closed:
                out = [e for e in self._buf if e[0] > since]
                if out:
                    return out
                left = end - self.clock()
                if left <= 0:
                    return []
                self._cv.wait(min(left, 1.0))
            return [e for e in self._buf if e[0] > since]

    def close(self):
        """Wake every waiter; pending prompts fail as missing input."""
        with self._cv:
            self.closed = True
            self._cv.notify_all()

    # ---- IO protocol -------------------------------------------------------
    def event(self, name, /, **data):
        if name == "phone_check":
            self.phone_url = data.get("url")
            self.phone_step = data.get("step")
        elif name in ("step_done", "step_failed", "run_finished") and self.phone_url and \
                (name == "run_finished" or data.get("step") == self.phone_step):
            self.phone_url = self.phone_step = None
        self._publish(name, data)

    def _preset_has(self, inp):
        if inp.name in self.preset:
            return True
        return bool(getattr(inp, "env", "") and self.env.get(inp.env))

    def has(self, inp):
        with self._cv:
            if inp.name in self._answers:
                return True
        return self._preset_has(inp)

    def _take_preset(self, inp, secret):
        if inp.name in self.preset:
            v = self.preset[inp.name]
            return _io.SecretAnswer(ref=v) if secret else v
        if inp.env and self.env.get(inp.env):
            v = self.env[inp.env]
            if secret:
                if self.redactor is not None:
                    self.redactor.add(v)
                return _io.SecretAnswer(value=v)
            return v
        return None

    def ask(self, inp, ctx, error=None):
        return self._ask(inp, ctx, error, secret=False)

    def ask_secret(self, inp, ctx, error=None):
        return self._ask(inp, ctx, error, secret=True)

    def _ask(self, inp, ctx, error, secret):
        with self._cv:
            if error is None and inp.name in self._answers:
                return self._answers.pop(inp.name)
            self._answers.pop(inp.name, None)    # a rejected answer is gone
        if error is None:
            v = self._take_preset(inp, secret)
            if v is not None:
                return v
        pid = self._open_prompt(inp, ctx, error)
        try:
            with self._cv:
                end = self.clock() + self.timeout
                while inp.name not in self._answers:
                    if self.closed or pid in self._cancelled:
                        self._close_prompt(pid, "cancelled")
                        raise _io.MissingInput([inp])
                    left = end - self.clock()
                    if left <= 0:
                        self._close_prompt(pid, "timeout")
                        raise _io.MissingInput([inp])
                    self._cv.wait(min(left, 1.0))
                ans = self._answers.pop(inp.name)
        finally:
            self._cancelled.discard(pid)
        self._close_prompt(pid, "answered")
        return ans

    def confirm(self, prompt, default=False):
        pid = _secrets.token_hex(8)
        view = {"id": pid, "type": "confirm", "step": self._ctx_step(), "prompt": prompt,
                "default": bool(default)}
        with self._cv:
            self._pending = view
            self._inputs = {}
        self._publish("prompt", dict(view))
        with self._cv:
            end = self.clock() + self.timeout
            while pid not in self._confirm:
                if self.closed or pid in self._cancelled:
                    break
                left = end - self.clock()
                if left <= 0:
                    break
                self._cv.wait(min(left, 1.0))
            answer = self._confirm.pop(pid, None)
            self._cancelled.discard(pid)
        reason = "answered" if answer is not None else ("cancelled" if self.closed else "timeout")
        self._close_prompt(pid, reason)
        # No answer is a "no": a confirmation is never assumed.
        return bool(answer) if answer is not None else False

    def _ctx_step(self):
        return getattr(self._ctx, "step_id", None) if self._ctx is not None else None

    # ---- prompts -----------------------------------------------------------
    def _field(self, inp, ctx, error=None):
        f = {"name": inp.name, "kind": inp.kind, "prompt": inp.prompt, "help": inp.help or "",
             "flag": inp.flag or "", "env": inp.env or "", "required": bool(inp.required),
             "error": error or ""}
        if inp.kind != "secret":
            try:
                d = _io.resolve(inp.default, ctx)
            except Exception:  # noqa: BLE001
                d = None
            stored = ctx.state.inputs.get(inp.name) if ctx is not None else None
            d = stored if stored is not None else d
            f["default"] = d if isinstance(d, (str, int, float, bool)) or d is None else str(d)
        if inp.kind == "choice":
            try:
                f["choices"] = [str(c) for c in (_io.resolve(inp.choices, ctx) or [])]
            except Exception:  # noqa: BLE001
                f["choices"] = []
        if inp.name == "connection" and ctx is not None:
            f["cards"] = _connection_cards(ctx)
        return f

    def _form(self, inp, ctx, error):
        """The asked input first, then the step's other inputs that still need
        an answer, so the browser fills one form per step."""
        out = [inp]
        step = self.steps.get(getattr(ctx, "step_id", None))
        if step is None:
            return out
        try:
            others = list(step.inputs(ctx) or [])
        except Exception:  # noqa: BLE001
            others = list(getattr(step, "INPUTS", ()))
        seen = {inp.name}
        found = False
        for o in others:
            if o.name == inp.name:
                found = True
                continue
            if not found or o.name in seen or self._preset_has(o):
                continue
            seen.add(o.name)
            if o.kind == "secret":
                if o.name in ctx.state.secret_refs:
                    continue
            elif o.name in ctx.state.inputs:
                continue
            out.append(o)
        return out

    def _open_prompt(self, inp, ctx, error):
        self._ctx = ctx
        pid = _secrets.token_hex(8)
        form = self._form(inp, ctx, error)
        fields = [self._field(i, ctx, error if i is inp else None) for i in form]
        step = getattr(ctx, "step_id", None)
        st = self.steps.get(step)
        view = {"id": pid, "type": "inputs", "step": step,
                "title": getattr(st, "title", "") or (step or ""), "fields": fields,
                "error": error or ""}
        if self.redactor is not None:
            view = self.redactor.redact_obj(view)
        with self._cv:
            self._pending = view
            self._inputs = {i.name: i for i in form}
        self._publish("prompt", dict(view))
        return pid

    def _close_prompt(self, pid, reason):
        with self._cv:
            if self._pending and self._pending.get("id") == pid:
                self._pending = None
                self._inputs = {}
        self._publish("prompt_closed", {"id": pid, "reason": reason})

    def pending(self):
        with self._cv:
            return dict(self._pending) if self._pending else None

    def cancel(self, pid=None):
        """Cancel the pending prompt (the step fails as missing input)."""
        with self._cv:
            if not self._pending or (pid and self._pending.get("id") != pid):
                return False
            self._cancelled.add(self._pending["id"])
            self._cv.notify_all()
            return True

    def clear(self):
        """Forget queued answers (between runs)."""
        with self._cv:
            self._answers.clear()
            self._confirm.clear()

    # ---- answers from the browser -----------------------------------------
    def submit_confirm(self, pid, answer):
        with self._cv:
            p = self._pending
            if not p or p.get("type") != "confirm" or p.get("id") != pid:
                return False
            self._confirm[pid] = bool(answer)
            self._cv.notify_all()
            return True

    def submit_inputs(self, step, pid, values):
        """Validate the browser's answers for the pending prompt. Returns None
        when the prompt is gone or stale, {name: error} when something is
        wrong (nothing is queued then), {} on success (all queued)."""
        with self._cv:
            p = self._pending
            if not p or p.get("type") != "inputs" or p.get("id") != pid or p.get("step") != step:
                return None
            inputs = dict(self._inputs)
            ctx = self._ctx
        if not isinstance(values, dict):
            return {"": "bad request"}
        errors, queued = {}, {}
        for name, inp in inputs.items():
            raw = values.get(name)
            try:
                if inp.kind == "secret":
                    queued[name] = self._secret_answer(inp, raw)
                else:
                    queued[name] = self._plain_answer(inp, raw, ctx)
            except _io.InvalidInput as e:
                errors[name] = str(e)
        if errors:
            return errors
        with self._cv:
            if not self._pending or self._pending.get("id") != pid:
                return None
            self._answers.update(queued)
            self._cv.notify_all()
        return {}

    def _plain_answer(self, inp, raw, ctx):
        if inp.kind == "bool":
            if raw is None or raw == "":
                d = _io.resolve(inp.default, ctx)
                raw = bool(d) if d is not None else False
            value = _io.coerce(inp, raw, ctx)
        else:
            if raw is None:
                raw = ""
            if not isinstance(raw, (str, int, float)):
                raise _io.InvalidInput("expected text")
            raw = str(raw)
            if len(raw) > 4096:
                raise _io.InvalidInput("too long")
            if raw.strip() == "":
                d = _io.resolve(inp.default, ctx)
                if d is not None and d != "":
                    raw = d
                elif inp.required:
                    raise _io.InvalidInput("required")
            value = _io.coerce(inp, raw, ctx)
        if inp.validate and value is not None and value != "":
            msg = inp.validate(value)
            if msg:
                raise _io.InvalidInput(msg)
        return value

    def _secret_answer(self, inp, raw):
        if not isinstance(raw, dict):
            raise _io.InvalidInput("enter the value, or a stored ref")
        ref, value = raw.get("ref"), raw.get("value")
        if isinstance(ref, str) and ref.strip():
            ref = ref.strip()
            try:
                scheme_of(ref)
            except SecretError:
                # Never echo it: a mistyped ref may be the secret itself.
                raise _io.InvalidInput("a ref starts with inf://, op:// or file://") from None
            return _io.SecretAnswer(ref=ref)
        if not isinstance(value, str) or value.strip() == "":
            raise _io.InvalidInput("required")
        if len(value) > 65536:
            raise _io.InvalidInput("too long")
        if self.redactor is not None:
            self.redactor.add(value)
        if inp.validate:
            msg = inp.validate(value)
            if msg:
                raise _io.InvalidInput(msg if self.redactor is None else self.redactor.redact(msg))
        return _io.SecretAnswer(value=value)


def _connection_cards(ctx):
    """[{name,title,status,reason,built,recommended}] for the connection step."""
    try:
        from .steps import connection as _conn
        facts = ctx.facts.get("network") or {}
        rows, rec = _conn.assess(ctx, facts)
    except Exception:  # noqa: BLE001
        return []
    return [{"name": r["name"], "title": r["title"], "status": r["status"],
             "reason": r["reason"], "built": bool(r.get("built")),
             "recommended": r["name"] == rec} for r in rows]

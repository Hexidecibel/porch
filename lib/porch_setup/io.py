"""The engine's UI protocol, and the CLI / test implementations.

The engine never prints or prompts by itself: it calls `ctx.io`. Anything
that implements `IO` below can drive it (WebIO in porch_setup/web.py is W3's
and lives there; it only needs these five members).

    class IO(Protocol):
        interactive: bool
        def has(self, inp) -> bool                       # answerable without prompting?
        def ask(self, inp, ctx, error=None) -> Any       # text / choice / bool
        def ask_secret(self, inp, ctx, error=None) -> SecretAnswer
        def confirm(self, prompt, default=False) -> bool
        def event(self, name, /, **data) -> None    # data may contain a 'kind' key

`ask` / `ask_secret` raise MissingInput when they cannot get an answer (non-
interactive and no flag/env). `error` is the previous answer's validation
message when the engine re-asks. Values handed to `event` are already
redacted by the engine.

Event kinds (and their data):
    step_started  step, title
    check         step, ok, code, message, hint
    action        step, kind, target, detail
    step_done     step, status            (done | adopted | skipped | unchanged | rolled_back)
    step_failed   step, phase, code, message, hint
    needs_input   step, name, kind, prompt, flag
    log           message, level, step
    done          ok, exit_code, summary
"""

import getpass as _getpass
import os
import sys
from dataclasses import dataclass
from typing import Any, Optional, Protocol, runtime_checkable


class MissingInput(Exception):
    def __init__(self, inputs, step=None):
        self.inputs = list(inputs)
        self.step = step
        names = ", ".join(i.flag or i.name for i in self.inputs)
        super().__init__(f"missing input: {names}")


class InvalidInput(Exception):
    pass


@dataclass
class SecretAnswer:
    """Exactly one of `ref` (an existing secret: inf:// op:// file://) or
    `value` (a new secret the engine will store with secretstore.put)."""
    ref: Optional[str] = None
    value: Optional[str] = None


@runtime_checkable
class IO(Protocol):
    interactive: bool

    def has(self, inp) -> bool: ...
    def ask(self, inp, ctx, error=None) -> Any: ...
    def ask_secret(self, inp, ctx, error=None) -> SecretAnswer: ...
    def confirm(self, prompt, default=False) -> bool: ...
    def event(self, name, /, **data) -> None: ...


def resolve(v, ctx):
    """Input.default / Input.choices may be a value or a callable(ctx)."""
    return v(ctx) if callable(v) else v


def coerce(inp, raw, ctx=None):
    """Turn a raw answer (str from a prompt/flag, or a typed value) into the
    Input's type. Raises InvalidInput."""
    if inp.kind == "bool":
        if isinstance(raw, bool):
            return raw
        s = str(raw).strip().lower()
        if s in ("y", "yes", "true", "1", "on"):
            return True
        if s in ("n", "no", "false", "0", "off"):
            return False
        raise InvalidInput("answer yes or no")
    if inp.kind == "choice":
        choices = [str(c) for c in (resolve(inp.choices, ctx) or [])]
        s = str(raw).strip()
        if choices and s not in choices:
            raise InvalidInput("choose one of: " + ", ".join(choices))
        return s
    if isinstance(raw, str):
        return raw.strip()
    return raw


class BaseIO:
    interactive = False

    def has(self, inp):
        return False

    def ask(self, inp, ctx, error=None):
        raise MissingInput([inp])

    def ask_secret(self, inp, ctx, error=None):
        raise MissingInput([inp])

    def confirm(self, prompt, default=False):
        return default

    def event(self, name, /, **data):
        pass


class NullIO(BaseIO):
    """For tests. Never prompts.

    answers:  {input name: value}. For a secret input the value is either a
              SecretAnswer, a str starting with a scheme (taken as a ref), or
              any other str (taken as the secret value).
    confirms: True/False for every confirm(), or {prompt substring: bool}
              (unmatched prompts get `default`).
    Records every event as (name, data) in `.events`, every asked input name
    in `.asked`, every confirm prompt in `.prompts`."""

    def __init__(self, answers=None, confirms=None):
        self.answers = dict(answers or {})
        self.confirms = confirms
        self.events = []
        self.asked = []
        self.prompts = []

    def has(self, inp):
        return inp.name in self.answers

    def ask(self, inp, ctx, error=None):
        self.asked.append(inp.name)
        if error is not None or inp.name not in self.answers:
            raise MissingInput([inp]) if error is None else InvalidInput(error)
        return self.answers[inp.name]

    def ask_secret(self, inp, ctx, error=None):
        self.asked.append(inp.name)
        if error is not None:
            raise InvalidInput(error)
        if inp.name not in self.answers:
            raise MissingInput([inp])
        a = self.answers[inp.name]
        if isinstance(a, SecretAnswer):
            return a
        if isinstance(a, str) and a.split("://", 1)[0] in ("inf", "op", "file") and "://" in a:
            return SecretAnswer(ref=a)
        return SecretAnswer(value=a)

    def confirm(self, prompt, default=False):
        self.prompts.append(prompt)
        if isinstance(self.confirms, bool):
            return self.confirms
        if isinstance(self.confirms, dict):
            for k, v in self.confirms.items():
                if k in prompt:
                    return v
        return default

    def event(self, name, /, **data):
        self.events.append((name, data))

    def kinds(self, name=None):
        """Data of every event called `name` (all events if None), for asserts."""
        return [d for k, d in self.events if name is None or k == name]


class CliIO(BaseIO):
    """Terminal front-end.

    answers:     {input name: value} from argparse (bin/porch maps each
                 Input.flag). For secret inputs this is a ref
                 (--dns-token-ref inf://...); secret VALUES only ever come
                 from Input.env (e.g. PORCH_DNS_TOKEN) or getpass.
    interactive: prompt on the tty (default: stdin is a tty).
    yes:         confirm() returns True without asking."""

    def __init__(self, answers=None, interactive=None, yes=False, env=None,
                 out=None, stdin=None, getpass=None, verbose=False):
        self.answers = {k: v for k, v in (answers or {}).items() if v is not None}
        self.stdin = stdin or sys.stdin
        self.out = out or sys.stderr
        self.interactive = (self.stdin.isatty() if interactive is None else interactive)
        self.yes = yes
        self.env = os.environ if env is None else env
        self._getpass = getpass or _getpass.getpass
        self.verbose = verbose

    def _p(self, s=""):
        print(s, file=self.out, flush=True)

    def has(self, inp):
        if inp.name in self.answers:
            return True
        return bool(getattr(inp, "env", "") and self.env.get(inp.env))

    def _line(self, prompt):
        self.out.write(prompt)
        self.out.flush()
        line = self.stdin.readline()
        if not line:
            raise MissingInput([])
        return line.rstrip("\n")

    def ask(self, inp, ctx, error=None):
        if error is None:
            if inp.name in self.answers:
                return self.answers[inp.name]
            if inp.env and self.env.get(inp.env):
                return self.env[inp.env]
        if not self.interactive:
            if error is not None:
                raise InvalidInput(error)
            raise MissingInput([inp])
        if error:
            self._p(f"  ! {error}")
        default = resolve(inp.default, ctx)
        choices = resolve(inp.choices, ctx) if inp.kind == "choice" else None
        if inp.help:
            self._p(f"  {inp.help}")
        if choices:
            self._p("  choices: " + ", ".join(str(c) for c in choices))
        if inp.kind == "bool":
            hint = " [Y/n]" if default else " [y/N]"
        else:
            hint = f" [{default}]" if default not in (None, "") else ""
        raw = self._line(f"? {inp.prompt}{hint}: ")
        if raw.strip() == "" and default is not None:
            return default
        return raw

    def ask_secret(self, inp, ctx, error=None):
        if error is None:
            if inp.name in self.answers:
                return SecretAnswer(ref=self.answers[inp.name])
            if inp.env and self.env.get(inp.env):
                return SecretAnswer(value=self.env[inp.env])
        if not self.interactive:
            if error is not None:
                raise InvalidInput(error)
            raise MissingInput([inp])
        if error:
            self._p(f"  ! {error}")
        if inp.help:
            self._p(f"  {inp.help}")
        v = self._getpass(f"? {inp.prompt} (hidden): ")
        if v.strip() == "":
            raise MissingInput([inp])
        return SecretAnswer(value=v)

    def confirm(self, prompt, default=False):
        if self.yes:
            return True
        if not self.interactive:
            return default
        raw = self._line(f"? {prompt} {'[Y/n]' if default else '[y/N]'}: ").strip().lower()
        if not raw:
            return default
        return raw in ("y", "yes")

    def event(self, name, /, **d):
        kind = name
        if kind == "step_started":
            self._p(f"==> {d['step']}: {d.get('title', '')}")
        elif kind == "check":
            if d["ok"] and not self.verbose:
                return
            mark = "ok  " if d["ok"] else "FAIL"
            self._p(f"  [{mark}] {d['code']}: {d['message']}")
            if not d["ok"] and d.get("hint"):
                self._p(f"         hint: {d['hint']}")
        elif kind == "action":
            self._p(f"  - {d['kind']} {d['target']}" + (f"  ({d['detail']})" if d.get("detail") else ""))
        elif kind == "step_done":
            self._p(f"  {d['status']}")
        elif kind == "step_failed":
            self._p(f"  FAILED ({d['phase']}) {d['code']}: {d['message']}")
            if d.get("hint"):
                self._p(f"  hint: {d['hint']}")
        elif kind == "needs_input":
            pass
        elif kind == "log":
            if d.get("level") == "error":
                return  # the step_failed event already said it
            if d.get("level") != "debug" or self.verbose:
                self._p(f"  {d['message']}")
        elif kind == "done":
            if d.get("summary"):
                self._p(d["summary"])

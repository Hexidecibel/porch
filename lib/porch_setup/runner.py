"""Subprocess wrapper every step uses instead of calling subprocess directly.

    r = ctx.run.run(["haproxy", "-c", "-f", path], mutating=False)
    r.ok, r.returncode, r.stdout, r.stderr

- argv is always a list (never a shell string).
- mutating=True (the default) calls are NOT executed under dry_run: they are
  recorded and return Result(returncode=0, dry_run=True). Read-only probes
  must pass mutating=False so they still run in --dry-run / --adopt.
- sudo=True prefixes `sudo -n` unless already root.
- check=True raises RunError on a non-zero exit.
- Every recorded call (Runner.calls) and every log line has known secret
  values masked by the redactor. The Result returned to the caller is raw.

FakeRunner (tests) never executes anything:
    fr = FakeRunner()
    fr.on(["haproxy", "-c"], stdout="Configuration file is valid")
    fr.on(lambda argv: argv[0] == "certbot", returncode=1, stderr="boom")
    fr.on(["systemctl"], func=lambda argv, **kw: Result(argv, 0, "active\\n", ""))
    fr.tools["haproxy"] = "/usr/sbin/haproxy"        # what which() returns
    fr.calls / fr.mutating_calls() / fr.argvs()
Rules match by argv prefix (or predicate); the first registered match wins;
unmatched calls return rc 0 with empty output (strict=True raises instead).
"""

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from . import redact as _redact


@dataclass
class Result:
    argv: List[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    dry_run: bool = False

    @property
    def ok(self):
        return self.returncode == 0


class RunError(Exception):
    def __init__(self, result, message):
        self.result = result
        super().__init__(message)


class Runner:
    def __init__(self, dry_run=False, redactor=None, sudo_cmd=("sudo", "-n"),
                 env=None, log: Optional[Callable[[str], None]] = None):
        self.dry_run = dry_run
        self.redactor = redactor or _redact.REDACTOR
        self.sudo_cmd = list(sudo_cmd)
        self.env = env
        self.log = log
        self.calls = []

    # ---- recording -----------------------------------------------------------
    def _record(self, argv, sudo, mutating, result, cwd):
        red = self.redactor.redact
        rec = {"argv": [red(a) for a in argv], "sudo": sudo, "mutating": mutating,
               "cwd": cwd, "returncode": result.returncode, "dry_run": result.dry_run,
               "stdout": red(result.stdout), "stderr": red(result.stderr)}
        self.calls.append(rec)
        if self.log:
            prefix = "would run" if result.dry_run else "run"
            self.log(f"{prefix}: {' '.join(rec['argv'])}" +
                     ("" if result.dry_run else f" -> {result.returncode}"))
        return rec

    def mutating_calls(self):
        return [c for c in self.calls if c["mutating"]]

    def argvs(self):
        return [c["argv"] for c in self.calls]

    # ---- api -----------------------------------------------------------------
    def which(self, name):
        return shutil.which(name)

    def _full_argv(self, argv, sudo):
        if sudo and os.geteuid() != 0:
            return self.sudo_cmd + argv
        return list(argv)

    def _execute(self, argv, *, input, env, cwd, timeout):
        full_env = None
        if self.env is not None or env is not None:
            full_env = dict(os.environ if self.env is None else self.env)
            full_env.update(env or {})
        try:
            p = subprocess.run(argv, input=input, capture_output=True, text=True,
                               env=full_env, cwd=cwd, timeout=timeout)
            return Result(list(argv), p.returncode, p.stdout, p.stderr)
        except FileNotFoundError:
            return Result(list(argv), 127, "", f"{argv[0]}: command not found")
        except subprocess.TimeoutExpired as e:
            out = e.stdout.decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
            return Result(list(argv), 124, out, f"timed out after {timeout}s")

    def run(self, argv, *, sudo=False, mutating=True, input=None, check=False,
            env=None, cwd=None, timeout=300) -> Result:
        if isinstance(argv, str) or not argv:
            raise TypeError("Runner.run takes a non-empty argv list, never a shell string")
        argv = [os.fspath(a) for a in argv]
        if self.dry_run and mutating:
            result = Result(list(argv), 0, "", "", dry_run=True)
        else:
            result = self._execute(self._full_argv(argv, sudo), input=input, env=env,
                                   cwd=cwd, timeout=timeout)
            result.argv = list(argv)
        rec = self._record(argv, sudo, mutating, result, cwd)
        if check and not result.ok:
            tail = (rec["stderr"] or rec["stdout"]).strip().splitlines()[-3:]
            raise RunError(result, f"{' '.join(rec['argv'])} exited {result.returncode}"
                           + (": " + " | ".join(tail) if tail else ""))
        return result


@dataclass
class _Rule:
    match: object
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    func: Optional[Callable] = None

    def matches(self, argv):
        if callable(self.match):
            return bool(self.match(argv))
        m = list(self.match)
        return argv[:len(m)] == m


class FakeRunner(Runner):
    def __init__(self, dry_run=False, redactor=None, strict=False, tools=None):
        super().__init__(dry_run=dry_run, redactor=redactor)
        self.rules = []
        self.strict = strict
        self.tools = dict(tools or {})
        self.inputs = []  # stdin passed per call, in order (raw)

    def on(self, match, returncode=0, stdout="", stderr="", func=None):
        self.rules.append(_Rule(match, returncode, stdout, stderr, func))
        return self

    def which(self, name):
        return self.tools.get(name)

    def _full_argv(self, argv, sudo):
        return list(argv)

    def _execute(self, argv, *, input, env, cwd, timeout):
        self.inputs.append(input)
        for r in self.rules:
            if r.matches(argv):
                if r.func:
                    return r.func(argv, input=input, env=env, cwd=cwd)
                return Result(list(argv), r.returncode, r.stdout, r.stderr)
        if self.strict:
            raise AssertionError(f"FakeRunner: unexpected call {argv!r}")
        return Result(list(argv), 0, "", "")

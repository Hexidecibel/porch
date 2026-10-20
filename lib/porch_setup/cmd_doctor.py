"""porch doctor [--json] [--fix-hints]: read-only health check.

Runs every registered step's verify() (no inputs asked, nothing written: the
context is dry-run, so mutating commands are skipped and state is not saved)
plus a few extras the steps do not own: the localhost bypass and home frpc
token, and config validity. Exit 0 when everything passes, 5 otherwise.
"""

import argparse
import json
import os
import stat
import sys

from . import registry
from .engine import Check, make_context
from .io import NullIO


def extras(ctx):
    out = []
    try:
        import porch_config
        cfg = porch_config.load(env=ctx.env)
        out.append(Check(True, "doctor.config", f"config ok: {cfg.source or 'built-in defaults'}"))
    except Exception as e:  # noqa: BLE001
        return [Check(False, "doctor.config", f"config/porch.toml is invalid: {e}",
                      "python3 lib/porch_config.py check")]
    v = (ctx.env.get("PORCH_LOCALHOST_BYPASS") or "").strip().lower()
    bypass = True if v in ("1", "true", "yes", "on") else False if v in ("0", "false", "no", "off") \
        else cfg.localhost_bypass
    adopted = cfg.install_mode == "adopt"
    out.append(Check(not bypass or adopted, "doctor.bypass",
                     f"localhost frpc bypass: {'ON' if bypass else 'off'}"
                     + (" (adopted install: relay modes stay refused until it is off)" if bypass else ""),
                     "set [adopt] localhost_bypass = false and restart the auth server"))
    from porch_setup.steps._common import app_data_dir
    tok = os.path.join(app_data_dir(ctx), ".home-frpc-token")
    try:
        st = os.stat(tok)
        private = not (st.st_mode & 0o077) and stat.S_ISREG(st.st_mode)
        out.append(Check(private, "doctor.home_token",
                         "home frpc token present" + ("" if private else " but readable by others"),
                         f"chmod 600 {tok}"))
    except FileNotFoundError:
        out.append(Check(bypass, "doctor.home_token",
                         "no home frpc token yet" + (" (fine while the bypass is on)" if bypass else ""),
                         "restart the auth server: it mints data/.home-frpc-token on start"))
    return out


def main(argv, steps=None, ctx=None, out=None):
    out = out or sys.stdout
    p = argparse.ArgumentParser(prog="porch doctor", description="Read-only porch health check.")
    p.add_argument("--json", action="store_true")
    p.add_argument("--fix-hints", action="store_true", help="print a hint under every failure")
    args = p.parse_args(argv)
    steps = registry.steps() if steps is None else steps
    ctx = ctx or make_context(io=NullIO(), dry_run=True)
    report = []
    for step in steps:
        ctx.step_id = step.id
        try:
            if not step.applicable(ctx):
                report.append({"step": step.id, "skipped": True, "checks": []})
                continue
            checks = list(step.verify(ctx) or [])
        except Exception as e:  # noqa: BLE001
            checks = [Check(False, "doctor.exception", f"{type(e).__name__}: {e}")]
        report.append({"step": step.id, "skipped": False, "checks": checks})
    ctx.step_id = None
    report.append({"step": "extras", "skipped": False, "checks": extras(ctx)})
    red = ctx.redactor.redact
    failed = sum(1 for r in report for ch in r["checks"] if not ch.ok)
    total = sum(len(r["checks"]) for r in report)
    if args.json:
        print(json.dumps({"ok": not failed, "failed": failed, "total": total, "steps": [
            {"step": r["step"], "skipped": r["skipped"],
             "checks": [{"ok": ch.ok, "code": ch.code, "message": red(ch.message),
                         "hint": red(ch.hint)} for ch in r["checks"]]} for r in report]},
            indent=2), file=out)
    else:
        for r in report:
            if r["skipped"]:
                print(f"{r['step']}: skipped (not applicable)", file=out)
                continue
            bad = [ch for ch in r["checks"] if not ch.ok]
            print(f"{r['step']}: {'ok' if not bad else f'{len(bad)} problem(s)'}", file=out)
            for ch in r["checks"]:
                if ch.ok:
                    continue
                print(f"  FAIL {ch.code}: {red(ch.message)}", file=out)
                if args.fix_hints and ch.hint:
                    print(f"       fix: {red(ch.hint)}", file=out)
        print(f"porch doctor: {total - failed}/{total} checks pass", file=out)
    return 0 if not failed else 5

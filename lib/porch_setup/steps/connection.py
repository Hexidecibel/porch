"""connection (ORDER 40): pick how the internet reaches this box and set it up.

Every registered mode (connect/*.py) is assessed against the network facts:
works / likely / unavailable, with a reason. The recommendation is the first
"works" mode (direct, then upnp, then manual, then the relays), else the
first "likely" one. IPv6 is listed as "coming later".

A mode may ask for its own inputs (Mode.inputs: the relays' provider, token,
host, ...). They are added once the mode is chosen: the engine re-reads a
step's inputs after every answer, so `porch setup` asks for them right after
the connection choice, and --non-interactive lists their flags as missing.

Outputs: mode, method, ingress_ipv4, ingress_ipv6, ddns. It also writes
state["connection"]["active"] and appends to ["history"]. Switching modes
(porch connect <mode>) sets up the new mode first, then tears down the old
mode's recorded changes.
"""

from .. import registry
from .. import state as _state
from ..connect.base import LIKELY, STATUS_RANK, UNAVAILABLE, WORKS
from ..engine import Check, Input, Step, StepError
from . import network_probe as _np

ORDER = 40

LATER = {
    "ipv6": "IPv6 only (AAAA records; IPv4-only visitors cannot reach it)",
}


def _later_reason(name, facts):
    if name == "ipv6":
        return ("this box has global IPv6 " + facts["ipv6"][0] if facts.get("ipv6")
                else "no global IPv6 address") + "; coming later"
    if facts.get("cgnat"):
        return "the fix for carrier-grade NAT; coming later"
    return "coming later"


def assess(ctx, facts, modes=None):
    """[{name, title, status, reason, built}] best first, and the recommended name."""
    modes = registry.modes() if modes is None else modes
    rows = []
    for name, mode in modes.items():
        try:
            status, reason = mode.detect(ctx, facts)
        except Exception as e:  # noqa: BLE001
            status, reason = UNAVAILABLE, f"detection failed: {e}"
        rows.append({"name": name, "title": mode.title, "status": status, "reason": reason,
                     "built": True, "order": getattr(mode, "order", 50)})
    rows.sort(key=lambda r: (STATUS_RANK.get(r["status"], 9), r["order"], r["name"]))
    rec = next((r["name"] for r in rows if r["status"] == WORKS), None) or \
        next((r["name"] for r in rows if r["status"] == LIKELY), None)
    for name, title in LATER.items():
        if name not in modes:
            rows.append({"name": name, "title": title, "status": "later",
                         "reason": _later_reason(name, facts), "built": False, "order": 99})
    return rows, rec


def table(rows, rec, active=None):
    out = []
    for r in rows:
        mark = "*" if r["name"] == rec else " "
        act = " (active)" if active and r["name"] == active else ""
        out.append(f" {mark} {r['name']:<8} {r['status']:<11} {r['title']}{act}")
        out.append(f"   {'':<8} {'':<11} {r['reason']}")
    if rec:
        out.append(f" * recommended: {rec}")
    else:
        out.append(" no connection mode can work here")
    return out


def _facts(ctx):
    # `porch connect` sets ctx.refresh_network so a switch sees live facts.
    if getattr(ctx, "refresh_network", False):
        ctx.refresh_network = False
        return _np.ensure(ctx, refresh=True)
    return _np.ensure(ctx)


def _recommended(ctx):
    try:
        _rows, rec = assess(ctx, _facts(ctx))
    except Exception:  # noqa: BLE001
        return "manual"
    return rec or "manual"


def _choices(ctx=None):
    return sorted(set(registry.modes()) | set(LATER))


_STATIC = Input("connection", "choice", "How should the internet reach this box?",
                default=_recommended, choices=_choices, flag="--connection",
                help="direct, upnp, manual, paid, oracle or byo (see `porch connect --status`)")


def _mode_inputs():
    """Every mode's inputs (for the static INPUTS -> `porch setup` flags)."""
    seen, out = set(), []
    for mode in registry.modes().values():
        try:
            items = mode.inputs(None)
        except Exception:  # noqa: BLE001 - a mode whose inputs need a context
            items = []
        for i in items or []:
            if i.flag and i.flag not in seen:
                seen.add(i.flag)
                out.append(i)
    return tuple(out)


def selected(ctx):
    """The chosen mode name, before or after it is stored: an explicit answer
    (CLI flag, NullIO / web preset) wins over the stored one."""
    for attr in ("answers", "preset"):
        v = (getattr(ctx.io, attr, None) or {}).get("connection")
        if v:
            return str(v)
    return ctx.input("connection")


class Connection(Step):
    id = "connection"
    title = "Connection"
    requires = ("network_probe",)

    @property
    def INPUTS(self):  # noqa: N802 - the Step contract's name
        return (_STATIC,) + _mode_inputs()

    def inputs(self, ctx):
        facts = _facts(ctx)
        rows, rec = assess(ctx, facts)
        help_text = "\n".join(["How visitors reach this box:"] + table(rows, rec))
        out = [Input("connection", "choice", _STATIC.prompt, default=rec or "manual",
                     choices=_choices(), flag="--connection", help=help_text)]
        mode = registry.modes().get(selected(ctx) or "")
        if mode is not None:
            out += list(mode.inputs(ctx) or [])
        return out

    def _mode(self, ctx):
        name = ctx.input("connection")
        return name, registry.modes().get(name)

    def preflight(self, ctx):
        facts = _facts(ctx)
        name, mode = self._mode(ctx)
        rows, rec = assess(ctx, facts)
        for line in table(rows, rec):
            ctx.log(line, "debug")
        if mode is None:
            if name in LATER:
                return [Check(False, "connection.later", f"{name}: {LATER[name]} is coming later",
                              f"use {rec}" if rec else "relay modes are not built yet")]
            return [Check(False, "connection.unknown", f"unknown connection mode {name!r}",
                          "choose one of: " + ", ".join(sorted(registry.modes())))]
        status, reason = mode.detect(ctx, facts)
        ok = status != UNAVAILABLE
        hint = ""
        if not ok:
            from ..relay import common as _relay
            hint = (_relay.BYPASS_HINT if reason == _relay.BYPASS_REASON
                    else f"use {rec} instead" if rec else "this network needs a relay mode (paid, oracle, byo)")
        return [Check(ok, f"connection.{name}", f"{name}: {status}: {reason}", hint)]

    def plan(self, ctx):
        _name, mode = self._mode(ctx)
        return mode.plan(ctx, _facts(ctx)) if mode else []

    def apply(self, ctx):
        facts = _facts(ctx)
        name, mode = self._mode(ctx)
        if mode is None:
            raise StepError("connection.unknown", f"unknown connection mode {name!r}")
        conn = ctx.state.connection
        prev = (conn.get("active") or {}).get("mode")
        out = dict(mode.apply(ctx, facts) or {})
        if prev and prev != name:
            self._teardown(ctx, prev)
        _rows, rec = assess(ctx, facts)
        now = _state.now_iso(ctx.clock)
        conn["active"] = {"mode": name, "method": out.get("method", name), "since": now,
                          "ingress_ipv4": out.get("ingress_ipv4"),
                          "ingress_ipv6": out.get("ingress_ipv6"), "ddns": bool(out.get("ddns"))}
        if prev != name:
            conn.setdefault("history", []).append({"mode": name, "from": prev, "at": now})
        ctx.state.save()
        return {"mode": name, "recommended": rec, **out}

    def _teardown(self, ctx, old_name):
        old = registry.modes().get(old_name)
        for entry in ctx.undo_entries():
            if entry.get("mode") != old_name:
                continue
            try:
                if old is None:
                    raise NotImplementedError(f"mode {old_name} is gone")
                old.undo(ctx, entry)
                ctx.drop_undo(entry)
            except Exception as e:  # noqa: BLE001
                ctx.log(f"could not undo {entry.get('kind')} from {old_name}: {e}; "
                        "it stays recorded for `porch setup --rollback`", "warn")

    def verify(self, ctx):
        name, mode = self._mode(ctx)
        active = (ctx.state.connection.get("active") or {}).get("mode")
        if ctx.adopt and active is None and mode is not None:
            # An existing install set up by hand: accept the chosen mode if it
            # can work here; the smoke step proves reachability.
            status, reason = mode.detect(ctx, ctx.facts.get("network") or _facts(ctx))
            return [Check(status != UNAVAILABLE, "connection.adopt", f"{name}: {status}: {reason}",
                          "" if status != UNAVAILABLE else "choose another --connection")]
        if active != name or mode is None:
            return [Check(False, "connection.active", f"active mode is {active}, wanted {name}",
                          f"run `porch connect {name}`")]
        return mode.verify(ctx, ctx.facts.get("network") or {}, ctx.outputs(self.id))

    def undo(self, ctx, entry):
        m = registry.modes().get(entry.get("mode", ""))
        if m is not None and not entry.get("kind", "").startswith("file."):
            m.undo(ctx, entry)
            return
        super().undo(ctx, entry)

    def rollback(self, ctx, outputs):
        super().rollback(ctx, outputs)
        conn = ctx.state.connection
        if conn.get("active"):
            conn.setdefault("history", []).append({"mode": None, "from": conn["active"].get("mode"),
                                                   "at": _state.now_iso(ctx.clock)})
            conn["active"] = None
            ctx.state.save()


STEP = Connection()

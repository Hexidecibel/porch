"""manual: a guided port forward. Porch shows the guide for the detected
router brand (admin URL, menu path, notes), this box's LAN IP and the three
ports, waits for "done", then runs the phone check and loops with specific
hints when it fails.

Before HAProxy, frps, DNS and the certificate exist (a fresh install, where
this step runs at ORDER 40) a tunnel URL cannot route yet, so the check is
deferred to the smoke step and the mode reports reach="deferred".
"""

from ..engine import Action, Check, StepError
from ..net import reach as _reach
from ..net import router as _router
from .base import LIKELY, PORT_USE, PORTS, UNAVAILABLE, WORKS, Mode, ingress_v6

ATTEMPTS = 3
REACH_TIMEOUT = 300

HINTS = (
    "Check each forward points at {lan} (not another device) and uses TCP, with the same external and internal port.",
    "Give this box a DHCP reservation for {lan}; if its address changed, the forwards point at nothing.",
    "If there is a second router (an ISP gateway in front of yours), forward on both, or put the ISP box in bridge mode.",
    "Some ISPs block inbound 80/443 on home plans; ask them, or use a relay mode (coming later).",
)


class ManualMode(Mode):
    name = "manual"
    title = "Port forwarding (guided, in your router's settings)"
    summary = "You add three port forwards in the router; Porch shows where and checks the result."
    order = 30

    def __init__(self):
        self.phone_check = _reach.phone_check
        self.stack_ready = _reach.stack_ready
        self.timeout = REACH_TIMEOUT

    def detect(self, ctx, facts):
        if facts.get("host_public_ipv4"):
            return UNAVAILABLE, "not needed: this machine has a public IP (use direct)"
        if facts.get("cgnat"):
            return UNAVAILABLE, (facts.get("cgnat_reason") or "carrier-grade NAT") + "; forwarding cannot help"
        g = _router.guide_for((facts.get("router") or {}).get("brand"))
        if g.get("cgnat"):
            return UNAVAILABLE, f"{g['name']}: {g.get('notes', '')}"
        if not facts.get("public_ipv4"):
            return LIKELY, "public address unknown; forwarding should work if the router has a public WAN IP"
        if ctx.facts.get("reach_ok"):
            return WORKS, "the phone check already passed"
        return LIKELY, f"the router's WAN address is public ({facts['public_ipv4']}); needs 3 forwards in its settings"

    def guide(self, facts):
        brand = (facts.get("router") or {}).get("brand")
        g = _router.guide_for(brand)
        gw = facts.get("gateway") or "<gateway>"
        lan = facts.get("lan_ipv4") or "<this box>"
        lines = [f"Router: {g.get('name') or 'your router'}"
                 + (" (managed from its phone app)" if g.get("app_only") else ""),
                 f"Open: {g.get('admin_url', '').replace('<gateway>', gw)}",
                 f"Go to: {g.get('menu', '')}",
                 f"Forward these to {lan} (this box):"]
        for p in PORTS:
            lines.append(f"    TCP {p:>5} -> {lan}:{p}    {PORT_USE[p]}")
        if g.get("notes"):
            lines.append("Note: " + g["notes"])
        if g.get("upnp"):
            lines.append(f"Tip: turning UPnP on ({g['upnp']}) lets `porch connect upnp` do this for you.")
        return lines

    def steps(self, ctx, facts):
        return self.guide(facts) + ["Then confirm, and open the phone-check link on cellular."]

    def plan(self, ctx, facts):
        lan = facts.get("lan_ipv4")
        return [Action("manual.forward", f"tcp {p}", f"-> {lan}:{p} (you, in the router)") for p in PORTS]

    def apply(self, ctx, facts):
        lan = facts.get("lan_ipv4") or "this box"
        ctx.log("\n".join(self.guide(facts)))
        out = {"method": "manual", "ingress_ipv4": facts.get("public_ipv4"),
               "ingress_ipv6": ingress_v6(facts), "ddns": True, "lan_ipv4": facts.get("lan_ipv4"),
               "ports": list(PORTS)}
        if not ctx.confirm(f"Have you forwarded TCP {', '.join(map(str, PORTS))} to {lan}?", default=False):
            raise StepError("connect.manual.not_done", "port forwarding not confirmed",
                            "add the forwards, then run `porch connect manual` again (or pass --yes)")
        if not self.stack_ready(ctx):
            ctx.log("The phone check needs HAProxy, frps, DNS and the certificate, which later steps "
                    "set up; the smoke step will run it.")
            out["reach"] = "deferred"
            return out
        local = [facts.get("public_ipv4")] if facts.get("public_ipv4") else []
        detail = ""
        for attempt in range(ATTEMPTS):
            ok, detail = self.phone_check(ctx, timeout=self.timeout, local_ips=local)
            if ok:
                out["reach"] = "ok"
                out["reach_detail"] = detail
                ctx.set_fact("reach_ok", True)
                return out
            ctx.log(f"Not reachable yet: {detail}", "warn")
            ctx.log("Hint: " + HINTS[attempt % len(HINTS)].format(lan=lan))
            if attempt + 1 < ATTEMPTS and not ctx.confirm("Fixed it? Try the phone check again?", default=False):
                break
        raise StepError("connect.manual.unreachable", f"the phone check did not pass ({detail})",
                        HINTS[0].format(lan=lan))

    def verify(self, ctx, facts, outputs):
        if outputs.get("reach") == "ok":
            return [Check(True, "connect.manual.reach", "the phone check passed")]
        if outputs.get("reach") == "deferred":
            return [Check(True, "connect.manual.reach",
                          "forwards confirmed; the smoke step will run the phone check")]
        return [Check(False, "connect.manual.reach", "port forwarding not confirmed",
                      "run `porch connect manual`")]


MODE = ManualMode()

"""Connection-mode contract (helper module: no MODE, so the registry skips it).

    class MyMode(Mode):
        name = "upnp"; title = "Automatic port mapping (UPnP / NAT-PMP)"
        def detect(self, ctx, facts) -> (WORKS | LIKELY | UNAVAILABLE, reason)
        def inputs(self, ctx) -> [Input]         # asked once this mode is chosen
        def steps(self, ctx, facts) -> [str]     # what the user / porch will do
        def plan(self, ctx, facts) -> [Action]
        def apply(self, ctx, facts) -> {"ingress_ipv4", "ingress_ipv6", "ddns", ...}
        def verify(self, ctx, facts, outputs) -> [Check]
        def undo(self, ctx, entry)               # one of this mode's undo entries
    MODE = MyMode()

`facts` is the network_probe dict (ctx.facts["network"]). Undo entries a mode
records carry `mode=<name>` so the connection step can tear down only the old
mode's changes when switching.
"""

from ..engine import Check

WORKS, LIKELY, UNAVAILABLE = "works", "likely", "unavailable"
STATUS_RANK = {WORKS: 0, LIKELY: 1, UNAVAILABLE: 2}
PORTS = (80, 443, 7000)
PORT_USE = {80: "HTTP (Let's Encrypt, redirects)", 443: "HTTPS", 7000: "frp (paired devices)"}


class Mode:
    name = ""
    title = ""
    summary = ""
    order = 50          # display / recommendation order among equal statuses
    built = True        # False: listed with "coming later", never selectable

    def detect(self, ctx, facts):
        return UNAVAILABLE, "not implemented"

    def inputs(self, ctx):
        """Extra Inputs this mode needs once chosen (ctx may be None: the CLI
        only reads their flags)."""
        return []

    def steps(self, ctx, facts):
        return []

    def plan(self, ctx, facts):
        return []

    def apply(self, ctx, facts):
        return {}

    def verify(self, ctx, facts, outputs):
        return [Check(True, f"connect.{self.name}", "nothing to verify")]

    def undo(self, ctx, entry):
        raise NotImplementedError(f"mode {self.name} cannot undo {entry.get('kind')!r}")

    def record_undo(self, ctx, kind, **data):
        return ctx.record_undo(kind, mode=self.name, **data)

    def __repr__(self):
        return f"<Mode {self.name}>"


def ingress_v6(facts):
    v6 = facts.get("ipv6") or []
    return v6[0] if v6 else None

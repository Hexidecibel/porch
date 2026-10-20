"""upnp: ask the router to forward TCP 80, 443 and 7000 itself, through UPnP
IGD (AddPortMapping) or, when there is no IGD, NAT-PMP / PCP.

Each mapping is recorded (write-ahead) before it is made, so rollback deletes
exactly what porch added, and only while it still points at this box. A
mapping that already points at this box is reused; one that points elsewhere
stops the step. The home IP can change, so this mode sets ddns=True.

Leases: UPnP asks for 7 days (falls back to permanent on IGDv1 routers that
only take those); NAT-PMP / PCP ask for 7 days and record what the router
granted. `porch connect upnp --refresh` renews them.
"""

from ..engine import Action, Check, StepError
from ..net import natpmp as _natpmp
from ..net import upnp as _upnp
from .base import LIKELY, PORTS, UNAVAILABLE, WORKS, Mode, ingress_v6

LEASE = 7 * 24 * 3600
PROTO = "TCP"


def _desc(port):
    return f"porch {port}"


class UPnPMode(Mode):
    name = "upnp"
    title = "Automatic port mapping (UPnP / NAT-PMP)"
    summary = "Porch asks your router to forward the ports. Nothing to click."
    order = 20

    def __init__(self):
        # Overridable for tests.
        self.find_igd = lambda ctx: _upnp.find_igd(http=ctx.http)
        self.igd_at = lambda ctx, entry: _upnp.IGD(
            _upnp.Device(entry.get("location", ""), "", {}, []), entry["service"],
            entry["control_url"], http=ctx.http)
        self.natpmp_client = lambda gateway: _natpmp.Client(gateway)

    # ---- detection -------------------------------------------------------------
    @staticmethod
    def _method(facts):
        if facts.get("upnp"):
            return "upnp"
        n = facts.get("natpmp") or {}
        if n.get("natpmp"):
            return "natpmp"
        if n.get("pcp"):
            return "pcp"
        return None

    def detect(self, ctx, facts):
        if facts.get("host_public_ipv4"):
            return UNAVAILABLE, "not needed: this machine has a public IP (use direct)"
        method = self._method(facts)
        if facts.get("cgnat"):
            return UNAVAILABLE, (facts.get("cgnat_reason") or "carrier-grade NAT")
        if not method:
            return UNAVAILABLE, "the router answers neither UPnP nor NAT-PMP/PCP (it may be turned off in its settings)"
        label = {"upnp": "UPnP", "natpmp": "NAT-PMP", "pcp": "PCP"}[method]
        wan, pub = facts.get("wan_ipv4"), facts.get("public_ipv4")
        if wan and pub and wan == pub:
            return WORKS, f"router answers {label}; its WAN address {wan} is the public address"
        if not pub:
            return LIKELY, f"router answers {label}, but the public address could not be confirmed"
        return LIKELY, f"router answers {label}, but its WAN address is unknown"

    def steps(self, ctx, facts):
        lan = facts.get("lan_ipv4")
        return [f"Map TCP {p} on the router to {lan}:{p}" for p in PORTS] + [
            "Keep the DNS records updated if the home IP changes (ddns)."]

    def plan(self, ctx, facts):
        method = self._method(facts) or "upnp"
        lan = facts.get("lan_ipv4")
        return [Action(f"{method}.map", f"tcp {p}", f"-> {lan}:{p}, lease {LEASE}s") for p in PORTS]

    # ---- apply -------------------------------------------------------------------
    def _have_undo(self, ctx, kind, port):
        return any(e.get("kind") == kind and e.get("port") == port and e.get("mode") == self.name
                   for e in ctx.undo_entries())

    def apply(self, ctx, facts):
        lan = facts.get("lan_ipv4")
        if not lan:
            raise StepError("connect.upnp.no_lan_ip", "this machine's LAN address is unknown",
                            "re-run `porch setup --only network_probe`")
        if not ctx.confirm(f"Ask the router to forward TCP {', '.join(map(str, PORTS))} to {lan}?",
                           default=False):
            raise StepError("connect.upnp.not_confirmed", "router changes not confirmed",
                            "run `porch connect upnp` interactively, or pass --yes")
        igd = None
        try:
            igd = self.find_igd(ctx)
        except Exception:  # noqa: BLE001
            igd = None
        if igd is not None:
            return self._apply_upnp(ctx, facts, igd, lan)
        gw = facts.get("gateway")
        n = facts.get("natpmp") or {}
        if gw and n.get("natpmp"):
            return self._apply_natpmp(ctx, facts, gw, lan)
        if gw and n.get("pcp"):
            return self._apply_pcp(ctx, facts, gw, lan)
        raise StepError("connect.upnp.none", "the router answers neither UPnP nor NAT-PMP/PCP",
                        "turn UPnP on in the router's settings, or use `porch connect manual`")

    def _apply_upnp(self, ctx, facts, igd, lan):
        mappings, lease_used = [], None
        # Look at every port first: a port that forwards to another machine
        # stops the step before anything is mapped (no half-done router).
        current = {}
        for port in PORTS:
            try:
                current[port] = igd.get_mapping(port, PROTO)
            except _upnp.UPnPError as e:
                raise StepError("connect.upnp.query", f"router refused to list port {port}: {e}",
                                "use `porch connect manual`") from None
        for port in PORTS:
            cur = current[port]
            if cur and not (cur["internal_client"] == lan and cur["internal_port"] == port):
                raise StepError(
                    "connect.upnp.conflict",
                    f"router port {port} already forwards to {cur['internal_client']}:{cur['internal_port']}"
                    + (f" ({cur['description']})" if cur.get("description") else ""),
                    "remove that forward in the router (or move it), then run `porch connect upnp` again")
        for port in PORTS:
            cur = current[port]
            if cur and cur["internal_client"] == lan and cur["internal_port"] == port:
                mappings.append({"port": port, "state": "present", "lease": cur["lease"]})
                if cur["lease"] == 0 or not _upnp.is_porch_mapping(cur):
                    continue        # someone else's (or permanent) mapping: leave it be
            if not self._have_undo(ctx, "upnp.delete", port):
                self.record_undo(ctx, "upnp.delete", port=port, proto=PROTO, lan=lan,
                                 location=igd.device.location, service=igd.service_type,
                                 control_url=igd.control_url)
            try:
                lease_used = igd.add_mapping(port, PROTO, lan, port, _desc(port), LEASE)
            except _upnp.UPnPError as e:
                hint = ("the router refused: allow UPnP port mapping changes in its settings"
                        if e.code == _upnp.ERR_NOT_AUTHORIZED else "use `porch connect manual`")
                raise StepError("connect.upnp.add", f"could not map port {port}: {e}", hint) from None
            if not mappings or mappings[-1]["port"] != port:
                mappings.append({"port": port, "state": "added", "lease": lease_used})
            ctx.log(f"router forwards TCP {port} -> {lan}:{port} (UPnP)")
        wan = None
        try:
            wan = igd.external_ip()
        except _upnp.UPnPError:
            pass
        return {"method": "upnp", "ingress_ipv4": wan or facts.get("public_ipv4"),
                "ingress_ipv6": ingress_v6(facts), "ddns": True, "lan_ipv4": lan,
                "lease": LEASE if lease_used is None else lease_used, "mappings": mappings,
                "igd": {"location": igd.device.location, "service": igd.service_type,
                        "control_url": igd.control_url}}

    def _apply_natpmp(self, ctx, facts, gw, lan):
        c = self.natpmp_client(gw)
        mappings, lease = [], LEASE
        for port in PORTS:
            if not self._have_undo(ctx, "natpmp.unmap", port):
                self.record_undo(ctx, "natpmp.unmap", port=port, proto="tcp", gateway=gw)
            try:
                ext, life = c.map("tcp", port, port, LEASE)
            except _natpmp.NatPMPError as e:
                raise StepError("connect.natpmp.map", f"could not map port {port}: {e}",
                                "use `porch connect manual`") from None
            if ext != port:
                try:
                    c.unmap("tcp", port)
                except _natpmp.NatPMPError:
                    pass
                raise StepError("connect.natpmp.port", f"router gave external port {ext} instead of {port}",
                                "another device holds that port on the router; use `porch connect manual`")
            lease = min(lease, life)
            mappings.append({"port": port, "state": "added", "lease": life})
            ctx.log(f"router forwards TCP {port} -> {lan}:{port} (NAT-PMP, {life}s)")
        wan = None
        try:
            wan = c.external_address()
        except _natpmp.NatPMPError:
            pass
        return {"method": "natpmp", "ingress_ipv4": wan or facts.get("public_ipv4"),
                "ingress_ipv6": ingress_v6(facts), "ddns": True, "lan_ipv4": lan, "gateway": gw,
                "lease": lease, "expires_at": int(ctx.clock()) + lease, "mappings": mappings}

    def _apply_pcp(self, ctx, facts, gw, lan):
        import os
        c = self.natpmp_client(gw)
        mappings, lease, wan = [], LEASE, None
        for port in PORTS:
            prior = [e for e in ctx.undo_entries() if e.get("kind") == "pcp.unmap" and e.get("port") == port]
            nonce = bytes.fromhex(prior[0]["nonce"]) if prior else os.urandom(12)
            if not prior:
                self.record_undo(ctx, "pcp.unmap", port=port, proto="tcp", gateway=gw, client_ip=lan,
                                 nonce=nonce.hex())
            try:
                r = c.pcp_map("tcp", port, port, LEASE, lan, nonce)
            except _natpmp.NatPMPError as e:
                raise StepError("connect.pcp.map", f"could not map port {port}: {e}",
                                "use `porch connect manual`") from None
            if r["external_port"] != port:
                raise StepError("connect.pcp.port", f"router gave external port {r['external_port']} instead of {port}",
                                "use `porch connect manual`")
            wan = r["external_ip"]
            lease = min(lease, r["lifetime"])
            mappings.append({"port": port, "state": "added", "lease": r["lifetime"]})
        return {"method": "pcp", "ingress_ipv4": wan or facts.get("public_ipv4"),
                "ingress_ipv6": ingress_v6(facts), "ddns": True, "lan_ipv4": lan, "gateway": gw,
                "lease": lease, "expires_at": int(ctx.clock()) + lease, "mappings": mappings}

    # ---- verify ------------------------------------------------------------------
    def verify(self, ctx, facts, outputs):
        method = outputs.get("method")
        lan = outputs.get("lan_ipv4") or facts.get("lan_ipv4")
        if method == "upnp":
            igd_info = outputs.get("igd") or {}
            try:
                igd = self.igd_at(ctx, igd_info)
                checks = []
                for port in PORTS:
                    m = igd.get_mapping(port, PROTO)
                    ok = bool(m) and m["internal_client"] == lan and m["internal_port"] == port
                    checks.append(Check(ok, f"connect.upnp.port{port}",
                                        f"router forwards TCP {port} to {lan}" if ok
                                        else f"router no longer forwards TCP {port} to {lan}",
                                        "" if ok else "run `porch connect upnp` again"))
                return checks
            except (_upnp.UPnPError, KeyError, OSError) as e:
                return [Check(False, "connect.upnp.query", f"cannot ask the router: {e}",
                              "check the router is up; run `porch connect --status`")]
        if method in ("natpmp", "pcp"):
            ok = int(ctx.clock()) < int(outputs.get("expires_at") or 0)
            return [Check(ok, f"connect.{method}.lease",
                          "port mappings are within their lease" if ok else "port mapping lease expired",
                          "" if ok else "run `porch connect upnp --refresh`")]
        return [Check(False, "connect.upnp.outputs", "no mapping recorded", "run `porch connect upnp`")]

    # ---- undo ----------------------------------------------------------------------
    def undo(self, ctx, entry):
        kind = entry.get("kind")
        port = entry.get("port")
        if kind == "upnp.delete":
            igd = self.igd_at(ctx, entry)
            cur = igd.get_mapping(port, entry.get("proto", PROTO))
            if cur and cur["internal_client"] == entry.get("lan") and cur["internal_port"] == port:
                igd.delete_mapping(port, entry.get("proto", PROTO))
                ctx.log(f"removed router mapping TCP {port}")
            return
        if kind == "natpmp.unmap":
            try:
                self.natpmp_client(entry["gateway"]).unmap("tcp", port)
            except _natpmp.NatPMPError as e:
                ctx.log(f"NAT-PMP unmap {port}: {e} (it expires on its own)", "warn")
            return
        if kind == "pcp.unmap":
            try:
                self.natpmp_client(entry["gateway"]).pcp_unmap("tcp", port, entry["client_ip"], entry["nonce"])
            except _natpmp.NatPMPError as e:
                ctx.log(f"PCP unmap {port}: {e} (it expires on its own)", "warn")
            return
        super().undo(ctx, entry)


MODE = UPnPMode()

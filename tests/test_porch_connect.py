"""connect/ modes, steps/network_probe + steps/connection, and `porch connect`. All fakes."""

import contextlib
import io as stdio
import os
import shutil
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "lib"))

import porch_config  # noqa: E402
from porch_setup import cmd_connect, registry  # noqa: E402
from porch_setup.connect import manual as manual_mod  # noqa: E402
from porch_setup.connect import upnp as upnp_mod  # noqa: E402
from porch_setup.engine import (EXIT_APPLY, EXIT_PREFLIGHT, EXIT_USAGE, Engine,  # noqa: E402
                                make_context)
from porch_setup.io import NullIO  # noqa: E402
from porch_setup.net import natpmp, upnp  # noqa: E402
from porch_setup.redact import Redactor  # noqa: E402
from porch_setup.runner import FakeRunner  # noqa: E402
from porch_setup.steps import connection, network_probe  # noqa: E402

CFG = porch_config.load(env={"PORCH_CONFIG": "none"})
LAN = "192.168.1.48"

HOME = {"iface": "enp3s0", "gateway": "192.168.1.1", "lan_ipv4": LAN, "host_public_ipv4": [],
        "public_ipv4": "203.0.113.16", "public_ipv4_sources": ["a", "b"], "public_ipv4_error": "",
        "upnp": {"location": "http://192.168.1.1:5000/d.xml", "service": upnp.WAN_SERVICES[0],
                 "control_url": "http://192.168.1.1:5000/ctl", "info": {}, "external_ip": "203.0.113.16"},
        "natpmp": {"natpmp": False, "pcp": False, "external_ip": None, "error": ""},
        "wan_ipv4": "203.0.113.16", "wan_source": "upnp", "cgnat": False, "cgnat_reason": "",
        "ipv6": ["2001:470:c0de:1::48"], "router": {"brand": "netgear", "name": "NETGEAR", "source": "http"}}


def facts(**kw):
    f = {k: (dict(v) if isinstance(v, dict) else v) for k, v in HOME.items()}
    f.update(kw)
    return f


NATPMP_HOME = facts(upnp=None, natpmp={"natpmp": True, "pcp": True, "external_ip": "203.0.113.16", "error": ""},
                    wan_source="natpmp")
NO_MAP_HOME = facts(upnp=None, wan_ipv4=None, wan_source=None)
CGNAT = facts(upnp=None, natpmp={"natpmp": True, "pcp": False, "external_ip": "100.72.1.9", "error": ""},
              wan_ipv4="100.72.1.9", wan_source="natpmp", cgnat=True,
              cgnat_reason="the router's WAN address 100.72.1.9 is in 100.64.0.0/10 (carrier-grade NAT)")
VPS = facts(host_public_ipv4=["51.15.20.7"], public_ipv4="51.15.20.7", upnp=None, wan_ipv4=None,
            wan_source=None, gateway="51.15.20.1", lan_ipv4="51.15.20.7")


class FakeIGD:
    def __init__(self, mappings=None):
        self.mappings = dict(mappings or {})
        self.device = upnp.Device("http://192.168.1.1:5000/d.xml", "", {}, [])
        self.service_type = upnp.WAN_SERVICES[0]
        self.control_url = "http://192.168.1.1:5000/ctl"
        self.adds, self.deletes = [], []

    def external_ip(self):
        return "203.0.113.16"

    def get_mapping(self, port, proto="TCP"):
        m = self.mappings.get(port)
        return dict(m) if m else None

    def add_mapping(self, port, proto, client, iport, desc, lease):
        self.adds.append(port)
        self.mappings[port] = {"internal_client": client, "internal_port": iport, "description": desc,
                               "lease": lease, "external_port": port, "protocol": proto, "enabled": True}
        return lease

    def delete_mapping(self, port, proto="TCP"):
        self.deletes.append(port)
        return self.mappings.pop(port, None) is not None


class FakePMP:
    def __init__(self, taken=()):
        self.taken, self.maps, self.unmaps = set(taken), {}, []

    def map(self, proto, iport, eport, life):
        if life == 0:
            self.unmaps.append(iport)
            self.maps.pop(iport, None)
            return 0, 0
        ext = eport + 1 if eport in self.taken else eport
        self.maps[iport] = ext
        return ext, 7200

    def unmap(self, proto, iport):
        return self.map(proto, iport, 0, 0)

    def external_address(self):
        return "203.0.113.16"


class Base(unittest.TestCase):
    FACTS = HOME

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.probes = 0
        self.facts = self.FACTS

        def fake_probe(ctx):
            self.probes += 1
            return {k: (dict(v) if isinstance(v, dict) else v) for k, v in self.facts.items()}
        self._patch(network_probe, "PROBE", fake_probe)
        self.igd = FakeIGD()
        self.pmp = FakePMP()
        m = upnp_mod.MODE
        self._patch(m, "find_igd", lambda ctx: self.igd if self.facts.get("upnp") else None)
        self._patch(m, "igd_at", lambda ctx, entry: self.igd)
        self._patch(m, "natpmp_client", lambda gw: self.pmp)
        mm = manual_mod.MODE
        self.ready = False
        self.reach_results = []
        self._patch(mm, "stack_ready", lambda ctx: self.ready)
        self._patch(mm, "phone_check", self._fake_phone)
        self.now = 1_700_000_000.0

    def _fake_phone(self, ctx, timeout=0, local_ips=()):
        return self.reach_results.pop(0) if self.reach_results else (False, "no request arrived")

    def _patch(self, obj, name, value):
        old = getattr(obj, name)
        setattr(obj, name, value)
        self.addCleanup(setattr, obj, name, old)

    def kw(self):
        return {"runner": FakeRunner(), "data_dir": self.tmp + "/data", "cfg": CFG, "redactor": Redactor(),
                "secrets_dir": self.tmp + "/s", "sleep": lambda s: None, "clock": lambda: self.now}

    def ctx(self, mode="upnp", confirms=True, **extra):
        self.io = NullIO({"connection": mode}, confirms=confirms)
        return make_context(io=self.io, **{**self.kw(), **extra})

    def run_steps(self, mode="upnp", confirms=True, **extra):
        ctx = self.ctx(mode, confirms, **extra)
        return ctx, Engine([network_probe.STEP, connection.STEP], ctx).run()


class AssessTest(Base):
    def rows(self, f):
        ctx = self.ctx()
        rows, rec = connection.assess(ctx, f)
        return {r["name"]: r for r in rows}, rec

    def test_registry_has_built_modes(self):
        self.assertTrue({"direct", "upnp", "manual"} <= set(registry.modes()))
        ids = [s.id for s in registry.steps()]
        self.assertLess(ids.index("network_probe"), ids.index("connection"))

    def test_home_with_upnp(self):
        rows, rec = self.rows(HOME)
        self.assertEqual(rec, "upnp")
        self.assertEqual(rows["upnp"]["status"], "works")
        self.assertEqual(rows["manual"]["status"], "likely")
        self.assertEqual(rows["direct"]["status"], "unavailable")
        self.assertEqual(rows["paid"]["status"], "likely")
        self.assertEqual(rows["ipv6"]["status"], "later")
        self.assertIn("2001:470:", rows["ipv6"]["reason"])

    def test_natpmp_counts(self):
        rows, rec = self.rows(NATPMP_HOME)
        self.assertEqual(rec, "upnp")
        self.assertIn("NAT-PMP", rows["upnp"]["reason"])

    def test_no_mapping_protocol(self):
        rows, rec = self.rows(NO_MAP_HOME)
        self.assertEqual(rec, "manual")
        self.assertEqual(rows["upnp"]["status"], "unavailable")

    def test_vps(self):
        rows, rec = self.rows(VPS)
        self.assertEqual(rec, "direct")
        self.assertEqual(rows["manual"]["status"], "unavailable")

    def test_cgnat(self):
        rows, rec = self.rows(CGNAT)
        self.assertEqual(rec, "paid")          # the relays are the fix for CGNAT
        for n in ("upnp", "manual", "direct"):
            self.assertEqual(rows[n]["status"], "unavailable", n)
        self.assertIn("carrier-grade", rows["manual"]["reason"])
        self.assertIn("carrier-grade NAT", rows["oracle"]["reason"])
        self.assertEqual(rows["paid"]["status"], "works")
        text = "\n".join(connection.table(list(rows.values()), rec))
        self.assertIn("recommended: paid", text)

    def test_isp_cgnat_brand(self):
        rows, _ = self.rows(facts(router={"brand": "starlink"}, upnp=None))
        self.assertEqual(rows["manual"]["status"], "unavailable")


class UPnPModeTest(Base):
    def test_maps_three_ports_idempotent_and_rollback(self):
        ctx, r = self.run_steps()
        self.assertTrue(r.ok, r)
        self.assertEqual(self.igd.adds, [80, 443, 7000])
        for p in (80, 443, 7000):
            self.assertEqual(self.igd.mappings[p]["internal_client"], LAN)
            self.assertEqual(self.igd.mappings[p]["description"], f"porch {p}")
        out = ctx.outputs("connection")
        self.assertEqual((out["mode"], out["method"], out["ddns"]), ("upnp", "upnp", True))
        self.assertEqual(out["ingress_ipv4"], "203.0.113.16")
        act = ctx.state.connection["active"]
        self.assertEqual((act["mode"], act["ddns"]), ("upnp", True))
        self.assertEqual(len(ctx.state.connection["history"]), 1)
        self.assertEqual(ctx.facts["public_ipv4"], "203.0.113.16")
        self.assertTrue(any("forward TCP" in p for p in self.io.prompts))
        undo = ctx.state.steps["connection"]["undo"]
        self.assertEqual([(u["kind"], u["port"], u["mode"]) for u in undo],
                         [("upnp.delete", p, "upnp") for p in (80, 443, 7000)])

        ctx2, r2 = self.run_steps()
        self.assertTrue(r2.ok)
        self.assertEqual(self.igd.adds, [80, 443, 7000])          # unchanged: nothing re-added
        self.assertIn("unchanged", [d["status"] for d in self.io.kinds("step_done")])

        rb = Engine([network_probe.STEP, connection.STEP], ctx2).rollback()
        self.assertTrue(rb.ok, rb)
        self.assertEqual(self.igd.mappings, {})
        self.assertIsNone(ctx2.state.connection["active"])

    def test_rollback_spares_a_mapping_someone_changed(self):
        ctx, r = self.run_steps()
        self.igd.mappings[443]["internal_client"] = "192.168.1.77"
        Engine([network_probe.STEP, connection.STEP], ctx).rollback()
        self.assertEqual(list(self.igd.mappings), [443])

    def test_conflict(self):
        self.igd.mappings[443] = {"internal_client": "192.168.1.77", "internal_port": 443,
                                  "description": "xbox", "lease": 0}
        ctx, r = self.run_steps()
        self.assertEqual(r.exit_code, EXIT_APPLY)
        self.assertEqual(r.error["code"], "connect.upnp.conflict")
        self.assertIn("192.168.1.77", r.error["message"])
        self.assertEqual(self.igd.adds, [])                        # nothing half-mapped
        Engine([network_probe.STEP, connection.STEP], ctx).rollback()
        self.assertEqual(list(self.igd.mappings), [443])          # theirs stays

    def test_existing_forward_to_us_is_reused_not_owned(self):
        self.igd.mappings[80] = {"internal_client": LAN, "internal_port": 80, "description": "manual",
                                 "lease": 0}
        ctx, r = self.run_steps()
        self.assertTrue(r.ok, r)
        self.assertEqual(self.igd.adds, [443, 7000])
        Engine([network_probe.STEP, connection.STEP], ctx).rollback()
        self.assertEqual(list(self.igd.mappings), [80])

    def test_needs_consent(self):
        ctx, r = self.run_steps(confirms=False)
        self.assertEqual(r.error["code"], "connect.upnp.not_confirmed")
        self.assertEqual(self.igd.adds, [])

    def test_dry_run_changes_nothing(self):
        ctx, r = self.run_steps(dry_run=True)
        self.assertTrue(r.ok, r)
        self.assertEqual(self.igd.adds, [])
        kinds = [d["kind"] for d in self.io.kinds("action")]
        self.assertIn("upnp.map", kinds)
        self.assertFalse(os.path.exists(self.tmp + "/data/porch-setup.json"))

    def test_natpmp_path_and_lease_expiry(self):
        self.facts = NATPMP_HOME
        ctx, r = self.run_steps()
        self.assertTrue(r.ok, r)
        self.assertEqual(self.pmp.maps, {80: 80, 443: 443, 7000: 7000})
        out = ctx.outputs("connection")
        self.assertEqual((out["method"], out["lease"]), ("natpmp", 7200))
        self.now += 8000
        checks = connection.STEP.verify(ctx)
        self.assertFalse(checks[0].ok)
        self.assertIn("--refresh", checks[0].hint)
        Engine([network_probe.STEP, connection.STEP], ctx).rollback()
        self.assertEqual(sorted(self.pmp.unmaps), [80, 443, 7000])

    def test_natpmp_wrong_port_unmaps_only_that_one(self):
        self.facts = NATPMP_HOME
        self.pmp.taken = {80}
        ctx, r = self.run_steps()
        self.assertEqual(r.error["code"], "connect.natpmp.port")
        self.assertEqual(self.pmp.unmaps, [80])
        self.assertEqual(self.pmp.maps, {})


class ManualAndSwitchTest(Base):
    def test_manual_deferred_before_stack(self):
        ctx, r = self.run_steps("manual")
        self.assertTrue(r.ok, r)
        out = ctx.outputs("connection")
        self.assertEqual((out["reach"], out["ddns"]), ("deferred", True))
        logs = "\n".join(d["message"] for d in self.io.kinds("log"))
        self.assertIn("orbilogin.com", logs)
        self.assertIn(f"TCP   443 -> {LAN}:443", logs)
        self.assertIn("smoke step", logs)

    def test_manual_phone_check_loops_with_hints(self):
        self.ready = True
        self.reach_results = [(False, "no request arrived within 300s"), (True, "request from 8.8.4.4")]
        ctx, r = self.run_steps("manual")
        self.assertTrue(r.ok, r)
        self.assertEqual(ctx.outputs("connection")["reach"], "ok")
        self.assertTrue(ctx.facts["reach_ok"])
        logs = "\n".join(d["message"] for d in self.io.kinds("log"))
        self.assertIn("Hint:", logs)
        self.assertTrue(any("Try the phone check again" in p for p in self.io.prompts))

    def test_manual_unreachable_fails_with_hint(self):
        self.ready = True
        ctx, r = self.run_steps("manual")
        self.assertEqual(r.exit_code, EXIT_APPLY)
        self.assertEqual(r.error["code"], "connect.manual.unreachable")
        self.assertIn(LAN, r.error["hint"])

    def test_manual_not_confirmed(self):
        ctx, r = self.run_steps("manual", confirms=False)
        self.assertEqual(r.error["code"], "connect.manual.not_done")

    def test_switch_upnp_to_manual_tears_down_old(self):
        ctx, r = self.run_steps("upnp")
        self.assertTrue(r.ok)
        ctx2, r2 = self.run_steps("manual")
        self.assertTrue(r2.ok, r2)
        self.assertEqual(self.igd.mappings, {})
        self.assertEqual(ctx2.state.steps["connection"]["undo"], [])
        hist = ctx2.state.connection["history"]
        self.assertEqual([(h["mode"], h["from"]) for h in hist], [("upnp", None), ("manual", "upnp")])
        self.assertEqual(ctx2.state.connection["active"]["mode"], "manual")

    def test_cgnat_refused_in_preflight(self):
        self.facts = CGNAT
        ctx, r = self.run_steps("upnp")
        self.assertEqual(r.exit_code, EXIT_PREFLIGHT)
        self.assertIn("carrier-grade", r.error["message"])
        ctx, r = self.run_steps("ipv6")
        self.assertEqual(r.error["code"], "connection.later")

    def test_direct(self):
        self.facts = VPS
        ctx, r = self.run_steps("direct")
        self.assertTrue(r.ok, r)
        out = ctx.outputs("connection")
        self.assertEqual((out["ingress_ipv4"], out["ddns"]), ("51.15.20.7", False))

    def test_default_is_recommendation(self):
        ctx = make_context(io=NullIO(confirms=True), **self.kw())
        r = Engine([network_probe.STEP, connection.STEP], ctx).run()
        self.assertTrue(r.ok, r)
        self.assertEqual(ctx.input("connection"), "upnp")

    def test_adopt_accepts_hand_made_setup(self):
        ctx = self.ctx("manual", adopt=True)
        r = Engine([network_probe.STEP, connection.STEP], ctx).run()
        self.assertTrue(r.ok, r)
        self.assertEqual(ctx.state.steps["connection"]["status"], "adopted")
        self.assertEqual(self.igd.adds, [])


class CmdConnectTest(Base):
    def main(self, argv, io=None):
        out, err = stdio.StringIO(), stdio.StringIO()
        with contextlib.redirect_stderr(err):
            rc = cmd_connect.main(argv, io=io, out=out, env={}, ctx_kwargs=self.kw())
        return rc, out.getvalue(), err.getvalue()

    def test_status_is_read_only(self):
        rc, out, _ = self.main(["--status"])
        self.assertEqual(rc, 0)
        self.assertIn("recommended: upnp", out)
        self.assertIn("router WAN IPv4: 203.0.113.16", out)
        self.assertFalse(os.path.exists(self.tmp + "/data/porch-setup.json"))
        rc, out, _ = self.main(["--status", "--json"])
        self.assertIn('"recommended": "upnp"', out)

    def test_later_modes(self):
        rc, out, err = self.main(["ipv6"])
        self.assertEqual(rc, EXIT_USAGE)
        self.assertIn("coming later", out + err)

    def test_unknown_mode(self):
        rc, _, err = self.main(["frob"])
        self.assertEqual(rc, EXIT_USAGE)
        self.assertEqual(self.probes, 0)

    def test_refuses_unattended_without_yes(self):
        rc, _, err = self.main(["upnp"], io=NullIO({"connection": "upnp"}, confirms=True))
        self.assertEqual(rc, EXIT_USAGE)
        self.assertIn("--yes", err)
        self.assertEqual(self.probes, 0)
        self.assertEqual(self.igd.adds, [])

    def test_switch_and_refresh(self):
        rc, out, err = self.main(["upnp", "--yes"], io=NullIO({"connection": "upnp"}, confirms=True))
        self.assertEqual(rc, 0, err)
        self.assertIn("connection: upnp", out)
        self.assertEqual(self.igd.adds, [80, 443, 7000])
        rc, out, err = self.main(["--refresh", "--yes"], io=NullIO(confirms=True))
        self.assertEqual(rc, 0, err)
        self.assertIn("renewed 3 mappings", out)
        self.assertEqual(self.igd.adds, [80, 443, 7000] * 2)
        ctx = make_context(io=NullIO(), **self.kw())
        self.assertEqual(len(ctx.state.steps["connection"]["undo"]), 3)   # no duplicates

    def test_refresh_needs_no_new_confirmation(self):
        rc, _, err = self.main(["upnp", "--yes"], io=NullIO({"connection": "upnp"}, confirms=True))
        self.assertEqual(rc, 0, err)
        rc, out, err = self.main(["upnp", "--refresh"])      # the CLI's own IO, no --yes
        self.assertEqual(rc, 0, err)
        self.assertIn("renewed 3 mappings", out)

    def test_off_undoes_a_failed_attempt(self):
        # A router that fails half-way: 80 maps, then 443 errors out.
        real_add = self.igd.add_mapping

        def flaky(port, *a, **kw):
            if port == 443:
                raise upnp.UPnPError("boom", 501)
            return real_add(port, *a, **kw)
        self.igd.add_mapping = flaky
        rc, _, err = self.main(["upnp", "--yes"], io=NullIO({"connection": "upnp"}, confirms=True))
        self.assertEqual(rc, EXIT_APPLY)
        self.assertIn("porch connect --off", err)
        self.assertIn(80, self.igd.mappings)
        rc, out, err = self.main(["--off", "--yes"], io=NullIO(confirms=True))
        self.assertEqual(rc, 0, err)
        self.assertIn("failed upnp attempt", out)
        self.assertEqual(self.igd.mappings, {})


if __name__ == "__main__":
    unittest.main()

"""steps/dns_provider.py and steps/dns_records.py with a FakeProvider zone and a
FakeDNS resolver: create, idempotence, conflicts, apex opt-in, wildcard cover,
propagation waits, adopt checks, rollback, secret hygiene."""

import io as _stdio
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import porch_config  # noqa: E402
from porch_dns_fakes import FakeDNS, FakeProvider  # noqa: E402
from porch_setup import cmd_dns  # noqa: E402
from porch_setup.dns.base import Record  # noqa: E402
from porch_setup.engine import (EXIT_APPLY, EXIT_PREFLIGHT, EXIT_USAGE, EXIT_VERIFY,  # noqa: E402
                                Engine, make_context)
from porch_setup.io import NullIO  # noqa: E402
from porch_setup.redact import Redactor  # noqa: E402
from porch_setup.runner import FakeRunner  # noqa: E402
from porch_setup.steps.dns_provider import STEP as PROV  # noqa: E402
from porch_setup.steps.dns_records import STEP as RECS  # noqa: E402
from porch_setup.steps.dns_records import diff  # noqa: E402

TOKEN = "cf-SECRET-token-424242"
IP = "1.2.3.4"
HOSTS = ["auth.porch.example.com", "panel.porch.example.com", "tunnel.porch.example.com",
         "*.tunnel.porch.example.com"]


class StepsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.dns = FakeDNS().add_zone("example.com", {"ns1.p.net": "192.0.2.53",
                                                      "ns2.p.net": "192.0.2.54"})
        self.prov = FakeProvider("example.com", dns=self.dns)
        self.t = [1_700_000_000.0]
        self.sleeps = []
        self.root = "porch.example.com"

    def ctx(self, answers=None, adopt=False, confirms=True, dry_run=False, env=None):
        base = {"dns_provider": "cloudflare", "dns_token": TOKEN, "dns_ipv4": IP}
        base.update(answers or {})
        base = {k: v for k, v in base.items() if v is not None}
        self.io = NullIO(base, confirms=confirms)
        cfg = porch_config.load(env={"PORCH_CONFIG": "none", "PORCH_DOMAIN": self.root})

        def sleep(s):
            self.sleeps.append(s)
            self.t[0] += s
        c = make_context(io=self.io, runner=FakeRunner(), data_dir=self.tmp + "/data", cfg=cfg,
                         redactor=Redactor(), secrets_dir=self.tmp + "/secrets", adopt=adopt,
                         dry_run=dry_run, dns=self.dns.resolver(), sleep=sleep,
                         clock=lambda: self.t[0], env=dict(env or {"PORCH_DNS_WAIT": "60"}))
        c.provider_factory = self.factory
        return c

    def factory(self, name, creds):
        self.creds = creds
        return self.prov

    def a_records(self):
        return sorted(n for n, t, c in self.prov.contents() if t == "A")

    # ---- dns_provider ---------------------------------------------------------
    def test_provider_detects_default_from_facts_and_checks(self):
        ctx = self.ctx({"dns_provider": None})
        ctx.set_fact("zone_apex", "example.com")
        ctx.set_fact("ns", ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"])
        r = Engine([PROV], ctx).run()
        self.assertTrue(r.ok, r)
        self.assertEqual(ctx.state.inputs["dns_provider"], "cloudflare")
        self.assertEqual(self.creds, {"token": TOKEN})
        self.assertEqual(ctx.state.steps["dns_provider"]["outputs"]["zone"], "example.com")
        self.assertIn(("check", "example.com"), self.prov.calls)
        with open(os.path.join(self.tmp, "data", "porch-setup.json")) as f:
            self.assertNotIn(TOKEN, f.read())
        self.assertTrue(ctx.state.secret_refs["dns_token"].startswith("file://"))

    def test_provider_needs_flag_without_facts_non_interactive(self):
        ctx = self.ctx({"dns_provider": None, "dns_token": None})
        r = Engine([PROV], ctx).run()
        self.assertEqual(r.exit_code, EXIT_USAGE)
        self.assertIn("--dns-provider", r.missing)
        self.assertEqual(self.dns.queries, [])   # no lookups before preflight

    def test_namecom_requires_username(self):
        ctx = self.ctx({"dns_provider": "namecom"})
        r = Engine([PROV], ctx).run()
        self.assertEqual(r.exit_code, EXIT_USAGE)
        self.assertEqual(r.missing, ["--dns-username"])
        ctx = self.ctx({"dns_provider": "namecom", "dns_username": "alice"})
        self.assertTrue(Engine([PROV], ctx).run().ok)
        self.assertEqual(self.creds, {"token": TOKEN, "username": "alice"})

    def test_provider_auth_failure_has_hint(self):
        self.prov.fail = {"check": "dns.auth"}
        r = Engine([PROV], self.ctx()).run()
        self.assertEqual(r.exit_code, EXIT_APPLY)
        self.assertEqual(r.error["code"], "dns.auth")
        self.assertEqual(r.error["hint"], "fake hint")

    def test_unknown_zone_fails_preflight(self):
        self.root = "porch.nowhere.invalid"
        r = Engine([PROV], self.ctx()).run()
        self.assertEqual(r.exit_code, EXIT_PREFLIGHT)
        self.assertEqual(r.error["code"], "dns.zone")

    # ---- dns_records ------------------------------------------------------------
    def test_creates_records_under_base_and_is_idempotent(self):
        ctx = self.ctx()
        r = Engine([PROV, RECS], ctx).run()
        self.assertTrue(r.ok, r)
        self.assertEqual(self.a_records(), sorted(HOSTS))
        self.assertNotIn("example.com", self.a_records())          # apex untouched
        self.assertTrue(all(c[3] == IP for c in self.prov.mutations()))
        out = ctx.state.steps["dns_records"]["outputs"]
        self.assertEqual(len(out["created"]), 4)
        self.assertEqual(len(ctx.state.steps["dns_records"]["undo"]), 4)
        n = len(self.prov.mutations())
        r = Engine([PROV, RECS], self.ctx()).run()
        self.assertTrue(r.ok, r)
        self.assertEqual(len(self.prov.mutations()), n)
        self.assertIn("unchanged", [d["status"] for d in self.io.kinds("step_done")])

    def test_ipv6_records(self):
        r = Engine([PROV, RECS], self.ctx({"dns_ipv6": "2606:4700::1"})).run()
        self.assertTrue(r.ok, r)
        aaaa = sorted(n for n, t, c in self.prov.contents() if t == "AAAA")
        self.assertEqual(aaaa, sorted(HOSTS))

    def test_rejects_private_target(self):
        r = Engine([PROV, RECS], self.ctx({"dns_ipv4": "192.168.1.5"})).run()
        self.assertEqual(r.exit_code, EXIT_USAGE)
        self.assertIn("not a public address", r.error["message"])

    def test_apex_only_when_opted_in(self):
        self.root = "example.com"
        r = Engine([PROV, RECS], self.ctx()).run()
        self.assertTrue(r.ok, r)
        self.assertNotIn("example.com", self.a_records())
        self.assertIn("auth.example.com", self.a_records())
        r = Engine([PROV, RECS], self.ctx({"dns_apex": True})).run()
        self.assertTrue(r.ok, r)
        self.assertIn("example.com", self.a_records())

    def test_apex_host_without_opt_in_is_refused(self):
        self.root = "example.com"
        env = {"PORCH_CONFIG": "none", "PORCH_DOMAIN": "example.com",
               "PORCH_PANEL_HOST": "example.com"}
        ctx = self.ctx()
        ctx._cfg = porch_config.load(env=env)
        r = Engine([PROV, RECS], ctx).run()
        self.assertEqual(r.exit_code, EXIT_PREFLIGHT)
        self.assertEqual(r.error["code"], "dns.apex")
        self.assertIn("--dns-apex", r.error["hint"])
        self.assertEqual(self.prov.mutations(), [])

    def test_wildcard_in_zone_covers_a_name(self):
        self.root = "example.com"
        self.prov._add(Record("*.example.com", "A", IP))
        r = Engine([PROV, RECS], self.ctx()).run()
        self.assertTrue(r.ok, r)
        created = sorted(c[1] for c in self.prov.mutations() if c[0] == "create")
        self.assertEqual(created, ["*.tunnel.example.com"])   # auth/panel/tunnel ride *.example.com

    def test_conflict_declined_then_accepted_then_rolled_back(self):
        old = self.prov._add(Record("auth.porch.example.com", "A", "5.6.7.8", ttl=600))
        self.prov._add(Record("panel.porch.example.com", "CNAME", "elsewhere.example.net"))
        base = self.prov.contents()
        r = Engine([PROV, RECS], self.ctx(confirms=False)).run()
        self.assertEqual(r.exit_code, EXIT_APPLY)
        self.assertEqual(r.error["code"], "dns.conflict")
        self.assertIn("5.6.7.8", r.error["message"])
        # a resume after answering yes finishes the job
        r = Engine([PROV, RECS], self.ctx(confirms=True)).run()
        self.assertTrue(r.ok, r)
        self.assertEqual(self.a_records(), sorted(HOSTS))
        self.assertEqual(self.prov.records[old].content, IP)       # updated in place
        self.assertNotIn("CNAME", {t for _n, t, _c in self.prov.contents()})
        r = Engine([PROV, RECS], self.ctx()).rollback()
        self.assertTrue(r.ok, r)
        self.assertEqual(self.prov.contents(), base)
        self.assertEqual(self.prov.records[old].ttl, 600)

    def test_waits_for_propagation_and_fails_with_hint(self):
        self.prov.dns = None          # the provider accepts records, the NS never serve them
        r = Engine([PROV, RECS], self.ctx()).run()
        self.assertEqual(r.exit_code, EXIT_VERIFY)
        self.assertEqual(r.error["code"], "dns.resolves")
        self.assertGreaterEqual(sum(self.sleeps), 60)
        self.assertTrue(any("waiting for DNS" in d["message"] for d in self.io.kinds("log")))

    def test_public_resolvers_lagging_is_its_own_failure(self):
        self.dns.public_view = {k: dict(v) for k, v in self.dns.zones.items()}  # frozen snapshot
        r = Engine([PROV, RECS], self.ctx()).run()
        self.assertEqual(r.exit_code, EXIT_VERIFY)
        self.assertEqual(r.error["code"], "dns.propagation")
        self.assertIn("negative TTL", r.error["hint"])

    def test_dry_run_changes_nothing(self):
        ctx = self.ctx(dry_run=True)
        r = Engine([PROV, RECS], ctx).run()
        self.assertTrue(r.ok, r)
        self.assertEqual(self.prov.mutations(), [])
        kinds = [(a["kind"], a["target"]) for a in self.io.kinds("action")]
        self.assertIn(("dns.create", "A auth.porch.example.com"), kinds)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "data", "porch-setup.json")))

    def test_adopt_without_ip_checks_consistency(self):
        for h in HOSTS:
            self.dns.set("example.com", h, "A", ["9.9.9.9"])
        ctx = self.ctx({"dns_ipv4": None}, adopt=True)
        r = Engine([PROV, RECS], ctx).run()
        self.assertTrue(r.ok, r)
        self.assertEqual(ctx.state.steps["dns_records"]["status"], "adopted")
        self.assertEqual(self.sleeps, [])
        self.assertEqual(self.prov.mutations(), [])
        self.dns.set("example.com", "panel.porch.example.com", "A", ["8.8.4.4"])
        r = Engine([PROV, RECS], self.ctx({"dns_ipv4": None}, adopt=True)).run()
        self.assertFalse(r.ok)
        self.assertEqual(r.error["code"], "dns.inconsistent")

    def test_manual_provider_shows_table_then_polls(self):
        from porch_setup.dns.manual import Manual
        ctx = self.ctx({"dns_provider": "manual", "dns_token": None})
        ctx.provider_factory = lambda n, c: Manual()

        def sleep(s):
            self.t[0] += s
            for h in HOSTS:   # the user adds them while porch waits
                self.dns.set("example.com", h, "A", [IP])
        ctx.sleep = sleep
        r = Engine([PROV, RECS], ctx).run()
        self.assertTrue(r.ok, r)
        logs = "\n".join(d["message"] for d in self.io.kinds("log"))
        self.assertIn("add these records at your DNS host", logs)
        self.assertIn("*.tunnel.porch.example.com", logs)

    def test_diff_kinds(self):
        want = [Record("a.x.org", "A", IP), Record("b.x.org", "A", IP), Record("c.x.org", "A", IP),
                Record("d.x.org", "A", IP), Record("e.y.x.org", "A", IP)]
        have = [Record("a.x.org", "A", IP), Record("b.x.org", "A", "9.9.9.9"),
                Record("c.x.org", "CNAME", "z.org"), Record("*.y.x.org", "A", IP)]
        self.assertEqual([k for k, _d, _e in diff(want, have)],
                         ["ok", "replace", "cname", "create", "covered"])

    def test_cmd_dns_show(self):
        Engine([PROV, RECS], self.ctx()).run()
        out = _stdio.StringIO()
        kw = {"io": NullIO(), "runner": FakeRunner(), "data_dir": self.tmp + "/data",
              "cfg": porch_config.load(env={"PORCH_CONFIG": "none", "PORCH_DOMAIN": self.root}),
              "redactor": Redactor(), "secrets_dir": self.tmp + "/secrets",
              "dns": self.dns.resolver(), "env": {}}
        self.assertEqual(cmd_dns.main(["show"], out=out, ctx_kwargs=kw), 0)
        text = out.getvalue()
        self.assertIn("zone example.com", text)
        self.assertIn("*.tunnel.porch.example.com", text)
        self.assertIn("live", text)
        self.assertEqual(cmd_dns.main(["watch"], out=out, ctx_kwargs=kw), EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()

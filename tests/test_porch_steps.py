"""Tests for W1's setup steps (lib/porch_setup/steps/) and porch doctor."""

import contextlib
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "lib"))

import porch_config  # noqa: E402
from porch_setup import cmd_doctor, registry, render  # noqa: E402
from porch_setup.engine import Check, Engine, Step, StepError, make_context  # noqa: E402
from porch_setup.io import NullIO  # noqa: E402
from porch_setup.redact import Redactor  # noqa: E402
from porch_setup.runner import FakeRunner, Result  # noqa: E402
from porch_setup.steps import (admin, domain, firewall, frps, haproxy, landing,  # noqa: E402
                               pocket, preflight, services, smoke)

DEFAULT = porch_config.load(env={"PORCH_CONFIG": "none"})
TOOLS = {t: f"/usr/bin/{t}" for t in ("haproxy", "certbot", "curl", "ss", "ufw")}


class FakeResp:
    def __init__(self, status):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def fake_http(table):
    def urlopen(url, timeout=None):
        st = table.get(url)
        if st is None:
            raise OSError("connection refused")
        return FakeResp(st)
    return urlopen


def cfg_file(d, text):
    p = os.path.join(d, "porch.toml")
    with open(p, "w") as f:
        f.write(text)
    return porch_config.load(path=p, env={}), p


ADOPT_TOML = '[install]\nmode = "adopt"\n'


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.data = os.path.join(self.tmp, "data")
        os.makedirs(self.data)
        self.red = Redactor()
        self.runner = FakeRunner(tools=dict(TOOLS))
        self.runner.on(["haproxy", "-v"], stdout="HAProxy version 2.8.16-0ubuntu0.24.04.3")
        self.runner.on(["certbot", "--version"], stdout="certbot 5.8.0")
        self.runner.on(["curl"], stdout="200")
        self.runner.on(["loginctl", "show-user"], stdout="Linger=yes\n")
        self.runner.on(["ss"], stdout='LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("haproxy",pid=1,fd=7))\n')
        self.env = {"USER": "porchuser", "PORCH_CONFIG": os.path.join(self.tmp, "porch.toml"),
                    "XDG_CONFIG_HOME": os.path.join(self.tmp, "xdg"),
                    "PORCH_APP_DATA": self.data}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def ctx(self, cfg=DEFAULT, answers=None, http=None, **kw):
        self.io = NullIO(answers or {}, confirms=True)
        return make_context(io=self.io, runner=self.runner, data_dir=self.data, cfg=cfg,
                            redactor=self.red, secrets_dir=os.path.join(self.tmp, "sec"),
                            env=self.env, http=http or fake_http({}), sleep=lambda s: None, **kw)

    def checks(self, step, ctx):
        ctx.step_id = step.id
        return {ch.code: ch for ch in step.verify(ctx)}


class RegistryTest(unittest.TestCase):
    def test_w1_steps_registered_in_order(self):
        ids = [s.id for s in registry.steps()]
        mine = ["preflight", "domain", "firewall", "haproxy", "frps", "services", "admin",
                "landing", "pocket", "smoke"]
        self.assertEqual([i for i in ids if i in mine], mine)


class PreflightTest(Base):
    def test_tools_ports_linger(self):
        step = preflight.Preflight()
        step.ntp = staticmethod(lambda server: 0.4)
        ctx = self.ctx()
        ctx.step_id = step.id
        checks = {c.code: c for c in step.preflight(ctx)}
        self.assertTrue(all(c.ok for c in checks.values()), [c for c in checks.values() if not c.ok])
        self.assertIn("2.8.16", checks["preflight.haproxy"].message)
        self.runner.rules.insert(0, FakeRunner().on(
            ["ss"], stdout='LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=2,fd=6))\n').rules[0])
        self.runner.rules.insert(0, FakeRunner().on(["haproxy", "-v"], stdout="HAProxy version 2.2.1").rules[0])
        step.ntp = staticmethod(lambda server: 300.0)
        checks = {c.code: c for c in step.preflight(ctx)}
        self.assertFalse(checks["preflight.port443"].ok)
        self.assertIn("nginx", checks["preflight.port443"].hint)
        self.assertFalse(checks["preflight.haproxy"].ok)
        self.assertFalse(checks["preflight.clock"].ok)

    def test_linger_enabled_after_confirm(self):
        self.runner.rules.insert(0, FakeRunner().on(["loginctl", "show-user"], stdout="Linger=no\n").rules[0])
        step = preflight.Preflight()
        ctx = self.ctx()
        ctx.step_id = step.id
        self.assertFalse(self.checks(step, ctx)["preflight.linger"].ok)
        step.apply(ctx)
        self.assertIn({"argv": ["loginctl", "enable-linger", "porchuser"], "sudo": True},
                      [{"argv": c["argv"], "sudo": c["sudo"]} for c in self.runner.calls])


class PreflightSafetyTest(Base):
    def step(self):
        st = preflight.Preflight()
        st.ntp = staticmethod(lambda server: 0.1)
        return st

    def pre(self, ctx=None):
        ctx = ctx or self.ctx()
        ctx.step_id = "preflight"
        return {c.code: c for c in self.step().preflight(ctx)}

    def test_internal_ports_free_held_and_after_services(self):
        self.assertTrue(self.pre()["preflight.internal_ports"].ok)
        self.runner.rules.insert(0, FakeRunner().on(["ss"], stdout=(
            'LISTEN 0 5 127.0.0.1:9512 0.0.0.0:* users:(("node",pid=3,fd=3))\n'
            'LISTEN 0 5 127.0.0.1:7500 0.0.0.0:* users:(("frps",pid=4,fd=3))\n')).rules[0])
        ch = self.pre()["preflight.internal_ports"]
        self.assertFalse(ch.ok)
        self.assertIn("9512 (auth server) is held by node", ch.message)
        self.assertNotIn("7500", ch.message)          # frps on its own port is fine
        ctx = self.ctx()
        ctx.state.step("services")["status"] = "done"   # a re-run: those are porch's now
        self.assertNotIn("preflight.internal_ports", self.pre(ctx))

    def test_foreign_user_units(self):
        d = os.path.join(self.tmp, "xdg", "systemd", "user")
        os.makedirs(d)
        self.assertTrue(self.pre()["preflight.units"].ok)
        # what `bin/pocket --install-service` wrote is the same file: fine
        with open(os.path.join(d, "porch-pocket@.service"), "w") as f:
            f.write(pocket.render_unit(self.ctx().repo_dir, DEFAULT.brand))
        self.assertTrue(self.pre()["preflight.units"].ok)
        with open(os.path.join(d, "porch-auth.service"), "w") as f:
            f.write("[Service]\nExecStart=/usr/bin/somethingelse\n")
        ch = self.pre()["preflight.units"]
        self.assertFalse(ch.ok)
        self.assertIn("porch-auth.service", ch.message)
        cfg, _ = cfg_file(self.tmp, ADOPT_TOML)
        self.assertNotIn("preflight.units", self.pre(self.ctx(cfg=cfg)))

    def test_nopasswd_and_cert_warnings(self):
        self.runner.on(["sudo", "-n", "-l"], stdout="User porch may run:\n    (ALL) NOPASSWD: ALL\n")
        live = os.path.join(self.tmp, "etc", "letsencrypt", "live", "example.com")
        os.makedirs(live)
        self.env["PORCH_ETC_ROOT"] = self.tmp
        self.pre()
        warns = [e["message"] for e in self.io.kinds("log") if e.get("level") == "warn"]
        self.assertTrue(any("NOPASSWD: ALL" in w and "can become root" in w for w in warns), warns)
        self.assertTrue(any("example.com" in w and "never renews" in w for w in warns), warns)


class DomainTest(Base):
    def test_dry_run_later_steps_see_the_planned_domain(self):
        # Found on a fresh VPS: a dry run wrote nothing, so the haproxy step
        # planned for the built-in cush.rocks instead of the typed domain.
        seen = {}

        class Peek(Step):
            id = "peek"
            def apply(self, ctx):
                return {}
            def plan(self, ctx):
                seen["root"] = ctx.cfg.root
                return []
        ctx = self.ctx(answers={"domain": "cjc1.com"}, dry_run=True)
        self.assertTrue(Engine([domain.Domain(), Peek()], ctx).run().ok)
        self.assertEqual(seen["root"], "porch.cjc1.com")
        self.assertFalse(os.path.exists(self.env["PORCH_CONFIG"]))

    def test_fresh_writes_porch_subdomain(self):
        ctx = self.ctx(answers={"domain": "Example.com"})
        r = Engine([domain.Domain()], ctx).run()
        self.assertTrue(r.ok, r)
        cfg = porch_config.load(path=self.env["PORCH_CONFIG"], env={})
        self.assertEqual(cfg.root, "porch.example.com")
        self.assertEqual(cfg.tunnel_base, "tunnel.porch.example.com")
        self.assertEqual(cfg.install_mode, "fresh")
        self.assertEqual(ctx.cfg.root, "porch.example.com")
        # second run: no-op; rollback removes the file it created
        self.assertTrue(Engine([domain.Domain()], self.ctx()).run().ok)
        Engine([domain.Domain()], self.ctx()).rollback()
        self.assertFalse(os.path.exists(self.env["PORCH_CONFIG"]))

    def test_apex_and_existing_config_refused(self):
        r = Engine([domain.Domain()], self.ctx(answers={"domain": "example.com", "apex": True})).run()
        self.assertTrue(r.ok)
        self.assertEqual(porch_config.load(path=self.env["PORCH_CONFIG"], env={}).root, "example.com")
        shutil.rmtree(self.data)
        os.makedirs(self.data)
        r = Engine([domain.Domain()], self.ctx(answers={"domain": "other.org"})).run()
        self.assertFalse(r.ok)
        self.assertEqual(r.error["code"], "domain.config")

    def test_adopt_uses_existing_root(self):
        cfg, path = cfg_file(self.tmp, ADOPT_TOML)
        r = Engine([domain.Domain()], self.ctx(cfg=cfg, adopt=True)).run()
        self.assertTrue(r.ok, r)
        self.assertEqual(r.statuses["domain"], "adopted")


UFW = """Status: active

To                         Action      From
--                         ------      ----
80/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere
Anywhere                   ALLOW       192.168.1.0/24
80/tcp (v6)                ALLOW       Anywhere (v6)
"""


class FirewallTest(Base):
    def test_opens_only_missing_and_rolls_back(self):
        self.runner.on(["ufw", "status"], stdout=UFW)
        step = firewall.Firewall()
        ctx = self.ctx()
        self.assertFalse(self.checks(step, ctx)["firewall.ports"].ok)
        self.assertEqual(firewall.Firewall.open_ports("ufw", UFW), {80, 443})
        self.assertEqual(firewall.Firewall.open_ports("ufw", "7000:7010/tcp ALLOW Anywhere"),
                         set(range(7000, 7011)))
        ctx.step_id = step.id
        ctx.state.step(step.id)
        out = step.apply(ctx)
        self.assertEqual(out["added"], [7000])
        self.assertIn(["ufw", "allow", "7000/tcp", "comment", "porch"], self.runner.argvs())
        step.rollback(ctx, out)
        self.assertIn(["ufw", "delete", "allow", "7000/tcp"], self.runner.argvs())

    def test_relay_and_no_firewall(self):
        step = firewall.Firewall()
        self.runner.tools.pop("ufw")
        self.assertTrue(self.checks(step, self.ctx())["firewall.none"].ok)
        self.runner.tools["ufw"] = "/usr/sbin/ufw"
        self.runner.on(["ufw", "status"], stdout="Status: active\n")
        ctx = self.ctx()
        ctx.state.connection["active"] = "paid"
        self.assertTrue(self.checks(step, ctx)["firewall.relay"].ok)


class HaproxyTest(Base):
    def test_adopt_verify_diff_and_sni(self):
        cfg, _ = cfg_file(self.tmp, ADOPT_TOML + '[adopt]\nallow = ["frontend www-https: bind *:443"]\n')
        live = render.render_haproxy(cfg).replace(
            "bind *:443 ssl crt /etc/ssl/ssl-certs/cush.rocks",
            "bind *:443 ssl crt /etc/ssl/ssl-certs/cush.rocks crt /etc/ssl/other.pem")
        live += "\nbackend radarr\n\tserver r 127.0.0.1:7878\n"
        step = haproxy.Haproxy()
        step.live_path = os.path.join(self.tmp, "haproxy.cfg")
        with open(step.live_path, "w") as f:
            f.write(live)
        checks = self.checks(step, self.ctx(cfg=cfg))
        self.assertTrue(checks["haproxy.diff"].ok, checks["haproxy.diff"].message)
        self.assertIn("1 allowed", checks["haproxy.diff"].message)
        self.assertTrue(checks["haproxy.sni"].ok)
        with open(step.live_path, "w") as f:
            f.write(live.replace("\tuse_backend tunnel if tunnel\n", ""))
        self.assertFalse(self.checks(step, self.ctx(cfg=cfg))["haproxy.diff"].ok)

    def test_sni_accepts_503_until_services_run(self):
        # Found on the e2e VPS: the haproxy step (90) verified before the
        # backends exist (services, 110) and failed on HAProxy's 503.
        step = haproxy.Haproxy()
        step.live_path = os.path.join(self.tmp, "haproxy.cfg")
        with open(step.live_path, "w") as f:
            f.write(render.render_haproxy(DEFAULT))
        self.runner.rules = [r for r in self.runner.rules if r.match != ["curl"]]
        self.runner.on(["curl"], stdout="503")
        self.assertTrue(self.checks(step, self.ctx())["haproxy.sni"].ok)
        ctx = self.ctx()
        ctx.state.step("services")["status"] = "done"
        self.assertFalse(self.checks(step, ctx)["haproxy.sni"].ok)

    def test_fresh_refuses_foreign_config_and_installs(self):
        step = haproxy.Haproxy()
        step.live_path = os.path.join(self.tmp, "haproxy.cfg")
        with open(step.live_path, "w") as f:
            f.write("global\n\tdaemon\nfrontend mine\n\tbind :8080\nbackend radarr\n\tserver r x\n")
        ctx = self.ctx()
        ctx.step_id = step.id
        pre = {c.code: c for c in step.preflight(ctx)}
        self.assertFalse(pre["haproxy.foreign"].ok)
        self.assertIn("frontend mine", pre["haproxy.foreign"].message)
        with open(step.live_path, "w") as f:
            f.write("global\n\tdaemon\ndefaults\n\tmode http\n")
        self.assertTrue(all(c.ok for c in step.preflight(ctx)))
        self.runner.on(lambda a: a[0].endswith("haproxy-apply"),
                       stdout="→ backed up live config to /etc/haproxy/backups/haproxy.cfg.1.bak\n✓ applied\n")
        ctx.state.step(step.id)
        out = step.apply(ctx)
        self.assertEqual(out["backup"], "/etc/haproxy/backups/haproxy.cfg.1.bak")
        self.assertIn(["install", "-d", "-m", "0755", "-o", "porchuser", "-g", "haproxy",
                       "/etc/haproxy/maps"], self.runner.argvs())
        # Porch's error pages go in before the config that names them.
        argvs = self.runner.argvs()
        pages = [a for a in argvs if a[:2] == ["install", "-m"] and a[-1].startswith(
            "/etc/haproxy/errors/porch/")]
        self.assertEqual(sorted(os.path.basename(a[-1]) for a in pages),
                         [f"{c}.http" for c in (400, 403, 408, 429, 500, 502, 503, 504)])
        apply_at = next(i for i, a in enumerate(argvs) if a[0].endswith("haproxy-apply"))
        self.assertLess(argvs.index(pages[-1]), apply_at)
        step.rollback(ctx, out)
        self.assertEqual(self.runner.argvs()[-1][1:], ["/etc/haproxy/backups/haproxy.cfg.1.bak", "--yes"])

    def test_adopt_never_applies(self):
        cfg, _ = cfg_file(self.tmp, ADOPT_TOML)
        ctx = self.ctx(cfg=cfg)
        with self.assertRaises(StepError):
            haproxy.Haproxy().apply(ctx)


class FrpsTest(Base):
    def frps_step(self):
        step = frps.Frps()
        repo = os.path.join(self.tmp, "repo")
        os.makedirs(os.path.join(repo, "config"), exist_ok=True)
        return step, repo

    def test_fresh_render_private_and_password_kept(self):
        step, repo = self.frps_step()
        ctx = self.ctx(repo_dir=repo)
        r = Engine([step], ctx).run()
        self.assertTrue(r.ok, r)
        path = os.path.join(repo, "config", "frps.toml")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        pw = step.password(ctx)
        with open(path) as f:
            self.assertIn(pw, f.read())
        with open(os.path.join(self.data, "porch-setup.json")) as f:
            self.assertNotIn(pw, f.read())
        self.assertEqual(step.password(self.ctx(repo_dir=repo)), pw)

    def test_verify_flags_missing_ops_and_open_bind(self):
        step, repo = self.frps_step()
        text = render.render_frps(DEFAULT, "pw-abcdef").replace(
            'ops = ["Login", "NewProxy", "NewWorkConn", "Ping"]', 'ops = ["Login"]').replace(
            'proxyBindAddr = "127.0.0.1"\n', "")
        path = os.path.join(repo, "config", "frps.toml")
        with open(path, "w") as f:
            f.write(text)
        os.chmod(path, 0o644)
        checks = self.checks(step, self.ctx(repo_dir=repo))
        self.assertFalse(checks["frps.plugin"].ok)
        self.assertFalse(checks["frps.bind"].ok)
        self.assertFalse(checks["frps.mode"].ok)
        self.assertTrue(checks["frps.subdomain"].ok)
        cfg, _ = cfg_file(self.tmp, ADOPT_TOML + '[adopt]\nallow = ["frps: proxyBindAddr"]\n')
        self.assertTrue(self.checks(step, self.ctx(cfg=cfg, repo_dir=repo))["frps.bind"].ok)


class ServicesTest(Base):
    HEALTH = {"http://127.0.0.1:9512/auth/": 200, "http://127.0.0.1:9471/api/me": 200,
              "http://127.0.0.1:9411/": 404, "http://127.0.0.1:9473/": 200}

    def test_fresh_units_enable_and_undo(self):
        step = services.Services()
        step.tcp_open = staticmethod(lambda h, p, timeout=2.0: True)
        self.runner.on(["systemctl", "--user", "is-active"], stdout="active\n")
        ctx = self.ctx(http=fake_http(self.HEALTH))
        r = Engine([step], ctx).run()
        self.assertTrue(r.ok, r)
        unit_dir = os.path.join(self.tmp, "xdg", "systemd", "user")
        self.assertEqual(sorted(os.listdir(unit_dir)), sorted(render.render_units(DEFAULT)))
        self.assertIn(["systemctl", "--user", "enable", "--now", *sorted(render.render_units(DEFAULT))],
                      [a[:4] + sorted(a[4:]) for a in self.runner.argvs()])
        Engine([step], self.ctx(http=fake_http(self.HEALTH))).rollback()
        self.assertEqual(os.listdir(unit_dir), [])
        self.assertTrue(any(a[:4] == ["systemctl", "--user", "disable", "--now"] for a in self.runner.argvs()))

    def test_user_bus_found_without_session_env(self):
        # sudo / systemd-run --uid drop XDG_RUNTIME_DIR and the bus address:
        # "no systemd user session" on the e2e VPS with linger on.
        envs = []

        def show(argv, env=None, **kw):
            envs.append(env or {})
            return Result(argv, 0, "HOME=/x\n", "")
        self.runner.on(["systemctl", "--user", "show-environment"], func=show)
        self.env.pop("XDG_RUNTIME_DIR", None)
        self.env.pop("DBUS_SESSION_BUS_ADDRESS", None)
        checks = {k.code: k for k in services.Services().preflight(self.ctx())}
        self.assertTrue(checks["services.user_systemd"].ok)
        run = f"/run/user/{os.getuid()}"
        self.assertEqual(envs[0]["XDG_RUNTIME_DIR"], run)
        self.assertEqual(envs[0]["DBUS_SESSION_BUS_ADDRESS"], f"unix:path={run}/bus")

    def test_dry_run_does_not_need_the_session_preflight_would_create(self):
        self.runner.on(["systemctl", "--user", "show-environment"], returncode=1)
        checks = {k.code: k for k in services.Services().preflight(self.ctx(dry_run=True))}
        self.assertTrue(checks["services.user_systemd"].ok)

    def test_waits_for_units_and_makes_landing_dir(self):
        # e2e VPS: health ran 1s before the auth server listened, and
        # porch-landing looped on a web root only the landing step created.
        step = services.Services()
        calls = {"n": 0}

        def tcp_open(h, p, timeout=2.0):
            calls["n"] += 1
            return calls["n"] > 3          # frps "comes up" on the 4th look
        step.tcp_open = staticmethod(tcp_open)
        self.runner.on(["systemctl", "--user", "is-active"], stdout="active\n")
        web_root = os.path.join(self.tmp, "landing")
        with mock.patch.object(render, "default_web_root", lambda env=None: web_root):
            r = Engine([step], self.ctx(http=fake_http(self.HEALTH))).run()
        self.assertTrue(r.ok, r)
        self.assertTrue(os.path.isdir(web_root))
        self.assertGreater(calls["n"], 3)

    def test_health_failure(self):
        step = services.Services()
        step.tcp_open = staticmethod(lambda h, p, timeout=2.0: False)
        checks = self.checks(step, self.ctx(http=fake_http({})))
        self.assertFalse(checks["services.auth"].ok)
        self.assertFalse(checks["services.frps"].ok)


class AdminTest(Base):
    def test_reads_devices_from_app_data_not_setup_state_dir(self):
        # PORCH_SETUP_DIR moves setup's state; devices.json stays with the apps.
        apps = os.path.join(self.tmp, "apps")
        os.makedirs(apps)
        with open(os.path.join(apps, "devices.json"), "w") as f:
            json.dump({"admin": {"password_scrypt": "x"}}, f)
        self.env["PORCH_APP_DATA"] = apps
        self.assertTrue(admin.has_admin(self.ctx()))
        self.env["PORCH_APP_DATA"] = self.data
        self.assertFalse(admin.has_admin(self.ctx()))

    def test_sets_password_via_stdin_never_stored(self):
        pw = "correct-horse-battery"
        self.env["PORCH_ADMIN_PASSWORD"] = pw
        step = admin.Admin()
        devices = os.path.join(self.data, "devices.json")

        def set_pw(argv, input=None, **kw):
            with open(devices, "w") as f:
                json.dump({"admin": {"password_scrypt": "x"}}, f)
            return Result(argv, 0, "Admin password set.\n", "")
        self.runner.on(lambda a: a[0].endswith("auth-admin"), func=set_pw)
        ctx = self.ctx(http=fake_http({"http://127.0.0.1:9512/auth/": 200}), answers={"admin_password": pw})
        r = Engine([step], ctx).run()
        self.assertTrue(r.ok, r)
        self.assertIn(pw + "\n", self.runner.inputs)
        self.assertNotIn(pw, json.dumps(self.runner.calls))
        for name in ("porch-setup.json", "porch-setup.log"):
            with open(os.path.join(self.data, name)) as f:
                self.assertNotIn(pw, f.read())
        self.assertIn("https://auth.cush.rocks/auth/", json.dumps(self.io.events))

    def test_short_password_refused(self):
        ctx = self.ctx(http=fake_http({"http://127.0.0.1:9512/auth/": 200}), answers={"admin_password": "short"})
        r = Engine([admin.Admin()], ctx).run()
        self.assertEqual(r.error["code"], "admin.password")


class LandingSmokeTest(Base):
    def test_landing_deploys_to_web_root(self):
        ctx = self.ctx()
        ctx.step_id = "landing"
        out = landing.Landing().apply(ctx)
        self.assertTrue(out["web_root"].endswith(os.path.join("porch", "landing")))
        cfg, _ = cfg_file(self.tmp, ADOPT_TOML)
        self.assertEqual(landing.Landing().web_root(self.ctx(cfg=cfg)), "/var/www/tunnel")
        self.assertTrue(self.checks(landing.Landing(), self.ctx())["landing.https"].ok)

    def test_smoke_verify(self):
        step = smoke.Smoke()
        seen = []
        step.tls_probe = staticmethod(lambda h: (seen.append(h) or True, f"{h}: ok", 60))
        checks = step.verify(self.ctx())
        self.assertTrue(all(c.ok for c in checks))
        self.assertEqual(seen[:3], ["auth.cush.rocks", "panel.cush.rocks", "tunnel.cush.rocks"])
        self.assertTrue(seen[3].endswith(".tunnel.cush.rocks"))
        step.tls_probe = staticmethod(lambda h: (True, f"{h}: ok", 3))
        self.assertTrue(any(c.code == "smoke.cert_expiry" for c in step.verify(self.ctx())))

    def test_smoke_tunnel_non_interactive(self):
        step = smoke.Smoke()
        ctx = self.ctx()
        ctx.step_id = "smoke"
        ctx.state.step("smoke")
        out = step.apply(ctx)
        self.assertEqual(out, {"tunnel": "ok", "external": None})
        names = [a for a in self.runner.argvs() if a[0].endswith("/tunnel")]
        self.assertEqual(len(names), 1)
        self.assertTrue(any(a[0].endswith("/status") and a[1:2] == ["close"] for a in self.runner.argvs()))

    def test_smoke_phone_check_shows_the_wizard_qr(self):
        # Found on the e2e VPS: the web wizard showed no QR here because the
        # smoke step never emitted the phone_check event its panel listens for.
        step = smoke.Smoke()
        step.phone_wait = 0
        ctx = self.ctx()
        self.io.interactive = True
        ctx.step_id = "smoke"
        ctx.state.step("smoke")
        with self.assertRaises(StepError):      # no phone in a unit test
            step.apply(ctx)
        shown = self.io.kinds("phone_check")
        self.assertEqual(len(shown), 1)
        self.assertTrue(shown[0]["url"].startswith("https://"))
        self.assertEqual(shown[0]["step"], "smoke")

    def test_public_source(self):
        self.assertTrue(smoke._public("8.8.8.8, 127.0.0.1"))
        self.assertFalse(smoke._public("192.168.1.5"))
        self.assertFalse(smoke._public(""))


class PocketStepTest(Base):
    def setUp(self):
        super().setUp()
        self.state_dir = os.path.join(self.tmp, "tunnel-state")
        os.makedirs(self.state_dir)
        self.env["TUNNEL_STATE_DIR"] = self.state_dir
        self.unit = os.path.join(self.tmp, "xdg", "systemd", "user", "porch-pocket@.service")

    def live(self, port=41234):
        with open(os.path.join(self.state_dir, "pocket.json"), "w") as f:
            json.dump({"name": "pocket", "type": "pocket", "port": port}, f)
        return fake_http({f"http://127.0.0.1:{port}/manifest.webmanifest": 200})

    def test_installs_unit_verifies_and_rolls_back(self):
        step = pocket.Pocket()
        self.runner.on(["systemctl", "--user", "is-active"], stdout="active\n")
        http = self.live()
        r = Engine([step], self.ctx(http=http)).run()
        self.assertTrue(r.ok, r)
        with open(self.unit) as f:
            text = f.read()
        self.assertIn(f"ExecStart=/bin/bash {self.ctx().repo_dir}/bin/pocket %i --expires never", text)
        self.assertNotIn("${", text)
        argvs = self.runner.argvs()
        self.assertIn(["systemctl", "--user", "enable", "--now", "porch-pocket@pocket.service"], argvs)
        curls = [a for a in argvs if a[0] == "curl"]
        self.assertTrue(any("https://pocket.tunnel.cush.rocks/manifest.webmanifest" in a for a in curls))
        # Idempotent: a second run only verifies.
        before = len(self.runner.argvs())
        r = Engine([step], self.ctx(http=http)).run()
        self.assertTrue(r.ok, r)
        self.assertFalse(any(a[:3] == ["systemctl", "--user", "enable"] for a in self.runner.argvs()[before:]))
        Engine([step], self.ctx(http=http)).rollback()
        self.assertFalse(os.path.exists(self.unit))
        self.assertIn(["systemctl", "--user", "disable", "--now", "porch-pocket@pocket.service"],
                      self.runner.argvs())

    def test_takes_over_the_same_file_refuses_another(self):
        step = pocket.Pocket()
        os.makedirs(os.path.dirname(self.unit))
        ctx = self.ctx(http=self.live())
        with open(self.unit, "w") as f:
            f.write(pocket.render_unit(ctx.repo_dir, "Porch"))
        ctx.step_id = "pocket"
        ctx.state.step("pocket")
        self.assertEqual(step.apply(ctx)["unit"], "porch-pocket@pocket.service")
        os.unlink(self.unit)
        ctx.state.files.pop(self.unit, None)
        with open(self.unit, "w") as f:
            f.write("[Service]\nExecStart=/bin/true\n")
        with self.assertRaises(StepError) as cm:
            step.apply(ctx)
        self.assertEqual(cm.exception.code, "pocket.unit_exists")

    def test_health_fails_without_a_door(self):
        checks = self.checks(pocket.Pocket(), self.ctx())
        self.assertFalse(checks["pocket.local"].ok)
        self.assertIn("pocket.json", checks["pocket.local"].message)

    def test_adopt_only_verifies(self):
        cfg, _ = cfg_file(self.tmp, ADOPT_TOML)
        step = pocket.Pocket()
        ctx = self.ctx(cfg=cfg, http=self.live())
        self.assertEqual(step.plan(ctx), [])
        with self.assertRaises(StepError):
            step.apply(ctx)
        r = Engine([step], self.ctx(cfg=cfg, http=self.live(), adopt=True)).run()
        self.assertTrue(r.ok, r)
        self.assertFalse(os.path.exists(self.unit))
        self.assertFalse(any(a[:2] == ["systemctl", "--user"] and "enable" in a for a in self.runner.argvs()))

    def test_signin_url_goes_through_the_handoff(self):
        self.assertEqual(pocket.signin_url(DEFAULT),
                         "https://pocket.tunnel.cush.rocks/__porch/start?rd=%2F")
        self.assertEqual(pocket.pocket_url(DEFAULT), "https://pocket.tunnel.cush.rocks/")


class DoctorTest(Base):
    def test_doctor_reports_and_writes_nothing(self):
        class Good(Step):
            id = "good"

            def verify(self, ctx):
                return [Check(True, "g", "fine")]

        class Bad(Step):
            id = "bad"

            def verify(self, ctx):
                ctx.run.run(["touch", "/should/not/run"])
                return [Check(False, "b.x", "broken", "fix it")]
        ctx = self.ctx(dry_run=True)
        out = io.StringIO()
        rc = cmd_doctor.main(["--fix-hints"], steps=[Good(), Bad()], ctx=ctx, out=out)
        self.assertEqual(rc, 5)
        self.assertIn("FAIL b.x: broken", out.getvalue())
        self.assertIn("fix: fix it", out.getvalue())
        self.assertTrue(self.runner.calls[-1]["dry_run"])
        self.assertFalse(os.path.exists(os.path.join(self.data, "porch-setup.json")))
        out = io.StringIO()
        cmd_doctor.main(["--json"], steps=[Good()], ctx=self.ctx(dry_run=True), out=out)
        data = json.loads(out.getvalue())
        self.assertEqual(data["steps"][0]["checks"][0]["code"], "g")
        self.assertEqual(data["steps"][-1]["step"], "extras")


if __name__ == "__main__":
    unittest.main()

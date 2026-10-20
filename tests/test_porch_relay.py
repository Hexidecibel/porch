"""Relay connection modes (paid, byo, oracle), provider clients and the relay
scripts. Everything is faked: provider HTTP, ssh (FakeRunner), the relay's
control port and the home frpc admin API. Nothing here creates a server,
opens an ssh connection or touches systemd."""

import base64
import contextlib
import io as stdio
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
sys.path.insert(0, os.path.join(_REPO, "lib"))

import porch_config  # noqa: E402
from porch_setup import cli, cmd_connect, registry, render  # noqa: E402
from porch_setup.connect import byo as byo_mod  # noqa: E402
from porch_setup.connect import oracle as oracle_mod  # noqa: E402
from porch_setup.connect import paid as paid_mod  # noqa: E402
from porch_setup.engine import (EXIT_PREFLIGHT, EXIT_USAGE, Engine, StepError,  # noqa: E402
                                make_context)
from porch_setup.io import NullIO  # noqa: E402
from porch_setup.redact import Redactor  # noqa: E402
from porch_setup.relay import common  # noqa: E402
from porch_setup.relay import providers as prov  # noqa: E402
from porch_setup.runner import FakeRunner, Result  # noqa: E402
from porch_setup.steps import _common, connection, firewall, network_probe  # noqa: E402

CFG = porch_config.load(env={"PORCH_CONFIG": "none"})
TOKEN = "do-secret-token-0123456789abcdef"
RELAY_IP = "203.0.113.50"

CGNAT = {"iface": "eth0", "gateway": "192.168.1.1", "lan_ipv4": "192.168.1.48", "host_public_ipv4": [],
         "public_ipv4": "198.51.100.7", "public_ipv4_sources": ["a", "b"], "public_ipv4_error": "",
         "upnp": None, "natpmp": {"natpmp": True, "pcp": False, "external_ip": "100.72.1.9", "error": ""},
         "wan_ipv4": "100.72.1.9", "wan_source": "natpmp", "cgnat": True,
         "cgnat_reason": "the router's WAN address 100.72.1.9 is in 100.64.0.0/10 (carrier-grade NAT)",
         "ipv6": [], "router": {"brand": None, "name": "", "source": ""}}


def cfg_with_bypass(on):
    cfg = porch_config.load(env={"PORCH_CONFIG": "none"})
    object.__setattr__(cfg, "localhost_bypass", on)     # Config is read-only on purpose
    return cfg


# ---- fakes ---------------------------------------------------------------------------

class FakeDOApi:
    """Just enough of the DigitalOcean v2 API. `log` is shared with the
    runner so tests can assert ordering across HTTP and systemctl."""

    def __init__(self, log, ready_after=1):
        self.log = log
        self.droplets = {}
        self.next_id = 500
        self.ready_after = ready_after
        self.polls = {}
        self.headers = []
        self.bodies = []

    def __call__(self, method, url, headers, body):
        self.headers.append(headers)
        path = url.split("/v2", 1)[1]
        self.log.append(("http", method, path))
        if body:
            self.bodies.append(json.loads(body))
        if headers.get("Authorization") != f"Bearer {TOKEN}":
            return 401, b'{"id":"unauthorized"}'
        if method == "GET" and path == "/account":
            return 200, b'{"account":{"status":"active"}}'
        if method == "GET" and path.startswith("/sizes"):
            return 200, json.dumps({"sizes": [
                {"slug": "s-1vcpu-512mb-10gb", "available": True, "price_monthly": 4.0,
                 "price_hourly": 0.00595, "regions": ["sfo3", "nyc1"]},
                {"slug": "s-1vcpu-1gb", "available": True, "price_monthly": 6.0,
                 "price_hourly": 0.00893, "regions": ["nyc3", "sfo3"]}]}).encode()
        if method == "POST" and path == "/droplets":
            d = json.loads(body)
            did = self.next_id
            self.next_id += 1
            self.droplets[did] = {"id": did, "name": d["name"], "status": "new", "tags": d["tags"],
                                  "networks": {"v4": []}}
            return 202, json.dumps({"droplet": self.droplets[did]}).encode()
        m = re.match(r"^/droplets/(\d+)$", path)
        if m:
            did = int(m.group(1))
            if did not in self.droplets:
                return 404, b'{"id":"not_found"}'
            if method == "DELETE":
                del self.droplets[did]
                return 204, b""
            self.polls[did] = self.polls.get(did, 0) + 1
            if self.polls[did] >= self.ready_after:
                self.droplets[did]["status"] = "active"
                self.droplets[did]["networks"] = {"v4": [{"type": "private", "ip_address": "10.0.0.5"},
                                                         {"type": "public", "ip_address": RELAY_IP}]}
            return 200, json.dumps({"droplet": self.droplets[did]}).encode()
        if method == "GET" and path.startswith("/droplets?tag_name="):
            tag = path.split("=", 1)[1].split("&")[0]
            return 200, json.dumps({"droplets": [d for d in self.droplets.values()
                                                 if tag in d["tags"]]}).encode()
        return 500, b"unexpected"


class FakeResp:
    def __init__(self, data):
        self.data = data

    def read(self):
        return self.data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def admin_api(statuses=None):
    """ctx.http stand-in answering the relay frpc's /api/status."""
    def http(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else req
        if url.endswith("/api/status"):
            st = statuses if statuses is not None else {n: "running" for n in common.PROXIES}
            return FakeResp(json.dumps({"tcp": [{"name": k, "status": v} for k, v in st.items()]}).encode())
        raise OSError("refused")
    return http


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        os.makedirs(self.tmp + "/repo/bin")
        os.makedirs(self.tmp + "/repo/config")
        with open(self.tmp + "/repo/bin/frpc", "w") as f:
            f.write("#!/bin/sh\n")
        self.events = []
        self.do = FakeDOApi(self.events)
        self.facts = CGNAT
        self._patch(network_probe, "PROBE", lambda ctx: json.loads(json.dumps(self.facts)))
        self._patch(paid_mod.MODE, "http", self.do)
        self.control_up = True
        for m in (paid_mod.MODE, byo_mod.MODE, oracle_mod.MODE):
            self._patch(m, "tcp_open", lambda h, p, timeout=3.0: self.control_up)
        self.t = [1_700_000_000.0]
        self.runner = FakeRunner()
        self.runner.on(lambda a: True, func=self._run)
        self.ssh_ok = True
        self.env = {"XDG_CONFIG_HOME": self.tmp + "/xdg", "XDG_RUNTIME_DIR": self.tmp + "/run"}

    def _run(self, argv, input=None, **kw):
        self.events.append(("run", tuple(argv)))
        if argv[0] == "systemctl" and "is-active" in argv:
            return Result(argv, 0, "active\n", "")
        if argv[0] == "ssh":
            if not self.ssh_ok:
                return Result(argv, 1, "", "sudo: a password is required\n")
            if input and "PORCH_RELAY_OK" in input:
                return Result(argv, 0, "porch relay install\nPORCH_RELAY_OK bind=203.0.113.50\n", "")
            return Result(argv, 0, "PORCH_RELAY_REMOVED\n", "")
        return Result(argv, 0, "", "")

    def _patch(self, obj, name, value):
        old = getattr(obj, name)
        setattr(obj, name, value)
        self.addCleanup(setattr, obj, name, old)

    def clock(self):
        self.t[0] += 1
        return self.t[0]

    def kw(self, http=None):
        return {"runner": self.runner, "data_dir": self.tmp + "/data", "cfg": CFG, "redactor": Redactor(),
                "secrets_dir": self.tmp + "/s", "sleep": lambda s: None, "clock": self.clock,
                "repo_dir": self.tmp + "/repo", "env": self.env, "http": http or admin_api()}

    def ctx(self, answers, confirms=True, **extra):
        self.io = NullIO(answers, confirms=confirms)
        return make_context(io=self.io, **{**self.kw(), **extra})

    def run_paid(self, confirms=True, **answers):
        a = {"connection": "paid", "relay_token": TOKEN, **answers}
        ctx = self.ctx(a, confirms)
        return ctx, Engine([network_probe.STEP, connection.STEP], ctx).run()

    def index(self, pred):
        for i, e in enumerate(self.events):
            if pred(e):
                return i
        return -1


# ---- providers -------------------------------------------------------------------------

class ProviderTest(unittest.TestCase):
    def test_digitalocean_plan_create_delete_and_token_scrubbed(self):
        log = []
        api = FakeDOApi(log)
        do = prov.DigitalOcean(TOKEN, http=api)
        self.assertEqual(do.check()["status"], "active")
        p = do.plan()
        self.assertEqual((p["size"], p["region"], p["monthly"]), ("s-1vcpu-512mb-10gb", "nyc1", 4.0))
        p = do.plan(region="nyc3")             # the $4 size is not there: next size
        self.assertEqual((p["size"], p["region"]), ("s-1vcpu-1gb", "nyc3"))
        with self.assertRaises(prov.ProviderError):
            do.plan(region="lon1")
        s = do.create("porch-relay-x", "nyc3", "s-1vcpu-1gb", "#!/bin/bash\n", ["porch-relay", "porch-e2e"])
        self.assertFalse(s["ready"])
        body = api.bodies[-1]
        self.assertEqual(body["image"], "ubuntu-24-04-x64")
        self.assertEqual(body["tags"], ["porch-relay", "porch-e2e"])
        self.assertEqual(body["user_data"], "#!/bin/bash\n")
        s = do.get(s["id"])
        self.assertEqual((s["ready"], s["ipv4"]), (True, RELAY_IP))
        self.assertEqual([x["id"] for x in do.list_tagged("porch-relay")], [s["id"]])
        do.delete(s["id"])
        self.assertIsNone(do.get(s["id"]))
        do.delete(s["id"])                     # 404 is done
        bad = prov.DigitalOcean("wrong-" + TOKEN, http=api)
        with self.assertRaises(prov.ProviderError) as cm:
            bad.check()
        self.assertIn("refused", str(cm.exception))
        self.assertNotIn("wrong-", str(cm.exception))

    def test_vultr_refusal_names_the_access_list(self):
        v = prov.Vultr("k-" + TOKEN, http=lambda m, u, h, b: (401, b'{"error":"Unauthorized IP address"}'))
        with self.assertRaises(prov.ProviderError) as cm:
            v.check()
        self.assertIn("Access Control", str(cm.exception))
        self.assertNotIn(TOKEN, str(cm.exception))

    def test_error_bodies_never_echo_the_token(self):
        def http(method, url, headers, body):
            return 422, ("bad token " + TOKEN).encode()
        with self.assertRaises(prov.ProviderError) as cm:
            prov.DigitalOcean(TOKEN, http=http).check()
        self.assertNotIn(TOKEN, str(cm.exception))
        self.assertIn("<token>", str(cm.exception))

    def test_hetzner_is_not_a_provider(self):
        # Removed: unit-tested only, never run live. DigitalOcean + Vultr stay.
        self.assertEqual(sorted(prov.PROVIDERS), ["digitalocean", "vultr"])
        self.assertFalse(hasattr(prov, "Hetzner"))

    def test_vultr(self):
        calls = []

        def http(method, url, headers, body):
            calls.append((method, url, json.loads(body) if body else None))
            if "/plans" in url:
                return 200, json.dumps({"plans": [
                    {"id": "vc2-1c-0.5gb", "monthly_cost": 2.5, "locations": ["ewr"]},
                    {"id": "vc2-1c-1gb", "monthly_cost": 5, "locations": ["ewr", "lax"]}]}).encode()
            if "/os" in url:
                return 200, b'{"os":[{"id":1743,"name":"Ubuntu 22.04 LTS x64","arch":"x64"},{"id":2284,"name":"Ubuntu 24.04 LTS x64","arch":"x64"}]}'
            if method == "POST" and url.endswith("/instances"):
                return 202, b'{"instance":{"id":"cb676a46-66fd-4dfb-b839-443f2e6c0b60","label":"porch-relay-b","status":"pending","main_ip":"0.0.0.0","tags":["porch-relay"],"default_password":"NOPE"}}'
            if "/instances/cb676a46" in url:
                if method == "DELETE":
                    return 204, b""
                return 200, b'{"instance":{"id":"cb676a46-66fd-4dfb-b839-443f2e6c0b60","label":"porch-relay-b","status":"active","main_ip":"192.0.2.44","tags":["porch-relay"]}}'
            if "/instances?tag=porch-relay" in url:
                return 200, b'{"instances":[{"id":"cb676a46-66fd-4dfb-b839-443f2e6c0b60","label":"porch-relay-b","status":"active","main_ip":"192.0.2.44","tags":["porch-relay"]},{"id":"ffff","label":"other","tags":[]}]}'
            return 500, b""
        v = prov.Vultr("vtok", http=http)
        p = v.plan()
        self.assertEqual((p["size"], p["region"], p["monthly"]), ("vc2-1c-1gb", "ewr", 5.0))
        with self.assertRaises(prov.ProviderError):
            v.plan(region="fra")
        s = v.create("porch-relay-b", "ewr", "vc2-1c-1gb", "#!/bin/bash\necho hi\n", ["porch-relay"])
        self.assertIsNone(s["ipv4"])           # 0.0.0.0 until it boots
        self.assertNotIn("NOPE", json.dumps(s))
        body = calls[-1][2]
        self.assertEqual(body["os_id"], 2284)
        self.assertEqual(base64.b64decode(body["user_data"]).decode(), "#!/bin/bash\necho hi\n")
        self.assertEqual(v.get(s["id"])["ipv4"], "192.0.2.44")
        self.assertEqual(len(v.list_tagged("porch-relay")), 1)
        v.delete(s["id"])
        with self.assertRaises(prov.ProviderError):
            v.get("../../account")


# ---- scripts and configs -------------------------------------------------------------------

class ScriptTest(unittest.TestCase):
    def test_install_script_pins_and_quotes(self):
        tok = common.new_token()
        s = common.render_install(tok, "paid", 7000, ssh_from="198.51.100.7",
                                  ssh_pubkey="ssh-ed25519 AAAA x@y")
        self.assertIn(common.FRP_SHA256["amd64"], s)
        self.assertIn(common.FRP_SHA256["arm64"], s)
        self.assertIn('auth.token = "' + tok + '"', s)
        self.assertIn("allowPorts = [{ single = 80 }, { single = 443 }, { single = 7000 }]", s)
        self.assertIn("bindPort = 7835", s)
        self.assertNotIn("webServer", s)               # dashboard off
        self.assertIn("MODE=paid", s)
        self.assertIn("SSH_FROM=198.51.100.7", s)
        self.assertIn("SSH_PUBKEY='ssh-ed25519 AAAA x@y'", s)
        self.assertIsNone(re.search(r"\$\{[a-z_]+\}", s))   # no template name left unsubstituted
        with self.assertRaises(StepError):
            common.render_install('x"; rm -rf /', "paid", 7000)
        with self.assertRaises(StepError):
            common.render_install(tok, "nope", 7000)
        p = subprocess.run(["bash", "-n"], input=s, text=True, capture_output=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        p = subprocess.run(["bash", "-n"], input=common.render_uninstall(), text=True, capture_output=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_byo_script_never_resets_firewall_or_ssh(self):
        s = common.render_install(common.new_token(), "byo", 7000)
        self.assertIn("MODE=byo", s)
        self.assertIn("SSH_FROM=''", s)
        # the reset branch is guarded by MODE = paid
        self.assertIn('if [ "$MODE" = paid ] && command -v ufw', s)
        u = common.render_uninstall()
        for bad in ("shutdown", "poweroff", "port 22", "ufw disable", "ufw --force reset"):
            self.assertNotIn(bad, u)

    def frps_text(self, script):
        m = re.search(r"<<CONF\n(.*?)\nCONF\n", script, re.S)
        return m.group(1).replace("$BIND", "127.0.0.1")

    @unittest.skipUnless(os.path.exists(os.path.join(_REPO, "bin", "frps")), "needs bin/frps")
    def test_frp_accepts_both_configs(self):
        tok = common.new_token()
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "frps.toml")
            with open(p, "w") as f:
                f.write(self.frps_text(common.render_install(tok, "paid", 7000)))
            r = subprocess.run([os.path.join(_REPO, "bin", "frps"), "verify", "-c", p],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            p = os.path.join(d, "frpc.toml")
            with open(p, "w") as f:
                f.write(common.render_frpc(CFG, RELAY_IP, tok, common.new_token(), "paid"))
            r = subprocess.run([os.path.join(_REPO, "bin", "frpc"), "verify", "-c", p],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_frpc_config(self):
        import tomllib
        tok, pw = common.new_token(), common.new_token()
        data = tomllib.loads(common.render_frpc(CFG, RELAY_IP, tok, pw, "paid"))
        self.assertEqual((data["serverAddr"], data["serverPort"]), (RELAY_IP, 7835))
        self.assertEqual(data["auth"]["token"], tok)
        self.assertEqual(data["webServer"]["addr"], "127.0.0.1")
        px = {p["remotePort"]: p for p in data["proxies"]}
        self.assertEqual(sorted(px), [80, 443, 7000])
        self.assertEqual(px[80]["localPort"], 9476)
        self.assertEqual(px[443]["localPort"], 9477)
        self.assertEqual(px[7000]["localPort"], 7000)
        self.assertEqual(px[80]["transport"]["proxyProtocolVersion"], "v2")
        self.assertEqual(px[443]["transport"]["proxyProtocolVersion"], "v2")
        self.assertNotIn("transport", px[7000])         # frps speaks no PROXY protocol
        self.assertEqual({p["name"] for p in data["proxies"]}, set(common.PROXIES))

    def test_haproxy_relay_binds_keep_the_client_address(self):
        text = render.render_haproxy(CFG, "fresh", relay=True)
        self.assertIn("bind 127.0.0.1:9476 accept-proxy", text)
        self.assertIn("ssl crt", text.split("bind 127.0.0.1:9477", 1)[1].splitlines()[0])
        self.assertIn("accept-proxy", text.split("bind 127.0.0.1:9477", 1)[1].splitlines()[0])
        # the auth server's per-IP limits read X-Forwarded-For, set from %[src]
        # (the PROXY header's client address on the relay binds)
        self.assertIn("http-request set-header X-Forwarded-For %[src]", text)
        self.assertNotIn("accept-proxy", render.render_haproxy(CFG, "fresh"))
        # 9476/9477 never collide with the wizard (8443) or each other
        o = render.options(CFG)
        self.assertEqual(len({o["relay_http_port"], o["relay_https_port"], o["relay_admin_port"], 8443}), 4)

    def test_cmd_render_relay_flag(self):
        from porch_setup import cmd_render
        out = stdio.StringIO()
        self.assertEqual(cmd_render.main(["haproxy", "--relay", "--profile", "fresh"], cfg=CFG, out=out), 0)
        self.assertIn("bind 127.0.0.1:9477 ssl", out.getvalue())

    def test_authserver_uses_the_relayed_client(self):
        import authserver
        # HAProxy (loopback peer) puts the PROXY-protocol client in XFF.
        self.assertEqual(authserver.client_ip_from("127.0.0.1", ["198.51.100.23"]), "198.51.100.23")
        self.assertEqual(authserver.client_ip_from("127.0.0.1", ["6.6.6.6, 198.51.100.23"]), "198.51.100.23")


# ---- bypass refusal --------------------------------------------------------------------------

class BypassTest(Base):
    def test_bypass_helper_agrees_with_authserver(self):
        import authserver
        for env_v in (None, "1", "0", "true", "off", "yes", "junk"):
            for cfg_v in (False, True):
                cfg = cfg_with_bypass(cfg_v)
                env = {} if env_v is None else {"PORCH_LOCALHOST_BYPASS": env_v}
                ctx = make_context(io=NullIO(), **{**self.kw(), "cfg": cfg, "env": env})
                self.assertEqual(common.bypass_on(ctx), authserver.localhost_bypass_enabled(cfg, env),
                                 (env_v, cfg_v))

    def test_relay_modes_refuse_while_bypass_is_on(self):
        self.env["PORCH_LOCALHOST_BYPASS"] = "1"
        for mode in ("paid", "byo", "oracle"):
            ctx = self.ctx({"connection": mode, "relay_token": TOKEN, "relay_host": "ubuntu@" + RELAY_IP})
            status, reason = registry.modes()[mode].detect(ctx, CGNAT)
            self.assertEqual(status, "unavailable", mode)
            self.assertIn("bypass", reason)
            r = Engine([network_probe.STEP, connection.STEP], ctx).run()
            self.assertEqual(r.exit_code, EXIT_PREFLIGHT, mode)
            self.assertIn("bypass", r.error["message"])
            self.assertIn("localhost_bypass = false", r.error["hint"])
        self.assertEqual([e for e in self.events if e[0] == "http"], [])
        self.assertFalse([e for e in self.events if e[0] == "run" and e[1][0] == "ssh"])

    def test_apply_refuses_too(self):
        self.env["PORCH_LOCALHOST_BYPASS"] = "on"
        ctx = self.ctx({"relay_token": TOKEN})
        for m in (paid_mod.MODE, byo_mod.MODE):
            with self.assertRaises(StepError) as cm:
                m.apply(ctx, CGNAT)
            self.assertEqual(cm.exception.code, "connect.relay.bypass")
        self.assertEqual(self.events, [])

    def test_config_bypass_refuses_and_cmd_connect_exits_3(self):
        cfg = cfg_with_bypass(True)      # [adopt] localhost_bypass = true, no env override
        out, err = stdio.StringIO(), stdio.StringIO()
        with contextlib.redirect_stderr(err):
            rc = cmd_connect.main(["paid", "--token-ref", "file:///nope", "--yes"], out=out, env=self.env,
                                  ctx_kwargs={**{k: v for k, v in self.kw().items() if k != "env"}, "cfg": cfg})
        self.assertEqual(rc, EXIT_PREFLIGHT)
        self.assertIn("refused", err.getvalue())
        self.assertEqual(self.events, [])


# ---- paid ------------------------------------------------------------------------------------

class PaidTest(Base):
    def test_create_install_verify_and_rollback_order(self):
        ctx, r = self.run_paid(relay_tag="porch-e2e")
        self.assertTrue(r.ok, r)
        out = ctx.outputs("connection")
        self.assertEqual((out["mode"], out["ingress_ipv4"], out["ddns"]), ("paid", RELAY_IP, False))
        self.assertIsNone(out["ingress_ipv6"])
        self.assertEqual(out["relay"]["provider"], "digitalocean")
        self.assertEqual(out["relay"]["monthly"], 4.0)
        create = self.do.bodies[-1]
        self.assertEqual(create["tags"], ["porch-relay", "porch-e2e"])
        self.assertIn("SSH_FROM=198.51.100.7", create["user_data"])    # ssh only from home
        # the price was shown and confirmed before the create call
        logs = [d["message"] for d in self.io.kinds("log")]
        self.assertTrue(any("4.00 USD/month" in m for m in logs))
        self.assertTrue(any("4.00 USD/month" in p for p in self.io.prompts))
        # home side: 0600 config with the token, the user unit, systemctl
        frpc = self.tmp + "/repo/config/relay-frpc.toml"
        self.assertEqual(os.stat(frpc).st_mode & 0o777, 0o600)
        with open(frpc) as f:
            text = f.read()
        token = re.search(r'auth.token = "([^"]+)"', text).group(1)
        self.assertIn(token, create["user_data"])
        self.assertTrue(os.path.exists(self.tmp + "/xdg/systemd/user/porch-relay.service"))
        self.assertGreater(self.index(lambda e: e[0] == "run" and e[1][:4] == ("systemctl", "--user", "restart", "porch-relay.service")), 0)
        # secrets stay out of state, logs and recorded commands
        with open(self.tmp + "/data/porch-setup.json") as f:
            state = f.read()
        self.assertNotIn(TOKEN, state)
        self.assertNotIn(token, state)
        self.assertNotIn(token, json.dumps(self.runner.calls))
        with open(self.tmp + "/data/porch-setup.log") as f:
            self.assertNotIn(TOKEN, f.read())
        undo = [u["kind"] for u in ctx.state.steps["connection"]["undo"]]
        self.assertEqual(undo, ["relay.server_delete", "relay.home_remove"])
        self.assertEqual(ctx.state.steps["connection"]["undo"][0]["id"], 500)
        # firewall: nothing to open at home
        self.assertTrue(_common.relay_mode(ctx))
        self.assertEqual(firewall.STEP.ports(ctx), ())

        # a second run is a no-op (verify passes), no second server
        ctx2, r2 = self.run_paid()
        self.assertTrue(r2.ok, r2)
        self.assertEqual(len(self.do.droplets), 1)

        self.events.clear()
        ctx3 = self.ctx({})
        rb = Engine([network_probe.STEP, connection.STEP], ctx3).rollback()
        self.assertTrue(rb.ok, rb)
        stop = self.index(lambda e: e[0] == "run" and "disable" in e[1] and "porch-relay.service" in e[1])
        delete = self.index(lambda e: e == ("http", "DELETE", "/droplets/500"))
        self.assertGreaterEqual(stop, 0)
        self.assertGreater(delete, stop)          # home frpc stops before the relay goes
        self.assertEqual(self.do.droplets, {})
        self.assertFalse(os.path.exists(frpc))
        self.assertIsNone(ctx3.state.connection["active"])

    def test_declined_creates_nothing(self):
        ctx, r = self.run_paid(confirms=False)
        self.assertFalse(r.ok)
        self.assertEqual(r.error["code"], "connect.paid.not_confirmed")
        self.assertFalse([e for e in self.events if e[:2] == ("http", "POST")])
        self.assertEqual(ctx.state.steps["connection"]["undo"], [])

    def test_missing_token_is_a_missing_flag(self):
        ctx = self.ctx({"connection": "paid"})
        r = Engine([network_probe.STEP, connection.STEP], ctx).run()
        self.assertEqual(r.exit_code, EXIT_USAGE)
        self.assertIn("--relay-token-ref", r.missing)

    def test_setup_has_relay_flags(self):
        p = cli.setup_parser(registry.steps())
        a = p.parse_args(["--connection", "paid", "--relay-provider", "vultr", "--relay-token-ref",
                          "inf://prod/x/Y", "--relay-host", "ubuntu@1.2.3.4", "--relay-tag", "porch-e2e"])
        self.assertEqual(a.in_relay_provider, "vultr")
        self.assertEqual(a.in_relay_token_ref, "inf://prod/x/Y")
        self.assertEqual(a.in_relay_host, "ubuntu@1.2.3.4")

    def test_never_deletes_an_untagged_server(self):
        ctx, r = self.run_paid()
        self.assertTrue(r.ok, r)
        self.do.droplets[500]["tags"] = ["someone-else"]
        rb = Engine([network_probe.STEP, connection.STEP], self.ctx({})).rollback()
        self.assertFalse(rb.ok)
        self.assertEqual(rb.error["code"], "connect.paid.untagged")
        self.assertIn(500, self.do.droplets)

    def test_crash_mid_create_deletes_by_name_and_tag_only(self):
        ctx = self.ctx({"connection": "paid", "relay_token": TOKEN})
        Engine([network_probe.STEP], ctx).run()
        # an entry written before the create call, then a crash
        ctx.step_id = "connection"
        entry = paid_mod.MODE.record_undo(ctx, "relay.server_delete", provider="digitalocean",
                                          name="porch-relay-dead", tag="porch-relay", id=None)
        ctx.step_id = None
        ctx.state.secret_refs["relay_token"] = "file://" + self.tmp + "/s/relay_token"
        ctx.secrets.put(ctx.state.secret_refs["relay_token"], TOKEN)
        ctx.state.steps["connection"]["status"] = "failed"
        ctx.state.save()
        self.do.droplets[900] = {"id": 900, "name": "porch-relay-dead", "status": "active",
                                 "tags": ["porch-relay"], "networks": {"v4": []}}
        self.do.droplets[901] = {"id": 901, "name": "porch-relay-other", "status": "active",
                                 "tags": ["porch-relay"], "networks": {"v4": []}}
        rb = Engine([network_probe.STEP, connection.STEP], self.ctx({})).rollback()
        self.assertTrue(rb.ok, rb)
        self.assertEqual(sorted(self.do.droplets), [901])
        self.assertTrue(entry)

    def test_switch_to_direct_tears_the_relay_down(self):
        ctx, r = self.run_paid()
        self.assertTrue(r.ok, r)
        self.facts = dict(CGNAT, host_public_ipv4=["51.15.20.7"], public_ipv4="51.15.20.7", cgnat=False)
        ctx2 = self.ctx({"connection": "direct"})
        ctx2.refresh_network = True
        r2 = Engine([network_probe.STEP, connection.STEP], ctx2).run()
        self.assertTrue(r2.ok, r2)
        self.assertEqual(self.do.droplets, {})
        self.assertEqual(ctx2.state.steps["connection"]["undo"], [])
        self.assertFalse(_common.relay_mode(ctx2))

    def test_verify_reports_dead_proxies(self):
        ctx, r = self.run_paid()
        self.assertTrue(r.ok, r)
        ctx2 = make_context(io=NullIO(), **self.kw(http=admin_api({"porch-relay-http": "running",
                                                                  "porch-relay-https": "start error"})))
        checks = {c.code: c for c in paid_mod.MODE.verify(ctx2, CGNAT, ctx2.outputs("connection"))}
        self.assertFalse(checks["connect.relay.proxies"].ok)
        self.assertIn("https=start error", checks["connect.relay.proxies"].message)
        self.control_up = False
        checks = {c.code: c for c in paid_mod.MODE.verify(ctx2, CGNAT, ctx2.outputs("connection"))}
        self.assertFalse(checks["connect.relay.control"].ok)


# ---- byo / oracle ----------------------------------------------------------------------------

class ByoTest(Base):
    def run_byo(self, mode="byo", **answers):
        ctx = self.ctx({"connection": mode, "relay_host": "ubuntu@" + RELAY_IP,
                        "relay_ssh_key": "~/.ssh/relay", **answers})
        return ctx, Engine([network_probe.STEP, connection.STEP], ctx).run()

    def ssh_calls(self):
        return [(i, e) for i, e in enumerate(self.events) if e[0] == "run" and e[1][0] == "ssh"]

    def test_install_over_ssh_and_rollback_never_deletes_the_server(self):
        ctx, r = self.run_byo()
        self.assertTrue(r.ok, r)
        out = ctx.outputs("connection")
        self.assertEqual((out["ingress_ipv4"], out["relay"]["target"]), (RELAY_IP, "ubuntu@" + RELAY_IP))
        (i, call), = self.ssh_calls()
        argv = call[1]
        self.assertEqual(argv[-2:], ("ubuntu@" + RELAY_IP, "sudo -n bash -s"))
        self.assertIn(os.path.expanduser("~/.ssh/relay"), argv)
        script = self.runner.inputs[[c["argv"][0] for c in self.runner.calls].index("ssh")]
        token = re.search(r'auth.token = "([^"]+)"', script).group(1)
        self.assertNotIn(token, " ".join(argv))          # the token only travels on stdin
        self.assertIn("MODE=byo", script)
        undo = [u["kind"] for u in ctx.state.steps["connection"]["undo"]]
        self.assertEqual(undo, ["relay.ssh_uninstall", "relay.home_remove"])

        self.events.clear()
        rb = Engine([network_probe.STEP, connection.STEP], self.ctx({})).rollback()
        self.assertTrue(rb.ok, rb)
        (j, call), = self.ssh_calls()
        stop = self.index(lambda e: e[0] == "run" and "disable" in e[1])
        self.assertLess(stop, j)
        uninstall = self.runner.inputs[-1] if self.runner.calls[-1]["argv"][0] == "ssh" else \
            [self.runner.inputs[k] for k, c in enumerate(self.runner.calls) if c["argv"][0] == "ssh"][-1]
        self.assertIn("/etc/porch-relay/installed", uninstall)
        self.assertNotIn("PORCH_RELAY_OK", uninstall)
        # no provider API, nothing that powers off or deletes the machine
        self.assertEqual([e for e in self.events if e[0] == "http"], [])
        for bad in ("shutdown", "poweroff", "halt", "rm -rf /\n"):
            self.assertNotIn(bad, uninstall)

    def test_sudo_failure_hint(self):
        self.ssh_ok = False
        ctx, r = self.run_byo()
        self.assertFalse(r.ok)
        self.assertEqual(r.error["code"], "connect.byo.install")
        self.assertIn("passwordless sudo", r.error["hint"])
        # recorded before running, so a rollback still cleans up
        self.assertEqual([u["kind"] for u in ctx.state.steps["connection"]["undo"]], ["relay.ssh_uninstall"])

    def test_bad_target_is_rejected(self):
        ctx = self.ctx({"connection": "byo", "relay_host": "root@host; rm -rf /"})
        r = Engine([network_probe.STEP, connection.STEP], ctx).run()
        self.assertEqual(r.exit_code, EXIT_USAGE)
        self.assertEqual(self.ssh_calls(), [])

    def test_oracle_is_byo_with_a_guide(self):
        ctx, r = self.run_byo("oracle")
        self.assertTrue(r.ok, r)
        self.assertEqual(ctx.state.steps["connection"]["undo"][0]["mode"], "oracle")
        self.assertIn("MODE=oracle", self.runner.inputs[[c["argv"][0] for c in self.runner.calls].index("ssh")])
        rb = Engine([network_probe.STEP, connection.STEP], self.ctx({})).rollback()
        self.assertTrue(rb.ok, rb)

    def test_oracle_without_host_prints_the_guide(self):
        out, err = stdio.StringIO(), stdio.StringIO()
        with contextlib.redirect_stderr(err):
            rc = cmd_connect.main(["oracle"], out=out, env=self.env, ctx_kwargs={
                k: v for k, v in self.kw().items() if k != "env"})
        self.assertEqual(rc, EXIT_USAGE)
        self.assertIn("Security Lists", out.getvalue())
        self.assertIn("7835", out.getvalue())
        self.assertEqual(self.events, [])


# ---- porch connect ---------------------------------------------------------------------------

class CmdConnectRelayTest(Base):
    def main(self, argv, io=None):
        out, err = stdio.StringIO(), stdio.StringIO()
        with contextlib.redirect_stderr(err):
            rc = cmd_connect.main(argv, io=io, out=out, env=self.env,
                                  ctx_kwargs={k: v for k, v in self.kw().items() if k != "env"})
        return rc, out.getvalue(), err.getvalue()

    def test_paid_status_and_off(self):
        rc, out, err = self.main(["paid", "--token-ref", "file://" + self.tmp + "/s/do", "--yes"],
                                 io=NullIO({"connection": "paid", "relay_token": TOKEN}, confirms=True))
        self.assertEqual(rc, 0, err)
        self.assertIn(f"connection: paid (ingress {RELAY_IP}", out)
        rc, out, err = self.main(["--status", "--no-probe"])
        self.assertEqual(rc, 0, err)
        self.assertIn(f"relay: digitalocean {RELAY_IP} (server 500, s-1vcpu-512mb-10gb in nyc1, 4.00 USD/month)", out)
        self.assertIn("relay proxies: http=running, https=running, frp=running", out)
        # --off needs a yes when unattended
        rc, out, err = self.main(["--off"], io=NullIO(confirms=False))
        self.assertEqual(rc, EXIT_USAGE)
        self.assertIn(500, self.do.droplets)
        rc, out, err = self.main(["--off", "--yes"], io=NullIO(confirms=False))
        self.assertEqual(rc, 0, err)
        self.assertIn("digitalocean server 500", out)
        self.assertIn("connection: off", out)
        self.assertEqual(self.do.droplets, {})

    def test_relay_flags_only_with_relay_modes(self):
        rc, _, err = self.main(["upnp", "--provider", "vultr", "--yes"])
        self.assertEqual(rc, EXIT_USAGE)
        self.assertIn("only go with", err)

    def test_answers_mapping(self):
        a = cmd_connect._parser().parse_args(["byo", "ubuntu@1.2.3.4", "--ssh-key", "k"])
        self.assertEqual(cmd_connect._answers(a), {"connection": "byo", "relay_host": "ubuntu@1.2.3.4",
                                                   "relay_ssh_key": "k"})
        a = cmd_connect._parser().parse_args(["paid", "--provider", "vultr", "--token-ref", "inf://a/b/C",
                                              "--region", "ewr", "--tag", "porch-e2e"])
        self.assertEqual(cmd_connect._answers(a), {"connection": "paid", "relay_provider": "vultr",
                                                   "relay_token": "inf://a/b/C", "relay_region": "ewr",
                                                   "relay_tag": "porch-e2e"})


class WebCardsTest(Base):
    def test_relay_cards_are_selectable(self):
        from porch_setup import webio
        ctx = self.ctx({})
        ctx.state.facts["network"] = CGNAT
        cards = {c["name"]: c for c in webio._connection_cards(ctx)}
        for n in ("paid", "oracle", "byo"):
            self.assertTrue(cards[n]["built"], n)
            self.assertNotIn(cards[n]["status"], ("unavailable", "later"), n)
        self.assertTrue(cards["paid"]["recommended"])
        self.assertEqual(cards["ipv6"]["status"], "later")


if __name__ == "__main__":
    unittest.main()

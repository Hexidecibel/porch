"""bin/porch-e2e (lib/porch_e2e.py): the pure parts, with a fake DO API and a
fake ssh runner. Nothing here talks to DigitalOcean or any host."""

import io
import contextlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import porch_e2e as e2e  # noqa: E402

# Built at run time: a literal would be in the git archive the test uploads.
TOKEN = "dop_v1_FAKE-" + os.urandom(12).hex()


def droplet(did, ip="203.0.113.7", tags=("porch-e2e",), status="active",
            created="2026-10-19T00:00:00Z"):
    return {"id": did, "name": f"porch-e2e-{did}", "status": status, "tags": list(tags),
            "created_at": created, "size_slug": "s-1vcpu-1gb",
            "size": {"price_hourly": 0.00893}, "region": {"slug": "nyc3"},
            "networks": {"v4": [{"type": "private", "ip_address": "10.0.0.2"},
                                {"type": "public", "ip_address": ip}]}}


class FakeDO:
    def __init__(self, droplets=()):
        self.droplets = list(droplets)
        self.calls = []
        self.keys = {}
        self.regions = ["nyc3", "tor1"]
        self.fail_create = False
        self.firewalls = []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, headers, body))
        assert headers["Authorization"] == f"Bearer {TOKEN}"
        path = url[len(e2e.API):]
        js = json.loads(body) if body else None
        if method == "GET" and path.startswith("/droplets?tag_name="):
            return 200, json.dumps({"droplets": self.droplets}).encode()
        if method == "GET" and path.startswith("/droplets/"):
            did = int(path.rsplit("/", 1)[1])
            return 200, json.dumps({"droplet": next(d for d in self.droplets if d["id"] == did)}).encode()
        if method == "POST" and path == "/account/keys":
            self.keys[77] = js
            return 201, json.dumps({"ssh_key": {"id": 77, "name": js["name"]}}).encode()
        if method == "POST" and path == "/droplets" and self.fail_create:
            return 422, b'{"message": "Size is not available in this region."}'
        if method == "POST" and path == "/droplets":
            self.created_region = js["region"]
            did = 4242 if all(x["id"] != 4242 for x in self.droplets) else 6161   # 6161: a byo server
            d = droplet(did, ip="203.0.113.7" if did == 4242 else "203.0.113.99")
            d["name"] = js["name"]
            d["tags"] = js["tags"]
            self.droplets.append(d)
            return 202, json.dumps({"droplet": dict(d, status="new", networks={})}).encode()
        if method == "DELETE" and path.startswith("/droplets?tag_name="):
            self.droplets = []
            return 204, b""
        if method == "DELETE" and path.startswith("/account/keys/"):
            return 204, b""
        if method == "GET" and path.startswith("/sizes"):
            return 200, json.dumps({"sizes": [{"slug": "s-1vcpu-1gb", "available": True,
                                               "regions": self.regions}]}).encode()
        if method == "GET" and path.startswith("/account/keys"):
            return 200, b'{"ssh_keys": []}'
        if method == "GET" and path.startswith("/firewalls"):
            return 200, json.dumps({"firewalls": self.firewalls + [{"id": "aaaa-other", "name": "prod-web"}]}).encode()
        if method == "POST" and path == "/firewalls":
            fw = dict(js, id="0f0f0f0f-1111")
            self.firewalls.append(fw)
            return 202, json.dumps({"firewall": fw}).encode()
        if method == "DELETE" and path.startswith("/firewalls/"):
            fid = path.rsplit("/", 1)[1]
            self.firewalls = [f for f in self.firewalls if f["id"] != fid]
            return 204, b""
        return 404, b'{"message": "not found"}'


WIZ_LOG = (b"Requesting a Let's Encrypt certificate for 203.0.113.7 ...\n\nPorch setup wizard\n"
           b"(staging certificate: your browser will warn)\nOpen this link (it works once; keep it private):\n"
           b"    https://203.0.113.7/#k=AbC_d-123\n")


class FakeRun:
    def __init__(self, log=WIZ_LOG):
        self.calls = []
        self.log = log

    def __call__(self, argv, input=None, capture_output=False, timeout=None, check=False, **kw):
        self.calls.append((argv, input))
        if argv[0] == "ssh-keygen":
            key = argv[argv.index("-f") + 1]
            with open(key, "w") as f:
                f.write("PRIVATE")
            with open(key + ".pub", "w") as f:
                f.write("ssh-ed25519 AAAAfake porch-e2e")
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        out = b"ok\n"
        if argv[0] == "ssh" and argv[-1].startswith("cat "):
            out = self.log
        return subprocess.CompletedProcess(argv, 0, out, b"")


class FakeResolver:
    """Authoritative answers: the porch hosts resolve for the first
    `leftover_polls` rounds, then nothing."""
    def __init__(self, leftover_polls):
        self.left = leftover_polls
        self.asked = []
        self._round_names = set()

    def zone_apex(self, name):
        return "cjc1.com"

    def authoritative(self, name, rtype, zone=None):
        if name in self._round_names and name == "auth.cjc1.com" and rtype == "A":
            self.left -= 1          # a new polling round started
            self._round_names = set()
        self._round_names.add(name)
        self.asked.append((name, rtype))
        hit = self.left > 0 and rtype == "A" and name in ("auth.cjc1.com", "tunnel.cjc1.com")
        return {"173.245.58.1": ["203.0.113.7"] if hit else [], "172.64.33.1": []}


class FakeCF:
    def __init__(self, recs):
        from porch_setup.dns.base import Record
        self.recs = [Record(n, t, "203.0.113.7") for n, t in recs] + [Record("cjc1.com", "A", "192.0.2.1")]

    def list(self, zone):
        return list(self.recs)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.dir = os.path.join(self.tmp, "e2e")
        self.out, self.err = io.StringIO(), io.StringIO()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def main(self, argv, fake, run=None, inp=lambda _: "no", **kw):
        return e2e.main(argv, env={"PORCH_E2E_DIR": self.dir}, http=fake,
                        run=run or FakeRun(), token_reader=kw.pop("token_reader", lambda ref: TOKEN),
                        out=self.out, err=self.err, sleep=lambda s: None,
                        clock=lambda: 1_760_000_000, inp=inp, **kw)


class TestApi(Base):
    def test_create_request_shape(self):
        fake = FakeDO()
        do = e2e.DO(TOKEN, http=fake)
        do.create_droplet("porch-e2e-x", "nyc3", "s-1vcpu-1gb", 77)
        method, url, headers, body = fake.calls[-1]
        self.assertEqual((method, url), ("POST", e2e.API + "/droplets"))
        b = json.loads(body)
        self.assertEqual(b["tags"], ["porch-e2e"])
        self.assertEqual(b["image"], "ubuntu-24-04-x64")
        self.assertEqual(b["ssh_keys"], [77])
        self.assertEqual(headers["Content-Type"], "application/json")

    def test_image_option(self):
        fake = FakeDO()
        e2e.DO(TOKEN, http=fake).create_droplet("porch-e2e-x", "nyc3", "s-1vcpu-1gb", 77,
                                                image="debian-13-x64")
        self.assertEqual(json.loads(fake.calls[-1][3])["image"], "debian-13-x64")
        a = e2e.parser().parse_args(["up", "--installer", "--image", "debian-13-x64"])
        self.assertEqual(a.image, "debian-13-x64")
        self.assertEqual(e2e.parser().parse_args(["up"]).image, e2e.IMAGE)
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            e2e.parser().parse_args(["up", "--image", "../x; rm"])

    def test_tag_filter_drops_untagged(self):
        fake = FakeDO([droplet(1), droplet(2, tags=("prod",)), droplet(3, tags=())])
        self.assertEqual([d["id"] for d in e2e.DO(TOKEN, http=fake).droplets()], [1])

    def test_delete_is_by_tag(self):
        fake = FakeDO([droplet(1)])
        e2e.DO(TOKEN, http=fake).delete_tagged()
        self.assertEqual(fake.calls[-1][:2], ("DELETE", e2e.API + "/droplets?tag_name=porch-e2e"))
        with self.assertRaises(e2e.E2EError):
            e2e.DO(TOKEN, http=fake).delete_tagged("")

    def test_error_redacts_token(self):
        do = e2e.DO(TOKEN, http=lambda *a: (401, f"bad {TOKEN}".encode()))
        with self.assertRaises(e2e.E2EError) as cm:
            do.droplets()
        self.assertNotIn(TOKEN, str(cm.exception))

    def test_cost(self):
        hours, cost = e2e.est_cost(droplet(1, created="2026-10-19T00:00:00Z"),
                                   e2e.parse_ts("2026-10-19T02:00:00Z"))
        self.assertAlmostEqual(hours, 2.0)
        self.assertAlmostEqual(cost, 0.01786)


class TestLog(unittest.TestCase):
    def test_ip_cert(self):
        i = e2e.parse_wizard_log(WIZ_LOG.decode())
        self.assertEqual(i["url"], "https://203.0.113.7/#k=AbC_d-123")
        self.assertTrue(i["staging"])
        self.assertIsNone(i["fingerprint"])

    def test_fallback(self):
        text = ("porch setup --web: IP certificate failed: boom (hint)\n"
                "Falling back to a self-signed certificate.\n"
                "Open this link\n    https://203.0.113.7/#k=zz\n"
                "fingerprint is exactly:\n    AA:BB:CC\n")
        i = e2e.parse_wizard_log(text)
        self.assertTrue(i["fell_back"])
        self.assertEqual(i["fingerprint"], "AA:BB:CC")
        self.assertIn("boom", i["ip_cert_error"])

    def test_start_cmd_uses_sudo_and_staging(self):
        c = e2e.wizard_start_cmd()
        self.assertIn("/usr/bin/sudo -n /home/porch/porch/bin/porch setup --web --staging", c)
        self.assertIn("--uid=porch", c)


class TestCommands(Base):
    def test_up_refuses_when_droplet_exists(self):
        fake = FakeDO([droplet(9)])
        self.assertEqual(self.main(["up"], fake), 1)
        self.assertIn("already exists", self.err.getvalue())
        self.assertFalse(any(c[0] == "POST" for c in fake.calls))

    def test_up_refuses_on_stale_state(self):
        os.makedirs(self.dir)
        e2e.save_state(self.dir, {"droplet_id": 5})
        fake = FakeDO()
        self.assertEqual(self.main(["up"], fake), 1)
        self.assertIn("stale state", self.err.getvalue())

    def test_up_full_never_leaks_token(self):
        fake, run = FakeDO(), FakeRun()
        self.assertEqual(self.main(["up"], fake, run=run), 0, self.err.getvalue())
        self.assertIn("WIZARD URL: https://203.0.113.7/#k=AbC_d-123", self.out.getvalue())
        st = e2e.load_state(self.dir)
        self.assertEqual((st["droplet_id"], st["ip"], st["key_id"]), (4242, "203.0.113.7", 77))
        for name in os.listdir(self.dir):
            with open(os.path.join(self.dir, name), "rb") as f:
                self.assertNotIn(TOKEN.encode(), f.read(), name)
            self.assertEqual(os.stat(os.path.join(self.dir, name)).st_mode & 0o077, 0, name)
        self.assertEqual(os.stat(self.dir).st_mode & 0o777, 0o700)
        self.assertNotIn(TOKEN, self.out.getvalue() + self.err.getvalue())
        for argv, inp in run.calls:
            self.assertNotIn(TOKEN, " ".join(argv))
            if inp:
                self.assertNotIn(TOKEN.encode(), inp)
        # nothing secret-ish shipped: the upload is a git archive of tracked files
        uploads = [inp for argv, inp in run.calls if argv[-1].endswith(f"tar -x -C {e2e.REMOTE_REPO}")]
        self.assertEqual(len(uploads), 1)
        import tarfile
        names = set(tarfile.open(fileobj=io.BytesIO(uploads[0])).getnames())
        self.assertIn("bin/porch", names)
        for bad in ("data/devices.json", "config/porch.toml", "config/frps.toml",
                    "config/frpc.toml", ".env"):
            self.assertNotIn(bad, names)
        # ... plus the file manifest (no .git on the droplet), matching that archive
        mans = [inp for argv, inp in run.calls if argv[-1].endswith("share/porch-files.txt")]
        self.assertEqual(len(mans), 1)
        listed = set(mans[0].decode().split())
        self.assertIn("share/porch-files.txt", listed)
        self.assertIn("bin/porch", listed)
        self.assertLessEqual(listed - {"share/porch-files.txt"}, names)
        self.assertNotIn("data/devices.json", listed)

    def test_prefill_passed_to_wizard_and_kept(self):
        fake, run = FakeDO(), FakeRun()
        self.assertEqual(self.main(["up", "--domain", "CJC1.com", "--dns-provider", "cloudflare"],
                                   fake, run=run), 0, self.err.getvalue())
        starts = [a[-1] for a, _ in run.calls if "systemd-run" in a[-1]]
        self.assertIn("--web --staging --no-qr --domain cjc1.com --dns-provider cloudflare", starts[0])
        st = e2e.load_state(self.dir)
        self.assertEqual(st["prefill"], {"domain": "cjc1.com", "dns_provider": "cloudflare"})
        run2 = FakeRun()
        self.assertEqual(self.main(["up", "--redeploy"], fake, run=run2), 0, self.err.getvalue())
        starts = [a[-1] for a, _ in run2.calls if "systemd-run" in a[-1]]
        self.assertIn("--domain cjc1.com --dns-provider cloudflare", starts[0])

    def test_bad_prefill_refused_before_anything(self):
        fake = FakeDO()
        self.assertEqual(self.main(["up", "--domain", "x; rm -rf /"], fake), 1)
        self.assertFalse(any(c[0] == "POST" for c in fake.calls))

    def test_region_fallback(self):
        self.assertEqual(e2e.pick_region("nyc3", ["sfo2", "tor1"]), "tor1")
        self.assertEqual(e2e.pick_region("lon1", ["lon1", "tor1"]), "lon1")
        self.assertIsNone(e2e.pick_region("nyc3", []))
        fake = FakeDO()
        fake.regions = ["sfo2", "tor1"]
        self.assertEqual(self.main(["up"], fake), 0, self.err.getvalue())
        self.assertEqual(fake.created_region, "tor1")

    def test_create_failure_removes_key_and_state(self):
        fake = FakeDO()
        fake.fail_create = True
        self.assertEqual(self.main(["up"], fake), 1)
        self.assertIn(("DELETE", e2e.API + "/account/keys/77"), [c[:2] for c in fake.calls])
        self.assertIsNone(e2e.load_state(self.dir))

    def test_down_needs_confirm_then_deletes_by_tag(self):
        os.makedirs(self.dir)
        e2e.save_state(self.dir, {"droplet_id": 9, "ip": "203.0.113.7", "key_id": 77})
        fake = FakeDO([droplet(9)])
        self.assertEqual(self.main(["down"], fake), 6)
        self.assertTrue(fake.droplets)
        run = FakeRun()
        self.assertEqual(self.main(["down", "--yes"], fake, run=run), 0)
        self.assertFalse(fake.droplets)
        self.assertIn(("DELETE", e2e.API + "/account/keys/77"), [c[:2] for c in fake.calls])
        self.assertIsNone(e2e.load_state(self.dir))
        self.assertTrue(any("--rollback --non-interactive" in a[-1] for a, _ in run.calls))
        self.assertNotIn(TOKEN, self.out.getvalue() + self.err.getvalue())

    # -- down: DNS must be clean afterwards --
    def _down_with_dns(self, resolver, provider=None, cfg=None):
        os.makedirs(self.dir, exist_ok=True)
        e2e.save_state(self.dir, {"droplet_id": 9, "ip": "203.0.113.7", "key_id": 77,
                                  "prefill": {"domain": "cjc1.com", "dns_provider": "cloudflare"}})
        fake = FakeDO([droplet(9)])
        run = FakeRun()
        cfg_json = json.dumps({"domain": cfg or {"root": "cjc1.com", "auth_host": "auth.cjc1.com",
                                                 "panel_host": "panel.cjc1.com",
                                                 "landing_host": "tunnel.cjc1.com",
                                                 "tunnel_base": "tunnel.cjc1.com"}}).encode()
        real = run.__call__

        def runner(argv, **kw):
            if argv[0] == "ssh" and "porch_config.py dump" in argv[-1]:
                run.calls.append((argv, None))
                return subprocess.CompletedProcess(argv, 0, cfg_json, b"")
            return real(argv, **kw)
        t = [1_760_000_000]

        def sleep(sec):
            t[0] += sec
        rc = e2e.main(["down", "--yes"], env={"PORCH_E2E_DIR": self.dir}, http=fake, run=runner,
                      token_reader=lambda ref: TOKEN, out=self.out, err=self.err, sleep=sleep,
                      clock=lambda: t[0], resolver=resolver, dns_provider=provider)
        return rc, fake, run

    def test_down_dns_clean_after_polling(self):
        res = FakeResolver(leftover_polls=2)
        rc, fake, run = self._down_with_dns(res, provider=lambda tok: FakeCF([]))
        self.assertEqual(rc, 0, self.out.getvalue())
        self.assertFalse(fake.droplets)
        out = self.out.getvalue()
        self.assertIn("DNS clean", out)
        self.assertIn("Cloudflare: no porch A/AAAA/CNAME records left", out)
        asked = {n for n, _ in res.asked}
        for h in ("auth.cjc1.com", "panel.cjc1.com", "tunnel.cjc1.com", "auth.porch.cjc1.com"):
            self.assertIn(h, asked)
        self.assertTrue(any(n.endswith(".tunnel.cjc1.com") and n.startswith("porch-e2e-") for n in asked))
        self.assertNotIn("cjc1.com", asked)        # never the apex
        # read the hosts before the rollback removed porch.toml
        cmds = [a[-1] for a, _ in run.calls if a[0] == "ssh"]
        self.assertLess(next(i for i, c in enumerate(cmds) if "porch_config.py dump" in c),
                        next(i for i, c in enumerate(cmds) if "--rollback" in c))

    def test_down_reports_leftover_records_and_still_deletes(self):
        rc, fake, _ = self._down_with_dns(FakeResolver(leftover_polls=10**6),
                                          provider=lambda tok: FakeCF([("*.tunnel.cjc1.com", "A")]))
        out = self.out.getvalue()
        self.assertEqual(rc, 3, out)
        self.assertFalse(fake.droplets)
        self.assertIn("still published: auth.cjc1.com A -> 203.0.113.7", out)
        self.assertIn("Cloudflare still has: *.tunnel.cjc1.com A", out)

    def test_down_cloudflare_error_never_prints_token(self):
        def boom(tok):
            raise RuntimeError(f"401 for Bearer {tok}")
        rc, _, _ = self._down_with_dns(FakeResolver(0), provider=boom)
        self.assertEqual(rc, 0)
        self.assertIn("Cloudflare check skipped", self.out.getvalue())
        self.assertNotIn(TOKEN, self.out.getvalue() + self.err.getvalue())

    def test_wizard_start_waits_for_the_port(self):
        c = e2e.wizard_start_cmd()
        self.assertIn("sport = :8443", c)
        self.assertLess(c.index("sport = :8443"), c.index("systemd-run"))

    def test_log_domain_cert(self):
        i = e2e.parse_wizard_log("Setup has a domain certificate: serving it as auth.cjc1.com\n"
                                 "    https://auth.cjc1.com:8443/#k=abc\n")
        self.assertTrue(i["domain_cert"])
        self.assertEqual(i["url"], "https://auth.cjc1.com:8443/#k=abc")

    def test_ssh_runs_remote_command(self):
        os.makedirs(self.dir)
        e2e.save_state(self.dir, {"droplet_id": 9, "ip": "203.0.113.7"})
        run = FakeRun()
        self.assertEqual(self.main(["ssh", "systemctl", "is-active", "x"], FakeDO([droplet(9)]),
                                   run=run), 0)
        argv = run.calls[-1][0]
        self.assertEqual(argv[-2:], ["porch@203.0.113.7", "systemctl is-active x"])

    def test_ssh_refuses_untagged_state(self):
        os.makedirs(self.dir)
        e2e.save_state(self.dir, {"droplet_id": 9, "ip": "203.0.113.7"})
        run = FakeRun()
        self.assertEqual(self.main(["logs"], FakeDO([droplet(9, tags=("prod",))]), run=run), 1)
        self.assertFalse(any(a[0] == "ssh" for a, _ in run.calls))


CF = "cf-FAKE-" + os.urandom(8).hex()
SETUP_LOG = [b"==> preflight: Preflight\n", b"  done\n", b"porch setup: ok\n"]


def steps_json(n_done=14, failed=None):
    steps = [{"id": f"s{i}", "status": "done", "error": None} for i in range(n_done)]
    if failed:
        steps.append({"id": failed, "status": "failed", "error": {"code": "x.y", "message": "boom " + CF}})
    return json.dumps({"steps": steps}).encode()


class FakePopen:
    """ssh streaming: records argv + stdin, replays `lines`, exits `rc`."""
    def __init__(self, lines=SETUP_LOG, rc=0):
        self.lines, self.rc, self.calls = lines, rc, []

    def __call__(self, argv, stdin=None, stdout=None, stderr=None):
        rec = {"argv": argv, "stdin": b""}
        self.calls.append(rec)
        outer = self

        class P:
            class _In:
                def write(self, b):
                    rec["stdin"] += b

                def close(self):
                    pass
            stdin = _In()
            stdout = iter(outer.lines)

            def wait(self, timeout=None):
                return outer.rc
        return P()


class RelayRun(FakeRun):
    """ssh + curl for relay-test."""
    def __init__(self, steps=None, me="198.51.100.77"):
        super().__init__()
        self.steps = steps or steps_json()
        self.me = me
        self.served = ""

    def __call__(self, argv, input=None, capture_output=False, timeout=None, check=False, **kw):
        if argv[0] == "curl":
            self.calls.append((argv, input))
            url = argv[-1]
            if "ipify" in url:
                return subprocess.CompletedProcess(argv, 0, f"{self.me}\n200".encode(), b"")
            code = (("/auth/admin/login", 401), ("://panel.", 403), ("://porch-e2e-", 404))
            c = next((v for k, v in code if k in url), 200)
            body = self.served if "://e2erelay." in url else ""
            return subprocess.CompletedProcess(argv, 0, f"{body}\n{c}".encode(), b"")
        if argv[0] == "ssh" and "/tmp/e2erelay/index.html" in argv[-1]:
            import re as _re
            self.served = _re.search(r"echo (porch-relay-[0-9a-f]+)", argv[-1]).group(1)
        if argv[0] == "ssh" and "--status --json" in argv[-1]:
            self.calls.append((argv, input))
            return subprocess.CompletedProcess(argv, 0, self.steps, b"")
        if argv[0] == "ssh" and "journalctl" in argv[-1]:
            self.calls.append((argv, input))
            return subprocess.CompletedProcess(argv, 0, f"admin login failed ip={self.me}\n".encode(), b"")
        if argv[0] == "ssh" and "connect --status" in argv[-1]:
            self.calls.append((argv, input))
            return subprocess.CompletedProcess(argv, 0, b"active: paid\nrelay: digitalocean 203.0.113.99\n"
                                               b"  [ok  ] relay proxies: http=running, https=running, frp=running\n", b"")
        if argv[0] == "ssh" and "echo dir=" in argv[-1]:
            self.calls.append((argv, input))
            return subprocess.CompletedProcess(argv, 0, b"dir=gone\nunit=inactive\niptables=0\nsaved=0\n"
                                               b"reject=1\n", b"")
        if argv[0] == "ssh" and "ss -Hltn" in argv[-1]:
            self.calls.append((argv, input))
            return subprocess.CompletedProcess(argv, 0, b"LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\n", b"")
        return super().__call__(argv, input=input, capture_output=capture_output, timeout=timeout, check=check)


class FakeA:
    """authoritative A answers for relay-test's DNS check, plus clean after teardown."""
    def __init__(self, ip):
        self.ip, self.clean = ip, False

    def zone_apex(self, name):
        return "cjc1.com"

    def authoritative(self, name, rtype, zone=None):
        if self.clean or rtype != "A" or name != "auth.cjc1.com":
            return {"173.245.58.1": []}
        return {"173.245.58.1": [self.ip], "172.64.33.1": [self.ip]}


class TestCliAndRelay(Base):
    def reader(self, ref):
        return CF if "CLOUDFLARE" in ref else TOKEN

    def test_up_cli_streams_and_keeps_secrets_off_argv(self):
        fake, run, pop = FakeDO(), RelayRun(), FakePopen()
        rc = self.main(["up", "--cli", "--domain", "cjc1.com", "--dns-provider", "cloudflare"], fake,
                       run=run, popen=pop, token_reader=self.reader)
        self.assertEqual(rc, 0, self.out.getvalue() + self.err.getvalue())
        (call,) = pop.calls
        cmd = call["argv"][-1]
        self.assertIn("bin/porch setup --non-interactive --yes --domain cjc1.com --apex --connection direct "
                      "--dns-provider cloudflare --no-acme-staging", cmd)
        self.assertNotIn(CF, " ".join(call["argv"]))
        self.assertTrue(call["stdin"].startswith(CF.encode() + b"\n"))
        self.assertEqual(len(call["stdin"].split(b"\n")), 3)          # token, password, ""
        self.assertIn("  | porch setup: ok", self.out.getvalue())
        self.assertIn("14/14 steps done", self.out.getvalue())
        self.assertNotIn(CF, self.out.getvalue() + self.err.getvalue())
        self.assertNotIn(call["stdin"].split(b"\n")[1].decode(), self.out.getvalue())
        st = e2e.load_state(self.dir)
        self.assertEqual(st["results"]["setup"]["done"], 14)
        self.assertFalse(any("systemd-run" in a[-1] for a, _ in run.calls))   # no wizard

    def test_up_cli_fails_on_a_failed_step(self):
        fake, pop = FakeDO(), FakePopen(rc=4)
        run = RelayRun(steps=steps_json(9, failed="certificate"))
        rc = self.main(["up", "--cli", "--domain", "cjc1.com", "--dns-provider", "cloudflare",
                        "--acme-staging"], fake, run=run, popen=pop, token_reader=self.reader)
        self.assertEqual(rc, 1)
        self.assertIn("--acme-staging", pop.calls[0]["argv"][-1])
        self.assertIn("certificate: failed x.y boom <secret>", self.out.getvalue())
        self.assertNotIn(CF, self.out.getvalue())

    def test_up_cli_needs_domain_and_cloudflare(self):
        fake = FakeDO()
        self.assertEqual(self.main(["up", "--cli"], fake), 1)
        self.assertEqual(self.main(["up", "--cli", "--domain", "x.com", "--dns-provider", "namecom"], fake), 1)
        self.assertFalse(any(c[0] == "POST" for c in fake.calls))

    def test_relay_test_end_to_end_with_fakes(self):
        fake, run, pop = FakeDO(), RelayRun(), FakePopen()

        def popen(argv, **kw):
            # porch setup "creates" the relay droplet, tagged porch-e2e
            relay = droplet(5151, ip="203.0.113.99")
            relay["name"] = "porch-relay-abcd1234"
            relay["size_slug"] = "s-1vcpu-512mb-10gb"
            fake.droplets.append(relay)
            return pop(argv, **kw)
        res = FakeA("203.0.113.99")
        app_kw = dict(popen=popen, token_reader=self.reader, resolver=res,
                      dns_provider=lambda tok: FakeCF([]))
        orig = e2e.App.tcp_reachable
        e2e.App.tcp_reachable = staticmethod(lambda ip, port, timeout=6: ip == "203.0.113.99")
        self.addCleanup(setattr, e2e.App, "tcp_reachable", orig)
        fixed = [r for r in run.calls]
        self.assertEqual(fixed, [])

        def run_rb(argv, **kw):
            if argv[0] == "ssh" and "--rollback" in argv[-1]:
                fake.droplets = [d for d in fake.droplets if d["id"] != 5151]   # porch deleted the relay
                res.clean = True
            return run(argv, **kw)
        rc = self.main(["relay-test", "--domain", "cjc1.com", "--dns-provider", "cloudflare"], fake,
                       run=run_rb, **app_kw)
        out = self.out.getvalue()
        self.assertEqual(rc, 0, out + self.err.getvalue())
        cmd = pop.calls[0]["argv"][-1]
        self.assertIn("--connection paid", cmd)
        self.assertIn("--relay-token-ref 'file://~/.config/porch/secrets/do-relay'", cmd)
        self.assertIn("--relay-tag porch-e2e", cmd)
        # the home droplet's cloud firewall takes ssh only, and is deleted at the end
        posted = [json.loads(c[3]) for c in fake.calls if c[:2] == ("POST", e2e.API + "/firewalls")]
        self.assertEqual(posted[0]["inbound_rules"], [{"protocol": "tcp", "ports": "22",
                                                       "sources": {"addresses": ["0.0.0.0/0", "::/0"]}}])
        self.assertEqual(posted[0]["droplet_ids"], [4242])
        self.assertEqual(fake.firewalls, [])
        self.assertNotIn(("DELETE", e2e.API + "/firewalls/aaaa-other"), [c[:2] for c in fake.calls])
        # DO token: written to the droplet over stdin twice (setup, rollback), removed twice
        puts = [(a, i) for a, i in run.calls if a[0] == "ssh" and "do-relay" in a[-1] and a[-1].endswith("do-relay")
                and "cat >" in a[-1]]
        self.assertEqual(len(puts), 2)
        self.assertTrue(all(i == TOKEN.encode() for _, i in puts))
        rms = [a for a, _ in run.calls if a[0] == "ssh" and a[-1].startswith("rm -f ~/.config/porch/secrets/do-relay")]
        self.assertEqual(len(rms), 2)
        for argv, _ in run.calls:
            self.assertNotIn(TOKEN, " ".join(argv))
            self.assertNotIn(CF, " ".join(argv))
        self.assertNotIn(TOKEN, out)
        self.assertNotIn(CF, out)
        self.assertIn("relay checks: 13/13 passed", out)
        self.assertIn("relay droplet 5151: deleted by porch's rollback", out)
        self.assertIn("deleted cloud firewall 0f0f0f0f-1111", out)
        self.assertIn("total est. cost", out)
        self.assertEqual(fake.droplets, [])
        self.assertIsNone(e2e.load_state(self.dir))

    def _relay_env(self, fake, run, delete_on_rollback=None):
        res = FakeA("203.0.113.99")
        orig = e2e.App.tcp_reachable
        e2e.App.tcp_reachable = staticmethod(lambda ip, port, timeout=6: ip == "203.0.113.99")
        self.addCleanup(setattr, e2e.App, "tcp_reachable", orig)

        def run_rb(argv, **kw):
            if argv[0] == "ssh" and "--rollback" in argv[-1]:
                res.clean = True
                if delete_on_rollback:
                    delete_on_rollback()
            return run(argv, **kw)
        return run_rb, dict(token_reader=self.reader, resolver=res, dns_provider=lambda tok: FakeCF([]))

    def test_relay_test_byo_oracle_sim(self):
        fake, run, pop = FakeDO(), RelayRun(), FakePopen()
        run_rb, kw = self._relay_env(fake, run)
        rc = self.main(["relay-test", "--domain", "cjc1.com", "--dns-provider", "cloudflare", "--mode", "byo",
                        "--oracle-sim"], fake, run=run_rb, popen=pop, **kw)
        out = self.out.getvalue()
        self.assertEqual(rc, 0, out + self.err.getvalue())
        created = [json.loads(c[3]) for c in fake.calls if c[:2] == ("POST", e2e.API + "/droplets")]
        self.assertEqual([c["size"] for c in created], ["s-1vcpu-1gb", e2e.BYO_SIZE])
        self.assertTrue(created[1]["name"].startswith("porch-e2e-byo-"))
        self.assertEqual(created[1]["tags"], ["porch-e2e"])
        cmd = pop.calls[0]["argv"][-1]
        self.assertIn("--connection oracle", cmd)
        self.assertIn(f"--relay-host root@203.0.113.99 --relay-ssh-key {e2e.BYO_KEY}", cmd)
        self.assertNotIn("--relay-token-ref", cmd)
        sims = [i for a, i in run.calls if a[0] == "ssh" and a[-2] == "root@203.0.113.99" and a[-1] == "bash -s"]
        self.assertEqual(sims, [e2e.ORACLE_SIM.encode()])
        self.assertFalse(any("do-relay" in a[-1] for a, _ in run.calls if a[0] == "ssh"))
        self.assertIn("relay checks: 13/13 passed", out)
        self.assertIn("byo server 203.0.113.99 after rollback: clean", out)
        self.assertEqual(fake.droplets, [])

    def test_relay_test_vultr(self):
        fake, run, pop = FakeDO(), RelayRun(), FakePopen()
        V = "vultr-FAKE-" + os.urandom(6).hex()
        inst = {"id": "a1b2c3d4-0000-1111-2222-333344445555", "label": "porch-relay-ab12", "status": "active",
                "main_ip": "203.0.113.99", "tags": ["porch-relay", "porch-e2e"]}
        vstate = {"instances": []}
        vcalls = []

        def vhttp(method, url, headers, body):
            vcalls.append((method, url))
            assert headers["Authorization"] == f"Bearer {V}"
            path = url.split("/v2", 1)[1]
            if method == "GET" and path.startswith("/instances?tag="):
                return 200, json.dumps({"instances": vstate["instances"]}).encode()
            if method == "GET" and path.startswith("/plans"):
                return 200, json.dumps({"plans": [{"id": "vc2-1c-1gb", "locations": ["ewr"],
                                                   "monthly_cost": 5}]}).encode()
            if method == "GET" and path.startswith("/instances/"):
                found = [i for i in vstate["instances"] if path.endswith(i["id"])]
                return (200, json.dumps({"instance": found[0]}).encode()) if found else (404, b"{}")
            if method == "DELETE" and path.startswith("/instances/"):
                vstate["instances"] = [i for i in vstate["instances"] if not path.endswith(i["id"])]
                return 204, b""
            return 404, b"{}"
        e2e.App.relay_http = staticmethod(vhttp)
        self.addCleanup(delattr, e2e.App, "relay_http")

        def popen(argv, **kw):
            vstate["instances"].append(inst)            # porch setup "creates" the Vultr relay
            return pop(argv, **kw)
        run_rb, kw = self._relay_env(fake, run, delete_on_rollback=lambda: vstate.update(instances=[]))
        kw["token_reader"] = lambda ref: V if "VULTR" in ref else self.reader(ref)
        rc = self.main(["relay-test", "--domain", "cjc1.com", "--dns-provider", "cloudflare",
                        "--relay-provider", "vultr"], fake, run=run_rb, popen=popen, **kw)
        out = self.out.getvalue()
        self.assertEqual(rc, 0, out + self.err.getvalue())
        cmd = pop.calls[0]["argv"][-1]
        self.assertIn("--relay-provider vultr --relay-token-ref 'file://~/.config/porch/secrets/vultr-relay'", cmd)
        self.assertNotIn("--relay-region", cmd)
        puts = [i for a, i in run.calls if a[0] == "ssh" and a[-1].endswith("cat > ~/.config/porch/secrets/vultr-relay")]
        self.assertEqual(puts, [V.encode(), V.encode()])
        self.assertIn("relay vultr a1b2c3d4-0000-1111-2222-333344445555: deleted by porch's rollback", out)
        self.assertIn("vultr instances tagged porch-e2e left: none", out)
        self.assertNotIn(V, out)
        for argv, _ in run.calls:
            self.assertNotIn(V, " ".join(argv))

    def test_relay_test_flags_a_reachable_home(self):
        fake, run = FakeDO(), RelayRun()
        e2e_app = e2e.App(env={"PORCH_E2E_DIR": self.dir}, http=fake, run=run, token_reader=self.reader,
                          out=self.out, err=self.err, sleep=lambda s: None, clock=lambda: 1_760_000_000,
                          resolver=FakeA("203.0.113.99"))
        e2e_app.tcp_reachable = lambda ip, port, timeout=6: port == 443 or ip == "203.0.113.99"
        os.makedirs(self.dir)
        st = {"droplet_id": 4242, "ip": "203.0.113.7", "prefill": {"domain": "cjc1.com"}, "relay_test": {}}
        rc = e2e_app.relay_checks(st, {"id": 5151, "ip": "203.0.113.99"})
        self.assertEqual(rc, 1)
        self.assertIn("[FAIL] home 203.0.113.7:443 direct: REACHABLE", self.out.getvalue())

    def test_frp_pin_matches_the_relay_installer(self):
        from porch_setup.relay import common
        self.assertEqual(e2e.FRP_SHA256, common.FRP_SHA256["amd64"])
        self.assertEqual(e2e.FRP_VERSION, common.FRP_VERSION)


class InstallerRun(FakeRun):
    """FakeRun that also 'builds' the tarball bin/publish-tarball --out writes."""
    def __call__(self, argv, input=None, capture_output=False, timeout=None, check=False, **kw):
        if argv[0].endswith("publish-tarball"):
            self.calls.append((argv, input))
            out = argv[argv.index("--out") + 1]
            with open(out, "wb") as f:
                f.write(b"TARBALL")
            with open(out + ".sha256", "w") as f:
                f.write("ab" * 32 + "  cush-tools.tar.gz\n")
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        return super().__call__(argv, input=input, capture_output=capture_output, timeout=timeout,
                                check=check, **kw)


class TestInstaller(Base):
    def test_up_installer_runs_the_real_script_over_stdin(self):
        fake, run = FakeDO(), InstallerRun()
        pop = FakePopen(lines=[b"Porch server installer\n", b"    https://203.0.113.7:8443/#k=AbC\n"])
        rc = self.main(["up", "--installer", "--domain", "cjc1.com", "--dns-provider", "cloudflare"],
                       fake, run=run, popen=pop)
        self.assertEqual(rc, 0, self.out.getvalue() + self.err.getvalue())
        # no PROVISION / git archive upload: the droplet is bare until porch.sh runs
        self.assertFalse(any(a[-1] == "bash -s" for a, _ in run.calls))
        self.assertFalse(any("tar -x -C" in a[-1] for a, _ in run.calls))
        # the tarball and its .sha256 go to /root/porch-install
        ups = {a[-1]: inp for a, inp in run.calls if a[0] == "ssh" and a[-1].startswith("cat > ")}
        self.assertEqual(ups[f"cat > {e2e.INSTALL_UPLOAD}/cush-tools.tar.gz"], b"TARBALL")
        self.assertIn(b"  cush-tools.tar.gz", ups[f"cat > {e2e.INSTALL_UPLOAD}/cush-tools.tar.gz.sha256"])
        (call,) = pop.calls
        self.assertIn("root@203.0.113.7", call["argv"])
        self.assertEqual(call["argv"][-1],
                         f"PORCH_TARBALL=file://{e2e.INSTALL_UPLOAD}/cush-tools.tar.gz sh -s -- "
                         "--staging --domain cjc1.com --dns-provider cloudflare")
        with open(os.path.join(os.path.dirname(__file__), "..", "site", "porch.sh"), "rb") as f:
            self.assertEqual(call["stdin"], f.read())
        # cloud firewall: 22, 80 and 8443
        posted = [json.loads(c[3]) for c in fake.calls if c[:2] == ("POST", e2e.API + "/firewalls")]
        self.assertEqual([r["ports"] for r in posted[0]["inbound_rules"]], ["22", "80", "8443"])
        self.assertTrue(posted[0]["name"].startswith("porch-e2e-"))
        st = e2e.load_state(self.dir)
        self.assertTrue(st["installer"])
        self.assertEqual(st["wizard_unit"], "porch-wizard")
        self.assertEqual(st["results"]["installer"]["exit"], 0)
        self.assertIn("WIZARD URL: https://203.0.113.7/#k=AbC_d-123", self.out.getvalue())
        # porch's ssh key is set up after the installer made the user
        self.assertTrue(any("/home/porch/.ssh/authorized_keys" in a[-1] for a, _ in run.calls))
        # down stops porch-wizard (not porch-e2e-wizard) and deletes the firewall
        run2 = InstallerRun()
        self.assertEqual(self.main(["down", "--yes"], fake, run=run2), 0, self.out.getvalue())
        self.assertTrue(any("systemctl stop porch-wizard " in a[-1] for a, _ in run2.calls))
        self.assertEqual(fake.firewalls, [])

    def test_installer_failure_is_exit_1_and_production_drops_staging(self):
        fake, run, pop = FakeDO(), InstallerRun(), FakePopen(lines=[b"x boom\n"], rc=1)
        self.assertEqual(self.main(["up", "--installer", "--production"], fake, run=run, popen=pop), 1)
        self.assertEqual(pop.calls[0]["argv"][-1],
                         f"PORCH_TARBALL=file://{e2e.INSTALL_UPLOAD}/cush-tools.tar.gz sh -s --")
        self.assertIn("  | x boom", self.out.getvalue())
        self.assertEqual(e2e.load_state(self.dir)["results"]["installer"]["exit"], 1)

    def test_redeploy_reruns_the_installer(self):
        os.makedirs(self.dir)
        e2e.save_state(self.dir, {"droplet_id": 9, "ip": "203.0.113.7", "key_id": 77, "installer": True,
                                  "wizard_unit": "porch-wizard"})
        fake, run, pop = FakeDO([droplet(9)]), InstallerRun(), FakePopen(lines=[])
        self.assertEqual(self.main(["up", "--redeploy"], fake, run=run, popen=pop), 0, self.out.getvalue())
        self.assertEqual(len(pop.calls), 1)
        self.assertIn("sh -s -- --staging", pop.calls[0]["argv"][-1])
        self.assertFalse(any("tar -x -C" in a[-1] for a, _ in run.calls))

    def test_installer_cli_needs_domain_and_cloudflare(self):
        fake = FakeDO()
        self.assertEqual(self.main(["up", "--installer", "--cli"], fake), 1)
        self.assertFalse(any(c[0] == "POST" for c in fake.calls))

    def test_installer_then_cli_setup(self):
        class Run(RelayRun):
            def __call__(self, argv, **kw):
                if argv[0].endswith("publish-tarball"):
                    return InstallerRun.__call__(self, argv, **kw)
                return super().__call__(argv, **kw)
        fake, run = FakeDO(), Run()
        pop = FakePopen(lines=[b"    https://203.0.113.7:8443/#k=AbC\n", b"porch setup: ok\n"])
        rc = self.main(["up", "--installer", "--cli", "--production", "--domain", "cjc1.com",
                        "--dns-provider", "cloudflare"], fake, run=run, popen=pop,
                       token_reader=lambda ref: CF if "CLOUDFLARE" in ref else TOKEN)
        self.assertEqual(rc, 0, self.out.getvalue() + self.err.getvalue())
        inst, setup = pop.calls
        self.assertIn("sh -s -- --domain cjc1.com", inst["argv"][-1])
        self.assertIn("bin/porch setup --non-interactive --yes --domain cjc1.com", setup["argv"][-1])
        self.assertIn("porch@203.0.113.7", setup["argv"])
        self.assertNotIn(CF, " ".join(setup["argv"]))
        self.assertTrue(setup["stdin"].startswith(CF.encode() + b"\n"))
        # the wizard is stopped before setup needs :80
        self.assertTrue(any("systemctl stop porch-wizard" in a[-1] for a, _ in run.calls))
        posted = [json.loads(c[3]) for c in fake.calls if c[:2] == ("POST", e2e.API + "/firewalls")]
        self.assertEqual([r["ports"] for r in posted[0]["inbound_rules"]], ["22", "80", "8443", "443", "7000"])
        self.assertEqual(e2e.load_state(self.dir)["results"]["setup"]["done"], 14)
        self.assertEqual(e2e.load_state(self.dir)["results"]["wizard_http"], 200)
        self.assertIn("wizard https://203.0.113.7/ answered 200", self.out.getvalue())


class TestDefaultRootDns(Base):
    def test_unconfigured_droplet_skips_the_dns_check(self):
        os.makedirs(self.dir)
        e2e.save_state(self.dir, {"droplet_id": 9, "ip": "203.0.113.7", "key_id": 77})
        fake, run = FakeDO([droplet(9)]), FakeRun()
        dump = json.dumps({"domain": {"root": e2e.DEFAULT_ROOT, "auth_host": "auth.cush.rocks"}}).encode()
        real = run.__call__

        def runner(argv, **kw):
            if argv[0] == "ssh" and "porch_config.py dump" in argv[-1]:
                return subprocess.CompletedProcess(argv, 0, dump, b"")
            return real(argv, **kw)
        self.assertEqual(self.main(["down", "--yes"], fake, run=runner), 0, self.out.getvalue())
        self.assertIn("DNS check skipped: no domain recorded", self.out.getvalue())


if __name__ == "__main__":
    unittest.main()

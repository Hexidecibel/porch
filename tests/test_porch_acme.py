"""acme.py + bin/porch-acme-hook + bin/porch-cert-deploy + the certificate step,
driven by a fake certbot that calls the hooks with CERTBOT_DOMAIN /
CERTBOT_VALIDATION the way certbot does. No network, no real CA."""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import porch_config  # noqa: E402
from porch_dns_fakes import FakeDNS, FakeProvider  # noqa: E402
from porch_setup import acme  # noqa: E402
from porch_setup.engine import EXIT_PREFLIGHT, Engine, make_context  # noqa: E402
from porch_setup.io import NullIO  # noqa: E402
from porch_setup.redact import Redactor  # noqa: E402
from porch_setup.runner import FakeRunner, Result  # noqa: E402
from porch_setup.steps.certificate import STEP as CERT  # noqa: E402
from porch_setup.steps.dns_provider import STEP as PROV  # noqa: E402
from porch_setup.steps.dns_records import STEP as RECS  # noqa: E402

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HAVE_OPENSSL = shutil.which("openssl") is not None
TOKEN = "cf-SECRET-token-31337"
NOW = 1_790_000_000.0   # 2026-09


def make_cert(tmp, sans, days=90):
    """(fullchain pem, key pem) for a self-signed cert with these SANs."""
    key, crt = os.path.join(tmp, "k.pem"), os.path.join(tmp, "c.pem")
    ext = "subjectAltName=" + ",".join("DNS:" + s for s in sans)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-keyout", key, "-out", crt, "-days", str(days), "-subj",
                    "/CN=" + sans[0], "-addext", ext], check=True, capture_output=True)
    with open(crt) as f, open(key) as g:
        return f.read(), g.read()


def real_openssl(argv, input=None, env=None, cwd=None):
    p = subprocess.run(argv, input=input, capture_output=True, text=True)
    return Result(list(argv), p.returncode, p.stdout, p.stderr)


class UnitTest(unittest.TestCase):
    def test_versions_and_argv(self):
        self.assertEqual(acme.parse_version("certbot 5.8.0"), (5, 8, 0))
        r = FakeRunner().on(["certbot", "--version"], stdout="certbot 1.21.0")
        with self.assertRaises(acme.AcmeError) as cm:
            acme.version_check(r)
        self.assertEqual(cm.exception.code, "cert.certbot_old")
        r = FakeRunner().on(["certbot", "--version"], returncode=127)
        with self.assertRaises(acme.AcmeError) as cm:
            acme.version_check(r)
        self.assertEqual(cm.exception.code, "cert.certbot_missing")
        self.assertEqual(r.mutating_calls(), [])
        a = acme.certonly_argv(["auth.x.org", "*.tunnel.x.org"], "porch-x.org", base="/b",
                               repo_dir="/r", dry_run=True)
        self.assertIn("--dry-run", a)
        self.assertNotIn("--deploy-hook", a)
        self.assertEqual(a[a.index("--config-dir") + 1], "/b/config")
        self.assertEqual(a[a.index("--manual-auth-hook") + 1], "/r/bin/porch-acme-hook auth")
        self.assertIn("--register-unsafely-without-email", a)
        a = acme.certonly_argv(["auth.x.org"], "porch-x.org", base="/b", repo_dir="/r",
                               email="me@x.org", staging=True)
        self.assertEqual(a[a.index("--deploy-hook") + 1], "/r/bin/porch-cert-deploy")
        self.assertIn("--test-cert", a)
        self.assertIn("--keep-until-expiring", a)
        self.assertEqual(a[a.index("--email") + 1], "me@x.org")
        rn = acme.renew_argv("porch-x.org", base="/b", repo_dir="/r", dry_run=True)
        self.assertEqual(rn[:2], ["certbot", "renew"])

    def test_parse_and_covers(self):
        out = ("subject=CN = *.tunnel.x.org\nissuer=C = US, O = Let's Encrypt, CN = E6\n"
               "notAfter=Dec 31 02:26:04 2026 GMT\nX509v3 Subject Alternative Name: \n"
               "    DNS:*.tunnel.x.org, DNS:tunnel.x.org, IP Address:192.0.2.1\n")
        info = acme.parse_openssl(out)
        self.assertEqual(info.sans, ["*.tunnel.x.org", "tunnel.x.org", "192.0.2.1"])
        self.assertTrue(info.covers("a.tunnel.x.org"))
        self.assertTrue(info.covers("*.tunnel.x.org"))
        self.assertTrue(info.covers("tunnel.x.org"))
        self.assertFalse(info.covers("a.b.tunnel.x.org"))
        self.assertFalse(info.covers("auth.x.org"))
        self.assertAlmostEqual(info.days_left(info.not_after - 86400 * 3), 3.0)
        self.assertEqual(acme.challenge_name("*.tunnel.x.org"), "_acme-challenge.tunnel.x.org")
        self.assertEqual(acme.challenge_name("tunnel.x.org"), "_acme-challenge.tunnel.x.org")

    @unittest.skipUnless(HAVE_OPENSSL, "openssl not installed")
    def test_inspect_real_pem(self):
        with tempfile.TemporaryDirectory() as d:
            pem, key = make_cert(d, ["auth.x.org", "*.tunnel.x.org"], days=30)
            r = FakeRunner().on(["openssl"], func=real_openssl)
            info = acme.inspect_pem(r, pem)
            self.assertEqual(info.sans, ["auth.x.org", "*.tunnel.x.org"])
            self.assertGreater(info.not_after, 0)
            p = os.path.join(d, "combined.pem")
            with open(p, "w") as f:
                f.write(pem + key)
            got = acme.read_cert_file(p)
            self.assertNotIn("PRIVATE KEY", got)
            self.assertIn("BEGIN CERTIFICATE", got)


BUSY = ("An unexpected error occurred:\n"
        "urn:ietf:params:acme:error:rateLimited :: The service is being rate limited :: "
        "Service busy; retry later.")
LIMIT = ("An unexpected error occurred:\n"
         "Error creating new order :: too many certificates (5) already issued for this exact "
         "set of identifiers in the last 168h0m0s, retry after 2026-10-21 03:12:45 UTC: see "
         "https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-hostnames")


class CertbotRetryTest(unittest.TestCase):
    def seq(self, *results):
        """A FakeRunner whose certbot answers the given (rc, stderr) in order."""
        calls = []
        it = iter(results)

        def fake(argv, input=None, env=None, cwd=None):
            calls.append(argv)
            rc, err = next(it)
            return Result(list(argv), rc, "", err)
        return FakeRunner().on(["certbot"], func=fake), calls

    def test_classify(self):
        self.assertEqual(acme.classify_certbot_failure(BUSY), ("busy", None, None))
        self.assertEqual(acme.classify_certbot_failure("HTTP 503 Service Unavailable")[0], "busy")
        self.assertEqual(acme.classify_certbot_failure("Service busy; retry later. Retry-After: 45"),
                         ("busy", 45, None))
        self.assertEqual(acme.classify_certbot_failure(LIMIT),
                         ("rate_limit", None, "2026-10-21 03:12:45 UTC"))
        # rateLimited WITH "too many" is a real limit, never a busy retry
        self.assertEqual(acme.classify_certbot_failure(
            "urn:ietf:params:acme:error:rateLimited :: too many failed authorizations recently")[0],
            "rate_limit")
        self.assertEqual(acme.classify_certbot_failure("Some challenges have failed.")[0], None)

    def test_busy_is_retried_with_backoff(self):
        r, calls = self.seq((1, BUSY), (1, BUSY), (0, ""))
        slept, logs = [], []
        res = acme.run_certbot(r, ["certbot", "certonly"], sleep=slept.append, log=logs.append)
        self.assertEqual(res.returncode, 0)
        self.assertEqual(len(calls), 3)
        self.assertEqual(slept, list(acme.BUSY_DELAYS))
        self.assertLessEqual(sum(slept), 150)       # about two minutes in all
        self.assertIn("busy", logs[0])

    def test_retry_after_hint_is_honoured(self):
        r, calls = self.seq((1, "Service busy; retry later. Retry-After: 12"), (0, ""))
        slept = []
        acme.run_certbot(r, ["certbot"], sleep=slept.append)
        self.assertEqual(slept, [12])
        r, calls = self.seq((1, "503 Service Unavailable, Retry-After: 3600"))
        with self.assertRaises(acme.AcmeError) as cm:
            acme.run_certbot(r, ["certbot"], sleep=slept.append)
        self.assertEqual(cm.exception.code, "cert.busy")
        self.assertIn("3600", cm.exception.message)
        self.assertEqual(len(calls), 1)

    def test_still_busy_after_three_tries(self):
        r, calls = self.seq((1, BUSY), (1, BUSY), (1, BUSY))
        with self.assertRaises(acme.AcmeError) as cm:
            acme.run_certbot(r, ["certbot"], sleep=lambda s: None)
        self.assertEqual(cm.exception.code, "cert.busy")
        self.assertEqual(len(calls), 3)

    def test_rate_limit_is_never_retried(self):
        r, calls = self.seq((1, LIMIT))
        slept = []
        with self.assertRaises(acme.AcmeError) as cm:
            acme.run_certbot(r, ["certbot"], sleep=slept.append)
        self.assertEqual(cm.exception.code, "cert.rate_limited")
        self.assertIn("too many certificates", cm.exception.message)
        self.assertIn("2026-10-21 03:12:45 UTC", cm.exception.message)
        self.assertIn("2026-10-21 03:12:45 UTC", cm.exception.hint)
        self.assertEqual((len(calls), slept), (1, []))

    def test_other_failures_return_at_once(self):
        r, calls = self.seq((1, "Some challenges have failed."))
        res = acme.run_certbot(r, ["certbot"], sleep=lambda s: self.fail("slept"))
        self.assertEqual((res.returncode, len(calls)), (1, 1))


class HookTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data = os.path.join(self.tmp.name, "data")
        os.makedirs(self.data)
        with open(os.path.join(self.data, "porch-setup.json"), "w") as f:
            json.dump({"version": 1, "inputs": {"dns_provider": "cloudflare"},
                       "secret_refs": {"dns_token": "file://~/.config/porch/secrets/dns_token"},
                       "facts": {"zone_apex": "example.com"},
                       "steps": {"dns_provider": {"outputs": {"provider": "cloudflare",
                                                              "zone": "example.com"}}}}, f)
        self.dns = FakeDNS().add_zone("example.com", {"ns1.p.net": "192.0.2.53",
                                                      "ns2.p.net": "192.0.2.54"})
        self.prov = FakeProvider("example.com", dns=self.dns)
        self.t = [0.0]
        self.out = open(os.path.join(self.tmp.name, "log"), "w+")
        self.addCleanup(self.out.close)

    def env(self, domain, value):
        return {"PORCH_SETUP_DIR": self.data, "CERTBOT_DOMAIN": domain, "CERTBOT_VALIDATION": value}

    def hook(self, action, domain, value, **kw):
        def sleep(s):
            self.t[0] += s
        return acme.hook_main(action, self.env(domain, value), provider=self.prov,
                              resolver=self.dns.resolver(), clock=lambda: self.t[0], sleep=sleep,
                              out=self.out, **kw)

    def test_two_values_share_a_name_and_cleanup_removes_only_its_own(self):
        name = "_acme-challenge.tunnel.example.com"
        self.prov.records["keep"] = __import__("porch_setup.dns.base", fromlist=["Record"]).Record(
            name, "TXT", "someone-elses", id="keep")
        self.assertEqual(self.hook("auth", "tunnel.example.com", "val-A"), 0)
        self.assertEqual(self.hook("auth", "*.tunnel.example.com", "val-B"), 0)
        vals = sorted(r.content for r in self.prov.records.values())
        self.assertEqual(vals, ["someone-elses", "val-A", "val-B"])
        self.assertEqual(sorted(self.dns.resolver().authoritative(name, "TXT", zone="example.com")
                                ["192.0.2.53"]), ["someone-elses", "val-A", "val-B"])
        # re-running auth with the same value does not add a duplicate
        self.assertEqual(self.hook("auth", "tunnel.example.com", "val-A"), 0)
        self.assertEqual(len(self.prov.records), 3)
        self.assertEqual(self.hook("cleanup", "tunnel.example.com", "val-A"), 0)
        self.assertEqual(sorted(r.content for r in self.prov.records.values()),
                         ["someone-elses", "val-B"])
        self.assertEqual(self.hook("cleanup", "*.tunnel.example.com", "val-B"), 0)
        self.assertEqual([r.content for r in self.prov.records.values()], ["someone-elses"])

    def test_waits_for_authoritative_ns(self):
        lag = {"n": 0}
        real = self.prov._publish

        def slow_publish():
            lag["n"] += 1
        self.prov._publish = slow_publish
        orig_sleep_calls = []

        def sleep(s):
            orig_sleep_calls.append(s)
            self.t[0] += s
            if len(orig_sleep_calls) == 3:
                real()   # the NS catch up after three polls
        rc = acme.hook_main("auth", self.env("x.example.com", "v1"), provider=self.prov,
                            resolver=self.dns.resolver(), clock=lambda: self.t[0], sleep=sleep,
                            out=self.out)
        self.assertEqual(rc, 0)
        self.assertEqual(len(orig_sleep_calls), 3)
        self.out.seek(0)
        self.assertIn("live on 2 name server(s)", self.out.read())

    def test_bad_usage_and_missing_state(self):
        self.assertEqual(acme.hook_main("bogus", {}, out=self.out), 2)
        self.assertEqual(acme.hook_main("auth", {"PORCH_SETUP_DIR": self.data}, out=self.out), 2)
        empty = os.path.join(self.tmp.name, "empty")
        os.makedirs(empty)
        rc = acme.hook_main("auth", {"PORCH_SETUP_DIR": empty, "CERTBOT_DOMAIN": "a.example.com",
                                     "CERTBOT_VALIDATION": "v"}, out=self.out)
        self.assertEqual(rc, 1)

    def test_provider_failure_fails_auth_not_cleanup(self):
        self.prov.fail = {"create": "dns.auth", "list": "dns.auth"}
        self.assertEqual(self.hook("auth", "a.example.com", "v"), 1)
        self.assertEqual(self.hook("cleanup", "a.example.com", "v"), 0)

    def test_hook_builds_provider_from_state_and_secret(self):
        sec = os.path.join(self.tmp.name, "secrets")
        os.makedirs(sec, mode=0o700)
        with open(os.path.join(sec, "dns_token"), "w") as f:
            f.write(TOKEN)
        p = acme._hook_provider(acme.load_hook_config({"PORCH_SETUP_DIR": self.data}),
                                {"PORCH_SECRETS_DIR": sec, "PORCH_DNS_BASE_URL": "http://127.0.0.1:9"})
        self.assertEqual(p.name, "cloudflare")
        self.assertEqual(p.creds["token"], TOKEN)
        self.assertEqual(p.base_url, "http://127.0.0.1:9")


class BinHooksTest(unittest.TestCase):
    """The real bin/porch-acme-hook (subprocess) against a loopback Cloudflare
    API fake and a loopback DNS server, and bin/porch-cert-deploy."""

    def test_bin_acme_hook_end_to_end(self):
        from test_porch_dns_providers import CF_TOKEN, CloudflareFake, FakeAPI
        api = FakeAPI()
        self.addCleanup(api.close)
        cf = CloudflareFake()
        dns = FakeDNS().add_zone("example.com", {"ns1.p.net": "192.0.2.53"})

        def handler(*a):
            st = cf(*a)
            dns.zones["example.com"] = {k: v for k, v in dns.zones["example.com"].items()
                                        if k[1] in ("SOA", "NS")}
            for r in cf.records.values():
                dns.zones["example.com"].setdefault((r["name"], r["type"]), []).append(
                    r["content"].strip('"'))
            return st
        api.handler = handler
        port, stop = dns.serve("192.0.2.53")
        self.addCleanup(stop)
        with tempfile.TemporaryDirectory() as d:
            data, sec = os.path.join(d, "data"), os.path.join(d, "sec")
            os.makedirs(data)
            os.makedirs(sec, mode=0o700)
            with open(os.path.join(sec, "dns_token"), "w") as f:
                f.write(CF_TOKEN)
            with open(os.path.join(data, "porch-setup.json"), "w") as f:
                json.dump({"inputs": {"dns_provider": "cloudflare"},
                           "secret_refs": {"dns_token": "file://~/.config/porch/secrets/dns_token"},
                           "facts": {"zone_apex": "example.com"}}, f)
            env = dict(os.environ, PORCH_SETUP_DIR=data, PORCH_SECRETS_DIR=sec,
                       PORCH_DNS_BASE_URL=api.url + "/client/v4", PORCH_ACME_NS=f"127.0.0.1:{port}",
                       PORCH_ACME_WAIT="5", CERTBOT_DOMAIN="*.tunnel.example.com",
                       CERTBOT_VALIDATION="chal-1")
            hook = os.path.join(REPO, "bin", "porch-acme-hook")
            p = subprocess.run([hook, "auth"], env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("live on 1 name server", p.stderr)
            self.assertEqual([r["content"] for r in cf.records.values()], ['"chal-1"'])
            self.assertNotIn(CF_TOKEN, p.stdout + p.stderr)
            p = subprocess.run([hook, "cleanup"], env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(cf.records, {})

    def test_cert_deploy_writes_0600_combined_pem(self):
        with tempfile.TemporaryDirectory() as d:
            live = os.path.join(d, "live", "porch-x.org")
            os.makedirs(live)
            with open(os.path.join(live, "fullchain.pem"), "w") as f:
                f.write("CHAIN\n")
            with open(os.path.join(live, "privkey.pem"), "w") as f:
                f.write("KEY\n")
            certs = os.path.join(d, "certs")
            env = dict(os.environ, RENEWED_LINEAGE=live, PORCH_CERT_DIR=certs, PORCH_CERT_RELOAD="0")
            p = subprocess.run([os.path.join(REPO, "bin", "porch-cert-deploy")], env=env,
                               capture_output=True, text=True, timeout=30)
            self.assertEqual(p.returncode, 0, p.stderr)
            out = os.path.join(certs, "porch-x.org.pem")
            with open(out) as f:
                self.assertEqual(f.read(), "CHAIN\nKEY\n")
            self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(certs).st_mode), 0o700)
            self.assertEqual([n for n in os.listdir(certs) if n.startswith(".")], [])
            os.remove(out)
            os.symlink("/etc/passwd", out)
            p = subprocess.run([os.path.join(REPO, "bin", "porch-cert-deploy")], env=env,
                               capture_output=True, text=True, timeout=30)
            self.assertNotEqual(p.returncode, 0)
            p = subprocess.run([os.path.join(REPO, "bin", "porch-cert-deploy")],
                               env={k: v for k, v in env.items() if k != "RENEWED_LINEAGE"},
                               capture_output=True, text=True, timeout=30)
            self.assertNotEqual(p.returncode, 0)


@unittest.skipUnless(HAVE_OPENSSL, "openssl not installed")
class CertificateStepTest(unittest.TestCase):
    """dns_provider -> dns_records -> certificate with a fake certbot."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.acme_dir = os.path.join(self.tmp, "acme")
        self.cert_dir = os.path.join(self.tmp, "certs")
        self.env = {"PORCH_ACME_DIR": self.acme_dir, "PORCH_CERT_DIR": self.cert_dir,
                    "PORCH_DNS_WAIT": "60"}
        self.dns = FakeDNS().add_zone("example.com", {"ns1.p.net": "192.0.2.53",
                                                      "ns2.p.net": "192.0.2.54"})
        self.prov = FakeProvider("example.com", dns=self.dns)
        self.certbot_calls = []
        self.runner = FakeRunner()
        self.runner.on(["certbot", "--version"], stdout="certbot 5.8.0")
        self.runner.on(["certbot", "certonly"], func=self.fake_certbot)
        self.runner.on(["openssl"], func=real_openssl)
        self.runner.on(lambda a: a[0].endswith("porch-cert-deploy"), func=self.run_deploy)
        self.t = [NOW]
        self.devnull = open(os.devnull, "w")
        self.addCleanup(self.devnull.close)

    def ctx(self, answers=None, adopt=False, confirms=True):
        base = {"dns_provider": "cloudflare", "dns_token": TOKEN, "dns_ipv4": "1.2.3.4"}
        base.update(answers or {})
        io = NullIO(base, confirms=confirms)
        cfg = porch_config.load(env={"PORCH_CONFIG": "none", "PORCH_DOMAIN": "porch.example.com"})

        def sleep(s):
            self.t[0] += s
        c = make_context(io=io, runner=self.runner, data_dir=self.tmp + "/data", cfg=cfg,
                         redactor=Redactor(), secrets_dir=self.tmp + "/secrets", adopt=adopt,
                         dns=self.dns.resolver(), sleep=sleep, clock=lambda: self.t[0],
                         env=self.env, repo_dir=REPO)
        c.provider_factory = lambda name, creds: self.prov
        self.io = io
        return c

    def fake_certbot(self, argv, input=None, env=None, cwd=None):
        """certbot certonly --manual: auth hook per -d, (cert), cleanup per -d."""
        self.certbot_calls.append(argv)
        doms = [argv[i + 1] for i, a in enumerate(argv) if a == "-d"]
        for i, d in enumerate(doms):
            hook_env = dict(env, CERTBOT_DOMAIN=d.lstrip("*."), CERTBOT_VALIDATION=f"v{i}-{d}")
            rc = acme.hook_main("auth", hook_env, provider=self.prov, resolver=self.dns.resolver(),
                                clock=lambda: self.t[0], sleep=lambda s: None,
                                out=self.devnull)
            if rc != 0:
                return Result(argv, 1, "", "auth hook failed")
        # both challenges for tunnel.X and *.tunnel.X are live at the same time
        name = "_acme-challenge.tunnel.porch.example.com"
        self.assertEqual(len(self.dns.get("example.com", name, "TXT")), 2)
        for i, d in enumerate(doms):
            hook_env = dict(env, CERTBOT_DOMAIN=d.lstrip("*."), CERTBOT_VALIDATION=f"v{i}-{d}")
            acme.hook_main("cleanup", hook_env, provider=self.prov, resolver=self.dns.resolver(),
                           out=self.devnull)
        if "--dry-run" in argv:
            return Result(argv, 0, "The dry run was successful.", "")
        base = argv[argv.index("--config-dir") + 1]
        name = argv[argv.index("--cert-name") + 1]
        live = os.path.join(base, "live", name)
        os.makedirs(live, exist_ok=True)
        pem, key = make_cert(self.tmp, doms, days=90)
        with open(os.path.join(live, "fullchain.pem"), "w") as f:
            f.write(pem)
        with open(os.path.join(live, "privkey.pem"), "w") as f:
            f.write(key)
        os.makedirs(os.path.join(base, "renewal"), exist_ok=True)
        open(os.path.join(base, "renewal", name + ".conf"), "w").close()
        return self.run_deploy([argv[argv.index("--deploy-hook") + 1]],
                               env=dict(env, RENEWED_LINEAGE=live))

    def run_deploy(self, argv, input=None, env=None, cwd=None):
        e = dict(os.environ)
        e.update(env or {})
        e["PORCH_CERT_RELOAD"] = "0"
        p = subprocess.run(argv, env=e, capture_output=True, text=True, timeout=30)
        return Result(list(argv), p.returncode, p.stdout, p.stderr)

    def test_full_chain_issue_then_idempotent(self):
        # NOW must be near the cert's real validity for days_left; use real time
        import time
        self.t[0] = time.time()
        ctx = self.ctx()
        r = Engine([PROV, RECS, CERT], ctx).run()
        self.assertTrue(r.ok, r)
        self.assertEqual([("--dry-run" in a) for a in self.certbot_calls], [True, False])
        doms = [a[i + 1] for a in self.certbot_calls[:1] for i, x in enumerate(a) if x == "-d"]
        self.assertEqual(doms, ["auth.porch.example.com", "panel.porch.example.com",
                                "tunnel.porch.example.com", "*.tunnel.porch.example.com"])
        self.assertEqual(self.certbot_calls[0][self.certbot_calls[0].index("--cert-name") + 1],
                         "porch-porch.example.com")
        pem = os.path.join(self.cert_dir, "porch-porch.example.com.pem")
        self.assertEqual(stat.S_IMODE(os.stat(pem).st_mode), 0o600)
        # challenge TXT records are gone again; only the A records remain
        self.assertEqual({t for _n, t, _c in self.prov.contents()}, {"A"})
        out = ctx.state.steps["certificate"]["outputs"]
        self.assertEqual(out["pem"], pem)
        self.assertIn("*.tunnel.porch.example.com", out["sans"])
        # the hook env pointed certbot at this run's state + secrets
        env_calls = [c for c in self.runner.calls if c["argv"][:2] == ["certbot", "certonly"]]
        self.assertTrue(env_calls)
        with open(os.path.join(self.tmp, "data", "porch-setup.json")) as f:
            self.assertNotIn(TOKEN, f.read())
        # second run: nothing re-issued, no DNS writes
        n_calls, n_mut = len(self.certbot_calls), len(self.prov.mutations())
        r = Engine([PROV, RECS, CERT], self.ctx()).run()
        self.assertTrue(r.ok, r)
        self.assertEqual(len(self.certbot_calls), n_calls)
        self.assertEqual(len(self.prov.mutations()), n_mut)
        # rollback removes the combined PEM, keeps the lineage
        r = Engine([CERT], self.ctx()).rollback()
        self.assertTrue(r.ok, r)
        self.assertFalse(os.path.exists(pem))
        self.assertTrue(os.path.exists(os.path.join(self.acme_dir, "config", "live",
                                                    "porch-porch.example.com", "fullchain.pem")))

    def test_dry_run_failure_stops_before_real_issue(self):
        import time
        self.t[0] = time.time()
        self.runner.rules.insert(0, type(self.runner.rules[0])(
            lambda a: a[:2] == ["certbot", "certonly"] and "--dry-run" in a, 1, "",
            "Some challenges have failed."))
        r = Engine([PROV, RECS, CERT], self.ctx()).run()
        self.assertFalse(r.ok)
        self.assertEqual(r.error["code"], "cert.dry_run")
        self.assertIn("letsencrypt.log", r.error["hint"])
        self.assertEqual(self.certbot_calls, [])

    def _fail_first_issue(self, stderr, times=1):
        """The real (non --dry-run) certonly answers `stderr` `times` times first."""
        left = [times]
        real = self.fake_certbot

        def fake(argv, input=None, env=None, cwd=None):
            if "--dry-run" not in argv and left[0] > 0:
                left[0] -= 1
                self.issue_failures.append(argv)
                return Result(list(argv), 1, "", stderr)
            return real(argv, input=input, env=env, cwd=cwd)
        self.issue_failures = []
        self.runner.rules = [r for r in self.runner.rules if r.func != real]
        self.runner.on(["certbot", "certonly"], func=fake)

    def test_busy_ca_is_retried_then_issues(self):
        import time
        self.t[0] = time.time()
        self._fail_first_issue(BUSY, 2)
        r = Engine([PROV, RECS, CERT], self.ctx()).run()
        self.assertTrue(r.ok, r)
        self.assertEqual(len(self.issue_failures), 2)
        self.assertTrue(any("busy" in str(e) for e in self.io.events), self.io.events[-5:])

    def test_rate_limit_stops_with_the_retry_date(self):
        import time
        self.t[0] = time.time()
        self._fail_first_issue(LIMIT, 5)
        r = Engine([PROV, RECS, CERT], self.ctx()).run()
        self.assertFalse(r.ok)
        self.assertEqual(r.error["code"], "cert.rate_limited")
        self.assertIn("2026-10-21 03:12:45 UTC", r.error["message"])
        self.assertEqual(len(self.issue_failures), 1)

    def test_manual_provider_is_refused_with_a_command(self):
        from porch_setup.dns.manual import Manual
        ctx = self.ctx({"dns_provider": "manual"})
        ctx.provider_factory = lambda name, creds: Manual()
        self.dns.set("example.com", "auth.porch.example.com", "A", ["203.0.113.7"])
        r = Engine([PROV, CERT], ctx).run()
        self.assertEqual(r.exit_code, EXIT_PREFLIGHT)
        self.assertEqual(r.error["code"], "cert.manual")
        self.assertIn("certbot certonly --manual", r.error["hint"])

    def test_adopt_checks_what_haproxy_serves(self):
        import time
        self.t[0] = time.time()
        served = {}
        for h in ("auth.porch.example.com", "panel.porch.example.com", "tunnel.porch.example.com"):
            served[h] = make_cert(self.tmp, [h], days=60)[0]
        served["porch-check.tunnel.porch.example.com"] = make_cert(
            self.tmp, ["*.tunnel.porch.example.com"], days=60)[0]
        ctx = self.ctx(adopt=True)
        ctx.tls_probe = lambda host: (served[host], True)
        checks = CERT.verify(ctx)
        self.assertTrue(all(c.ok for c in checks), checks)
        self.assertIn("4 name(s)", checks[0].message)
        served["panel.porch.example.com"] = make_cert(self.tmp, ["panel.porch.example.com"], days=10)[0]
        checks = CERT.verify(ctx)
        self.assertFalse(checks[0].ok)
        self.assertIn("expires in", checks[0].message)
        served["panel.porch.example.com"] = make_cert(self.tmp, ["other.example.com"], days=60)[0]
        self.assertIn("served certificate is for", CERT.verify(ctx)[0].message)
        ctx.tls_probe = lambda host: (served[host], False)
        served["panel.porch.example.com"] = make_cert(self.tmp, ["panel.porch.example.com"], days=60)[0]
        self.assertIn("not trusted", CERT.verify(ctx)[0].message)


if __name__ == "__main__":
    unittest.main()


class OwnCertbotDirTest(unittest.TestCase):
    def test_every_certbot_call_uses_porchs_own_dirs(self):
        # Existing /etc/letsencrypt certificates must never be renewed,
        # revoked or deleted by porch: every certbot verb runs with
        # --config-dir/--work-dir/--logs-dir under porch's acme dir.
        import re as _re
        src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib",
                                "porch_setup", "acme.py"), encoding="utf-8").read()
        calls = _re.findall(r"\[CERTBOT, \"([a-z-]+)\"([^\]]*)", src)
        verbs = {v for v, _ in calls}
        self.assertTrue({"certonly", "renew", "delete"} <= verbs, verbs)
        for verb, rest in calls:
            if verb == "--version":
                continue
            self.assertIn("*dir_args(", rest.split(",")[1] if "," in rest else rest, verb)
        self.assertNotIn("/etc/letsencrypt", src)

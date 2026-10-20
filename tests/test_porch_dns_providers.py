"""DNS providers against loopback http.server fakes of the Cloudflare v4 and
name.com v4 APIs, plus NS detection and the manual/propagation helpers."""

import base64
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from porch_dns_fakes import FakeDNS  # noqa: E402
from porch_setup import registry  # noqa: E402
from porch_setup.dns import detect, manual  # noqa: E402
from porch_setup.dns.base import ProviderError, Record, relative_name  # noqa: E402
from porch_setup.dns.cloudflare import Cloudflare  # noqa: E402
from porch_setup.dns.namecom import NameCom  # noqa: E402

CF_TOKEN = "cf-token-SECRET-123456"
NC_USER, NC_TOKEN = "alice", "nc-token-SECRET-abcdef"


class FakeAPI:
    """Shared server: each test installs `self.handler(method, path, query, body, headers)`
    -> (status, json)."""

    def __init__(self):
        api = self
        self.requests = []

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self):
                u = urlparse(self.path)
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n)) if n else None
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                api.requests.append((self.command, u.path, q, body, dict(self.headers)))
                status, payload = api.handler(self.command, u.path, q, body, self.headers)
                raw = json.dumps(payload).encode() if payload is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            do_GET = do_POST = do_PUT = do_DELETE = _do

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class CloudflareFake:
    def __init__(self, zone="example.com"):
        self.zone = zone
        self.records = {}
        self.n = 0
        self.rate_limit = False

    def add(self, name, rtype, content, ttl=300, proxied=False):
        self.n += 1
        rid = f"cf{self.n}"
        self.records[rid] = {"id": rid, "name": name, "type": rtype, "content": content,
                             "ttl": ttl, "proxied": proxied}
        return rid

    def __call__(self, method, path, q, body, headers):
        if headers.get("Authorization") != "Bearer " + CF_TOKEN:
            return 403, {"success": False, "errors": [{"code": 9109, "message": "Invalid access token"}]}
        if self.rate_limit:
            return 429, {"success": False, "errors": [{"message": "slow down"}]}
        p = path.removeprefix("/client/v4")
        if p == "/zones":
            res = [{"id": "z1", "name": self.zone}] if q.get("name") == self.zone else []
            return 200, {"success": True, "result": res}
        if p == "/zones/z1/dns_records" and method == "GET":
            recs = [r for r in self.records.values()
                    if ("name" not in q or r["name"] == q["name"])
                    and ("type" not in q or r["type"] == q["type"])]
            per, page = int(q.get("per_page", 100)), int(q.get("page", 1))
            pages = max(1, -(-len(recs) // per))
            return 200, {"success": True, "result": recs[(page - 1) * per: page * per],
                         "result_info": {"page": page, "total_pages": pages}}
        if p == "/zones/z1/dns_records" and method == "POST":
            content = body["content"]
            if body["type"] == "TXT":
                content = f'"{content}"'          # newer API echoes TXT quoted
            rid = self.add(body["name"], body["type"], content, body["ttl"], body.get("proxied"))
            return 200, {"success": True, "result": self.records[rid]}
        if p.startswith("/zones/z1/dns_records/"):
            rid = p.rsplit("/", 1)[1]
            if rid not in self.records:
                return 404, {"success": False, "errors": [{"message": "Record not found"}]}
            if method == "PUT":
                self.records[rid].update(body)
                return 200, {"success": True, "result": self.records[rid]}
            if method == "DELETE":
                del self.records[rid]
                return 200, {"success": True, "result": {"id": rid}}
        return 404, {"success": False, "errors": [{"message": "no route"}]}


class NameComFake:
    def __init__(self, zone="example.com"):
        self.zone = zone
        self.records = {}
        self.n = 100

    def add(self, host, rtype, answer, ttl=300):
        self.n += 1
        fqdn = (f"{host}." if host else "") + self.zone + "."
        self.records[self.n] = {"id": self.n, "domainName": self.zone, "host": host,
                                "fqdn": fqdn, "type": rtype, "answer": answer, "ttl": ttl}
        if not host:
            del self.records[self.n]["host"]
        return self.n

    def __call__(self, method, path, q, body, headers):
        want = "Basic " + base64.b64encode(f"{NC_USER}:{NC_TOKEN}".encode()).decode()
        if headers.get("Authorization") != want:
            return 401, {"message": "Unauthenticated"}
        p = path.removeprefix("/v4")
        if p == f"/domains/{self.zone}":
            return 200, {"domainName": self.zone}
        if p.startswith("/domains/") and not p.startswith(f"/domains/{self.zone}"):
            return 404, {"message": "Not Found", "details": "domain not in account"}
        if p == f"/domains/{self.zone}/records" and method == "GET":
            recs = list(self.records.values())
            per, page = int(q.get("perPage", 1000)), int(q.get("page", 1))
            chunk = recs[(page - 1) * per: page * per]
            out = {"records": chunk}
            if page * per < len(recs):
                out["nextPage"] = page + 1
            return 200, out
        if p == f"/domains/{self.zone}/records" and method == "POST":
            if body["ttl"] < 300:
                return 400, {"message": "Invalid Argument", "details": "ttl"}
            rid = self.add(body["host"], body["type"], body["answer"], body["ttl"])
            return 200, self.records[rid]
        if p.startswith(f"/domains/{self.zone}/records/"):
            rid = int(p.rsplit("/", 1)[1])
            if rid not in self.records:
                return 404, {"message": "Not Found"}
            if method == "PUT":
                self.records[rid].update(answer=body["answer"], ttl=body["ttl"])
                return 200, self.records[rid]
            if method == "DELETE":
                del self.records[rid]
                return 200, {}
        return 404, {"message": "Not Found"}


class ProviderAPITest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = FakeAPI()

    @classmethod
    def tearDownClass(cls):
        cls.api.close()

    def setUp(self):
        self.api.requests.clear()

    # ---- Cloudflare ----------------------------------------------------------
    def cf(self, token=CF_TOKEN):
        self.cff = CloudflareFake()
        self.api.handler = self.cff
        return Cloudflare({"token": token}, base_url=self.api.url + "/client/v4")

    def test_cloudflare_crud_and_pagination(self):
        p = self.cf()
        p.check("example.com")
        for i in range(150):
            self.cff.add(f"h{i}.example.com", "A", "192.0.2.1")
        self.assertEqual(len(p.list("example.com")), 150)
        pages = [r[2].get("page") for r in self.api.requests if r[1].endswith("/dns_records")]
        self.assertIn("2", pages)
        rid = p.create("example.com", Record("auth.porch.example.com", "A", "203.0.113.7"))
        body = [r[3] for r in self.api.requests if r[0] == "POST"][-1]
        self.assertEqual(body, {"type": "A", "name": "auth.porch.example.com",
                                "content": "203.0.113.7", "ttl": 300, "proxied": False})
        got = p.list("example.com", name="auth.porch.example.com", rtype="A")
        self.assertEqual([(r.id, r.content) for r in got], [(rid, "203.0.113.7")])
        p.update("example.com", rid, Record("auth.porch.example.com", "A", "203.0.113.8"))
        self.assertEqual(self.cff.records[rid]["content"], "203.0.113.8")
        self.assertFalse(self.cff.records[rid]["proxied"])
        t = p.create("example.com", Record("_acme-challenge.x.example.com", "TXT", "tok"))
        self.assertNotIn("proxied", [r[3] for r in self.api.requests if r[0] == "POST"][-1])
        self.assertEqual(p.list("example.com", name="_acme-challenge.x.example.com")[0].content, "tok")
        p.delete("example.com", t)
        self.assertNotIn(t, self.cff.records)

    def test_cloudflare_errors(self):
        p = self.cf(token="wrong-token-999999")
        with self.assertRaises(ProviderError) as cm:
            p.check("example.com")
        self.assertEqual(cm.exception.code, "dns.auth")
        self.assertIn("Zone:DNS:Edit", cm.exception.hint)
        self.assertNotIn("wrong-token", str(cm.exception) + cm.exception.hint)
        p = self.cf()
        with self.assertRaises(ProviderError) as cm:
            p.check("other.org")
        self.assertEqual(cm.exception.code, "dns.zone")
        self.cff.rate_limit = True
        p._zone_ids["example.com"] = "z1"
        with self.assertRaises(ProviderError) as cm:
            p.list("example.com")
        self.assertEqual(cm.exception.code, "dns.rate")
        dead = Cloudflare({"token": CF_TOKEN}, base_url="http://127.0.0.1:9")
        with self.assertRaises(ProviderError) as cm:
            dead.check("example.com")
        self.assertEqual(cm.exception.code, "dns.api")

    # ---- name.com -------------------------------------------------------------
    def nc(self, user=NC_USER, token=NC_TOKEN):
        self.ncf = NameComFake()
        self.api.handler = self.ncf
        return NameCom({"username": user, "token": token}, base_url=self.api.url + "/v4")

    def test_namecom_crud_and_pagination(self):
        p = self.nc()
        p.PER_PAGE = 2
        p.check("example.com")
        self.ncf.add("", "A", "192.0.2.1")
        self.ncf.add("www", "CNAME", "example.com")
        self.ncf.add("*.tunnel", "A", "192.0.2.1")
        recs = p.list("example.com")
        self.assertEqual(sorted(r.name for r in recs),
                         ["*.tunnel.example.com", "example.com", "www.example.com"])
        rid = p.create("example.com", Record("auth.porch.example.com", "A", "203.0.113.7", ttl=60))
        body = [r[3] for r in self.api.requests if r[0] == "POST"][-1]
        self.assertEqual(body, {"host": "auth.porch", "type": "A", "answer": "203.0.113.7",
                                "ttl": 300})   # clamped to the 300s minimum
        self.assertEqual([r.id for r in p.list("example.com", name="auth.porch.example.com")], [rid])
        p.update("example.com", rid, Record("auth.porch.example.com", "A", "203.0.113.9"))
        self.assertEqual(self.ncf.records[int(rid)]["answer"], "203.0.113.9")
        p.delete("example.com", rid)
        self.assertNotIn(int(rid), self.ncf.records)
        apex = p.create("example.com", Record("example.com", "TXT", "v=x"))
        self.assertEqual([r[3] for r in self.api.requests if r[0] == "POST"][-1]["host"], "")
        self.assertEqual([r.name for r in p.list("example.com", rtype="TXT")], ["example.com"])

    def test_namecom_errors(self):
        p = self.nc(token="bad-token-777777")
        with self.assertRaises(ProviderError) as cm:
            p.check("example.com")
        self.assertEqual(cm.exception.code, "dns.auth")
        self.assertIn("API Token", cm.exception.hint)
        self.assertNotIn("bad-token", str(cm.exception) + cm.exception.hint)
        p = self.nc()
        with self.assertRaises(ProviderError) as cm:
            p.check("other.org")
        self.assertEqual(cm.exception.code, "dns.zone")
        p = self.nc(user="")
        with self.assertRaises(ProviderError) as cm:
            p.check("example.com")
        self.assertIn("--dns-username", cm.exception.hint)
        with self.assertRaises(ProviderError):
            relative_name("auth.other.org", "example.com")


class RegistryAndDetectTest(unittest.TestCase):
    def test_registry_finds_providers(self):
        names = registry.providers()
        self.assertEqual(sorted(names), ["cloudflare", "manual", "namecom"])

    def test_detect(self):
        avail = {"cloudflare", "namecom", "manual"}
        d = detect.detect(["ns1dhq.name.com.", "ns2btz.name.com"], available=avail)
        self.assertEqual((d.provider, d.supported, d.known), ("namecom", True, True))
        d = detect.detect(["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"], available=avail)
        self.assertEqual(d.provider, "cloudflare")
        d = detect.detect(["ns-1.awsdns-01.org", "ns-2.awsdns-02.co.uk"], available=avail)
        self.assertEqual((d.provider, d.lexicon, d.title), ("manual", "route53", "Amazon Route 53"))
        d = detect.detect(["ns43.domaincontrol.com"], available=avail)
        self.assertEqual((d.provider, d.lexicon), ("manual", "godaddy"))
        d = detect.detect(["dns1.registrar-servers.com"], available=avail)
        self.assertEqual(d.lexicon, "namecheap")
        d = detect.detect(["ns.example.net"], available=avail)
        self.assertEqual((d.provider, d.known, d.lexicon), ("manual", False, None))
        self.assertEqual(detect.detect([], available=avail).provider, "manual")


class ManualTest(unittest.TestCase):
    def setUp(self):
        self.d = FakeDNS().add_zone("example.com", {"ns1.p.net": "192.0.2.53", "ns2.p.net": "192.0.2.54"})
        self.r = self.d.resolver()
        self.t = [0.0]

    def clock(self):
        return self.t[0]

    def test_table_and_manual_refuses_changes(self):
        recs = [Record("auth.example.com", "A", "203.0.113.7"),
                Record("*.tunnel.example.com", "A", "203.0.113.7")]
        t = manual.table(recs)
        self.assertIn("*.tunnel.example.com", t)
        self.assertIn("203.0.113.7", t)
        m = manual.Manual()
        m.check("example.com")
        with self.assertRaises(ProviderError) as cm:
            m.create("example.com", recs[0])
        self.assertEqual(cm.exception.code, "dns.manual")

    def test_wait_for_polls_until_authoritative_and_public(self):
        rec = Record("*.tunnel.example.com", "A", "203.0.113.7")
        polls = []

        def sleep(s):
            self.t[0] += s
            polls.append(s)
            if len(polls) == 2:   # the user adds it after two polls
                self.d.set("example.com", "*.tunnel.example.com", "A", ["203.0.113.7"])
        msgs = []
        ok, res = manual.wait_for(self.r, [rec], "example.com", clock=self.clock, sleep=sleep,
                                  timeout=600, interval=10, progress=msgs.append)
        self.assertTrue(ok)
        self.assertEqual(len(polls), 2)
        self.assertIn("waiting for DNS", msgs[0])
        # random probe label, asked of both NS and both public resolvers
        servers = {q[0] for q in self.d.queries if q[1].startswith("porch-check-")}
        self.assertTrue({"192.0.2.53", "192.0.2.54", "1.1.1.1", "8.8.8.8"} <= servers)

    def test_wait_for_times_out_and_describes(self):
        rec = Record("auth.example.com", "A", "203.0.113.7")
        self.d.set("example.com", "auth.example.com", "A", ["198.51.100.9"])

        def sleep(s):
            self.t[0] += s
        ok, res = manual.wait_for(self.r, [rec], "example.com", clock=self.clock, sleep=sleep,
                                  timeout=30, interval=10)
        self.assertFalse(ok)
        why = manual.describe_failure(res)
        self.assertIn("198.51.100.9", why[0])

    def test_matches(self):
        self.assertTrue(manual.matches(Record("a.x", "TXT", "v1"), ["v0", "v1"]))
        self.assertFalse(manual.matches(Record("a.x", "A", "192.0.2.1"), ["192.0.2.1", "192.0.2.2"]))
        self.assertTrue(manual.matches(Record("a.x", "AAAA", "2001:db8::1"), ["2001:0db8::1"]))
        self.assertFalse(manual.matches(Record("a.x", "A", "192.0.2.1"), None))


if __name__ == "__main__":
    unittest.main()

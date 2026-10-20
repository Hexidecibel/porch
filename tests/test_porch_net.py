"""lib/porch_setup/net: probe, router detection, reach (phone check). No real network."""

import io
import os
import shutil
import socket
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from email.message import Message

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "lib"))

import porch_config  # noqa: E402
from porch_setup.engine import make_context  # noqa: E402
from porch_setup.io import NullIO  # noqa: E402
from porch_setup.net import probe, reach, router  # noqa: E402
from porch_setup.redact import Redactor  # noqa: E402
from porch_setup.runner import FakeRunner  # noqa: E402

CFG = porch_config.load(env={"PORCH_CONFIG": "none"})

ROUTE = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
docker0\t0000C80A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
wlan0\t00000000\t0102A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
enp3s0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
"""

FIB = """Main:
  +-- 0.0.0.0/0 3 0 5
Local:
  +-- 0.0.0.0/0 3 0 5
     |-- 100.101.102.103
        /32 host LOCAL
     |-- 127.0.0.1
        /32 host LOCAL
     |-- 192.168.1.48
        /32 host LOCAL
     |-- 192.168.1.255
        /32 link BROADCAST
"""

FIB_VPS = FIB.replace("192.168.1.48", "51.15.20.7")

INET6 = """00000000000000000000000000000001 01 80 10 80       lo
fe800000000000005277b828c0d2700e 02 40 20 80   enp3s0
20010470c0de0001a031d597c6299ff6 02 40 00 01   enp3s0
20010470c0de00019e1b5301497308e2 02 40 00 00   enp3s0
fd7a115ca1e0000000000000a10157a2 04 80 00 80 tailscale0
20010db8000000000000000000000001 02 40 00 00   enp3s0
20010470c0de00010000000000000099 02 40 00 20   enp3s0
"""

ARP = """IP address       HW type     Flags       HW address            Mask     Device
192.168.1.32     0x1         0x2         00:17:88:64:43:68     *        enp3s0
192.168.1.1      0x1         0x2         94:18:65:dc:90:e5     *        enp3s0
"""


class Resp:
    def __init__(self, body, headers=None, status=200):
        self._b = io.BytesIO(body)
        self.headers = Message()
        for k, v in (headers or {}).items():
            self.headers[k] = v
        self.status = status

    def read(self, n=-1):
        return self._b.read(n)

    def getcode(self):
        return self.status

    def close(self):
        pass


def fake_http(routes):
    """routes: {url prefix: bytes | Exception | callable(req)}"""
    calls = []

    def http(req, timeout=None):
        url = req.full_url if isinstance(req, urllib.request.Request) else req
        calls.append(url)
        for prefix, v in routes.items():
            if url.startswith(prefix):
                if callable(v) and not isinstance(v, (bytes, Exception)):
                    return v(req)
                if isinstance(v, Exception):
                    raise v
                return Resp(v)
        raise urllib.error.URLError("no route")
    http.calls = calls
    return http


class Files(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def f(self, name, text):
        p = os.path.join(self.tmp, name)
        with open(p, "w") as fh:
            fh.write(text)
        return p


class ProbeHelpers(Files):
    def test_default_route_lowest_metric(self):
        self.assertEqual(probe.default_route(self.f("route", ROUTE)), ("enp3s0", "192.168.1.1"))
        self.assertEqual(probe.default_route(self.f("r2", ROUTE.splitlines()[0] + "\n")), (None, None))
        self.assertEqual(probe.default_route(os.path.join(self.tmp, "missing")), (None, None))

    def test_local_and_public_ipv4(self):
        p = self.f("fib", FIB)
        self.assertEqual(probe.local_ipv4s(p), ["100.101.102.103", "127.0.0.1", "192.168.1.48"])
        self.assertEqual(probe.host_public_ipv4(p), [])        # tailscale 100.x never counts
        self.assertEqual(probe.host_public_ipv4(self.f("vps", FIB_VPS)), ["51.15.20.7"])

    def test_global_ipv6(self):
        v6 = probe.global_ipv6(self.f("inet6", INET6))
        # stable first, temporary after; no ULA, link-local, doc prefix or deprecated
        self.assertEqual(v6, ["2001:470:c0de:1:9e1b:5301:4973:8e2", "2001:470:c0de:1:a031:d597:c629:9ff6"])

    def test_classify(self):
        c = probe.classify
        # classify needs a globally routable WAN, so not the 203.0.113.0/24 documentation range
        self.assertEqual(c({"wan_ipv4": "1.2.3.4", "public_ipv4": "1.2.3.4"}), (False, ""))
        self.assertTrue(c({"wan_ipv4": "100.70.1.2", "public_ipv4": "203.0.113.16"})[0])
        self.assertIn("double NAT", c({"wan_ipv4": "192.168.0.5", "public_ipv4": "1.2.3.4"})[1])
        self.assertIn("differs", c({"wan_ipv4": "5.6.7.8", "public_ipv4": "1.2.3.4"})[1])
        self.assertTrue(c({"wan_ipv4": None, "public_ipv4": "100.64.0.9"})[0])
        self.assertEqual(c({"host_public_ipv4": ["1.2.3.4"], "wan_ipv4": "10.0.0.1"}), (False, ""))
        self.assertEqual(c({"wan_ipv4": None, "public_ipv4": "1.2.3.4"}), (False, ""))
        self.assertTrue(probe.is_cgnat("100.127.255.255"))
        self.assertFalse(probe.is_public_v4("100.64.0.1"))
        self.assertTrue(probe.is_rfc1918("172.20.0.1"))

    def test_public_ipv4_needs_two_agreeing(self):
        svc = ("https://a/", "https://b/", "https://c/")
        h = fake_http({"https://a/": b"1.2.3.4\n", "https://b/": b"1.2.3.4"})
        self.assertEqual(probe.public_ipv4(h, svc), ("1.2.3.4", ["https://a/", "https://b/"], ""))
        self.assertNotIn("https://c/", h.calls)
        h = fake_http({"https://a/": b"1.2.3.4", "https://b/": b"5.6.7.8", "https://c/": b"<html>"})
        ip, _, err = probe.public_ipv4(h, svc)
        self.assertIsNone(ip)
        self.assertIn("disagree", err)
        h = fake_http({"https://a/": urllib.error.URLError("down"), "https://b/": b"1.2.3.4"})
        ip, src, err = probe.public_ipv4(h, svc)
        self.assertEqual((ip, src), (None, ["https://b/"]))
        self.assertIn("only one", err)
        h = fake_http({"https://a/": b"9.9.9.9", "https://b/": OSError("x"), "https://c/": b"9.9.9.9"})
        self.assertEqual(probe.public_ipv4(h, svc)[0], "9.9.9.9")

    def test_probe_wires_everything(self):
        # a globally routable WAN (not the 203.0.113.0/24 documentation range), so no CGNAT verdict
        class IGD:
            device = type("D", (), {"describe": lambda s: "ASUSTeK RT-AX86U"})()

            def as_dict(self):
                return {"location": "http://192.168.1.1:5000/d.xml", "service": "x", "info": {}}

            def external_ip(self):
                return "1.2.3.4"
        h = fake_http({"https://a/": b"1.2.3.4", "https://b/": b"1.2.3.4"})
        facts = probe.probe(h, route_path=self.f("route", ROUTE), fib_path=self.f("fib", FIB),
                            inet6_path=self.f("inet6", INET6), arp_path=self.f("arp", ARP),
                            find_igd=lambda: IGD(), echo_services=("https://a/", "https://b/"),
                            natpmp_probe=lambda gw, cip: {"natpmp": True, "pcp": False,
                                                          "external_ip": "1.2.3.4", "error": ""},
                            lan_ip_fn=lambda gw: "192.168.1.48")
        self.assertEqual(facts["gateway"], "192.168.1.1")
        self.assertEqual((facts["wan_ipv4"], facts["wan_source"]), ("1.2.3.4", "upnp"))
        self.assertFalse(facts["cgnat"])
        self.assertEqual(facts["router"]["brand"], "asus")
        self.assertEqual(facts["router"]["source"], "upnp")
        self.assertTrue(any("router WAN" in line for line in probe.summary(facts)))

    def test_probe_cgnat_via_natpmp(self):
        h = fake_http({"https://a/": b"203.0.113.50", "https://b/": b"203.0.113.50"})
        facts = probe.probe(h, route_path=self.f("route", ROUTE), fib_path=self.f("fib", FIB),
                            inet6_path=self.f("i6", ""), arp_path=self.f("arp", ARP),
                            find_igd=lambda: None, echo_services=("https://a/", "https://b/"),
                            natpmp_probe=lambda gw, cip: {"natpmp": True, "pcp": False,
                                                          "external_ip": "100.80.3.4", "error": ""},
                            lan_ip_fn=lambda gw: "192.168.1.48", detect_router=False)
        self.assertEqual(facts["wan_source"], "natpmp")
        self.assertTrue(facts["cgnat"])
        self.assertIn("100.64.0.0/10", facts["cgnat_reason"])
        self.assertEqual(facts["ipv6"], [])

    def test_lan_ipv4_loopback(self):
        self.assertEqual(probe.lan_ipv4("127.0.0.1"), "127.0.0.1")


class RouterTest(Files):
    def test_data_files_load(self):
        brands, generic = router.load_guides()
        ids = [b["id"] for b in brands]
        self.assertGreaterEqual(len(ids), 25)
        self.assertEqual(len(ids), len(set(ids)))
        for want in ("eero", "google", "xfinity", "netgear", "tplink", "asus", "linksys", "ubiquiti",
                     "att", "verizon", "spectrum"):
            self.assertIn(want, ids)
        for b in brands:
            for k in ("name", "admin_url", "menu", "match"):
                self.assertIn(k, b, b["id"])
        self.assertTrue(router.guide_for("eero")["app_only"])
        self.assertTrue(router.guide_for("google")["app_only"])
        self.assertEqual(router.guide_for("nope")["id"], "generic")
        self.assertIn("menu", generic)
        oui, _names = router.load_oui()
        self.assertGreaterEqual(len(set(oui.values())), 30)
        for prefix in oui:
            self.assertRegex(prefix, r"^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}$")

    def test_match_text_word_boundaries(self):
        self.assertEqual(router.match_text("NETGEAR Router Orbi Index"), "netgear")
        self.assertEqual(router.match_text("Xfinity Gateway (Technicolor XB7)"), "xfinity")
        self.assertEqual(router.match_text("TP-Link Deco X55"), "tplink_deco")
        self.assertIsNone(router.match_text("decoder"))
        self.assertIsNone(router.match_text(""))

    def test_oui_from_arp(self):
        arp = self.f("arp", ARP)
        self.assertEqual(router.arp_mac("192.168.1.1", arp), "94:18:65:dc:90:e5")
        self.assertIsNone(router.arp_mac("192.168.1.9", arp))
        self.assertEqual(router.oui_brand("94-18-65-dc-90-e5"), "netgear")
        d = router.detect_brand("192.168.1.1", arp_path=arp, fetch_http=False)
        self.assertEqual((d["brand"], d["source"]), ("netgear", "oui"))

    def test_gateway_http_title_and_realm(self):
        h = fake_http({"http://192.168.1.1/": b"<html><TITLE>Archer AX21 &amp; co</TITLE>"})
        self.assertEqual(router.gateway_http_text("192.168.1.1", h), "Archer AX21 & co")
        d = router.detect_brand("192.168.1.1", http=h, arp_path=self.f("arp", ""))
        self.assertEqual((d["brand"], d["source"]), ("tplink", "http"))

        hdrs = Message()
        hdrs["WWW-Authenticate"] = 'Basic realm="NETGEAR R7000"'
        err = urllib.error.HTTPError("http://192.168.1.1/", 401, "auth", hdrs, io.BytesIO(b""))
        h = fake_http({"http://192.168.1.1/": err})
        self.assertIn("NETGEAR R7000", router.gateway_http_text("192.168.1.1", h))
        h = fake_http({})
        self.assertEqual(router.gateway_http_text("192.168.1.1", h), "")
        d = router.detect_brand("192.168.1.1", http=h, arp_path=self.f("a2", ""))
        self.assertIsNone(d["brand"])


class ReachTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.runner = FakeRunner()
        self.io = NullIO()
        self.ctx = make_context(io=self.io, runner=self.runner, data_dir=self.tmp + "/data", cfg=CFG,
                                redactor=Redactor(), secrets_dir=self.tmp + "/s", sleep=lambda s: None)

    def get(self, pc, path, headers=None):
        req = urllib.request.Request(f"http://127.0.0.1:{pc.port}{path}", headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, b""

    def test_bind_server_range_and_never_9877(self):
        with self.assertRaises(reach.ReachError):      # 9877 is never even tried
            reach.bind_server(lo=9877, hi=9877)
        blocker = socket.socket()
        blocker.bind(("127.0.0.1", 0))
        p = blocker.getsockname()[1]
        try:
            with self.assertRaises(reach.ReachError):
                reach.bind_server(lo=p, hi=p)
        finally:
            blocker.close()

    def test_phone_check_hit(self):
        with reach.PhoneCheck(self.ctx, local_ips={"203.0.113.16"}) as pc:
            self.assertTrue(reach.PORT_RANGE[0] <= pc.port <= reach.PORT_RANGE[1])
            self.assertNotEqual(pc.port, 9877)
            url = pc.use_url("https://example.test/")
            self.assertEqual(url, "https://example.test/" + pc.nonce)
            self.assertEqual(self.get(pc, "/wrong")[0], 404)
            self.assertEqual(self.get(pc, "/")[0], 404)
            # from this LAN / our own public IP (hairpin): recorded, not accepted
            st, _ = self.get(pc, "/" + pc.nonce, {"X-Forwarded-For": "192.168.1.20"})
            self.assertEqual(st, 200)
            self.get(pc, "/" + pc.nonce, {"X-Forwarded-For": "203.0.113.16, 127.0.0.1"})
            self.assertIsNone(pc.wait(timeout=0.2, poll=0.05))
            self.assertTrue(any("Wi-Fi" in d["message"] for d in self.io.kinds("log")))
            st, body = self.get(pc, "/" + pc.nonce + "?x=1", {"X-Forwarded-For": "8.8.4.4, 127.0.0.1"})
            self.assertIn(b"It works", body)
            hit = pc.wait(timeout=2)
            self.assertEqual(hit["ip"], "8.8.4.4")
        self.assertEqual(self.runner.calls, [])     # no tunnel was started

    def test_tunnel_route_and_close(self):
        pc = reach.PhoneCheck(self.ctx, bin_dir="/opt/porch/bin")
        url = pc.open_tunnel(name="porch-reach-abcd")
        self.assertEqual(url, f"https://porch-reach-abcd.{CFG.tunnel_base}/{pc.nonce}")
        pc.show()
        pc.close()
        argvs = self.runner.argvs()
        self.assertEqual(argvs[0], ["/opt/porch/bin/tunnel", str(pc.port), "porch-reach-abcd", "--bg"])
        self.assertEqual(argvs[-1], ["/opt/porch/bin/status", "close", "porch-reach-abcd"])
        self.assertTrue(any(url in d["message"] for d in self.io.kinds("log")))
        self.assertEqual(self.io.kinds("phone_check")[0]["url"], url)

    def test_tunnel_failure(self):
        self.runner.on(lambda a: a[0].endswith("/tunnel"), returncode=1, stderr="frpc missing")
        ok, detail = reach.phone_check(self.ctx, timeout=0.1)
        self.assertFalse(ok)
        self.assertIn("frpc missing", detail)

    def test_phone_check_timeout(self):
        ok, detail = reach.phone_check(self.ctx, url="https://x.test/", timeout=0.1)
        self.assertFalse(ok)
        self.assertIn("no request", detail)

    def test_stack_ready(self):
        self.assertTrue(reach.stack_ready(self.ctx, connect=lambda p: None))

        def refuse(p):
            raise ConnectionRefusedError()
        self.assertFalse(reach.stack_ready(self.ctx, connect=refuse))


class EchoOverrideTest(unittest.TestCase):
    def test_env_echo_services(self):
        self.assertEqual(probe.env_echo_services({}), ())
        self.assertEqual(probe.env_echo_services({"PORCH_IP_ECHO": " http://a/x, ,http://b/y "}),
                         ("http://a/x", "http://b/y"))


if __name__ == "__main__":
    unittest.main()

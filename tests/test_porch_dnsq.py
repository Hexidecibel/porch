"""lib/porch_setup/dnsq.py: wire format, resolver, SOA walk, authoritative NS, TC -> TCP."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from porch_dns_fakes import FakeDNS  # noqa: E402
from porch_setup import dnsq  # noqa: E402


def world():
    d = FakeDNS().add_zone("example.com", {"ns1.prov.net": "192.0.2.53", "ns2.prov.net": "192.0.2.54"})
    d.set("example.com", "auth.porch.example.com", "A", ["203.0.113.7"])
    d.set("example.com", "*.tunnel.porch.example.com", "A", ["203.0.113.7"])
    d.set("example.com", "v6.example.com", "AAAA", ["2001:db8::7"])
    d.set("example.com", "www.example.com", "CNAME", ["auth.porch.example.com"])
    d.set("example.com", "_acme-challenge.tunnel.example.com", "TXT", ["one", "two"])
    d.set("example.com", "long.example.com", "TXT", ["x" * 600])
    return d


class WireTest(unittest.TestCase):
    def test_query_roundtrip_and_compression(self):
        q = dnsq.build_query("Auth.Example.COM.", "A", qid=0x1234)
        self.assertEqual(q[:2], b"\x12\x34")
        self.assertEqual(q[12:], dnsq.encode_name("auth.example.com") + b"\x00\x01\x00\x01")
        # hand-made answer whose record name is a pointer to the question (0xc00c)
        ans = (struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + q[12:]
               + b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([203, 0, 113, 9]))
        r = dnsq.parse_message(ans)
        self.assertEqual((r.id, r.rcode, r.tc), (0x1234, 0, False))
        self.assertEqual(r.answers[0].name, "auth.example.com")
        self.assertEqual(r.answers[0].data, "203.0.113.9")

    def test_rejects_bad_input(self):
        with self.assertRaises(dnsq.DNSError):
            dnsq.build_query("x.example.com", "MX")
        with self.assertRaises(dnsq.DNSError):
            dnsq.encode_name("a" * 64 + ".com")
        with self.assertRaises(dnsq.DNSError):
            dnsq.parse_message(b"\x00" * 5)
        loop = struct.pack(">HHHHHH", 1, 0x8180, 0, 1, 0, 0) + b"\xc0\x0c"
        with self.assertRaises(dnsq.DNSError):
            dnsq.parse_message(loop)

    def test_txt_unquote(self):
        self.assertEqual(dnsq.txt_unquote('"abc"'), "abc")
        self.assertEqual(dnsq.txt_unquote('"ab" "cd"'), "abcd")
        self.assertEqual(dnsq.txt_unquote("plain"), "plain")


class ResolverTest(unittest.TestCase):
    def setUp(self):
        self.d = world()
        self.r = self.d.resolver()

    def test_types(self):
        self.assertEqual(self.r.resolve("auth.porch.example.com", "A"), ["203.0.113.7"])
        self.assertEqual(self.r.resolve("v6.example.com", "AAAA"), ["2001:db8::7"])
        self.assertEqual(sorted(self.r.resolve("_acme-challenge.tunnel.example.com", "TXT")),
                         ["one", "two"])
        self.assertEqual(self.r.resolve("long.example.com", "TXT"), ["x" * 600])
        self.assertEqual(self.r.resolve("www.example.com", "CNAME"), ["auth.porch.example.com"])
        self.assertEqual(self.r.resolve("www.example.com", "A"), ["203.0.113.7"])   # CNAME chased
        self.assertEqual(self.r.resolve("zz.tunnel.porch.example.com", "A"), ["203.0.113.7"])
        self.assertEqual(self.r.resolve("nope.example.com", "A"), [])
        soa = self.r.resolve("example.com", "SOA")[0]
        self.assertEqual(soa["mname"], "ns1.prov.net")

    def test_zone_apex_and_ns(self):
        self.assertEqual(self.r.zone_apex("auth.porch.example.com"), "example.com")
        self.assertEqual(self.r.zone_apex("example.com"), "example.com")
        self.assertEqual(self.r.zone_apex("deep.missing.example.com"), "example.com")
        self.assertEqual(self.r.ns("example.com"), ["ns1.prov.net", "ns2.prov.net"])
        self.assertEqual(self.r.ns_addresses("example.com"), ["192.0.2.53", "192.0.2.54"])
        with self.assertRaises(dnsq.DNSError):
            self.r.zone_apex("unregistered.invalid")

    def test_authoritative_sees_change_before_public(self):
        self.d.public_view = {k: dict(v) for k, v in self.d.zones.items()}
        self.d.set("example.com", "new.example.com", "A", ["198.51.100.1"])
        auth = self.r.authoritative("new.example.com", "A")
        self.assertEqual(auth, {"192.0.2.53": ["198.51.100.1"], "192.0.2.54": ["198.51.100.1"]})
        self.assertEqual(self.r.resolve("new.example.com", "A", server="1.1.1.1"), [])
        # asked the NS directly
        self.assertIn(("192.0.2.53", "new.example.com", "A"), self.d.queries)

    def test_dead_server_falls_through_and_retries(self):
        self.d.dead.add("1.1.1.1")
        self.assertEqual(self.r.resolve("auth.porch.example.com", "A"), ["203.0.113.7"])
        tried = [q[0] for q in self.d.queries]
        self.assertEqual(tried.count("1.1.1.1"), 2)       # retries=2
        self.assertIn("8.8.8.8", tried)
        with self.assertRaises(dnsq.DNSTimeout):
            self.r.resolve("auth.porch.example.com", "A", server="1.1.1.1")
        self.d.dead.add("192.0.2.54")
        auth = self.r.authoritative("auth.porch.example.com", "A", zone="example.com")
        self.assertEqual(auth["192.0.2.54"], None)

    def test_truncated_udp_retries_over_tcp(self):
        self.d.truncate_udp = True
        seen = []
        orig = self.d.transport

        def t(server, port, payload, tcp, timeout):
            seen.append(tcp)
            return orig(server, port, payload, tcp, timeout)
        r = dnsq.Resolver(transport=t)
        self.assertEqual(r.resolve("auth.porch.example.com", "A"), ["203.0.113.7"])
        self.assertEqual(seen, [False, True])

    def test_split_server(self):
        self.assertEqual(dnsq._split_server("1.2.3.4"), ("1.2.3.4", 53))
        self.assertEqual(dnsq._split_server("127.0.0.1:5300"), ("127.0.0.1", 5300))
        self.assertEqual(dnsq._split_server("[::1]:5300"), ("::1", 5300))
        self.assertEqual(dnsq._split_server("::1"), ("::1", 53))


class LoopbackSocketTest(unittest.TestCase):
    """The default socket transport against a real loopback UDP/TCP server."""

    def test_udp_and_tcp_fallback(self):
        d = world()
        port, stop = d.serve("192.0.2.53")
        self.addCleanup(stop)
        r = dnsq.Resolver(servers=[f"127.0.0.1:{port}"], timeout=2)
        self.assertEqual(r.resolve("auth.porch.example.com", "A"), ["203.0.113.7"])
        d.truncate_udp = True
        self.assertEqual(sorted(r.resolve("_acme-challenge.tunnel.example.com", "TXT")),
                         ["one", "two"])

    def test_timeout(self):
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        self.addCleanup(s.close)
        r = dnsq.Resolver(servers=[f"127.0.0.1:{s.getsockname()[1]}"], timeout=0.2, retries=1)
        with self.assertRaises(dnsq.DNSTimeout):
            r.resolve("x.example.com", "A")


if __name__ == "__main__":
    unittest.main()

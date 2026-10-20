"""lib/porch_setup/net/natpmp.py against a loopback UDP NAT-PMP / PCP responder."""

import os
import socket
import struct
import sys
import threading
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "lib"))

from porch_setup.net import natpmp  # noqa: E402

EXT = "203.0.113.16"


class Responder:
    """NAT-PMP (v0) + PCP (v2) gateway. taken = external ports already in use."""

    def __init__(self, natpmp_on=True, pcp_on=True, drop_first=0, taken=()):
        self.natpmp_on, self.pcp_on = natpmp_on, pcp_on
        self.drop = drop_first
        self.taken = set(taken)
        self.maps = {}          # (proto, internal) -> (external, lifetime)
        self.received = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def close(self):
        self.sock.close()

    def _loop(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(1100)
            except OSError:
                return
            self.received.append(data)
            if self.drop:
                self.drop -= 1
                continue
            resp = self.handle(data)
            if resp:
                self.sock.sendto(resp, addr)

    def handle(self, d):
        ver, op = d[0], d[1]
        if ver == 0:
            if not self.natpmp_on:
                if self.pcp_on:   # PCP server answering a v0 request: UNSUPP_VERSION
                    return struct.pack("!BBBBI", 2, 0x80 | op, 0, 1, 0) + b"\0" * 20
                return None
            if op == 0:
                return struct.pack("!BBHI", 0, 128, 0, 1234) + socket.inet_aton(EXT)
            _v, op, _r, iport, eport, life = struct.unpack("!BBHHHI", d[:12])
            proto = "tcp" if op == 2 else "udp"
            if life == 0:
                self.maps.pop((proto, iport), None)
                return struct.pack("!BBHIHHI", 0, 128 + op, 0, 1234, iport, 0, 0)
            ext = eport
            while ext in self.taken:
                ext += 1
            self.maps[(proto, iport)] = (ext, min(life, 3600))
            return struct.pack("!BBHIHHI", 0, 128 + op, 0, 1234, iport, ext, min(life, 3600))
        if ver == 2 and self.pcp_on:
            life = struct.unpack("!I", d[4:8])[0]
            if op == 0:
                return struct.pack("!BBBBII", 2, 0x80, 0, 0, 0, 1234) + b"\0" * 12
            if op == 1:
                nonce, proto_n = d[24:36], d[36]
                iport, eport = struct.unpack("!HH", d[40:44])
                proto = "tcp" if proto_n == 6 else "udp"
                if life == 0:
                    self.maps.pop((proto, iport), None)
                    eport = 0
                else:
                    self.maps[(proto, iport)] = (eport, life)
                ext16 = natpmp._v4_mapped(EXT)
                return (struct.pack("!BBBBII", 2, 0x81, 0, 0, life, 1234) + b"\0" * 12 + nonce
                        + struct.pack("!B3xHH", proto_n, iport, eport) + ext16)
        return None


class NatPMPTest(unittest.TestCase):
    def mk(self, **kw):
        r = Responder(**kw)
        self.addCleanup(r.close)
        return r, natpmp.Client("127.0.0.1", port=r.port, tries=3, first_timeout=0.05)

    def test_external_address(self):
        r, c = self.mk()
        self.assertEqual(c.external_address(), EXT)
        self.assertEqual(r.received[0], b"\x00\x00")

    def test_retry_after_lost_packet(self):
        r, c = self.mk(drop_first=1)
        self.assertEqual(c.external_address(), EXT)
        self.assertEqual(len(r.received), 2)

    def test_map_unmap(self):
        r, c = self.mk()
        self.assertEqual(c.map("tcp", 443, 443, 604800), (443, 3600))
        self.assertEqual(r.maps[("tcp", 443)], (443, 3600))
        c.unmap("tcp", 443)
        self.assertNotIn(("tcp", 443), r.maps)

    def test_map_gets_other_port_when_taken(self):
        r, c = self.mk(taken={80})
        self.assertEqual(c.map("tcp", 80, 80, 7200)[0], 81)

    def test_no_response(self):
        r, c = self.mk(natpmp_on=False, pcp_on=False)
        with self.assertRaises(natpmp.NoResponse):
            c.external_address()

    def test_pcp_only(self):
        r, c = self.mk(natpmp_on=False)
        with self.assertRaises(natpmp.NatPMPError) as cm:
            c.external_address()
        self.assertEqual(cm.exception.code, "pcp-only")
        self.assertTrue(c.pcp_announce("192.168.1.48"))
        nonce = os.urandom(12)
        res = c.pcp_map("tcp", 7000, 7000, 7200, "192.168.1.48", nonce)
        self.assertEqual(res, {"external_ip": EXT, "external_port": 7000, "lifetime": 7200,
                               "nonce": nonce.hex()})
        req = r.received[-1]
        self.assertEqual(req[8:24], natpmp._v4_mapped("192.168.1.48"))
        c.pcp_unmap("tcp", 7000, "192.168.1.48", nonce.hex())
        self.assertNotIn(("tcp", 7000), r.maps)

    def test_probe(self):
        r, _ = self.mk()
        p = natpmp.probe("127.0.0.1", port=r.port, client_ip="192.168.1.48")
        self.assertEqual((p["natpmp"], p["pcp"], p["external_ip"]), (True, True, EXT))
        r2, _ = self.mk(natpmp_on=False)
        p = natpmp.probe("127.0.0.1", port=r2.port)
        self.assertEqual((p["natpmp"], p["pcp"], p["external_ip"]), (False, True, None))

    def test_probe_refused_port(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        p = natpmp.probe("127.0.0.1", port=port, tries=1)
        self.assertFalse(p["natpmp"] or p["pcp"])


if __name__ == "__main__":
    unittest.main()

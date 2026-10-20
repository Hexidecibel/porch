"""NAT-PMP (RFC 6886) and PCP (RFC 6887) over UDP 5351 to the gateway.

    c = Client("192.168.1.1")
    c.external_address()            # NAT-PMP opcode 0 (read-only) -> "203.0.113.16"
    c.pcp_announce()                # PCP ANNOUNCE (read-only) -> True if a PCP server answers
    c.map("tcp", 443, 443, 7200)    # NAT-PMP map -> (external port, lifetime)
    c.unmap("tcp", 443)             # lifetime 0
    c.pcp_map("tcp", 443, 443, 7200, client_ip="192.168.1.48", nonce=b"...12 bytes...")

Tests point `port` at a loopback responder (and set gateway to 127.0.0.1).
"""

import ipaddress
import os
import socket
import struct

PORT = 5351
OP_ADDR, OP_MAP_UDP, OP_MAP_TCP = 0, 1, 2
PCP_VERSION = 2
PCP_ANNOUNCE, PCP_MAP = 0, 1
PROTO_NUM = {"tcp": 6, "udp": 17}

RESULTS = {0: "success", 1: "unsupported version", 2: "not authorized / refused",
           3: "network failure", 4: "out of resources", 5: "unsupported opcode"}
PCP_RESULTS = {0: "success", 1: "unsupported version", 2: "not authorized", 3: "malformed request",
               4: "unsupported opcode", 5: "unsupported option", 6: "malformed option",
               7: "network failure", 8: "no resources", 9: "unsupported protocol",
               10: "user exceeded quota", 11: "cannot provide external",
               12: "address mismatch", 13: "excessive remote peers"}


class NatPMPError(Exception):
    def __init__(self, message, code=None):
        self.code = code
        super().__init__(message)


class NoResponse(NatPMPError):
    pass


def _v4_mapped(ip):
    return ipaddress.IPv6Address("::ffff:" + str(ipaddress.IPv4Address(ip))).packed


def _unmapped(b16):
    a = ipaddress.IPv6Address(b16)
    return str(a.ipv4_mapped) if a.ipv4_mapped else str(a)


class Client:
    def __init__(self, gateway, port=PORT, tries=4, first_timeout=0.25):
        self.gateway = gateway
        self.port = port
        self.tries = tries
        self.first_timeout = first_timeout

    def _exchange(self, payload, accept):
        """Send with RFC 6886 doubling retries; return the first datagram from
        the gateway that `accept(data)` likes."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((self.gateway, self.port))
            t = self.first_timeout
            for _ in range(self.tries):
                try:
                    sock.send(payload)
                except OSError as e:
                    raise NoResponse(f"cannot send to {self.gateway}:{self.port}: {e}") from None
                sock.settimeout(t)
                try:
                    while True:
                        data = sock.recv(1100)
                        if accept(data):
                            return data
                except socket.timeout:
                    t *= 2
                except ConnectionRefusedError:
                    raise NoResponse(f"{self.gateway}:{self.port} refused (no NAT-PMP/PCP)") from None
                except OSError as e:
                    raise NoResponse(str(e)) from None
        finally:
            sock.close()
        raise NoResponse(f"no NAT-PMP/PCP answer from {self.gateway}")

    # ---- NAT-PMP --------------------------------------------------------------
    def external_address(self):
        data = self._exchange(struct.pack("!BB", 0, OP_ADDR),
                              lambda d: (len(d) >= 2 and d[1] == 128 + OP_ADDR) or
                              (len(d) >= 4 and d[0] == PCP_VERSION))
        if data[0] == PCP_VERSION:
            # A PCP-only server answers a v0 request with UNSUPP_VERSION.
            raise NatPMPError("gateway speaks PCP only", code="pcp-only")
        if len(data) < 12:
            raise NatPMPError("short NAT-PMP reply")
        _v, _op, result, _epoch = struct.unpack("!BBHI", data[:8])
        if result:
            raise NatPMPError(f"NAT-PMP: {RESULTS.get(result, result)}", code=result)
        return socket.inet_ntoa(data[8:12])

    def map(self, proto, internal_port, external_port, lifetime=7200):
        op = OP_MAP_TCP if proto.lower() == "tcp" else OP_MAP_UDP
        req = struct.pack("!BBHHHI", 0, op, 0, int(internal_port), int(external_port), int(lifetime))
        data = self._exchange(req, lambda d: len(d) >= 16 and d[1] == 128 + op
                              and struct.unpack("!H", d[8:10])[0] == int(internal_port))
        _v, _op, result, _epoch, _ip, mapped, life = struct.unpack("!BBHIHHI", data[:16])
        if result:
            raise NatPMPError(f"NAT-PMP map: {RESULTS.get(result, result)}", code=result)
        return mapped, life

    def unmap(self, proto, internal_port):
        return self.map(proto, internal_port, 0, 0)

    # ---- PCP ------------------------------------------------------------------
    def _pcp_header(self, opcode, lifetime, client_ip):
        return struct.pack("!BBHI", PCP_VERSION, opcode, 0, int(lifetime)) + _v4_mapped(client_ip)

    def pcp_announce(self, client_ip="0.0.0.0"):
        """True when a PCP server answers ANNOUNCE (read-only)."""
        try:
            data = self._exchange(self._pcp_header(PCP_ANNOUNCE, 0, client_ip),
                                  lambda d: len(d) >= 4 and d[0] == PCP_VERSION and d[1] == 0x80)
        except NoResponse:
            return False
        return data[3] == 0

    def pcp_map(self, proto, internal_port, external_port, lifetime, client_ip, nonce=None,
                external_ip="0.0.0.0"):
        """-> {"external_ip", "external_port", "lifetime", "nonce"(hex)}. Keep
        the nonce: a later delete (lifetime 0) must reuse it."""
        nonce = nonce or os.urandom(12)
        proto_n = PROTO_NUM[proto.lower()]
        payload = (self._pcp_header(PCP_MAP, lifetime, client_ip) + nonce
                   + struct.pack("!B3xHH", proto_n, int(internal_port), int(external_port))
                   + _v4_mapped(external_ip))
        data = self._exchange(payload, lambda d: len(d) >= 60 and d[0] == PCP_VERSION
                              and d[1] == 0x80 | PCP_MAP and d[24:36] == nonce)
        result = data[3]
        life = struct.unpack("!I", data[4:8])[0]
        if result:
            raise NatPMPError(f"PCP map: {PCP_RESULTS.get(result, result)}", code=result)
        ext_port = struct.unpack("!H", data[42:44])[0]
        return {"external_ip": _unmapped(data[44:60]), "external_port": ext_port,
                "lifetime": life, "nonce": nonce.hex()}

    def pcp_unmap(self, proto, internal_port, client_ip, nonce_hex):
        return self.pcp_map(proto, internal_port, 0, 0, client_ip, bytes.fromhex(nonce_hex))


def probe(gateway, port=PORT, client_ip="0.0.0.0", tries=3):
    """Read-only: {"natpmp": bool, "pcp": bool, "external_ip": str|None, "error": str}."""
    c = Client(gateway, port, tries=tries)
    out = {"natpmp": False, "pcp": False, "external_ip": None, "error": ""}
    try:
        out["external_ip"] = c.external_address()
        out["natpmp"] = True
    except NatPMPError as e:
        out["error"] = str(e)
        if e.code == "pcp-only":
            out["pcp"] = True
    if not out["pcp"] and not out["natpmp"] and isinstance(out["error"], str) and "refused" in out["error"]:
        return out
    if not out["pcp"]:
        out["pcp"] = c.pcp_announce(client_ip)
    return out

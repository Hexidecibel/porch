"""Minimal stdlib DNS client (RFC 1035 wire format) for porch setup.

This is `ctx.dns`. It asks a *specific* server, which `dig +short` from the
system resolver can't promise, and it is how setup knows a record is live on
the zone's authoritative name servers before ACME or a user relies on it.

    r = Resolver()                                  # 1.1.1.1, 8.8.8.8
    r.resolve("auth.example.com", "A")              # ['203.0.113.7']
    r.resolve("x.example.com", "TXT", server="198.51.100.1")
    r.zone_apex("auth.porch.example.com")           # 'example.com' (SOA walk)
    r.ns("example.com")                             # ['ns1.host.net', ...]
    r.ns_addresses("example.com")                   # ['198.51.100.1', ...]
    r.authoritative("auth.example.com", "A")        # {ns ip: [values]}

Supported types: A, AAAA, NS, SOA, TXT, CNAME. UDP first, TCP when the
answer comes back truncated (TC). Retries per server, then the next server.

Tests pass `transport=fn(server, port, payload, tcp, timeout) -> bytes` (or
use the loopback server in tests/test_porch_dnsq.py); nothing here touches the
network unless the default transport is used.
"""

import ipaddress
import random
import socket
import struct
from dataclasses import dataclass, field
from typing import List

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "TXT": 16, "AAAA": 28}
TYPE_NAMES = {v: k for k, v in TYPES.items()}
CLASS_IN = 1

NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED = 0, 1, 2, 3, 4, 5
RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
               5: "REFUSED"}

PUBLIC_RESOLVERS = ("1.1.1.1", "8.8.8.8")


class DNSError(Exception):
    pass


class DNSTimeout(DNSError):
    pass


@dataclass
class RR:
    name: str           # owner, lower case, no trailing dot
    type: str           # "A", ... or "TYPE<n>" for anything else
    ttl: int
    data: object        # str for A/AAAA/NS/CNAME/TXT (TXT strings joined), dict for SOA


@dataclass
class Response:
    id: int
    rcode: int
    aa: bool
    tc: bool
    answers: List[RR] = field(default_factory=list)
    authority: List[RR] = field(default_factory=list)
    additional: List[RR] = field(default_factory=list)
    server: str = ""

    @property
    def rcode_name(self):
        return RCODE_NAMES.get(self.rcode, str(self.rcode))


def norm(name):
    name = (name or "").strip().lower()
    return name[:-1] if name.endswith(".") else name


# ---- wire format ---------------------------------------------------------------

def encode_name(name):
    name = norm(name)
    out = b""
    if name:
        for label in name.split("."):
            b = label.encode("idna") if not label.isascii() else label.encode("ascii")
            if not b or len(b) > 63:
                raise DNSError(f"bad DNS label in {name!r}")
            out += bytes([len(b)]) + b
    if len(out) + 1 > 255:
        raise DNSError(f"name too long: {name!r}")
    return out + b"\x00"


def build_query(name, rtype, qid=None, rd=True):
    t = TYPES.get(rtype.upper()) if isinstance(rtype, str) else int(rtype)
    if not t:
        raise DNSError(f"unsupported record type {rtype!r}")
    qid = random.randint(0, 0xFFFF) if qid is None else qid
    flags = 0x0100 if rd else 0
    return struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 0) + encode_name(name) + struct.pack(">HH", t, CLASS_IN)


def _read_name(buf, off):
    labels, jumped, end, hops = [], False, off, 0
    while True:
        if off >= len(buf):
            raise DNSError("truncated name")
        n = buf[off]
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                raise DNSError("truncated pointer")
            ptr = ((n & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                end = off + 2
            jumped = True
            off = ptr
            hops += 1
            if hops > 64:
                raise DNSError("name compression loop")
            continue
        if n & 0xC0:
            raise DNSError("bad label type")
        off += 1
        if n == 0:
            break
        labels.append(buf[off:off + n].decode("ascii", "replace"))
        off += n
    return ".".join(labels).lower(), (end if jumped else off)


def _rdata(buf, off, rdlen, t):
    seg = buf[off:off + rdlen]
    if len(seg) != rdlen:
        raise DNSError("truncated rdata")
    if t == 1 and rdlen == 4:
        return socket.inet_ntop(socket.AF_INET, seg)
    if t == 28 and rdlen == 16:
        return socket.inet_ntop(socket.AF_INET6, seg)
    if t in (2, 5):
        return _read_name(buf, off)[0]
    if t == 16:
        parts, i = [], 0
        while i < len(seg):
            n = seg[i]
            parts.append(seg[i + 1:i + 1 + n].decode("utf-8", "replace"))
            i += 1 + n
        return "".join(parts)
    if t == 6:
        mname, o = _read_name(buf, off)
        rname, o = _read_name(buf, o)
        serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", buf[o:o + 20])
        return {"mname": mname, "rname": rname, "serial": serial, "refresh": refresh,
                "retry": retry, "expire": expire, "minimum": minimum}
    return seg.hex()


def parse_message(buf):
    if len(buf) < 12:
        raise DNSError("short DNS message")
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", buf[:12])
    off = 12
    for _ in range(qd):
        _, off = _read_name(buf, off)
        off += 4
    resp = Response(qid, flags & 0x000F, bool(flags & 0x0400), bool(flags & 0x0200))
    for count, bucket in ((an, resp.answers), (ns, resp.authority), (ar, resp.additional)):
        for _ in range(count):
            name, off = _read_name(buf, off)
            if off + 10 > len(buf):
                raise DNSError("truncated record")
            t, _cls, ttl, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
            off += 10
            bucket.append(RR(name, TYPE_NAMES.get(t, f"TYPE{t}"), ttl, _rdata(buf, off, rdlen, t)))
            off += rdlen
    return resp


# ---- transport -------------------------------------------------------------------

def _family(server):
    try:
        return socket.AF_INET6 if ipaddress.ip_address(server).version == 6 else socket.AF_INET
    except ValueError:
        return socket.AF_INET


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise DNSError("connection closed mid-answer")
        data += chunk
    return data


def socket_transport(server, port, payload, tcp, timeout):
    """The default transport: one UDP datagram, or one TCP exchange."""
    try:
        if tcp:
            with socket.create_connection((server, port), timeout=timeout) as s:
                s.settimeout(timeout)
                s.sendall(struct.pack(">H", len(payload)) + payload)
                (n,) = struct.unpack(">H", _recv_exact(s, 2))
                return _recv_exact(s, n)
        with socket.socket(_family(server), socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload, (server, port))
            while True:
                data, _addr = s.recvfrom(65535)
                if data[:2] == payload[:2]:
                    return data
    except socket.timeout:
        raise DNSTimeout(f"no answer from {server} within {timeout}s") from None
    except OSError as e:
        raise DNSError(f"{server}: {e.strerror or e}") from None


def _split_server(server):
    """'1.2.3.4' / '1.2.3.4:53' / '[::1]:53' / '::1' -> (host, port)."""
    s = server.strip()
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else 53
    if s.count(":") == 1:
        host, port = s.split(":")
        return host, int(port)
    return s, 53


# ---- resolver ----------------------------------------------------------------------

class Resolver:
    def __init__(self, servers=PUBLIC_RESOLVERS, timeout=3.0, retries=2, transport=None):
        self.servers = list(servers)
        self.timeout = timeout
        self.retries = retries
        self.transport = transport or socket_transport
        self._ns_cache = {}

    # one question, one server (with retries and the TC -> TCP fallback)
    def _ask(self, server, name, rtype, rd=True):
        host, port = _split_server(server)
        last = None
        for _ in range(max(1, self.retries)):
            q = build_query(name, rtype, rd=rd)
            try:
                raw = self.transport(host, port, q, False, self.timeout)
                resp = parse_message(raw)
                if resp.id != struct.unpack(">H", q[:2])[0]:
                    raise DNSError("answer id mismatch")
                if resp.tc:
                    resp = parse_message(self.transport(host, port, q, True, self.timeout))
                resp.server = server
                return resp
            except DNSError as e:
                last = e
        raise last or DNSTimeout(f"no answer from {server}")

    def query(self, name, rtype, server=None, rd=True):
        """A Response from `server`, else from the first configured server that
        answers (SERVFAIL/REFUSED move on to the next one)."""
        servers = [server] if server else self.servers
        last = None
        for s in servers:
            try:
                resp = self._ask(s, name, rtype, rd=rd)
            except DNSError as e:
                last = e
                continue
            if resp.rcode in (SERVFAIL, REFUSED) and not server and s != servers[-1]:
                last = DNSError(f"{s}: {resp.rcode_name}")
                continue
            return resp
        raise last or DNSError("no DNS servers configured")

    def resolve(self, name, rtype, server=None):
        """Values of type `rtype` for `name`, following CNAMEs inside the answer.
        [] on NXDOMAIN / no data; DNSError on SERVFAIL/REFUSED/timeouts."""
        rtype = rtype.upper()
        resp = self.query(name, rtype, server=server)
        if resp.rcode == NXDOMAIN:
            return []
        if resp.rcode != NOERROR:
            raise DNSError(f"{resp.server}: {resp.rcode_name} for {norm(name)} {rtype}")
        want, seen = norm(name), set()
        while True:
            vals = [rr.data for rr in resp.answers if rr.name == want and rr.type == rtype]
            if vals or rtype == "CNAME":
                return vals
            cn = [rr.data for rr in resp.answers if rr.name == want and rr.type == "CNAME"]
            if not cn or cn[0] in seen:
                return []
            seen.add(want)
            want = cn[0]

    def zone_apex(self, name, server=None):
        """The zone that holds `name` (SOA walk). DNSError when none is found."""
        name = norm(name)
        labels = name.split(".")
        for i in range(len(labels) - 1):
            cand = ".".join(labels[i:])
            resp = self.query(cand, "SOA", server=server)
            if resp.rcode not in (NOERROR, NXDOMAIN):
                raise DNSError(f"{resp.server}: {resp.rcode_name} looking up the zone of {name}")
            for rr in resp.answers:
                if rr.type == "SOA":
                    return rr.name
            for rr in resp.authority:
                if rr.type == "SOA" and (cand == rr.name or cand.endswith("." + rr.name)):
                    if rr.name.count(".") >= 1:
                        return rr.name
        raise DNSError(f"no zone (SOA) found for {name}: is the domain registered?")

    def ns(self, zone, server=None):
        vals = self.resolve(zone, "NS", server=server)
        return sorted(norm(v) for v in vals)

    def ns_addresses(self, zone, v6=False):
        """IPs of the zone's authoritative name servers (cached per zone)."""
        zone = norm(zone)
        key = (zone, v6)
        if key in self._ns_cache:
            return list(self._ns_cache[key])
        addrs = []
        for n in self.ns(zone):
            for t in ("A", "AAAA") if v6 else ("A",):
                try:
                    for ip in self.resolve(n, t):
                        if ip not in addrs:
                            addrs.append(ip)
                except DNSError:
                    continue
        if not addrs:
            raise DNSError(f"none of {zone}'s name servers resolve to an address")
        self._ns_cache[key] = addrs
        return list(addrs)

    def authoritative(self, name, rtype, zone=None):
        """{ns ip: values or None (no answer)} asked of every authoritative NS
        of `zone` (default: found by SOA walk), non-recursively."""
        zone = zone or self.zone_apex(name)
        out = {}
        for ip in self.ns_addresses(zone):
            try:
                out[ip] = self.resolve(name, rtype, server=ip)
            except DNSError:
                out[ip] = None
        return out


def txt_unquote(value):
    """TXT values are stored unquoted here; providers that return quoted
    content are normalized through this."""
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] == '"':
        v = v[1:-1]
    return v.replace('" "', "")

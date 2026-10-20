"""Shared fakes for the porch DNS / ACME tests (no network).

FakeDNS: an in-memory authoritative + recursive "internet" that answers
dnsq wire-format queries through Resolver(transport=fake.transport), or over
real loopback UDP/TCP sockets via serve().
FakeProvider: an in-memory DNS provider zone that records each call and can
publish its records into a FakeDNS (optionally only after N polls)."""

import os
import socket
import socketserver
import struct
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from porch_setup import dnsq  # noqa: E402
from porch_setup.dns.base import Provider, ProviderError, Record  # noqa: E402


def _rdata(rtype, value):
    if rtype == "A":
        return socket.inet_pton(socket.AF_INET, value)
    if rtype == "AAAA":
        return socket.inet_pton(socket.AF_INET6, value)
    if rtype in ("NS", "CNAME"):
        return dnsq.encode_name(value)
    if rtype == "TXT":
        b = value.encode()
        out = b""
        for i in range(0, max(len(b), 1), 255):
            chunk = b[i:i + 255]
            out += bytes([len(chunk)]) + chunk
        return out
    if rtype == "SOA":
        return (dnsq.encode_name(value.get("mname", "ns1." + "x")) + dnsq.encode_name("hostmaster.x")
                + struct.pack(">IIIII", 1, 7200, 3600, 1209600, value.get("minimum", 300)))
    raise ValueError(rtype)


def _rr(name, rtype, value, ttl=300):
    rd = _rdata(rtype, value)
    return dnsq.encode_name(name) + struct.pack(">HHIH", dnsq.TYPES[rtype], 1, ttl, len(rd)) + rd


class FakeDNS:
    """zones: {zone: {(name, type): [values]}} served by `ns_ips[zone]`.
    Public resolvers (1.1.1.1, 8.8.8.8, ...) see `public` (default: the
    union of all zones). Unknown servers time out."""

    def __init__(self):
        self.zones = {}
        self.ns_ips = {}
        self.public_view = None       # None: same as authoritative
        self.truncate_udp = False
        self.queries = []
        self.dead = set()

    def add_zone(self, zone, ns_names_ips):
        """ns_names_ips: {"ns1.prov.net": "192.0.2.53", ...}"""
        zone = dnsq.norm(zone)
        self.zones.setdefault(zone, {})
        self.zones[zone][(zone, "SOA")] = [{"mname": list(ns_names_ips)[0]}]
        self.zones[zone][(zone, "NS")] = list(ns_names_ips)
        self.ns_ips[zone] = list(ns_names_ips.values())
        for n, ip in ns_names_ips.items():
            self.set_global(n, "A", [ip])
        return self

    def set_global(self, name, rtype, values):
        z = self.zones.setdefault("_glue", {})
        z[(dnsq.norm(name), rtype)] = list(values)

    def set(self, zone, name, rtype, values):
        self.zones[dnsq.norm(zone)][(dnsq.norm(name), rtype)] = list(values)

    def get(self, zone, name, rtype):
        return list(self.zones[dnsq.norm(zone)].get((dnsq.norm(name), rtype), []))

    def _zone_for(self, name):
        best = None
        for z in self.zones:
            if z == "_glue":
                continue
            if name == z or name.endswith("." + z):
                if best is None or len(z) > len(best):
                    best = z
        return best

    def _lookup(self, data, zone, name, rtype):
        """(rcode, answers[(name, type, value)], authority)"""
        if (name, rtype) in data:
            return 0, [(name, rtype, v) for v in data[(name, rtype)]], []
        if (name, "CNAME") in data and rtype != "CNAME":
            tgt = data[(name, "CNAME")][0]
            ans = [(name, "CNAME", tgt)]
            rc, more, _a = self._lookup(data, zone, dnsq.norm(tgt), rtype)
            return 0, ans + more, []
        # wildcard
        if "." in name:
            wild = "*." + name.split(".", 1)[1]
            if (wild, rtype) in data:
                return 0, [(name, rtype, v) for v in data[(wild, rtype)]], []
        exists = any(k[0] == name or k[0].endswith("." + name) for k in data)
        soa = [(zone, "SOA", data[(zone, "SOA")][0])] if zone and (zone, "SOA") in data else []
        return (0 if exists else 3), [], soa

    def answer(self, server, query):
        q = dnsq.parse_message(query + b"")  # header only (no answers)
        # re-read the question
        name, off = dnsq._read_name(query, 12)
        qtype, _ = struct.unpack(">HH", query[off:off + 4])
        rtype = dnsq.TYPE_NAMES[qtype]
        self.queries.append((server, name, rtype))
        if server in self.dead:
            raise dnsq.DNSTimeout(f"no answer from {server}")
        auth_zone = next((z for z, ips in self.ns_ips.items() if server in ips), None)
        if auth_zone is not None:
            data = dict(self.zones.get("_glue", {}))
            data.update(self.zones[auth_zone])
            zone = auth_zone if (name == auth_zone or name.endswith("." + auth_zone)) else None
            if zone is None:
                return self._msg(q.id, query[12:off + 4], 5, [], [])
        else:
            view = self.public_view if self.public_view is not None else self.zones
            data = {}
            for z in view.values():
                data.update(z)
            zone = self._zone_for(name)
        rc, ans, auth = self._lookup(data, zone, name, rtype)
        return self._msg(q.id, query[12:off + 4], rc, ans, auth, aa=auth_zone is not None)

    def _msg(self, qid, question, rcode, ans, auth, aa=False, tc=False):
        flags = 0x8000 | (0x0400 if aa else 0) | (0x0200 if tc else 0) | 0x0080 | rcode
        if tc:
            ans, auth = [], []
        body = b"".join(_rr(n, t, v) for n, t, v in ans) + b"".join(_rr(n, t, v) for n, t, v in auth)
        return struct.pack(">HHHHHH", qid, flags, 1, len(ans), len(auth), 0) + question + body

    def transport(self, server, port, payload, tcp, timeout):
        resp = self.answer(server, payload)
        if self.truncate_udp and not tcp:
            qid = struct.unpack(">H", payload[:2])[0]
            name, off = dnsq._read_name(payload, 12)
            return self._msg(qid, payload[12:off + 4], 0, [], [], tc=True)
        return resp

    def resolver(self, **kw):
        return dnsq.Resolver(transport=self.transport, **kw)

    # ---- real loopback sockets --------------------------------------------------
    def serve(self, as_server):
        """Start UDP+TCP servers on 127.0.0.1 answering as `as_server`.
        Returns (port, stop)."""
        fake = self

        class U(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                resp = fake.answer(as_server, data)
                if fake.truncate_udp:
                    qid = struct.unpack(">H", data[:2])[0]
                    _n, off = dnsq._read_name(data, 12)
                    resp = fake._msg(qid, data[12:off + 4], 0, [], [], tc=True)
                sock.sendto(resp, self.client_address)

        class T(socketserver.BaseRequestHandler):
            def handle(self):
                n = struct.unpack(">H", self.request.recv(2))[0]
                data = b""
                while len(data) < n:
                    data += self.request.recv(n - len(data))
                resp = fake.answer(as_server, data)
                self.request.sendall(struct.pack(">H", len(resp)) + resp)

        # DNS needs UDP and TCP on the same port number. A free UDP port says
        # nothing about TCP: some other socket on the box (any outgoing TCP
        # connection picks its local port from the same ephemeral range) can
        # already hold it -> "Address already in use" about 1 run in 5. So
        # pick a pair that is free for both, trying again on a clash.
        class TCP(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
        last = None
        for _ in range(50):
            udp = socketserver.ThreadingUDPServer(("127.0.0.1", 0), U)
            port = udp.server_address[1]
            try:
                tcp = TCP(("127.0.0.1", port), T)
                break
            except OSError as e:
                udp.server_close()
                last = e
        else:
            raise last
        for s in (udp, tcp):
            threading.Thread(target=s.serve_forever, daemon=True).start()

        def stop():
            for s in (udp, tcp):
                s.shutdown()
                s.server_close()
        return port, stop


class FakeProvider(Provider):
    """In-memory zone. `dns` (a FakeDNS) gets every change published at once,
    or after `delay` publish() calls when set."""
    name = "fake"
    title = "Fake"

    def __init__(self, zone, dns=None, records=None, fail=None):
        super().__init__({})
        self.zone = dnsq.norm(zone)
        self.records = {}
        self.calls = []
        self.dns = dns
        self.fail = fail or {}
        self._n = 0
        for r in records or []:
            self._add(r)

    def _add(self, r):
        self._n += 1
        rid = f"r{self._n}"
        self.records[rid] = Record(r.name, r.type, r.content, r.ttl, id=rid)
        self._publish()
        return rid

    def _publish(self):
        if self.dns is None:
            return
        zd = self.dns.zones[self.zone]
        for k in [k for k in zd if k[1] not in ("SOA", "NS")]:
            del zd[k]
        for r in self.records.values():
            zd.setdefault((r.name, r.type), []).append(r.content)

    def _maybe_fail(self, op):
        if op in self.fail:
            code = self.fail[op]
            raise ProviderError(code, f"fake {op} failed", "fake hint")

    def check(self, zone):
        self.calls.append(("check", zone))
        self._maybe_fail("check")

    def list(self, zone, name=None, rtype=None):
        self.calls.append(("list", zone, name, rtype))
        self._maybe_fail("list")
        return self._filter([Record(r.name, r.type, r.content, r.ttl, id=r.id)
                             for r in self.records.values()], name, rtype)

    def create(self, zone, record):
        self.calls.append(("create", record.name, record.type, record.content))
        self._maybe_fail("create")
        return self._add(record)

    def update(self, zone, rid, record):
        self.calls.append(("update", rid, record.content))
        self._maybe_fail("update")
        self.records[rid] = Record(record.name, record.type, record.content, record.ttl, id=rid)
        self._publish()

    def delete(self, zone, rid):
        self.calls.append(("delete", rid))
        self._maybe_fail("delete")
        del self.records[rid]
        self._publish()

    def mutations(self):
        return [c for c in self.calls if c[0] in ("create", "update", "delete")]

    def contents(self):
        return sorted((r.name, r.type, r.content) for r in self.records.values())

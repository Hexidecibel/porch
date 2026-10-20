#!/usr/bin/env python3
"""Filtering forward proxy for bin/snap's headless Chrome.

Checking only the first URL is not enough: a redirect, a meta refresh, an
iframe or an <img> can point Chrome at http://127.0.0.1:9471/ or
http://169.254.169.254/ and the result is then published on a public URL.
bin/snap therefore starts this proxy on 127.0.0.1 (ephemeral port) and runs
Chrome with --proxy-server pointing at it and --proxy-bypass-list=<-loopback>
(without that, Chrome talks to localhost directly). Every connection Chrome
makes, CONNECT (https, wss) or absolute-form GET/POST (http), comes through
here. For each one the proxy:

  * resolves the target host itself,
  * refuses it unless every address is public (no loopback, RFC1918,
    link-local, CGNAT, ULA, multicast, unspecified, reserved; IPv4-mapped v6
    is unwrapped first), unless --allow-private,
  * connects to the exact address it checked, so a DNS answer that changes
    between check and use (rebinding) cannot swap it.

Usage: snapproxy.py --port-file PATH [--allow-private] [--bind 127.0.0.1]
The bound port is written to PATH once the socket is listening.
"""

import argparse
import ipaddress
import os
import select
import socket
import socketserver
import sys
import threading

MAX_HEAD = 64 * 1024
CONNECT_TIMEOUT = 10
IDLE_TIMEOUT = 60


class Refused(Exception):
    pass


def ip_is_public(ip):
    ip = ipaddress.ip_address(ip)
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        elif ip.sixtofour:
            ip = ip.sixtofour
        elif ip.teredo:
            ip = ip.teredo[1]
    return ip.is_global and not ip.is_multicast


def resolve_checked(host, port, *, allow_private=False, resolver=socket.getaddrinfo):
    """Return the list of IPs to connect to, or raise Refused."""
    host = host.strip("[]")
    if not host:
        raise Refused("no host")
    try:
        literal = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        literal = None
    if literal is not None:
        ips = [str(literal)]
    else:
        try:
            infos = resolver(host, port, 0, socket.SOCK_STREAM)
        except (socket.gaierror, UnicodeError, OSError) as e:
            raise Refused(f"cannot resolve {host}: {e}")
        ips = []
        for info in infos:
            ip = info[4][0].split("%", 1)[0]
            if ip not in ips:
                ips.append(ip)
    if not ips:
        raise Refused(f"cannot resolve {host}")
    if not allow_private:
        bad = [ip for ip in ips if not ip_is_public(ip)]
        if bad:
            raise Refused(f"{host} -> {', '.join(bad)} is not a public address")
    v4 = [ip for ip in ips if ":" not in ip]
    v6 = [ip for ip in ips if ":" in ip]
    return v4 + v6


def split_hostport(hp, default_port):
    hp = hp.strip()
    if hp.startswith("["):
        end = hp.find("]")
        if end < 0:
            raise Refused("bad host")
        host, rest = hp[1:end], hp[end + 1:]
        port = rest[1:] if rest.startswith(":") else ""
    elif hp.count(":") == 1:
        host, port = hp.split(":")
    elif ":" in hp:
        host, port = hp, ""        # bare IPv6, no port
    else:
        host, port = hp, ""
    if port:
        if not port.isdigit() or not 0 < int(port) < 65536:
            raise Refused("bad port")
        port = int(port)
    else:
        port = default_port
    return host, port


class ProxyHandler(socketserver.BaseRequestHandler):
    allow_private = False
    resolver = staticmethod(socket.getaddrinfo)
    connector = staticmethod(socket.create_connection)
    quiet = False

    def _log(self, msg):
        if not self.quiet:
            sys.stderr.write(f"[snapproxy] {msg}\n")

    def _read_head(self):
        sock = self.request
        sock.settimeout(IDLE_TIMEOUT)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(8192)
            if not chunk:
                return None, b""
            buf += chunk
            if len(buf) > MAX_HEAD:
                raise Refused("request head too large")
        head, rest = buf.split(b"\r\n\r\n", 1)
        return head.decode("latin-1"), rest

    def _reply(self, code, reason):
        body = f"{code} {reason}\n".encode()
        try:
            self.request.sendall(
                f"HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
        except OSError:
            pass

    def _connect(self, host, port):
        ips = resolve_checked(host, port, allow_private=self.allow_private,
                              resolver=self.resolver)
        last = None
        for ip in ips:
            try:
                up = self.connector((ip, port), timeout=CONNECT_TIMEOUT)
                up.settimeout(IDLE_TIMEOUT)
                return up
            except OSError as e:
                last = e
        raise ConnectionError(f"connect {host}:{port} failed: {last}")

    def handle(self):
        try:
            head, rest = self._read_head()
        except (Refused, OSError) as e:
            self._reply(400, "Bad Request")
            return
        if not head:
            return
        lines = head.split("\r\n")
        try:
            method, target, version = lines[0].split(" ", 2)
        except ValueError:
            self._reply(400, "Bad Request")
            return
        try:
            if method.upper() == "CONNECT":
                host, port = split_hostport(target, 443)
                up = self._connect(host, port)
                self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if rest:
                    up.sendall(rest)
            else:
                low = target.lower()
                if not low.startswith("http://"):
                    raise Refused("only absolute http:// targets and CONNECT are proxied")
                after = target[len("http://"):]
                slash = after.find("/")
                hostport, path = (after, "/") if slash < 0 else (after[:slash], after[slash:])
                if "@" in hostport:
                    raise Refused("userinfo in proxy target")
                host, port = split_hostport(hostport, 80)
                up = self._connect(host, port)
                out = [f"{method} {path} {version}"]
                for line in lines[1:]:
                    name = line.split(":", 1)[0].strip().lower()
                    if name in ("proxy-connection", "proxy-authorization", "connection", "keep-alive"):
                        continue
                    out.append(line)
                out.append("Connection: close")
                up.sendall(("\r\n".join(out) + "\r\n\r\n").encode("latin-1") + rest)
        except Refused as e:
            self._log(f"refused {method} {target}: {e}")
            self._reply(403, "Forbidden")
            return
        except (ConnectionError, OSError) as e:
            self._log(f"{method} {target}: {e}")
            self._reply(502, "Bad Gateway")
            return
        self._pipe(self.request, up)

    @staticmethod
    def _pipe(a, b):
        socks = [a, b]
        try:
            while True:
                r, _, _ = select.select(socks, [], [], IDLE_TIMEOUT)
                if not r:
                    return
                for s in r:
                    data = s.recv(65536)
                    if not data:
                        return
                    (b if s is a else a).sendall(data)
        except OSError:
            return
        finally:
            try:
                b.close()
            except OSError:
                pass


class ProxyServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(bind="127.0.0.1", port=0, *, allow_private=False,
                resolver=None, connector=None, quiet=False):
    attrs = {"allow_private": allow_private, "quiet": quiet}
    if resolver is not None:
        attrs["resolver"] = staticmethod(resolver)
    if connector is not None:
        attrs["connector"] = staticmethod(connector)
    handler = type("BoundProxyHandler", (ProxyHandler,), attrs)
    return ProxyServer((bind, port), handler)


def main():
    p = argparse.ArgumentParser(description="snap filtering proxy")
    p.add_argument("--port-file", required=True)
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--allow-private", action="store_true")
    a = p.parse_args()
    srv = make_server(a.bind, 0, allow_private=a.allow_private)
    tmp = a.port_file + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(srv.server_address[1]))
    os.replace(tmp, a.port_file)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

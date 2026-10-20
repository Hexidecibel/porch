"""lib/snapproxy.py: the filtering proxy bin/snap runs all Chrome traffic through."""

import os
import socket
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_LIB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib")
sys.path.insert(0, _LIB)
import snapproxy  # noqa: E402


def fake_resolver(mapping):
    def resolve(host, port, family=0, type_=0, *a):
        if host not in mapping:
            raise socket.gaierror("nope")
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 (ip, port)) for ip in mapping[host]]
    return resolve


class _Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"public-ok " + self.path.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class SnapProxyTests(unittest.TestCase):
    PUBLIC = "93.184.216.34"

    def setUp(self):
        self.backend = ThreadingHTTPServer(("127.0.0.1", 0), _Backend)
        threading.Thread(target=self.backend.serve_forever, daemon=True).start()
        self.connects = []
        bport = self.backend.server_address[1]

        def connector(addr, timeout=None):
            self.connects.append(addr)
            if addr[0] == self.PUBLIC:     # "the internet" is our local backend
                return socket.create_connection(("127.0.0.1", bport), timeout=timeout)
            raise AssertionError(f"proxy tried to connect to {addr}")

        res = fake_resolver({"rebind.example": ["127.0.0.1"],
                             "mixed.example": [self.PUBLIC, "10.1.2.3"],
                             "good.example": [self.PUBLIC]})
        self.proxy = snapproxy.make_server(resolver=res, connector=connector, quiet=True)
        threading.Thread(target=self.proxy.serve_forever, daemon=True).start()
        self.port = self.proxy.server_address[1]

    def tearDown(self):
        self.proxy.shutdown(); self.proxy.server_close()
        self.backend.shutdown(); self.backend.server_close()

    def _send(self, raw):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        s.sendall(raw)
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
            if raw.startswith(b"CONNECT") and b"\r\n\r\n" in data:
                break
        s.close()
        return data

    def test_refuses_private_targets(self):
        bad_hosts = ["127.0.0.1", "[::1]", "[::ffff:127.0.0.1]", "10.0.0.5",
                     "169.254.169.254", "100.64.0.1", "192.168.1.1", "0.0.0.0",
                     "[fc00::1]", "224.0.0.1", "rebind.example", "mixed.example"]
        for h in bad_hosts:
            for raw in (f"CONNECT {h}:443 HTTP/1.1\r\nHost: {h}:443\r\n\r\n",
                        f"GET http://{h}/latest/meta-data/ HTTP/1.1\r\nHost: {h}\r\n\r\n",
                        f"GET http://{h}:9471/api HTTP/1.1\r\nHost: {h}\r\n\r\n"):
                resp = self._send(raw.encode())
                self.assertTrue(resp.startswith(b"HTTP/1.1 403"), (raw, resp[:80]))
        self.assertEqual(self.connects, [])

    def test_refuses_origin_form_and_unresolvable(self):
        self.assertTrue(self._send(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").startswith(b"HTTP/1.1 403"))
        self.assertTrue(self._send(b"CONNECT nx.example:443 HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 403"))
        self.assertEqual(self.connects, [])

    def test_allows_public_and_connects_to_checked_ip(self):
        resp = self._send(b"GET http://good.example/hello HTTP/1.1\r\nHost: good.example\r\n"
                          b"Proxy-Connection: keep-alive\r\n\r\n")
        self.assertIn(b"200", resp.split(b"\r\n", 1)[0])
        self.assertTrue(resp.endswith(b"public-ok /hello"), resp)
        self.assertEqual(self.connects, [(self.PUBLIC, 80)])

    def test_connect_public_tunnels(self):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        s.sendall(f"CONNECT {self.PUBLIC}:443 HTTP/1.1\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head:
            head += s.recv(1024)
        self.assertTrue(head.startswith(b"HTTP/1.1 200"))
        s.sendall(b"GET /through HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        data = b""
        while True:
            c = s.recv(65536)
            if not c:
                break
            data += c
        s.close()
        self.assertTrue(data.endswith(b"public-ok /through"))
        self.assertEqual(self.connects, [(self.PUBLIC, 443)])

    def test_ip_classification(self):
        for ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "169.254.169.254",
                   "100.64.1.1", "fe80::1", "::", "ff02::1", "2002:7f00:1::1"):
            self.assertFalse(snapproxy.ip_is_public(ip), ip)
        self.assertTrue(snapproxy.ip_is_public("93.184.216.34"))
        self.assertTrue(snapproxy.ip_is_public("2606:4700::1111"))

    def test_allow_private_permits(self):
        self.assertEqual(snapproxy.resolve_checked("127.0.0.1", 80, allow_private=True), ["127.0.0.1"])


if __name__ == "__main__":
    unittest.main()

"""The shared core (lib/porch_http.py + lib/porch_auth.py) as the media,
music and drop servers use it: deadline scope and quota bookkeeping, run
through each server's own imports. Temp dirs and ephemeral 127.0.0.1 ports
only."""

import importlib.util
import os
import re
import socket
import sys
import tempfile
import threading
import time
import types
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path

_LIB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib")


def _load(name):
    spec = importlib.util.spec_from_file_location("hb_" + name, os.path.join(_LIB, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MODS = {n: _load(n) for n in ("mediaserver", "musicserver", "dropserver")}
HANDLERS = {"mediaserver": ("MediaHandler", "media_dir", "a.jpg"),
            "musicserver": ("MusicHandler", "music_dir", "a.mp3"),
            "dropserver": ("DropHandler", "upload_dir", "a.txt")}
BODY = 24 * 1024 * 1024


class SharedCoreImportTest(unittest.TestCase):
    """The servers import the shared modules instead of carrying copies."""

    COPIES = (r"^class BoundedThreadingHTTPServer\b", r"^class _DeadlineReaper\b",
              r"^class HardenedHandlerMixin\b", r"^class MultipartStreamer\b",
              r"^class Quota\b", r"^def client_ip\b", r"^def owner_entries\b",
              r"^def is_owner_token\b", r"^def _expiry_epoch\b", r"^def place_unique\b",
              r"^GATE_COOKIE\s*=", r"shared hardening block")

    def test_servers_import_the_core(self):
        ph = sys.modules["porch_http"]
        pa = sys.modules["porch_auth"]
        for n, mod in MODS.items():
            src = open(os.path.join(_LIB, n + ".py")).read()
            self.assertRegex(src, r"(?m)^import porch_auth\b", n)
            self.assertRegex(src, r"(?m)^from porch_http import \(", n)
            for pat in self.COPIES:
                self.assertIsNone(re.search(pat, src, re.M), f"{n}: {pat}")
            # The names the servers use are the shared objects themselves.
            self.assertIs(mod.HardenedHandlerMixin, ph.HardenedHandlerMixin, n)
            self.assertIs(mod.MultipartStreamer, ph.MultipartStreamer, n)
            self.assertIs(mod.Quota, ph.Quota, n)
            self.assertIs(mod.porch_auth, pa, n)


class PausedResponseTest(unittest.TestCase):
    """A client that stops reading a long response for longer than the
    request deadline still gets the rest: the deadline covers the request."""

    def _run(self, mod):
        ph = sys.modules["porch_http"]
        saved = (ph.REQUEST_DEADLINE, ph.HEADER_DEADLINE)
        ph.REQUEST_DEADLINE, ph.HEADER_DEADLINE = 1, 2
        self.addCleanup(lambda: (setattr(ph, "REQUEST_DEADLINE", saved[0]),
                                 setattr(ph, "HEADER_DEADLINE", saved[1])))

        class H(mod.HardenedHandlerMixin, BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(BODY))
                self.end_headers()
                chunk = b"x" * 65536
                for _ in range(BODY // len(chunk)):
                    self.wfile.write(chunk)
                    self.transferred(len(chunk))

        srv = mod.BoundedThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        s = socket.create_connection(srv.server_address, timeout=15)
        s.sendall(b"GET /big HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        data = s.recv(4096)
        time.sleep(3.5)           # well past REQUEST_DEADLINE + a reaper tick
        while True:
            c = s.recv(1 << 20)
            if not c:
                break
            data += c
        s.close()
        head, _, body = data.partition(b"\r\n\r\n")
        self.assertIn(b"200", head.split(b"\r\n")[0])
        self.assertEqual(len(body), BODY, mod.__name__)

    def test_media(self):
        self._run(MODS["mediaserver"])

    def test_music(self):
        self._run(MODS["musicserver"])

    def test_drop(self):
        self._run(MODS["dropserver"])

    def test_slow_request_head_is_still_reaped(self):
        mod = MODS["dropserver"]
        ph = sys.modules["porch_http"]
        saved = ph.HEADER_DEADLINE
        ph.HEADER_DEADLINE = 1
        self.addCleanup(lambda: setattr(ph, "HEADER_DEADLINE", saved))

        class H(mod.HardenedHandlerMixin, BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(204)
                self.end_headers()
        srv = mod.BoundedThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        s = socket.create_connection(srv.server_address, timeout=10)
        s.sendall(b"GET / HTTP/1.1\r\n")
        t0 = time.monotonic()
        self.assertEqual(s.recv(100), b"")   # hung up, not served
        self.assertLess(time.monotonic() - t0, 5)
        s.close()


class SpoolQuotaTest(unittest.TestCase):
    """quota.begin() always has its quota.end(), even if new_tmp() raises."""

    def test_new_tmp_failure_releases_the_slot(self):
        for name, mod in MODS.items():
            cls_name, dir_attr, fname = HANDLERS[name]
            d = tempfile.mkdtemp()
            quota = mod.Quota(Path(d), lambda: (0, 0), max_bytes=10 ** 9, max_items=1,
                              min_free=0)
            fake = types.SimpleNamespace(**{dir_attr: Path(d), "max_file": 10 ** 9})
            real = mod.new_tmp

            def boom(directory):
                raise OSError("disk gone")
            mod.new_tmp = boom
            try:
                with self.assertRaises(OSError, msg=name):
                    getattr(mod, cls_name)._spool_part(fake, fname, iter([b"data"]), quota)
            finally:
                mod.new_tmp = real
            self.assertEqual((quota.inflight, quota.items, quota.used), (0, 0, 0), name)
            # The single item slot is usable again.
            self.assertIsNone(quota.begin(), name)


if __name__ == "__main__":
    unittest.main()

"""The phone check: prove the box is reachable from the internet, with a
human holding a phone on cellular. No third-party probe.

    pc = PhoneCheck(ctx)                  # binds a throwaway server on 127.0.0.1:<9400-9900>
    pc.open_tunnel()                      # bin/tunnel <port> porch-reach-<rand> --bg
      or pc.use_url("https://x.example/") # caller routes that prefix to pc.port
    pc.show()                             # QR (bin/qr --terminal -) + the URL
    hit = pc.wait(timeout=300)            # dict for the first request carrying the nonce, or None
    pc.close()                            # stops the tunnel and the server

Or in one go: phone_check(ctx, url=None, timeout=300) -> (ok, detail).

A hit coming from this LAN or from the box's own public IP (hairpin NAT on
Wi-Fi) is recorded but not accepted: the user is asked to switch to cellular.
"""

import hmac
import http.server
import ipaddress
import os
import random
import secrets
import threading
import time

PORT_RANGE = (9400, 9900)
NEVER_PORTS = {9877}
PAGE = (b"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'>"
        b"<title>Porch reach check</title><body style='font-family:system-ui;padding:2em'>"
        b"<h1>It works.</h1><p>Your Porch server is reachable from the internet. "
        b"You can close this page.</p>")


class ReachError(Exception):
    pass


def _client_ip(handler):
    xff = handler.headers.get("X-Forwarded-For", "")
    hops = [h.strip() for h in xff.split(",") if h.strip()]
    for h in reversed(hops):
        try:
            a = ipaddress.ip_address(h)
        except ValueError:
            continue
        if not a.is_loopback:
            return str(a)
    return handler.client_address[0]


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "porch-reach"
    sys_version = ""

    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):  # noqa: N802
        check = self.server.check
        path = self.path.split("?", 1)[0].strip("/")
        if hmac.compare_digest(path.encode(), check.nonce.encode()):
            check._record(self)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(PAGE)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(PAGE)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_HEAD = do_GET


def bind_server(handler=_Handler, lo=PORT_RANGE[0], hi=PORT_RANGE[1], rng=None, host="127.0.0.1"):
    """A ThreadingHTTPServer on a free port in [lo, hi] (bind is the check),
    never one of NEVER_PORTS."""
    ports = [p for p in range(lo, hi + 1) if p not in NEVER_PORTS]
    (rng or random.SystemRandom()).shuffle(ports)
    for p in ports[:200]:
        try:
            srv = http.server.ThreadingHTTPServer((host, p), handler)
        except OSError:
            continue
        srv.daemon_threads = True
        return srv
    raise ReachError(f"no free port in {lo}-{hi}")


class PhoneCheck:
    def __init__(self, ctx, local_ips=(), rng=None, bin_dir=None):
        self.ctx = ctx
        self.nonce = secrets.token_urlsafe(18)
        self.local_ips = set(local_ips)
        self.hits = []
        self._event = threading.Event()
        self._lock = threading.Lock()
        self.bin_dir = bin_dir or os.path.join(ctx.repo_dir, "bin")
        self.tunnel_name = None
        self.url = None
        self.server = bind_server(rng=rng)
        self.server.check = self
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    # -- routing ---------------------------------------------------------------
    def use_url(self, prefix):
        self.url = prefix.rstrip("/") + "/" + self.nonce
        return self.url

    def open_tunnel(self, name=None):
        name = name or "porch-reach-" + secrets.token_hex(4)
        r = self.ctx.run.run([os.path.join(self.bin_dir, "tunnel"), str(self.port), name, "--bg"],
                             timeout=30)
        if not r.ok:
            raise ReachError(f"bin/tunnel failed (rc {r.returncode}): {(r.stderr or r.stdout).strip()[:200]}")
        self.tunnel_name = name
        return self.use_url(self.ctx.cfg.tunnel_url(name))

    # -- hits --------------------------------------------------------------------
    def _record(self, handler):
        ip = _client_ip(handler)
        hit = {"ip": ip, "at": time.time(), "local": self.is_local(ip),
               "ua": (handler.headers.get("User-Agent") or "")[:120]}
        with self._lock:
            self.hits.append(hit)
        self._event.set()

    def is_local(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return a.is_private or a.is_loopback or a.is_link_local or ip in self.local_ips

    def show(self):
        """Print a QR (when bin/qr and python qrcode are available) and the URL."""
        qr = os.path.join(self.bin_dir, "qr")
        art = ""
        if os.path.exists(qr):
            r = self.ctx.run.run([qr, "--terminal", "-"], input=self.url, mutating=False, timeout=20)
            if r.ok and r.stdout.strip():
                art = r.stdout.rstrip("\n")
        msg = ("Phone check: turn Wi-Fi OFF on your phone (use cellular data), then open:\n"
               f"    {self.url}\n")
        if art:
            msg = art + "\n" + msg
        self.ctx.log(msg)
        self.ctx.emit("phone_check", url=self.url, step=self.ctx.step_id)

    def wait(self, timeout=300, poll=1.0):
        """First non-local hit, or None after timeout. A local (Wi-Fi /
        hairpin) hit logs a hint and keeps waiting."""
        end = time.monotonic() + timeout
        warned = 0
        while True:
            with self._lock:
                good = [h for h in self.hits if not h["local"]]
                n_local = len(self.hits) - len(good)
            if good:
                return good[0]
            if n_local > warned:
                warned = n_local
                self.ctx.log("That request came from your own network (Wi-Fi), which does not "
                             "prove outside access. Turn Wi-Fi off and open the link again.", "warn")
            left = end - time.monotonic()
            if left <= 0:
                return None
            self._event.wait(min(poll, left))
            self._event.clear()

    def close(self):
        if self.tunnel_name:
            self.ctx.run.run([os.path.join(self.bin_dir, "status"), "close", self.tunnel_name],
                             timeout=30)
            self.tunnel_name = None
        try:
            self.server.shutdown()
            self.server.server_close()
        except Exception:  # noqa: BLE001
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def phone_check(ctx, url=None, timeout=300, local_ips=(), check_cls=PhoneCheck):
    """(ok, detail). url=None runs a throwaway bin/tunnel."""
    try:
        pc = check_cls(ctx, local_ips=local_ips)
    except ReachError as e:
        return False, str(e)
    with pc:
        try:
            if url:
                pc.use_url(url)
            else:
                pc.open_tunnel()
        except ReachError as e:
            return False, str(e)
        pc.show()
        hit = pc.wait(timeout)
        if hit:
            return True, f"request from {hit['ip']}"
        if pc.hits:
            return False, "only requests from your own network arrived (turn Wi-Fi off)"
        return False, f"no request arrived within {int(timeout)}s"


def stack_ready(ctx, ports=(7000, 443), connect=None):
    """True when the local frps (7000) and HTTPS (443) listen, i.e. a
    bin/tunnel URL can route at all. Before haproxy/frps/dns/cert are set up
    the phone check has to wait for the smoke step."""
    import socket
    conn = connect or (lambda p: socket.create_connection(("127.0.0.1", p), timeout=1).close())
    for p in ports:
        try:
            conn(p)
        except OSError:
            return False
    return True

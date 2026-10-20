"""smoke: end-to-end checks.

verify (read-only, also used by --adopt and doctor):
  1. a TLS handshake at 127.0.0.1:443 for the auth, panel and landing hosts
     and a random name under the tunnel base (the wildcard), with chain and
     hostname checks, and >= 14 days left on the certificate;
  2. GET https://<auth host>/auth/ -> 200.
apply (only in a real run):
  3. a throwaway tunnel porch-smoke-<rand> to a local server, fetched through
     127.0.0.1:443 with SNI;
  4. the phone check: open the printed URL on cellular; the local server
     must see a request from a public address. Skipped when non-interactive.
"""

import ipaddress
import os
import secrets
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..engine import Action, Check, Step, StepError
from . import _common as c

ORDER = 140
MIN_DAYS = 14


def tls_probe(host, ip="127.0.0.1", port=443, timeout=8):
    """(ok, message, days_left) for a verified handshake with SNI=host."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return False, f"{host}: certificate rejected: {e.verify_message}", None
    except (OSError, ssl.SSLError) as e:
        return False, f"{host}: TLS handshake failed: {e}", None
    days = (ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400
    return True, f"{host}: certificate ok, {days:.0f} days left", days


class _Hits:
    def __init__(self, nonce):
        self.nonce = nonce
        self.sources = []


def _server(hits):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/" + hits.nonce:
                self.send_error(404)
                return
            hits.sources.append(self.headers.get("X-Forwarded-For", ""))
            body = b"porch ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _public(addr):
    try:
        ip = ipaddress.ip_address(addr.split(",")[0].strip())
    except ValueError:
        return False
    return ip.is_global


class Smoke(Step):
    id = "smoke"
    title = "End-to-end check"
    requires = ("landing",)
    tls_probe = staticmethod(tls_probe)
    tunnel_wait = 30
    phone_wait = 180

    def hosts(self, ctx):
        cfg = ctx.cfg
        rand = "porch-probe-" + secrets.token_hex(3)
        return [cfg.auth_host, cfg.panel_host, cfg.landing_host, f"{rand}.{cfg.tunnel_base}"]

    def verify(self, ctx):
        out = []
        for host in dict.fromkeys(self.hosts(ctx)):
            ok, msg, days = self.tls_probe(host)
            if ok and days is not None and days < MIN_DAYS:
                out.append(Check(False, "smoke.cert_expiry", msg, "porch cert renew"))
            else:
                out.append(Check(ok, "smoke.tls", msg, "" if ok else
                                 "does the certificate cover this name (auth, panel, tunnel, *.tunnel)?"))
        out.append(c.https_check(ctx, "smoke.auth", ctx.cfg.auth_host, "/auth/"))
        return out

    def plan(self, ctx):
        return [Action("tunnel", f"porch-smoke-<rand>.{ctx.cfg.tunnel_base}", "throwaway, closed after"),
                Action("phone", "open a URL on cellular", "interactive only")]

    def apply(self, ctx):
        nonce = secrets.token_urlsafe(12)
        hits = _Hits(nonce)
        srv = _server(hits)
        name = "porch-smoke-" + secrets.token_hex(3)
        host = f"{name}.{ctx.cfg.tunnel_base}"
        bin_dir = os.path.join(ctx.repo_dir, "bin")
        try:
            ctx.record_undo("tunnel.close", name=name)
            r = ctx.run.run([os.path.join(bin_dir, "tunnel"), str(srv.server_address[1]), name, "--bg"])
            if not r.ok:
                raise StepError("smoke.tunnel", "bin/tunnel failed: " + (r.stderr or r.stdout).strip()[-300:])
            deadline = ctx.clock() + self.tunnel_wait
            code = None
            while ctx.clock() < deadline:
                code, _ = c.https_code(ctx, host, "/" + nonce, timeout=5)
                if code == 200:
                    break
                ctx.sleep(1)
            if code != 200:
                raise StepError("smoke.tunnel", f"https://{host}/ did not answer through HAProxy "
                                f"(last status {code})", "bin/status; logs/frps.log")
            external = None
            if ctx.io.interactive:
                url = f"https://{host}/{nonce}"
                ctx.log(f"Phone check: turn Wi-Fi off and open {url}")
                # the web wizard shows its QR panel on this event (as
                # net/reach.py's phone check does); the CLI ignores it
                ctx.emit("phone_check", url=url, step=ctx.step_id)
                if ctx.run.which("qrencode"):
                    q = ctx.run.run(["qrencode", "-t", "ANSIUTF8", url], mutating=False)
                    if q.ok:
                        ctx.log("\n" + q.stdout)
                ctx.confirm("Press Enter once the page shows 'porch ok' on your phone", default=True)
                deadline = ctx.clock() + self.phone_wait
                while ctx.clock() < deadline and not any(_public(s) for s in hits.sources):
                    ctx.sleep(2)
                external = any(_public(s) for s in hits.sources)
                if not external:
                    raise StepError("smoke.external", "no request from the internet reached the box",
                                    "check the router port forward (80, 443) and the firewall")
            else:
                ctx.log("phone check skipped (non-interactive)")
            return {"tunnel": "ok", "external": external}
        finally:
            ctx.run.run([os.path.join(bin_dir, "status"), "close", name])
            srv.shutdown()
            srv.server_close()

    def undo(self, ctx, entry):
        if entry["kind"] != "tunnel.close":
            return super().undo(ctx, entry)
        ctx.run.run([os.path.join(ctx.repo_dir, "bin", "status"), "close", entry["name"]])


STEP = Smoke()

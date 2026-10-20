"""The web setup wizard: an HTTPS front-end over the same Engine the CLI uses.

    wiz = Wizard(steps, ctx_kwargs={...}, env=env)
    srv = make_tls_server(wiz, ("127.0.0.1", 8443), cert, key)   # or bind first, tls later
    wiz.serve(srv)                 # until setup completes, idle timeout, or wiz.stop()

Only ctx.io differs from `porch setup`: a WebIO (webio.py) whose prompts the
page answers over the API below.

Auth (docs/porch-setup-design.md, "Web wizard security"):
  * a 32-byte key travels in the URL fragment (#k=...), which browsers never
    send. wizard.js reads it, clears it with history.replaceState and POSTs
    it to /api/session. The key works once (hmac.compare_digest).
  * the answer is a host-only `Secure; HttpOnly; SameSite=Strict` session
    cookie plus a CSRF token the page sends as X-Porch-CSRF on every POST
    (also handed out by GET /api/state, so a reload keeps working).
  * 5 wrong keys lock /api/session for 10 minutes.
  * a strict nonce CSP; porch.css and fonts from /__porch-assets/, the page's
    script and stylesheet from /static/ (an exact-path table).
  * the server exits after `idle_timeout` (60 min) without a request, and
    shortly after setup completes.

API (all JSON; everything but /api/session needs the cookie):
  GET  /api/state                  steps, pending prompt, running, last result, URLs, csrf
  GET  /api/events?since=N         SSE; replays from N (or Last-Event-ID)
  GET  /api/qr                     {"size", "rows"} QR matrix of the phone-check URL
  GET  /api/qr?for=ready           the same for the ready page's Pocket sign-in URL (once complete)
  POST /api/session   {key}
  POST /api/run       {mode: run|resume|adopt|dry-run, dry_run?: bool}
  POST /api/rollback  {to?: step, dry_run?: bool}
  POST /api/inputs/<step> {prompt, values: {name: value | {"value"|"ref"}}}
  POST /api/confirm   {prompt, answer: bool}
  POST /api/cancel    {prompt}
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler

import porch_http as ph

from . import engine as _engine
from .webio import WebIO

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(HERE, "web")
COOKIE = "porch_setup"
KEY_BYTES = 32
MAX_FAILURES = 5
LOCKOUT = 600
IDLE_TIMEOUT = 3600
EXIT_GRACE = 300            # s the summary stays up after setup completes
HANDSHAKE_TIMEOUT = 10
BODY_CAP = 128 * 1024
MODES = ("run", "resume", "adopt", "dry-run")
_STEP_RE = re.compile(r"[a-z0-9_]{1,40}")
_PID_RE = re.compile(r"[0-9a-f]{16}")

STATIC = {
    "/static/wizard.js": ("wizard.js", "text/javascript; charset=utf-8"),
    "/static/wizard.css": ("wizard.css", "text/css; charset=utf-8"),
}


class WebError(Exception):
    pass


# ---- the wizard (state shared by all requests) ---------------------------------

class Wizard:
    def __init__(self, steps, *, ctx_kwargs=None, env=None, preset=None, key=None,
                 idle_timeout=IDLE_TIMEOUT, exit_grace=EXIT_GRACE, prompt_timeout=None,
                 clock=time.monotonic, origin_check=True, host_label=""):
        self.steps = list(steps)
        self.ctx_kwargs = dict(ctx_kwargs or {})
        self.env = os.environ if env is None else env
        self.key = key or secrets.token_urlsafe(KEY_BYTES)
        self.key_used = False
        self.failures = 0
        self.locked_until = 0.0
        self.sessions = {}               # sid -> csrf
        self.clock = clock
        self.idle_timeout = idle_timeout
        self.exit_grace = exit_grace
        self.origin_check = origin_check
        self.host_label = host_label
        self.last_activity = clock()
        self._lock = threading.Lock()
        self.thread = None
        self.run_info = None             # {"mode", "dry_run", "kind"}
        self.last_result = None
        self.complete = False
        self.exit_at = None
        self.stopped = threading.Event()
        redactor = self.ctx_kwargs.get("redactor")
        if redactor is None:
            from . import redact as _redact
            redactor = _redact.REDACTOR
            self.ctx_kwargs["redactor"] = redactor
        self.redactor = redactor
        self.io = WebIO(redactor=redactor, steps={s.id: s for s in self.steps}, preset=preset,
                        env=self.env, on_activity=self.touch,
                        **({"timeout": prompt_timeout} if prompt_timeout else {}))

    # ---- activity / lifetime ---------------------------------------------------
    def touch(self):
        self.last_activity = self.clock()

    def running(self):
        return self.thread is not None and self.thread.is_alive()

    def should_exit(self):
        now = self.clock()
        if self.stopped.is_set():
            return "stopped"
        if self.exit_at is not None and now >= self.exit_at and not self.running():
            return "complete"
        if not self.running() and now - self.last_activity > self.idle_timeout:
            return "idle"
        return None

    def stop(self):
        self.stopped.set()
        self.io.close()

    # ---- auth ------------------------------------------------------------------
    def open_session(self, key):
        """(status, body, sid or None)."""
        now = self.clock()
        with self._lock:
            if now < self.locked_until:
                return 429, {"error": "locked", "retry_after": int(self.locked_until - now) + 1}, None
            ok = (isinstance(key, str) and not self.key_used
                  and hmac.compare_digest(key.encode("utf-8", "replace"), self.key.encode()))
            if not ok:
                self.failures += 1
                if self.failures >= MAX_FAILURES:
                    self.failures = 0
                    self.locked_until = now + LOCKOUT
                return 403, {"error": "this link is not valid (or was already used)"}, None
            self.key_used = True
            self.failures = 0
            sid = secrets.token_urlsafe(32)
            csrf = secrets.token_urlsafe(32)
            self.sessions[sid] = csrf
        self.touch()
        return 200, {"csrf": csrf}, sid

    def session_csrf(self, sid):
        if not sid:
            return None
        with self._lock:
            for s, csrf in self.sessions.items():
                if hmac.compare_digest(s.encode(), sid.encode("utf-8", "replace")):
                    return csrf
        return None

    # ---- engine ----------------------------------------------------------------
    def _context(self, dry_run=False, adopt=False):
        return _engine.make_context(io=self.io, dry_run=dry_run, adopt=adopt, env=self.env,
                                    **self.ctx_kwargs)

    def _status_engine(self):
        kw = dict(self.ctx_kwargs)
        kw.pop("runner", None)
        kw["log"] = False
        ctx = _engine.make_context(io=None, dry_run=True, env=self.env, **kw)
        return _engine.Engine(self.steps, ctx)

    def start(self, kind, mode="run", dry_run=False, to_step=None):
        """kind 'run' or 'rollback'. Returns (status, body)."""
        if kind == "run" and mode not in MODES:
            return 400, {"error": "mode must be one of " + ", ".join(MODES)}
        if mode == "dry-run":
            mode, dry_run = "run", True
        with self._lock:
            if self.running():
                return 409, {"error": "a setup run is already in progress",
                             "code": "web.busy"}
            if to_step is not None and to_step not in {s.id for s in self.steps}:
                return 400, {"error": f"unknown step {to_step!r}"}
            try:
                ctx = self._context(dry_run=bool(dry_run), adopt=(mode == "adopt"))
                eng = _engine.Engine(self.steps, ctx)
            except Exception as e:  # noqa: BLE001
                return 500, {"error": self.redactor.redact(f"{type(e).__name__}: {e}")}
            info = {"kind": kind, "mode": mode, "dry_run": bool(dry_run), "to": to_step}
            self.run_info = info
            self.io.clear()
            self.exit_at = None
            self.thread = threading.Thread(target=self._run, args=(eng, info), daemon=True,
                                           name="porch-setup-engine")
            self.io.event("run_started", **info)
            self.thread.start()
        return 202, {"started": info}

    def _run(self, eng, info):
        try:
            if info["kind"] == "rollback":
                r = eng.rollback(to_step=info["to"])
            elif info["mode"] == "resume":
                r = eng.resume()
            else:
                r = eng.run()
        except Exception as e:  # noqa: BLE001 - surface, never kill the server
            r = _engine.RunResult(False, _engine.EXIT_APPLY,
                                  error={"code": "web.exception",
                                         "message": self.redactor.redact(f"{type(e).__name__}: {e}")})
        res = {"ok": r.ok, "exit_code": r.exit_code, "failed_step": r.failed_step,
               "error": self.redactor.redact_obj(r.error) if r.error else None,
               "statuses": r.statuses, "missing": r.missing, **info}
        if r.error and r.error.get("code") == "engine.locked":
            res["error"]["message"] = ("another porch setup is running on this box (CLI or "
                                       "another wizard); wait for it to finish, then try again")
        self.last_result = res
        complete = (r.ok and info["kind"] == "run" and not info["dry_run"]
                    and info["mode"] in ("run", "resume", "adopt")
                    and all(v in _engine.DONE_LIKE for v in r.statuses.values()))
        if complete:
            self.complete = True
            self.exit_at = self.clock() + self.exit_grace
        self.io.event("run_finished", **res, complete=complete, urls=self.urls() if complete else {},
                      ready=self.ready() if complete else None)
        self.touch()

    def live_statuses(self):
        """{step: status} from the events of the latest run. A dry run persists
        nothing, so this is the only record of what it planned."""
        out = {}
        for _seq, name, data in self.io.events_since(0):
            if name == "run_started":
                out = {}
            elif name == "step_started":
                out[data.get("step")] = "running"
            elif name == "step_done":
                st = data.get("status")
                out[data.get("step")] = "planned" if st == "would-roll-back" else st
            elif name == "step_failed":
                out[data.get("step")] = "failed"
        return out

    def active_step(self):
        """The step the running engine is on (from the last step_started)."""
        if not self.running():
            return None
        for _seq, name, data in reversed(self.io.events_since(0)):
            if name == "step_started":
                return data.get("step")
            if name == "run_started":
                return None
        return None

    def urls(self):
        """The live URLs once setup is done (from the config the domain step wrote)."""
        try:
            cfg = self.ctx_kwargs.get("cfg")
            if cfg is None:
                cfg = self._status_engine().ctx.reload_cfg()
        except Exception:  # noqa: BLE001
            return {}
        from . import ready
        return ready.urls(cfg)

    def ready(self):
        """The ready page's data (ready.info) once setup is complete, else None."""
        if not self.complete:
            return None
        try:
            cfg = self.ctx_kwargs.get("cfg")
            if cfg is None:
                cfg = self._status_engine().ctx.reload_cfg()
        except Exception:  # noqa: BLE001
            return None
        from . import ready
        return ready.info(cfg)

    def state(self, csrf):
        try:
            st = self._status_engine().status()
            steps = st["steps"]
            mode = st["mode"]
        except Exception as e:  # noqa: BLE001
            steps, mode = [], None
            self.io.event("log", message=f"could not read the setup state: {e}", level="warn",
                          step=None)
        titles = {s.id: s.title for s in self.steps}
        live = self.live_statuses()
        rows = []
        for s in steps:
            row = {k: s[k] for k in ("id", "status", "error", "attempts")}
            row["title"] = titles.get(s["id"], s["title"])
            if s["id"] in live and (live[s["id"]] != "running" or self.running()):
                row["status"] = live[s["id"]]
            rows.append(row)
        return {"steps": rows,
                "mode": mode, "running": self.running(), "run": self.run_info,
                "pending": self.io.pending(), "last_result": self.last_result,
                "complete": self.complete, "seq": self.io.seq, "csrf": csrf,
                "urls": self.urls(), "ready": self.ready(), "host": self.host_label,
                "idle_timeout": self.idle_timeout,
                "phone": ({"url": self.io.phone_url, "step": self.io.phone_step}
                          if self.io.phone_url else None),
                "active_step": self.active_step()}

    # ---- serving ---------------------------------------------------------------
    def serve(self, *servers, poll=1.0, out=None):
        """serve_forever on every server until should_exit(). Returns the reason."""
        threads = []
        for s in servers:
            s.wizard = self
            t = threading.Thread(target=s.serve_forever, kwargs={"poll_interval": 0.5},
                                 daemon=True)
            t.start()
            threads.append(t)
        reason = None
        try:
            while reason is None:
                self.stopped.wait(poll)
                reason = self.should_exit()
        except KeyboardInterrupt:
            reason = "interrupted"
        finally:
            self.io.close()
            for s in servers:
                s.shutdown()
                s.server_close()
        return reason


# ---- HTTP ----------------------------------------------------------------------

def _read_static(name):
    with open(os.path.join(STATIC_DIR, name), "rb") as f:
        return f.read()


def csp(nonce):
    return ("default-src 'none'; "
            f"script-src 'nonce-{nonce}'; {ph.porch_style_src(nonce)}; "
            "img-src 'self' data:; connect-src 'self'; "
            "form-action 'none'; base-uri 'none'; frame-ancestors 'none'")


def render_page(nonce):
    html = _read_static("wizard.html").decode("utf-8")
    return (html.replace("{{NONCE}}", nonce)
                .replace("{{PORCH_CSS}}", ph.porch_css_tag())
                .replace("{{MARK}}", ph.porch_mark(28))).encode("utf-8")


class Handler(ph.HardenedHandlerMixin, BaseHTTPRequestHandler):
    server_version = "porch-setup"
    protocol_version = "HTTP/1.1"

    def setup(self):
        # The TLS handshake happens here, in the connection's own thread, never
        # in the accept loop (a client that stalls mid-handshake blocks nobody).
        if isinstance(self.request, ssl.SSLSocket):
            self.request.settimeout(HANDSHAKE_TIMEOUT)
            self.request.do_handshake()
        super().setup()

    def log_message(self, fmt, *args):  # no request logs: URLs could carry a key typo
        pass

    @property
    def wiz(self):
        return self.server.wizard

    # ---- responses -----------------------------------------------------------
    def _common(self):
        ph.security_headers(self, referrer="no-referrer", frame="DENY")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        if getattr(self.server, "tls", False):
            self.send_header("Strict-Transport-Security", "max-age=600")

    def _json(self, code, obj, extra=()):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", ph.SANDBOX_CSP)
        for k, v in extra:
            self.send_header(k, v)
        self._common()
        self.end_headers()
        self.wfile.write(body)

    def _plain(self, code, text):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", ph.SANDBOX_CSP)
        self._common()
        self.end_headers()
        self.wfile.write(body)

    # ---- session ---------------------------------------------------------------
    def _sid(self):
        return ph.parse_cookies(self.headers.get("Cookie", "")).get(COOKIE)

    def _csrf(self):
        return self.wiz.session_csrf(self._sid())

    def _origin_ok(self):
        return not self.wiz.origin_check or ph.same_origin(self)

    # ---- GET -------------------------------------------------------------------
    def do_GET(self):  # noqa: N802
        if ph.serve_asset(self):
            return
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            nonce = ph.csp_nonce()
            body = render_page(nonce)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", csp(nonce))
            self._common()
            self.end_headers()
            self.wfile.write(body)
            return
        if path in STATIC:
            name, ctype = STATIC[path]
            body = _read_static(name)
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", ph.SANDBOX_CSP)
            self._common()
            self.end_headers()
            self.wfile.write(body)
            return
        if not path.startswith("/api/"):
            return self._plain(404, "not found\n")
        csrf = self._csrf()
        if csrf is None:
            return self._json(401, {"error": "no session"})
        if path == "/api/state":
            self.wiz.touch()
            return self._json(200, self.wiz.state(csrf))
        if path == "/api/events":
            return self._events()
        if path == "/api/qr":
            return self._qr()
        return self._json(404, {"error": "not found"})

    def _events(self):
        since = 0
        last = self.headers.get("Last-Event-ID", "")
        q = self.path.split("?", 1)[1] if "?" in self.path else ""
        for part in q.split("&"):
            k, _, v = part.partition("=")
            if k == "since" and v.isdigit():
                since = int(v)
        if last.isdigit():
            since = int(last)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Connection", "close")
        self._common()
        self.end_headers()
        self.close_connection = True
        self.wiz.touch()
        try:
            self.wfile.write(b"retry: 2000\n\n")
            self.wfile.flush()
            while not self.wiz.io.closed and not self.wiz.stopped.is_set():
                evs = self.wiz.io.wait_events(since, timeout=getattr(self.server, "sse_ping", 15))
                if not evs:
                    self.wfile.write(b": ping\n\n")
                for seq, name, data in evs:
                    payload = json.dumps({"name": name, "data": data}, default=str)
                    self.wfile.write(f"id: {seq}\nevent: porch\ndata: {payload}\n\n".encode())
                    since = seq
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, socket.timeout, ssl.SSLError, OSError):
            return

    def _qr(self):
        q = self.path.split("?", 1)[1] if "?" in self.path else ""
        if "for=ready" in q.split("&"):
            # The ready page's phone QR: Pocket's sign-in start (ready.info).
            r = self.wiz.ready()
            url = r["pocket_signin"] if r else None
        else:
            url = self.wiz.io.phone_url
        # H: the page knocks out the middle for the porch mark (up to ~30%
        # of modules may be lost). No quiet zone: the page pads it itself.
        m = qr_matrix(url, ec="H", border=0) if url else None
        if m is None:
            return self._json(404, {"error": "no QR available"})
        return self._json(200, {"size": len(m), "ec": "H",
                                "rows": ["".join("1" if c else "0" for c in r) for r in m]})

    # ---- POST ------------------------------------------------------------------
    def do_POST(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if not self._origin_ok():
            return self._json(403, {"error": "cross-origin request refused"})
        body = ph.read_json_body(self, BODY_CAP)
        if body is None:
            return self._json(400, {"error": "bad JSON body"})
        if path == "/api/session":
            code, obj, sid = self.wiz.open_session(body.get("key"))
            extra = ()
            if sid:
                extra = (("Set-Cookie", f"{COOKIE}={sid}; Path=/; Secure; HttpOnly; SameSite=Strict"),)
            return self._json(code, obj, extra)
        csrf = self._csrf()
        if csrf is None:
            return self._json(401, {"error": "no session"})
        sent = self.headers.get("X-Porch-CSRF", "")
        if not hmac.compare_digest(sent.encode("utf-8", "replace"), csrf.encode()):
            return self._json(403, {"error": "missing or wrong X-Porch-CSRF"})
        self.wiz.touch()
        if path == "/api/run":
            code, obj = self.wiz.start("run", mode=str(body.get("mode") or "run"),
                                       dry_run=bool(body.get("dry_run")))
            return self._json(code, obj)
        if path == "/api/rollback":
            to = body.get("to") or None
            if to is not None and (not isinstance(to, str) or not _STEP_RE.fullmatch(to)):
                return self._json(400, {"error": "bad step id"})
            code, obj = self.wiz.start("rollback", dry_run=bool(body.get("dry_run")), to_step=to)
            return self._json(code, obj)
        pid = body.get("prompt")
        if not isinstance(pid, str) or not _PID_RE.fullmatch(pid):
            return self._json(400, {"error": "bad prompt id"})
        if path.startswith("/api/inputs/"):
            step = path[len("/api/inputs/"):]
            if not _STEP_RE.fullmatch(step):
                return self._json(400, {"error": "bad step id"})
            errs = self.wiz.io.submit_inputs(step, pid, body.get("values"))
            if errs is None:
                return self._json(409, {"error": "that question is no longer open"})
            if errs:
                return self._json(422, {"errors": errs})
            return self._json(200, {"ok": True})
        if path == "/api/confirm":
            if not self.wiz.io.submit_confirm(pid, bool(body.get("answer"))):
                return self._json(409, {"error": "that question is no longer open"})
            return self._json(200, {"ok": True})
        if path == "/api/cancel":
            return self._json(200 if self.wiz.io.cancel(pid) else 409, {"ok": True})
        return self._json(404, {"error": "not found"})


class TLSServer(ph.BoundedThreadingHTTPServer):
    """BoundedThreadingHTTPServer whose accepted sockets are wrapped in TLS
    (handshake deferred to the handler thread). `sslctx` may be set after
    binding, so :443 can be bound as root before the certificate exists."""

    sslctx = None
    tls = True
    wizard = None
    sse_ping = 15

    def get_request(self):
        sock, addr = self.socket.accept()
        if self.sslctx is None:
            sock.close()
            raise OSError("TLS not ready")
        return self.sslctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], (ssl.SSLError, OSError)):
            return
        super().handle_error(request, client_address)


def server_context(cert, key):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    c.minimum_version = ssl.TLSVersion.TLSv1_2
    c.load_cert_chain(cert, key)
    return c


def bind_tls(addr, max_connections=32):
    """A TLSServer bound to addr (no certificate yet)."""
    host = addr[0]
    attrs = {"max_connections": max_connections}
    if ":" in host:
        attrs["address_family"] = socket.AF_INET6
    cls = type("TLSServer", (TLSServer,), attrs)
    return cls(addr, Handler)


def make_tls_server(wizard, addr, cert, key):
    srv = bind_tls(addr)
    srv.sslctx = server_context(cert, key)
    srv.wizard = wizard
    return srv


# ---- :80 for the ACME http-01 challenge ------------------------------------------

class AcmeHandler(ph.HardenedHandlerMixin, BaseHTTPRequestHandler):
    server_version = "porch-setup"
    PREFIX = "/.well-known/acme-challenge/"

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        body, code, ctype = b"not found\n", 404, "text/plain; charset=utf-8"
        if path.startswith(self.PREFIX):
            token = path[len(self.PREFIX):]
            if re.fullmatch(r"[A-Za-z0-9_-]{1,256}", token):
                p = os.path.join(self.server.webroot, token)
                try:
                    with open(p, "rb") as f:
                        body, code, ctype = f.read(4096), 200, "application/octet-stream"
                except OSError:
                    pass
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        ph.security_headers(self)
        self.end_headers()
        self.wfile.write(body)

    do_HEAD = do_GET


def bind_acme(addr, webroot):
    host = addr[0]
    attrs = {"max_connections": 16}
    if ":" in host:
        attrs["address_family"] = socket.AF_INET6
    cls = type("AcmeServer", (ph.BoundedThreadingHTTPServer,), attrs)
    srv = cls(addr, AcmeHandler)
    srv.webroot = webroot
    return srv


# ---- certificates ----------------------------------------------------------------

def fingerprint(cert_path):
    """SHA-256 fingerprint of the first certificate in a PEM file, AA:BB:..."""
    with open(cert_path, "r", encoding="ascii") as f:
        pem = f.read()
    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)
    if not m:
        raise WebError("no certificate in " + cert_path)
    der = ssl.PEM_cert_to_DER_cert(m.group(0))
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def self_signed_argv(cert, key, sans, days=2):
    san = ",".join(sans)
    return ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-keyout", key, "-out", cert, "-days", str(days),
            "-subj", "/CN=porch setup wizard", "-addext", f"subjectAltName={san}",
            "-addext", "basicConstraints=critical,CA:FALSE",
            "-addext", "extendedKeyUsage=serverAuth"]


def make_self_signed(runner, directory, extra_ips=(), extra_names=()):
    """(cert, key, sha256 fingerprint) in `directory` (0700, key 0600)."""
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    cert, key = os.path.join(directory, "wizard.crt"), os.path.join(directory, "wizard.key")
    sans = ["DNS:localhost", "IP:127.0.0.1", "IP:::1"]
    sans += [f"IP:{ip}" for ip in extra_ips if ip]
    sans += [f"DNS:{n}" for n in extra_names if n]
    old = os.umask(0o077)
    try:
        r = runner.run(self_signed_argv(cert, key, sans), mutating=False, timeout=60)
    finally:
        os.umask(old)
    if r.returncode != 0:
        raise WebError("openssl could not make a certificate: " + (r.stderr or "").strip()[-300:])
    os.chmod(key, 0o600)
    return cert, key, fingerprint(cert)


# ---- privilege drop -------------------------------------------------------------

def drop_privileges(env=None, os_mod=os, pwd_mod=None):
    """After binding :80/:443 as root, become the user who ran sudo
    (SUDO_UID / SUDO_GID). No-op (returns None) when not root. Raises
    WebError rather than ever continuing as root. Returns the new uid."""
    import pwd as _pwd
    pwd_mod = pwd_mod or _pwd
    env = os.environ if env is None else env
    if os_mod.geteuid() != 0:
        return None
    uid_s, gid_s = env.get("SUDO_UID", ""), env.get("SUDO_GID", "")
    if not (uid_s.isdigit() and gid_s.isdigit()):
        raise WebError("running as root without SUDO_UID/SUDO_GID: start the wizard with "
                       "sudo from the account that will own porch")
    uid, gid = int(uid_s), int(gid_s)
    if uid == 0 or gid == 0:
        raise WebError("refusing to run the wizard as root (SUDO_UID/SUDO_GID is 0): run sudo "
                       "from the account that will own porch")
    pw = pwd_mod.getpwuid(uid)
    groups = os_mod.getgrouplist(pw.pw_name, gid)
    os_mod.setgroups(groups)
    os_mod.setresgid(gid, gid, gid)
    os_mod.setresuid(uid, uid, uid)
    try:
        os_mod.setuid(0)
    except PermissionError:
        pass
    else:
        raise WebError("privilege drop failed: could regain root")
    if os_mod.geteuid() != uid or os_mod.getegid() != gid:
        raise WebError("privilege drop failed")
    if isinstance(env, dict) or env is os.environ:
        env["HOME"] = pw.pw_dir
        env["USER"] = env["LOGNAME"] = pw.pw_name
        for k in ("SUDO_COMMAND", "SUDO_USER", "SUDO_UID", "SUDO_GID", "MAIL"):
            env.pop(k, None)
    return uid


# ---- terminal QR ---------------------------------------------------------------------

def qr_matrix(data, ec="L", border=2):
    """[[bool]] QR modules (`border`-module quiet zone) or None when
    python-qrcode is not installed. Optional: nothing else depends on it.
    ec: L/M/Q/H error correction (H leaves room for the logo the page draws)."""
    try:
        import qrcode
    except ImportError:
        return None
    try:
        q = qrcode.QRCode(border=border,
                          error_correction=getattr(qrcode.constants, "ERROR_CORRECT_" + ec))
        q.add_data(data)
        q.make(fit=True)
        return q.get_matrix()
    except Exception:  # noqa: BLE001
        return None


def qr_text(data):
    """Half-block terminal art for `data`, or "" (no python-qrcode)."""
    m = qr_matrix(data)
    if not m:
        return ""
    lines = []
    for y in range(0, len(m), 2):
        top, bot = m[y], (m[y + 1] if y + 1 < len(m) else [False] * len(m[y]))
        row = []
        for a, b in zip(top, bot):
            # dark modules print as spaces on a light background via inverse
            row.append({(True, True): " ", (True, False): "▄",
                        (False, True): "▀", (False, False): "█"}[(a, b)])
        lines.append("".join(row))
    return "\n".join(lines)


def private_tempdir(prefix="porch-web-"):
    d = tempfile.mkdtemp(prefix=prefix)
    os.chmod(d, 0o700)
    return d


def rmtree_quiet(path):
    if path:
        shutil.rmtree(path, ignore_errors=True)


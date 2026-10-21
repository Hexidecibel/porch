"""Shared fixtures for tests/test_pocket_api.py and tests/test_pocket_stepup.py:
a Pocket server on an ephemeral 127.0.0.1 port in a thread, every store in a
temp dir, a fake porch-auth (CLI-token API) on another thread, an injectable
clock, fake launchers. Never touches ~/pocket, data/, /tmp/tunnel-state or
the live auth server. (Not a test module: it defines no TestCase.)
"""

import hashlib
import http.client
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
_LIB = os.path.join(_HERE, "..", "lib")
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
# Launch recipes any path writes go to a throwaway dir (bin/test sets it too).
os.environ.setdefault("PORCH_DOORS_DIR", tempfile.mkdtemp(prefix="porch-doors-"))
os.environ.setdefault("PORCH_CONFIG", "none")

_spec = importlib.util.spec_from_file_location("pocketserver", os.path.join(_LIB, "pocketserver.py"))
ps = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ps)
import auth_client  # noqa: E402
import pocket_stepup  # noqa: E402

OWNER_TOKEN = "o" * 64
OWNER2_TOKEN = "p" * 64
GUEST_TOKEN = "g" * 64
CLI_TOKEN = "cli-token-" + "x" * 30
AUTH_TOKEN = "auth-cli-token-" + "z" * 40
ADMIN_PASSWORD = "right-password-123"
RP_ID = "pocket.test"
RP_ORIGIN = "https://pocket.test"


def sha(t):
    return hashlib.sha256(t.encode()).hexdigest()


def write_devices(path):
    devices = [
        {"id": "dev_owner", "name": "My iPhone", "type": "browser", "role": "admin",
         "token_sha256": sha(OWNER_TOKEN)},
        {"id": "dev_owner2", "name": "Laptop", "type": "browser", "role": "admin",
         "token_sha256": sha(OWNER2_TOKEN)},
        {"id": "dev_guest", "name": "guest", "type": "browser", "role": "guest",
         "token_sha256": sha(GUEST_TOKEN)},
    ]
    with open(path, "w") as f:
        json.dump({"devices": devices}, f)


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


# ---- fake porch-auth ---------------------------------------------------------------

def fake_auth_state():
    return {
        "needs_setup": False,
        "pairings": [
            {"code": "ABCD-1234", "device_name": "build-box", "kind": "tunnel",
             "expires_at": 1_900_000_000, "created_at": 1_800_000_000},
            {"code": "WEBB-5678", "device_name": "Sam's Pixel", "kind": "web",
             "expires_at": 1_900_000_000, "created_at": 1_800_000_000},
        ],
        "devices": [
            {"id": "dev_owner", "name": "My iPhone", "type": "browser", "apps": ["*"],
             "pass": None, "role": "admin", "tunnel_admin": None, "revoked": False,
             "created_at": 1, "expires_at": None, "invite_id": None, "last_seen": 5,
             "run_id_history": [], "token_sha256": "LEAK-ME-NOT"},
            {"id": "dev_box", "name": "box", "type": "tunnel", "apps": None, "pass": None,
             "role": None, "tunnel_admin": False, "revoked": False, "created_at": 2,
             "expires_at": None, "invite_id": None, "last_seen": 6, "run_id_history": ["r1"]},
        ],
        "protected_apps": ["music.tunnel.cush.rocks"],
        "known_hosts": [{"host": "music.tunnel.cush.rocks", "protected": True},
                        {"host": "trendlab.cush.rocks", "protected": False}],
        "public_paths": [
            {"id": "pp_0000beef", "host": "music.tunnel.cush.rocks", "path": "/s/",
             "kind": "prefix", "app": "promo-studio", "why": "share links",
             "created_at": 1_800_000_000, "created_by": "cli", "enabled": True,
             "active": True, "inactive": None},
        ],
        "access_requests": [
            {"id": "acc0000000000001", "host": "trendlab.cush.rocks", "note": "Robin",
             "ip": "203.0.113.5", "kind": "stranger", "device_id": None, "device_name": None,
             "state": "pending", "how": None, "invite_id": None, "created": 1_800_000_000,
             "decided": None, "until": 1_800_001_800, "waiting": 1,
             "invite_url": "LEAK-ME-NOT", "tokens": ["LEAK-ME-NOT"]},
        ],
        "invites": [
            {"id": "inv_1", "note": "Sam", "apps": ["trendlab.cush.rocks"], "landing": None,
             "uses": 0, "max_uses": 1, "live": 0, "standing": False, "device_ttl_minutes": None,
             "status": "active", "expires_at": 1_900_000_000, "created_at": 1_800_000_000,
             "devices": []},
        ],
    }


class FakeAuth(BaseHTTPRequestHandler):
    """Accepts exactly the CLI token; records every request (bodies too, for
    asserting what Pocket sent)."""

    def log_message(self, *a):
        pass

    def _answer(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_one(self):
        srv = self.server
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            body = json.loads(raw) if raw else {}
        except ValueError:
            body = None
        srv.seen.append({"method": self.command, "path": self.path, "body": body,
                         "headers": {k.lower(): v for k, v in self.headers.items()}})
        if self.headers.get(auth_client.CLI_TOKEN_HEADER) != AUTH_TOKEN:
            return self._answer(401, {"error": "unauthorized"})
        p = self.path
        if p in srv.missing:
            return self._answer(404, {"error": "not found"})
        if not isinstance(body, dict) and p not in ("/auth/admin/verify-password",
                                                    "/auth/admin/device-rename"):
            return self._answer(400, {"error": "JSON body must be an object"})
        if not isinstance(body, dict):
            return self._answer(400, {"error": "JSON body must be an object"})
        if p == "/auth/admin/state":
            return self._answer(200, srv.state)
        if p == "/auth/admin/verify-password":
            if body.get("password") == ADMIN_PASSWORD:
                return self._answer(200, {"ok": True})
            if not body:
                return self._answer(400, {"error": "no password"})
            return self._answer(401, {"error": "invalid password"})
        if p == "/auth/admin/approve":
            code = body.get("code")
            pr = next((x for x in srv.state["pairings"] if x["code"] == code), None)
            if pr is None:
                return self._answer(404, {"error": "code not found"})
            if pr["kind"] == "web" and "apps" not in body:
                return self._answer(400, {"error": "a web pairing needs apps"})
            srv.state["pairings"].remove(pr)
            return self._answer(200, {"ok": True, "device_id": "dev_new", "type": "tunnel"})
        if p == "/auth/admin/reject":
            return self._answer(200, {"ok": True})
        if p in ("/auth/admin/revoke", "/auth/admin/device-apps", "/auth/admin/device-rename"):
            if not body.get("device_id"):
                return self._answer(400, {"error": "device_id required"})
            if body["device_id"] == "dev_missing":
                return self._answer(404, {"error": "device not found"})
            return self._answer(200, {"ok": True})
        if p == "/auth/admin/device-role":
            return self._answer(200, {"ok": True, "role": body.get("role"),
                                      "tunnel_admin": body.get("role") == "admin"})
        if p == "/auth/admin/apps":
            return self._answer(200, {"ok": True})
        if p == "/auth/admin/invites":
            inv = {"id": "inv_new", "note": body.get("note", ""), "apps": body.get("apps"),
                   "uses": 0, "max_uses": body.get("max_uses", 1), "standing": False,
                   "status": "active", "token_sha256": "LEAK-ME-NOT", "created_at": 1}
            return self._answer(200, {"ok": True, "invite": inv,
                                      "url": srv.invite_url})
        if p == "/auth/admin/invite-revoke":
            return self._answer(200, {"ok": True})
        if p == "/auth/admin/access-requests/decide":
            r = next((x for x in srv.state.get("access_requests", [])
                      if x["id"] == body.get("id") and x["state"] == "pending"), None)
            if r is None:
                return self._answer(404, {"error": "No such request"})
            if body.get("decision") not in ("allow", "deny"):
                return self._answer(400, {"error": "decision must be allow or deny"})
            r["state"] = "approved" if body["decision"] == "allow" else "denied"
            if body["decision"] == "allow":
                r.update(how="invite", invite_id="inv_acc")
            return self._answer(200, {"ok": True, "request": dict(r)})
        if p == "/auth/admin/set-password":
            return self._answer(200, {"ok": True})
        if p == "/auth/admin/public-paths":
            items = srv.state.setdefault("public_paths", [])
            if self.command == "GET":
                return self._answer(200, {"public_paths": items, "max": 100})
            action = body.get("action")
            if action == "add":
                if body.get("path") == "/":
                    return self._answer(400, {"error": "a public path cannot be the whole site (/)"})
                entry = {"id": "pp_%08x" % (len(items) + 1), "host": body.get("host"),
                         "path": body.get("path"), "app": body.get("app"),
                         "why": body.get("why", ""), "created_by": body.get("by"),
                         "kind": "prefix" if str(body.get("path")).endswith("/") else "exact",
                         "created_at": 1_800_000_100, "enabled": True, "active": True,
                         "inactive": None, "secret": "LEAK-ME-NOT"}
                items.append(entry)
                return self._answer(200, {"ok": True, "entry": entry, "public_paths": items,
                                          "haproxy": "ok"})
            entry = next((e for e in items if e["id"] == body.get("id")), None)
            if entry is None:
                return self._answer(404, {"error": "public path not found"})
            if action == "remove":
                items.remove(entry)
                entry = None
            else:
                entry["enabled"] = entry["active"] = action == "enable"
                entry["inactive"] = None if entry["active"] else "switched off"
            return self._answer(200, {"ok": True, "entry": entry, "public_paths": items,
                                      "haproxy": "ok"})
        return self._answer(404, {"error": "not found"})

    do_GET = do_POST = handle_one


def start_fake_auth(data_dir):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeAuth)
    srv.seen, srv.state, srv.missing = [], fake_auth_state(), set()
    srv.invite_url = "https://auth.cush.rocks/auth/invite/INVITE-SECRET-" + "q" * 20
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    with open(os.path.join(data_dir, auth_client.CLI_TOKEN_FILENAME), "w") as f:
        f.write(AUTH_TOKEN + "\n")
    return srv


# ---- doors ------------------------------------------------------------------------

class Sleepers:
    """Throwaway processes whose pids stand in for live launchers."""

    def __init__(self):
        self.procs = []

    def pid(self):
        p = subprocess.Popen(["sleep", "120"])
        self.procs.append(p)
        return p.pid

    def close(self):
        for p in self.procs:
            try:
                p.kill()
                p.wait(5)
            except OSError:
                pass


def write_door(state_dir, name, pid, **extra):
    st = {"name": name, "type": extra.pop("type", "drop"), "pid": pid, "port": 9999,
          "started": extra.pop("started", 1_800_000_000), "expires": extra.pop("expires", 4_000_000_000)}
    st.update(extra)
    with open(os.path.join(state_dir, f"{name}.json"), "w") as f:
        json.dump(st, f)
    return st


class FakeRunner:
    """door_ops.run_launch's runner: records the call, writes a state file."""

    def __init__(self, state_dir, sleepers, rc=0):
        self.state_dir, self.sleepers, self.rc = state_dir, sleepers, rc
        self.calls = []

    def __call__(self, argv, **kw):
        self.calls.append({"argv": list(argv), **kw})
        if self.rc == 0:
            name = argv[1]
            rules = {}
            if "--guest-link" in argv:
                rules["guest"] = "G" * 22
            write_door(self.state_dir, name, self.sleepers.pid(), type=os.path.basename(argv[0]),
                       rules=rules)
        return subprocess.CompletedProcess(argv, self.rc, b"", b"" if self.rc == 0 else b"boom")


# ---- the server -------------------------------------------------------------------

class PocketFixture:
    """Build with .start(); .stop() in tearDown. Attributes: tmp, base,
    state_dir, port, H, clock, auth (the fake server), runner, sleepers,
    reopened."""

    def __init__(self, watcher=False, auth=True, extra=None):
        self.tmp = tempfile.mkdtemp(prefix="porch-pocket-api-")
        self.base = os.path.join(self.tmp, "pocket")
        self.inbox = os.path.join(self.base, "inbox")
        os.makedirs(self.inbox)
        self.data = os.path.join(self.tmp, "data")
        os.makedirs(self.data)
        self.devices = os.path.join(self.data, "devices.json")
        write_devices(self.devices)
        self.state_dir = os.path.join(self.tmp, "state")
        os.makedirs(self.state_dir)
        self.doors_dir = os.path.join(self.tmp, "doors")
        os.makedirs(self.doors_dir, mode=0o700)
        self.inspect_base = os.path.join(self.tmp, "inspect")
        os.makedirs(self.inspect_base, mode=0o700)
        self.history = os.path.join(self.data, "history.jsonl")
        self.clock = Clock()
        self.sleepers = Sleepers()
        self.runner = FakeRunner(self.state_dir, self.sleepers)
        self.reopened = []
        self.auth = start_fake_auth(self.data) if auth else None
        self.client = auth_client.Client(
            self.data, f"http://127.0.0.1:{self.auth.server_address[1]}") if auth else None
        self.hub = ps.Hub(max_total=8, per_client=8)
        attrs = dict(
            base_dir=ps.Path(self.base), inbox_dir=ps.Path(self.inbox),
            devices_path=self.devices, store=ps.ClipStore(os.path.join(self.base, ".clip.json")),
            hub=self.hub, cli_token=CLI_TOKEN, min_free=0, sse_heartbeat=0.3,
            keys=ps.KeyStore(os.path.join(self.base, ".share-keys.json")),
            reopen_store=ps.reopen_requests.Store(os.path.join(self.tmp, "requests.json")),
            state_dir=self.state_dir, history_path=self.history, doors_dir=self.doors_dir,
            inspect_base=self.inspect_base, doors_unmanaged=False,
            door_runner=staticmethod(self.runner),
            door_reopener=staticmethod(lambda n, e: self.reopened.append((n, e))),
            audit=ps.AuditLog(os.path.join(self.base, ".audit.jsonl"), clock=self.clock),
            auth=self.client, watcher=None, pocket_name="pocket", pocket_host=RP_ID,
            rp_id=RP_ID, rp_origin=RP_ORIGIN,
            passkeys=pocket_stepup.PasskeyStore(os.path.join(self.base, ".passkeys.json"),
                                                RP_ID, self.clock),
            challenges=pocket_stepup.ChallengeStore(self.clock),
            stepups=pocket_stepup.StepUpStore(self.clock),
            stepup_fail_ip=ps.RateLimit(*pocket_stepup.FAIL_IP_RATE),
            stepup_fail_dev=ps.RateLimit(*pocket_stepup.FAIL_DEVICE_RATE),
            stepup_options_rate=ps.RateLimit(*pocket_stepup.OPTIONS_RATE),
            launch_lock=threading.Lock(),
        )
        if watcher and auth:
            attrs["watcher"] = ps.AuthWatcher(self.client, clock=self.clock)
        attrs.update(extra or {})
        self.H = type("H", (ps.PocketHandler,), attrs)

    def start(self):
        self.server = ps.BoundedThreadingHTTPServer(("127.0.0.1", 0), self.H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        if self.auth is not None:
            self.auth.shutdown()
            self.auth.server_close()
        self.sleepers.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- requests ----

    def req(self, method, path, body=None, token=OWNER_TOKEN, stepup=None, ctype="application/json",
            origin=True, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = dict(headers or {})
        if origin:
            h["Origin"] = f"http://127.0.0.1:{self.port}"
        cookies = []
        if token:
            cookies.append(f"cush_auth={token}")
        if stepup:
            cookies.append(f"{ps.STEPUP_COOKIE}={stepup}")
        if cookies:
            h["Cookie"] = "; ".join(cookies)
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            if ctype:
                h["Content-Type"] = ctype
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        raw = r.read()
        c.close()
        try:
            out = json.loads(raw) if raw else None
        except ValueError:
            out = raw
        return r, out

    def get(self, path, **kw):
        return self.req("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.req("POST", path, {} if body is None else body, **kw)

    def password_stepup(self, token=OWNER_TOKEN):
        r, out = self.post("/api/stepup/password", {"password": ADMIN_PASSWORD}, token=token)
        assert r.status == 200, (r.status, out)
        return cookie_value(r)


def cookie_value(r, name=None):
    name = name or ps.STEPUP_COOKIE
    for k, v in r.getheaders():
        if k.lower() == "set-cookie" and v.startswith(name + "="):
            return v.split(";", 1)[0].split("=", 1)[1]
    return None


class CaptureStderr:
    """Swap sys.stderr for the duration (the server threads write there)."""

    def __enter__(self):
        self.old = sys.stderr
        self.buf = io.StringIO()
        sys.stderr = self.buf
        return self

    def __exit__(self, *a):
        sys.stderr = self.old

    @property
    def text(self):
        return self.buf.getvalue()

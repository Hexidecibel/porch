"""Tests for lib/authserver.py. Stdlib unittest only; run with bin/test.

Nothing here talks to HAProxy or touches /etc/haproxy/maps or data/: the map
globals that main() normally sets are pointed at a temp dir, and the admin
socket is replaced by FakeHaproxy.
"""

import http.client
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "authserver", os.path.join(_HERE, "..", "lib", "authserver.py")
)
authserver = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(authserver)

TOKEN_A = "a" * 64
TOKEN_B = "b" * 64


class FakeHaproxy:
    """Stands in for _haproxy_socket_cmd, replying the way HAProxy 2.8 does.

    Keeps a live table and prepared versions per map so tests can assert on
    what a request would actually see, not only on the commands sent.
    """

    UNKNOWN = "Unknown map identifier. Please use #<id> or <file>.\n\n"

    def __init__(self, known):
        self.live = {path: {"stale": "old"} for path in known}
        self.pending = {}      # (path, version) -> {key: value}
        self.next_ver = {path: 0 for path in known}
        self.commands = []
        self.fail = None       # callable(cmd) -> reply to send instead, or False

    def __call__(self, cmd):
        self.commands.append(cmd)
        if self.fail is not None:
            forced = self.fail(cmd)
            if forced is not False:
                return forced
        verb, _, rest = cmd.partition(" map ")
        args = rest.split(" ")
        ver = None
        if args[0].startswith("@"):
            ver = int(args.pop(0)[1:])
        path = args[0]
        if path not in self.live:
            return self.UNKNOWN
        if verb == "prepare":
            self.next_ver[path] += 1
            self.pending[(path, self.next_ver[path])] = {}
            return f"New version created: {self.next_ver[path]}\n\n"
        if verb == "add":
            self.pending[(path, ver)][args[1]] = args[2]
            return "\n"
        if verb == "commit":
            self.live[path] = self.pending.pop((path, ver))
            return "\n"
        if verb == "clear" and ver is not None:
            self.pending.pop((path, ver), None)
            return "\n"
        raise AssertionError(f"unexpected command: {cmd}")

    def sent(self, path):
        """Commands sent for one map, with the path cut out for readability."""
        return [c.replace(" " + path, "") for c in self.commands if path in c.split(" ")]


class MapSyncTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = self.tmp.name
        self.grants = os.path.join(d, "cush-grants.map")
        self.identity = os.path.join(d, "cush-identity.map")
        self.protected = os.path.join(d, "cush-protected.map")
        self.devices = os.path.join(d, "cush-devices.map")
        state = {
            "devices": [
                {"id": "dev-a", "type": "browser", "role": "admin",
                 "name": "Laptop", "token_sha256": TOKEN_A, "apps": ["*"]},
                {"id": "dev-b", "type": "browser", "role": "guest",
                 "name": "Phone", "token_sha256": TOKEN_B,
                 "apps": ["grab.cush.rocks"]},
            ],
            "pairings": [],
            "admin": None,
            "protected_apps": ["grab.cush.rocks", "resume.cush.rocks"],
            "invites": [],
        }
        saved = {
            name: getattr(authserver, name)
            for name in ("MAPS_DIR", "GRANTS_MAP", "IDENTITY_MAP", "PROTECTED_MAP",
                         "DEVICES_MAP", "PUBLIC_MAP", "PUBLIC_EXACT_MAP", "STATE",
                         "_haproxy_socket_cmd", "log")
        }
        self.addCleanup(lambda: [setattr(authserver, k, v) for k, v in saved.items()])
        authserver.MAPS_DIR = d
        authserver.GRANTS_MAP = self.grants
        authserver.IDENTITY_MAP = self.identity
        authserver.PROTECTED_MAP = self.protected
        authserver.DEVICES_MAP = self.devices
        authserver.STATE = state
        authserver._PUSHED_TEXT.clear()
        authserver._UNKNOWN_MAPS_LOGGED.clear()
        self.logs = []
        authserver.log = self.logs.append
        # Like the real haproxy.cfg: the devices map is not loaded.
        self.hap = FakeHaproxy([self.grants, self.identity, self.protected])
        authserver._haproxy_socket_cmd = self.hap

    def test_import_did_not_configure_real_paths(self):
        # main() is what points the module at /etc/haproxy/maps; a bare import
        # must leave sync_haproxy_maps a no-op.
        fresh = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(fresh)
        self.assertEqual(fresh.DEVICES_MAP, "")
        calls = []
        fresh._haproxy_socket_cmd = calls.append
        fresh.sync_haproxy_maps()
        self.assertEqual(calls, [])

    def test_no_maps_never_touches_files_or_socket(self):
        # porch's fresh profile (no edge gate) starts the server with --no-maps:
        # no "Permission denied" from the haproxy admin socket, no WARNING.
        authserver.configure_maps(None)
        self.assertEqual(authserver.initial_map_sync(), "skipped")
        self.assertEqual(authserver.sync_haproxy_maps(force=True), "skipped")
        self.assertEqual(self.hap.sent(self.protected), [])
        self.assertFalse(os.path.exists(self.devices))
        self.assertEqual(self.logs, ["HAProxy map sync: off (no edge gate; --no-maps)"])
        authserver.configure_maps(os.path.dirname(self.devices))
        self.assertEqual(authserver.DEVICES_MAP, self.devices)
        self.assertEqual(authserver.initial_map_sync(), "ok")
        self.assertFalse(any("WARNING" in m for m in self.logs))

    def test_happy_path_command_sequence(self):
        authserver.sync_haproxy_maps()
        self.assertEqual(self.hap.sent(self.protected), [
            "prepare map",
            "add map @1 grab.cush.rocks 1",
            "add map @1 resume.cush.rocks 1",
            "commit map @1",
        ])
        self.assertEqual(self.hap.sent(self.grants), [
            "prepare map",
            f"add map @1 {TOKEN_A}:* dev-a",
            f"add map @1 {TOKEN_B}:grab.cush.rocks dev-b",
            "commit map @1",
        ])
        self.assertEqual(self.hap.sent(self.identity), [
            "prepare map",
            f"add map @1 {TOKEN_A} dev-a|admin|Laptop",
            f"add map @1 {TOKEN_B} dev-b|guest|Phone",
            "commit map @1",
        ])
        self.assertEqual(self.hap.live[self.protected],
                         {"grab.cush.rocks": "1", "resume.cush.rocks": "1"})
        # Nothing ever empties a live map in place.
        self.assertFalse([c for c in self.hap.commands
                          if re.match(r"(clear|del|set) map", c)])
        # Commit order: grants, identity, protected.
        commits = [c.split(" ")[-1] for c in self.hap.commands
                   if c.startswith("commit map")]
        self.assertEqual(commits, [self.grants, self.identity, self.protected])

    def test_files_written_and_unknown_devices_map_tolerated(self):
        authserver.sync_haproxy_maps()
        with open(self.devices) as f:
            self.assertEqual(f.read(), f"{TOKEN_A} dev-a\n{TOKEN_B} dev-b\n")
        with open(self.protected) as f:
            self.assertEqual(f.read(), "grab.cush.rocks 1\nresume.cush.rocks 1\n")
        self.assertEqual(self.hap.sent(self.devices), ["prepare map"])
        authserver.STATE["devices"].pop()
        authserver.sync_haproxy_maps()
        authserver.sync_haproxy_maps(force=True)
        noise = [m for m in self.logs if "cush-devices.map" in m]
        self.assertEqual(len(noise), 1, noise)

    def test_no_commit_when_an_add_fails(self):
        for reply in ("Out of memory error.\n\n", None):
            with self.subTest(reply=reply):
                self.setUp()
                bad = f"add map @1 {self.protected} resume.cush.rocks 1"
                self.hap.fail = lambda cmd: reply if cmd == bad else False
                authserver.sync_haproxy_maps()
                self.assertEqual(self.hap.sent(self.protected), [
                    "prepare map",
                    "add map @1 grab.cush.rocks 1",
                    "add map @1 resume.cush.rocks 1",
                    "clear map @1",
                ])
                # The old live map is untouched and the half-built version is gone.
                self.assertEqual(self.hap.live[self.protected], {"stale": "old"})
                self.assertNotIn((self.protected, 1), self.hap.pending)
                self.assertTrue(any("add 'resume.cush.rocks' failed" in m
                                    for m in self.logs))
                # The other maps still went through.
                self.assertNotIn("stale", self.hap.live[self.grants])

    def test_no_commit_when_prepare_fails(self):
        for reply in ("Permission denied\n\n", "New version created: \n\n", ""):
            with self.subTest(reply=reply):
                self.setUp()
                self.hap.fail = lambda cmd: (
                    reply if cmd == f"prepare map {self.protected}" else False)
                authserver.sync_haproxy_maps()
                self.assertEqual(self.hap.sent(self.protected), ["prepare map"])
                self.assertEqual(self.hap.live[self.protected], {"stale": "old"})
                self.assertTrue(any("prepare failed" in m for m in self.logs))

    def test_socket_down_sends_nothing_more(self):
        self.hap.fail = lambda cmd: None
        authserver.sync_haproxy_maps()
        self.assertEqual(self.hap.commands, [f"prepare map {self.grants}"])
        self.assertEqual(authserver._PUSHED_TEXT, {})

    def test_failed_commit_is_not_recorded(self):
        self.hap.fail = lambda cmd: (
            "Version number out of range.\n\n"
            if cmd.startswith(f"commit map @1 {self.protected}") else False)
        authserver.sync_haproxy_maps()
        self.assertEqual(self.hap.live[self.protected], {"stale": "old"})
        self.assertNotIn(self.protected, authserver._PUSHED_TEXT)

    def test_unchanged_map_skipped_on_second_sync(self):
        authserver.sync_haproxy_maps()
        self.hap.commands.clear()
        authserver.sync_haproxy_maps()
        self.assertEqual(self.hap.commands, [])
        # Only the map whose text changed is pushed again.
        authserver.STATE["protected_apps"].append("velo.cush.rocks")
        authserver.sync_haproxy_maps()
        self.assertEqual(self.hap.sent(self.protected), [
            "prepare map",
            "add map @2 grab.cush.rocks 1",
            "add map @2 resume.cush.rocks 1",
            "add map @2 velo.cush.rocks 1",
            "commit map @2",
        ])
        self.assertEqual(self.hap.sent(self.grants), [])
        self.assertEqual(self.hap.sent(self.identity), [])

    def test_force_pushes_unchanged_maps(self):
        authserver.sync_haproxy_maps()
        self.hap.commands.clear()
        authserver.sync_haproxy_maps(force=True)
        commits = [c for c in self.hap.commands if c.startswith("commit map")]
        self.assertEqual(len(commits), 3)

    def test_failed_push_retried_next_sync(self):
        bad = f"add map @1 {self.protected} grab.cush.rocks 1"
        self.hap.fail = lambda cmd: "Out of memory error.\n\n" if cmd == bad else False
        authserver.sync_haproxy_maps()
        self.assertEqual(self.hap.live[self.protected], {"stale": "old"})
        self.hap.fail = None
        self.hap.commands.clear()
        authserver.sync_haproxy_maps()
        # Same text as last time, but that push never landed: it goes again,
        # while the maps that did land are left alone.
        self.assertEqual(self.hap.sent(self.protected), [
            "prepare map",
            "add map @2 grab.cush.rocks 1",
            "add map @2 resume.cush.rocks 1",
            "commit map @2",
        ])
        self.assertEqual(self.hap.sent(self.grants), [])
        self.assertEqual(self.hap.live[self.protected],
                         {"grab.cush.rocks": "1", "resume.cush.rocks": "1"})

    def test_unwritable_files_disable_the_skip(self):
        authserver.sync_haproxy_maps()
        self.hap.commands.clear()

        def boom(path, text):
            raise PermissionError("read-only")
        real = authserver._atomic_write_text
        authserver._atomic_write_text = boom
        self.addCleanup(setattr, authserver, "_atomic_write_text", real)
        authserver.sync_haproxy_maps()
        commits = [c for c in self.hap.commands if c.startswith("commit map")]
        self.assertEqual(len(commits), 3)


class ServerCase(unittest.TestCase):
    """Runs AuthHandler on a loopback port against a temp data dir and temp
    map files, with FakeHaproxy as the admin socket."""

    PROTECTED = ["grab.cush.rocks", "trendlab.cush.rocks"]

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = self.tmp.name
        names = ("DATA_DIR", "DEVICES_PATH", "MAPS_DIR", "GRANTS_MAP",
                 "IDENTITY_MAP", "PROTECTED_MAP", "DEVICES_MAP", "STATE",
                 "PUBLIC_MAP", "PUBLIC_EXACT_MAP",
                 "TOKEN_CACHE", "CLI_TOKEN", "_haproxy_socket_cmd", "log",
                 "OWNER_STATE_DIR")
        saved = {name: getattr(authserver, name) for name in names}
        self.addCleanup(lambda: [setattr(authserver, k, v) for k, v in saved.items()])
        authserver.DATA_DIR = d
        authserver.OWNER_STATE_DIR = os.path.join(d, "tunnel-state")
        os.makedirs(authserver.OWNER_STATE_DIR)
        authserver._OWNER_NAMES_CACHE["key"] = None
        authserver.DEVICES_PATH = os.path.join(d, "devices.json")
        authserver.MAPS_DIR = d
        authserver.GRANTS_MAP = os.path.join(d, "cush-grants.map")
        authserver.IDENTITY_MAP = os.path.join(d, "cush-identity.map")
        authserver.PROTECTED_MAP = os.path.join(d, "cush-protected.map")
        authserver.DEVICES_MAP = os.path.join(d, "cush-devices.map")
        authserver.PUBLIC_MAP = os.path.join(d, "cush-public.map")
        authserver.PUBLIC_EXACT_MAP = os.path.join(d, "cush-public-exact.map")
        authserver.STATE = {
            "devices": [], "pairings": [], "invites": [],
            # Present so /auth/admin/state does not answer "needs_setup".
            "admin": {"session_secret": authserver.b64url(b"k" * 32), "epoch": 0},
            "server": {"addr": "tunnel.cush.rocks", "port": 7000},
            "protected_apps": list(self.PROTECTED),
            "app_hosts": list(self.PROTECTED),
        }
        authserver.TOKEN_CACHE = {}
        authserver._PUSHED_TEXT.clear()
        authserver._UNKNOWN_MAPS_LOGGED.clear()
        authserver.INVITE_ACCEPT_ATTEMPTS.clear()
        authserver.AUTH_ATTEMPTS.clear()
        authserver.GLOBAL_FAILS.clear()
        authserver.HANDOFF_CODES.clear()
        with authserver.PENDING_TOKENS_LOCK:
            authserver.PENDING_TOKENS.clear()
        self.logs = []
        authserver.log = self.logs.append
        self.hap = FakeHaproxy([authserver.GRANTS_MAP, authserver.IDENTITY_MAP,
                                authserver.PROTECTED_MAP])
        authserver._haproxy_socket_cmd = self.hap
        authserver.write_cli_token()
        self.cli = authserver.CLI_TOKEN

        class Quiet(authserver.AuthHandler):
            def log_message(self, format, *args):
                pass

        self.httpd = authserver.ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
        self.port = self.httpd.server_address[1]
        thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def req(self, method, path, body=None, headers=None, cli=True):
        """One request. Returns (status, decoded JSON or None, response headers)."""
        hdrs = dict(headers or {})
        if cli:
            hdrs.setdefault(authserver.CLI_TOKEN_HEADER, self.cli)
        payload = None
        if body is not None:
            payload = json.dumps(body)
            hdrs["Content-Type"] = "application/json"
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=payload, headers=hdrs)
            resp = conn.getresponse()
            raw = resp.read()
            try:
                data = json.loads(raw.decode("utf-8"))
            except ValueError:
                data = None
            return resp.status, data, resp.getheaders()
        finally:
            conn.close()

    def map_text(self, path):
        with open(path) as f:
            return f.read()


class StaticCssTest(ServerCase):
    """GET /auth/static/auth.css: the one static file, public, nothing else."""

    CSS = b".flex{display:flex}"

    def setUp(self):
        super().setUp()
        saved = (authserver.AUTH_CSS_FILE, authserver.AUTH_CSS, authserver.AUTH_CSS_ETAG)
        self.addCleanup(lambda: [setattr(authserver, k, v) for k, v in zip(
            ("AUTH_CSS_FILE", "AUTH_CSS", "AUTH_CSS_ETAG"), saved)])
        authserver.AUTH_CSS_FILE = os.path.join(self.tmp.name, "auth.css")
        with open(authserver.AUTH_CSS_FILE, "wb") as f:
            f.write(self.CSS)
        # Something next to it that a directory-serving route would hand out.
        with open(os.path.join(self.tmp.name, "other.css"), "wb") as f:
            f.write(b"nope")
        authserver.load_auth_css()

    def raw(self, path, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            # http.client sends the path as given, dot segments and all.
            conn.request("GET", path, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def test_served_without_a_session(self):
        status, headers, body = self.raw(authserver.AUTH_CSS_PATH)
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/css; charset=utf-8")
        self.assertEqual(headers["Cache-Control"], "no-cache")
        self.assertEqual(body, self.CSS)

    def test_etag_revalidates_and_changes_with_the_content(self):
        _, headers, _ = self.raw(authserver.AUTH_CSS_PATH)
        etag = headers["ETag"]
        status, _, body = self.raw(authserver.AUTH_CSS_PATH, {"If-None-Match": etag})
        self.assertEqual((status, body), (304, b""))
        with open(authserver.AUTH_CSS_FILE, "wb") as f:
            f.write(b".block{display:block}")
        authserver.load_auth_css()
        status, headers, _ = self.raw(authserver.AUTH_CSS_PATH, {"If-None-Match": etag})
        self.assertEqual(status, 200)
        self.assertNotEqual(headers["ETag"], etag)

    def test_nothing_else_under_static_is_served(self):
        for path in ("/auth/static/", "/auth/static", "/auth/static/other.css",
                     "/auth/static/auth.css/", "/auth/static/devices.json",
                     "/auth/static/../../data/devices.json",
                     "/auth/static/..%2f..%2fdata%2fdevices.json",
                     "/auth/static/%2e%2e/authserver.py",
                     "/auth/static/auth.css%00.py"):
            status, _, body = self.raw(path)
            self.assertEqual(status, 404, path)
            self.assertNotIn(b"nope", body)

    def test_porch_fonts_served_by_exact_hashed_path(self):
        import porch_http
        fonts = [p for p in porch_http.ASSETS if p.endswith(".woff2")]
        self.assertTrue(fonts)
        for p in fonts:
            status, headers, body = self.raw("/auth" + p)
            self.assertEqual(status, 200, p)
            self.assertEqual(headers["Content-Type"], "font/woff2")
            self.assertIn("immutable", headers["Cache-Control"])
            self.assertEqual(body[:4], b"wOF2")
        # the committed auth.css names exactly these files
        with open(os.path.join(os.path.dirname(authserver.__file__), "auth.css"), "rb") as f:
            css = f.read()
        for p in fonts:
            self.assertIn(("/auth" + p).encode(), css)
        for path in ("/auth/__porch-assets/fonts/geist-400.woff2",
                     "/auth/__porch-assets/../authserver.py",
                     "/auth/__porch-assets/%2e%2e/auth.css",
                     "/auth/__porch-assets/"):
            self.assertEqual(self.raw(path)[0], 404, path)

    def test_missing_file_is_a_404_not_a_crash(self):
        os.unlink(authserver.AUTH_CSS_FILE)
        authserver.load_auth_css()
        self.assertEqual(self.raw(authserver.AUTH_CSS_PATH)[0], 404)
        self.assertTrue(any("auth.css" in line for line in self.logs))
        self.assertEqual(self.req("GET", "/healthz", cli=False)[0], 200)

    def test_pages_link_the_local_sheet_and_nothing_external(self):
        for page in (authserver.ADMIN_HTML, authserver.LOGIN_HTML, authserver.INVITE_HTML):
            self.assertIn('<link rel="stylesheet" href="/auth/static/auth.css">', page)
            self.assertIsNone(re.search(r"""(?:src|href)\s*=\s*["']?(?:https?:)?//""", page))


class CliTokenTest(ServerCase):
    def test_token_file_is_private_and_matches(self):
        path = os.path.join(self.tmp.name, authserver.CLI_TOKEN_FILE)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        with open(path) as f:
            self.assertEqual(f.read().strip(), self.cli)
        self.assertGreaterEqual(len(self.cli), 40)
        # A restart mints a new token and the old one stops working.
        authserver.write_cli_token()
        self.assertNotEqual(authserver.CLI_TOKEN, self.cli)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(self.req("POST", "/auth/admin/apps",
                                  {"host": "x.cush.rocks", "action": "protect"})[0], 401)

    def test_token_authorises_admin_calls(self):
        code, body, _ = self.req("POST", "/auth/admin/apps",
                                 {"host": "gatetest.cush.rocks", "action": "protect"})
        self.assertEqual(code, 200)
        self.assertIn("gatetest.cush.rocks", body["protected_apps"])

    def test_missing_or_wrong_token_is_refused(self):
        body = {"host": "gatetest.cush.rocks", "action": "protect"}
        self.assertEqual(self.req("POST", "/auth/admin/apps", body, cli=False)[0], 401)
        for bad in ("nope", self.cli[:-1], self.cli + "x", "t\u00e9st"):
            hdr = {authserver.CLI_TOKEN_HEADER: bad.encode("utf-8").decode("latin-1")}
            self.assertEqual(self.req("POST", "/auth/admin/apps", body, hdr)[0], 401, bad)
        self.assertNotIn("gatetest.cush.rocks", authserver.STATE["protected_apps"])

    def test_token_ignored_on_proxied_requests(self):
        # HAProxy and nginx both stamp what they forward; a request carrying
        # any of these did not come from the local CLI.
        body = {"host": "gatetest.cush.rocks", "action": "protect"}
        for name in authserver.PROXY_HEADERS:
            code = self.req("POST", "/auth/admin/apps", body, {name: "203.0.113.9"})[0]
            self.assertEqual(code, 401, name)
        self.assertNotIn("gatetest.cush.rocks", authserver.STATE["protected_apps"])

    def test_token_never_rides_a_browser_request(self):
        body = {"host": "gatetest.cush.rocks", "action": "protect"}
        # Same-origin browser POST: passes _origin_ok, but Origin means it is
        # not the CLI, so the token does not count.
        same = {"Origin": f"http://127.0.0.1:{self.port}"}
        self.assertEqual(self.req("POST", "/auth/admin/apps", body, same)[0], 401)
        # Cross-origin: the CSRF guard still answers first.
        cross = {"Origin": "https://evil.tunnel.cush.rocks"}
        self.assertEqual(self.req("POST", "/auth/admin/apps", body, cross)[0], 403)


class AppsActionTest(ServerCase):
    def apps(self, host, action):
        return self.req("POST", "/auth/admin/apps", {"host": host, "action": action})

    def test_protect_unprotect_forget(self):
        host = "gatetest.cush.rocks"
        self.assertEqual(self.apps(host, "protect")[0], 200)
        self.assertIn(f"{host} 1\n", self.map_text(authserver.PROTECTED_MAP))
        self.assertIn(host, self.hap.live[authserver.PROTECTED_MAP])
        # Still protected: forget must refuse rather than leave it gated but unlisted.
        self.assertEqual(self.apps(host, "forget")[0], 409)
        self.assertEqual(self.apps(host, "unprotect")[0], 200)
        self.assertNotIn(host, self.map_text(authserver.PROTECTED_MAP))
        listed = [h["host"] for h in self.req("GET", "/auth/admin/state")[1]["known_hosts"]]
        self.assertIn(host, listed)
        self.assertEqual(self.apps(host, "forget")[0], 200)
        listed = [h["host"] for h in self.req("GET", "/auth/admin/state")[1]["known_hosts"]]
        self.assertNotIn(host, listed)
        self.assertNotIn(host, authserver.STATE["app_hosts"])
        self.assertEqual(self.apps(host, "forget")[0], 404)

    def test_forget_refuses_builtin_hosts(self):
        host = authserver.KNOWN_HOSTS[0]
        authserver.STATE["protected_apps"] = [
            h for h in authserver.STATE["protected_apps"] if h != host]
        self.assertEqual(self.apps(host, "forget")[0], 409)
        self.assertEqual(self.apps("auth.cush.rocks", "forget")[0], 400)
        self.assertEqual(self.apps("gatetest.cush.rocks", "bogus")[0], 400)


class Clock:
    """Stands in for the `time` module inside authserver so tests can move
    the clock forward instead of sleeping through a pass."""

    def __init__(self):
        self.offset = 0.0

    def time(self):
        return time.time() + self.offset

    def sleep(self, seconds):
        time.sleep(seconds)

    def advance(self, seconds):
        self.offset += seconds


GRAB = "grab.cush.rocks"
TREND = "trendlab.cush.rocks"


class PassCase(ServerCase):
    def setUp(self):
        super().setUp()
        self.clock = Clock()
        real = authserver.time
        authserver.time = self.clock
        self.addCleanup(setattr, authserver, "time", real)

    def invite(self, **body):
        """Create an invite through the API. Returns (plaintext token, id)."""
        body.setdefault("apps", [TREND])
        code, data, _ = self.req("POST", "/auth/admin/invites", body)
        self.assertEqual(code, 200, data)
        return data["url"].rsplit("/", 1)[1], data["invite"]["id"]

    def standing(self, minutes=2, cap=2, **body):
        return self.invite(standing=True, device_ttl_minutes=minutes,
                           max_uses=cap, **body)

    def accept(self, token, cookie=None):
        """POST /i/<token>/accept as a browser. Returns (status, body, the new
        cush_auth cookie value or None, its Max-Age or None)."""
        authserver.INVITE_ACCEPT_ATTEMPTS.clear()
        headers = {"Cookie": f"cush_auth={cookie}"} if cookie else {}
        code, data, hdrs = self.req("POST", f"/i/{token}/accept",
                                    {"device_name": "t"}, headers, cli=False)
        value = max_age = None
        for k, v in hdrs:
            if k.lower() == "set-cookie" and v.startswith("cush_auth="):
                value = v.split(";")[0].split("=", 1)[1]
                max_age = int(re.search(r"Max-Age=(\d+)", v).group(1))
        return code, data, value, max_age

    def state(self):
        return self.req("GET", "/auth/admin/state")[1]

    def grants(self):
        """Grants-map keys as HAProxy would see them after a sync at 'now'."""
        authserver.sync_haproxy_maps(now=self.clock.time())
        return set(self.hap.live[authserver.GRANTS_MAP])

    def key(self, cookie, host):
        return f"{authserver.sha256_hex(cookie)}:{host}"

    def device(self, cookie):
        sha = authserver.sha256_hex(cookie)
        return next((d for d in authserver.STATE["devices"]
                     if d["token_sha256"] == sha), None)

    def invite_row(self, invite_id):
        return next(i for i in self.state()["invites"] if i["id"] == invite_id)


class InviteCreateTest(PassCase):
    def create(self, **body):
        body.setdefault("apps", [TREND])
        return self.req("POST", "/auth/admin/invites", body)

    def test_all_apps_rejected(self):
        code, data, _ = self.create(apps=["*"])
        self.assertEqual(code, 400)
        self.assertIn("all apps", data["error"])
        self.assertEqual(self.create(apps=["*"], standing=True,
                                     device_ttl_minutes=60)[0], 400)
        self.assertEqual(authserver.STATE["invites"], [])

    def test_device_ttl_validation(self):
        for bad in (0, -5, authserver.DEVICE_TTL_MAX_MINUTES + 1, True, "60", 1.5):
            self.assertEqual(self.create(device_ttl_minutes=bad)[0], 400, bad)
        self.assertEqual(self.create(device_ttl_minutes=1)[0], 200)
        self.assertEqual(
            self.create(device_ttl_minutes=authserver.DEVICE_TTL_MAX_MINUTES)[0], 200)
        # Left out or null: permanent devices, as before.
        _, data, _ = self.create()
        self.assertIsNone(data["invite"]["device_ttl_minutes"])
        self.assertFalse(data["invite"]["standing"])

    def test_standing_rules(self):
        # Permanent devices from a link that never closes: refused.
        self.assertEqual(self.create(standing=True)[0], 400)
        self.assertEqual(self.create(standing="yes", device_ttl_minutes=60)[0], 400)
        code, data, _ = self.create(standing=True, device_ttl_minutes=1440)
        self.assertEqual(code, 200)
        inv = data["invite"]
        self.assertIsNone(inv["expires_at"])
        self.assertEqual(inv["max_uses"], authserver.INVITE_STANDING_DEFAULT_LIVE)
        self.assertIsNone(authserver.STATE["invites"][-1]["expires_at"])
        # The live cap goes to 500; an ordinary invite still stops at 50.
        self.assertEqual(self.create(standing=True, device_ttl_minutes=60,
                                     max_uses=500)[0], 200)
        self.assertEqual(self.create(standing=True, device_ttl_minutes=60,
                                     max_uses=501)[0], 400)
        self.assertEqual(self.create(max_uses=51)[0], 400)
        # A standing link may still be given an expiry; others must have one.
        _, data, _ = self.create(standing=True, device_ttl_minutes=60, expires_hours=2)
        self.assertAlmostEqual(data["invite"]["expires_at"],
                               self.clock.time() + 7200, delta=5)
        self.assertEqual(self.create(expires_hours=None)[0], 400)

    def test_state_payload_survives_null_expiry(self):
        _, invite_id = self.standing()
        row = self.invite_row(invite_id)
        self.assertIsNone(row["expires_at"])
        self.assertEqual((row["standing"], row["live"], row["status"],
                          row["device_ttl_minutes"]), (True, 0, "active", 2))


class InviteStatusTest(PassCase):
    def setUp(self):
        super().setUp()
        self.now = 1_000_000.0
        iso = authserver.iso_from_epoch
        self.inv = {"id": "inv_00000001", "standing": True, "max_uses": 2,
                    "uses": 99, "expires_at": None, "device_ttl_minutes": 60,
                    "created_at": iso(self.now - 90 * 86400)}
        authserver.STATE["invites"] = [self.inv]

    def dev(self, n, **extra):
        d = {"id": f"dev_{n}", "type": "browser", "role": "guest",
             "apps": [TREND], "token_sha256": f"{n:064x}", "revoked": False}
        d.update(extra)
        authserver.STATE["devices"].append(d)
        return d

    def status(self, now=None):
        return authserver._invite_status(self.inv, self.now if now is None else now)

    def test_standing_null_expiry_is_active_whatever_uses_says(self):
        self.assertEqual(self.status(), "active")
        self.assertEqual(self.status(self.now + 10 * 365 * 86400), "active")

    def test_null_expiry_only_means_forever_on_a_standing_invite(self):
        self.inv["standing"] = False
        self.inv["uses"] = 0
        self.assertEqual(self.status(), "expired")

    def test_standing_invite_can_still_expire_and_be_revoked(self):
        self.inv["expires_at"] = authserver.iso_from_epoch(self.now + 60)
        self.assertEqual(self.status(), "active")
        self.assertEqual(self.status(self.now + 61), "expired")
        self.inv["revoked"] = True
        self.assertEqual(self.status(), "revoked")

    def test_cap_counts_live_devices_and_refills(self):
        iso = authserver.iso_from_epoch
        self.dev(1, invite_id=self.inv["id"], expires_at=iso(self.now + 100))
        self.assertEqual(self.status(), "active")
        self.dev(2, invite_id=self.inv["id"], expires_at=iso(self.now + 200))
        self.assertEqual(authserver._invite_live_count(self.inv, self.now), 2)
        self.assertEqual(self.status(), "full")
        # Devices of other invites, and permanent ones, do not count.
        self.dev(3, invite_id="inv_ffffffff", expires_at=iso(self.now + 200))
        self.dev(4)
        self.assertEqual(authserver._invite_live_count(self.inv, self.now), 2)
        # The first pass runs out: one slot is free again, before any sweep.
        self.assertEqual(self.status(self.now + 101), "active")
        self.assertEqual(authserver._invite_live_count(self.inv, self.now + 201), 0)

    def test_revoked_devices_and_passes_in_the_count(self):
        iso = authserver.iso_from_epoch
        d = self.dev(1, invite_id=self.inv["id"], expires_at=iso(self.now + 100))
        self.dev(2, apps=[GRAB], **{"pass": {
            "invite_id": self.inv["id"], "apps": [TREND],
            "expires_at": iso(self.now + 50)}})
        self.assertEqual(self.status(), "full")
        self.assertEqual(self.status(self.now + 51), "active")
        d["revoked"] = True
        self.assertEqual(authserver._invite_live_count(self.inv, self.now), 1)

    def test_sweeper_keeps_an_old_open_standing_invite(self):
        # 90 days old, no expiry, currently full: none of that is "finished".
        iso = authserver.iso_from_epoch
        now = self.clock.time()
        self.inv["created_at"] = iso(now - 90 * 86400)
        self.dev(1, invite_id=self.inv["id"], expires_at=iso(now + 500))
        self.dev(2, invite_id=self.inv["id"], expires_at=iso(now + 500))
        self.assertEqual(authserver._invite_status(self.inv, now), "full")
        authserver.sweep_once(now)
        self.assertEqual(authserver.STATE["invites"], [self.inv])
        # Once revoked it ages out after the keep window like any other.
        self.inv["revoked"] = True
        self.inv["revoked_at"] = iso(now - authserver.INVITE_KEEP_SECS - 60)
        authserver.sweep_once(now)
        self.assertEqual(authserver.STATE["invites"], [])


class DeviceExpiryTest(PassCase):
    def test_permanent_devices_never_expire(self):
        far = time.time() + 50 * 365 * 86400
        for d in ({}, {"expires_at": None}, {"expires_at": ""}):
            self.assertFalse(authserver._device_expired(d, far), d)
        # Present but unreadable: fail closed.
        self.assertTrue(authserver._device_expired({"expires_at": "soon"}, 0))
        authserver.STATE["devices"] = [
            {"id": "dev_perm", "type": "browser", "role": "guest", "name": "P",
             "apps": [GRAB], "token_sha256": TOKEN_A, "revoked": False,
             "created_at": "2020-01-01T00:00:00Z"},
            {"id": "dev_tun", "type": "tunnel", "name": "T", "apps": None,
             "token_sha256": TOKEN_B, "revoked": False},
        ]
        authserver.TOKEN_CACHE = {TOKEN_A: ("dev_perm", "browser"),
                                  TOKEN_B: ("dev_tun", "tunnel")}
        authserver.sweep_once(far)
        self.assertEqual([d["id"] for d in authserver.STATE["devices"]],
                         ["dev_perm", "dev_tun"])
        self.assertEqual(set(authserver.TOKEN_CACHE), {TOKEN_A, TOKEN_B})
        authserver.sync_haproxy_maps(now=far)
        self.assertEqual(self.map_text(authserver.GRANTS_MAP),
                         f"{TOKEN_A}:{GRAB} dev_perm\n")

    def test_expired_device_leaves_maps_cache_and_me_before_any_sweep(self):
        token, invite_id = self.standing(minutes=2)
        code, data, cookie, max_age = self.accept(token)
        self.assertEqual(code, 200)
        self.assertFalse(data["merged"])
        # The cookie lasts as long as the device, not the 90-day default.
        self.assertTrue(115 <= max_age <= 120, max_age)
        self.assertAlmostEqual(data["expires_at"], self.clock.time() + 120, delta=3)
        dev = self.device(cookie)
        self.assertEqual((dev["apps"], dev["role"], dev["invite_id"]),
                         ([TREND], "guest", invite_id))
        self.assertIn(self.key(cookie, TREND), self.grants())
        self.assertIn(dev["id"], self.map_text(authserver.IDENTITY_MAP))
        me = {"Cookie": f"cush_auth={cookie}"}
        self.assertTrue(self.req("GET", "/auth/me", headers=me, cli=False)[1]["authenticated"])
        row = next(d for d in self.state()["devices"] if d["id"] == dev["id"])
        self.assertAlmostEqual(row["expires_at"], self.clock.time() + 120, delta=3)

        self.clock.advance(121)
        # No sweep has run: the row is still there, but nothing honours it.
        self.assertIsNotNone(self.device(cookie))
        self.assertEqual(self.grants(), set())
        for path in (authserver.GRANTS_MAP, authserver.IDENTITY_MAP,
                     authserver.DEVICES_MAP):
            self.assertEqual(self.map_text(path), "", path)
        self.assertFalse(self.req("GET", "/auth/me", headers=me, cli=False)[1]["authenticated"])
        self.assertEqual([d for d in self.state()["devices"] if d["id"] == dev["id"]], [])
        # A restart (or SIGHUP) rebuilds the token cache without it.
        authserver.load_state()
        self.assertNotIn(dev["token_sha256"], authserver.TOKEN_CACHE)

    def test_sweeper_drops_expired_rows_and_resyncs(self):
        token, invite_id = self.standing(minutes=2)
        _, _, cookie, _ = self.accept(token)
        dev = self.device(cookie)
        self.assertEqual(self.invite_row(invite_id)["devices"],
                         [{"id": dev["id"], "name": "t"}])
        self.assertIn(self.key(cookie, TREND), self.hap.live[authserver.GRANTS_MAP])
        # Not due yet: untouched, and the sweeper asks to be woken at expiry.
        delay = authserver.sweep_once()
        self.assertIsNotNone(self.device(cookie))
        self.assertEqual(delay, authserver.SWEEP_INTERVAL)
        self.clock.advance(100)
        self.assertTrue(18 <= authserver.sweep_once() <= 21)

        self.clock.advance(21)
        self.assertEqual(authserver.sweep_once(), authserver.SWEEP_INTERVAL)
        self.assertIsNone(self.device(cookie))
        self.assertNotIn(dev["token_sha256"], authserver.TOKEN_CACHE)
        # sweep_once itself pushed the maps; no later sync is needed.
        self.assertEqual(self.hap.live[authserver.GRANTS_MAP], {})
        self.assertEqual(self.map_text(authserver.GRANTS_MAP), "")
        with open(authserver.DEVICES_PATH) as f:
            disk = json.load(f)
        self.assertEqual(disk["devices"], [])
        self.assertEqual(disk["invites"][0]["device_ids"], [])
        self.assertEqual(self.invite_row(invite_id)["uses"], 1)

    def test_sweeper_does_not_rewrite_state_for_a_settled_pairing(self):
        iso = authserver.iso_from_epoch
        now = self.clock.time()
        authserver.STATE["pairings"] = [{
            "code": "ABCD-2345", "status": "approved", "issued_token": None,
            "created_at": iso(now - 3600), "expires_at": iso(now - 3000)}]
        saves = []
        real = authserver.save_state_locked
        authserver.save_state_locked = lambda: saves.append(1)
        self.addCleanup(setattr, authserver, "save_state_locked", real)
        authserver.sweep_once()
        authserver.sweep_once()
        self.assertEqual(saves, [])
        # A leftover token is still cleared, once.
        authserver.STATE["pairings"][0]["issued_token"] = "legacy"
        authserver.sweep_once()
        authserver.sweep_once()
        self.assertEqual(saves, [1])
        self.assertIsNone(authserver.STATE["pairings"][0]["issued_token"])


class StandingInviteTest(PassCase):
    def test_cap_fills_says_so_and_refills(self):
        token, invite_id = self.standing(minutes=2, cap=2)
        _, _, a, _ = self.accept(token)
        self.clock.advance(30)
        code, _, b, _ = self.accept(token)
        self.assertEqual(code, 200)
        self.assertEqual(self.invite_row(invite_id)["status"], "full")
        self.assertEqual(self.invite_row(invite_id)["live"], 2)

        code, data, cookie, _ = self.accept(token)
        self.assertEqual(code, 503)
        self.assertTrue(data["full"])
        self.assertIn("in use", data["error"])
        self.assertNotIn("used", data["error"].replace("in use", ""))
        self.assertIsNone(cookie)
        self.assertEqual(len(authserver.STATE["devices"]), 2)
        # The landing page says the same, not "invite already used".
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        self.addCleanup(conn.close)
        conn.request("GET", f"/i/{token}")
        resp = conn.getresponse()
        page = resp.read().decode("utf-8")
        self.assertEqual(resp.status, 200)
        self.assertIn('"status": "full"', page)
        self.assertIn("All passes are in use", page)
        # Someone who already holds one of the passes is waved through.
        code, data, cookie, _ = self.accept(token, a)
        self.assertEqual((code, data.get("noop"), cookie), (200, True, None))

        # A's pass runs out (B's has 30s left): one slot, then full again.
        self.clock.advance(91)
        self.assertEqual(self.invite_row(invite_id)["live"], 1)
        code, _, c, _ = self.accept(token)
        self.assertEqual(code, 200)
        self.assertEqual(self.accept(token)[0], 503)
        keys = self.grants()
        self.assertNotIn(self.key(a, TREND), keys)
        self.assertIn(self.key(b, TREND), keys)
        self.assertIn(self.key(c, TREND), keys)
        self.assertEqual(self.invite_row(invite_id)["uses"], 3)

    def test_expired_cookie_gets_a_fresh_pass(self):
        token, _ = self.standing(minutes=1, cap=1)
        _, _, a, _ = self.accept(token)
        self.clock.advance(61)
        # Same browser comes back still sending the dead cookie.
        code, data, b, max_age = self.accept(token, a)
        self.assertEqual(code, 200)
        self.assertFalse(data["merged"])
        self.assertNotEqual(a, b)
        self.assertTrue(55 <= max_age <= 60)

    def test_permanent_invite_cookie_keeps_the_long_max_age(self):
        token, _ = self.invite(apps=[GRAB])
        code, data, cookie, max_age = self.accept(token)
        self.assertEqual((code, max_age), (200, authserver.GATE_TTL))
        self.assertNotIn("expires_at", self.device(cookie))
        self.assertNotIn("expires_at", data)


class PassOnEnrolledDeviceTest(PassCase):
    def enrolled(self):
        token, _ = self.invite(apps=[GRAB])
        return self.accept(token)[2]

    def test_pass_adds_apps_for_a_while_and_never_touches_permanent_scope(self):
        cookie = self.enrolled()
        token, invite_id = self.standing(minutes=2, cap=5)
        code, data, new_cookie, _ = self.accept(token, cookie)
        self.assertEqual((code, data["merged"], new_cookie), (200, True, None))
        dev = self.device(cookie)
        self.assertEqual(dev["apps"], [GRAB])
        self.assertNotIn("expires_at", dev)
        self.assertEqual((dev["pass"]["invite_id"], dev["pass"]["apps"]),
                         (invite_id, [TREND]))
        self.assertEqual(len(authserver.STATE["devices"]), 1)
        self.assertEqual(self.grants(),
                         {self.key(cookie, GRAB), self.key(cookie, TREND)})
        self.assertEqual(authserver.device_apps(dev, self.clock.time()), [GRAB, TREND])
        self.assertEqual(authserver.device_perm_apps(dev), [GRAB])
        # The panel is given the permanent scope and the pass separately...
        row = self.state()["devices"][0]
        self.assertEqual(row["apps"], [GRAB])
        self.assertEqual(row["pass"]["apps"], [TREND])
        self.assertIsNone(row["expires_at"])
        self.assertEqual(self.invite_row(invite_id)["live"], 1)
        # ...so saving the scope editor as shown does not make the pass permanent.
        self.req("POST", "/auth/admin/device-apps",
                 {"device_id": dev["id"], "apps": row["apps"]})
        self.assertEqual(dev["apps"], [GRAB])

        # Already covered: accepting again spends nothing.
        code, data, _, _ = self.accept(token, cookie)
        self.assertEqual((code, data.get("noop")), (200, True))
        self.assertEqual(self.invite_row(invite_id)["uses"], 1)

        self.clock.advance(121)
        self.assertEqual(self.grants(), {self.key(cookie, GRAB)})
        self.assertEqual(self.state()["devices"][0]["pass"], None)
        authserver.sweep_once()
        dev = self.device(cookie)
        self.assertNotIn("pass", dev)
        self.assertEqual(dev["apps"], [GRAB])
        self.assertEqual(self.hap.live[authserver.GRANTS_MAP],
                         {self.key(cookie, GRAB): dev["id"]})
        self.assertIn(dev["token_sha256"], authserver.TOKEN_CACHE)
        # And the pass can be taken again afterwards.
        self.assertEqual(self.accept(token, cookie)[1].get("noop"), None)
        self.assertEqual(self.device(cookie)["pass"]["apps"], [TREND])

    def test_permanent_invite_still_merges_but_not_the_pass_apps(self):
        cookie = self.enrolled()
        self.accept(self.standing(minutes=2)[0], cookie)
        token, _ = self.invite(apps=["up.cush.rocks"])
        code, data, new_cookie, _ = self.accept(token, cookie)
        self.assertEqual((code, data["merged"], new_cookie), (200, True, None))
        dev = self.device(cookie)
        self.assertEqual(dev["apps"], [GRAB, "up.cush.rocks"])
        self.assertEqual(dev["pass"]["apps"], [TREND])

    def test_all_apps_device_takes_no_pass_even_when_full(self):
        authserver.STATE["devices"].append(
            {"id": "dev_admin", "type": "browser", "role": "admin", "name": "Me",
             "apps": ["*"], "token_sha256": authserver.sha256_hex("admintok"),
             "revoked": False})
        authserver.TOKEN_CACHE[authserver.sha256_hex("admintok")] = ("dev_admin", "browser")
        token, invite_id = self.standing(minutes=2, cap=1)
        self.accept(token)
        code, data, cookie, _ = self.accept(token, "admintok")
        self.assertEqual((code, data.get("noop"), cookie), (200, True, None))
        admin = self.device("admintok")
        self.assertEqual(admin["apps"], ["*"])
        self.assertNotIn("pass", admin)
        self.assertEqual(self.invite_row(invite_id)["uses"], 1)

    def test_a_pass_cannot_carry_all_apps(self):
        d = {"apps": [GRAB], "pass": {"apps": ["*", TREND], "invite_id": "x",
             "expires_at": authserver.iso_from_epoch(time.time() + 60)}}
        self.assertEqual(authserver.device_apps(d), [GRAB, TREND])

    def test_permanent_invite_promotes_a_pass_device(self):
        token, standing_id = self.standing(minutes=2)
        _, _, cookie, _ = self.accept(token)
        expires = self.device(cookie)["expires_at"]
        ptoken, perm_id = self.invite(apps=[GRAB])
        code, data, new_cookie, max_age = self.accept(ptoken, cookie)
        # Same device and token, now permanent, cookie reissued at full length.
        self.assertEqual((code, new_cookie, max_age),
                         (200, cookie, authserver.GATE_TTL))
        dev = self.device(cookie)
        self.assertNotIn("expires_at", dev)
        self.assertEqual((dev["apps"], dev["invite_id"]), ([GRAB], perm_id))
        self.assertEqual(dev["pass"], {"invite_id": standing_id, "apps": [TREND],
                                       "expires_at": expires})
        self.clock.advance(121)
        authserver.sweep_once()
        self.assertEqual(self.device(cookie)["apps"], [GRAB])
        self.assertEqual(self.grants(), {self.key(cookie, GRAB)})


class InviteRevokeTest(PassCase):
    def revoke(self, invite_id, **body):
        body["id"] = invite_id
        return self.req("POST", "/auth/admin/invite-revoke", body)

    def test_without_devices_they_keep_working(self):
        token, invite_id = self.standing(minutes=10)
        _, _, cookie, _ = self.accept(token)
        code, data, _ = self.revoke(invite_id)
        self.assertEqual((code, data["devices_revoked"]), (200, 0))
        self.assertEqual(self.invite_row(invite_id)["status"], "revoked")
        self.assertEqual(self.accept(token)[0], 410)
        self.assertFalse(self.device(cookie)["revoked"])
        self.assertIn(self.key(cookie, TREND), self.grants())
        # Asked again later with the flag: the devices go then.
        self.assertEqual(self.revoke(invite_id, revoke_devices=True)[1]["devices_revoked"], 1)
        self.assertEqual(self.grants(), set())

    def test_with_devices_cuts_devices_and_passes_only_of_that_invite(self):
        other_token, _ = self.invite(apps=[GRAB])
        _, _, enrolled, _ = self.accept(other_token)
        token, invite_id = self.standing(minutes=10, cap=5)
        _, _, minted, _ = self.accept(token)
        self.accept(token, enrolled)
        self.assertEqual(self.invite_row(invite_id)["live"], 2)

        self.assertEqual(self.revoke(invite_id, revoke_devices="yes")[0], 400)
        code, data, _ = self.revoke(invite_id, revoke_devices=True)
        self.assertEqual((code, data["devices_revoked"]), (200, 2))
        self.assertTrue(self.device(minted)["revoked"])
        self.assertNotIn(authserver.sha256_hex(minted), authserver.TOKEN_CACHE)
        # The enrolled browser loses the pass and nothing else.
        dev = self.device(enrolled)
        self.assertFalse(dev["revoked"])
        self.assertNotIn("pass", dev)
        self.assertEqual(dev["apps"], [GRAB])
        # Pushed by the handler itself.
        self.assertEqual(set(self.hap.live[authserver.GRANTS_MAP]),
                         {self.key(enrolled, GRAB)})
        self.assertEqual(self.revoke("inv_deadbeef", revoke_devices=True)[0], 404)


if __name__ == "__main__":
    unittest.main()


# --- hardening round: setup token, limiter, CSP, approve scope, NewProxy, ------
# --- revoke status, per-host handoff, CLI through the API ------------------------

AUTH = "auth.cush.rocks"
APP = "grab.cush.rocks"


class NoAdminCase(ServerCase):
    def setUp(self):
        super().setUp()
        saved = authserver.SETUP_TOKEN
        self.addCleanup(setattr, authserver, "SETUP_TOKEN", saved)
        authserver.SETUP_TOKEN = ""
        authserver.STATE["admin"] = None
        authserver.ensure_setup_token()
        self.token_path = os.path.join(self.tmp.name, authserver.SETUP_TOKEN_FILE)


class SetupTokenTest(NoAdminCase):
    def test_setup_needs_the_token_and_a_long_password(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.token_path).st_mode), 0o600)
        with open(self.token_path) as f:
            tok = f.read().strip()
        self.assertEqual(tok, authserver.SETUP_TOKEN)
        self.assertTrue(any(tok in line for line in self.logs))
        long_pw = "correct horse battery"
        for body in ({"password": long_pw}, {"password": long_pw, "setup_token": "nope"}):
            code, _, _ = self.req("POST", "/auth/admin/setup", body, cli=False)
            self.assertEqual(code, 403)
        self.assertIsNone(authserver.STATE["admin"])
        code, data, _ = self.req("POST", "/auth/admin/setup",
                                 {"password": "short-pw", "setup_token": tok}, cli=False)
        self.assertEqual(code, 400)
        self.assertIn("12", data["error"])
        code, _, hdrs = self.req("POST", "/auth/admin/setup",
                                 {"password": long_pw, "setup_token": tok}, cli=False)
        self.assertEqual(code, 200)
        self.assertTrue(any(k.lower() == "set-cookie" for k, _ in hdrs))
        self.assertFalse(os.path.exists(self.token_path))
        self.assertEqual(authserver.SETUP_TOKEN, "")
        # Second setup: refused, the token is gone anyway.
        self.assertEqual(self.req("POST", "/auth/admin/setup",
                                  {"password": long_pw, "setup_token": tok}, cli=False)[0], 409)

    def test_cli_can_set_the_first_password(self):
        code, _, _ = self.req("POST", "/auth/admin/set-password", {"new": "x" * 11})
        self.assertEqual(code, 400)
        code, _, hdrs = self.req("POST", "/auth/admin/set-password", {"new": "x" * 12})
        self.assertEqual(code, 200)
        self.assertIsNotNone(authserver.STATE["admin"]["password_scrypt"])
        self.assertFalse(any(k.lower() == "set-cookie" for k, _ in hdrs))
        self.assertFalse(os.path.exists(self.token_path))


class PasswordCase(ServerCase):
    PW = "a-long-admin-password"

    def setUp(self):
        super().setUp()
        authserver.STATE["admin"] = None
        self.assertEqual(self.req("POST", "/auth/admin/set-password", {"new": self.PW})[0], 200)

    def login(self, pw, ip=None):
        hdrs = {"X-Forwarded-For": ip} if ip else {}
        return self.req("POST", "/auth/admin/login", {"password": pw}, hdrs, cli=False)[0]


class LimiterTest(PasswordCase):
    def test_login_and_enroll_share_one_per_ip_budget(self):
        for _ in range(3):
            self.assertEqual(self.login("wrong", "198.51.100.7"), 401)
        for _ in range(2):
            code = self.req("POST", "/auth/enroll", {"password": "wrong"},
                            {"X-Forwarded-For": "198.51.100.7"}, cli=False)[0]
            self.assertEqual(code, 401)
        self.assertEqual(self.login(self.PW, "198.51.100.7"), 429)
        code = self.req("POST", "/auth/enroll", {"password": self.PW},
                        {"X-Forwarded-For": "198.51.100.7"}, cli=False)[0]
        self.assertEqual(code, 429)
        # Another IP is unaffected.
        self.assertEqual(self.login(self.PW, "198.51.100.8"), 200)

    def test_global_failures_slow_down_but_never_lock_out(self):
        slept = []
        saved = authserver._sleep
        authserver._sleep = slept.append
        self.addCleanup(lambda: setattr(authserver, "_sleep", saved))
        authserver.GLOBAL_FAILS.extend([time.time()] * (authserver.GLOBAL_FAIL_MAX * 4))
        # A spray from everywhere: the owner still gets in, just slower.
        self.assertEqual(self.login(self.PW, "203.0.113.50"), 200)
        self.assertEqual(slept, [authserver.GLOBAL_DELAY_MAX])
        authserver.GLOBAL_FAILS.clear()
        slept.clear()
        authserver.GLOBAL_FAILS.extend([time.time()] * authserver.GLOBAL_FAIL_MAX)
        self.assertEqual(self.login(self.PW, "203.0.113.51"), 200)
        self.assertEqual(len(slept), 1)
        self.assertLess(slept[0], authserver.GLOBAL_DELAY_MAX)
        authserver.GLOBAL_FAILS.clear()
        slept.clear()
        self.assertEqual(self.login(self.PW, "203.0.113.52"), 200)
        self.assertEqual(slept, [])

    def test_per_ip_key_is_rightmost_non_loopback_hop(self):
        f = authserver.client_ip_from
        # nginx $proxy_add_x_forwarded_for behind HAProxy: "client, 127.0.0.1"
        self.assertEqual(f("127.0.0.1", ["198.51.100.7, 127.0.0.1"]), "198.51.100.7")
        # A client-forged left-most entry does not pick the key.
        self.assertEqual(f("127.0.0.1", ["1.2.3.4, 198.51.100.7, 127.0.0.1"]), "198.51.100.7")
        self.assertEqual(f("127.0.0.1", ["1.2.3.4", "198.51.100.7"]), "198.51.100.7")
        self.assertEqual(f("::1", ["2001:db8::1, ::1"]), "2001:db8::1")
        # XFF from a non-loopback peer is ignored entirely.
        self.assertEqual(f("203.0.113.9", ["198.51.100.7"]), "203.0.113.9")
        # Only loopback hops: the peer itself.
        self.assertEqual(f("127.0.0.1", ["127.0.0.1"]), "127.0.0.1")
        self.assertEqual(f("127.0.0.1", []), "127.0.0.1")

    def test_spoofed_leftmost_xff_cannot_dodge_per_ip_limit(self):
        for i in range(5):
            self.assertEqual(self.login("wrong", f"10.9.9.{i}, 198.51.100.77"), 401)
        self.assertEqual(self.login(self.PW, "10.9.9.200, 198.51.100.77"), 429)

    def test_scrypt_runs_outside_state_lock(self):
        seen = []
        real = authserver.scrypt_hash

        def spy(pw, salt):
            seen.append(authserver.STATE_LOCK.locked())
            return real(pw, salt)
        authserver.scrypt_hash = spy
        self.addCleanup(setattr, authserver, "scrypt_hash", real)
        self.assertEqual(self.login(self.PW, "192.0.2.1"), 200)
        self.assertEqual(seen, [False])

    def test_browser_set_password_needs_current_and_12_chars(self):
        code, _, hdrs = self.req("POST", "/auth/admin/login", {"password": self.PW}, cli=False)
        self.assertEqual(code, 200)
        sess = next(v for k, v in hdrs if k.lower() == "set-cookie").split(";")[0]
        h = {"Cookie": sess}
        self.assertEqual(self.req("POST", "/auth/admin/set-password",
                                  {"new": "y" * 20}, h, cli=False)[0], 401)
        self.assertEqual(self.req("POST", "/auth/admin/set-password",
                                  {"current": self.PW, "new": "short"}, h, cli=False)[0], 400)
        self.assertEqual(self.req("POST", "/auth/admin/set-password",
                                  {"current": self.PW, "new": "y" * 20}, h, cli=False)[0], 200)
        self.assertEqual(self.login("y" * 20, "192.0.2.3"), 200)


class VerifyPasswordTest(PasswordCase):
    """POST /auth/admin/verify-password: Pocket's step-up check. CLI token
    only, the login page's limiter, no cookie."""

    def verify(self, pw, ip="198.51.100.20", **kw):
        return self.req("POST", "/auth/admin/verify-password", {"password": pw, "ip": ip}, **kw)

    def test_cli_only(self):
        code, _, hdrs = self.req("POST", "/auth/admin/login", {"password": self.PW}, cli=False)
        sess = next(v for k, v in hdrs if k.lower() == "set-cookie").split(";")[0]
        self.assertEqual(self.verify(self.PW, headers={"Cookie": sess}, cli=False)[0], 403)
        self.assertEqual(self.verify(self.PW, cli=False)[0], 403)
        # The CLI token on something that looks proxied is not the CLI.
        self.assertEqual(self.verify(self.PW, headers={"X-Forwarded-For": "1.2.3.4"})[0], 403)

    def test_ok_and_wrong_no_cookie(self):
        code, data, hdrs = self.verify(self.PW)
        self.assertEqual((code, data), (200, {"ok": True}))
        self.assertFalse(any(k.lower() == "set-cookie" for k, _ in hdrs))
        code, data, hdrs = self.verify("wrong")
        self.assertEqual((code, data["error"]), (401, "invalid password"))
        self.assertFalse(any(k.lower() == "set-cookie" for k, _ in hdrs))
        self.assertTrue(any("step-up password failed ip=198.51.100.20" in m for m in self.logs))
        self.assertFalse(any(self.PW in m for m in self.logs))
        self.assertEqual(len(authserver.GLOBAL_FAILS), 1)

    def test_shares_the_login_limiter(self):
        for _ in range(3):
            self.assertEqual(self.verify("wrong")[0], 401)
        for _ in range(2):
            self.assertEqual(self.login("wrong", "198.51.100.20"), 401)
        self.assertEqual(self.verify(self.PW)[0], 429)
        self.assertEqual(self.login(self.PW, "198.51.100.20"), 429)
        self.assertEqual(self.verify(self.PW, "198.51.100.21")[0], 200)

    def test_bad_ip_is_one_shared_key(self):
        for ip in ("not-an-ip", None, 5, "1.2.3.4, 5.6.7.8", "x", "y"):
            self.verify("wrong", ip)
        self.assertEqual(self.verify(self.PW, "garbage")[0], 429)
        self.assertIn("pocket", authserver.AUTH_ATTEMPTS)


class DeviceRenameTest(PassCase):
    def mint(self):
        with authserver.STATE_LOCK:
            handler = authserver.AuthHandler.__new__(authserver.AuthHandler)
            dev, _ = handler._mint_browser_device_locked("Tablet", [APP], "admin")
            authserver.save_state_locked()
        return dev

    def test_rename_syncs_the_identity_map(self):
        dev = self.mint()
        code, data, _ = self.req("POST", "/auth/admin/device-rename",
                                 {"device_id": dev["id"], "name": "  Sam's iPad  "})
        self.assertEqual(code, 200, data)
        self.assertEqual(data["name"], "Sam's iPad")
        self.assertEqual(dev["name"], "Sam's iPad")
        with open(authserver.DEVICES_PATH) as f:
            on_disk = next(d for d in json.load(f)["devices"] if d["id"] == dev["id"])
        self.assertEqual(on_disk["name"], "Sam's iPad")
        self.assertTrue(any("Sam" in v for v in self.hap.live[authserver.IDENTITY_MAP].values()))

    def test_validation(self):
        dev = self.mint()
        for body, code in (({"device_id": dev["id"], "name": ""}, 400),
                           ({"device_id": dev["id"], "name": "   "}, 400),
                           ({"device_id": dev["id"], "name": "x" * 65}, 400),
                           ({"device_id": dev["id"], "name": "a\nb"}, 400),
                           ({"device_id": dev["id"], "name": 7}, 400),
                           ({"name": "ok"}, 400),
                           ({"device_id": "nope", "name": "ok"}, 404)):
            self.assertEqual(self.req("POST", "/auth/admin/device-rename", body)[0], code, body)
        self.assertEqual(dev["name"], "Tablet")
        # Session-gated like every admin route.
        self.assertEqual(self.req("POST", "/auth/admin/device-rename",
                                  {"device_id": dev["id"], "name": "x"}, cli=False)[0], 401)


class HeadersAndBodyTest(ServerCase):
    def test_html_pages_send_csp_with_matching_nonces(self):
        for path in ("/auth/", "/login", "/i/" + "x" * 43):
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
            conn.request("GET", path)
            resp = conn.getresponse()
            body = resp.read().decode()
            conn.close()
            h = {k.lower(): v for k, v in resp.getheaders()}
            csp = h["content-security-policy"]
            nonce = re.search(r"'nonce-([0-9a-f]+)'", csp).group(1)
            self.assertIn("frame-ancestors 'none'", csp)
            self.assertIn("default-src 'none'", csp)
            self.assertEqual(h["x-frame-options"], "DENY")
            self.assertEqual(h["x-content-type-options"], "nosniff")
            self.assertEqual(h["cache-control"], "no-store")
            self.assertNotIn("__NONCE__", body)
            tags = re.findall(r"<(style|script)\b([^>]*)>", body)
            self.assertTrue(tags, path)
            for _, attrs in tags:
                self.assertIn(f'nonce="{nonce}"', attrs, path)
            self.assertNotIn(' style="', body, path)
        self.assertEqual(
            dict((k.lower(), v) for k, v in resp.getheaders())["referrer-policy"],
            "no-referrer")

    def test_non_object_json_bodies_are_400(self):
        for raw in ("[]", "1", '"x"', "null"):
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
            conn.request("POST", "/auth/admin/revoke", body=raw, headers={
                "Content-Type": "application/json", authserver.CLI_TOKEN_HEADER: self.cli})
            resp = conn.getresponse()
            resp.read()
            conn.close()
            self.assertEqual(resp.status, 400, raw)

    def test_corrupt_devices_json_is_reported_clearly(self):
        for text in ("{not json", "[]", '{"devices": [1]}', '{"devices": {}}'):
            with open(authserver.DEVICES_PATH, "w") as f:
                f.write(text)
            with self.assertRaises(authserver.StateError) as cm:
                authserver.load_state(fatal=False)
            self.assertIn(authserver.DEVICES_PATH, str(cm.exception))
            with self.assertRaises(SystemExit):
                authserver.load_state(fatal=True)
            self.assertTrue(any("FATAL" in line for line in self.logs))


class ApproveRevokeTest(ServerCase):
    def pair(self, kind):
        path = "/auth/web-pair/start" if kind == "web" else "/auth/pair/start"
        code, data, _ = self.req("POST", path, {"device_name": "dev"}, cli=False)
        self.assertEqual(code, 200)
        return data

    def test_web_approve_needs_explicit_scope_and_fills_pending_tokens(self):
        p = self.pair("web")
        code, data, _ = self.req("POST", "/auth/admin/approve", {"code": p["code"]})
        self.assertEqual(code, 400)
        self.assertIn("explicit", data["error"])
        code, data, _ = self.req("POST", "/auth/admin/approve",
                                 {"code": p["code"], "apps": [APP]})
        self.assertEqual(code, 200)
        self.assertEqual((data["type"], data["haproxy"]), ("browser", "ok"))
        dev = authserver.STATE["devices"][-1]
        self.assertEqual((dev["type"], dev["apps"], dev["role"]), ("browser", [APP], "guest"))
        self.assertIn(p["poll_token"], authserver.PENDING_TOKENS)
        with open(authserver.DEVICES_PATH) as f:
            self.assertNotIn(authserver.PENDING_TOKENS[p["poll_token"]][0], f.read())

    def test_tunnel_approve_mints_a_tunnel_device_without_apps(self):
        p = self.pair("tunnel")
        code, data, _ = self.req("POST", "/auth/admin/approve", {"code": p["code"]})
        self.assertEqual((code, data["type"]), (200, "tunnel"))
        self.assertIsNone(authserver.STATE["devices"][-1]["apps"])

    def test_haproxy_failure_is_reported(self):
        p = self.pair("web")
        self.hap.fail = lambda cmd: None    # socket unreachable
        code, data, _ = self.req("POST", "/auth/admin/approve",
                                 {"code": p["code"], "apps": ["*"]})
        self.assertEqual(code, 200)
        self.assertTrue(data["haproxy"].startswith("failed"), data)
        self.assertIn("socket", data["haproxy"])
        code, data, _ = self.req("POST", "/auth/admin/revoke",
                                 {"device_id": data["device_id"]})
        self.assertEqual(code, 200)
        self.assertTrue(data["haproxy"].startswith("failed"))
        self.hap.fail = lambda cmd: "Permission denied\n" if cmd.startswith("prepare") else False
        code, data, _ = self.req("POST", "/auth/admin/apps",
                                 {"host": "x1.cush.rocks", "action": "protect"})
        self.assertIn("push of", data["haproxy"])
        self.assertIn("hapNote", authserver.ADMIN_HTML)


def verify(case, op, content):
    code, data, _ = case.req("POST", f"/verify?op={op}", {"op": op, "content": content},
                             cli=False)
    case.assertEqual(code, 200)
    return data


class FrpPluginTest(ServerCase):
    def setUp(self):
        super().setUp()
        self.tok = "tunnel-token-123"
        sha = authserver.sha256_hex(self.tok)
        authserver.STATE["devices"].append({
            "id": "dev_t1", "type": "tunnel", "name": "laptop", "token_sha256": sha,
            "revoked": False, "apps": None})
        authserver.TOKEN_CACHE[sha] = ("dev_t1", "tunnel")

    def proxy(self, **kw):
        c = {"user": {"user": "", "metas": {"device_token": self.tok}, "run_id": "r"},
             "proxy_name": "p", "proxy_type": "http", "subdomain": "mything"}
        c.update(kw)
        return verify(self, "NewProxy", c)

    def test_new_proxy_rules(self):
        self.assertFalse(self.proxy()["reject"])
        self.assertFalse(self.proxy(proxy_type="https")["reject"])
        for kw in ({"proxy_type": "tcp", "remote_port": 22, "subdomain": ""},
                   {"proxy_type": "udp", "remote_port": 53, "subdomain": ""},
                   {"proxy_type": "stcp"},
                   {"custom_domains": ["grab.cush.rocks"]},
                   {"subdomain": "entry-apikey"}, {"subdomain": "auth"}):
            self.assertTrue(self.proxy(**kw)["reject"], kw)
        authserver.STATE["devices"][-1]["tunnel_admin"] = True
        self.assertFalse(self.proxy(proxy_type="tcp", remote_port=22)["reject"])
        self.assertFalse(self.proxy(subdomain="entry-x")["reject"])

    def test_new_proxy_routing_knobs_need_admin(self):
        for kw in ({"locations": ["/admin"]}, {"http_user": "u", "http_pwd": "p"},
                   {"route_by_http_user": "owner"}, {"group": "g", "group_key": "k"},
                   {"host_header_rewrite": "127.0.0.1"},
                   {"headers": {"Host": "grab.cush.rocks"}},
                   {"subdomain": ""}):
            self.assertTrue(self.proxy(**kw)["reject"], kw)
        self.assertFalse(self.proxy(locations=[], http_user="", headers={"X-A": "1"})["reject"])
        authserver.STATE["devices"][-1]["tunnel_admin"] = True
        self.assertFalse(self.proxy(locations=["/x"], host_header_rewrite="h")["reject"])

    def test_owner_tool_names_reserved(self):
        for sub in ("panel", "auth", "music", "musicbox", "media-wedding", "photos2",
                    "drop-x", "entry-k"):
            self.assertTrue(self.proxy(subdomain=sub)["reject"], sub)
        # Names the owner's localhost tunnels use now or have used.
        with open(os.path.join(authserver.DATA_DIR, "history.jsonl"), "w") as f:
            f.write(json.dumps({"event": "start", "name": "promo-v2", "type": "serve"}) + "\n")
            f.write("not json\n")
        open(os.path.join(authserver.OWNER_STATE_DIR, "livenow.json"), "w").close()
        self.assertTrue(self.proxy(subdomain="promo-v2")["reject"])
        self.assertTrue(self.proxy(subdomain="LiveNow")["reject"])
        self.assertFalse(self.proxy(subdomain="mything")["reject"])
        authserver.STATE["devices"][-1]["tunnel_admin"] = True
        self.assertFalse(self.proxy(subdomain="promo-v2")["reject"])

    def test_reload_reads_file_under_state_lock(self):
        # A save that lands between the reload's read and its swap of STATE
        # would be lost; holding STATE_LOCK across both makes that impossible.
        with authserver.STATE_LOCK:
            authserver.save_state_locked()
        seen = []
        real = authserver.validate_state

        def spy(data):
            seen.append(authserver.STATE_LOCK.locked())
            return real(data)
        authserver.validate_state = spy
        self.addCleanup(lambda: setattr(authserver, "validate_state", real))
        authserver.load_state(fatal=False)
        self.assertEqual(seen, [True])
        self.assertFalse(authserver.STATE_LOCK.locked())

    def test_localhost_session_is_unrestricted_with_bypass(self):
        self.bypass(True)
        c = {"user": {"metas": {}}, "proxy_type": "tcp", "remote_port": 2222}
        self.assertFalse(verify(self, "NewProxy", c)["reject"])
        self.assertFalse(verify(self, "Login", {"client_address": "127.0.0.1:4000",
                                                "metas": {}})["reject"])
        self.assertFalse(verify(self, "Login", {"client_address": "[::1]:4000",
                                                "metas": {"device_token": "junk"}})["reject"])
        self.assertTrue(any("localhost bypass" in m for m in self.logs))

    def bypass(self, on):
        old = authserver.LOCALHOST_BYPASS
        authserver.LOCALHOST_BYPASS = on
        self.addCleanup(setattr, authserver, "LOCALHOST_BYPASS", old)

    def test_bypass_off_rejects_tokenless_localhost(self):
        self.bypass(False)
        r = verify(self, "Login", {"client_address": "127.0.0.1:4000", "metas": {}})
        self.assertTrue(r["reject"])
        self.assertIn("device_token", r["reject_reason"])
        self.assertTrue(verify(self, "Login", {"client_address": "[::1]:4000",
                                               "metas": {"device_token": "junk"}})["reject"])
        for op in ("NewProxy", "NewWorkConn", "Ping"):
            c = {"user": {"metas": {}}, "proxy_type": "tcp", "remote_port": 2222}
            self.assertTrue(verify(self, op, c)["reject"], op)
        # a paired device still works from loopback (a relay forwards it there)
        self.assertFalse(verify(self, "Login", {"client_address": "127.0.0.1:4000",
                                                "metas": {"device_token": self.tok}})["reject"])

    def test_home_token_minted_and_accepted(self):
        self.bypass(False)
        dev = authserver.ensure_home_device()
        path = os.path.join(authserver.DATA_DIR, authserver.HOME_TOKEN_FILE)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        with open(path) as f:
            tok = f.read().strip()
        self.assertGreaterEqual(len(tok), 40)
        self.assertEqual(dev["name"], "home")
        self.assertIs(dev["tunnel_admin"], True)
        self.assertIsNone(dev["apps"])
        with open(authserver.DEVICES_PATH) as f:
            self.assertIn(dev["id"], f.read())
        login = {"client_address": "127.0.0.1:4000", "metas": {"device_token": tok}}
        self.assertFalse(verify(self, "Login", login)["reject"])
        user = {"user": {"metas": {"device_token": tok}, "run_id": "r"}}
        self.assertFalse(verify(self, "NewProxy", dict(user, proxy_type="tcp",
                                                       remote_port=2222))["reject"])
        self.assertFalse(verify(self, "NewProxy", dict(user, proxy_type="http",
                                                       subdomain="music"))["reject"])
        # idempotent: same file, same device
        again = authserver.ensure_home_device()
        self.assertEqual(again["id"], dev["id"])
        self.assertEqual(sum(1 for d in authserver.STATE["devices"] if d.get("home")), 1)

    def test_revoked_home_token_rejected_and_not_resurrected(self):
        self.bypass(False)
        dev = authserver.ensure_home_device()
        with open(os.path.join(authserver.DATA_DIR, authserver.HOME_TOKEN_FILE)) as f:
            tok = f.read().strip()
        code, _, _ = self.req("POST", "/auth/admin/revoke", {"device_id": dev["id"]})
        self.assertEqual(code, 200)
        login = {"client_address": "127.0.0.1:4000", "metas": {"device_token": tok}}
        self.assertTrue(verify(self, "Login", login)["reject"])
        self.assertTrue(verify(self, "Ping", {"user": {"metas": {"device_token": tok}}})["reject"])
        self.assertIsNone(authserver.ensure_home_device())
        self.assertTrue(verify(self, "Login", login)["reject"])
        # rotate: delete the file, start again -> a new live device
        os.unlink(os.path.join(authserver.DATA_DIR, authserver.HOME_TOKEN_FILE))
        new = authserver.ensure_home_device()
        self.assertNotEqual(new["id"], dev["id"])

    def test_bypass_setting_resolution(self):
        cfg_on = type("C", (), {"localhost_bypass": True})()
        cfg_off = type("C", (), {"localhost_bypass": False})()
        f = authserver.localhost_bypass_enabled
        self.assertFalse(f(cfg_off, env={}))
        self.assertTrue(f(cfg_on, env={}))
        self.assertTrue(f(cfg_off, env={"PORCH_LOCALHOST_BYPASS": "1"}))
        self.assertFalse(f(cfg_on, env={"PORCH_LOCALHOST_BYPASS": "0"}))
        self.assertTrue(f(cfg_on, env={"PORCH_LOCALHOST_BYPASS": "maybe"}))
        # the built-in defaults (no config file) are a fresh install: off
        self.assertFalse(porch_config.load(env={"PORCH_CONFIG": "none"}).localhost_bypass)

    def test_revoke_cuts_proxies_work_conns_and_heartbeats(self):
        user = {"user": {"metas": {"device_token": self.tok}, "run_id": "r"}}
        for op in ("NewWorkConn", "Ping"):
            self.assertFalse(verify(self, op, user)["reject"])
        code, data, _ = self.req("POST", "/auth/admin/revoke", {"device_id": "dev_t1"})
        self.assertEqual(code, 200)
        self.assertIn("tunnel", data)
        for op in ("NewWorkConn", "Ping"):
            self.assertTrue(verify(self, op, user)["reject"], op)
        self.assertTrue(self.proxy()["reject"])
        self.assertTrue(verify(self, "Login", {"client_address": "198.51.100.1:5000",
                                               "metas": {"device_token": self.tok}})["reject"])

    def test_role_endpoint_sets_tunnel_admin_not_role(self):
        code, data, _ = self.req("POST", "/auth/admin/device-role",
                                 {"device_id": "dev_t1", "role": "admin"})
        self.assertEqual(code, 200)
        d = authserver.STATE["devices"][-1]
        self.assertIs(d["tunnel_admin"], True)
        self.assertNotIn("role", d)


class HandoffTest(PassCase):
    """GET /auth/handoff on the auth host -> /__porch/auth on the app host."""

    def setUp(self):
        super().setUp()
        handler = authserver.AuthHandler.__new__(authserver.AuthHandler)
        with authserver.STATE_LOCK:
            _, self.cookie = handler._mint_browser_device_locked("Phone", [APP], "guest")

    def get(self, path, host, cookies=None):
        hdrs = {"Host": host}
        if cookies:
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        code, _, h = self.req("GET", path, headers=hdrs, cli=False)
        return code, {k.lower(): v for k, v in h}, h

    STATE = "S" * 32

    def start(self, host=APP, rd=None, cookie=None):
        q = f"/auth/handoff?host={host}&state={self.STATE}"
        if rd is not None:
            q += "&rd=" + authserver.quote(rd, safe="")
        return self.get(q, AUTH, {"cush_auth": cookie or self.cookie})

    def code_from(self, location):
        from urllib.parse import urlparse as up, parse_qs as pq
        u = up(location)
        return u.hostname, pq(u.query)

    def redeem(self, host, code, rd=None, state=STATE):
        q = "/__porch/auth?code=" + code
        if rd is not None:
            q += "&rd=" + authserver.quote(rd, safe="")
        return self.get(q, host, {authserver.STATE_COOKIE: state} if state else None)

    def full(self, rd=None):
        code, h, _ = self.start(rd=rd)
        self.assertEqual(code, 302, h)
        host, qs = self.code_from(h["location"])
        self.assertEqual(host, APP)
        code, h2, raw = self.redeem(APP, qs["code"][0], qs.get("rd", [None])[0])
        self.assertEqual(code, 302)
        cookie = next(v for k, v in raw if k.lower() == "set-cookie")
        return h2["location"], cookie

    def test_cookie_is_host_only_and_validates_for_its_host(self):
        loc, cookie = self.full(rd=f"https://{APP}/x?y=1")
        self.assertEqual(loc, f"https://{APP}/x?y=1")
        self.assertTrue(cookie.startswith("porch_host="))
        for attr in ("Secure", "HttpOnly", "SameSite=Lax", "Path=/"):
            self.assertIn(attr, cookie)
        self.assertNotIn("Domain", cookie)
        tok = cookie.split(";")[0].split("=", 1)[1]
        devs = authserver.STATE["devices"]
        self.assertIsNotNone(authserver.find_host_token_device(devs, tok, APP))
        self.assertIsNone(authserver.find_host_token_device(devs, tok, "trendlab.cush.rocks"))
        self.assertIsNone(authserver.find_host_token_device(devs, self.cookie, APP))
        stored = self.device(self.cookie)["host_tokens"][0]
        self.assertEqual(stored["sha256"], authserver.sha256_hex(tok))
        self.assertEqual(stored["host"], APP)
        code, data, _ = self.req("GET", "/__porch/me", headers={
            "Host": APP, "Cookie": cookie.split(";")[0]}, cli=False)
        self.assertTrue(data["authenticated"])
        code, data, _ = self.req("GET", "/__porch/me", headers={
            "Host": "trendlab.cush.rocks", "Cookie": cookie.split(";")[0]}, cli=False)
        self.assertFalse(data["authenticated"])

    def test_code_is_single_use(self):
        code, h, _ = self.start()
        _, qs = self.code_from(h["location"])
        self.assertEqual(self.redeem(APP, qs["code"][0])[0], 302)
        self.assertEqual(self.redeem(APP, qs["code"][0])[0], 400)

    def test_code_is_bound_to_its_host(self):
        code, h, _ = self.start()
        _, qs = self.code_from(h["location"])
        self.assertEqual(self.redeem("evil.tunnel.cush.rocks", qs["code"][0])[0], 400)
        # The failed attempt spent it.
        self.assertEqual(self.redeem(APP, qs["code"][0])[0], 400)
        # Forwarded host disagreeing with Host never matches.
        code, h, _ = self.start()
        _, qs = self.code_from(h["location"])
        code, _, _ = self.req("GET", "/__porch/auth?code=" + qs["code"][0], headers={
            "Host": APP, "X-Forwarded-Host": "evil.cush.rocks",
            "Cookie": f"{authserver.STATE_COOKIE}={self.STATE}"}, cli=False)
        self.assertEqual(code, 400)

    def test_code_needs_the_starting_browsers_state_cookie(self):
        # Login CSRF: a code minted for one browser's flow, redeemed in a
        # browser without the matching __Host-porch_state cookie, is refused.
        for bad in (None, "T" * 32, "S" * 31):
            code, h, _ = self.start()
            _, qs = self.code_from(h["location"])
            self.assertEqual(self.redeem(APP, qs["code"][0], state=bad)[0], 400, bad)
            # ...and spent: no retry with the right cookie.
            self.assertEqual(self.redeem(APP, qs["code"][0])[0], 400)
        self.assertFalse(self.device(self.cookie).get("host_tokens"))

    def test_porch_start_sets_state_and_bounces(self):
        code, h, raw = self.get("/__porch/start?rd=%2Fdeep%3Fq%3D1", APP)
        self.assertEqual(code, 302)
        cookie = next(v for k, v in raw if k.lower() == "set-cookie")
        self.assertTrue(cookie.startswith("__Host-porch_state="))
        for attr in ("Path=/;", "Secure", "HttpOnly", "SameSite=Lax"):
            self.assertIn(attr, cookie)
        self.assertNotIn("Domain", cookie)
        state = cookie.split(";")[0].split("=", 1)[1]
        host, qs = self.code_from(h["location"])
        self.assertEqual(host, AUTH)
        self.assertEqual(qs["state"], [state])
        self.assertEqual(qs["host"], [APP])
        self.assertEqual(qs["rd"], [f"https://{APP}/deep?q=1"])
        self.assertEqual(self.get("/__porch/start", AUTH)[0], 400)
        # The whole flow with that state works and clears the state cookie.
        code, h, _ = self.get(h["location"][len(f"https://{AUTH}"):], AUTH,
                              {"cush_auth": self.cookie})
        _, qs = self.code_from(h["location"])
        code, h2, raw = self.redeem(APP, qs["code"][0], state=state)
        self.assertEqual(code, 302)
        cookies = [v for k, v in raw if k.lower() == "set-cookie"]
        self.assertTrue(any(c.startswith("porch_host=") for c in cookies))
        self.assertTrue(any(c.startswith("__Host-porch_state=;") and "Max-Age=0" in c
                            for c in cookies))

    def test_handoff_without_state_goes_to_porch_start(self):
        code, h, _ = self.get(f"/auth/handoff?host={APP}&rd=%2Fx", AUTH,
                              {"cush_auth": self.cookie})
        self.assertEqual(code, 302)
        self.assertEqual(h["location"], f"https://{APP}/__porch/start?rd=" +
                         authserver.quote(f"https://{APP}/x", safe=""))
        self.assertEqual(authserver.HANDOFF_CODES, {})

    def test_code_expires(self):
        code, h, _ = self.start()
        _, qs = self.code_from(h["location"])
        self.clock.advance(authserver.HANDOFF_TTL + 1)
        self.assertEqual(self.redeem(APP, qs["code"][0])[0], 400)

    def test_host_token_expiry_follows_the_device(self):
        self.device(self.cookie)["expires_at"] = authserver.iso_from_epoch(
            self.clock.time() + 120)
        _, cookie = self.full()
        tok = cookie.split(";")[0].split("=", 1)[1]
        self.assertLessEqual(int(re.search(r"Max-Age=(\d+)", cookie).group(1)), 120)
        devs = authserver.STATE["devices"]
        self.assertIsNotNone(authserver.find_host_token_device(devs, tok, APP, self.clock.time()))
        self.clock.advance(121)
        self.assertIsNone(authserver.find_host_token_device(devs, tok, APP, self.clock.time()))

    def test_revoke_cascades_to_host_tokens(self):
        _, cookie = self.full()
        tok = cookie.split(";")[0].split("=", 1)[1]
        dev = self.device(self.cookie)
        self.assertEqual(self.req("POST", "/auth/admin/revoke", {"device_id": dev["id"]})[0], 200)
        self.assertIsNone(authserver.find_host_token_device(authserver.STATE["devices"], tok, APP))
        self.assertEqual(dev["host_tokens"], [])

    def test_revoked_between_start_and_redeem(self):
        code, h, _ = self.start()
        _, qs = self.code_from(h["location"])
        self.device(self.cookie)["revoked"] = True
        self.assertEqual(self.redeem(APP, qs["code"][0])[0], 403)

    def test_open_redirect_protection(self):
        bad = ["https://evil.com/", "//evil.com/x", "https://evil.cush.rocks/",
               f"https://{APP}.evil.com/", f"https://{APP}@evil.com/",
               f"https://user@{APP}/", f"https://{APP}:444/", f"http://{APP}/",
               "javascript:alert(1)", f"https://{APP}/\r\nSet-Cookie:x=1",
               f"https://{APP}/\"><script>", "/\\evil.com", "///evil.com"]
        for rd in bad:
            code, h, _ = self.start(rd=rd)
            self.assertEqual(code, 302, rd)
            _, qs = self.code_from(h["location"])
            self.assertEqual(qs["rd"][0], f"https://{APP}/", rd)
            # A tampered rd on the second leg is clamped too.
            code, h2, _ = self.redeem(APP, qs["code"][0], rd)
            self.assertEqual(h2["location"], f"https://{APP}/", rd)
        code, h, _ = self.start(rd="/deep/path?q=1")
        _, qs = self.code_from(h["location"])
        self.assertEqual(qs["rd"][0], f"https://{APP}/deep/path?q=1")

    def test_start_rules(self):
        # Only on the auth host.
        self.assertEqual(self.get(f"/auth/handoff?host={APP}", APP,
                                  {"cush_auth": self.cookie})[0], 404)
        # Not enrolled: off to /login, which returns to the handoff.
        code, h, _ = self.get(f"/auth/handoff?host={APP}&state={self.STATE}", AUTH)
        self.assertEqual(code, 302)
        self.assertTrue(h["location"].startswith("/login?rd=https%3A%2F%2Fauth.cush.rocks%2Fauth%2Fhandoff"))
        from urllib.parse import unquote
        self.assertTrue(authserver.RD_RE.match(unquote(h["location"][len("/login?rd="):])))
        # Out of the guest's scope; bad hosts.
        self.assertEqual(self.start(host="trendlab.cush.rocks")[0], 403)
        for host in ("auth.cush.rocks", "evil.com", "a.b.c.cush.rocks", "cush.rocks"):
            self.assertEqual(self.start(host=host)[0], 400, host)
        # An admin device may hand off to any host, tunnel hosts included.
        self.device(self.cookie)["role"] = "admin"
        self.assertEqual(self.start(host="music.tunnel.cush.rocks")[0], 302)


# ---- domain config -----------------------------------------------------------

sys.path.insert(0, os.path.join(_HERE, "..", "lib"))
import porch_config  # noqa: E402


def _cfg(**env):
    e = {"PORCH_CONFIG": "none"}
    e.update(env)
    return porch_config.load(env=e)


class DomainPatternTest(unittest.TestCase):
    """The host/rd patterns are built from config and stay strict."""

    def tearDown(self):
        authserver.configure_domain(_cfg())

    def test_default_lookalikes_rejected(self):
        authserver.configure_domain(_cfg())
        h = authserver.HANDOFF_HOST_RE
        for good in ("grab.cush.rocks", "music.tunnel.cush.rocks", "eviltunnel.cush.rocks"):
            self.assertTrue(h.match(good), good)
        for bad in ("tunnel.cush.rocks.evil.com", "x.tunnel.cush.rocks.evil.com",
                    "x.eviltunnel.cush.rocks", "cush.rocks", "xcush.rocks",
                    "a.b.tunnel.cush.rocks", "grab.cushxrocks", "grab.cush.rocks\n",
                    "grab.cush.rocks.", "*.cush.rocks"):
            self.assertIsNone(h.match(bad), bad)
        for bad in ("grab.cush.rocks.evil.com", "grabcush.rocks", "grab.cushXrocks",
                    "grab.cush.rocks\n", "a.b.cush.rocks"):
            self.assertIsNone(authserver.HOST_RE.match(bad), bad)
        for bad in ("https://grab.cush.rocks.evil.com/", "https://grab.cushxrocks/",
                    "https://grab.cush.rocks/\n", "https://grab.cush.rocks@evil.com/"):
            self.assertIsNone(authserver.RD_RE.match(bad), bad)
        self.assertTrue(authserver.RD_RE.match("https://grab.cush.rocks/x?y=1"))

    def test_other_domain_patterns(self):
        authserver.configure_domain(_cfg(PORCH_DOMAIN="example.org"))
        self.assertEqual(authserver.AUTH_HOST, "auth.example.org")
        self.assertEqual(authserver.COOKIE_DOMAIN, ".example.org")
        self.assertEqual(authserver.INVITE_BASE_URL, "https://auth.example.org/i/")
        self.assertEqual(authserver.DEFAULT_RD, "https://tunnel.example.org/")
        self.assertEqual(authserver.KNOWN_HOSTS, [])
        self.assertEqual(authserver.DEFAULT_SERVER, {"addr": "tunnel.example.org", "port": 7000})
        h = authserver.HANDOFF_HOST_RE
        self.assertTrue(h.match("wiki.example.org"))
        self.assertTrue(h.match("music.tunnel.example.org"))
        for bad in ("grab.cush.rocks", "music.tunnel.cush.rocks", "wiki.exampleXorg",
                    "wiki.example.org.evil.com", "x.eviltunnel.example.org"):
            self.assertIsNone(h.match(bad), bad)
        self.assertIsNone(authserver.HOST_RE.match("grab.cush.rocks"))
        self.assertIsNone(authserver.RD_RE.match("https://grab.cush.rocks/"))
        with self.assertRaises(ValueError):
            authserver.normalize_apps(["grab.cush.rocks"])
        self.assertEqual(authserver.normalize_apps(["Wiki.example.org"]), ["wiki.example.org"])
        with self.assertRaises(ValueError):
            authserver.normalize_apps(["auth.example.org"])

    def test_tunnel_base_outside_root(self):
        cfg = porch_config.load(env={"PORCH_CONFIG": "none", "PORCH_DOMAIN": "example.org",
                                     "PORCH_TUNNEL_BASE": "apps.example.org"})
        authserver.configure_domain(cfg)
        self.assertTrue(authserver.HANDOFF_HOST_RE.match("drop.apps.example.org"))
        self.assertIsNone(authserver.HANDOFF_HOST_RE.match("drop.tunnel.example.org"))


EX_AUTH = "auth.example.org"
EX_APP = "wiki.example.org"


class OtherDomainEndToEndTest(PassCase):
    """The whole server on example.org: invites, gate cookie, handoff, pages."""

    PROTECTED = [EX_APP]
    STATE_VAL = "S" * 32

    def setUp(self):
        authserver.configure_domain(_cfg(PORCH_DOMAIN="example.org"))
        self.addCleanup(authserver.configure_domain, _cfg())
        super().setUp()
        authserver.STATE["server"] = dict(authserver.DEFAULT_SERVER)

    def raw(self, path, host):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("GET", path, headers={"Host": host})
            r = conn.getresponse()
            return r.status, r.read().decode("utf-8")
        finally:
            conn.close()

    def get(self, path, host, cookies=None):
        hdrs = {"Host": host}
        if cookies:
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        code, _, h = self.req("GET", path, headers=hdrs, cli=False)
        return code, {k.lower(): v for k, v in h}, h

    def test_invite_and_gate_cookie(self):
        code, data, _ = self.req("POST", "/auth/admin/invites", {"apps": [EX_APP]})
        self.assertEqual(code, 200, data)
        self.assertTrue(data["url"].startswith("https://auth.example.org/i/"))
        code, data, _ = self.req("POST", "/auth/admin/invites", {"apps": ["grab.cush.rocks"]})
        self.assertEqual(code, 400)
        token = self.invite(apps=[EX_APP])[0]
        authserver.INVITE_ACCEPT_ATTEMPTS.clear()
        code, _, hdrs = self.req("POST", f"/i/{token}/accept", {"device_name": "t"}, cli=False)
        self.assertEqual(code, 200)
        cookie = next(v for k, v in hdrs if k.lower() == "set-cookie" and v.startswith("cush_auth="))
        self.assertIn("Domain=.example.org;", cookie)
        self.assertIn(self.key(cookie.split(";")[0].split("=", 1)[1], EX_APP), self.grants())

    def test_handoff_round_trip(self):
        handler = authserver.AuthHandler.__new__(authserver.AuthHandler)
        with authserver.STATE_LOCK:
            dev, cookie = handler._mint_browser_device_locked("Phone", [EX_APP], "admin")
        q = f"/auth/handoff?host={EX_APP}&state={self.STATE_VAL}&rd=" + authserver.quote(
            f"https://{EX_APP}/page", safe="")
        code, h, _ = self.get(q, EX_AUTH, {"cush_auth": cookie})
        self.assertEqual(code, 302, h)
        from urllib.parse import urlparse as up, parse_qs as pq
        loc = up(h["location"])
        self.assertEqual(loc.hostname, EX_APP)
        qs = pq(loc.query)
        code, h2, raw = self.get("/__porch/auth?code=" + qs["code"][0] + "&rd="
                                 + authserver.quote(qs["rd"][0], safe=""), EX_APP,
                                 {authserver.STATE_COOKIE: self.STATE_VAL})
        self.assertEqual(code, 302)
        self.assertEqual(h2["location"], f"https://{EX_APP}/page")
        # A tunnel host on the new domain works for an admin; the old domain,
        # the auth host and lookalikes do not.
        code, h, _ = self.get(f"/auth/handoff?host=music.tunnel.example.org&state={self.STATE_VAL}",
                              EX_AUTH, {"cush_auth": cookie})
        self.assertEqual(code, 302)
        for bad in ("grab.cush.rocks", EX_AUTH, "wiki.example.org.evil.com",
                    "x.eviltunnel.example.org", "music.tunnel.cush.rocks"):
            code, _, _ = self.get(f"/auth/handoff?host={bad}&state={self.STATE_VAL}",
                                  EX_AUTH, {"cush_auth": cookie})
            self.assertEqual(code, 400, bad)
        # The handoff only answers on the configured auth host.
        code, _, _ = self.get(q, "auth.cush.rocks", {"cush_auth": cookie})
        self.assertEqual(code, 404)
        # Open redirect protection on the new domain.
        for rd in ("https://grab.cush.rocks/", f"https://{EX_APP}.evil.com/",
                   "https://evil.example.org.evil.com/"):
            code, h, _ = self.get(f"/auth/handoff?host={EX_APP}&state={self.STATE_VAL}&rd="
                                  + authserver.quote(rd, safe=""), EX_AUTH, {"cush_auth": cookie})
            self.assertEqual(pq(up(h["location"]).query)["rd"][0], f"https://{EX_APP}/", rd)

    def test_pages_carry_the_domain(self):
        code, body = self.raw("/login", EX_AUTH)
        self.assertEqual(code, 200)
        self.assertNotIn("cush.rocks", body)
        self.assertNotIn("__PORCH_", body)
        code, body = self.raw("/i/" + "x" * 43, EX_AUTH)
        self.assertIn(r"[a-z0-9-]+\.example\.org(\/|$)", body)
        self.assertIn('"https://tunnel.example.org/"', body)
        self.assertNotIn("__PORCH_", body)
        code, body = self.raw("/auth/", EX_AUTH)
        self.assertIn("*.example.org", body)
        self.assertIn('"auth.example.org"', body)
        self.assertNotIn("cush.rocks", body)

    def test_apps_action_uses_the_domain(self):
        code, _, _ = self.req("POST", "/auth/admin/apps", {"host": "grab.cush.rocks", "action": "protect"})
        self.assertEqual(code, 400)
        code, _, _ = self.req("POST", "/auth/admin/apps", {"host": EX_AUTH, "action": "protect"})
        self.assertEqual(code, 400)
        code, data, _ = self.req("POST", "/auth/admin/apps", {"host": "docs.example.org", "action": "protect"})
        self.assertEqual(code, 200, data)
        self.assertIn("docs.example.org", self.hap.live[authserver.PROTECTED_MAP])


class CliThroughApiTest(PassCase):
    """bin/auth-admin talks to the running server; nothing it does can be
    lost to the server's next save."""

    ADMIN = os.path.join(_HERE, "..", "bin", "auth-admin")

    def run_cli(self, *args, url=None):
        env = dict(os.environ, PORCH_AUTH_URL=url or f"http://127.0.0.1:{self.port}")
        return subprocess.run([sys.executable, self.ADMIN, *args, "--data", self.tmp.name],
                              capture_output=True, text=True, env=env, timeout=60)

    def test_revoke_goes_through_the_server(self):
        with authserver.STATE_LOCK:
            handler = authserver.AuthHandler.__new__(authserver.AuthHandler)
            dev, _ = handler._mint_browser_device_locked("Tablet", [APP], "guest")
            authserver.save_state_locked()
        r = self.run_cli("revoke", dev["id"], "--yes")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(dev["revoked"])
        # The server's next save keeps it.
        authserver.sync_haproxy_maps()
        with authserver.STATE_LOCK:
            authserver.save_state_locked()
        with open(authserver.DEVICES_PATH) as f:
            on_disk = next(d for d in json.load(f)["devices"] if d["id"] == dev["id"])
        self.assertTrue(on_disk["revoked"])

    def test_approve_needs_scope_for_web_and_uses_the_server(self):
        code, p, _ = self.req("POST", "/auth/web-pair/start", {"device_name": "b"}, cli=False)
        r = self.run_cli("approve", p["code"], "--yes")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("explicit scope", r.stderr)
        r = self.run_cli("approve", p["code"], "--yes", "--apps", APP)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(authserver.STATE["devices"][-1]["type"], "browser")
        self.assertIn(p["poll_token"], authserver.PENDING_TOKENS)

    def test_rename_through_the_server(self):
        with authserver.STATE_LOCK:
            handler = authserver.AuthHandler.__new__(authserver.AuthHandler)
            dev, _ = handler._mint_browser_device_locked("Old name", [APP], "guest")
            authserver.save_state_locked()
        r = self.run_cli("rename", "Old name", "New name")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("to 'New name'", r.stdout)
        self.assertEqual(dev["name"], "New name")
        r = self.run_cli("rename", dev["id"], "")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("1-64 printable", r.stderr)
        r = self.run_cli("rename", "nobody", "x")
        self.assertIn("no device matches", r.stderr)
        self.assertNotIn(self.cli, r.stderr + r.stdout)

    def test_data_before_the_subcommand_is_kept(self):
        """`auth-admin --data DIR <cmd>` must use DIR, never fall back to the
        live data/ (a subcommand default used to overwrite it)."""
        with authserver.STATE_LOCK:
            handler = authserver.AuthHandler.__new__(authserver.AuthHandler)
            dev, _ = handler._mint_browser_device_locked("Front data", [APP], "guest")
            authserver.save_state_locked()
        env = dict(os.environ, PORCH_AUTH_URL=f"http://127.0.0.1:{self.port}")
        r = subprocess.run([sys.executable, self.ADMIN, "--data", self.tmp.name, "list"],
                           capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Front data", r.stdout)

    def test_stale_token_message(self):
        with open(os.path.join(self.tmp.name, authserver.CLI_TOKEN_FILE), "w") as f:
            f.write("not-the-token")
        r = self.run_cli("list")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("server said 401", r.stderr)
        self.assertIn("stale token?", r.stderr)
        self.assertNotIn("not-the-token", r.stderr)

    def test_offline_fallback_uses_the_shared_lock(self):
        dead = "http://127.0.0.1:9"   # discard port: nothing listens
        with authserver.STATE_LOCK:
            handler = authserver.AuthHandler.__new__(authserver.AuthHandler)
            dev, _ = handler._mint_browser_device_locked("Old", [APP], "guest")
            authserver.save_state_locked()
        # While the lock is held exclusively, the CLI waits.
        lock = authserver.devices_lock(authserver.DEVICES_PATH, exclusive=True)
        lock.__enter__()
        env = dict(os.environ, PORCH_AUTH_URL=dead)
        proc = subprocess.Popen([sys.executable, self.ADMIN, "revoke", dev["id"], "--yes",
                                 "--data", self.tmp.name], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(1.0)
        self.assertIsNone(proc.poll())
        lock.__exit__(None, None, None)
        out, err = proc.communicate(timeout=30)
        self.assertEqual(proc.returncode, 0, err)
        with open(authserver.DEVICES_PATH) as f:
            on_disk = next(d for d in json.load(f)["devices"] if d["id"] == dev["id"])
        self.assertTrue(on_disk["revoked"])

    def test_offline_refused_while_server_lock_held(self):
        saved = authserver.DATA_DIR, authserver._SERVER_LOCK_FD
        authserver.acquire_server_lock()
        fd = authserver._SERVER_LOCK_FD

        def release():
            os.close(fd)
            authserver.DATA_DIR, authserver._SERVER_LOCK_FD = saved
        self.addCleanup(release)
        r = self.run_cli("revoke", "nope", "--yes", url="http://127.0.0.1:9")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("could not reach authserver", r.stderr)


class LoginDoubleSubmitTest(unittest.TestCase):
    """The /login enroll form sends one request at a time: five devices were
    once minted in the same second by repeated taps during the slow scrypt."""

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_one_enroll_in_flight(self):
        html = authserver.LOGIN_HTML
        js = re.search(r'<script nonce="__NONCE__">(.*?)</script>', html, re.S).group(1)
        js = js.replace('"__RD__"', '"https://pocket.tunnel.cush.rocks/"')
        harness = r"""
const els = {}, fetches = [];
function mk(id){ return els[id] || (els[id] = {id, value: id === 'pw' ? 'secret' : '', textContent: 'Enroll',
  disabled: false, classList: {add(){}, remove(){}}, handlers: {},
  addEventListener(t, f){ (this.handlers[t] = this.handlers[t] || []).push(f); }}); }
global.document = {getElementById: mk, addEventListener(){}, hidden: false};
global.window = {location: {href: ''}, addEventListener(){}};
global.location = window.location;
global.setTimeout = () => 0; global.clearTimeout = () => {};
global.fetch = (url, o) => new Promise((res) => { fetches.push({url, res}); });
""" + js + r"""
const fire = (id, t, ev) => (els[id].handlers[t] || []).forEach(f => f(ev || {}));
for (let i = 0; i < 4; i++) fire('go', 'click');
fire('pw', 'keydown', {key: 'Enter'}); fire('name', 'keydown', {key: 'Enter'});
const first = fetches.filter(f => f.url === '/auth/enroll').length;
const disabled = els.go.disabled;
fetches[0].res({ok: false, status: 401, json: () => Promise.resolve({ok: false})});
setImmediate(() => setImmediate(() => {
  const reenabled = !els.go.disabled, msg = els.msg.textContent;
  fire('go', 'click');
  console.log(JSON.stringify({first, disabled, reenabled, msg,
    second: fetches.filter(f => f.url === '/auth/enroll').length}));
}));
"""
        out = subprocess.run(["node", "-e", harness], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        r = json.loads(out.stdout.strip().splitlines()[-1])
        self.assertEqual(r["first"], 1)
        self.assertTrue(r["disabled"])
        self.assertTrue(r["reenabled"])
        self.assertEqual(r["second"], 2)
        self.assertEqual(r["msg"], "Invalid password")

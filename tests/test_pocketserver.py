"""Tests for lib/pocketserver.py (bin/pocket) and lib/porch_setup/cmd_clip.py
(porch clip). Stdlib unittest; temp dirs; servers on ephemeral 127.0.0.1
ports in threads. Never touches ~/pocket, data/ or /tmp/tunnel-state.
"""

import hashlib
import http.client
import importlib.util
import io
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest

import mobile_markup  # tests/ helper

_HERE = os.path.dirname(os.path.abspath(__file__))
_LIB = os.path.join(_HERE, "..", "lib")
_spec = importlib.util.spec_from_file_location("pocketserver", os.path.join(_LIB, "pocketserver.py"))
ps = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ps)
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
from porch_setup import cmd_clip  # noqa: E402

OWNER_TOKEN = "o" * 64
GUEST_TOKEN = "g" * 64
CLI_TOKEN = "cli-token-" + "x" * 30


def sha(t):
    return hashlib.sha256(t.encode()).hexdigest()


def app_bundle(page):
    """The shell plus every hashed /static/ script and stylesheet it names
    (the app's code lives in those files now, not in the page)."""
    parts = [page]
    for path in re.findall(r'(?:src|href)="(/static/[^"]+)"', page):
        hit = ps.pocket_assets.lookup(path)
        if hit:
            parts.append(hit[0].decode("utf-8"))
    return "\n".join(parts)


def write_devices(path):
    devices = [
        {"name": "owner", "type": "browser", "role": "admin", "token_sha256": sha(OWNER_TOKEN)},
        {"name": "guest", "type": "browser", "role": "guest", "token_sha256": sha(GUEST_TOKEN)},
    ]
    with open(path, "w") as f:
        json.dump({"devices": devices}, f)


def multipart(fields=(), files=(), boundary="pocketboundary42"):
    out = b""
    for name, value in fields:
        out += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n"
                ).encode() + value.encode() + b"\r\n"
    for name, data in files:
        out += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"files\"; "
                f"filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                ).encode() + data + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return out, f"multipart/form-data; boundary={boundary}"


class ServerCase(unittest.TestCase):
    devices_present = True

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="porch-pocket-")
        self.base = os.path.join(self.tmp, "pocket")
        self.inbox = os.path.join(self.base, "inbox")
        os.makedirs(self.inbox)
        self.devices = os.path.join(self.tmp, "devices.json")
        if self.devices_present:
            write_devices(self.devices)
        self.store = ps.ClipStore(os.path.join(self.base, ".clip.json"))
        self.hub = ps.Hub(max_total=4, per_client=2)
        attrs = dict(base_dir=ps.Path(self.base), inbox_dir=ps.Path(self.inbox),
                     devices_path=self.devices, store=self.store, hub=self.hub,
                     cli_token=CLI_TOKEN, min_free=0, max_total=4 * 1024 * 1024,
                     max_file=1024 * 1024, max_files=50, sse_heartbeat=0.3,
                     upload_slots=ps.UploadSlots(total=32, per_ip=32),
                     keys=ps.KeyStore(os.path.join(self.base, ".share-keys.json")),
                     key_rate=ps.RateLimit(5, 600), key_fail=ps.RateLimit(3, 600),
                     reopen_store=ps.reopen_requests.Store(os.path.join(self.tmp, "requests.json")),
                     # Never the live /tmp/tunnel-state or frpc processes.
                     state_dir=os.path.join(self.tmp, "doorstate"), doors_unmanaged=False)
        os.makedirs(attrs["state_dir"])
        attrs.update(self.handler_attrs())
        self.H = type("H", (ps.PocketHandler,), attrs)
        self.server = ps.BoundedThreadingHTTPServer(("127.0.0.1", 0), self.H)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def handler_attrs(self):
        return {}

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def req(self, method, path, body=None, token=None, ctype=None, origin=True, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = dict(headers or {})
        if origin:
            h["Origin"] = f"http://127.0.0.1:{self.port}"
        if token:
            h["Cookie"] = f"cush_auth={token}"
        if ctype:
            h["Content-Type"] = ctype
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r, data

    def owner(self, method, path, body=None, **kw):
        return self.req(method, path, body, token=OWNER_TOKEN, **kw)

    def jpost(self, path, obj, **kw):
        return self.owner("POST", path, json.dumps(obj).encode(), ctype="application/json", **kw)

    def cli(self, method, path, body=None, headers=None):
        h = {ps.CLI_TOKEN_HEADER: CLI_TOKEN}
        h.update(headers or {})
        data = json.dumps(body).encode() if body is not None else None
        if data:
            h["Content-Type"] = "application/json"
        return self.req(method, path, data, origin=False, headers=h)


GATED = [("GET", "/"), ("GET", "/api/clip"), ("GET", "/api/inbox"), ("GET", "/api/events"),
         ("GET", "/inbox/a.txt"), ("POST", "/api/clip"), ("POST", "/share"),
         ("POST", "/api/clip/abcdefgh/delete"), ("POST", "/api/inbox/a.txt/delete"),
         ("DELETE", "/api/clip/abcdefgh"), ("OPTIONS", "/tus/"), ("POST", "/tus/"),
         ("GET", "/nope"), ("GET", "/api/keys"), ("POST", "/api/keys"),
         ("POST", "/api/keys/abcdefghij/rotate"), ("POST", "/api/keys/abcdefghij/delete")]
PUBLIC = ["/manifest.webmanifest", "/sw.js", "/icon.svg"]


class GateTests(ServerCase):

    def test_every_route_needs_the_owner(self):
        with open(os.path.join(self.inbox, "a.txt"), "w") as f:
            f.write("secret")
        for token in (None, GUEST_TOKEN, "nope"):
            for method, path in GATED:
                r, body = self.req(method, path, b"{}" if method == "POST" else None, token=token)
                self.assertEqual(r.status, 403, (token, method, path))
                self.assertNotIn(b"secret", body)

    def test_refusal_page_is_porch_styled_and_says_nothing(self):
        r, body = self.req("GET", "/")
        self.assertEqual(r.status, 403)
        page = body.decode()
        self.assertIn("/__porch-assets/porch.", page)
        self.assertIn("p-shell", page)
        self.assertNotIn("api/clip", page)
        self.assertIn("nonce-", r.getheader("Content-Security-Policy"))

    def test_signin_link_with_a_public_host(self):
        r, body = self.req("GET", "/", headers={"Host": "pocket.tunnel.cush.rocks"})
        self.assertEqual(r.status, 403)
        self.assertIn(b"Owner? Sign in", body)
        self.assertIn(b"https://pocket.tunnel.cush.rocks/__porch/start?rd=", body)

    def test_public_routes_need_nothing(self):
        for path in PUBLIC:
            r, _ = self.req("GET", path)
            self.assertEqual(r.status, 200, path)
        if "/icon-192.png" in ps.ICONS:
            r, body = self.req("GET", "/icon-192.png")
            self.assertEqual((r.status, r.getheader("Content-Type")), (200, "image/png"))
            self.assertTrue(body.startswith(b"\x89PNG"))

    def test_owner_gets_the_page(self):
        r, body = self.owner("GET", "/")
        self.assertEqual(r.status, 200)
        page = body.decode()
        csp = r.getheader("Content-Security-Policy")
        self.assertIn("worker-src 'self'", csp)
        self.assertIn("manifest-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertIn('rel="manifest"', page)
        self.assertIn('id="app"', page)              # the Porch app shell
        self.assertIn("PorchTus", app_bundle(page))

    def test_page_script_is_textcontent_only(self):
        _, body = self.owner("GET", "/")
        page = body.decode()
        for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
                    "alert(", "style=\""):
            self.assertNotIn(bad, page, bad)
        self.assertNotIn("innerHTML", ps.SERVICE_WORKER_JS)

    def test_writes_need_same_origin(self):
        r, _ = self.owner("POST", "/api/clip", b'{"text":"x"}', ctype="application/json",
                          origin=False)
        self.assertEqual(r.status, 403)
        r, _ = self.owner("POST", "/api/clip", b'{"text":"x"}', ctype="application/json",
                          origin=False, headers={"Origin": "https://evil.example"})
        self.assertEqual(r.status, 403)
        self.assertIsNone(self.store.snapshot()["current"])

    def test_share_accepts_browser_initiated_navigation(self):
        body, ctype = multipart([("text", "from the share sheet")])
        # Sec-Fetch-Site: none and no Origin: the share target's own POST.
        r, _ = self.owner("POST", "/share", body, ctype=ctype, origin=False,
                          headers={"Sec-Fetch-Site": "none"})
        self.assertEqual(r.status, 303)
        # A cross-site page cannot claim it.
        r, _ = self.owner("POST", "/share", body, ctype=ctype, origin=False,
                          headers={"Sec-Fetch-Site": "none", "Origin": "https://evil.example"})
        self.assertEqual(r.status, 403)
        r, _ = self.owner("POST", "/share", body, ctype=ctype, origin=False,
                          headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(r.status, 403)


class FailClosedTests(ServerCase):
    devices_present = False

    def test_no_registry_means_nobody(self):
        for method, path in GATED:
            r, _ = self.req(method, path, b"{}" if method == "POST" else None, token=OWNER_TOKEN)
            self.assertEqual(r.status, 403, (method, path))
        r, body = self.req("GET", "/")
        self.assertNotIn(b"Sign in", body)
        r, _ = self.req("GET", "/manifest.webmanifest")
        self.assertEqual(r.status, 200)


class PwaTests(ServerCase):

    def test_manifest_has_share_target(self):
        r, body = self.req("GET", "/manifest.webmanifest")
        self.assertEqual(r.getheader("Content-Type"), "application/manifest+json")
        m = json.loads(body)
        self.assertEqual((m["start_url"], m["scope"], m["display"]), ("/", "/", "standalone"))
        self.assertEqual(m["theme_color"], "#121014")
        st = m["share_target"]
        self.assertEqual((st["action"], st["method"], st["enctype"]),
                         ("/share", "POST", "multipart/form-data"))
        self.assertEqual({k: st["params"][k] for k in ("title", "text", "url")},
                         {"title": "title", "text": "text", "url": "url"})
        self.assertEqual(st["params"]["files"], [{"name": "files", "accept": ["*/*"]}])
        sizes = {i["sizes"] for i in m["icons"]}
        self.assertIn("any", sizes)
        if "/icon-512.png" in ps.ICONS:
            self.assertIn("512x512", sizes)
            self.assertTrue(any(i["purpose"] == "maskable" for i in m["icons"]))

    def test_service_worker(self):
        r, body = self.req("GET", "/sw.js")
        self.assertTrue(r.getheader("Content-Type").startswith("text/javascript"))
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
        js = body.decode()
        self.assertIn("navigate", js)
        # It caches the page shell only, never an API answer; its one API
        # call is the notification's Allow button (POST /api/reopen/<id>).
        fetch_handler = js.split("addEventListener('fetch'", 1)[1].split("});", 1)[0]
        self.assertNotIn("/api/", fetch_handler)
        self.assertEqual(js.count("/api/"), 1)
        self.assertIn("fetch('/api/reopen/' + d.id", js)

    def test_service_worker_v2_push_types_and_precache(self):
        r, body = self.req("GET", "/sw.js")
        js = body.decode()
        self.assertIn("pocket-shell-v2", js)
        self.assertIn("/^[A-Z]{4}-[0-9]{4}$/", js)
        self.assertIn("'/#/requests/pairing/' + d.code", js)
        self.assertIn("'/#/people/guests/'", js)
        self.assertNotIn("__PRECACHE_URL__", js)
        m = re.search(r"const PRECACHE = '(/static/precache\.[0-9a-f]{12}\.json)'", js)
        self.assertIsNotNone(m)
        r, raw = self.owner("GET", m.group(1))
        self.assertEqual(r.status, 200)
        self.assertIn("immutable", r.getheader("Cache-Control"))
        lst = json.loads(raw)
        self.assertTrue(lst and all(p.startswith(("/static/", "/__porch-assets/")) for p in lst))
        for name in ("qr.js", "core.js", "app.css", "boot.js", "tus.js"):
            self.assertIn(ps.pocket_assets.asset_url(name), lst)
        self.assertIn(sys.modules["porch_http"].PORCH_CSS_PATH, lst)   # styled offline
        # Pairing and access notifications carry no action buttons (approving
        # or letting someone in needs a step-up).
        pairing = js.split("} else if (pairing || access) {", 1)[1].split("}", 1)[0]
        self.assertNotIn("actions", pairing)
        self.assertIn("'/#/requests/access/' + d.id", js)


class ShareTests(ServerCase):

    def test_text_url_and_two_files(self):
        body, ctype = multipart([("title", "A page"), ("text", "look at this"),
                                 ("url", "https://example.com/x")],
                                [("one.jpg", b"J" * 1000), ("../two.txt", b"hello")])
        r, _ = self.owner("POST", "/share", body, ctype=ctype)
        self.assertEqual(r.status, 303)
        cur = self.store.snapshot()["current"]
        # The redirect names what came in, so the page can offer "Make a link?".
        self.assertEqual(r.getheader("Location"),
                         f"/?shared=1&files=2&text=1&f=one.jpg&f=two.txt&c={cur['id']}")
        self.assertEqual(sorted(os.listdir(self.inbox)), ["one.jpg", "two.txt"])
        self.assertEqual(cur["text"], "A page\nlook at this\nhttps://example.com/x")
        self.assertEqual(cur["source"], "desktop")
        st = os.stat(os.path.join(self.base, ".clip.json"))
        self.assertEqual(st.st_mode & 0o777, 0o600)

    def test_link_repeated_in_text_is_kept_once(self):
        body, ctype = multipart([("text", "https://example.com/a"), ("url", "https://example.com/a")])
        self.owner("POST", "/share", body, ctype=ctype,
                   headers={"User-Agent": "Mozilla/5.0 (Linux; Android 14) Mobile"})
        cur = self.store.snapshot()["current"]
        self.assertEqual((cur["text"], cur["source"]), ("https://example.com/a", "phone"))

    def test_fetch_mode_answers_json(self):
        body, ctype = multipart([], [("f.bin", b"x" * 10)])
        r, data = self.owner("POST", "/share", body, ctype=ctype, headers={"X-Porch-Fetch": "1"})
        self.assertEqual(r.status, 200)
        self.assertEqual(json.loads(data)["files"], [{"name": "f.bin", "size": 10}])

    def test_per_file_cap(self):
        body, ctype = multipart([], [("big.bin", b"x" * (1024 * 1024 + 10))])
        r, data = self.owner("POST", "/share", body, ctype=ctype)
        self.assertEqual(r.status, 413)
        self.assertIn(b"per-file limit", data)
        self.assertEqual([n for n in os.listdir(self.inbox) if not n.startswith(".")], [])

    def test_request_cap_before_reading(self):
        self.H.max_total = 1024
        r, _ = self.owner("POST", "/share", b"x" * 10, ctype="multipart/form-data; boundary=b",
                          headers={"Content-Length": str(10 * 1024 * 1024)})
        self.assertEqual(r.status, 413)

    def test_text_field_cap(self):
        body, ctype = multipart([("text", "y" * (ps.MAX_FIELD_BYTES + 1))])
        r, _ = self.owner("POST", "/share", body, ctype=ctype)
        self.assertEqual(r.status, 413)
        self.assertIsNone(self.store.snapshot()["current"])

    def test_quota(self):
        self.H.max_files = 1
        body, ctype = multipart([], [("a.bin", b"1"), ("b.bin", b"2")])
        r, data = self.owner("POST", "/share", body, ctype=ctype)
        self.assertEqual(r.status, 413)
        self.assertIn(b"1 file(s) made it in", data)
        self.assertEqual(os.listdir(self.inbox), ["a.bin"])


class ClipTests(ServerCase):

    def test_set_get_history_delete(self):
        for t in ("one", "two", "three"):
            r, _ = self.jpost("/api/clip", {"text": t})
            self.assertEqual(r.status, 200)
        r, data = self.owner("GET", "/api/clip")
        snap = json.loads(data)
        self.assertEqual(snap["current"]["text"], "three")
        self.assertEqual([e["text"] for e in snap["history"]], ["two", "one"])
        # re-setting an old text moves it up instead of duplicating it
        self.jpost("/api/clip", {"text": "one"})
        snap = self.store.snapshot()
        self.assertEqual([snap["current"]["text"]] + [e["text"] for e in snap["history"]],
                         ["one", "three", "two"])
        eid = snap["current"]["id"]
        r, _ = self.jpost(f"/api/clip/{eid}/delete", {})
        self.assertEqual(r.status, 200)
        self.assertEqual(self.store.snapshot()["current"]["text"], "three")
        r, _ = self.owner("DELETE", f"/api/clip/{self.store.snapshot()['current']['id']}")
        self.assertEqual(r.status, 200)
        r, _ = self.jpost("/api/clip/doesnotexist/delete", {})
        self.assertEqual(r.status, 404)

    def test_history_is_capped_and_persisted(self):
        for i in range(ps.MAX_HISTORY + 5):
            self.store.add(f"t{i}", "desktop")
        again = ps.ClipStore(os.path.join(self.base, ".clip.json"))
        self.assertEqual(len(again.entries), ps.MAX_HISTORY)
        self.assertEqual(again.snapshot()["current"]["text"], f"t{ps.MAX_HISTORY + 4}")

    def test_caps_and_bad_bodies(self):
        r, _ = self.jpost("/api/clip", {"text": "z" * (ps.MAX_CLIP_BYTES + 1)})
        self.assertEqual(r.status, 413)
        r, _ = self.jpost("/api/clip", {"text": "   "})
        self.assertEqual(r.status, 400)
        r, _ = self.owner("POST", "/api/clip", b"not json", ctype="application/json")
        self.assertEqual(r.status, 400)


class CliTokenTests(ServerCase):

    def test_accepted_locally(self):
        r, _ = self.cli("POST", "/api/clip", {"text": "from cli"})
        self.assertEqual(r.status, 200)
        self.assertEqual(self.store.snapshot()["current"]["source"], "cli")
        r, data = self.cli("GET", "/api/clip")
        self.assertEqual(json.loads(data)["current"]["text"], "from cli")

    def test_refused_when_forwarded_or_from_a_page(self):
        for extra in ({"X-Forwarded-For": "203.0.113.9"}, {"Forwarded": "for=1.2.3.4"},
                      {"Origin": f"http://127.0.0.1:{self.port}"}, {"X-Real-IP": "1.2.3.4"},
                      {"Host": "pocket.tunnel.cush.rocks"}):
            r, _ = self.cli("GET", "/api/clip", headers=extra)
            self.assertEqual(r.status, 403, extra)

    def test_wrong_token_and_not_for_the_page(self):
        r, _ = self.req("GET", "/api/clip", origin=False, headers={ps.CLI_TOKEN_HEADER: "nope"})
        self.assertEqual(r.status, 403)
        r, _ = self.cli("GET", "/")
        self.assertEqual(r.status, 403)

    def test_off_when_unset(self):
        self.H.cli_token = ""
        r, _ = self.req("GET", "/api/clip", origin=False, headers={ps.CLI_TOKEN_HEADER: ""})
        self.assertEqual(r.status, 403)


class EventTests(ServerCase):

    def open_stream(self, token=OWNER_TOKEN):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        s.sendall((f"GET /api/events HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\n"
                   f"Cookie: cush_auth={token}\r\n\r\n").encode())
        return s, s.makefile("rb")

    def read_until(self, f, needle, limit=200):
        lines = []
        for _ in range(limit):
            line = f.readline().decode()
            lines.append(line)
            if needle in line:
                return lines
        self.fail(f"{needle!r} not seen in {lines!r}")

    def test_pushes_clip_change_and_heartbeat(self):
        s, f = self.open_stream()
        try:
            self.assertIn("200", f.readline().decode())
            self.read_until(f, "event: inbox")
            self.read_until(f, ": ping")          # heartbeat (0.3s in tests)
            self.jpost("/api/clip", {"text": "pushed"})
            lines = self.read_until(f, "pushed")
            self.assertIn("event: clip\n", lines)
            with open(os.path.join(self.inbox, "dropped.txt"), "w") as out:
                out.write("x")
            self.read_until(f, "dropped.txt")      # out-of-band inbox change
        finally:
            f.close()
            s.close()

    def test_per_client_cap(self):
        held = [self.open_stream(), self.open_stream()]
        try:
            for s, f in held:
                self.assertIn("200", f.readline().decode())
            r, _ = self.owner("GET", "/api/events")
            self.assertEqual(r.status, 429)
        finally:
            for s, f in held:
                f.close()
                s.close()


class InboxTests(ServerCase):

    def test_tus_upload_lands_in_inbox(self):
        data = b"tus bytes " * 100
        meta = "filename " + __import__("base64").b64encode(b"note.txt").decode()
        r, _ = self.owner("POST", "/tus/", headers={"Tus-Resumable": "1.0.0",
                                                     "Upload-Length": str(len(data)),
                                                     "Upload-Metadata": meta})
        self.assertEqual(r.status, 201)
        loc = r.getheader("Location")
        r, _ = self.owner("PATCH", loc, data, ctype="application/offset+octet-stream",
                          headers={"Tus-Resumable": "1.0.0", "Upload-Offset": "0"})
        self.assertEqual(r.status, 204)
        self.assertEqual(r.getheader("Porch-Upload-Name"), "note.txt")
        with open(os.path.join(self.inbox, "note.txt"), "rb") as f:
            self.assertEqual(f.read(), data)
        self.assertGreater(self.hub.versions["inbox"], 0)

    def test_tus_needs_owner_and_origin(self):
        h = {"Tus-Resumable": "1.0.0", "Upload-Length": "5"}
        r, _ = self.req("POST", "/tus/", headers=h, token=GUEST_TOKEN)
        self.assertEqual(r.status, 403)
        r, _ = self.owner("POST", "/tus/", headers=h, origin=False)
        self.assertEqual(r.status, 403)

    def test_list_download_and_delete(self):
        with open(os.path.join(self.inbox, "page.html"), "w") as f:
            f.write("<script>alert(1)</script>")
        with open(os.path.join(self.inbox, "pic.png"), "wb") as f:
            f.write(b"\x89PNG....")
        r, data = self.owner("GET", "/api/inbox")
        self.assertEqual(sorted(x["name"] for x in json.loads(data)), ["page.html", "pic.png"])
        r, body = self.owner("GET", "/inbox/page.html")
        self.assertEqual(r.getheader("Content-Type"), "application/octet-stream")
        self.assertTrue(r.getheader("Content-Disposition").startswith("attachment"))
        self.assertIn("sandbox", r.getheader("Content-Security-Policy"))
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
        r, _ = self.owner("GET", "/inbox/pic.png")
        self.assertEqual(r.getheader("Content-Type"), "image/png")
        self.assertTrue(r.getheader("Content-Disposition").startswith("inline"))
        r, _ = self.owner("GET", "/inbox/pic.png?dl=1")
        self.assertEqual(r.getheader("Content-Type"), "application/octet-stream")
        self.assertTrue(r.getheader("Content-Disposition").startswith("attachment"))
        self.assertIn("sandbox", r.getheader("Content-Security-Policy"))
        r, _ = self.owner("GET", "/inbox/..%2f..%2fdevices.json")
        self.assertEqual(r.status, 404)
        r, _ = self.jpost("/api/inbox/pic.png/delete", {})
        self.assertEqual(r.status, 200)
        self.assertEqual(os.listdir(self.inbox), ["page.html"])
        r, _ = self.jpost("/api/inbox/pic.png/delete", {})
        self.assertEqual(r.status, 404)

    def test_symlink_is_neither_listed_nor_served(self):
        os.symlink(self.devices, os.path.join(self.inbox, "link.json"))
        _, data = self.owner("GET", "/api/inbox")
        self.assertEqual(json.loads(data), [])
        r, _ = self.owner("GET", "/inbox/link.json")
        self.assertEqual(r.status, 404)


class ClipCliTests(ServerCase):

    def setUp(self):
        super().setUp()
        self.state_dir = os.path.join(self.tmp, "state")
        os.mkdir(self.state_dir)
        with open(os.path.join(self.state_dir, "pt.json"), "w") as f:
            json.dump({"name": "pt", "type": "pocket", "port": self.port}, f)
        self.token_file = os.path.join(self.tmp, "pt.token")
        with open(self.token_file, "w") as f:
            f.write(CLI_TOKEN + "\n")

    def run_cli(self, *argv, stdin=""):
        out = io.StringIO()
        code = cmd_clip.main(["--name", "pt"] + list(argv), stdin=io.StringIO(stdin), out=out,
                             state_dir=self.state_dir, token_file=self.token_file)
        return code, out.getvalue()

    def test_set_get_ls_rm(self):
        self.assertEqual(self.run_cli("set", "hello", "world"), (0, ""))
        self.assertEqual(self.run_cli(), (0, "hello world"))
        self.assertEqual(self.run_cli("set", "-", stdin="from stdin\n")[0], 0)
        self.assertEqual(self.run_cli("get"), (0, "from stdin\n"))
        code, out = self.run_cli("ls")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("* "))
        self.assertIn("hello world", out)
        code, out = self.run_cli("ls", "--json")
        entries = json.loads(out)
        self.assertEqual([e["source"] for e in entries], ["cli", "cli"])
        self.assertEqual(self.run_cli("rm", entries[0]["id"])[0], 0)
        self.assertEqual(self.run_cli(), (0, "hello world"))

    def test_watch_prints_changes(self):
        out = io.StringIO()
        port, token = cmd_clip.locate("pt", self.state_dir, self.token_file)
        t = threading.Thread(target=cmd_clip.watch, args=(port, token, out),
                             kwargs={"max_events": 1}, daemon=True)
        t.start()
        time.sleep(0.4)
        self.store.add("watched", "desktop")
        self.hub.bump("clip")
        t.join(5)
        self.assertEqual(out.getvalue(), "watched\n")

    def test_not_running_and_bad_token(self):
        code = cmd_clip.main(["--name", "missing"], out=io.StringIO(),
                             state_dir=self.state_dir, token_file=self.token_file)
        self.assertEqual(code, 1)
        with open(self.token_file, "w") as f:
            f.write("wrong")
        self.assertEqual(self.run_cli()[0], 1)


class DeviceKeyTests(ServerCase):
    """iOS Shortcut keys: write-only, /share only, hashed, revocable, limited."""

    def make_key(self, label="My iPhone"):
        r, d = self.jpost("/api/keys", {"label": label})
        self.assertEqual(r.status, 201, d)
        return json.loads(d)

    def share(self, key, fields=(("text", "from the shortcut"),), files=(), header="bearer",
              **kw):
        body, ctype = multipart(fields, files)
        h = {"Authorization": f"Bearer {key}"} if header == "bearer" else \
            {"X-Porch-Share-Key": key}
        return self.req("POST", "/share", body, ctype=ctype, origin=False, headers=h, **kw)

    def test_create_list_and_hashed_at_rest(self):
        k = self.make_key()
        self.assertTrue(k["key"].startswith("pks_"))
        r, d = self.owner("GET", "/api/keys")
        listing = json.loads(d)
        self.assertEqual([e["label"] for e in listing], ["My iPhone"])
        self.assertNotIn("key", listing[0])
        self.assertNotIn("sha256", listing[0])
        path = os.path.join(self.base, ".share-keys.json")
        raw = open(path).read()
        self.assertNotIn(k["key"], raw)
        self.assertIn(hashlib.sha256(k["key"].encode()).hexdigest(), raw)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_key_shares_text_and_files_as_json(self):
        k = self.make_key()
        r, d = self.share(k["key"], fields=[("text", "https://example.com/z")],
                          files=[("IMG_1.jpg", b"J" * 500)])
        self.assertEqual(r.status, 200, d)
        j = json.loads(d)
        self.assertEqual(j["message"], "Got 1 file and a clip.")
        self.assertEqual(os.listdir(self.inbox), ["IMG_1.jpg"])
        cur = self.store.snapshot()["current"]
        self.assertEqual((cur["text"], cur["source"]), ("https://example.com/z", "My iPhone"))
        self.assertEqual(self.share(k["key"], header="x")[0].status, 200)
        r, d = self.owner("GET", "/api/keys")
        self.assertEqual(json.loads(d)[0]["uses"], 2)

    def test_key_grants_nothing_but_share(self):
        k = self.make_key()
        auth = {"Authorization": f"Bearer {k['key']}"}
        for method, path in GATED:
            if path == "/share":
                continue
            r, _ = self.req(method, path, origin=False, headers=auth)
            self.assertIn(r.status, (403,), (method, path))
            r, _ = self.req(method, path, origin=True, headers={"X-Porch-Share-Key": k["key"]})
            self.assertIn(r.status, (403,), (method, path))
        # not the inbox, not tus, not the key API (it can't mint more keys)
        open(os.path.join(self.inbox, "secret.txt"), "w").write("s")
        self.assertEqual(self.req("GET", "/inbox/secret.txt", origin=False, headers=auth)[0].status, 403)
        r, _ = self.req("POST", "/tus/", origin=True,
                        headers=dict(auth, **{"Tus-Resumable": "1.0.0", "Upload-Length": "5"}))
        self.assertEqual(r.status, 403)

    def test_wrong_and_malformed_keys_are_401_then_rate_limited(self):
        k = self.make_key()
        for bad in ("pks_" + "A" * 43, "nonsense", "pks_short"):
            r, d = self.share(bad)
            self.assertEqual(r.status, 401, bad)
        # key_fail is 3 per window: now even the right key waits
        r, _ = self.share(k["key"])
        self.assertEqual(r.status, 429)
        self.assertEqual(self.store.snapshot()["current"], None)

    def test_per_key_rate_limit(self):
        k = self.make_key()
        for i in range(5):
            self.assertEqual(self.share(k["key"], fields=[("text", f"n{i}")])[0].status, 200)
        r, _ = self.share(k["key"], fields=[("text", "one too many")])
        self.assertEqual(r.status, 429)
        k2 = self.make_key("iPad")                # another key has its own budget
        self.assertEqual(self.share(k2["key"])[0].status, 200)

    def test_rotate_and_revoke(self):
        k = self.make_key()
        r, d = self.jpost(f"/api/keys/{k['id']}/rotate", {})
        self.assertEqual(r.status, 200)
        k2 = json.loads(d)
        self.assertEqual((k2["id"], k2["label"]), (k["id"], k["label"]))
        self.assertNotEqual(k2["key"], k["key"])
        self.assertEqual(self.share(k["key"])[0].status, 401)
        self.assertEqual(self.share(k2["key"])[0].status, 200)
        r, d = self.jpost(f"/api/keys/{k['id']}/delete", {})
        self.assertEqual((r.status, json.loads(d)), (200, []))
        self.assertEqual(self.share(k2["key"])[0].status, 401)
        self.assertEqual(self.jpost(f"/api/keys/{k['id']}/delete", {})[0].status, 404)

    def test_key_management_is_owner_page_only(self):
        # no Origin: refused; CLI token: refused; guest: refused
        r, _ = self.owner("POST", "/api/keys", b"{}", ctype="application/json", origin=False)
        self.assertEqual(r.status, 403)
        self.assertEqual(self.cli("POST", "/api/keys", {"label": "x"})[0].status, 403)
        self.assertEqual(self.cli("GET", "/api/keys")[0].status, 403)
        r, _ = self.req("POST", "/api/keys", b"{}", token=GUEST_TOKEN, ctype="application/json")
        self.assertEqual(r.status, 403)

    def test_key_cap_and_label_cleaning(self):
        self.H.keys.max_keys = 2
        self.assertEqual(self.make_key("a\u0000b\n  c" + "x" * 80)["label"], "a b c" + "x" * 35)
        self.make_key("two")
        r, d = self.jpost("/api/keys", {"label": "three"})
        self.assertEqual(r.status, 409)

    def test_key_is_never_logged(self):
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            k = self.make_key()
            self.share(k["key"])
            self.share(k["key"][:-1] + ("A" if k["key"][-1] != "A" else "B"))
            self.jpost(f"/api/keys/{k['id']}/rotate", {})
        log = buf.getvalue()
        self.assertIn("device key", log)
        self.assertNotIn(k["key"], log)
        self.assertNotIn(k["key"][4:20], log)

    def test_page_has_the_iphone_panel(self):
        r, d = self.owner("GET", "/", origin=False)
        bundle = app_bundle(d.decode())            # You > Share from iPhone
        self.assertIn("Share from iPhone", bundle)
        self.assertIn("Get Contents of URL", bundle)


class ServiceUnitTests(unittest.TestCase):
    """bin/pocket --install-service: the porch-pocket@.service user unit."""

    def test_render(self):
        u = ps.render_service_unit(repo_dir="/opt/porch", brand="Acme 100%")
        self.assertIn("ExecStart=/bin/bash /opt/porch/bin/pocket %i --expires never\n", u)
        self.assertNotIn("--bg", [l for l in u.splitlines() if l.startswith("ExecStart")][0])
        self.assertIn("Restart=on-failure\n", u)
        self.assertIn("WorkingDirectory=/opt/porch\n", u)
        self.assertIn("WantedBy=default.target", u)
        self.assertIn("StartLimitIntervalSec=0", u)
        self.assertIn("Acme 100%%", u)               # a literal %, not a specifier
        self.assertNotIn("${", u)

    def test_live_checkout_renders(self):
        u = ps.render_service_unit()
        self.assertIn(os.path.join(ps.REPO_DIR, "bin", "pocket"), u)

    def test_refuses_paths_and_names_that_do_not_fit(self):
        with self.assertRaises(ValueError):
            ps.render_service_unit(repo_dir="/home/me/my porch")
        for bad in ("", "Pocket", "../x", "a b", "-x", "x" * 42):
            with self.assertRaises(ValueError):
                ps.unit_name(bad)
        self.assertEqual(ps.unit_name("work-2"), "porch-pocket@work-2.service")

    def test_install_and_uninstall_with_a_fake_systemctl(self):
        tmp = tempfile.mkdtemp(prefix="porch-unit-")
        calls = []
        saved = (os.environ.get("XDG_CONFIG_HOME"), ps._systemctl, ps.subprocess.run)

        class R:
            returncode, stdout, stderr = 0, "Linger=yes", ""
        try:
            os.environ["XDG_CONFIG_HOME"] = tmp
            ps._systemctl = lambda *a, check=True: calls.append(a) or R()
            ps.subprocess.run = lambda *a, **k: R()
            with contextlib_redirect():
                self.assertEqual(ps.install_service("pocket"), "porch-pocket@pocket.service")
            path = os.path.join(tmp, "systemd", "user", "porch-pocket@.service")
            self.assertEqual(open(path).read(), ps.render_service_unit())
            self.assertEqual(calls, [("daemon-reload",), ("enable", "porch-pocket@pocket.service"),
                                     ("restart", "porch-pocket@pocket.service")])
            calls.clear()
            with contextlib_redirect():
                ps.uninstall_service("pocket")
            self.assertIn(("disable", "--now", "porch-pocket@pocket.service"), calls)
            self.assertFalse(os.path.exists(path))
        finally:
            if saved[0] is None:
                os.environ.pop("XDG_CONFIG_HOME", None)
            else:
                os.environ["XDG_CONFIG_HOME"] = saved[0]
            ps._systemctl, ps.subprocess.run = saved[1], saved[2]
            shutil.rmtree(tmp, ignore_errors=True)


# ---- Make link, the links panel, sealed uploads ------------------------------

def sealed_blob(content_len=100, filler=None):
    """Bytes shaped like a porch-seal v1 file: the magic + version byte, then
    anything, at a length the format allows (48 + 4112 + one record)."""
    total = 48 + 4112 + content_len + 16
    head = b"PSEAL1\n\x00\x01"
    body = filler if filler is not None else os.urandom(total - len(head))
    return (head + body)[:total].ljust(total, b"\0")


class FakeLauncher:
    """Stands in for bin/porch share / bin/seal: records the call and, like a
    real --bg launcher, leaves a door state file behind."""

    def __init__(self, state_dir):
        self.state_dir = state_dir
        self.calls = []
        self.rc, self.out, self.err = 0, "", ""
        self.timeout = False
        self.make_state = True

    @staticmethod
    def name_of(argv):
        return argv[argv.index("--name") + 1] if "--name" in argv else argv[2]

    def __call__(self, argv, env, data, timeout):
        self.calls.append({"argv": list(argv), "env": dict(env), "data": data, "timeout": timeout})
        name = self.name_of(argv)
        if self.make_state:
            rules = {}
            if "--guest-link" in argv:
                rules["guest"] = "G" * 24
            if "--password" in argv:
                rules["password"] = "scrypt$16384$8$1$c2FsdA$aGFzaA"
            if "--burn" in argv:
                rules["max_opens"] = 1
            elif "--max-opens" in argv:
                rules["max_opens"] = int(argv[argv.index("--max-opens") + 1])
            exp = argv[argv.index("--expires") + 1]
            expires = None if exp == "never" else int(time.time()) + {"1h": 3600, "24h": 86400, "7d": 604800}[exp]
            st = {"name": name, "type": "seal" if argv[0].endswith("seal") else "view",
                  "pid": os.getpid(), "port": 1, "started": int(time.time()), "expires": expires,
                  "keep_alive": expires is None, "rules": rules, "opens": 0, "last_open": None}
            with open(os.path.join(self.state_dir, name + ".json"), "w") as f:
                json.dump(st, f)
        if self.timeout:
            raise ps.LinkTimeout()
        return self.rc, self.out, self.err


class LinkCase(ServerCase):

    def handler_attrs(self):
        self.state_dir = os.path.join(self.tmp, "state")
        os.makedirs(self.state_dir)
        self.launcher = FakeLauncher(self.state_dir)
        self.closed = []

        def closer(name):
            self.closed.append(name)
            for fn in (name + ".json",):
                try:
                    os.unlink(os.path.join(self.state_dir, fn))
                except OSError:
                    pass
        return {"state_dir": self.state_dir, "link_runner": staticmethod(self.launcher),
                "link_closer": staticmethod(closer), "max_links": 3, "pocket_name": "pocket",
                "link_lock": threading.Lock()}

    def put_inbox(self, name="photo.jpg", data=b"\xff\xd8\xff" + b"x" * 50):
        with open(os.path.join(self.inbox, name), "wb") as f:
            f.write(data)
        return os.path.join(self.inbox, name)

    def make(self, body, **kw):
        r, d = self.jpost("/api/links", body, **kw)
        return r, json.loads(d or b"{}")


class MakeLinkTests(LinkCase):

    def test_owner_page_only(self):
        self.put_inbox()
        body = json.dumps({"kind": "inbox", "id": "photo.jpg"}).encode()
        r, _ = self.req("POST", "/api/links", body, token=GUEST_TOKEN, ctype="application/json")
        self.assertEqual(r.status, 403)
        r, _ = self.owner("POST", "/api/links", body, ctype="application/json", origin=False)
        self.assertEqual(r.status, 403)
        r, _ = self.owner("POST", "/api/links", body, ctype="application/json", origin=False,
                          headers={"Origin": "https://evil.example"})
        self.assertEqual(r.status, 403)
        r, _ = self.cli("POST", "/api/links", {"kind": "inbox", "id": "photo.jpg"})
        self.assertEqual(r.status, 403)
        r, _ = self.cli("GET", "/api/links")
        self.assertEqual(r.status, 403)
        r, _ = self.req("GET", "/api/links", token=GUEST_TOKEN)
        self.assertEqual(r.status, 403)
        self.assertEqual(self.launcher.calls, [])

    def test_inbox_link_argv_and_env(self):
        path = self.put_inbox("Holiday-Photo.jpg")
        os.environ["_CUSH_DAEMONIZED"] = "1"           # what a --bg pocket inherits
        os.environ["_PORCH_DOOR_SPEC"] = "{}"
        try:
            r, j = self.make({"kind": "inbox", "id": "Holiday-Photo.jpg",
                              "rules": {"expires": "7d", "password": "hunter22", "burn": True,
                                        "guest": True}})
        finally:
            os.environ.pop("_CUSH_DAEMONIZED", None)
            os.environ.pop("_PORCH_DOOR_SPEC", None)
        self.assertEqual(r.status, 201, j)
        call = self.launcher.calls[0]
        argv, env = call["argv"], call["env"]
        self.assertTrue(argv[0].endswith("/bin/porch"))
        self.assertEqual(argv[1:3], ["share", os.path.realpath(path)])
        name = argv[argv.index("--name") + 1]
        self.assertRegex(name, r"^pk-holiday-photo-[0-9a-f]{4}$")
        for flag in ("--password", "--burn", "--guest-link", "--bg"):
            self.assertIn(flag, argv)
        self.assertEqual(argv[argv.index("--expires") + 1], "7d")
        self.assertFalse(any("hunter22" in a for a in argv))
        self.assertEqual(env["PORCH_DOOR_PASSWORD"], "hunter22")
        for k in ps.LAUNCHER_ENV_DROP[:-1]:
            self.assertNotIn(k, env)
        self.assertIsNone(call["data"])
        self.assertEqual(j["name"], name)
        self.assertEqual(j["url"], f"https://{name}.tunnel.cush.rocks/")
        self.assertEqual(j["guest_url"], f"https://{name}.tunnel.cush.rocks/?k=" + "G" * 24)
        self.assertAlmostEqual(j["expires"], time.time() + 604800, delta=30)
        with open(os.path.join(self.state_dir, name + ".json")) as f:
            tag = json.load(f)["pocket"]
        self.assertEqual(tag, {"name": "pocket", "kind": "inbox", "label": "Holiday-Photo.jpg"})
        self.assertGreater(self.hub.versions["links"], 0)

    def test_no_password_means_no_env(self):
        self.put_inbox()
        r, j = self.make({"kind": "inbox", "id": "photo.jpg", "rules": {"expires": "1h"}})
        self.assertEqual(r.status, 201, j)
        call = self.launcher.calls[0]
        self.assertNotIn("PORCH_DOOR_PASSWORD", call["env"])
        self.assertNotIn("--password", call["argv"])
        self.assertIsNone(j["guest_url"])

    def test_clip_goes_through_stdin(self):
        secret_text = "the door code is 4711, see you at 8"
        entry = self.store.add(secret_text, "phone")
        r, j = self.make({"kind": "clip", "id": entry["id"], "rules": {"expires": "never",
                                                                       "max_opens": 5}})
        self.assertEqual(r.status, 201, j)
        call = self.launcher.calls[0]
        self.assertEqual(call["argv"][1:3], ["share", "-"])
        self.assertEqual(call["data"], secret_text.encode())
        self.assertFalse(any("4711" in a for a in call["argv"]))
        self.assertEqual(call["argv"][call["argv"].index("--max-opens") + 1], "5")
        self.assertRegex(j["name"], r"^pk-clip-[0-9a-f]{4}$")
        self.assertIsNone(j["expires"])

    def test_validation(self):
        self.put_inbox()
        entry = self.store.add("hello", "phone")
        bad = [
            ({"kind": "disk", "id": "photo.jpg"}, 400),
            ({"kind": "inbox", "id": ""}, 400),
            ({"kind": "inbox", "id": 5}, 400),
            ({"kind": "inbox", "id": "../../etc/passwd"}, 404),
            ({"kind": "inbox", "id": "missing.jpg"}, 404),
            ({"kind": "clip", "id": "nope!"}, 404),
            ({"kind": "clip", "id": "abcdefghij"}, 404),
            ({"kind": "sealed", "id": "x.pseal"}, 404),
            ({"kind": "inbox", "id": "photo.jpg", "rules": {"expires": "2h"}}, 400),
            ({"kind": "inbox", "id": "photo.jpg", "rules": {"color": "red"}}, 400),
            ({"kind": "inbox", "id": "photo.jpg", "rules": {"password": "short"}}, 400),
            ({"kind": "inbox", "id": "photo.jpg", "rules": {"password": 123456}}, 400),
            ({"kind": "inbox", "id": "photo.jpg", "rules": {"max_opens": 0}}, 400),
            ({"kind": "inbox", "id": "photo.jpg", "rules": {"max_opens": True}}, 400),
            ({"kind": "inbox", "id": "photo.jpg", "rules": {"max_opens": 1001}}, 400),
            ({"kind": "inbox", "id": "photo.jpg", "rules": {"burn": "yes"}}, 400),
            ({"kind": "inbox", "id": "photo.jpg", "rules": {"guest": 1}}, 400),
            ({"kind": "inbox", "id": "photo.jpg", "rules": []}, 400),
            ({"kind": "inbox", "id": "photo.jpg", "name": "evil;rm -rf"}, 400),
            ({"kind": "inbox", "id": "photo.jpg", "name": "pocket"}, 400),
            ({"kind": "inbox", "id": "photo.jpg", "name": "pk-"}, 400),
            ({"kind": "clip", "id": entry["id"], "name": "pk-x-"}, 400),
        ]
        for body, status in bad:
            r, j = self.make(body)
            self.assertEqual(r.status, status, (body, j))
        r, _ = self.owner("POST", "/api/links", b"not json", ctype="application/json")
        self.assertEqual(r.status, 400)
        self.assertEqual(self.launcher.calls, [])
        r, j = self.make({"kind": "inbox", "id": "photo.jpg", "name": "pk-my-photo"})
        self.assertEqual((r.status, j["name"]), (201, "pk-my-photo"))
        r, j = self.make({"kind": "inbox", "id": "photo.jpg", "name": "pk-my-photo"})
        self.assertEqual(r.status, 409)                 # that door is open already

    def test_cap_counts_live_doors(self):
        self.put_inbox()
        for _ in range(3):
            r, j = self.make({"kind": "inbox", "id": "photo.jpg"})
            self.assertEqual(r.status, 201, j)
        r, j = self.make({"kind": "inbox", "id": "photo.jpg"})
        self.assertEqual(r.status, 409)
        self.assertIn("at most 3", j["message"])
        self.assertEqual(len(self.launcher.calls), 3)
        # A record whose launcher is gone does not hold a slot.
        name = json.loads(self.owner("GET", "/api/links")[1])[0]["name"]
        p = os.path.join(self.state_dir, name + ".json")
        st = json.load(open(p))
        st["pid"] = 2 ** 22 + 12345
        json.dump(st, open(p, "w"))
        r, j = self.make({"kind": "inbox", "id": "photo.jpg"})
        self.assertEqual(r.status, 201, j)

    def test_timeout_closes_the_door(self):
        self.put_inbox()
        self.launcher.timeout = True
        r, j = self.make({"kind": "inbox", "id": "photo.jpg"})
        self.assertEqual(r.status, 504)
        name = self.launcher.name_of(self.launcher.calls[0]["argv"])
        self.assertEqual(self.closed, [name])
        self.assertFalse(os.path.exists(os.path.join(self.state_dir, name + ".json")))

    def test_launcher_failure_closes_a_half_open_door(self):
        self.put_inbox()
        self.launcher.rc, self.launcher.err = 1, "porch share: \x1b[31mboom\x1b[0m\n"
        r, j = self.make({"kind": "inbox", "id": "photo.jpg"})
        self.assertEqual(r.status, 502)
        self.assertIn("boom", j["message"])
        self.assertNotIn("\x1b", j["message"])
        self.assertEqual(len(self.closed), 1)
        # No state at all after the launch: also a failure, and closed.
        self.launcher.rc, self.launcher.make_state = 0, False
        r, j = self.make({"kind": "inbox", "id": "photo.jpg"})
        self.assertEqual(r.status, 502)
        self.assertEqual(len(self.closed), 2)

    def test_run_launcher_kills_on_timeout(self):
        t0 = time.time()
        with self.assertRaises(ps.LinkTimeout):
            ps.run_launcher(["sleep", "30"], ps.launcher_env(), None, 0.5)
        self.assertLess(time.time() - t0, 10)
        rc, out, err = ps.run_launcher(["cat"], ps.launcher_env(), b"via stdin", 10)
        self.assertEqual((rc, out), (0, "via stdin"))

    def test_launcher_env_drops_daemon_markers(self):
        env = ps.launcher_env("pw123456", base={"PATH": "/bin", "_CUSH_DAEMONIZED": "1",
                                                "CUSH_LOG_FILE": "x", "TUNNEL_NO_STATE": "1",
                                                "_PORCH_DOOR_SPEC": "{}",
                                                "PORCH_DOOR_PASSWORD": "old"})
        self.assertEqual(env, {"PATH": "/bin", "PORCH_DOOR_PASSWORD": "pw123456"})


class LinksPanelTests(LinkCase):

    def test_list_and_actions(self):
        self.put_inbox()
        r, made = self.make({"kind": "inbox", "id": "photo.jpg",
                             "rules": {"expires": "1h", "password": "hunter22", "guest": True}})
        self.assertEqual(r.status, 201)
        name = made["name"]
        # Doors this pocket did not make are neither listed nor touchable.
        for other, tag in (("pk-other-1a2b", {"name": "work", "kind": "inbox"}), ("plain", None)):
            st = {"name": other, "type": "view", "pid": os.getpid(), "expires": None}
            if tag:
                st["pocket"] = tag
            json.dump(st, open(os.path.join(self.state_dir, other + ".json"), "w"))
        r, d = self.owner("GET", "/api/links")
        links = json.loads(d)
        self.assertEqual([l["name"] for l in links], [name])
        l = links[0]
        self.assertEqual(l["rules"], {"password": True, "guest_link": True, "max_opens": None})
        self.assertEqual((l["kind"], l["label"], l["opens"], l["alive"]), ("inbox", "photo.jpg", 0, True))
        self.assertNotIn(b"scrypt", d)
        before = l["expires"]
        r, d = self.jpost(f"/api/links/{name}/extend", {})
        self.assertEqual(r.status, 200)
        self.assertEqual(json.loads(d)[0]["expires"], before + 3600)
        r, d = self.jpost(f"/api/links/{name}/never", {})
        self.assertIsNone(json.loads(d)[0]["expires"])
        for bad in ("pk-other-1a2b", "plain", "..%2f..", "PK-UP"):
            r, _ = self.jpost(f"/api/links/{bad}/close", {})
            self.assertEqual(r.status, 404, bad)
        r, _ = self.jpost(f"/api/links/{name}/explode", {})
        self.assertEqual(r.status, 404)
        r, _ = self.owner("POST", f"/api/links/{name}/close", b"{}", ctype="application/json",
                          origin=False)
        self.assertEqual(r.status, 403)
        r, _ = self.req("POST", f"/api/links/{name}/close", b"{}", token=GUEST_TOKEN)
        self.assertEqual(r.status, 403)
        self.assertEqual(self.closed, [])
        r, d = self.jpost(f"/api/links/{name}/close", {})
        self.assertEqual((r.status, json.loads(d)), (200, []))
        self.assertEqual(self.closed, [name])

    def test_events_carry_links(self):
        self.put_inbox()
        self.make({"kind": "inbox", "id": "photo.jpg"})
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("GET", "/api/events", headers={"Cookie": f"cush_auth={OWNER_TOKEN}"})
        r = c.getresponse()
        buf = b""
        while b"event: links" not in buf or not buf.endswith(b"\n\n"):
            buf += r.fp.read1(65536)
        c.close()
        line = [x for x in buf.split(b"\n\n") if b"event: links" in x][0]
        data = json.loads(line.split(b"data: ", 1)[1])
        self.assertEqual(len(data), 1)
        self.assertTrue(data[0]["name"].startswith("pk-photo-"))


class SealedTests(LinkCase):

    def tus_create(self, length, meta="sealed MQ==", **kw):
        h = {"Tus-Resumable": "1.0.0", "Upload-Length": str(length)}
        if meta is not None:
            h["Upload-Metadata"] = meta
        return self.owner("POST", "/tus-sealed/", headers=h, **kw)

    def tus_patch(self, loc, data, offset=0):
        return self.owner("PATCH", loc, data, ctype="application/offset+octet-stream",
                          headers={"Tus-Resumable": "1.0.0", "Upload-Offset": str(offset)})

    def upload(self, blob):
        r, _ = self.tus_create(len(blob))
        self.assertEqual(r.status, 201)
        loc = r.getheader("Location")
        self.assertTrue(loc.startswith("/tus-sealed/"))
        mid = len(blob) // 2
        r, _ = self.tus_patch(loc, blob[:mid])
        self.assertEqual(r.status, 204)
        r, _ = self.tus_patch(loc, blob[mid:], mid)
        self.assertEqual(r.status, 204)
        return r.getheader("Porch-Upload-Name")

    def test_ciphertext_is_stored_byte_exact_and_never_sniffed(self):
        # After the magic: bytes that would sniff as a JPEG and as HTML.
        filler = b"\xff\xd8\xff\xe0<html><script>x</script>" + os.urandom(5000)
        blob = sealed_blob(4000, filler)
        name = self.upload(blob)
        self.assertRegex(name, r"^[A-Za-z0-9_-]{22}\.pseal$")
        path = os.path.join(self.base, "sealed", name)
        with open(path, "rb") as f:
            self.assertEqual(f.read(), blob)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(os.path.dirname(path)).st_mode & 0o777, 0o700)
        r, d = self.owner("GET", "/api/inbox")
        self.assertEqual(json.loads(d), [])               # not an inbox file
        r, _ = self.owner("GET", "/inbox/" + name)
        self.assertEqual(r.status, 404)

    def test_refusals(self):
        blob = sealed_blob()
        r, d = self.tus_create(len(blob), meta=None)       # no sealed=1
        self.assertEqual(r.status, 400)
        r, d = self.tus_create(len(blob), meta="filename eC5qcGc=")
        self.assertEqual(r.status, 400)
        r, d = self.tus_create(4160 + 10)                  # no such ciphertext length
        self.assertEqual(r.status, 400)
        r, d = self.tus_create(100)
        self.assertEqual(r.status, 400)
        r, _ = self.tus_create(len(blob), origin=False)
        self.assertEqual(r.status, 403)
        r, _ = self.req("POST", "/tus-sealed/", headers={"Tus-Resumable": "1.0.0",
                                                         "Upload-Length": str(len(blob)),
                                                         "Upload-Metadata": "sealed MQ=="},
                        token=GUEST_TOKEN)
        self.assertEqual(r.status, 403)
        # A first chunk without the porch-seal magic is refused and dropped.
        r, _ = self.tus_create(len(blob))
        loc = r.getheader("Location")
        r, d = self.tus_patch(loc, b"\x89PNG\r\n\x1a\n" + blob[8:200])
        self.assertEqual(r.status, 415)
        self.assertIn(b"porch-seal", d)
        left = [n for n in os.listdir(os.path.join(self.base, "sealed")) if not n.startswith(".")]
        self.assertEqual(left, [])
        self.assertEqual(os.listdir(os.path.join(self.base, "sealed", ".tus")), [])

    def test_sealed_blobs_count_toward_the_quota(self):
        os.makedirs(os.path.join(self.base, "sealed"), exist_ok=True)
        with open(os.path.join(self.base, "sealed", "A" * 22 + ".pseal"), "wb") as f:
            f.write(b"\0" * (3 * 1024 * 1024 + 512 * 1024))
        body, ctype = multipart([], [("big.bin", b"B" * (700 * 1024))])
        r, d = self.owner("POST", "/share", body, ctype=ctype, headers={"X-Porch-Fetch": "1"})
        self.assertEqual(r.status, 413, d)
        self.assertIn(b"full", d)

    def test_sealed_link_runs_bin_seal_without_a_key(self):
        name = self.upload(sealed_blob())
        r, j = self.make({"kind": "sealed", "id": name, "rules": {"expires": "24h", "burn": True}})
        self.assertEqual(r.status, 201, j)
        argv = self.launcher.calls[0]["argv"]
        sealed_dir = os.path.join(self.base, "sealed")
        self.assertTrue(argv[0].endswith("/bin/seal"))
        self.assertEqual(argv[1], os.path.join(sealed_dir, name))
        self.assertRegex(argv[2], r"^pk-file-[0-9a-f]{4}$")
        self.assertIn("--owned-file", argv)            # bin/seal deletes it when the door closes
        self.assertEqual(argv[argv.index("--owned-dir") + 1], sealed_dir)
        self.assertEqual(argv[-1], "--bg")
        self.assertIn("--burn", argv)
        self.assertNotIn("#", j["url"])
        self.assertEqual(j["kind"], "sealed")
        with open(os.path.join(self.state_dir, j["name"] + ".json")) as f:
            self.assertEqual(json.load(f)["pocket"]["item"], name)
        # A password for a sealed link is the seal's, never a door gate here.
        r, j = self.make({"kind": "sealed", "id": "../" + name})
        self.assertEqual(r.status, 404)

    def test_orphans_are_swept_owned_ones_kept(self):
        owned = self.upload(sealed_blob())
        r, j = self.make({"kind": "sealed", "id": owned})
        self.assertEqual(r.status, 201)
        orphan = self.upload(sealed_blob())
        fresh = self.upload(sealed_blob())
        d = os.path.join(self.base, "sealed")
        old = time.time() - 2 * ps.SEALED_ORPHAN_AGE
        for n in (owned, orphan):
            os.utime(os.path.join(d, n), (old, old))
        self.owner("GET", "/api/links")
        left = sorted(n for n in os.listdir(d) if not n.startswith("."))
        self.assertEqual(left, sorted([owned, fresh]))

    def test_no_key_in_any_log_line(self):
        """The page keeps the key (#k=...) to itself. Run the whole server
        side of Send encrypted with a password-gated, guest-linked inbox link
        alongside, and check that no key, password or token is ever logged."""
        import contextlib
        key = "kR3y" + "x" * 39                          # what the page would hold
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            name = self.upload(sealed_blob())
            r, j = self.make({"kind": "sealed", "id": name, "rules": {"guest": True}})
            self.assertEqual(r.status, 201)
            link = j["url"] + "#k=" + key                 # built in the browser
            self.put_inbox()
            r, j2 = self.make({"kind": "inbox", "id": "photo.jpg",
                               "rules": {"password": "hunter22", "guest": True}})
            self.owner("GET", "/api/links")
            self.jpost(f"/api/links/{j2['name']}/close", {})
        log = buf.getvalue()
        self.assertIn("link pk-", log)
        for secret in (key, link, "#k=", "hunter22", "G" * 24):
            self.assertNotIn(secret, log)
        for call in self.launcher.calls:
            blob = json.dumps(call["argv"]) + json.dumps(
                {k: v for k, v in call["env"].items() if k != "PORCH_DOOR_PASSWORD"})
            self.assertNotIn("#k=", blob)
            self.assertNotIn("hunter22", blob)


class PageLinkUiTests(ServerCase):

    def test_page_has_the_sheet_links_and_seal_script(self):
        r, body = self.owner("GET", "/", origin=False)
        page = app_bundle(body.decode())
        for needle in ('id="sheet"', 'id="links"', 'id="sealBtn"', 'id="expChips"',
                       'src="/static/seal.js"', "navigator.share", "PorchQR", "/tus-sealed/",
                       "sealed ' + btoa('1')"):
            self.assertIn(needle, page)
        csp = r.getheader("Content-Security-Policy")
        self.assertIn("script-src 'self' 'nonce-", csp)
        # The key is joined to the URL in the page and goes into no request.
        self.assertIn("res.url + '#k=' + sealer.key", page)

    def test_pickers_are_native_label_activated_inputs(self):
        _, body = self.owner("GET", "/", origin=False)
        page = body.decode()
        mobile_markup.check_pickers(self, page, multiple=("fileInput", "photoInput"),
                                    single=("sealInput", "sealPhotoInput"))
        # Android opens its photo picker only for an image/video-only input
        self.assertIn('id="photoInput" class="upload-input" accept="image/*,video/*" multiple', page)
        self.assertIn('id="sealPhotoInput" class="upload-input" accept="image/*,video/*">', page)
        mobile_markup.check_responsive(self, page)

    def test_sheet_fits_a_phone(self):
        _, body = self.owner("GET", "/", origin=False)
        page = body.decode()
        mobile_markup.check_responsive(self, page)
        css = ps.pocket_assets.lookup(ps.pocket_assets.asset_url("app.css"))[0].decode()
        self.assertIn(ps.pocket_assets.asset_url("app.css"), page)
        self.assertIn("viewport-fit=cover", page)
        self.assertIn("max-height:calc(100dvh - env(safe-area-inset-top)", css)
        self.assertIn("overflow-y:auto", css)
        self.assertRegex(css, r"\.sheet-foot\{[^}]*position:sticky;bottom:0")
        self.assertRegex(css, r"\.sheet-foot\{[^}]*env\(safe-area-inset-bottom\)|--sheet-b:env\(safe-area-inset-bottom\)")
        self.assertIn(".chip{min-height:44px", css)
        # Both panes end in the sticky row; progress and errors ride in it.
        self.assertGreaterEqual(page.count('<div class="sheet-foot"'), 2)
        foot = page.index('<div class="sheet-foot">')
        self.assertLess(foot, page.index('id="sealProg"'))
        self.assertLess(foot, page.index('id="sheetErr"'))

    def test_seal_js_is_served_to_the_owner(self):
        if not os.path.exists(ps.STATIC_JS["/static/seal.js"]):
            self.skipTest("lib/seal.js is not there yet")
        r, d = self.owner("GET", "/static/seal.js")
        self.assertEqual(r.status, 200)
        self.assertTrue(r.getheader("Content-Type").startswith("text/javascript"))
        self.assertIn(b"PorchSeal", d)
        r, _ = self.req("GET", "/static/seal.js", token=GUEST_TOKEN)
        self.assertEqual(r.status, 403)

    def test_hashed_static_assets(self):
        """lib/pocket_assets.py: every script in lib/pocket_static/ (and the tus
        client) at a content-hashed path, owner-only, immutable; nothing else."""
        import pocket_assets
        for name, src in (("qr.js", ps.QR_CLIENT_JS), ("share.js", ps.LINKS_CLIENT_JS),
                          ("tus.js", ps.porch_tus.TUS_CLIENT_JS)):
            path = pocket_assets.asset_url(name)
            self.assertRegex(path, r"^/static/[a-z]+\.[0-9a-f]{12}\.js$")
            r, d = self.owner("GET", path)
            self.assertEqual(r.status, 200)
            self.assertEqual(d.decode(), src)
            self.assertIn("immutable", r.getheader("Cache-Control"))
            self.assertTrue(r.getheader("Content-Type").startswith("text/javascript"))
            self.assertEqual(self.req("GET", path, token=GUEST_TOKEN)[0].status, 403)
        for bad in ("/static/qr.000000000000.js", "/static/legacy.html", "/static/sw.js",
                    "/static/../pocketserver.py"):
            self.assertEqual(self.owner("GET", bad)[0].status, 404, bad)


class QrTests(unittest.TestCase):
    """PorchQR (in the page) must draw exactly what python-qrcode draws for
    the same text, error correction level and mask."""

    def test_matrices_match_python_qrcode(self):
        node = shutil.which("node")
        try:
            import qrcode
            from qrcode.util import QRData
        except ImportError:
            self.skipTest("python-qrcode is not installed")
        if not node:
            self.skipTest("node is not installed")
        import random
        import string
        import subprocess
        rnd = random.Random(5)
        cases = [("https://pk-photo-1a2b.tunnel.cush.rocks/#k=" + "A" * 43, "M", 2)]
        for n in (1, 17, 40, 77, 120, 200, 330):
            for ecl in "LMQH":
                text = "".join(rnd.choice(string.ascii_letters + string.digits + "-_/:.#=?é")
                               for _ in range(n))
                cases.append((text, ecl, rnd.randrange(8)))
        script = ps.QR_CLIENT_JS + r"""
const cases = JSON.parse(require('fs').readFileSync(0, 'utf8'));
console.log(JSON.stringify(cases.map(([t, e, k]) => {
  const q = PorchQR.matrix(t, {ecl: e, mask: k});
  return [q.version, q.rows.map(r => r.map(b => b ? 1 : 0).join(''))];
})));"""
        out = subprocess.run([node, "-e", script], input=json.dumps(cases), capture_output=True,
                             text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        got = json.loads(out.stdout)
        ec = {"L": qrcode.constants.ERROR_CORRECT_L, "M": qrcode.constants.ERROR_CORRECT_M,
              "Q": qrcode.constants.ERROR_CORRECT_Q, "H": qrcode.constants.ERROR_CORRECT_H}
        mode = getattr(qrcode.util, "MODE_8BIT_BYTE", None) or qrcode.util.MODE_8BIT
        for (text, e, k), (version, rows) in zip(cases, got):
            q = qrcode.QRCode(error_correction=ec[e], mask_pattern=k, border=0)
            q.add_data(QRData(text.encode(), mode=mode))
            q.make(fit=True)
            want = ["".join("1" if b else "0" for b in row) for row in q.get_matrix()]
            self.assertEqual((version, rows), (q.version, want), (len(text), e, k))


def contextlib_redirect():
    import contextlib
    return contextlib.redirect_stdout(io.StringIO())


if __name__ == "__main__":
    unittest.main()

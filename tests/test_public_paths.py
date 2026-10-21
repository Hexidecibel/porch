"""Public paths on gated apps (lib/authserver.py, bin/auth-admin public).

The auth-server side: validation, the two map files (prefix: map_beg,
exact: map_str), the admin routes and the CLI. The HAProxy side (the gate
fragments really letting a public path through and nothing else) is in
test_public_paths_haproxy.py. Same harness as test_authserver: temp data dir
and maps, FakeHaproxy for the admin socket.
"""

import os
import subprocess
import sys
import unittest

import test_authserver as ta

authserver = ta.authserver
HOST = "grab.cush.rocks"        # in ServerCase.PROTECTED
OTHER = "trendlab.cush.rocks"   # also gated


class ValidateTest(unittest.TestCase):
    GOOD = [
        ("/s/", "/s/"),
        ("/robots.txt", "/robots.txt"),
        ("/api/v1/hook", "/api/v1/hook"),
        ("/a-b_c.d~e/", "/a-b_c.d~e/"),
        ("/" + "a" * 127, "/" + "a" * 127),
    ]
    BAD = [
        "", "s/", "/", "//", "/s//x", "/s/../x", "/..", "/s/*", "/s?x", "/s#x",
        "/s/%2e", "/s x", "/s\\x", "/s;x", "/é", "/__porch/x", "/__porch-assets/",
        "/__PORCH/x", "/" + "a" * 128, "/s/\n", " /s/",
    ]

    def test_good_paths(self):
        for raw, want in self.GOOD:
            self.assertEqual(authserver.validate_public_path("Grab.Cush.Rocks", raw),
                             ("grab.cush.rocks", want), raw)

    def test_bad_paths(self):
        for raw in self.BAD:
            with self.assertRaises(ValueError, msg=repr(raw)):
                authserver.validate_public_path(HOST, raw)

    def test_bad_hosts(self):
        for host in ("", "cush.rocks", "a.b.cush.rocks", "evil.com", "x y.cush.rocks",
                     authserver.AUTH_HOST, None, 3):
            with self.assertRaises(ValueError, msg=repr(host)):
                authserver.validate_public_path(host, "/s/")

    def test_prefix_or_exact(self):
        self.assertTrue(authserver.public_path_is_prefix("/s/"))
        self.assertFalse(authserver.public_path_is_prefix("/s"))


class MapPairsTest(unittest.TestCase):
    def setUp(self):
        saved = authserver.log
        self.addCleanup(setattr, authserver, "log", saved)
        authserver.log = lambda m: None

    def test_prefix_exact_disabled_ungated_and_bad(self):
        entries = [
            {"id": "pp_00000001", "host": HOST, "path": "/s/", "enabled": True},
            {"id": "pp_00000002", "host": HOST, "path": "/robots.txt"},
            {"id": "pp_00000003", "host": HOST, "path": "/off/", "enabled": False},
            {"id": "pp_00000004", "host": "open.cush.rocks", "path": "/s/"},
            {"id": "pp_00000005", "host": HOST, "path": "/a b"},
            {"id": "bad id", "host": HOST, "path": "/x/"},
            {"id": "pp_00000006", "host": OTHER, "path": "/hook"},
            "junk",
        ]
        prefix, exact = authserver.public_map_pairs(entries, {HOST, OTHER})
        self.assertEqual(prefix, [(f"{HOST}/s/", "pp_00000001")])
        self.assertEqual(exact, [(f"{HOST}/robots.txt", "pp_00000002"),
                                 (f"{OTHER}/hook", "pp_00000006")])


class PublicPathsServerTest(ta.ServerCase):
    def setUp(self):
        super().setUp()
        self.hap = ta.FakeHaproxy([authserver.GRANTS_MAP, authserver.IDENTITY_MAP,
                                   authserver.PROTECTED_MAP, authserver.PUBLIC_MAP,
                                   authserver.PUBLIC_EXACT_MAP])
        authserver._haproxy_socket_cmd = self.hap

    def pp(self, **body):
        return self.req("POST", "/auth/admin/public-paths", body)

    def add(self, path="/s/", host=HOST, app="promo-studio", why="share links", **kw):
        return self.pp(action="add", host=host, path=path, app=app, why=why, **kw)

    def test_add_writes_the_right_map_and_pushes_after_protected(self):
        code, body, _ = self.add()
        self.assertEqual(code, 200, body)
        e = body["entry"]
        self.assertRegex(e["id"], r"^pp_[0-9a-f]{8}$")
        self.assertEqual((e["kind"], e["active"], e["created_by"]), ("prefix", True, "cli"))
        self.assertEqual(body["haproxy"], "ok")
        self.assertEqual(self.map_text(authserver.PUBLIC_MAP), f"{HOST}/s/ {e['id']}\n")
        self.assertEqual(self.map_text(authserver.PUBLIC_EXACT_MAP), "")
        self.assertEqual(self.hap.live[authserver.PUBLIC_MAP], {f"{HOST}/s/": e["id"]})
        # The first sync pushed every map: the public ones after protected.
        commits = [c.split(" ")[-1] for c in self.hap.commands if c.startswith("commit map")]
        self.assertLess(commits.index(authserver.PROTECTED_MAP),
                        commits.index(authserver.PUBLIC_MAP))
        # The empty exact map was swapped in too (prepare + commit, no adds).
        self.assertEqual(self.hap.live[authserver.PUBLIC_EXACT_MAP], {})

        code, body, _ = self.add(path="/robots.txt", by="pocket")
        self.assertEqual(code, 200)
        self.assertEqual(body["entry"]["kind"], "exact")
        self.assertEqual(body["entry"]["created_by"], "pocket")
        self.assertEqual(self.map_text(authserver.PUBLIC_EXACT_MAP),
                         f"{HOST}/robots.txt {body['entry']['id']}\n")
        self.assertNotIn("robots", self.map_text(authserver.PUBLIC_MAP))
        self.assertTrue(any("public path add" in m and "path=/robots.txt" in m
                            for m in self.logs))

    def test_refusals(self):
        self.assertEqual(self.add(path="/")[0], 400)
        self.assertEqual(self.add(path="/s/../x")[0], 400)
        self.assertEqual(self.add(path="/__porch/me")[0], 400)
        self.assertEqual(self.add(app="")[0], 400)
        self.assertEqual(self.add(app="x" * 41)[0], 400)
        self.assertEqual(self.add(why="x" * 121)[0], 400)
        self.assertEqual(self.add(why="line\nbreak")[0], 400)
        code, body, _ = self.add(host="open.cush.rocks")
        self.assertEqual(code, 409)
        self.assertIn("not gated", body["error"])
        self.assertEqual(self.add()[0], 200)
        self.assertEqual(self.add()[0], 409)          # duplicate
        self.assertEqual(self.pp(action="nope")[0], 400)
        self.assertEqual(self.pp(action="disable", id="pp_ffffffff")[0], 404)
        self.assertEqual(self.pp(action="disable", id="../x")[0], 400)
        # No CLI token, no session: nothing.
        self.assertEqual(self.req("GET", "/auth/admin/public-paths", cli=False)[0], 401)
        self.assertEqual(self.req("POST", "/auth/admin/public-paths",
                                  {"action": "add", "host": HOST, "path": "/z/", "app": "a"},
                                  cli=False)[0], 401)

    def test_limit(self):
        authserver.STATE["public_paths"] = [
            {"id": f"pp_{i:08x}", "host": HOST, "path": f"/p{i}/", "app": "a",
             "enabled": True} for i in range(authserver.PUBLIC_PATH_MAX)]
        code, body, _ = self.add(path="/one-more/")
        self.assertEqual(code, 409)
        self.assertIn("at most", body["error"])

    def test_off_on_remove(self):
        pid = self.add()[1]["entry"]["id"]
        code, body, _ = self.pp(action="disable", id=pid)
        self.assertEqual(code, 200)
        self.assertEqual((body["entry"]["enabled"], body["entry"]["inactive"]),
                         (False, "switched off"))
        self.assertEqual(self.map_text(authserver.PUBLIC_MAP), "")
        self.assertEqual(self.hap.live[authserver.PUBLIC_MAP], {})
        self.assertEqual(len(authserver.STATE["public_paths"]), 1)   # kept
        self.assertTrue(self.pp(action="enable", id=pid)[1]["entry"]["active"])
        self.assertIn(pid, self.map_text(authserver.PUBLIC_MAP))
        code, body, _ = self.pp(action="remove", id=pid)
        self.assertEqual((code, body["entry"], body["public_paths"]), (200, None, []))
        self.assertEqual(self.map_text(authserver.PUBLIC_MAP), "")
        self.assertEqual(authserver.STATE["public_paths"], [])

    def test_unprotecting_the_host_takes_it_out_of_the_map(self):
        pid = self.add()[1]["entry"]["id"]
        self.req("POST", "/auth/admin/apps", {"host": HOST, "action": "unprotect"})
        self.assertEqual(self.map_text(authserver.PUBLIC_MAP), "")
        items = self.req("GET", "/auth/admin/public-paths")[1]["public_paths"]
        self.assertEqual((items[0]["id"], items[0]["active"], items[0]["inactive"]),
                         (pid, False, "host not gated"))
        state = self.req("GET", "/auth/admin/state")[1]
        self.assertEqual(state["public_paths"][0]["inactive"], "host not gated")
        self.req("POST", "/auth/admin/apps", {"host": HOST, "action": "protect"})
        self.assertIn(pid, self.map_text(authserver.PUBLIC_MAP))

    def test_persisted_and_reloaded(self):
        pid = self.add()[1]["entry"]["id"]
        authserver.load_state(fatal=False)
        self.assertEqual(authserver.STATE["public_paths"][0]["id"], pid)
        self.assertTrue(authserver.STATE["public_paths"][0]["created_at"])

    def test_unknown_by_reads_as_cli(self):
        # The CLI token may say cli or pocket; anything else reads as cli.
        self.assertEqual(self.add(by="evil")[1]["entry"]["created_by"], "cli")


class PublicCliTest(ta.ServerCase):
    ADMIN = os.path.join(ta._HERE, "..", "bin", "auth-admin")

    def run_cli(self, *args):
        env = dict(os.environ, PORCH_AUTH_URL=f"http://127.0.0.1:{self.port}")
        return subprocess.run([sys.executable, self.ADMIN, *args, "--data", self.tmp.name],
                              capture_output=True, text=True, env=env, timeout=60)

    def test_add_ls_off_on_rm(self):
        r = self.run_cli("public", "add", HOST, "/s/", "--app", "promo-studio",
                         "--why", "share links")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"https://{HOST}/s/", r.stdout)
        pid = authserver.STATE["public_paths"][0]["id"]
        self.assertEqual(authserver.STATE["public_paths"][0]["created_by"], "cli")
        r = self.run_cli("public", "ls")
        self.assertIn(pid, r.stdout)
        self.assertIn("promo-studio", r.stdout)
        self.assertIn(f"https://{HOST}/s/*", r.stdout)
        r = self.run_cli("public", "off", pid)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(authserver.STATE["public_paths"][0]["enabled"])
        r = self.run_cli("public", "on", pid)
        self.assertIn("is public", r.stdout)
        r = self.run_cli("public", "add", HOST, "/", "--app", "x")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("whole site", r.stderr)
        r = self.run_cli("public", "rm", pid, "--yes")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(authserver.STATE["public_paths"], [])
        r = self.run_cli("public", "ls", "--json")
        self.assertEqual(r.stdout.strip(), "[]")


if __name__ == "__main__":
    unittest.main()

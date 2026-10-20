"""Tests for `porch mcp` (lib/porch_mcp.py, lib/porch_setup/cmd_mcp.py): the
JSON-RPC/MCP protocol, tool schemas, every tool's argv against a fake runner,
the sensitive-path refusals and secret hygiene.

Nothing is launched except the server process itself (protocol-only calls).
"""

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib")
sys.path.insert(0, LIB)

import porch_mcp  # noqa: E402

CMD_MCP = os.path.join(LIB, "porch_setup", "cmd_mcp.py")


class FakeRunner:
    """Records each call; answers by the first matching (needle, rc, out, err)."""

    def __init__(self, answers=()):
        self.calls = []
        self.answers = list(answers)

    def __call__(self, argv, stdin=None, env=None, tty_stdin=False, timeout=None):
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
        self.calls.append({"argv": argv, "stdin": stdin, "env": env, "tty": tty_stdin})
        joined = " ".join(argv)
        for needle, rc, out, err in self.answers:
            if needle in joined:
                return rc, out, err
        return 0, "", ""

    @property
    def last(self):
        return self.calls[-1]


def rpc(server, method, params=None, id_=1):
    msg = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        msg["params"] = params
    return server.handle_line(json.dumps(msg))


def call(server, name, args):
    return rpc(server, "tools/call", {"name": name, "arguments": args})


class Base(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        self.sig = os.path.join(self.tmp, "sig")
        os.makedirs(self.sig, mode=0o700)
        self.clock = [0.0]
        self.runner = FakeRunner()
        self.tools = porch_mcp.Tools(runner=self.runner, sleep=self._sleep,
                                     clock=lambda: self.clock[0], home=self.home,
                                     secret_dir=self.sig)
        self.server = porch_mcp.Server(self.tools)
        rpc(self.server, "initialize", {"protocolVersion": "2025-06-18"})
        env = mock.patch.dict(os.environ, {"HOME": self.home})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("PORCH_DOOR_PASSWORD", None)
        quiet = mock.patch.object(porch_mcp, "log")
        quiet.start()
        self.addCleanup(quiet.stop)

    def _sleep(self, s):
        self.clock[0] += s

    def result(self, resp):
        self.assertIn("result", resp, resp)
        return resp["result"]

    def write(self, name, data=b"hello\n"):
        p = os.path.join(self.tmp, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        return p


class ProtocolTests(Base):

    def test_initialize_negotiates(self):
        for v in ("2025-06-18", "2025-03-26", "2024-11-05"):
            s = porch_mcp.Server(self.tools)
            r = self.result(rpc(s, "initialize", {"protocolVersion": v}))
            self.assertEqual(r["protocolVersion"], v)
            self.assertEqual(r["serverInfo"]["name"], "porch")
            self.assertIn("version", r["serverInfo"])
            self.assertIn("tools", r["capabilities"])
        r = self.result(rpc(porch_mcp.Server(self.tools), "initialize",
                            {"protocolVersion": "1999-01-01"}))
        self.assertEqual(r["protocolVersion"], "2025-06-18")

    def test_notifications_get_no_answer(self):
        s = porch_mcp.Server(self.tools)
        self.assertIsNone(s.handle_line('{"jsonrpc":"2.0","method":"notifications/initialized"}'))
        self.assertTrue(s.initialized)
        self.assertIsNone(s.handle_line('{"jsonrpc":"2.0","method":"notifications/whatever"}'))
        self.assertIsNone(s.handle_line('{"jsonrpc":"2.0","id":3,"result":{}}'))
        self.assertIsNone(s.handle_line("   \n"))

    def test_ping(self):
        self.assertEqual(self.result(rpc(self.server, "ping", id_="a")), {})

    def test_errors(self):
        self.assertEqual(rpc(self.server, "nope")["error"]["code"], -32601)
        r = self.server.handle_line("{not json")
        self.assertEqual(r["error"]["code"], -32700)
        self.assertIsNone(r["id"])
        self.assertEqual(self.server.handle_line(b"\xff\xfe")["error"]["code"], -32700)
        self.assertEqual(self.server.handle_line('{"id":1,"method":"ping"}')["error"]["code"],
                         -32600)
        self.assertEqual(self.server.handle_line('{"jsonrpc":"2.0","id":{},"method":"ping"}')
                         ["error"]["code"], -32600)
        self.assertEqual(self.server.handle_line("[]")["error"]["code"], -32600)
        self.assertEqual(self.server.handle_line('"str"')["error"]["code"], -32600)
        # invalid params
        self.assertEqual(rpc(self.server, "tools/call", {"name": "nope"})["error"]["code"],
                         -32602)
        self.assertEqual(rpc(self.server, "tools/call", {})["error"]["code"], -32602)
        self.assertEqual(self.server.handle_line(
            '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":[1]}')["error"]["code"],
            -32602)
        for args in ({"name": "BAD NAME"}, {}, {"name": "ok", "extra": 1}, {"name": 5}):
            r = call(self.server, "close_door", args)
            self.assertEqual(r["error"]["code"], -32602, args)
        r = call(self.server, "receive_file", {"wait_seconds": 99999})
        self.assertEqual(r["error"]["code"], -32602)
        r = call(self.server, "open_door", {"type": "ftp", "name": "x"})
        self.assertEqual(r["error"]["code"], -32602)
        r = call(self.server, "open_door", {"type": "tunnel", "name": "x", "port": True})
        self.assertEqual(r["error"]["code"], -32602)
        self.assertEqual(self.runner.calls, [])

    def test_batch(self):
        r = self.server.handle_line(json.dumps([
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "nope"}]))
        self.assertEqual([x["id"] for x in r], [1, 2])

    def test_tools_list_shape(self):
        tools = self.result(rpc(self.server, "tools/list"))["tools"]
        names = {t["name"] for t in tools}
        self.assertEqual(names, {"share", "receive_file", "ask_secret", "open_door", "close_door",
                                 "list_doors", "extend_door", "inspect_requests", "clip_get",
                                 "clip_set"})
        for t in tools:
            self.assertIsInstance(t["description"], str)
            self.assertGreater(len(t["description"]), 30)
            self.assertEqual(t["inputSchema"]["type"], "object")
            self.assertIsInstance(t["inputSchema"]["properties"], dict)
            for k in t["inputSchema"].get("required", []):
                self.assertIn(k, t["inputSchema"]["properties"])
        share = next(t for t in tools if t["name"] == "share")
        self.assertIn("1h", share["description"])
        self.assertIn("NAME of an environment", share["inputSchema"]["properties"]
                      ["password_env"]["description"])

    def test_structured_content_old_protocol(self):
        s = porch_mcp.Server(self.tools)
        rpc(s, "initialize", {"protocolVersion": "2024-11-05"})
        r = self.result(call(s, "close_door", {"name": "x"}))
        self.assertNotIn("structuredContent", r)
        self.assertEqual(len(r["content"]), 2)


class StdioTests(unittest.TestCase):

    def test_process_stdout_is_only_json(self):
        lines = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                        "clientInfo": {"name": "t", "version": "0"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "share", "arguments": {"path": "/definitely/not/here"}}},
            {"jsonrpc": "2.0", "id": 4, "method": "bogus"},
        ]
        data = "\n".join(json.dumps(m) for m in lines) + "\nnot json\n"
        p = subprocess.run([sys.executable, CMD_MCP], input=data.encode(), capture_output=True,
                           timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        out = p.stdout.decode().splitlines()
        self.assertEqual(len(out), 5)
        msgs = [json.loads(x) for x in out]
        self.assertTrue(all(m["jsonrpc"] == "2.0" for m in msgs))
        self.assertEqual(msgs[0]["result"]["protocolVersion"], "2025-03-26")
        self.assertTrue(msgs[2]["result"]["isError"])
        self.assertEqual(msgs[3]["error"]["code"], -32601)
        self.assertEqual(msgs[4]["error"]["code"], -32700)

    def test_serve_redirects_stray_prints(self):
        class Noisy(porch_mcp.Tools):
            def close_door(self, a):
                print("stray print from a tool")
                return "ok", {}
        out = io.BytesIO()
        inp = io.BytesIO(b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":'
                         b'{"name":"close_door","arguments":{"name":"x"}}}\n')
        with mock.patch("sys.stderr", new=io.StringIO()) as err:
            porch_mcp.serve(inp, out, porch_mcp.Server(Noisy(runner=FakeRunner())))
        self.assertNotIn(b"stray", out.getvalue())
        self.assertIn("stray", err.getvalue())
        self.assertEqual(len(out.getvalue().splitlines()), 1)

    def test_print_config(self):
        buf = io.StringIO()
        porch_mcp.print_config(buf)
        s = buf.getvalue()
        self.assertIn("claude mcp add porch", s)
        self.assertIn('"mcpServers"', s)
        self.assertIn(os.path.join(porch_mcp.BIN_DIR, "porch"), s)


class ToolArgvTests(Base):

    def test_share_path(self):
        p = self.write("notes.md", b"# hi\n")
        self.runner.answers = [("porch share", 0,
                                f"porch share: {p} -> view (markdown), viewer mode markdown\n"
                                "View: https://notes-ab12.tunnel.cush.rocks\nExpires: ...\n", "")]
        if not os.path.exists(os.path.join(LIB, "porch_setup", "cmd_share.py")):
            self.skipTest("cmd_share.py not present")
        r = self.result(call(self.server, "share", {"path": p, "expires": "2h", "name": "notes"}))
        self.assertFalse(r.get("isError"))
        c = self.runner.last
        self.assertEqual(c["argv"][0], sys.executable)
        self.assertEqual(c["argv"][1], os.path.join(porch_mcp.BIN_DIR, "porch"))
        self.assertEqual(c["argv"][2:], ["share", os.path.realpath(p), "--name", "notes",
                                         "--expires", "2h"])
        self.assertEqual(r["structuredContent"]["url"], "https://notes-ab12.tunnel.cush.rocks")
        self.assertEqual(r["structuredContent"]["type"], "view")
        self.assertEqual(r["structuredContent"]["viewer_mode"], "markdown")

    def test_share_always_names_the_door_and_closes_it_on_timeout(self):
        if not os.path.exists(os.path.join(LIB, "porch_setup", "cmd_share.py")):
            self.skipTest("cmd_share.py not present")
        p = self.write("Report Q3.md", b"# hi\n")

        def runner(argv, stdin=None, env=None, tty_stdin=False, timeout=None):
            self.runner.calls.append({"argv": argv, "stdin": stdin, "env": env, "tty": tty_stdin})
            if "share" in argv:
                raise porch_mcp.LaunchTimeout("porch timed out after 60s")
            return 0, "", ""
        self.tools.runner = runner
        r = self.result(call(self.server, "share", {"path": p}))
        self.assertTrue(r["isError"])
        share = self.runner.calls[0]["argv"]
        name = share[share.index("--name") + 1]
        self.assertRegex(name, r"^report-q3-[0-9a-f]{4}$")
        self.assertEqual(self.runner.calls[1]["argv"],
                         [os.path.join(porch_mcp.BIN_DIR, "status"), "close", name])
        self.assertIn(f"closed door {name}", r["content"][0]["text"])

    def test_share_text_password_and_guest(self):
        if not os.path.exists(os.path.join(LIB, "porch_setup", "cmd_share.py")):
            self.skipTest("cmd_share.py not present")
        self.runner.answers = [("porch share", 0,
                                "porch share: stdin -> view (text), viewer mode text\n"
                                "View: https://s.tunnel.cush.rocks\n"
                                "Guest link: https://s.tunnel.cush.rocks/?k=TOKEN\n", "")]
        os.environ["MY_PW"] = "hunter2-very-secret"
        os.environ["PORCH_DOOR_PASSWORD"] = "inherited-should-not-leak"
        r = call(self.server, "share", {"text": "hello", "password_env": "MY_PW",
                                        "guest_link": True, "burn": True})
        res = self.result(r)
        c = self.runner.last
        self.assertEqual(c["stdin"], b"hello")
        self.assertIn("-", c["argv"])
        self.assertIn("--password", c["argv"])
        self.assertIn("--guest-link", c["argv"])
        self.assertIn("--burn", c["argv"])
        self.assertEqual(c["env"]["PORCH_DOOR_PASSWORD"], "hunter2-very-secret")
        self.assertNotIn("hunter2", " ".join(c["argv"]))
        self.assertNotIn("hunter2", json.dumps(r))
        self.assertEqual(res["structuredContent"]["guest_link"], "https://s.tunnel.cush.rocks/?k=TOKEN")

    def test_inherited_password_is_not_passed(self):
        os.environ["PORCH_DOOR_PASSWORD"] = "inherited"
        call(self.server, "open_door", {"type": "tunnel", "name": "app", "port": 3000})
        self.assertNotIn("PORCH_DOOR_PASSWORD", self.runner.last["env"])
        self.assertNotIn("--password", self.runner.last["argv"])

    def test_password_env_unset(self):
        r = self.result(call(self.server, "open_door", {"type": "tunnel", "name": "app",
                                                        "port": 3000, "password_env": "NOPE_X"}))
        self.assertTrue(r["isError"])
        self.assertEqual(self.runner.calls, [])

    def test_share_needs_one_of(self):
        r = self.result(call(self.server, "share", {}))
        self.assertTrue(r["isError"])
        r = self.result(call(self.server, "share", {"path": "/x", "text": "y"}))
        self.assertTrue(r["isError"])

    def test_share_e2e_returns_key_link_and_never_logs_it(self):
        if not os.path.exists(os.path.join(LIB, "porch_setup", "cmd_share.py")):
            self.skipTest("cmd_share.py not present")
        key = "Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5"
        p = self.write("report.pdf", b"%PDF-1.4\n")
        self.runner.answers = [("porch share", 0,
                                f"porch share: {p} -> seal (key), end-to-end encrypted (application/pdf)\n"
                                "Seal: https://rep.tunnel.cush.rocks/\n"
                                "Guest link: https://rep.tunnel.cush.rocks/?k=TOKEN\n"
                                "Link (end-to-end encrypted; the key is the part after #, share it "
                                f"whole): https://rep.tunnel.cush.rocks/#k={key}\n"
                                "Guest link (door gate skipped, key included): "
                                f"https://rep.tunnel.cush.rocks/?k=TOKEN#k={key}\n", "")]
        logged = []
        with mock.patch.object(porch_mcp, "log", side_effect=logged.append):
            r = self.result(call(self.server, "share", {"path": p, "name": "rep", "e2e": True,
                                                        "burn": True, "guest_link": True}))
        self.assertFalse(r.get("isError"), r)
        argv = self.runner.last["argv"]
        self.assertIn("--e2e", argv)
        self.assertIn("--burn", argv)
        sc = r["structuredContent"]
        self.assertEqual(sc["url"], f"https://rep.tunnel.cush.rocks/#k={key}")
        self.assertEqual(sc["guest_link"], f"https://rep.tunnel.cush.rocks/?k=TOKEN#k={key}")
        self.assertTrue(sc["e2e"])
        self.assertIn(f"#k={key}", r["content"][0]["text"])
        self.assertTrue(logged)
        self.assertNotIn(key, " ".join(map(str, logged)))

    def test_share_e2e_refusals(self):
        if not os.path.exists(os.path.join(LIB, "porch_setup", "cmd_share.py")):
            self.skipTest("cmd_share.py not present")
        d = os.path.join(self.tmp, "folder")
        os.makedirs(d)
        r = self.result(call(self.server, "share", {"path": d, "e2e": True}))
        self.assertTrue(r["isError"])
        self.assertIn("one file", r["content"][0]["text"])
        r = self.result(call(self.server, "share", {"text": "x", "e2e": True, "as": "view"}))
        self.assertTrue(r["isError"])
        self.runner.answers = [("porch share", 3, "",
                                "porch share: --e2e needs python3-cryptography; install it with: "
                                "sudo apt install python3-cryptography\n")]
        r = self.result(call(self.server, "share", {"text": "x", "e2e": True}))
        self.assertTrue(r["isError"])
        self.assertIn("sudo apt install python3-cryptography", r["content"][0]["text"])
        self.assertEqual(self.runner.calls[-1]["stdin"], b"x")

    def test_share_missing_cmd_share(self):
        with mock.patch.object(porch_mcp, "LIB_DIR", self.tmp):
            r = self.result(call(self.server, "share", {"text": "hi"}))
        self.assertTrue(r["isError"])
        self.assertIn("not installed", r["content"][0]["text"])

    def test_receive_file(self):
        self.runner.answers = [("bin/drop", 0, "Drop: https://inbox.tunnel.cush.rocks\n"
                                               "Files will be saved to: x\n", "")]
        d = os.path.join(self.home, "drops", "inbox")
        os.makedirs(d)
        with open(os.path.join(d, "old.txt"), "w") as f:
            f.write("old")
        calls = [0]

        def sleep(s):
            self.clock[0] += s
            calls[0] += 1
            if calls[0] == 2:
                with open(os.path.join(d, ".upload-1.part"), "w") as f:
                    f.write("partial")
                with open(os.path.join(d, "new.bin"), "w") as f:
                    f.write("12345")
        self.tools.sleep = sleep
        r = self.result(call(self.server, "receive_file", {"name": "inbox", "wait_seconds": 30,
                                                           "expires": "30m"}))
        c = self.runner.last
        self.assertEqual(c["argv"], [os.path.join(porch_mcp.BIN_DIR, "drop"), "inbox", "--bg",
                                     "--expires", "30m"])
        sc = r["structuredContent"]
        self.assertEqual(sc["url"], "https://inbox.tunnel.cush.rocks")
        self.assertEqual(sc["directory"], d + "/")
        self.assertEqual(sc["files"], [{"path": os.path.join(d, "new.bin"), "size": 5}])

    def test_receive_file_timeout(self):
        r = self.result(call(self.server, "receive_file", {"name": "inbox", "wait_seconds": 5}))
        self.assertEqual(r["structuredContent"]["files"], [])
        self.assertTrue(r["structuredContent"]["timed_out"])

    def test_open_door_each_type(self):
        d = os.path.join(self.tmp, "site")
        os.makedirs(d)
        self.write("site/index.html", b"<p>hi</p>")
        f = self.write("doc.txt")
        B = porch_mcp.BIN_DIR
        cases = [
            ({"type": "tunnel", "name": "app", "port": 3000, "expires": "never"},
             [f"{B}/tunnel", "3000", "app", "--bg", "--expires", "never"], None, False),
            ({"type": "serve", "name": "site", "path": d, "max_opens": 3},
             [f"{B}/serve", os.path.realpath(d), "site", "--bg", "--max-opens", "3"], None, False),
            ({"type": "view", "name": "doc", "path": f},
             [f"{B}/view", os.path.realpath(f), "doc", "--bg"], None, False),
            ({"type": "paste", "name": "p1", "content": "hi from mcp"},
             [f"{B}/paste", "p1", "--bg"], b"hi from mcp", False),
            ({"type": "exchange", "name": "ex", "content": "send me"},
             [f"{B}/exchange", "ex", "--bg"], b"send me", False),
            ({"type": "exchange", "name": "ex"}, [f"{B}/exchange", "ex", "--bg"], None, True),
            ({"type": "hook", "name": "gh", "inspect": True}, [f"{B}/hook", "gh", "--bg"], None,
             False),
            ({"type": "pocket", "name": "pocket"}, [f"{B}/pocket", "pocket", "--bg"], None, False),
            ({"type": "tunnel", "name": "app", "port": 80, "inspect": True},
             [f"{B}/tunnel", "80", "app", "--bg", "--inspect"], None, False),
        ]
        for args, argv, stdin, tty in cases:
            r = self.result(call(self.server, "open_door", args))
            self.assertFalse(r.get("isError"), (args, r))
            c = self.runner.last
            self.assertEqual(c["argv"], argv, args)
            self.assertEqual(c["stdin"], stdin, args)
            self.assertEqual(c["tty"], tty, args)

    def test_open_door_validation(self):
        bad = [
            {"type": "tunnel", "name": "app"},
            {"type": "serve", "name": "s", "path": "/no/such/dir"},
            {"type": "serve", "name": "s", "path": self.write("f.txt")},
            {"type": "view", "name": "v", "path": self.tmp},
            {"type": "paste", "name": "p"},
            {"type": "paste", "name": "p", "content": ""},
            {"type": "pocket", "name": "p", "port": 3},
            {"type": "tunnel", "name": "app", "port": 3, "expires": "--evil"},
            {"type": "tunnel", "name": "app-", "port": 3},
        ]
        for args in bad:
            r = call(self.server, "open_door", args)
            if "error" in r:
                self.assertEqual(r["error"]["code"], -32602, args)
            else:
                self.assertTrue(r["result"]["isError"], args)
        self.assertEqual(self.runner.calls, [])

    def test_launcher_failure_is_error_result(self):
        self.runner.answers = [("bin/tunnel", 2, "", "Error: port must be a number\n")]
        r = self.result(call(self.server, "open_door", {"type": "tunnel", "name": "a", "port": 1}))
        self.assertTrue(r["isError"])
        self.assertIn("port must be a number", r["content"][0]["text"])

    def test_close_list_extend(self):
        call(self.server, "close_door", {"name": "app"})
        self.assertEqual(self.runner.last["argv"],
                         [os.path.join(porch_mcp.BIN_DIR, "status"), "close", "app"])
        self.runner.answers = [("door ls", 0, json.dumps([{"name": "app", "type": "paste",
                                                           "url": "https://app.x", "expires": None,
                                                           "opens": 2, "rules": {}}]), "")]
        r = self.result(call(self.server, "list_doors", {}))
        self.assertEqual(self.runner.last["argv"][1:], [os.path.join(porch_mcp.BIN_DIR, "porch"),
                                                        "door", "ls", "--json"])
        self.assertEqual(r["structuredContent"]["doors"][0]["name"], "app")
        call(self.server, "extend_door", {"name": "app", "expires": "2026-10-20T10:00"})
        self.assertEqual(self.runner.last["argv"][2:], ["door", "expire", "app", "2026-10-20T10:00"])
        r = self.result(call(self.server, "extend_door", {"name": "app", "expires": "soon"}))
        self.assertTrue(r["isError"])

    def test_inspect(self):
        recs = [{"id": i, "method": "POST", "target": "/x", "status": 200} for i in (5, 4, 3, 2)]
        self.runner.answers = [("inspect", 0, json.dumps(recs), "")]
        r = self.result(call(self.server, "inspect_requests", {"name": "gh", "since_id": 2,
                                                               "limit": 2}))
        self.assertEqual(self.runner.last["argv"][2:], ["inspect", "gh", "-n", "500", "--json"])
        self.assertEqual([x["id"] for x in r["structuredContent"]["requests"]], [3, 4])
        self.assertEqual(r["structuredContent"]["last_id"], 4)
        call(self.server, "inspect_requests", {"name": "gh"})
        self.assertEqual(self.runner.last["argv"][2:], ["inspect", "gh", "-n", "20", "--json"])

    def test_clip(self):
        self.runner.answers = [("clip", 0, "copied text", "")]
        r = self.result(call(self.server, "clip_get", {}))
        self.assertEqual(self.runner.last["argv"][2:], ["clip"])
        self.assertEqual(r["structuredContent"]["text"], "copied text")
        call(self.server, "clip_set", {"text": "from agent", "pocket": "work"})
        c = self.runner.last
        self.assertEqual(c["argv"][2:], ["clip", "--name", "work", "set", "-"])
        self.assertEqual(c["stdin"], b"from agent")

    def test_clip_not_running(self):
        self.runner.answers = [("clip", 1, "", 'porch clip: pocket "pocket" is not running\n')]
        r = self.result(call(self.server, "clip_get", {}))
        self.assertTrue(r["isError"])
        self.assertIn("porch clip failed", r["content"][0]["text"])


class SensitivePathTests(Base):

    def refused(self, path, allow=False):
        args = {"path": path}
        if allow:
            args["allow_sensitive"] = True
        r = self.result(call(self.server, "share", args))
        return bool(r.get("isError")) and "refused" in r["content"][0]["text"]

    def test_soft_refusals(self):
        for name in (".env", ".env.local", "server.pem", "id_rsa.pub"):
            p = self.write(name, b"X=1\n")
            self.assertTrue(self.refused(p), name)
        ssh = os.path.join(self.home, ".ssh")
        os.makedirs(ssh)
        p = os.path.join(ssh, "config")
        with open(p, "w") as f:
            f.write("Host x\n")
        self.assertTrue(self.refused(p))
        cfg = os.path.join(self.home, ".config", "cush-tools")
        os.makedirs(cfg)
        with open(os.path.join(cfg, "op.env"), "w") as f:
            f.write("x")
        self.assertTrue(self.refused(os.path.join(cfg, "op.env")))
        self.assertEqual(self.runner.calls, [])

    def test_allow_sensitive_lets_soft_through(self):
        if not os.path.exists(os.path.join(LIB, "porch_setup", "cmd_share.py")):
            self.skipTest("cmd_share.py not present")
        p = self.write(".env", b"X=1\n")
        self.runner.answers = [("porch share", 0, "View: https://e.tunnel.cush.rocks\n", "")]
        self.assertFalse(self.refused(p, allow=True))

    def test_hard_refusals(self):
        for name, data in (("id_ed25519", b"x"), ("tls.key", b"x"),
                           ("notes.txt", b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n")):
            p = self.write(name, data)
            self.assertTrue(self.refused(p, allow=True), name)
        r = self.result(call(self.server, "share", {
            "text": "-----BEGIN RSA PRIVATE KEY-----\nabc", "allow_sensitive": True}))
        self.assertTrue(r["isError"])
        self.assertEqual(self.runner.calls, [])

    def test_repo_secrets(self):
        repo = os.path.join(self.tmp, "repo")
        for rel in ("data/devices.json", "data/links.json", "data/history.jsonl",
                    "config/frps.toml", "site/index.html"):
            p = os.path.join(repo, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write("{}")
        v = lambda rel, allow=False: porch_mcp.vet_path(  # noqa: E731
            os.path.join(repo, rel), allow, repo=repo, home=self.home)
        with self.assertRaisesRegex(porch_mcp.ToolError, "never shared"):
            v("data/devices.json", True)
        with self.assertRaisesRegex(porch_mcp.ToolError, "sensitive"):
            v("config/frps.toml")
        v("config/frps.toml", True)
        with self.assertRaisesRegex(porch_mcp.ToolError, "sensitive"):
            v("data/history.jsonl")
        v("data/links.json")
        v("site")
        with self.assertRaisesRegex(porch_mcp.ToolError, "data/ or config/"):
            v("", True)

    def test_directory_with_key_inside(self):
        d = os.path.join(self.tmp, "proj")
        os.makedirs(os.path.join(d, "sub"))
        with open(os.path.join(d, "sub", "deploy.key"), "w") as f:
            f.write("x")
        with self.assertRaisesRegex(porch_mcp.ToolError, "never shared"):
            porch_mcp.vet_path(d, True, home=self.home)
        # dotfiles are not served by bin/serve, so they do not block a folder
        os.remove(os.path.join(d, "sub", "deploy.key"))
        with open(os.path.join(d, ".env"), "w") as f:
            f.write("x")
        porch_mcp.vet_path(d, home=self.home)

    def test_symlink_resolved(self):
        target = self.write(".env.prod", b"SECRET=1")
        link = os.path.join(self.tmp, "innocent.txt")
        os.symlink(target, link)
        self.assertTrue(self.refused(link))

    def test_hardlink_to_sensitive_file(self):
        cfg = os.path.join(self.home, ".config", "cush-tools")
        os.makedirs(cfg)
        secret = os.path.join(cfg, "op.env")
        with open(secret, "w") as f:
            f.write("OP_MASTER_PASSWORD=x\n")
        link = os.path.join(self.tmp, "notes.txt")
        os.link(secret, link)
        self.assertTrue(self.refused(link))
        d = os.path.join(self.tmp, "folder")
        os.makedirs(d)
        os.link(secret, os.path.join(d, "readme.txt"))
        with self.assertRaisesRegex(porch_mcp.ToolError, "hard link"):
            porch_mcp.vet_path(d, home=self.home)

    def test_case_and_trailing_slash(self):
        ssh = os.path.join(self.home, ".ssh")
        os.makedirs(ssh)
        with open(os.path.join(ssh, "known_hosts"), "w") as f:
            f.write("x")
        self.assertTrue(self.refused(ssh + "/"))
        self.assertTrue(self.refused(os.path.join(self.tmp, "..", os.path.basename(self.tmp),
                                                  "home", ".ssh", "known_hosts")))
        self.assertEqual(porch_mcp.classify(os.path.join(self.home, ".SSH", "x"),
                                            home=self.home)[0], "soft")
        for rel in (".aws/credentials", ".netrc", ".gnupg/x", ".local/share/porch/e2e/state.json"):
            self.assertEqual(porch_mcp.classify(os.path.join(self.home, rel), home=self.home)[0],
                             "soft", rel)

    def test_folder_with_symlinked_dir_to_ssh(self):
        ssh = os.path.join(self.home, ".ssh")
        os.makedirs(ssh)
        d = os.path.join(self.tmp, "site")
        os.makedirs(d)
        os.symlink(ssh, os.path.join(d, "keys"))
        with self.assertRaisesRegex(porch_mcp.ToolError, "~/.ssh"):
            porch_mcp.vet_path(d, home=self.home)

    def test_missing_path(self):
        r = self.result(call(self.server, "share", {"path": os.path.join(self.tmp, "nope")}))
        self.assertTrue(r["isError"])
        self.assertIn("no such file", r["content"][0]["text"])


class SecretTests(Base):
    SECRET = "sk_live_DO_NOT_LEAK_7f3a9c"

    def test_ask_secret_never_returns_value(self):
        secret_file = os.path.join(self.tmp, "entry", "apikey")
        os.makedirs(os.path.dirname(secret_file))
        with open(secret_file, "w") as f:
            f.write(self.SECRET)
        out = ("Secure entry: https://entry-apikey.tunnel.cush.rocks/TOK123/\n"
               f"Secret will be saved to: {secret_file}\nLog: x\n")
        self.runner.answers = [("secure-entry", 0, out, "")]
        responses = []
        orig_sleep = self.tools.sleep

        def sleep(s):
            orig_sleep(s)
            argv = self.runner.last["argv"]
            sig = argv[argv.index("--signal-file") + 1]
            open(sig, "w").close()
        self.tools.sleep = sleep
        resp = call(self.server, "ask_secret", {"label": "apikey", "wait_seconds": 30})
        responses.append(resp)
        r = self.result(resp)
        self.assertTrue(r["structuredContent"]["arrived"])
        self.assertEqual(r["structuredContent"]["url"],
                         "https://entry-apikey.tunnel.cush.rocks/TOK123/")
        self.assertEqual(r["structuredContent"]["stored_at"], secret_file)
        responses.append(call(self.server, "ask_secret", {"label": "apikey"}))
        # stdio path too, with stderr captured
        out_buf = io.BytesIO()
        line = json.dumps({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                           "params": {"name": "ask_secret",
                                      "arguments": {"label": "apikey", "wait_seconds": 3}}})
        with mock.patch("sys.stderr", new=io.StringIO()) as err:
            porch_mcp.serve(io.BytesIO(line.encode() + b"\n"), out_buf, self.server)
        blob = json.dumps(responses).encode() + out_buf.getvalue() + err.getvalue().encode()
        self.assertNotIn(self.SECRET.encode(), blob)
        self.assertNotIn(b"DO_NOT_LEAK", blob)

    def test_ask_secret_argv(self):
        self.runner.answers = [("secure-entry", 0,
                                "Secure entry: https://entry-db.tunnel.cush.rocks/T/\n"
                                "Secrets will be written to: inf://dev/app\n", "")]
        r = self.result(call(self.server, "ask_secret", {
            "label": "db", "fields": ["user", "key.pem:file"], "save_to": "inf://dev/app"}))
        argv = self.runner.last["argv"]
        self.assertEqual(argv[:6], [os.path.join(porch_mcp.BIN_DIR, "secure-entry"), "db",
                                    "--save-to-secrets", "inf://dev/app", "--field", "user"])
        self.assertIn("--signal-file", argv)
        self.assertEqual(argv[-1], "--bg")
        self.assertTrue(argv[argv.index("--signal-file") + 1].startswith(self.sig))
        self.assertEqual(r["structuredContent"]["stored_at"], "inf://dev/app")
        self.assertNotIn("arrived", r["structuredContent"])

    def test_ask_secret_bad_ref(self):
        r = call(self.server, "ask_secret", {"label": "db", "save_to": "file:///etc/passwd"})
        self.assertEqual(r["error"]["code"], -32602)
        r = call(self.server, "ask_secret", {"label": "db", "fields": ["--evil"]})
        self.assertEqual(r["error"]["code"], -32602)


class RunCmdTests(unittest.TestCase):

    def test_bounded_and_no_shell(self):
        rc, out, err = porch_mcp.run_cmd([sys.executable, "-c",
                                          "import sys; sys.stdout.write('x'*200000); "
                                          "sys.stderr.write('e')"])
        self.assertEqual(rc, 0)
        self.assertLess(len(out), porch_mcp.MAX_OUTPUT + 100)
        self.assertIn("truncated", out)
        self.assertEqual(err, "e")
        with self.assertRaises(TypeError):
            porch_mcp.run_cmd("echo hi")

    def test_stdin_and_tty(self):
        rc, out, _ = porch_mcp.run_cmd([sys.executable, "-c",
                                        "import sys; print(sys.stdin.read().upper())"],
                                       stdin=b"abc")
        self.assertEqual(out.strip(), "ABC")
        rc, out, _ = porch_mcp.run_cmd([sys.executable, "-c",
                                        "import sys; print(sys.stdin.isatty())"], tty_stdin=True)
        self.assertEqual(out.strip(), "True")
        rc, out, _ = porch_mcp.run_cmd([sys.executable, "-c",
                                        "import sys; print(repr(sys.stdin.read()))"])
        self.assertEqual(out.strip(), "''")

    def test_timeout(self):
        with self.assertRaisesRegex(porch_mcp.ToolError, "timed out"):
            porch_mcp.run_cmd([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1)


if __name__ == "__main__":
    unittest.main()

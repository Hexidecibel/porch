"""Tests for `porch share` and `porch tail` (lib/porch_setup/cmd_share.py,
cmd_tail.py): routing, names, stdin, --as, door flags, dry-run argv.

Nothing is launched: main() gets a fake `run`, and HOME / XDG_RUNTIME_DIR
point at temp dirs.
"""

import contextlib
import io
import os
import subprocess
import shutil
import sys
import tempfile
import unittest
from unittest import mock

LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib")
sys.path.insert(0, LIB)
sys.path.insert(0, os.path.join(LIB, "porch_setup"))

import cmd_share  # noqa: E402
import cmd_tail  # noqa: E402

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
PDF = b"%PDF-1.4\n%%EOF\n"
ID3 = b"ID3\x03\x00\x00\x00" + b"\x00" * 32


class ShareTests(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.home = tempfile.mkdtemp()
        run = tempfile.mkdtemp()
        os.chmod(run, 0o700)
        for d in (self.dir, self.home, run):
            self.addCleanup(shutil.rmtree, d, True)
        env = mock.patch.dict(os.environ, {"HOME": self.home, "XDG_RUNTIME_DIR": run})
        env.start()
        self.addCleanup(env.stop)
        self.runs = []

    def write(self, name, data):
        p = os.path.join(self.dir, name)
        with open(p, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())
        return p

    def main(self, argv, stdin=None, rc=0):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cmd_share.main(argv, stdin=stdin, run=lambda a: self.runs.append(a) or rc)
        return code, out.getvalue(), err.getvalue()

    def route(self, name, data, as_=None):
        return cmd_share.route(self.write(name, data), as_)[:2]

    def test_routing_by_content(self):
        self.assertEqual(self.route("photo.txt", PNG), ("media", None))      # magic beats ext
        self.assertEqual(self.route("song.bin", ID3), ("music", None))
        self.assertEqual(self.route("doc.md", PDF), ("view", "pdf"))
        self.assertEqual(self.route("README.md", "# hi"), ("view", "markdown"))
        self.assertEqual(self.route("t.csv", "a,b\n"), ("view", "csv"))
        self.assertEqual(self.route("x.py", "x=1"), ("view", "code"))
        self.assertEqual(self.route("a.zip", b"PK\x03\x04" + b"\x00" * 30), ("view", "zip"))
        self.assertEqual(self.route("blob", b"\x00\x01\x02"), ("view", "other"))
        self.assertEqual(cmd_share.route(self.dir)[:2], ("serve", None))

    def test_as_overrides(self):
        p = self.write("x.txt", "hello")
        self.assertEqual(cmd_share.route(p, "view:markdown")[:2], ("view", "markdown"))
        self.assertEqual(cmd_share.route(p, "paste")[:2], ("paste", None))
        for bad in ("serve", "view:nope", "media:png", "ftp"):
            with self.assertRaises(cmd_share.UsageError, msg=bad):
                cmd_share.route(p, bad)
        with self.assertRaises(cmd_share.UsageError):
            cmd_share.route(self.dir, "view")

    def test_names(self):
        self.assertEqual(cmd_share.default_name("/x/My Report (final).PDF", rand="abcd"),
                         "my-report-final-abcd")
        self.assertEqual(cmd_share.default_name("/x/___.md", rand="abcd"), "share-abcd")
        long = cmd_share.default_name("/x/" + "a" * 80 + ".txt", rand="abcd")
        self.assertTrue(cmd_share.valid_name(long))
        self.assertLessEqual(len(long), 41)
        for n in ("ok", "a-b-1", "x" * 41):
            self.assertTrue(cmd_share.valid_name(n), n)
        for n in ("", "-a", "a-", "A", "a_b", "a.b", "x" * 42, "../x"):
            self.assertFalse(cmd_share.valid_name(n), n)
        code, _, err = self.main(["--dry-run", "--name", "Bad_Name", self.write("a.md", "x")])
        self.assertEqual(code, 2)
        self.assertIn("invalid --name", err)

    def test_dry_run_view_argv(self):
        p = self.write("README.md", "# hi")
        code, out, _ = self.main(["--dry-run", p, "--name", "readme", "--expires", "2h",
                                  "--password", "--burn", "--bg"])
        self.assertEqual(code, 0)
        self.assertIn("-> view (markdown)", out)
        self.assertIn("command: " + os.path.join(cmd_share.BIN_DIR, "view") + " " +
                      os.path.realpath(p) + " readme --bg --expires 2h --password --burn", out)
        self.assertEqual(self.runs, [])

    def test_as_view_mode_passed(self):
        p = self.write("notes.txt", "# hi")
        code, out, _ = self.main(["--dry-run", "--as", "view:markdown", "--name", "n", p])
        self.assertIn(" n --as markdown --bg", out)

    def test_password_value_refused(self):
        code, _, err = self.main(["--password=hunter2", self.write("a.md", "x")])
        self.assertEqual(code, 2)
        self.assertNotIn("hunter2", err)

    def test_media_staging(self):
        p = self.write("pic.mp3", PNG)                       # wrong extension
        code, out, _ = self.main([p, "--name", "pics", "--guest-link"])
        self.assertEqual(code, 0)
        dest = os.path.join(self.home, "media", "pics", "pic.png")
        with open(dest, "rb") as f:
            self.assertEqual(f.read(), PNG)
        self.assertFalse(os.path.islink(dest))
        self.assertEqual(self.runs, [[os.path.join(cmd_share.BIN_DIR, "media"), "pics",
                                      "--no-guest-upload", "--bg", "--guest-link"]])
        # A second share under the same name would publish the first file too.
        code, _, err = self.main([p, "--name", "pics"])
        self.assertEqual(code, 2)
        self.assertIn("already has files", err)

    def test_music_staging_keeps_good_name(self):
        p = self.write("Track 1.mp3", ID3)
        code, out, _ = self.main([p, "--name", "mix"])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isfile(os.path.join(self.home, "music", "mix", "Track_1.mp3")))
        self.assertEqual(self.runs[0][:3], [os.path.join(cmd_share.BIN_DIR, "music"), "mix", "--bg"])

    def test_serve_directory(self):
        code, out, _ = self.main(["--dry-run", self.dir, "--name", "site"])
        self.assertIn("-> serve", out)
        self.assertIn(f"serve {os.path.realpath(self.dir)} site --list --bg", out)
        self.assertNotIn("allow-scripts", out)

    def test_serve_directory_with_index_has_no_listing(self):
        with open(os.path.join(self.dir, "index.html"), "w") as f:
            f.write("<p>hi</p>")
        code, out, _ = self.main(["--dry-run", self.dir, "--name", "site"])
        self.assertIn(f"serve {os.path.realpath(self.dir)} site --bg", out)
        self.assertNotIn("--list", out)

    def test_stdin(self):
        code, out, _ = self.main(["--dry-run", "-", "--name", "doc"], stdin=io.BytesIO(PDF))
        self.assertEqual(code, 0)
        self.assertIn("stdin -> view (pdf)", out)
        self.assertIn("would write", out)
        code, out, _ = self.main(["-", "--name", "doc2"], stdin=io.BytesIO(b'{"a": [1]}'))
        self.assertEqual(code, 0)
        path = self.runs[-1][1]
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        with open(path, "rb") as f:
            self.assertEqual(f.read(), b'{"a": [1]}')
        self.assertIn("-> view (json)", out)

    def test_stdin_copy_is_owned(self):
        # view: the 0600 copy goes to bin/view with --owned-file (removed when
        # the door closes); a launcher that fails removes it at once
        code, _, _ = self.main(["-", "--name", "own"], stdin=io.BytesIO(b"# hi\n"))
        self.assertEqual(code, 0)
        argv = self.runs[-1]
        self.assertIn("--owned-file", argv)
        self.assertTrue(os.path.exists(argv[1]))
        code, _, _ = self.main(["-", "--name", "own2"], stdin=io.BytesIO(b"# hi\n"), rc=1)
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(self.runs[-1][1]))
        # a file shared by path is never owned
        self.main([self.write("keep.md", "x"), "--name", "keep"])
        self.assertNotIn("--owned-file", self.runs[-1])
        self.assertTrue(os.path.exists(os.path.join(self.dir, "keep.md")))

    def test_view_owned_file_only_in_run_dir(self):
        keep = self.write("mine.md", "x")
        env = dict(os.environ, PORCH_CONFIG="none")
        p = subprocess.run([os.path.join(cmd_share.BIN_DIR, "view"), keep, "own-test",
                            "--owned-file", "--bg"], capture_output=True, text=True, env=env,
                           stdin=subprocess.DEVNULL, timeout=30)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("--owned-file only applies", p.stderr)
        self.assertTrue(os.path.exists(keep))

    def test_stdin_media_copy_removed_after_staging(self):
        code, _, _ = self.main(["-", "--name", "pic"], stdin=io.BytesIO(PNG))
        self.assertEqual(code, 0)
        staged = os.listdir(os.path.join(self.home, "media", "pic"))
        self.assertEqual(len(staged), 1)
        self.assertEqual(os.listdir(cmd_share.rundir.tool_dir("share")), [])

    def test_stdin_paste_is_piped(self):
        piped = []
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = cmd_share.main(["-", "--as", "paste", "--name", "pp"],
                                  stdin=io.BytesIO(b"hello"), run=self.runs.append,
                                  run_input=lambda a, d: piped.append((a, d)) or 0)
        self.assertEqual(code, 0)
        argv, data = piped[0]
        self.assertEqual(argv[1:], ["pp", "--bg"])
        self.assertEqual(data, b"hello")
        self.assertEqual(os.listdir(cmd_share.rundir.tool_dir("share")), [])

    def test_stage_refuses_symlinked_dir_and_existing_dest(self):
        target = os.path.join(self.dir, "elsewhere")
        os.makedirs(target)
        os.makedirs(os.path.join(self.home, "media"), exist_ok=True)
        os.symlink(target, os.path.join(self.home, "media", "lnk"))
        code, _, err = self.main([self.write("p.png", PNG), "--name", "lnk"])
        self.assertEqual(code, 2)
        self.assertIn("symlink", err)
        self.assertEqual(os.listdir(target), [])

    def test_refuses_fifo_and_devices(self):
        fifo = os.path.join(self.dir, "pipe")
        os.mkfifo(fifo)
        for p in (fifo, "/dev/null"):
            code, _, err = self.main(["--dry-run", p])
            self.assertEqual(code, 2, p)
            self.assertIn("not a regular file", err)

    def test_stdin_limits(self):
        code, _, err = self.main(["-"], stdin=io.BytesIO(b""))
        self.assertEqual(code, 2)
        with mock.patch.object(cmd_share, "MAX_STDIN", 10):
            code, _, err = self.main(["-"], stdin=io.BytesIO(b"x" * 11))
        self.assertEqual(code, 2)
        self.assertIn("share a file instead", err)

    def test_launcher_failure_is_exit_1(self):
        code, _, _ = self.main([self.write("a.md", "x")], rc=3)
        self.assertEqual(code, 1)

    def test_missing_path(self):
        code, _, err = self.main([os.path.join(self.dir, "nope")])
        self.assertEqual(code, 2)


class E2ETests(unittest.TestCase):
    """porch share --e2e: seal into the run dir, then bin/seal --owned-file."""
    write = ShareTests.write
    main = ShareTests.main

    def setUp(self):
        ShareTests.setUp(self)
        import porch_seal
        self.ps = porch_seal
        if not porch_seal.available():
            self.skipTest("python3-cryptography is not installed")
        self.state = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.state, True)
        p = mock.patch.object(cmd_share.door_state, "STATE_DIR", self.state)
        p.start()
        self.addCleanup(p.stop)
        os.environ.pop("PORCH_SEAL_PASSWORD", None)

    def test_dry_run(self):
        f = self.write("report.pdf", PDF)
        code, out, _ = self.main(["--e2e", f, "--name", "rep", "--dry-run", "--burn"])
        self.assertEqual(code, 0)
        self.assertIn("-> seal (key), end-to-end encrypted (application/pdf)", out)
        self.assertIn(f"/rep.pseal (0600, key mode)", out)
        self.assertIn("command: " + os.path.join(cmd_share.BIN_DIR, "seal"), out)
        self.assertIn("rep.pseal rep --owned-file --bg --burn", out)
        self.assertIn("link: https://rep.tunnel.cush.rocks/#k=<key, made at run time>", out)
        self.assertEqual(self.runs, [])
        self.assertEqual(os.listdir(os.path.dirname(cmd_share.rundir.tool_dir("share"))), ["share"])
        self.assertEqual(os.listdir(cmd_share.rundir.tool_dir("share")), [])

    def test_seal_and_launch(self):
        data = PDF * 1000
        f = self.write("report.pdf", data)
        code, out, _ = self.main(["--e2e", f, "--name", "rep", "--guest-link"])
        self.assertEqual(code, 0)
        argv = self.runs[-1]
        sealed = argv[1]
        self.assertEqual(argv[0], os.path.join(cmd_share.BIN_DIR, "seal"))
        self.assertEqual(argv[2:], ["rep", "--owned-file", "--bg", "--guest-link"])
        self.assertEqual(os.path.dirname(sealed), cmd_share.rundir.tool_dir("share"))
        self.assertEqual(os.stat(sealed).st_mode & 0o777, 0o600)
        line = [ln for ln in out.splitlines() if ln.startswith("Link")][0]
        self.assertIn("https://rep.tunnel.cush.rocks/#k=", line)
        key = line.split("#k=")[1].strip()
        meta, it = self.ps.open_file(sealed, key_b64=key)
        self.assertEqual(b"".join(it), data)
        self.assertEqual(meta["name"], "report.pdf")
        self.assertEqual(meta["type"], "application/pdf")
        with open(sealed, "rb") as fh:
            self.assertNotIn(b"%PDF", fh.read())

    def test_guest_link_carries_key(self):
        f = self.write("a.txt", "hello")
        import door_state
        tok = door_state.new_guest_token()
        door_state.write_state_atomic(os.path.join(self.state, "g1.json"),
                                      {"name": "g1", "rules": {"guest": tok}})
        code, out, _ = self.main(["--e2e", f, "--name", "g1", "--guest-link"])
        self.assertEqual(code, 0)
        guest = [ln for ln in out.splitlines() if ln.startswith("Guest link")][0]
        self.assertRegex(guest, r"https://g1\.tunnel\.cush\.rocks/\?k=" + tok + r"#k=[A-Za-z0-9_-]{43}$")

    def test_stdin_is_sealed_from_memory(self):
        code, out, _ = self.main(["--e2e", "-", "--name", "sin"], stdin=io.BytesIO(b"top secret\n"))
        self.assertEqual(code, 0)
        share_dir = cmd_share.rundir.tool_dir("share")
        self.assertEqual(os.listdir(share_dir), ["sin.pseal"])     # no plaintext copy
        key = out.split("#k=")[1].split()[0]
        meta, it = self.ps.open_file(os.path.join(share_dir, "sin.pseal"), key_b64=key)
        self.assertEqual(b"".join(it), b"top secret\n")
        self.assertEqual(meta["name"], "stdin.txt")

    def test_password_mode(self):
        f = self.write("a.txt", "hello")
        with mock.patch.dict(os.environ, {"PORCH_SEAL_PASSWORD": "longenough1"}):
            code, out, _ = self.main(["--e2e", f, "--name", "pw1", "--seal-password"])
        self.assertEqual(code, 0)
        self.assertNotIn("#k=", out)
        self.assertIn("sealed with a password", out)
        self.assertNotIn("longenough1", out + " ".join(self.runs[-1]))
        meta, it = self.ps.open_file(self.runs[-1][1], password="longenough1")
        self.assertEqual(b"".join(it), b"hello")
        with mock.patch.dict(os.environ, {"PORCH_SEAL_PASSWORD": "short"}):
            code, _, err = self.main(["--e2e", f, "--name", "pw2", "--seal-password"])
        self.assertEqual(code, 2)
        self.assertIn("at least 8", err)
        with mock.patch.object(cmd_share, "read_seal_password",
                               side_effect=cmd_share.UsageError("needs a terminal")):
            code, _, _ = self.main(["--e2e", f, "--name", "pw3", "--seal-password"])
        self.assertEqual(code, 2)

    def test_usage_errors(self):
        f = self.write("a.txt", "hello")
        for argv in (["--seal-password", f], ["--e2e", self.dir], ["--e2e", f, "--as", "view"],
                     ["--e2e", f, "--seal-password=x"]):
            code, _, _ = self.main(argv)
            self.assertEqual(code, 2, argv)
        self.assertEqual(self.runs, [])

    def test_launcher_failure_removes_sealed(self):
        f = self.write("a.txt", "hello")
        code, out, _ = self.main(["--e2e", f, "--name", "fail1"], rc=1)
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(self.runs[-1][1]))
        self.assertNotIn("#k=", out)

    def test_missing_cryptography_exit_3(self):
        f = self.write("a.txt", "hello")
        with mock.patch.object(self.ps, "available", return_value=False):
            code, _, err = self.main(["--e2e", f, "--name", "nocrypto"])
        self.assertEqual(code, 3)
        self.assertIn("sudo apt install python3-cryptography", err)
        self.assertEqual(self.runs, [])


class TailTests(unittest.TestCase):

    def test_build(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "app.log")
        open(p, "w").close()
        argv, dry = cmd_tail.build([p, "--name", "logs", "--expires", "1h", "--dry-run"])
        self.assertTrue(dry)
        self.assertEqual(argv, [os.path.join(cmd_share.BIN_DIR, "view"), os.path.realpath(p),
                                "logs", "--follow", "--bg", "--expires", "1h"])
        argv, _ = cmd_tail.build([p])
        self.assertRegex(argv[2], r"^app-[0-9a-f]{4}$")
        for bad in ([], [d], [p, "--name", "BAD"], [p, "--what"]):
            with self.assertRaises(cmd_share.UsageError, msg=bad):
                cmd_tail.build(bad)
        runs = []
        self.assertEqual(cmd_tail.main([p], run=lambda a: runs.append(a) or 0), 0)
        self.assertEqual(runs[0][3:5], ["--follow", "--bg"])


if __name__ == "__main__":
    unittest.main()

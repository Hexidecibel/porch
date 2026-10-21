"""bin/publish-tarball: only allowlisted files ship; data/ secrets never do."""

import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "bin", "publish-tarball")


def _git(cwd, *args):
    subprocess.run(["git", "-C", cwd, *args], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class PublishTarballTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.repo = os.path.join(self.tmp, "cush-tools")
        for d in ("bin", "lib", "config", "data", "logs", ".claude/commands"):
            os.makedirs(os.path.join(self.repo, d), exist_ok=True)
        shutil.copy(SCRIPT, os.path.join(self.repo, "bin", "publish-tarball"))
        shutil.copy(os.path.join(REPO, "lib", "porch_files.py"), os.path.join(self.repo, "lib", "porch_files.py"))
        shutil.copy(os.path.join(REPO, ".gitignore"), os.path.join(self.repo, ".gitignore"))
        files = {
            "bin/tunnel": "#!/bin/sh\n",
            "lib/authserver.py": "",
            "config/frpc.toml.example": "",
            "data/links.json": "{}",
            ".claude/commands/x.md": "x",
            "share/public-export-markers.txt": "SECRET-MARKER\n",   # tracked, never shipped
            # private working files: tracked, listed in share/public-exclude.txt, never shipped
            "share/public-exclude.txt": "# c\ntodo.md\nCLAUDE.md\n.claude/\ndocs/private-*.md\n",
            "CLAUDE.md": "private notes", "todo.md": "x", "docs/private-plan.md": "x",
            "docs/public.md": "ok",
        }
        for p, body in files.items():
            self._write(p, body)
        _git(self.repo, "init", "-q")
        _git(self.repo, "add", "-A")
        # Planted secrets: all must stay out.
        for p in ("data/devices.json", "data/devices.json.bak-x",
                  "data/backups/devices.json.bak-1", "data/.admin-cli-token",
                  "data/history.jsonl", "data/.authserver.lock",
                  "config/frpc.toml", "config/frps.toml", "logs/x.log",
                  "bin/frpc", ".claude/settings.json"):
            self._write(p, "SECRET")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, rel, body):
        path = os.path.join(self.repo, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(body)

    def _build(self, repo=None):
        out = os.path.join(self.tmp, "out.tgz")
        r = subprocess.run([os.path.join(repo or self.repo, "bin", "publish-tarball"), "--out", out],
                           capture_output=True, text=True)
        return r, out

    def test_checkout_directory_name_does_not_matter(self):
        # A worktree or renamed clone: the tarball still unpacks to porch/.
        other = os.path.join(self.tmp, "porch-wt-123")
        shutil.copytree(self.repo, other, symlinks=True)
        r, out = self._build(other)
        self.assertEqual(r.returncode, 0, r.stderr)
        with tarfile.open(out) as t:
            names = set(t.getnames())
        self.assertIn("porch/bin/tunnel", names)
        self.assertIn("porch/data/links.json", names)
        self.assertFalse(any("porch-wt-123" in n for n in names))
        self.assertTrue(all(n.startswith("porch/") for n in names), names)
        for n in names:
            self.assertNotIn("SECRET", n)
        self.assertNotIn("porch/data/devices.json.bak-x", names)

    def test_planted_secrets_do_not_ship(self):
        r, out = self._build()
        self.assertEqual(r.returncode, 0, r.stderr)
        with tarfile.open(out) as t:
            names = set(t.getnames())
        self.assertIn("porch/data/links.json", names)
        self.assertIn("porch/bin/tunnel", names)
        self.assertIn("porch/docs/public.md", names)
        self.assertIn("porch/share/public-exclude.txt", names)
        for n in names:
            self.assertNotIn("SECRET", n)
            if n.startswith("porch/data/"):
                self.assertEqual(n, "porch/data/links.json")
        for bad in ("data/devices.json.bak-x", "data/.admin-cli-token",
                    "data/history.jsonl", "config/frpc.toml", "logs/x.log",
                    "bin/frpc", ".claude/settings.json", "share/public-export-markers.txt"):
            self.assertNotIn("porch/" + bad, names)

    def test_public_exclude_list_never_ships(self):
        r, out = self._build()
        self.assertEqual(r.returncode, 0, r.stderr)
        with tarfile.open(out) as t:
            names = set(t.getnames())
            man = t.extractfile("porch/share/porch-files.txt").read().decode().split()
        for bad in ("CLAUDE.md", "todo.md", ".claude/commands/x.md", "docs/private-plan.md",
                    "share/public-export-markers.txt"):
            self.assertNotIn("porch/" + bad, names)
            self.assertNotIn(bad, man)
        # and an install repacking from the manifest drops them too, even if present
        inst = self._unpack(out, os.path.join(self.tmp, "fresh"))
        self._write_at(inst, "CLAUDE.md", "x")
        out2 = os.path.join(self.tmp, "out2.tgz")
        r2 = subprocess.run([os.path.join(inst, "bin", "publish-tarball"), "--out", out2],
                            capture_output=True, text=True)
        self.assertEqual(r2.returncode, 0, r2.stderr)
        with tarfile.open(out2) as t:
            self.assertNotIn("porch/CLAUDE.md", t.getnames())

    def test_prefix_and_sha256_name(self):
        out = os.path.join(self.tmp, "porch.tar.gz")
        r = subprocess.run([os.path.join(self.repo, "bin", "publish-tarball"), "--out", out,
                            "--prefix", "porch"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        with tarfile.open(out) as t:
            names = t.getnames()
        self.assertTrue(all(n.startswith("porch/") for n in names), names)
        self.assertIn("porch/bin/tunnel", names)
        with open(out + ".sha256") as f:
            self.assertTrue(f.read().endswith("  porch.tar.gz\n"))
        r = subprocess.run([os.path.join(self.repo, "bin", "publish-tarball"), "--out", out,
                            "--prefix", "../x"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)

    def _write_at(self, root, rel, body):
        with open(os.path.join(root, rel), "w") as f:
            f.write(body)

    def test_force_added_data_file_aborts(self):
        _git(self.repo, "add", "-f", "data/devices.json.bak-x")
        r, out = self._build()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("data/devices.json.bak-x", r.stderr)
        self.assertFalse(os.path.exists(out))

    def test_unignored_new_data_file_aborts(self):
        self._write("data/new-state.json", "{}")
        r, _ = self._build()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("data/new-state.json", r.stderr)

    # -- installs with no .git: pack from the shipped manifest --
    def _unpack(self, tgz, where):
        os.makedirs(where)
        with tarfile.open(tgz) as t:
            t.extractall(where, filter="data")
        return os.path.join(where, "porch")

    def test_git_tarball_ships_a_manifest(self):
        r, out = self._build()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("(git)", r.stdout)
        with tarfile.open(out) as t:
            names = set(t.getnames())
            man = t.extractfile("porch/share/porch-files.txt").read().decode().split()
        self.assertIn("porch/share/porch-files.txt", names)
        self.assertEqual(sorted("porch/" + m for m in man), sorted(names))
        self.assertNotIn("data/devices.json", man)

    def test_install_without_git_repacks_from_the_manifest(self):
        r, out = self._build()
        self.assertEqual(r.returncode, 0, r.stderr)
        inst = self._unpack(out, os.path.join(self.tmp, "fresh"))
        self.assertFalse(os.path.exists(os.path.join(inst, ".git")))
        # what a running install accumulates: none of it may ship
        for p in ("data/devices.json", "data/porch-setup.json", "data/.admin-cli-token",
                  "config/porch.toml", "config/frps.toml", "logs/a.log", "bin/frps", "lib/new.py"):
            path = os.path.join(inst, p)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write("SECRET")
        out2 = os.path.join(self.tmp, "out2.tgz")
        r2 = subprocess.run([os.path.join(inst, "bin", "publish-tarball"), "--out", out2],
                            capture_output=True, text=True)
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertIn("(manifest)", r2.stdout)
        with tarfile.open(out) as a, tarfile.open(out2) as b:
            self.assertEqual(set(a.getnames()), set(b.getnames()))
            for m in b.getmembers():
                if m.isfile():
                    self.assertNotEqual(b.extractfile(m).read(), b"SECRET", m.name)

    def test_install_inside_another_git_repo_still_uses_its_manifest(self):
        r, out = self._build()
        outer = os.path.join(self.tmp, "home")
        inst = self._unpack(out, outer)
        _git(outer, "init", "-q")
        out2 = os.path.join(self.tmp, "out2.tgz")
        r2 = subprocess.run([os.path.join(inst, "bin", "publish-tarball"), "--out", out2],
                            capture_output=True, text=True)
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertIn("(manifest)", r2.stdout)

    def _manifest_install(self, lines):
        inst = tempfile.mkdtemp(dir=self.tmp) + "/cush-tools"
        shutil.copytree(self.repo, inst, ignore=shutil.ignore_patterns(".git"))
        os.makedirs(os.path.join(inst, "share"), exist_ok=True)
        with open(os.path.join(inst, "share", "porch-files.txt"), "w") as f:
            f.write("".join(x + "\n" for x in lines))
        out = os.path.join(self.tmp, "o.tgz")
        r = subprocess.run([os.path.join(inst, "bin", "publish-tarball"), "--out", out],
                           capture_output=True, text=True)
        return r, out

    def test_manifest_listing_a_secret_aborts(self):
        base = ["bin/tunnel", "lib/authserver.py", "config/frpc.toml.example", "lib/porch_files.py",
                "bin/publish-tarball", "share/porch-files.txt"]
        for bad in ("data/devices.json", "data/.admin-cli-token"):
            r, out = self._manifest_install(base + [bad])
            self.assertNotEqual(r.returncode, 0)
            self.assertIn(bad, r.stderr)
            self.assertFalse(os.path.exists(out))
        r, out = self._manifest_install(base + ["../etc/passwd"])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not a plain relative path", r.stderr)
        # denylisted build artefacts are dropped, not shipped
        r, out = self._manifest_install(base + ["config/frps.toml", "logs/x.log", "bin/frpc"])
        self.assertEqual(r.returncode, 0, r.stderr)
        with tarfile.open(out) as t:
            names = set(t.getnames())
        self.assertNotIn("porch/config/frps.toml", names)
        self.assertNotIn("porch/bin/frpc", names)

    def test_no_git_and_no_manifest_fails(self):
        inst = os.path.join(self.tmp, "bare", "cush-tools")
        shutil.copytree(self.repo, inst, ignore=shutil.ignore_patterns(".git"))
        r = subprocess.run([os.path.join(inst, "bin", "publish-tarball"), "--out",
                            os.path.join(self.tmp, "x.tgz")], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("porch-files.txt", r.stderr)

    def test_publish_writes_porch_and_the_old_name(self):
        # porch.tar.gz for new installers, cush-tools.tar.gz (same bytes) for
        # installers rendered before the rename; each .sha256 names its file
        web = os.path.join(self.tmp, "web")
        os.makedirs(web)
        r = subprocess.run([os.path.join(self.repo, "bin", "publish-tarball")],
                           capture_output=True, text=True,
                           env=dict(os.environ, PORCH_WEB_ROOT=web))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sorted(os.listdir(web)), ["cush-tools.tar.gz", "cush-tools.tar.gz.sha256",
                                                   "porch.tar.gz", "porch.tar.gz.sha256"])
        with open(os.path.join(web, "porch.tar.gz"), "rb") as a, \
                open(os.path.join(web, "cush-tools.tar.gz"), "rb") as b:
            data = a.read()
            self.assertEqual(data, b.read())
        import hashlib
        hexd = hashlib.sha256(data).hexdigest()
        for name in ("porch.tar.gz", "cush-tools.tar.gz"):
            with open(os.path.join(web, name + ".sha256")) as f:
                self.assertEqual(f.read(), f"{hexd}  {name}\n")
        with tarfile.open(os.path.join(web, "porch.tar.gz")) as t:
            self.assertTrue(all(n.startswith("porch/") for n in t.getnames()))

    def test_manifest_for_a_ref_matches_git_archive(self):
        _git(self.repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "x")
        p = subprocess.run(["python3", os.path.join(self.repo, "lib", "porch_files.py"), "manifest",
                            self.repo, "--ref", "HEAD"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        man = p.stdout.split()
        self.assertIn("bin/tunnel", man)
        self.assertIn("share/porch-files.txt", man)
        self.assertNotIn("data/devices.json", man)


if __name__ == "__main__":
    unittest.main()

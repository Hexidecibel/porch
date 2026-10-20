"""bin/release: export -> tarball from the export -> force-push + gh release.

A throwaway source repo with the real bin/public-export, bin/publish-tarball,
lib/porch_files.py; gh is a stub on PATH that records its argv; the push
goes to a local bare repo. Nothing touches GitHub.
"""

import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(_HERE)
SCRIPT = os.path.join(REPO, "bin", "release")


def load_release():
    loader = importlib.machinery.SourceFileLoader("porch_release", SCRIPT)
    spec = importlib.util.spec_from_loader("porch_release", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class VersionTest(unittest.TestCase):
    def test_next_version(self):
        r = load_release()
        self.assertEqual(r.next_version([]), "v0.1.0")
        self.assertEqual(r.next_version(["nightly"]), "v0.1.0")
        self.assertEqual(r.next_version(["v0.1.0", "v0.1.9", "v0.1.10", "v0.0.99"]), "v0.1.11")
        self.assertEqual(r.next_version(["v1.2.3", "v0.9.9"]), "v1.2.4")


@unittest.skipUnless(shutil.which("git"), "git not installed")
class ReleaseFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                        HOME=self.tmp)
        for k in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
            self.env.pop(k, None)
        self.src = os.path.join(self.tmp, "src")
        for rel in ("bin/public-export", "bin/publish-tarball", "bin/release",
                    "lib/porch_files.py", ".gitignore"):
            dst = os.path.join(self.src, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(os.path.join(REPO, rel), dst)
        files = {
            "bin/porch": "#!/bin/sh\n", "bin/tunnel": "#!/bin/sh\n",
            "lib/authserver.py": "", "lib/porch_config.py": "",
            "config/frpc.toml.example": "", "data/links.json": "{}",
            "site/porch.sh": 'PORCH_TARBALL="${PORCH_TARBALL:-https://github.com/Hexidecibel/porch'
                             '/releases/latest/download/porch.tar.gz}"\n',
            "CLAUDE.md": "private", "todo.md": "private", ".claude/commands/x.md": "x",
            "share/public-exclude.txt": "todo.md\nCLAUDE.md\n.claude/\nshare/public-export-markers.txt\n",
            "share/public-export-markers.txt": "zz-marker-q9\n",
        }
        for rel, body in files.items():
            path = os.path.join(self.src, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(body)
        self.git("init", "-q", "-b", "master", cwd=self.src)
        self.git("add", "-A", cwd=self.src)
        self.git("-c", "user.name=T", "-c", "user.email=t@example.com", "commit", "-q", "-m", "x",
                 cwd=self.src)
        # gh stub: logs argv; `release list` prints $GH_TAGS
        self.stub = os.path.join(self.tmp, "stub")
        os.makedirs(self.stub)
        self.log = os.path.join(self.tmp, "gh.log")
        with open(os.path.join(self.stub, "gh"), "w") as f:
            f.write('#!/bin/sh\nprintf "%s\\n" "$*" >> "$GH_LOG"\n'
                    'if [ "$1 $2" = "release list" ]; then printf "%s" "$GH_TAGS"; fi\nexit 0\n')
        os.chmod(os.path.join(self.stub, "gh"), 0o755)
        self.env["PATH"] = self.stub + os.pathsep + os.environ["PATH"]
        self.env["GH_LOG"] = self.log
        self.env["GH_TAGS"] = ""
        self.bare = os.path.join(self.tmp, "remote.git")
        self.git("init", "-q", "--bare", self.bare, cwd=self.tmp)
        self.dist = os.path.join(self.tmp, "dist")

    def git(self, *args, cwd):
        return subprocess.run(["git", *args], cwd=cwd, env=self.env, check=True,
                              capture_output=True, text=True).stdout

    def release(self, *extra):
        return subprocess.run(
            ["python3", os.path.join(self.src, "bin", "release"), "--dist", self.dist,
             "--remote", self.bare, "--no-gh", "--author-name", "Porch Tester",
             "--author-email", "t@users.noreply.github.com", *extra],
            env=self.env, capture_output=True, text=True, timeout=300)

    def gh_calls(self):
        try:
            with open(self.log) as f:
                return f.read().splitlines()
        except FileNotFoundError:
            return []

    def tar_names(self):
        with tarfile.open(os.path.join(self.dist, "porch.tar.gz")) as t:
            return {m.name for m in t.getmembers() if not m.isdir()}

    def test_dry_run_builds_locally_and_runs_nothing(self):
        p = self.release("--dry-run")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("release v0.1.0", p.stdout)
        self.assertIn("git -C", p.stdout)
        self.assertIn("push --force", p.stdout)
        self.assertIn("gh release create v0.1.0", p.stdout)
        self.assertIn("dry run: nothing pushed", p.stdout)
        names = self.tar_names()
        self.assertIn("porch/bin/porch", names)
        self.assertIn("porch/site/porch.sh", names)
        self.assertTrue(all(n.startswith("porch/") for n in names), names)
        for bad in ("CLAUDE.md", "todo.md", ".claude/commands/x.md", "share/public-export-markers.txt"):
            self.assertNotIn("porch/" + bad, names)
        with open(os.path.join(self.dist, "porch.tar.gz.sha256")) as f:
            self.assertTrue(f.read().endswith("  porch.tar.gz\n"))
        # only the read-only release list ran
        self.assertEqual([c for c in self.gh_calls() if not c.startswith("release list")], [])
        self.assertEqual(self.git("for-each-ref", cwd=self.bare), "")

    def test_bumps_the_patch_of_the_latest_release(self):
        self.env["GH_TAGS"] = "v0.1.0\nv0.1.3\nv0.1.2\n"
        p = self.release("--dry-run")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("release v0.1.4", p.stdout)

    def test_real_run_needs_yes(self):
        p = self.release("--version", "v0.2.0")
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("--yes", p.stdout)
        self.assertEqual([c for c in self.gh_calls() if "create" in c], [])
        self.assertEqual(self.git("for-each-ref", cwd=self.bare), "")

    def test_yes_force_pushes_one_commit_and_creates_the_release(self):
        # an old main with unrelated history is replaced
        old = os.path.join(self.tmp, "old")
        os.makedirs(old)
        self.git("init", "-q", "-b", "main", cwd=old)
        with open(os.path.join(old, "f"), "w") as f:
            f.write("old")
        self.git("add", "-A", cwd=old)
        self.git("-c", "user.name=T", "-c", "user.email=t@example.com", "commit", "-q", "-m", "old",
                 cwd=old)
        self.git("push", "-q", self.bare, "main", cwd=old)
        p = self.release("--version", "v0.2.0", "--yes")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        log = self.git("log", "--format=%s", "main", cwd=self.bare).splitlines()
        self.assertEqual(log, ["Porch: initial public release"])
        files = self.git("ls-tree", "-r", "--name-only", "main", cwd=self.bare).split()
        self.assertIn("bin/porch", files)
        self.assertNotIn("CLAUDE.md", files)
        creates = [c for c in self.gh_calls() if c.startswith("release create")]
        self.assertEqual(len(creates), 1)
        c = creates[0]
        self.assertIn("release create v0.2.0 ", c)
        self.assertIn(os.path.join(self.dist, "porch.tar.gz") + " ", c)
        self.assertIn(os.path.join(self.dist, "porch.tar.gz.sha256"), c)
        self.assertIn("--repo Hexidecibel/porch", c)
        self.assertIn("--target main", c)
        self.assertIn("--title Porch v0.2.0", c)

    def test_bad_version_is_usage(self):
        p = self.release("--version", "1.0", "--dry-run")
        self.assertEqual(p.returncode, 2)


if __name__ == "__main__":
    unittest.main()

"""bin/public-export: one-commit export of HEAD, exclude list, leak scan."""

import os
import shutil
import subprocess
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(_HERE, "..", "bin", "public-export")
MARKER = "zz-planted-marker-q7"


@unittest.skipUnless(shutil.which("git"), "git not installed")
class PublicExport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.repo = os.path.join(self.tmp, "src")
        self.out = os.path.join(self.tmp, "out", "porch")
        # No user/global git config (hooks, signing) in the way.
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                        HOME=self.tmp)
        for k in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
            self.env.pop(k, None)
        files = {
            "README.md": "# demo\n",
            "lib/app.py": "print('hello')\n",
            "todo.md": "private notes\n",
            "CLAUDE.md": "assistant notes\n",
            ".claude/commands/x.md": "x\n",
            "config/porch.toml.example": "# example\n",
            "share/public-exclude.txt": "# comment\ntodo.md\nCLAUDE.md\n.claude/\n"
                                        "share/public-export-markers.txt\n",
            "share/public-export-markers.txt": f"# private\n{MARKER}\n",
        }
        for rel, body in files.items():
            self.write(rel, body)
        self.git("init", "-q", "-b", "main")
        self.commit("base")

    def write(self, rel, body):
        path = os.path.join(self.repo, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(body)

    def git(self, *args, cwd=None):
        return subprocess.run(["git", *args], cwd=cwd or self.repo, env=self.env,
                              check=True, capture_output=True, text=True).stdout

    def commit(self, msg):
        self.git("add", "-A")
        self.git("-c", "user.name=T", "-c", "user.email=t@example.com", "commit", "-q", "-m", msg)

    def run_export(self, *extra):
        return subprocess.run(["python3", SCRIPT, "--repo", self.repo, "--out", self.out, "--no-gh",
                               "--author-name", "Porch Tester",
                               "--author-email", "tester@users.noreply.github.com", *extra],
                              env=self.env, capture_output=True, text=True, timeout=120)

    def test_clean_export_is_one_commit_without_excluded_files(self):
        r = self.run_export()
        self.assertEqual(r.returncode, 0, r.stderr)
        files = sorted(self.git("ls-files", cwd=self.out).split())
        self.assertEqual(files, ["README.md", "config/porch.toml.example", "lib/app.py",
                                 "share/public-exclude.txt"])
        self.assertEqual(self.git("rev-list", "--count", "HEAD", cwd=self.out).strip(), "1")
        log = self.git("log", "-1", "--format=%an|%ae|%s", cwd=self.out).strip()
        self.assertEqual(log, "Porch Tester|tester@users.noreply.github.com|Porch: initial public release")
        for gone in ("todo.md", "CLAUDE.md", ".claude", "share/public-export-markers.txt"):
            self.assertFalse(os.path.exists(os.path.join(self.out, gone)), gone)
        self.assertIn("Exported 4 files", r.stdout)

    def test_uncommitted_changes_are_not_exported(self):
        self.write("lib/app.py", f"print('{MARKER}')\n")   # not committed
        r = self.run_export()
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(self.out, "lib", "app.py")) as f:
            self.assertEqual(f.read(), "print('hello')\n")

    def test_planted_marker_refuses(self):
        self.write("lib/app.py", f"print('hello')\nX = '{MARKER.upper()}'\n")
        self.commit("oops")
        r = self.run_export()
        self.assertEqual(r.returncode, 1)
        self.assertIn("lib/app.py:2", r.stderr)
        self.assertNotIn(MARKER, r.stderr.lower())
        self.assertFalse(os.path.exists(self.out))
        self.assertEqual(os.listdir(os.path.dirname(self.out)), [])   # stage removed

    def test_secret_shapes_and_forbidden_files_refuse(self):
        fake = "sk_live_" + "Q" * 24
        self.write("lib/keys.py", f"K = '{fake}'\n")
        self.write("config/porch.toml", "[domain]\n")
        self.commit("secrets")
        r = self.run_export()
        self.assertEqual(r.returncode, 1)
        self.assertIn("lib/keys.py:1: Stripe live key [sk_l…]", r.stderr)
        self.assertIn("config/porch.toml: forbidden file", r.stderr)
        self.assertNotIn(fake, r.stderr)
        # --allow clears both (a known-fake value, a fixture)
        r = self.run_export("--allow", "lib/keys.py:Stripe", "--allow", "config/porch.toml")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_non_empty_out_needs_force(self):
        os.makedirs(self.out)
        with open(os.path.join(self.out, "keep"), "w") as f:
            f.write("x")
        r = self.run_export()
        self.assertEqual(r.returncode, 2)
        self.assertIn("--force", r.stderr)
        r = self.run_export("--force")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.out, "keep")))
        self.assertEqual(self.git("rev-list", "--count", "HEAD", cwd=self.out).strip(), "1")


if __name__ == "__main__":
    unittest.main()

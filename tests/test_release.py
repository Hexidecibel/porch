"""bin/release + bin/public-pull: export -> tarball -> one appended public commit
+ tag + gh release; commits made on the public repo come back with public-pull.

A throwaway source repo with the real bin/public-export, bin/publish-tarball,
lib/porch_files.py; gh is a stub on PATH that records its argv; the push
goes to a local bare repo. Nothing touches GitHub.
"""

import importlib.machinery
import importlib.util
import json
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
        for k in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_AUTHOR_NAME",
                  "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL"):
            self.env.pop(k, None)
        self.src = os.path.join(self.tmp, "src")
        for rel in ("bin/public-export", "bin/publish-tarball", "bin/release", "bin/public-pull",
                    "lib/porch_files.py", "lib/public_sync.py", ".gitignore"):
            dst = os.path.join(self.src, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(os.path.join(REPO, rel), dst)
        files = {
            "bin/porch": "#!/bin/sh\n", "bin/tunnel": "#!/bin/sh\n",
            "lib/authserver.py": "", "lib/porch_config.py": "",
            "config/frpc.toml.example": "", "data/links.json": "{}",
            "site/porch.sh": 'PORCH_TARBALL="${PORCH_TARBALL:-https://github.com/Hexidecibel/porch'
                             '/releases/latest/download/porch.tar.gz}"\n',
            "README.md": "line one\nline two\nline three\n",
            "CLAUDE.md": "private", "todo.md": "private", ".claude/commands/x.md": "x",
            "share/public-exclude.txt": "todo.md\nCLAUDE.md\n.claude/\nshare/public-export-markers.txt\n"
                                        "share/public-release.json\n",
            "share/public-export-markers.txt": "zz-marker-q9\n",
        }
        for rel, body in files.items():
            self.write(rel, body)
        self.git("init", "-q", "-b", "master", cwd=self.src)
        self.git("config", "user.name", "Maintainer", cwd=self.src)
        self.git("config", "user.email", "m@example.com", cwd=self.src)
        self.git("config", "commit.gpgsign", "false", cwd=self.src)
        self.commit("initial")
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
        self.git("init", "-q", "--bare", "-b", "main", self.bare, cwd=self.tmp)
        self.dist = os.path.join(self.tmp, "dist")

    # helpers ------------------------------------------------------------------
    def write(self, rel, body, root=None):
        path = os.path.join(root or self.src, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(body)

    def git(self, *args, cwd, check=True):
        p = subprocess.run(["git", *args], cwd=cwd, env=self.env, capture_output=True, text=True)
        if check and p.returncode != 0:
            raise AssertionError(f"git {args} failed: {p.stderr}")
        return p.stdout

    def commit(self, msg, cwd=None):
        cwd = cwd or self.src
        self.git("add", "-A", cwd=cwd)
        self.git("commit", "-q", "-m", msg, cwd=cwd)

    def release(self, *extra):
        return subprocess.run(
            ["python3", os.path.join(self.src, "bin", "release"), "--dist", self.dist,
             "--remote", self.bare, "--no-gh", "--author-name", "Porch Tester",
             "--author-email", "t@users.noreply.github.com", *extra],
            env=self.env, capture_output=True, text=True, timeout=300)

    def pull(self, *extra):
        return subprocess.run(
            ["python3", os.path.join(self.src, "bin", "public-pull"), "--remote", self.bare, *extra],
            env=self.env, capture_output=True, text=True, timeout=300)

    def ok(self, p):
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        return p

    def gh_calls(self):
        try:
            with open(self.log) as f:
                return f.read().splitlines()
        except FileNotFoundError:
            return []

    def creates(self):
        return [c for c in self.gh_calls() if c.startswith("release create")]

    def tar_names(self):
        with tarfile.open(os.path.join(self.dist, "porch.tar.gz")) as t:
            return {m.name for m in t.getmembers() if not m.isdir()}

    def public_log(self):
        return self.git("log", "--format=%H %s", "main", cwd=self.bare).splitlines()

    def record(self):
        with open(os.path.join(self.src, "share", "public-release.json")) as f:
            return json.load(f)

    def contributor_commit(self, rel, body, subject="Fix a typo"):
        """Somebody merges a PR on GitHub: a commit on public main we lack."""
        c = os.path.join(self.tmp, "contrib")
        shutil.rmtree(c, ignore_errors=True)
        self.git("clone", "-q", self.bare, c, cwd=self.tmp)
        self.write(rel, body, root=c)
        self.git("add", "-A", cwd=c)
        self.git("-c", "user.name=Contributor", "-c", "user.email=c@example.org", "commit",
                 "-q", "-m", subject, cwd=c)
        self.git("push", "-q", "origin", "main", cwd=c)

    # tests --------------------------------------------------------------------
    def test_dry_run_builds_locally_and_runs_nothing(self):
        p = self.ok(self.release("--dry-run"))
        self.assertIn("release v0.1.0", p.stdout)
        self.assertIn("push --atomic", p.stdout)
        self.assertNotIn("--force", p.stdout)
        self.assertIn("gh release create v0.1.0", p.stdout)
        self.assertIn("dry run: nothing committed", p.stdout)
        names = self.tar_names()
        self.assertIn("porch/bin/porch", names)
        self.assertIn("porch/site/porch.sh", names)
        self.assertTrue(all(n.startswith("porch/") for n in names), names)
        for bad in ("CLAUDE.md", "todo.md", ".claude/commands/x.md",
                    "share/public-export-markers.txt", "share/public-release.json"):
            self.assertNotIn("porch/" + bad, names)
        with open(os.path.join(self.dist, "porch.tar.gz.sha256")) as f:
            self.assertTrue(f.read().endswith("  porch.tar.gz\n"))
        self.assertEqual([c for c in self.gh_calls() if not c.startswith("release list")], [])
        self.assertEqual(self.git("for-each-ref", cwd=self.bare), "")
        self.assertFalse(os.path.exists(os.path.join(self.src, "share", "public-release.json")))

    def test_bumps_the_patch_of_the_latest_release(self):
        self.env["GH_TAGS"] = "v0.1.0\nv0.1.3\nv0.1.2\n"
        p = self.ok(self.release("--dry-run"))
        self.assertIn("release v0.1.4", p.stdout)

    def test_real_run_needs_yes(self):
        p = self.release("--version", "v0.2.0")
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("--yes", p.stdout)
        self.assertEqual(self.creates(), [])
        self.assertEqual(self.git("for-each-ref", cwd=self.bare), "")

    def test_first_release_pushes_one_commit_tag_and_record(self):
        self.ok(self.release("--version", "v0.2.0", "--yes"))
        log = self.public_log()
        self.assertEqual(len(log), 1)
        self.assertTrue(log[0].endswith(" Porch v0.2.0"), log)
        files = self.git("ls-tree", "-r", "--name-only", "main", cwd=self.bare).split()
        self.assertIn("bin/porch", files)
        for bad in ("CLAUDE.md", "share/public-release.json", "share/public-export-markers.txt"):
            self.assertNotIn(bad, files)
        self.assertEqual(self.git("rev-parse", "v0.2.0^{commit}", cwd=self.bare).strip(),
                         log[0].split()[0])
        author = self.git("log", "-1", "--format=%an <%ae>", "main", cwd=self.bare).strip()
        self.assertEqual(author, "Porch Tester <t@users.noreply.github.com>")
        rec = self.record()
        self.assertEqual(rec["version"], "v0.2.0")
        self.assertEqual(rec["public_commit"], log[0].split()[0])
        # the record is committed in the private repo, and it names the exported commit
        self.assertEqual(self.git("status", "--porcelain", cwd=self.src), "")
        self.assertEqual(rec["private_commit"], self.git("rev-parse", "HEAD~1", cwd=self.src).strip())
        self.assertIn("Release v0.2.0", self.git("log", "-1", "--format=%s", cwd=self.src))
        c = self.creates()
        self.assertEqual(len(c), 1)
        self.assertIn("release create v0.2.0 ", c[0])
        self.assertIn(os.path.join(self.dist, "porch.tar.gz") + " ", c[0])
        self.assertIn("--repo Hexidecibel/porch", c[0])
        self.assertIn("--verify-tag", c[0])
        self.assertIn("--title Porch v0.2.0", c[0])

    def test_next_release_appends_a_commit_with_a_changelog(self):
        self.ok(self.release("--version", "v0.2.0", "--yes"))
        first = self.public_log()[0].split()[0]
        self.write("lib/authserver.py", "x = 1\n")
        self.commit("authserver: a real change")
        self.write("todo.md", "more private notes")
        self.commit("private-only commit about notes")        # touches only todo.md
        self.write("bin/tunnel", "#!/bin/sh\necho hi\n")
        self.commit("tunnel: greet (zz-marker-q9 host)")      # personal marker
        self.write("bin/tunnel", "#!/bin/sh\necho hello\n")
        self.commit("Update CLAUDE.md and the tunnel")        # names a private path
        p = self.ok(self.release("--yes"))
        self.assertIn("release v0.2.1", p.stdout)
        log = self.public_log()
        self.assertEqual(len(log), 2)
        self.assertEqual(self.git("rev-parse", "main~1", cwd=self.bare).strip(), first)
        msg = self.git("log", "-1", "--format=%B", "main", cwd=self.bare)
        self.assertTrue(msg.startswith("Porch v0.2.1\n\nChanges since v0.2.0:\n"), msg)
        self.assertIn("- authserver: a real change", msg)
        for leak in ("private-only", "zz-marker", "CLAUDE", "Release v0.2.0"):
            self.assertNotIn(leak, msg)
        self.assertIn("2 private subject(s) left out", p.stdout)
        self.assertEqual(self.record()["version"], "v0.2.1")
        self.assertEqual(len(self.creates()), 2)

    def test_no_change_is_a_no_op(self):
        self.ok(self.release("--version", "v0.2.0", "--yes"))
        self.write("todo.md", "private only")
        self.commit("notes")
        p = self.ok(self.release("--yes"))
        self.assertIn("nothing changed", p.stdout)
        self.assertEqual(len(self.public_log()), 1)
        self.assertEqual(len(self.creates()), 1)
        self.assertEqual(self.record()["version"], "v0.2.0")

    def test_existing_public_main_without_a_record_refuses(self):
        self.contributor_commit("x.txt", "x")
        p = self.release("--dry-run")
        self.assertEqual(p.returncode, 1)
        self.assertIn("public-release.json", p.stderr)

    def test_foreign_commit_refuses_then_public_pull_brings_it_in(self):
        self.ok(self.release("--version", "v0.2.0", "--yes"))
        self.contributor_commit("README.md", "line one\nline 2\nline three\n")
        p = self.release("--dry-run")
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("bin/public-pull", p.stderr)
        # dry run lists, applies nothing
        head = self.git("rev-parse", "HEAD", cwd=self.src)
        p = self.ok(self.pull("--dry-run"))
        self.assertIn("Fix a typo", p.stdout)
        self.assertEqual(self.git("rev-parse", "HEAD", cwd=self.src), head)
        # the real pull: the contributor's commit, authorship kept, then the record
        self.ok(self.pull())
        log = self.git("log", "-2", "--format=%an|%s", cwd=self.src).splitlines()
        self.assertEqual(log[1], "Contributor|Fix a typo")
        self.assertTrue(log[0].startswith("Maintainer|public-pull: synced"), log)
        with open(os.path.join(self.src, "README.md")) as f:
            self.assertEqual(f.read(), "line one\nline 2\nline three\n")
        public_main = self.git("rev-parse", "main", cwd=self.bare).strip()
        self.assertEqual(self.record()["public_synced"], public_main)
        self.assertIn("already up to date", self.ok(self.pull()).stdout)
        # nothing new on our side: the export equals public main
        self.assertIn("nothing changed", self.ok(self.release("--yes")).stdout)
        # a private change on top: one more commit, parent = the contributor's
        self.write("lib/authserver.py", "y = 2\n")
        self.commit("authserver: follow-up")
        self.ok(self.release("--yes"))
        self.assertEqual(self.git("rev-parse", "main~1", cwd=self.bare).strip(), public_main)
        msg = self.git("log", "-1", "--format=%B", "main", cwd=self.bare)
        self.assertIn("- authserver: follow-up", msg)
        self.assertNotIn("Fix a typo", msg)          # already public
        self.assertNotIn("public-pull", msg)         # record-only commit
        self.assertNotIn("public_synced", self.record())

    def test_public_pull_stops_on_a_conflict(self):
        self.ok(self.release("--version", "v0.2.0", "--yes"))
        self.contributor_commit("README.md", "line one\ntheirs\nline three\n")
        self.write("README.md", "line one\nours\nline three\n")
        self.commit("readme: ours")
        p = self.pull()
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("--continue", p.stdout)
        self.assertNotIn("public_synced", self.record())
        self.assertIn("in progress", self.pull().stderr)
        self.ok(self.pull("--abort"))
        self.assertEqual(self.git("log", "-1", "--format=%s", cwd=self.src).strip(), "readme: ours")
        # resolve by hand this time
        p = self.pull()
        self.assertEqual(p.returncode, 1)
        self.write("README.md", "line one\nmerged\nline three\n")
        self.git("add", "README.md", cwd=self.src)
        self.ok(self.pull("--continue"))
        self.assertEqual(self.git("log", "-2", "--format=%an", cwd=self.src).split()[1], "Contributor")
        self.assertIn("public_synced", self.record())

    def test_bad_version_is_usage(self):
        p = self.release("--version", "1.0", "--dry-run")
        self.assertEqual(p.returncode, 2)


class ChangelogFilterTest(unittest.TestCase):
    def test_private_mentions_and_markers(self):
        r = load_release()
        import re
        rules = [("personal marker #1", re.compile("zz-marker", re.I), [])]
        ex = ["todo.md", "CLAUDE.md", ".claude/", "share/public-export-markers.txt"]
        self.assertTrue(r._mentions_private("Update claude.md", ex))
        self.assertTrue(r._mentions_private("tweak .claude/commands", ex))
        self.assertTrue(r._mentions_private("new public-export-markers.txt entry", ex))
        self.assertFalse(r._mentions_private("Ask Claude about it", ex))
        self.assertEqual(r.subject_hits("host ZZ-MARKER x", rules), ["personal marker #1"])
        msg = r.commit_message("v1.0.1", "v1.0.0", ["a", "b"])
        self.assertEqual(msg, "Porch v1.0.1\n\nChanges since v1.0.0:\n- a\n- b\n")


if __name__ == "__main__":
    unittest.main()

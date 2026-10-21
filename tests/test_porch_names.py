"""The cush -> porch rename: new names work, the old ones still do.

bin/cush-* shims run bin/porch-*, hooks/pre-commit-cush runs the porch hook,
the hook installer adopts hooks from before the rename, PORCH_* environment
variables win over their CUSH_* names (still honoured), and per-user config
falls back to ~/.config/cush-tools/.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(REPO, "bin")
sys.path.insert(0, os.path.join(REPO, "lib"))

import auth_client  # noqa: E402
import door_ops  # noqa: E402
import porch_paths  # noqa: E402
from porch_setup import cli  # noqa: E402

RENAMED = ("audit", "find-empties", "hooks-install", "init", "migrate-all",
           "migrate-backend", "secrets-reap")


def run(argv, **kw):
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    kw.setdefault("timeout", 60)
    return subprocess.run(argv, **kw)


class ShimTest(unittest.TestCase):
    def test_every_cush_command_runs_its_porch_command(self):
        for n in RENAMED:
            new, old = os.path.join(BIN, f"porch-{n}"), os.path.join(BIN, f"cush-{n}")
            self.assertTrue(os.access(new, os.X_OK), new)
            self.assertTrue(os.access(old, os.X_OK), old)
            with open(old) as f:
                self.assertIn(f'porch-{n}" "$@"', f.read())
            a, b = run([new, "--help"]), run([old, "--help"])
            self.assertEqual(a.returncode, 0, a.stderr)
            self.assertEqual((a.returncode, a.stdout, a.stderr), (b.returncode, b.stdout, b.stderr), n)

    def test_shim_works_through_a_symlink(self):
        # e.g. ~/bin/cush-init -> <repo>/bin/cush-init
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        link = os.path.join(d, "cush-init")
        os.symlink(os.path.join(BIN, "cush-init"), link)
        p = run([link, "--help"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("porch-init", p.stdout + p.stderr)

    def test_porch_cli_aliases(self):
        for n in RENAMED:
            path, argv = cli.passthrough_target([n, "--help"])
            self.assertEqual(path, os.path.join(cli.BIN_DIR, f"porch-{n}"))
            self.assertEqual(argv[1:], ["--help"])
        p = run([os.path.join(BIN, "porch"), "init", "--help"])
        self.assertEqual(p.returncode, 0, p.stderr)


class HookTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmp, "proj")
        os.makedirs(self.repo)
        self.env = {"PATH": os.environ["PATH"], "HOME": self.home,
                    "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
        self.git("init", "-q")

    def git(self, *args):
        return run(["git", "-C", self.repo, *args], env=self.env)

    def commit_env_file(self):
        with open(os.path.join(self.repo, ".env"), "w") as f:
            f.write("A=1\n")
        self.git("add", "-f", ".env")
        return self.git("commit", "-q", "-m", "x")

    def test_legacy_hook_symlink_still_blocks(self):
        # an install from before the rename: .git/hooks/pre-commit -> hooks/pre-commit-cush
        hooks = os.path.join(self.repo, ".git", "hooks")
        os.makedirs(hooks, exist_ok=True)
        os.symlink(os.path.join(REPO, "hooks", "pre-commit-cush"), os.path.join(hooks, "pre-commit"))
        p = self.commit_env_file()
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("Blocked", p.stderr)

    def test_installer_installs_porch_hook_and_adopts_the_old_one(self):
        hooks = os.path.join(self.repo, ".git", "hooks")
        os.makedirs(hooks, exist_ok=True)
        target = os.path.join(hooks, "pre-commit")
        os.symlink(os.path.join(REPO, "hooks", "pre-commit-cush"), target)
        p = run([os.path.join(BIN, "porch-hooks-install"), self.repo], env=self.env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(os.readlink(target), os.path.join(REPO, "hooks", "pre-commit-porch"))
        p = self.commit_env_file()
        self.assertNotEqual(p.returncode, 0)
        # a copied hook carrying only the old marker is ours too
        os.remove(target)
        with open(target, "w") as f:
            f.write("#!/bin/sh\n# cush-tools-hook v1\nexit 0\n")
        p = run([os.path.join(BIN, "porch-hooks-install"), "--uninstall", self.repo], env=self.env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse(os.path.lexists(target))

    def test_bypass_file_new_and_legacy(self):
        hooks = os.path.join(self.repo, ".git", "hooks")
        os.makedirs(hooks, exist_ok=True)
        os.symlink(os.path.join(REPO, "hooks", "pre-commit-porch"), os.path.join(hooks, "pre-commit"))
        for d in ("porch", "cush-tools"):
            cfg = os.path.join(self.home, ".config", d)
            os.makedirs(cfg)
            with open(os.path.join(cfg, "hook-bypass"), "w") as f:
                f.write(".env\n")
            p = self.commit_env_file()
            self.assertEqual(p.returncode, 0, (d, p.stderr))
            shutil.rmtree(cfg)
            self.git("rm", "-q", "--cached", ".env")
            self.git("commit", "-q", "-m", "rm")

    def test_init_writes_porch_markers_and_respects_old_ones(self):
        p = run([os.path.join(BIN, "porch-init"), self.repo, "--no-direnv"], env=self.env)
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(os.path.join(self.repo, ".gitignore")) as f:
            gi = f.read()
        self.assertIn("# porch secrets\n", gi)
        self.assertNotIn("cush-tools", gi)
        # a project set up before the rename is already initialized
        other = os.path.join(self.tmp, "old")
        os.makedirs(other)
        with open(os.path.join(other, ".gitignore"), "w") as f:
            f.write("# cush-tools\n.env\n")
        with open(os.path.join(other, ".cush-secrets"), "w") as f:
            f.write("schema = 1\n")
        p = run([os.path.join(BIN, "cush-init"), other, "--no-direnv"], env=self.env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("already initialized", p.stderr)

    def test_porch_envrc_loader_is_allowed(self):
        hooks = os.path.join(self.repo, ".git", "hooks")
        os.makedirs(hooks, exist_ok=True)
        os.symlink(os.path.join(REPO, "hooks", "pre-commit-porch"), os.path.join(hooks, "pre-commit"))
        for body in ("/home/u/porch/bin/inject --no-prompt\n",
                     "/home/u/cush-tools/bin/inject --no-prompt\n",
                     "# Porch secrets loader — x\n/opt/elsewhere/bin/inject --no-prompt\n"):
            with open(os.path.join(self.repo, ".envrc"), "w") as f:
                f.write(body)
            self.git("add", "-f", ".envrc")
            p = self.git("commit", "-q", "-m", "x")
            self.assertEqual(p.returncode, 0, (body, p.stderr))
        with open(os.path.join(self.repo, ".envrc"), "w") as f:
            f.write("export TOKEN=abc\n")
        self.git("add", "-f", ".envrc")
        self.assertNotEqual(self.git("commit", "-q", "-m", "x").returncode, 0)


class EnvFallbackTest(unittest.TestCase):
    def setEnv(self, **kv):
        for k, v in kv.items():
            old = os.environ.get(k)
            self.addCleanup(lambda k=k, old=old: os.environ.pop(k, None) if old is None
                            else os.environ.__setitem__(k, old))
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_auth_url(self):
        self.setEnv(PORCH_AUTH_URL=None, CUSH_AUTH_URL=None)
        c = auth_client.Client(tempfile.gettempdir())
        self.assertEqual(c.url, auth_client.DEFAULT_URL)
        self.setEnv(CUSH_AUTH_URL="http://127.0.0.1:1111")
        self.assertEqual(c.url, "http://127.0.0.1:1111")
        self.setEnv(PORCH_AUTH_URL="http://127.0.0.1:2222")
        self.assertEqual(c.url, "http://127.0.0.1:2222")

    def test_auth_admin_url(self):
        code = ("import importlib.machinery, importlib.util, sys;"
                "l = importlib.machinery.SourceFileLoader('aa', sys.argv[1]);"
                "s = importlib.util.spec_from_loader('aa', l); m = importlib.util.module_from_spec(s);"
                "l.exec_module(m); print(m.AUTH_URL)")
        aa = os.path.join(BIN, "auth-admin")
        base = {k: v for k, v in os.environ.items() if not k.endswith("_AUTH_URL")}
        out = lambda **e: run([sys.executable, "-c", code, aa], env=dict(base, **e)).stdout.strip()  # noqa: E731
        self.assertEqual(out(), "http://127.0.0.1:9512")
        self.assertEqual(out(CUSH_AUTH_URL="http://127.0.0.1:1"), "http://127.0.0.1:1")
        self.assertEqual(out(CUSH_AUTH_URL="http://127.0.0.1:1", PORCH_AUTH_URL="http://127.0.0.1:2"),
                         "http://127.0.0.1:2")

    def test_history_file(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        self.setEnv(PORCH_HISTORY_FILE=None, CUSH_HISTORY_FILE=os.path.join(d, "old.jsonl"))
        self.assertEqual(door_ops.history_path(), os.path.join(d, "old.jsonl"))
        self.setEnv(PORCH_HISTORY_FILE=os.path.join(d, "new.jsonl"))
        self.assertEqual(door_ops.history_path(), os.path.join(d, "new.jsonl"))

    def test_tunnel_state_history_and_log_file(self):
        script = (f'. "{REPO}/lib/tunnel-state.sh"; '
                  'echo "${PORCH_HISTORY_FILE:-${CUSH_HISTORY_FILE:-none}}"')
        base = {k: v for k, v in os.environ.items() if "HISTORY_FILE" not in k}
        p = run(["bash", "-c", script], env=dict(base, CUSH_HISTORY_FILE="/x/old"))
        self.assertEqual(p.stdout.strip(), "/x/old")
        with open(os.path.join(REPO, "lib", "tunnel-state.sh")) as f:
            src = f.read()
        self.assertIn('${PORCH_HISTORY_FILE:-${CUSH_HISTORY_FILE:-', src)
        self.assertIn('${PORCH_LOG_FILE:-${CUSH_LOG_FILE:-}}', src)
        self.assertIn('export PORCH_LOG_FILE=', src)
        # launchers started from Pocket / reopen never inherit either name
        import door_recipe
        import pocket_links
        for drop in (door_ops.LAUNCHER_ENV_DROP, door_recipe.ENV_DROP, pocket_links.LAUNCHER_ENV_DROP):
            self.assertIn("PORCH_LOG_FILE", drop)
            self.assertIn("CUSH_LOG_FILE", drop)

    def test_env_first(self):
        self.assertEqual(porch_paths.env_first("A", "B", default="d", env={}), "d")
        self.assertEqual(porch_paths.env_first("A", "B", env={"B": "b"}), "b")
        self.assertEqual(porch_paths.env_first("A", "B", env={"A": "a", "B": "b"}), "a")
        self.assertEqual(porch_paths.env_first("A", "B", default="d", env={"A": ""}), "d")


class UserConfigTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, True)

    def put(self, d, name):
        p = os.path.join(self.home, ".config", d, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").close()
        return p

    def shell(self, name):
        p = run(["bash", "-c", f'. "{REPO}/lib/porch-user-config.sh"; porch_user_config_file {name}'],
                env=dict(os.environ, HOME=self.home))
        return p.stdout.strip()

    def test_new_dir_by_default(self):
        want = os.path.join(self.home, ".config", "porch", "op.env")
        self.assertEqual(porch_paths.user_config_file("op.env", home=self.home), want)
        self.assertEqual(self.shell("op.env"), want)

    def test_legacy_only(self):
        old = self.put("cush-tools", "op.env")
        self.assertEqual(porch_paths.user_config_file("op.env", home=self.home), old)
        self.assertEqual(self.shell("op.env"), old)

    def test_new_wins(self):
        self.put("cush-tools", "infisical.env")
        new = self.put("porch", "infisical.env")
        self.assertEqual(porch_paths.user_config_file("infisical.env", home=self.home), new)
        self.assertEqual(self.shell("infisical.env"), new)

    def test_op_sh_env_file_order(self):
        old = self.put("cush-tools", "op.env")
        script = f'. "{REPO}/lib/op.sh"; echo "$_CUSH_OP_ENV_FILE"'
        env = {k: v for k, v in os.environ.items() if not k.endswith("OP_ENV_FILE")}
        env["HOME"] = self.home
        self.assertEqual(run(["bash", "-c", script], env=env).stdout.strip(), old)
        self.assertEqual(run(["bash", "-c", script], env=dict(env, CUSH_OP_ENV_FILE="/c")).stdout.strip(), "/c")
        self.assertEqual(run(["bash", "-c", script],
                             env=dict(env, CUSH_OP_ENV_FILE="/c", PORCH_OP_ENV_FILE="/p")).stdout.strip(), "/p")


if __name__ == "__main__":
    unittest.main()

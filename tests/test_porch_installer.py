"""site/porch.sh (server installer) and site/install.sh (client installer):
POSIX syntax, frp pins, the dry-run plan under dash with stub commands, and
bin/publish-tarball's .sha256. No network, no root."""

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "lib"))

import porch_config  # noqa: E402
from porch_setup.relay import common  # noqa: E402

PORCH_SH = os.path.join(REPO, "site", "porch.sh")
INSTALL_SH = os.path.join(REPO, "site", "install.sh")
DASH = shutil.which("dash")


def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


class SyntaxTest(unittest.TestCase):
    def test_sh_n(self):
        for script in (PORCH_SH, INSTALL_SH):
            p = subprocess.run(["sh", "-n", script], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, script + p.stderr)

    @unittest.skipUnless(DASH, "dash not installed")
    def test_dash_n(self):
        for script in (PORCH_SH, INSTALL_SH):
            p = subprocess.run([DASH, "-n", script], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, script + p.stderr)

    def test_no_bashisms(self):
        for script in (PORCH_SH, INSTALL_SH):
            text = read(script)
            self.assertTrue(text.startswith("#!/bin/sh\n"), script)
            for pat in (r"\[\[", r"\$'\\", r"^\s*local\s", r"set -o pipefail", r"\$\{[A-Za-z_]+\[",
                        r"<<<", r"^\s*function\s"):
                self.assertIsNone(re.search(pat, text, re.M), f"{script}: {pat}")
            # one function, called last: a truncated `curl | sh` runs nothing
            self.assertTrue(text.rstrip().endswith('main "$@"'), script)


class PinTest(unittest.TestCase):
    def test_porch_sh_pins_match_relay(self):
        t = read(PORCH_SH)
        self.assertIn(f"FRP_VERSION={common.FRP_VERSION}\n", t)
        self.assertIn(f"FRP_SHA256_AMD64={common.FRP_SHA256['amd64']}\n", t)
        self.assertIn(f"FRP_SHA256_ARM64={common.FRP_SHA256['arm64']}\n", t)

    def test_install_sh_pins_match_relay(self):
        t = read(INSTALL_SH)
        self.assertIn(f"FRP_PINNED_VERSION={common.FRP_VERSION}\n", t)
        self.assertIn(f'PORCH_FRP_VERSION="${{PORCH_FRP_VERSION:-${{CUSH_FRP_VERSION:-{common.FRP_VERSION}}}}}"', t)
        self.assertIn(f"FRP_SHA256_LINUX_AMD64={common.FRP_SHA256['amd64']}\n", t)
        self.assertIn(f"FRP_SHA256_LINUX_ARM64={common.FRP_SHA256['arm64']}\n", t)
        for v in ("DARWIN_AMD64", "DARWIN_ARM64"):
            self.assertRegex(t, rf"FRP_SHA256_{v}=[0-9a-f]{{64}}\n")
        self.assertIn('verify_sha "$tmp/frp.tar.gz" "$frp_sha"', t)


STUB = "#!/bin/sh\necho \"$(basename \"$0\") $*\" >> \"$STUB_LOG\"\n{body}\n"


@unittest.skipUnless(DASH, "dash not installed")
class DryRunTest(unittest.TestCase):
    """PORCH_INSTALL_DRY_RUN=1 under dash, PATH = stubs + the basics."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.bin = os.path.join(self.tmp, "bin")
        os.mkdir(self.bin)
        self.log = os.path.join(self.tmp, "stub.log")
        # anything that would change the system must never be called for real
        for name in ("apt-get", "snap", "useradd", "visudo", "loginctl", "systemd-run",
                     "systemctl", "ufw", "curl", "install", "chown", "ln", "cloud-init"):
            self.stub(name)
        self.stub("ss")                       # nothing listens
        self.stub("id", 'case "$*" in "-u") echo 1000 ;; *) exit 1 ;; esac')   # no porch user yet
        self.root = os.path.join(self.tmp, "root")      # read-only checks look here (dry run)
        os.makedirs(os.path.join(self.root, "etc"))
        self.stub("getent", "exit 2")
        self.stub("uname", "echo x86_64")
        for tool in ("sh", "sed", "grep", "tr", "cut", "awk", "mktemp", "rm", "printf",
                     "basename", "head", "tail", "cat", "mkdir", "sleep"):
            real = shutil.which(tool)
            if real:
                os.symlink(real, os.path.join(self.bin, tool))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def stub(self, name, body="exit 0"):
        p = os.path.join(self.bin, name)
        with open(p, "w") as f:
            f.write(STUB.format(body=body))
        os.chmod(p, 0o755)

    def run_sh(self, *args, env=None):
        e = {"PATH": self.bin, "STUB_LOG": self.log, "PORCH_INSTALL_DRY_RUN": "1",
             "HOME": self.tmp, "TMPDIR": self.tmp, "PORCH_INSTALL_ROOT": self.root}
        e.update(env or {})
        return subprocess.run([DASH, PORCH_SH, *args], capture_output=True, text=True, env=e,
                              timeout=60)

    def stub_calls(self):
        try:
            return read(self.log).splitlines()
        except FileNotFoundError:
            return []

    def test_plan(self):
        p = self.run_sh("--staging", "--domain", "CJC1.com", "--dns-provider", "cloudflare")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        out = p.stdout
        plan = [ln for ln in out.splitlines() if ln.startswith("+ ")]
        text = "\n".join(out.splitlines())

        def idx(needle):
            for i, ln in enumerate(plan):
                if needle in ln:
                    return i
            self.fail(f"{needle!r} not in plan:\n" + "\n".join(plan))
        # nothing mutating ran: the stubs only saw read-only probes
        mut = [c for c in self.stub_calls() if c.split()[0] not in ("ss", "id", "getent", "uname")]
        self.assertEqual(mut, [], mut)
        self.assertIn("apt-get -o DPkg::Lock::Timeout=600 install -y -q haproxy python3", text)
        self.assertIn("python3-cryptography", text)    # porch share --e2e (lib/porch_seal.py)
        self.assertIn("snap_retry certbot --classic", text)
        self.assertIn("snap_retry snapd", text)
        idx("ln -sf /snap/bin/certbot /usr/local/bin/certbot")
        idx("--ip-address")
        idx("useradd -m -s /bin/bash porch")
        self.assertLess(idx("useradd"), idx("/home/porch/.porch-installer"))
        # the NOPASSWD:ALL line is an explicit, printed warning before anything runs
        self.assertIn("WARNING:", p.stderr)
        self.assertIn("passwordless sudo for every command", p.stderr)
        self.assertIn("porch ALL=(ALL) NOPASSWD:ALL", p.stderr)
        # sudoers: validated with visudo before it is installed
        self.assertIn("'porch ALL=(ALL) NOPASSWD:ALL'", text)
        self.assertLess(text.index("visudo -cf"), text.index("/etc/sudoers.d/90-porch"))
        idx("loginctl enable-linger porch")
        # tarball: downloaded, its .sha256 fetched, checked, and only then unpacked
        i_dl = idx("curl -fsSL --retry 3 -o")
        i_sum = idx("porch.tar.gz.sha256")
        i_chk = idx("sha256sum -c")
        i_tar = idx("tar -xzf")
        self.assertLess(i_dl, i_chk)
        self.assertLess(i_sum, i_chk)
        self.assertLess(i_chk, i_tar)
        # upgrade keeps data/: code copied without data/, data/ only adds missing files
        self.assertIn("--exclude=./data -cf - . | tar -C '/home/porch/porch'", text)
        self.assertIn("--skip-old-files", text)
        self.assertNotIn("rm -rf /home/porch/porch", text)
        # frp: pinned sha checked before it is unpacked
        i_frp = idx(f"frp_{common.FRP_VERSION}_linux_amd64.tar.gz")
        i_frpchk = idx(common.FRP_SHA256["amd64"])
        self.assertLess(i_frp, i_frpchk)
        self.assertLess(i_frpchk, idx("frps"))
        idx("ufw allow 80/tcp")
        idx("ufw allow 8443/tcp")
        wiz = plan[idx("systemd-run")]
        self.assertIn("--unit=porch-wizard --uid=porch --gid=porch", wiz)
        self.assertIn("-p WorkingDirectory=/home/porch/porch", wiz)
        self.assertIn("StandardOutput=append:/home/porch/wizard.log", wiz)
        self.assertTrue(wiz.endswith("/usr/bin/sudo -n /home/porch/porch/bin/porch setup --web "
                                     "--staging --no-qr --domain cjc1.com --dns-provider cloudflare"), wiz)
        self.assertLess(idx("systemctl stop porch-wizard"), idx("systemd-run"))
        # the 8443 rule the installer added is removed when the wizard exits
        self.assertRegex(wiz, r"-p ExecStopPost=/usr/bin/sudo -n \S*ufw delete allow 8443/tcp ")

    def test_sha_override_and_dir_and_no_wizard(self):
        sha = "AB" * 32
        p = self.run_sh("--no-wizard", "--dir", "/srv/porch",
                        env={"PORCH_TARBALL_SHA256": sha, "PORCH_TARBALL": "file:///x/t.tar.gz"})
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertNotIn(".sha256", p.stdout)
        self.assertIn(f"echo '{sha.lower()}  ", p.stdout)
        self.assertIn("install -d -m 0755 -o porch -g porch /srv/porch", p.stdout)
        self.assertIn("file:///x/t.tar.gz", p.stdout)
        self.assertNotIn("systemd-run", p.stdout)
        self.assertIn("wizard not started", p.stdout)

    def test_rejects_bad_input(self):
        for args in (["--domain", "x; rm -rf /"], ["--dns-provider", "a b"], ["--dir", "rel/path"],
                     ["--bogus"], ["--domain"]):
            p = self.run_sh(*args)
            self.assertNotEqual(p.returncode, 0, args)
            self.assertNotIn("+ ", p.stdout, args)
        p = self.run_sh(env={"PORCH_TARBALL_SHA256": "nothex"})
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("not a sha256", p.stderr)
        self.assertNotIn("tar -xzf", p.stdout)

    def test_port_80_held_by_something_else(self):
        self.stub("ss", 'case "$*" in *":80"*) echo \'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* '
                        'users:(("nginx",pid=1,fd=6))\' ;; esac')
        p = self.run_sh()
        self.assertEqual(p.returncode, 1)
        self.assertIn("port 80 is in use", p.stderr)
        self.assertIn("nginx", p.stderr)
        self.assertNotIn("apt-get", p.stdout)

    def test_port_held_by_haproxy_is_fine(self):
        self.stub("ss", 'case "$*" in *":443"*) echo \'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* '
                        'users:(("haproxy",pid=1,fd=7))\' ;; esac')
        p = self.run_sh("--no-wizard")
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_url_rereads_the_log(self):
        home = os.path.join(self.tmp, "home")
        os.mkdir(home)
        with open(os.path.join(home, "wizard.log"), "w") as f:
            f.write("Porch setup wizard\nOpen this link\n    https://203.0.113.7:8443/#k=old\n"
                    "    https://203.0.113.7:8443/#k=Ab_c-9\nfingerprint is exactly:\n    AA:BB\n")
        self.stub("getent", f'echo "porch:x:1001:1001::{home}:/bin/bash"')
        p = self.run_sh("--url")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("https://203.0.113.7:8443/#k=Ab_c-9", p.stdout)
        self.assertNotIn("#k=old", p.stdout)
        self.assertIn("AA:BB", p.stdout)
        self.assertIn("sudo sh porch.sh --url", p.stdout)
        os.unlink(os.path.join(home, "wizard.log"))
        self.assertEqual(self.run_sh("--url").returncode, 1)

    # ---- existing-server safety ------------------------------------------------
    def put(self, rel, text=""):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)
        return path

    def assert_refused(self, p, needle):
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn(needle, p.stderr)
        self.assertNotIn("apt-get", p.stdout)
        self.assertNotIn("useradd", p.stdout)

    def test_internal_port_held_by_another_program(self):
        self.stub("ss", 'case "$*" in *":9512"*) echo \'LISTEN 0 5 127.0.0.1:9512 0.0.0.0:* '
                        'users:(("node",pid=9,fd=3)) uid:1005 ino:1 sk:1\' ;; esac')
        self.assert_refused(self.run_sh(), "internal port(s) 9512")

    def test_internal_ports_of_the_porch_account_or_frps_are_fine(self):
        # an upgrade: porch's own services (its uid) and frps hold their ports
        home = os.path.join(self.tmp, "home")
        os.makedirs(home)
        with open(os.path.join(home, ".porch-installer"), "w") as f:
            f.write("x\n")
        self.stub("getent", f'echo "porch:x:1001:1001::{home}:/bin/bash"')
        self.stub("id", 'case "$*" in "-u") echo 0 ;; "-u porch") echo 1001 ;; porch) exit 0 ;; *) exit 1 ;; esac')
        self.stub("ss", 'case "$*" in *":9471"*) echo \'LISTEN 0 5 127.0.0.1:9471 0.0.0.0:* '
                        'users:(("python3",pid=9,fd=3)) uid:1001 ino:1 sk:1\' ;; '
                        '*":7000"*) echo \'LISTEN 0 5 0.0.0.0:7000 0.0.0.0:* users:(("frps",pid=8,fd=3)) uid:1001\' ;; esac')
        p = self.run_sh("--no-wizard")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("user porch exists", p.stdout)

    def test_existing_user_not_ours(self):
        home = os.path.join(self.tmp, "home")
        os.makedirs(home)
        self.stub("getent", f'echo "porch:x:1001:1001::{home}:/bin/bash"')
        self.stub("id", 'case "$*" in "-u") echo 0 ;; "-u porch") echo 1001 ;; porch) exit 0 ;; *) exit 1 ;; esac')
        self.assert_refused(self.run_sh(), "was not created by Porch")
        # an install from before the marker: our sudoers file says it is ours
        self.put("etc/sudoers.d/90-porch", "# Porch (porch.sh): porch setup and certificate renewals run sudo -n\n")
        p = self.run_sh("--no-wizard")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(f"{home}/.porch-installer", p.stdout)    # the marker is written now

    def test_foreign_porch_units(self):
        self.put("etc/systemd/system/porch-api.service", "[Service]\n")
        self.assert_refused(self.run_sh(), "/etc/systemd/system/porch-api.service")

    def test_docker_publishing_443(self):
        self.stub("docker", 'echo "web 0.0.0.0:443->443/tcp, [::]:443->443/tcp"')
        self.assert_refused(self.run_sh(), "docker container publishes")

    def test_foreign_certbot_in_usr_local(self):
        self.put("usr/local/bin/certbot", "#!/bin/sh\n")
        self.assert_refused(self.run_sh(), "/usr/local/bin/certbot exists")

    def test_warnings_for_web_servers_haproxy_and_certs(self):
        self.put("etc/nginx/nginx.conf")
        self.put("etc/haproxy/haproxy.cfg", "global\n\tdaemon\nfrontend web\n\tbind :443\n")
        self.put("etc/letsencrypt/live/example.com/fullchain.pem")
        p = self.run_sh("--no-wizard")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("nginx is installed", p.stderr)
        self.assertIn("already serves something", p.stderr)
        self.assertIn("certificates in /etc/letsencrypt: example.com", p.stderr)
        self.assertIn("never renews, revokes or deletes", p.stderr)
        # nothing in the plan touches /etc/letsencrypt
        self.assertNotIn("letsencrypt", "\n".join(l for l in p.stdout.splitlines() if l.startswith("+ ")))

    def test_check_is_read_only_and_reports(self):
        p = self.run_sh("--check", "--domain", "cjc1.com")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertNotIn("\n+ ", "\n" + p.stdout)              # no command printed or run
        mut = [c for c in self.stub_calls() if c.split()[0] not in ("ss", "id", "getent", "uname")
               and c != "ufw status"]
        self.assertEqual(mut, [], mut)
        for needle in ("What the installer would change", "packages (apt):", "haproxy", "snap:",
                       "create porch", "/etc/sudoers.d/90-porch", "loginctl enable-linger porch",
                       "/home/porch/porch (new)", "porch-wizard", "8443", "porch-pocket@pocket",
                       "nothing would stop the install. Nothing was changed."):
            self.assertIn(needle, p.stdout, needle)
        self.assertIn("NOPASSWD:ALL", p.stderr)
        # problems are reported, still exit 0, still nothing changed
        self.put("etc/systemd/system/porch-api.service", "[Service]\n")
        self.stub("ss", 'case "$*" in *":80"*) echo \'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* '
                        'users:(("nginx",pid=1,fd=6)) uid:0\' ;; esac')
        p = self.run_sh("--check")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("would stop here: port 80", p.stdout)
        self.assertIn("would stop here: systemd units named porch-*", p.stdout)
        self.assertIn("2 problem(s) above would stop the install", p.stdout)

    def test_internal_ports_match_render(self):
        from porch_setup import render
        m = re.search(r'^INTERNAL_PORTS="([0-9 ]+)"$', read(PORCH_SH), re.M)
        o = render.options(porch_config.load(env={"PORCH_CONFIG": "none"}), "fresh")
        want = {o[k] for k in ("auth_port", "status_port", "shortener_port", "landing_port",
                               "frp_vhost_port", "frp_dashboard_port", "acme_http_port")} | {7000}
        self.assertEqual(set(map(int, m.group(1).split())), want)
        self.assertIn("WIZARD_PORT=8443\n", read(PORCH_SH))

    def test_help(self):
        p = self.run_sh("--help")
        self.assertEqual(p.returncode, 0)
        self.assertIn("--dns-provider", p.stdout)


class PublishTarballTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("git") and os.path.exists(os.path.join(REPO, ".git")),
                         "needs a git checkout")
    def test_out_writes_matching_sha256(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        out = os.path.join(tmp, "t.tar.gz")
        p = subprocess.run([os.path.join(REPO, "bin", "publish-tarball"), "--out", out],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        with open(out, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        self.assertEqual(read(out + ".sha256"), f"{digest}  t.tar.gz\n")
        self.assertEqual(sorted(os.listdir(tmp)), ["t.tar.gz", "t.tar.gz.sha256"])   # no temp leftovers


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(DASH, "dash not installed")
class ClientInstallFailureTest(unittest.TestCase):
    """site/install.sh with CUSH_FORCE=1 replaces the old install only after
    every download verified (no network: a local tarball with a bad .sha256)."""

    def run_install(self, env_extra):
        env = {"PATH": os.environ["PATH"], "HOME": self.home,
               "CUSH_AUTH_URL": "https://tunnel.example.invalid"}
        env.update(env_extra)
        return subprocess.run([DASH, INSTALL_SH], capture_output=True, text=True, env=env,
                              stdin=subprocess.DEVNULL, timeout=60)

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        src = os.path.join(self.tmp, "src", "cush-tools", "bin")
        os.makedirs(src)
        with open(os.path.join(src, "bootstrap"), "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        self.tarball = os.path.join(self.tmp, "cush-tools.tar.gz")
        subprocess.run(["tar", "-czf", self.tarball, "-C", os.path.join(self.tmp, "src"),
                        "cush-tools"], check=True)
        with open(self.tarball + ".sha256", "w") as f:
            f.write("0" * 64 + "  cush-tools.tar.gz\n")

    def test_bad_sha_keeps_existing_install(self):
        dest = os.path.join(self.home, "cush-tools")
        os.makedirs(os.path.join(dest, "config"))
        marker = os.path.join(dest, "config", "frpc.toml")
        with open(marker, "w") as f:
            f.write("device_token = 'x'\n")
        p = self.run_install({"CUSH_DIR": dest, "CUSH_FORCE": "1",
                              "CUSH_REPO_TARBALL": "file://" + self.tarball})
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("does not match its published sha256", p.stderr)
        self.assertTrue(os.path.exists(marker), "the old install was removed before verifying")

    def which_dir(self, env_extra):
        """The install dir the script settles on, read from its "already
        exists" refusal (no PORCH_FORCE, so nothing is downloaded)."""
        p = self.run_install(env_extra)
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        out = p.stdout + p.stderr
        self.assertIn("already exists", out)
        return out

    def test_default_dir_is_porch(self):
        os.makedirs(os.path.join(self.home, "porch"))
        os.makedirs(os.path.join(self.home, "cush-tools"))
        out = self.which_dir({"PORCH_REPO_TARBALL": "file://" + self.tarball})
        self.assertIn(os.path.join(self.home, "porch") + " already exists", out)

    def test_existing_cush_tools_dir_is_kept(self):
        # a machine paired before the rename: upgrade ~/cush-tools in place
        os.makedirs(os.path.join(self.home, "cush-tools"))
        out = self.which_dir({"PORCH_REPO_TARBALL": "file://" + self.tarball})
        self.assertIn(os.path.join(self.home, "cush-tools") + " already exists", out)
        self.assertFalse(os.path.exists(os.path.join(self.home, "porch")))

    def test_porch_names_win_over_cush_names(self):
        a, b = os.path.join(self.home, "a"), os.path.join(self.home, "b")
        os.makedirs(a)
        os.makedirs(b)
        out = self.which_dir({"PORCH_DIR": a, "CUSH_DIR": b,
                              "PORCH_REPO_TARBALL": "file://" + self.tarball})
        self.assertIn(a + " already exists", out)
        out = self.which_dir({"CUSH_DIR": b, "CUSH_REPO_TARBALL": "file://" + self.tarball})
        self.assertIn(b + " already exists", out)

    def test_porch_force_replaces_only_after_verifying(self):
        dest = os.path.join(self.home, "porch")
        os.makedirs(dest)
        p = self.run_install({"PORCH_DIR": dest, "PORCH_FORCE": "1",
                              "PORCH_AUTH_URL": "https://tunnel.example.invalid",
                              "PORCH_REPO_TARBALL": "file://" + self.tarball})
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("does not match its published sha256", p.stderr)
        self.assertTrue(os.path.isdir(dest))

    def test_template_copy_refuses_to_run(self):
        # the raw repo copy has no server: it says so before downloading anything
        p = self.run_install({"CUSH_AUTH_URL": "", "CUSH_DIR": os.path.join(self.home, "c")})
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("template copy of install.sh", p.stderr)
        self.assertNotIn("downloading", p.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.home, "c")))

    def test_refuses_home_and_relative(self):
        for d in (self.home, self.home + "/", "relative/dir", "/"):
            p = self.run_install({"CUSH_DIR": d, "CUSH_FORCE": "1",
                                  "CUSH_REPO_TARBALL": "file://" + self.tarball})
            self.assertEqual(p.returncode, 1, d)
            self.assertTrue(os.path.isdir(self.home))

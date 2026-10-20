"""lib/daemonize.py log permissions and bin/secure-entry's daemon log line."""

import os
import re
import stat
import subprocess
import tempfile
import time
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DAEMONIZE = os.path.join(_ROOT, "lib", "daemonize.py")


class DaemonizeLogTest(unittest.TestCase):
    def _run(self, log):
        subprocess.run(["python3", DAEMONIZE, log, "sh", "-c", "echo hello"], check=True)
        for _ in range(100):
            if os.path.exists(log) and open(log).read().strip() == "hello":
                break
            time.sleep(0.05)
        self.assertEqual(open(log).read().strip(), "hello")
        return stat.S_IMODE(os.stat(log).st_mode)

    def test_new_log_is_0600(self):
        with tempfile.TemporaryDirectory() as d:
            old = os.umask(0o002)
            try:
                self.assertEqual(self._run(os.path.join(d, "x.log")), 0o600)
            finally:
                os.umask(old)

    def test_existing_world_readable_log_is_tightened(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "x.log")
            open(log, "w").close()
            os.chmod(log, 0o664)
            self.assertEqual(self._run(log), 0o600)


class SecureEntryDaemonLogTest(unittest.TestCase):
    def test_daemonized_child_does_not_log_token_url(self):
        # Every `echo "Secure entry: $ENTRY_URL"` must be on the parent's side
        # (inside the cush_daemonize success block) or in the not-daemonized
        # branch; the daemonized child's stdout is logs/<name>.log.
        src = open(os.path.join(_ROOT, "bin", "secure-entry")).read()
        tail = src[src.index('tunnel_state_register "$NAME" "secure-entry"'):]
        m = re.search(r'if \[ "\$\{_CUSH_DAEMONIZED:-\}" = "1" \]; then\n(.*?)\nelse\n(.*?)\nfi',
                      tail, re.S)
        self.assertIsNotNone(m)
        self.assertNotIn("ENTRY_URL", m.group(1))
        self.assertNotIn("SECURE_ENTRY_TOKEN", m.group(1))
        self.assertIn("ENTRY_URL", m.group(2))
        self.assertEqual(tail[:m.start()].count("ENTRY_URL"), 0)


if __name__ == "__main__":
    unittest.main()

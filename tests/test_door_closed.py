"""The closed-door page frps serves for a tunnel name with no live door."""
import os
import re
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "lib"))

import porch_config  # noqa: E402
import porch_http  # noqa: E402
from porch_setup import render  # noqa: E402

SRC = os.path.join(REPO, "site", "door-closed.html")


def rendered(cfg):
    with open(SRC, encoding="utf-8") as f:
        html = f.read()
    html = porch_config.site_render(html, cfg)
    return html.replace("/*PORCH_FONTS*/", porch_http.inline_font_faces(), 1)


class DoorClosedPageTest(unittest.TestCase):
    def test_self_contained(self):
        # frps serves it on the dead host, where nothing else can load.
        html = rendered(porch_config.load(env={"PORCH_CONFIG": "none"}))
        self.assertNotIn("/*PORCH_FONTS*/", html)
        self.assertEqual(html.count("data:font/woff2;base64,"), 4)
        refs = re.findall(r'(?:src|href)\s*=\s*"([^"]+)"', html)
        self.assertEqual(refs, ["https://panel.cush.rocks/"])
        self.assertNotIn("url(http", html)
        self.assertLess(len(html), 200_000)
        self.assertIn("<title>Door closed", html)
        # the hostname goes in as text, never markup
        self.assertIn("textContent = host", html)
        self.assertNotIn("innerHTML", html)

    def test_panel_link_follows_the_domain(self):
        cfg = porch_config.load(env={"PORCH_CONFIG": "none", "PORCH_DOMAIN": "example.org"})
        html = rendered(cfg)
        self.assertIn('href="https://panel.example.org/"', html)
        self.assertNotIn("cush.rocks", html)

    def test_ask_to_reopen(self):
        html = rendered(porch_config.load(env={"PORCH_CONFIG": "none"}))
        # posts to the landing host's statusserver, as a simple (no preflight)
        # cross-origin request that carries no cookies
        self.assertIn("var API = 'https://tunnel.cush.rocks/api/reopen-requests';", html)
        self.assertIn("'Content-Type': 'text/plain'", html)
        self.assertEqual(html.count("credentials: 'omit'"), 2)
        self.assertIn("body: JSON.stringify({ host: host, note: note.value.slice(0, 40) })", html)
        self.assertIn('maxlength="40"', html)
        # every visible string goes in as text
        self.assertNotIn("innerHTML", html)
        self.assertNotIn("insertAdjacentHTML", html)
        self.assertNotIn("document.write", html)
        for state in ("waiting", "approved", "denied", "expired", "error"):
            self.assertIn(f"'{state}'", html)
        self.assertIn("The owner said not now.", html)
        self.assertIn("No answer yet.", html)
        # storage is a convenience that may throw (private mode)
        uses = [ln for ln in html.splitlines() if "sessionStorage" in ln]
        self.assertEqual(len(uses), 2)
        for ln in uses:
            self.assertIn("try {", ln)
        # phones: 16px input (no iOS zoom), 48px controls, [hidden] wins over display rules
        self.assertRegex(html, r"\.ask input \{[^}]*height: 48px[^}]*font: 400 16px")
        self.assertIn("[hidden] { display: none !important; }", html)

    def test_reopen_api_follows_the_domain(self):
        cfg = porch_config.load(env={"PORCH_CONFIG": "none", "PORCH_DOMAIN": "example.org"})
        html = rendered(cfg)
        self.assertIn("var API = 'https://tunnel.example.org/api/reopen-requests';", html)

    def test_frps_points_at_it(self):
        cfg = porch_config.load(env={"PORCH_CONFIG": "none"})
        out = render.render_frps(cfg, "pw", web_root="/srv/porch-landing")
        self.assertIn('custom404Page = "/srv/porch-landing/door-closed.html"', out)


if __name__ == "__main__":
    unittest.main()

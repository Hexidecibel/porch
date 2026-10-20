"""Every app page links porch.css, every app serves it, and each page's CSP
allows exactly that (style/font from 'self') and nothing broader.

Stdlib unittest; each server runs on 127.0.0.1:<ephemeral> in a thread.
"""

import http.client
import os
import re
import sys
import tempfile
import threading
import unittest
from pathlib import Path

LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib")
sys.path.insert(0, LIB)

import porch_http as ph  # noqa: E402
import chatserver  # noqa: E402
import dropserver  # noqa: E402
import exchangeserver  # noqa: E402
import formserver  # noqa: E402
import mediaserver  # noqa: E402
import musicserver  # noqa: E402
import pasteserver  # noqa: E402
import secureentry  # noqa: E402
import serveserver  # noqa: E402
import statusserver  # noqa: E402
import viewserver  # noqa: E402
import sealserver  # noqa: E402
import porch_seal  # noqa: E402

FONT_PATH = next(p for p in ph.ASSETS if p.endswith(".woff2"))


class AppAssetTests(unittest.TestCase):

    def serve(self, handler):
        srv = ph.make_server(handler, 0, "127.0.0.1", tag="t")
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return srv.server_address[1]

    def get(self, port, path):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        c.request("GET", path, headers={"Host": f"127.0.0.1:{port}"})
        r = c.getresponse()
        body = r.read()
        c.close()
        return r, body

    def check_app(self, port, page="/", base="", page_status=200, css_href=None):
        r, body = self.get(port, page)
        self.assertEqual(r.status, page_status, page)
        href = css_href if css_href is not None else base + ph.PORCH_CSS_PATH
        self.assertIn(f'<link rel="stylesheet" href="{href}">'.encode(), body)
        csp = r.getheader("Content-Security-Policy")
        self.assertIn("default-src 'none'", csp)
        self.assertRegex(csp, r"style-src 'self'( 'nonce-[^']+')?;")
        self.assertIn("font-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn("*", csp)
        self.assertNotIn("https:", csp)
        # every <style>/<script> on the page carries the response's nonce
        m = re.search(r"'nonce-([^']+)'", csp)
        if m:
            for tag in re.findall(rb"<(?:style|script)(?![^>]*\bsrc=)[^>]*>", body):
                if b'type="application/json"' in tag:
                    continue
                self.assertIn(f'nonce="{m.group(1)}"'.encode(), tag)
        self.assertNotIn(b' style="', body)
        r, css = self.get(port, base + ph.PORCH_CSS_PATH)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.getheader("Content-Type"), "text/css; charset=utf-8")
        self.assertIn("immutable", r.getheader("Cache-Control"))
        r, font = self.get(port, base + FONT_PATH)
        self.assertEqual((r.status, r.getheader("Content-Type")), (200, "font/woff2"))
        r, _ = self.get(port, base + "/__porch-assets/../" + os.path.basename(LIB))
        self.assertEqual(r.status, 404)

    def test_drop(self):
        d = tempfile.mkdtemp()
        H = type("H", (dropserver.DropHandler,), {"upload_dir": Path(d), "_quota": None})
        self.check_app(self.serve(H))

    def test_media(self):
        d = tempfile.mkdtemp()
        H = type("H", (mediaserver.MediaHandler,), {"media_dir": Path(d), "_quota": None})
        self.check_app(self.serve(H))

    def test_music(self):
        d = tempfile.mkdtemp()
        H = type("H", (musicserver.MusicHandler,), {"music_dir": Path(d)})
        self.check_app(self.serve(H))

    def test_exchange_send_and_receive(self):
        E = exchangeserver.ExchangeHandler
        saved = (E.mode, E.send_html, E.receive_html)
        self.addCleanup(lambda: (setattr(E, "mode", saved[0]), setattr(E, "send_html", saved[1]),
                                 setattr(E, "receive_html", saved[2])))
        E.send_html = exchangeserver.render_send_html("text with <N> in it", "n")
        E.receive_html = exchangeserver.RECEIVE_HTML.replace("EXCHANGE_NAME", "n")
        port = self.serve(E)
        E.mode = "send"
        self.check_app(port)
        _, body = self.get(port, "/")
        self.assertIn(b"text with &lt;N&gt; in it", body)   # escaped, never a nonce slot
        E.mode = "receive"
        self.check_app(port)

    def test_paste(self):
        fields = {"PASTE_CONTENT": "x", "PASTE_NAME": "n", "PASTE_LANG": "", "PASTE_FOOTER": "f"}
        H = type("H", (pasteserver.PasteHandler,),
                 {"paste_parts": pasteserver.render_paste_parts(fields)})
        self.check_app(self.serve(H))

    def test_chat(self):
        page = (chatserver.CHAT_HTML.replace("__PORCH_CSS__", ph.porch_css_tag())
                .replace("__MARK__", ph.porch_mark(16)).replace("CHAT_NAME", "n"))
        H = type("H", (chatserver.ChatHandler,), {"chat_parts": tuple(page.split("CSP_NONCE"))})
        self.check_app(self.serve(H))

    def test_form(self):
        H = type("H", (formserver.FormHandler,), {
            "form_html": formserver.FORM_HTML.replace("FORM_TITLE", "T")
            .replace("FORM_SUBTITLE", "t").replace("FORM_FIELDS", "")})
        self.check_app(self.serve(H))

    def test_serve_listing(self):
        d = tempfile.mkdtemp()
        Path(d, "a.txt").write_text("a")
        H = serveserver.make_handler(d, allow_list=True)
        H.log_message = lambda *a: None
        port = self.serve(H)
        self.check_app(port)
        r, _ = self.get(port, "/")
        csp = r.getheader("Content-Security-Policy")
        self.assertIn("sandbox allow-same-origin", csp)
        self.assertNotIn("allow-scripts", csp)
        self.assertNotIn("script-src", csp)
        # a served file keeps its old CSP, not the listing's
        r, _ = self.get(port, "/a.txt")
        self.assertIn(r.getheader("Content-Security-Policy"),
                      (serveserver.CSP_SANDBOX, serveserver.CSP_SCRIPTS))

    def test_view(self):
        d = tempfile.mkdtemp()
        for name, data in (("a.md", "# hi"), ("a.pdf", "%PDF-1.4\n"), ("a.log", "x\n")):
            p = Path(d, name)
            p.write_text(data)
            H = viewserver.make_handler(str(p), "v", follow=name == "a.log", start_follower=False)
            H.log_message = lambda *a: None
            self.check_app(self.serve(H))

    def test_seal(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("python3-cryptography is not installed")
        d = tempfile.mkdtemp()
        import io
        p = str(Path(d, "a.pseal"))
        porch_seal.seal_file(io.BytesIO(b"hi"), p, "a.txt", "text/plain")
        H = sealserver.make_handler(p, "s")
        H.log_message = lambda *a: None
        self.check_app(self.serve(H))

    def test_status_refusal_page(self):
        H = type("H", (statusserver.StatusHandler,), {"devices_path": "/nonexistent"})
        # relative link, so the console also works below a path prefix
        self.check_app(self.serve(H), page_status=403,
                       css_href=ph.PORCH_CSS_PATH.lstrip("/"))

    def test_secure_entry_assets_only_below_token(self):
        S = secureentry.SecureEntryHandler
        saved = S.token
        self.addCleanup(setattr, S, "token", saved)
        S.token = "t" * 24
        port = self.serve(S)
        self.check_app(port, page=f"/{S.token}/", base=f"/{S.token}")
        for path in (ph.PORCH_CSS_PATH, FONT_PATH, "/wrong" + "x" * 20 + ph.PORCH_CSS_PATH):
            self.assertEqual(self.get(port, path)[0].status, 404, path)


class PorchCssPhoneTests(unittest.TestCase):
    """Design-system rules every page gets on a phone."""

    css = Path(__file__).resolve().parent.parent.joinpath("lib", "porch.css").read_text()

    def rule(self, selector):
        m = re.search(re.escape(selector) + r"\{([^}]*)\}", self.css)
        self.assertIsNotNone(m, selector)
        return m.group(1)

    def test_inputs_are_16px_so_ios_does_not_zoom(self):
        body = self.rule(".p-input,.p-textarea,.p-select")
        size = int(re.search(r"font:\s*\d+\s+(\d+)px", body).group(1))
        self.assertGreaterEqual(size, 16)

    def test_shell_pads_the_safe_areas(self):
        body = self.rule(".p-shell")
        for side in ("left", "right", "bottom"):
            self.assertIn(f"env(safe-area-inset-{side})", body)

    def test_small_buttons_are_44px_for_fingers(self):
        self.assertRegex(self.css, r"@media \(pointer:coarse\)\{\.p-btn--sm\{min-height:44px\}")


if __name__ == "__main__":
    unittest.main()

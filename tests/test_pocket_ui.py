"""The Porch app shell (lib/pocket_static/app.html + its scripts): static
checks that need no new server routes.

- the shell passes mobile_markup's responsive and picker checks;
- no style="" attributes, inline handlers or inline <style>/<script> code;
- no innerHTML / outerHTML / insertAdjacentHTML / document.write / eval in
  any static script (every string reaches the DOM through textContent);
- every <script> is a hashed /static/ path (or the nonced JSON config), the
  hashed paths resolve in pocket_assets and are served immutable;
- every element id the scripts bind at load exists in the shell.
"""
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mobile_markup  # noqa: E402  (tests/ helper)
import test_pocketserver as tp  # noqa: E402  (ServerCase, OWNER_TOKEN)

_LIB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'lib')
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
import pocket_assets  # noqa: E402

STATIC = os.path.join(_LIB, 'pocket_static')
SHELL = open(os.path.join(STATIC, 'app.html'), encoding='utf-8').read()
APP_JS = ('core.js', 'home.js', 'doors.js', 'inspect.js', 'requests.js', 'people.js', 'settings.js', 'boot.js')
ASSET_RE = re.compile(r'__ASSET_([A-Za-z0-9_.-]+)__')


def static_js():
    return sorted(f for f in os.listdir(STATIC) if f.endswith('.js'))


def read(name):
    with open(os.path.join(STATIC, name), encoding='utf-8') as f:
        return f.read()


def rendered():
    """The shell as the server fills it (head from pocketserver)."""
    head = tp.ps.HEAD_HTML.replace('__PORCH_CSS__', '').replace('__GROUND__', '#121014')
    return pocket_assets.render_shell(head, 'Pocket', 'n0nce', '{}')


class ShellMarkupTests(unittest.TestCase):
    def test_responsive(self):
        mobile_markup.check_responsive(self, rendered())
        self.assertIn('viewport-fit=cover', rendered())

    def test_pickers(self):
        mobile_markup.check_pickers(self, rendered(), multiple=('fileInput', 'photoInput'),
                                    single=('sealInput', 'sealPhotoInput'))

    def test_no_inline_style_or_handlers(self):
        self.assertIsNone(re.search(r'\sstyle\s*=', SHELL), 'style="" attribute in the shell')
        self.assertIsNone(re.search(r'<[^>]*\son[a-z]+\s*=', SHELL), 'inline event handler in the shell')
        self.assertNotIn('<style', SHELL)
        self.assertNotIn('javascript:', SHELL.lower())

    def test_scripts_are_hashed_or_nonced_json(self):
        tags = re.findall(r'<script\b([^>]*)>(.*?)</script>', SHELL, re.S)
        self.assertTrue(tags)
        for attrs, body in tags:
            if 'type="application/json"' in attrs:
                self.assertIn('nonce="__NONCE__"', attrs)
                self.assertEqual(body.strip(), '__CFG_JSON__')
                continue
            self.assertEqual(body.strip(), '', 'inline script code')
            src = re.search(r'src="([^"]+)"', attrs).group(1)
            self.assertIn('defer', attrs)
            self.assertTrue(src == '/static/seal.js' or ASSET_RE.fullmatch(src), src)
        # core first (the globals share.js needs), boot last
        order = ASSET_RE.findall(' '.join(a for a, _ in tags))
        self.assertLess(order.index('core.js'), order.index('share.js'))
        self.assertLess(order.index('home.js'), order.index('share.js'))
        self.assertEqual(order[-1], 'boot.js')
        for name in APP_JS:
            self.assertIn(name, order)

    def test_assets_resolve_hashed(self):
        names = ASSET_RE.findall(SHELL)
        self.assertIn('app.css', names)
        for name in names:
            url = pocket_assets.asset_url(name)
            stem, ext = os.path.splitext(name)
            self.assertRegex(url, r'^/static/' + re.escape(stem) + r'\.[0-9a-f]{12}' + re.escape(ext) + '$')
            data, ctype = pocket_assets.lookup(url)
            self.assertTrue(data)
            self.assertIn('css' if ext == '.css' else 'javascript', ctype)

    def test_no_markup_sinks_in_scripts(self):
        bad = re.compile(r'\.innerHTML\b|\.outerHTML\b|insertAdjacentHTML|document\.write|\beval\s*\(|new\s+Function\s*\('
                         r"|setAttribute\(\s*['\"](style|on[a-z]+)['\"]")
        for name in static_js():
            m = bad.search(read(name))
            self.assertIsNone(m, f'{name}: {m and m.group(0)}')

    def test_no_dialog_or_alert(self):
        for name in APP_JS + ('share.js',):
            src = read(name)
            for pat in (r'\balert\s*\(', r'(?<![.\w])confirm\s*\(', r'\bprompt\s*\(\s*[\'"]'):
                self.assertIsNone(re.search(pat, src), f'{name}: {pat}')

    def test_bound_ids_exist(self):
        ids = set(re.findall(r'\bid="([^"]+)"', SHELL))
        for name in ('core.js', 'home.js', 'share.js', 'boot.js'):
            for ref in re.findall(r"\$\('([A-Za-z][\w-]*)'\)", read(name)):
                self.assertIn(ref, ids, f'{name} binds #{ref}, missing from app.html')

    def test_app_css_rules(self):
        css = read('app.css')
        self.assertIn('prefers-reduced-motion', css)
        self.assertIn('safe-area-inset-bottom', css)
        self.assertIn('pointer:coarse', css)
        for bp in ('min-width:700px', 'min-width:1024px'):
            self.assertIn(bp, css)

    @unittest.skipUnless(shutil.which('node'), 'node is not installed')
    def test_scripts_parse(self):
        for name in static_js():
            r = subprocess.run(['node', '--check', os.path.join(STATIC, name)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f'{name}: {r.stderr}')

    def test_sheet_close_events_ignore_a_reopened_sheet(self):
        """A dialog's close event arrives as a task: when a result sheet
        opens right after a form sheet closes, the stale event must not wipe
        the new sheet (it did: an empty "Restart needed")."""
        for name, guard in (('core.js', 'if(d.open) return;'), ('share.js', 'if(sheet.open) return;')):
            src = read(name)
            for m in re.finditer(r"addEventListener\('close', \(\) ?=> ?\{", src):
                self.assertIn(guard, src[m.end():m.end() + 300], name)

    def test_redraws_only_hold_for_typing(self):
        core = read('core.js')
        self.assertIn('P.typingIn = function', core)
        for name in ('doors.js', 'people.js'):
            self.assertNotIn('pane.contains(document.activeElement)', read(name), name)

    def test_sw_pairing_code(self):
        sw = read('sw.js')
        if 'pairing' not in sw:
            self.skipTest('sw.js has no pairing push yet (WS2)')
        self.assertRegex(sw, r'\[A-Z\]\{4\}-\[0-9\]\{4\}')
        self.assertIn('/#/requests/pairing/', sw)


class ShellAssetServeTests(tp.ServerCase):
    def test_hashed_assets_are_immutable(self):
        for name in set(ASSET_RE.findall(SHELL)):
            r, data = self.owner('GET', pocket_assets.asset_url(name))
            self.assertEqual(r.status, 200, name)
            self.assertIn('immutable', r.getheader('Cache-Control') or '')
            self.assertEqual(r.getheader('X-Content-Type-Options'), 'nosniff')
            self.assertTrue(data)

    def test_unknown_static_is_404(self):
        r, _ = self.owner('GET', '/static/core.000000000000.js')
        self.assertEqual(r.status, 404)
        for gone in ('/static/legacy.html', '/static/app.html', '/legacy.html'):
            r, _ = self.owner('GET', gone)
            self.assertEqual(r.status, 404, gone)


class ShellServeTests(tp.ServerCase):
    """GET / is the Porch app shell, filled in by the server."""

    def page(self, ua=None):
        r, body = self.owner('GET', '/', origin=False,
                             headers={'User-Agent': ua} if ua else None)
        self.assertEqual(r.status, 200)
        return r, body.decode()

    def test_legacy_page_is_gone(self):
        self.assertFalse(os.path.exists(os.path.join(STATIC, 'legacy.html')))
        self.assertNotIn('legacy.html', pocket_assets.NOT_HASHED)

    def test_placeholders_filled(self):
        _, page = self.page()
        body = re.sub(r'<!--.*?-->', '', page, flags=re.S)
        self.assertIsNone(re.search(r'__[A-Z][A-Za-z0-9_.]*__', body))
        self.assertIn('<title>Porch</title>', page)
        self.assertIn('/__porch-assets/porch.', page)          # __HEAD__

    def test_csp_and_permissions_exact(self):
        r, page = self.page()
        nonce = re.search(r'<script type="application/json" id="cfg" nonce="([^"]+)">', page).group(1)
        self.assertEqual(r.getheader('Content-Security-Policy'),
                         "default-src 'none'; "
                         f"script-src 'self' 'nonce-{nonce}'; style-src 'self' 'nonce-{nonce}'; "
                         "font-src 'self'; img-src 'self' data: blob:; connect-src 'self'; "
                         "manifest-src 'self'; worker-src 'self'; "
                         "form-action 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.assertEqual(r.getheader('Permissions-Policy'),
                         'publickey-credentials-get=(self), publickey-credentials-create=(self), '
                         'camera=(), microphone=(), geolocation=()')
        self.assertEqual(r.getheader('Cache-Control'), 'no-store')
        _, again = self.page()
        self.assertNotIn(nonce, again)                         # fresh per response

    def test_config_block(self):
        _, page = self.page(ua='Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)')
        raw = re.search(r'id="cfg" nonce="[^"]+">(.*?)</script>', page, re.S).group(1)
        self.assertNotIn('<', raw)
        cfg = json.loads(raw)
        self.assertIsInstance(cfg['maxFile'], int)
        self.assertGreater(cfg['maxFile'], 0)
        self.assertIs(cfg['ios'], True)
        self.assertEqual(cfg['title'], 'Porch')
        self.assertIn('tunnel_base', cfg)
        if tp.ps.APP_VERSION:
            self.assertRegex(cfg['version'], r'^[0-9a-f]{4,40}$')
        _, page = self.page(ua='Mozilla/5.0 (X11; Linux x86_64)')
        self.assertIn('"ios": false', page)

    def test_every_asset_hashed_and_precached(self):
        _, page = self.page()
        refs = re.findall(r'(?:src|href)="(/static/[^"]+)"', page)
        self.assertIn('/static/seal.js', refs)                 # read per request, not hashed
        hashed = [u for u in refs if u != '/static/seal.js']
        for name in APP_JS + ('app.css', 'qr.js', 'share.js', 'tus.js'):
            self.assertIn(pocket_assets.asset_url(name), hashed, name)
        sw = tp.ps.SERVICE_WORKER_JS
        pre = re.search(r"const PRECACHE = '([^']+)'", sw).group(1)
        r, raw = self.owner('GET', pre)
        self.assertEqual(r.status, 200)
        listed = set(json.loads(raw))
        for u in hashed:
            self.assertIn(u, listed)
        for f in os.listdir(STATIC):                           # nothing left out
            if f.endswith(('.js', '.css')) and f not in pocket_assets.NOT_HASHED:
                self.assertIn(pocket_assets.asset_url(f), listed, f)
        css = re.search(r'href="(/__porch-assets/porch\.[0-9a-f]{12}\.css)"', page).group(1)
        self.assertIn(css, listed)

    def test_share_target_redirect_reaches_home(self):
        body, ctype = tp.multipart([('text', 'hello from the phone')], [('a.txt', b'hi')])
        r, _ = self.owner('POST', '/share', body, ctype=ctype)
        self.assertEqual(r.status, 303)
        loc = r.getheader('Location')
        self.assertTrue(loc.startswith('/?shared=1&'), loc)
        self.assertRegex(loc, r'[?&]f=a\.txt')
        self.assertRegex(loc, r'[?&]c=')
        home = read('home.js')
        for needle in ("qs.get('shared') === '1'", "qs.getAll('f')", "qs.get('c')", 'history.replaceState'):
            self.assertIn(needle, home)

INSTALL_HARNESS = r"""
const vm = require('vm'), fs = require('fs');
const src = fs.readFileSync(process.argv[1], 'utf8');
const cases = JSON.parse(process.argv[2]);
const out = {};
for (const [name, c] of Object.entries(cases)) {
  const listeners = {};
  const store = {};
  const subs = {};
  const P = {el: () => ({}), icon: () => ({}), btn: () => ({}), toast: () => {},
    on: (n, f) => { (subs[n] = subs[n] || []).push(f); return () => {}; },
    emit: (n, d) => (subs[n] || []).forEach((f) => f(d))};
  const win = {Porch: P, addEventListener: (n, f) => { listeners[n] = f; },
    matchMedia: (q) => ({matches: !!c.standalone && q.includes('standalone')})};
  const ctx = {window: win, navigator: {userAgent: c.ua, platform: c.platform || '', maxTouchPoints: c.touch || 0},
    localStorage: {getItem: (k) => store[k] || null, setItem: (k, v) => { store[k] = v; }},
    matchMedia: win.matchMedia, location: {origin: 'https://pocket.example'}, Promise};
  vm.runInNewContext(src, ctx);
  const before = P.installState();
  if (c.bip) listeners.beforeinstallprompt({preventDefault() {}, prompt() {}, userChoice: Promise.resolve({})});
  const after = P.installState();
  if (listeners.appinstalled) listeners.appinstalled();
  out[name] = [before, after, P.installState()];
}
console.log(JSON.stringify(out));
"""

IOS_SAFARI = ('Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 '
              '(KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1')
IOS_CHROME = IOS_SAFARI.replace('Version/18.0', 'CriOS/129.0.6668.69')
IPADOS = ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 '
          '(KHTML, like Gecko) Version/18.0 Safari/605.1.15')
ANDROID = ('Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) '
           'Chrome/129.0.0.0 Mobile Safari/537.36')


@unittest.skipUnless(shutil.which('node'), 'node not installed')
class InstallPromptTests(unittest.TestCase):
    """install.js: which card each browser gets (Home + You > About)."""

    def states(self, cases):
        r = subprocess.run(['node', '-e', INSTALL_HARNESS, os.path.join(STATIC, 'install.js'), json.dumps(cases)],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_states(self):
        got = self.states({
            'ios_safari': {'ua': IOS_SAFARI},
            'ios_chrome': {'ua': IOS_CHROME},
            'ios_firefox': {'ua': IOS_SAFARI.replace('Version/18.0', 'FxiOS/131.0')},
            'ios_edge': {'ua': IOS_SAFARI.replace('Version/18.0', 'EdgiOS/129.0')},
            'ipados_safari': {'ua': IPADOS, 'platform': 'MacIntel', 'touch': 5},
            'mac_safari': {'ua': IPADOS, 'platform': 'MacIntel', 'touch': 0},
            'android_no_event': {'ua': ANDROID},
            'android_event': {'ua': ANDROID, 'bip': True},
            'ios_standalone': {'ua': IOS_SAFARI, 'standalone': True},
            'android_standalone': {'ua': ANDROID, 'standalone': True, 'bip': True},
        })
        self.assertEqual(got['ios_safari'][0], 'ios-safari')
        for k in ('ios_chrome', 'ios_firefox', 'ios_edge'):
            self.assertEqual(got[k][0], 'ios-other', k)
        self.assertEqual(got['ipados_safari'][0], 'ios-safari')
        self.assertIsNone(got['mac_safari'][0])                 # a real Mac: nothing
        self.assertEqual(got['android_no_event'], [None, None, None])   # never the iOS card
        self.assertEqual(got['android_event'], [None, 'prompt', None])  # appinstalled hides it
        self.assertEqual(got['ios_standalone'], [None, None, None])
        self.assertEqual(got['android_standalone'], [None, None, None])

    def test_wired_into_shell_home_and_about(self):
        self.assertIn('__ASSET_install.js__', SHELL)
        self.assertLess(SHELL.index('__ASSET_core.js__'), SHELL.index('__ASSET_install.js__'))
        self.assertLess(SHELL.index('__ASSET_install.js__'), SHELL.index('__ASSET_home.js__'))
        self.assertIn("P.installCard('home')", read('home.js'))
        self.assertIn("P.installCard('about')", read('settings.js'))

    def test_manifest_is_installable(self):
        m = pocket_assets.manifest('Porch')
        self.assertEqual((m['id'], m['start_url'], m['display']), ('/', '/', 'standalone'))
        self.assertTrue(m['name'] and m['short_name'])
        sizes = {i['sizes'] for i in m['icons'] if i['type'] == 'image/png'}
        self.assertTrue({'192x192', '512x512'} <= sizes, sizes)


if __name__ == '__main__':
    unittest.main()

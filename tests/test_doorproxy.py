"""Tests for lib/doorproxy.py and lib/door_state.py. Stdlib unittest only.

A real upstream app and a real door proxy run on 127.0.0.1:0 in daemon
threads, against a temp state dir. Nothing is launched or killed: the proxy's
closer is a recorder. Door flags (lib/door-flags.sh) run through bash with a
temp TUNNEL_STATE_DIR.
"""

import hashlib
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
_LIB = os.path.join(_HERE, '..', 'lib')
sys.path.insert(0, _LIB)
import door_state  # noqa: E402
import doorproxy  # noqa: E402
import porch_auth  # noqa: E402
import porch_http  # noqa: E402

NAME = 'doortest'
HOST = f'{NAME}.tunnel.cush.rocks'
BIG = bytes(range(256)) * 4096          # 1 MiB


def iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


class Upstream(BaseHTTPRequestHandler):
    """The app behind the door: echoes what it got."""
    protocol_version = 'HTTP/1.1'
    seen = []

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype='application/json', extra=()):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def _body(self):
        if self.headers.get('Transfer-Encoding', '').lower() == 'chunked':
            out = b''
            while True:
                size = int(self.rfile.readline().split(b';')[0], 16)
                if size == 0:
                    self.rfile.readline()
                    return out
                out += self.rfile.read(size)
                self.rfile.readline()
        n = int(self.headers.get('Content-Length') or 0)
        return self.rfile.read(n) if n else b''

    def do_GET(self):
        Upstream.seen.append((self.command, self.path, dict(self.headers.items())))
        if self.path.startswith('/echo'):
            self._send(200, json.dumps({'path': self.path,
                                        'headers': dict(self.headers.items())}).encode(),
                       extra=(('Set-Cookie', 'a=1'), ('Set-Cookie', 'b=2'),
                              ('Keep-Alive', 'timeout=5')))
        elif self.path == '/big':
            rng = self.headers.get('Range')
            if rng:
                a, b = rng.split('=')[1].split('-')
                part = BIG[int(a):int(b) + 1]
                self._send(206, part, 'application/octet-stream',
                           (('Content-Range', f'bytes {a}-{b}/{len(BIG)}'),))
            else:
                self._send(200, BIG, 'application/octet-stream')
        elif self.path == '/chunked':
            self.send_response(200)
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()
            for piece in (b'hello ', b'chunked ', b'world'):
                self.wfile.write(b'%x\r\n%s\r\n' % (len(piece), piece))
            self.wfile.write(b'0\r\n\r\n')
        elif self.path == '/eof':
            self.send_response(200)
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(b'until-eof')
            self.close_connection = True
        elif self.path == '/ws':
            self.send_response(101)
            self.send_header('Upgrade', 'websocket')
            self.send_header('Connection', 'Upgrade')
            self.end_headers()
            self.wfile.flush()
            while True:
                data = self.connection.recv(1024)
                if not data:
                    break
                self.connection.sendall(data.upper())
            self.close_connection = True
        else:
            self._send(200, b'<html>page</html>', 'text/html')

    do_HEAD = do_GET

    def do_POST(self):
        body = self._body()
        Upstream.seen.append((self.command, self.path, dict(self.headers.items())))
        self._send(200, json.dumps({'len': len(body),
                                    'sha': hashlib.sha256(body).hexdigest()}).encode())


class Closer:
    def __init__(self):
        self.calls = 0
        self.event = threading.Event()

    def __call__(self):
        self.calls += 1
        self.event.set()


class DoorCase(unittest.TestCase):
    rules = {}

    def setUp(self):
        quiet = (doorproxy.log, doorproxy.DoorHandler.log_message)
        doorproxy.log = lambda msg: None
        doorproxy.DoorHandler.log_message = lambda *a: None
        self.addCleanup(lambda: (setattr(doorproxy, 'log', quiet[0]),
                                 setattr(doorproxy.DoorHandler, 'log_message', quiet[1])))
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state_dir = self.tmp.name
        self.devices = os.path.join(self.state_dir, 'devices.json')
        with open(self.devices, 'w') as f:
            json.dump({'devices': [{
                'id': 'dev_o', 'type': 'browser', 'role': 'admin',
                'token_sha256': hashlib.sha256(b'legacy').hexdigest(),
                'host_tokens': [{'sha256': hashlib.sha256(b'OWNERTOK').hexdigest(),
                                 'host': HOST, 'expires_at': iso(time.time() + 600)}]}]}, f)
        porch_auth.reset_cache()
        self.state_path = os.path.join(self.state_dir, f'{NAME}.json')
        self.write_state(self.rules)

        Upstream.seen = []
        self.up = ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
        self.up.daemon_threads = True
        threading.Thread(target=self.up.serve_forever, daemon=True).start()
        self.addCleanup(self.up.server_close)
        self.addCleanup(self.up.shutdown)

        self.closer = Closer()
        self.door = doorproxy.Door(NAME, self.state_dir, self.up.server_address[1],
                                   devices_path=self.devices, grace=0.3, closer=self.closer)
        self.srv = doorproxy.build_server(self.door, 0)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    def write_state(self, rules, **extra):
        s = {'name': NAME, 'type': 'serve', 'pid': os.getpid(), 'port': 1,
             'started': int(time.time()), 'expires': int(time.time()) + 3600,
             'keep_alive': False, 'rules': rules, 'opens': 0, 'last_open': None}
        s.update(extra)
        door_state.write_state_atomic(self.state_path, s)
        st = os.stat(self.state_path)
        os.utime(self.state_path, ns=(st.st_atime_ns, st.st_mtime_ns + 10_000_000))

    def state(self):
        return door_state.read_state(self.state_path)

    def req(self, method='GET', path='/', headers=None, body=None, doc=False, cookie=None):
        h = {'Host': HOST}
        if doc:
            h['Sec-Fetch-Dest'] = 'document'
        if cookie:
            h['Cookie'] = cookie
        h.update(headers or {})
        c = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        try:
            c.request(method, path, body=body, headers=h)
            r = c.getresponse()
            return r.status, r, r.read()
        finally:
            c.close()

    @staticmethod
    def door_cookie(resp):
        for k, v in resp.getheaders():
            if k.lower() == 'set-cookie' and v.startswith(doorproxy.COOKIE + '='):
                return v.split(';')[0]
        return None


class PassthroughTest(DoorCase):
    rules = {}

    def test_get_headers_xff_and_hop_by_hop(self):
        st, r, body = self.req('GET', '/echo?x=1', headers={
            'X-Forwarded-For': '203.0.113.9', 'Connection': 'keep-alive, X-Secret',
            'X-Secret': 'drop-me', 'Keep-Alive': '300', 'Proxy-Authorization': 'x',
            'Cookie': f'{doorproxy.COOKIE}=v1.1.abc; porch_host=keep; other=1'})
        self.assertEqual(st, 200)
        got = json.loads(body)
        hdr = {k.lower(): v for k, v in got['headers'].items()}
        self.assertEqual(got['path'], '/echo?x=1')
        self.assertEqual(hdr['host'], HOST)
        self.assertEqual(hdr['x-forwarded-for'], '203.0.113.9, 127.0.0.1')
        self.assertEqual(hdr['x-forwarded-proto'], 'https')
        for gone in ('x-secret', 'keep-alive', 'proxy-authorization'):
            self.assertNotIn(gone, hdr)
        self.assertEqual(hdr['cookie'], 'porch_host=keep; other=1')
        self.assertNotIn(doorproxy.COOKIE, hdr['cookie'])
        # Response: both Set-Cookies pass, hop-by-hop dropped.
        cookies = [v for k, v in r.getheaders() if k.lower() == 'set-cookie']
        self.assertEqual(cookies, ['a=1', 'b=2'])
        self.assertIsNone(r.getheader('Keep-Alive'))

    def test_real_client_ip_survives_for_the_app(self):
        # The app's porch_http.client_ip takes the right-most non-loopback hop.
        import porch_http
        st, _, body = self.req('GET', '/echo', headers={'X-Forwarded-For': '198.51.100.7'})
        hdrs = json.loads(body)['headers']

        class H:
            client_address = ('127.0.0.1', 1)
            headers = {'X-Forwarded-For': hdrs['X-Forwarded-For']}
        self.assertEqual(porch_http.client_ip(H), '198.51.100.7')

    def test_big_body_and_range(self):
        st, r, body = self.req('GET', '/big')
        self.assertEqual((st, len(body)), (200, len(BIG)))
        self.assertEqual(body, BIG)
        st, r, body = self.req('GET', '/big', headers={'Range': 'bytes=10-19'})
        self.assertEqual(st, 206)
        self.assertEqual(body, BIG[10:20])
        self.assertEqual(r.getheader('Content-Range'), f'bytes 10-19/{len(BIG)}')

    def test_chunked_and_eof_responses(self):
        st, r, body = self.req('GET', '/chunked')
        self.assertEqual(body, b'hello chunked world')
        st, r, body = self.req('GET', '/eof')
        self.assertEqual((st, body), (200, b'until-eof'))
        self.assertEqual(r.getheader('Transfer-Encoding'), 'chunked')

    def test_post_content_length_and_chunked(self):
        payload = os.urandom(300_000)
        st, _, body = self.req('POST', '/up', body=payload)
        self.assertEqual(json.loads(body), {'len': len(payload),
                                            'sha': hashlib.sha256(payload).hexdigest()})
        # A chunked request body, by hand.
        s = socket.create_connection(('127.0.0.1', self.port), timeout=10)
        try:
            s.sendall(f'POST /up HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n'
                      'Connection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n'.encode())
            data = b''
            while True:
                d = s.recv(65536)
                if not d:
                    break
                data += d
        finally:
            s.close()
        self.assertIn(b'200 OK', data.split(b'\r\n', 1)[0])
        self.assertIn(hashlib.sha256(b'hello world').hexdigest().encode(), data)

    def test_conflicting_framing_is_refused(self):
        s = socket.create_connection(('127.0.0.1', self.port), timeout=10)
        try:
            s.sendall(f'POST /up HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n'
                      'Content-Length: 5\r\n\r\n0\r\n\r\n'.encode())
            self.assertIn(b' 400 ', s.recv(4096).split(b'\r\n', 1)[0])
        finally:
            s.close()

    def test_websocket_upgrade_relay(self):
        s = socket.create_connection(('127.0.0.1', self.port), timeout=10)
        try:
            s.sendall(f'GET /ws HTTP/1.1\r\nHost: {HOST}\r\nUpgrade: websocket\r\n'
                      'Connection: Upgrade\r\nSec-WebSocket-Key: x\r\n\r\n'.encode())
            head = b''
            while b'\r\n\r\n' not in head:
                head += s.recv(1024)
            self.assertIn(b'101', head.split(b'\r\n', 1)[0])
            self.assertIn(b'upgrade: websocket', head.lower())
            s.sendall(b'ping frame')
            got = b''
            while len(got) < 10:
                got += s.recv(1024)
            self.assertEqual(got, b'PING FRAME')
        finally:
            s.close()

    def test_upstream_down_is_a_502_page(self):
        self.up.shutdown()
        self.up.server_close()
        st, r, body = self.req('GET', '/')
        self.assertEqual(st, 502)
        self.assertIn(b'isn&#x27;t answering', body)

    def test_observers_see_every_exchange_and_can_intercept(self):
        seen = []

        class Obs(doorproxy.DoorObserver):
            def on_request_body(self, exch, chunk):
                seen.append(('req', len(chunk)))

            def on_response_body(self, exch, chunk):
                seen.append(('resp', len(chunk)))

            def on_exchange(self, exch):
                seen.append(('done', exch.method, exch.path, exch.status, exch.handled_by))

        class Boom(doorproxy.DoorObserver):
            def on_request(self, exch):
                raise RuntimeError('observers must not break requests')

        class Hook(doorproxy.DoorObserver):
            def intercept(self, exch):
                if exch.path == '/hook':
                    return 202, [('Content-Type', 'text/plain')], b'captured'

        self.door.add_observer(Boom())
        self.door.add_observer(Obs())
        self.door.add_observer(Hook())
        self.assertEqual(self.req('POST', '/up', body=b'abc')[0], 200)
        st, _, body = self.req('POST', '/hook', body=b'webhook!')
        self.assertEqual((st, body), (202, b'captured'))
        # on_exchange runs after the response is written: the client can see
        # the answer a moment before the observer does.
        want = ('done', 'POST', '/hook', 202, 'intercept')
        up_done = ('done', 'POST', '/up', 200, 'upstream')
        deadline = time.time() + 5
        while (want not in seen or up_done not in seen) and time.time() < deadline:
            time.sleep(0.01)
        self.assertIn(('req', 3), seen)
        self.assertIn(up_done, seen)
        self.assertIn(want, seen)
        self.assertIn(('req', 8), seen)
        self.assertFalse([s for s in Upstream.seen if s[1] == '/hook'])


class PasswordTest(DoorCase):
    rules = {'password': door_state.hash_password('correct horse')}

    def login(self, pw, ip='203.0.113.5', nxt='/echo'):
        body = urllib.parse.urlencode({'password': pw, 'next': nxt})
        return self.req('POST', doorproxy.LOGIN_PATH, body=body, headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': f'https://{HOST}', 'X-Forwarded-For': ip})

    def test_gate_page(self):
        st, r, body = self.req('GET', '/secret', doc=True)
        self.assertEqual(st, 401)
        self.assertIn(b'This door is locked', body)
        self.assertIn(b'data-app="serve"', body)
        self.assertIn(b'name="password"', body)
        self.assertIn(b'value="/secret"', body)
        csp = r.getheader('Content-Security-Policy')
        self.assertIn("form-action 'self'", csp)
        self.assertNotIn('unsafe-inline', csp)
        self.assertNotIn(b'style="', body)
        self.assertFalse(Upstream.seen)
        # The gate page's stylesheet is served by the proxy itself.
        css = next(p for p in doorproxy.porch_css_tag().split('"') if p.startswith('/__porch'))
        self.assertEqual(self.req('GET', css)[0], 200)

    def test_wrong_then_right_password(self):
        st, _, body = self.login('nope')
        self.assertEqual(st, 401)
        self.assertIn(b'not right', body)
        st, r, _ = self.login('correct horse')
        self.assertEqual(st, 303)
        self.assertEqual(r.getheader('Location'), '/echo')
        sc = [v for k, v in r.getheaders() if k.lower() == 'set-cookie'][0]
        for attr in ('Secure', 'HttpOnly', 'SameSite=Lax', 'Path=/'):
            self.assertIn(attr, sc)
        cookie = self.door_cookie(r)
        self.assertNotIn('correct', cookie)
        self.assertNotIn(self.rules['password'].split('$')[-1], cookie)
        st, _, body = self.req('GET', '/echo', cookie=cookie)
        self.assertEqual(st, 200)
        self.assertNotIn(doorproxy.COOKIE, json.loads(body)['headers'].get('Cookie', ''))
        # A forged / tampered cookie is not a session.
        self.assertEqual(self.req('GET', '/echo', cookie=cookie[:-2] + '00')[0], 401)

    def test_rate_limit_per_ip(self):
        for _ in range(doorproxy.FAIL_LIMIT):
            self.assertEqual(self.login('bad', ip='192.0.2.1')[0], 401)
        st, r, _ = self.login('correct horse', ip='192.0.2.1')
        self.assertEqual(st, 429)
        self.assertEqual(r.getheader('Retry-After'), str(doorproxy.FAIL_WINDOW))
        self.assertEqual(self.login('correct horse', ip='192.0.2.2')[0], 303)

    def test_cross_site_login_and_open_redirect_refused(self):
        body = urllib.parse.urlencode({'password': 'correct horse'})
        st, _, _ = self.req('POST', doorproxy.LOGIN_PATH, body=body,
                            headers={'Origin': 'https://evil.example'})
        self.assertEqual(st, 403)
        st, r, _ = self.login('correct horse', nxt='//evil.example/')
        self.assertEqual(r.getheader('Location'), '/')

    def test_password_change_invalidates_sessions_live(self):
        cookie = self.door_cookie(self.login('correct horse')[1])
        self.assertEqual(self.req('GET', '/echo', cookie=cookie)[0], 200)
        self.write_state({'password': door_state.hash_password('another one')})
        self.assertEqual(self.req('GET', '/echo', cookie=cookie)[0], 401)
        self.write_state({})
        self.assertEqual(self.req('GET', '/echo')[0], 200)

    def test_owner_passes_and_is_not_counted(self):
        self.write_state({'password': self.rules['password'], 'max_opens': 1})
        for _ in range(3):
            st, _, _ = self.req('GET', '/', doc=True, cookie='porch_host=OWNERTOK')
            self.assertEqual(st, 200)
        self.assertEqual(self.state()['opens'], 0)
        # The same cookie on another host is nobody.
        st, _, _ = self.req('GET', '/', doc=True, cookie='porch_host=OWNERTOK',
                            headers={'Host': 'other.tunnel.cush.rocks'})
        self.assertEqual(st, 401)


class GuestLinkTest(DoorCase):
    rules = {'guest': 'G' * 32}

    def test_guest_link_sets_cookie_and_drops_k(self):
        st, _, body = self.req('GET', '/x', doc=True)
        self.assertEqual(st, 403)
        self.assertIn(b'needs its link', body)
        st, r, _ = self.req('GET', '/echo?a=1&k=' + 'G' * 32 + '&b=2', doc=True)
        self.assertEqual(st, 303)
        self.assertEqual(r.getheader('Location'), '/echo?a=1&b=2')
        cookie = self.door_cookie(r)
        self.assertTrue(cookie)
        st, _, body = self.req('GET', '/echo?a=1&b=2', cookie=cookie)
        self.assertEqual(st, 200)
        self.assertEqual(self.req('GET', '/?k=wrong', doc=True)[0], 403)

    def test_password_or_guest_either_admits(self):
        self.write_state({'guest': 'G' * 32, 'password': door_state.hash_password('pw-123456')})
        st, _, body = self.req('GET', '/', doc=True)
        self.assertEqual(st, 401)
        self.assertIn(b'guest link', body)
        self.assertEqual(self.req('GET', '/?k=' + 'G' * 32)[0], 303)


class OpensTest(DoorCase):
    rules = {'max_opens': 2}

    def test_counting_rules_and_close(self):
        # A page view counts and hands out a session for its assets.
        st, r, _ = self.req('GET', '/', doc=True)
        self.assertEqual(st, 200)
        cookie = self.door_cookie(r)
        self.assertTrue(cookie)
        self.assertEqual(self.state()['opens'], 1)
        self.assertIsInstance(self.state()['last_open'], int)
        # Assets, XHR and Range requests of that session don't count.
        self.req('GET', '/big', cookie=cookie, headers={'Sec-Fetch-Dest': 'image'})
        self.req('GET', '/echo', cookie=cookie, headers={'Accept': 'application/json'})
        self.req('GET', '/big', cookie=cookie, headers={'Range': 'bytes=0-9',
                                                        'Sec-Fetch-Dest': 'video'})
        self.assertEqual(self.state()['opens'], 1)
        # A cookieless request counts even when it isn't a document (curl).
        self.assertEqual(self.req('GET', '/echo', headers={'Accept': '*/*'})[0], 200)
        self.assertEqual(self.state()['opens'], 2)
        # Limit reached: new opens get the closed page, the session's assets
        # still load during the grace, then the door is closed.
        st, _, body = self.req('GET', '/', doc=True)
        self.assertEqual(st, 410)
        self.assertIn(b'This door is closed', body)
        self.assertEqual(self.req('GET', '/', doc=True, cookie=cookie)[0], 410)
        self.assertEqual(self.req('GET', '/big', cookie=cookie,
                                  headers={'Sec-Fetch-Dest': 'image'})[0], 200)
        self.assertTrue(self.closer.event.wait(5))
        self.assertEqual(self.closer.calls, 1)
        self.assertEqual(self.req('GET', '/big', cookie=cookie,
                                  headers={'Sec-Fetch-Dest': 'image'})[0], 410)
        self.assertEqual(self.state()['opens'], 2)

    def test_burn_with_password(self):
        self.write_state({'max_opens': 1, 'password': door_state.hash_password('burnburn')})
        # The gate page itself is not an open.
        self.req('GET', '/', doc=True)
        self.assertEqual(self.state()['opens'], 0)
        body = urllib.parse.urlencode({'password': 'burnburn', 'next': '/'})
        r = self.req('POST', doorproxy.LOGIN_PATH, body=body,
                     headers={'Origin': f'https://{HOST}'})[1]
        cookie = self.door_cookie(r)
        self.assertEqual(self.req('GET', '/', doc=True, cookie=cookie)[0], 200)
        self.assertEqual(self.req('GET', '/', doc=True, cookie=cookie)[0], 410)
        self.assertTrue(self.closer.event.wait(5))

    def test_raising_the_limit_in_the_grace_keeps_it_open(self):
        self.write_state({'max_opens': 1})
        self.assertEqual(self.req('GET', '/', doc=True)[0], 200)
        s = self.state()
        self.write_state({'max_opens': 5}, opens=s['opens'])
        time.sleep(0.6)
        self.assertEqual(self.closer.calls, 0)
        self.assertEqual(self.req('GET', '/', doc=True)[0], 200)

    def test_closed_pages_still_get_their_stylesheet(self):
        css = next(p for p in porch_http.ASSETS if p.endswith('.css'))
        self.assertEqual(self.req('GET', '/', doc=True)[0], 200)   # open 1 of 2
        # An asset is never an open, even with no session on a burn door.
        self.assertEqual(self.req('GET', css)[0], 200)
        self.assertEqual(self.state()['opens'], 1)
        self.req('GET', '/', doc=True)
        # Used up: the closed page and its stylesheet.
        self.assertEqual(self.req('GET', '/', doc=True)[0], 410)
        self.assertEqual(self.req('GET', css)[0], 200)
        # Expired: the same.
        self.write_state({'max_opens': 9}, expires=int(time.time()) - 5)
        self.assertEqual(self.req('GET', '/', doc=True)[0], 410)
        st, r, _ = self.req('GET', css)
        self.assertEqual((st, r.getheader('Content-Type').split(';')[0]), (200, 'text/css'))

    def test_expired_door_refuses(self):
        self.write_state({'max_opens': 9}, expires=int(time.time()) - 5)
        self.assertEqual(self.req('GET', '/', doc=True)[0], 410)
        self.write_state({'max_opens': 9}, expires=None, keep_alive=True)
        self.assertEqual(self.req('GET', '/', doc=True)[0], 200)


class SmugglingTest(DoorCase):
    """Framing the proxy must refuse rather than guess (review round 2)."""

    def raw(self, data):
        s = socket.create_connection(('127.0.0.1', self.port), timeout=10)
        try:
            s.sendall(data)
            out = b''
            while True:
                try:
                    d = s.recv(65536)
                except socket.timeout:
                    break
                if not d:
                    break
                out += d
            return out
        finally:
            s.close()

    def test_malformed_header_line_is_refused(self):
        # Python's header parser silently stops at a bad line, which would
        # drop the Content-Length after it: the body would become a second,
        # smuggled request on this connection.
        smuggled = f'GET /smuggled HTTP/1.1\r\nHost: {HOST}\r\n\r\n'
        out = self.raw((f'POST /up HTTP/1.1\r\nHost: {HOST}\r\nBad Header: 1\r\n'
                        f'Content-Length: {len(smuggled)}\r\n\r\n{smuggled}').encode())
        self.assertTrue(out.startswith(b'HTTP/1.1 400 '), out[:80])
        self.assertEqual(out.count(b'HTTP/1.1 '), 1)
        self.assertFalse([s for s in Upstream.seen if s[1] == '/smuggled'])

    def test_space_before_colon_is_refused(self):
        out = self.raw((f'POST /up HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding : chunked\r\n'
                        'Content-Length: 3\r\n\r\nabc').encode())
        self.assertTrue(out.startswith(b'HTTP/1.1 400 '), out[:80])

    def test_two_transfer_encodings_are_refused(self):
        out = self.raw((f'POST /up HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n'
                        'Transfer-Encoding: identity\r\n\r\n3\r\nabc\r\n0\r\n\r\n').encode())
        self.assertTrue(out.startswith(b'HTTP/1.1 400 '), out[:80])
        self.assertFalse([s for s in Upstream.seen if s[1] == '/up'])

    def test_upstream_reason_phrase_cannot_inject_headers(self):
        class Evil(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.wfile.write(b'HTTP/1.1 200 OK\rSet-Cookie: x=1\r\n'
                                 b'Content-Length: 2\r\nConnection: close\r\n\r\nok')
        up = ThreadingHTTPServer(('127.0.0.1', 0), Evil)
        threading.Thread(target=up.serve_forever, daemon=True).start()
        self.addCleanup(up.server_close)
        self.addCleanup(up.shutdown)
        self.door.upstream = ('127.0.0.1', up.server_address[1])
        out = self.raw(f'GET / HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n'.encode())
        self.assertNotIn(b'\r', out.split(b'\r\n', 1)[0])


class AppCookieTest(DoorCase):
    rules = {'password': door_state.hash_password('pw-123456')}

    def test_app_cannot_set_the_door_cookie(self):
        class Clobber(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header('Set-Cookie', doorproxy.COOKIE + '=junk; Path=/')
                self.send_header('Set-Cookie', 'app=1; Path=/')
                self.send_header('Content-Length', '2')
                self.end_headers()
                self.wfile.write(b'ok')
        up = ThreadingHTTPServer(('127.0.0.1', 0), Clobber)
        threading.Thread(target=up.serve_forever, daemon=True).start()
        self.addCleanup(up.server_close)
        self.addCleanup(up.shutdown)
        self.door.upstream = ('127.0.0.1', up.server_address[1])
        body = urllib.parse.urlencode({'password': 'pw-123456', 'next': '/'})
        cookie = self.door_cookie(self.req('POST', doorproxy.LOGIN_PATH, body=body,
                                           headers={'Origin': f'https://{HOST}'})[1])
        st, r, _ = self.req('GET', '/', cookie=cookie)
        self.assertEqual(st, 200)
        sc = [v for k, v in r.getheaders() if k.lower() == 'set-cookie']
        self.assertIn('app=1; Path=/', sc)
        self.assertFalse([v for v in sc if v.startswith(doorproxy.COOKIE)])


class GuestRedirectTest(DoorCase):
    rules = {'guest': 'G' * 32}

    def test_guest_redirect_stays_on_this_host(self):
        for path in ('/\\evil.example/x', '/\\/evil.example', '//evil.example/x'):
            st, r, _ = self.req('GET', path + '?k=' + 'G' * 32)
            self.assertEqual(st, 303, path)
            loc = r.getheader('Location')
            self.assertTrue(loc.startswith('/') and not loc.startswith(('//', '/\\')), loc)


class GatedOpensTest(DoorCase):
    """A gated door with max_opens: every session counts at least once, so a
    password or guest-link holder can't read a burn door for free with
    requests that don't look like page views."""
    rules = {'max_opens': 1, 'guest': 'G' * 32}

    def test_guest_session_counts_even_without_a_page_view(self):
        st, r, _ = self.req('GET', '/?k=' + 'G' * 32)
        self.assertEqual(st, 303)
        cookie = self.door_cookie(r)
        self.assertEqual(self.state()['opens'], 0)       # minting is not an open yet
        # Not a document (curl -H 'Sec-Fetch-Dest: empty'): still the open.
        st, r, _ = self.req('GET', '/echo', cookie=cookie, headers={'Sec-Fetch-Dest': 'empty'})
        self.assertEqual(st, 200)
        self.assertEqual(self.state()['opens'], 1)
        counted = self.door_cookie(r)
        self.assertTrue(counted and counted != cookie)
        # The counted session's assets load during the grace ...
        self.assertEqual(self.req('GET', '/big', cookie=counted,
                                  headers={'Sec-Fetch-Dest': 'image'})[0], 200)
        # ... but replaying the uncounted cookie is a new open: closed.
        self.assertEqual(self.req('GET', '/echo', cookie=cookie,
                                  headers={'Sec-Fetch-Dest': 'empty'})[0], 410)
        self.assertEqual(self.state()['opens'], 1)

    def test_browser_flow_counts_once(self):
        cookie = self.door_cookie(self.req('GET', '/?k=' + 'G' * 32)[1])
        st, r, _ = self.req('GET', '/', doc=True, cookie=cookie)
        self.assertEqual(st, 200)
        counted = self.door_cookie(r)
        self.assertEqual(self.req('GET', '/big', cookie=counted,
                                  headers={'Sec-Fetch-Dest': 'image'})[0], 200)
        self.assertEqual(self.state()['opens'], 1)

    def test_no_limit_needs_no_recount(self):
        self.write_state({'guest': 'G' * 32})
        cookie = self.door_cookie(self.req('GET', '/?k=' + 'G' * 32)[1])
        for _ in range(3):
            self.assertEqual(self.req('GET', '/echo', cookie=cookie)[0], 200)
        self.assertEqual(self.state()['opens'], 0)


class DoorStateTest(unittest.TestCase):
    NOW = 1_800_000_000

    def test_parse_expires(self):
        p = door_state.parse_expires
        self.assertEqual(p('30m', self.NOW), self.NOW + 1800)
        self.assertEqual(p('2h', self.NOW), self.NOW + 7200)
        self.assertEqual(p('+1d', self.NOW), self.NOW + 86400)
        self.assertEqual(p('45', self.NOW), self.NOW + 2700)
        self.assertIsNone(p('never', self.NOW))
        at = datetime.fromtimestamp(self.NOW, tz=timezone.utc) + timedelta(hours=3)
        self.assertEqual(p(at.strftime('%Y-%m-%dT%H:%M:%SZ'), self.NOW), self.NOW + 3 * 3600)
        self.assertEqual(p(at.isoformat(), self.NOW), self.NOW + 3 * 3600)
        local = datetime.fromtimestamp(self.NOW + 600).strftime('%Y-%m-%dT%H:%M:%S')
        self.assertEqual(p(local, self.NOW), self.NOW + 600)
        for bad in ('', 'soon', '0m', '2026-01-01T00:00:00Z', '400d', '-5m', '1y'):
            with self.assertRaises(door_state.DoorError, msg=bad):
                p(bad, self.NOW)

    def test_coerce_expires(self):
        c = door_state.coerce_expires
        self.assertEqual(c(self.NOW + 60, self.NOW), self.NOW + 60)
        self.assertIsNone(c('never', self.NOW))
        self.assertIsNone(c(None, self.NOW))
        self.assertEqual(c('+2h', self.NOW), self.NOW + 7200)
        for bad in (self.NOW - 1, True, [], {}):
            with self.assertRaises(door_state.DoorError):
                c(bad, self.NOW)

    def test_password_hash(self):
        h = door_state.hash_password('hunter22')
        self.assertTrue(h.startswith('scrypt$'))
        self.assertNotIn('hunter22', h)
        self.assertTrue(door_state.verify_password('hunter22', h))
        self.assertFalse(door_state.verify_password('hunter23', h))
        self.assertFalse(door_state.verify_password('x', 'garbage'))
        self.assertNotEqual(h, door_state.hash_password('hunter22'))  # salted
        with self.assertRaises(door_state.DoorError):
            door_state.hash_password('short')

    def test_clean_and_public_rules(self):
        h = door_state.hash_password('hunter22')
        raw = {'password': h, 'guest': 'A' * 20, 'max_opens': 3, 'evil': 1}
        self.assertEqual(door_state.clean_rules(raw), {'password': h, 'guest': 'A' * 20,
                                                       'max_opens': 3})
        self.assertEqual(door_state.clean_rules({'password': 'plain', 'guest': 'x',
                                                 'max_opens': True}), {})
        pub = door_state.public_rules(raw)
        self.assertEqual(pub, {'password': True, 'guest_link': True, 'max_opens': 3})
        self.assertNotIn(h, json.dumps(pub))
        self.assertEqual(door_state.rules_summary({'max_opens': 1}), 'burn after 1 open')

    def test_update_state_locked_and_private(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'x.json')
            door_state.write_state_atomic(path, {'name': 'x', 'opens': 0})
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

            def bump(s):
                s['opens'] += 1
            ts = [threading.Thread(target=lambda: [door_state.update_state(path, bump)
                                                   for _ in range(25)]) for _ in range(4)]
            [t.start() for t in ts]
            [t.join() for t in ts]
            self.assertEqual(door_state.read_state(path)['opens'], 100)
            self.assertEqual(sorted(os.listdir(d)), ['.x.lock', 'x.json'])
            with self.assertRaises(FileNotFoundError):
                door_state.update_state(os.path.join(d, 'gone.json'), bump)

    def test_secret_file(self):
        with tempfile.TemporaryDirectory() as d:
            a = door_state.load_or_create_secret(d, 'n')
            self.assertEqual(a, door_state.load_or_create_secret(d, 'n'))
            self.assertEqual(os.stat(os.path.join(d, '.n.secret')).st_mode & 0o777, 0o600)
            os.symlink('/etc/passwd', os.path.join(d, '.m.secret'))
            with self.assertRaises(OSError):
                door_state.load_or_create_secret(d, 'm')


class DoorFlagsShellTest(unittest.TestCase):
    """lib/door-flags.sh + tunnel_state_register, through bash."""

    SCRIPT = r'''
source "$1/tunnel-state.sh"
TUNNEL_STATE_DIR="$2"
shift 2
door_flags_parse "$@" || exit 2
set -- "${DOOR_REST[@]}"
echo "rest=$*"
door_spec_build "" || exit 2
[ -z "$(env | grep _PORCH_DOOR_SPEC)" ] || echo LEAKED
tunnel_state_register flagtest serve $$ 1234
door_print_summary flagtest
'''

    def run_flags(self, *args, env=None):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: subprocess.run(['rm', '-rf', d]))
        e = {k: v for k, v in os.environ.items() if not k.startswith('PORCH_DOOR')}
        e['CUSH_HISTORY_FILE'] = os.path.join(d, 'history.jsonl')
        e.update(env or {})
        p = subprocess.run(['bash', '-c', self.SCRIPT, 'x', _LIB, d, *args],
                           capture_output=True, text=True, env=e, stdin=subprocess.DEVNULL,
                           start_new_session=True, timeout=30)
        state = None
        if os.path.exists(os.path.join(d, 'flagtest.json')):
            with open(os.path.join(d, 'flagtest.json')) as f:
                state = json.load(f)
        return p, state

    def test_flags_reach_the_state_file(self):
        p, s = self.run_flags('a', '--password', '--expires', '2h', '--guest-link', 'b',
                              '--max-opens=3', env={'PORCH_DOOR_PASSWORD': 'flagpass1'})
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('rest=a b', p.stdout)
        self.assertNotIn('LEAKED', p.stdout)
        self.assertTrue(door_state.verify_password('flagpass1', s['rules']['password']))
        self.assertEqual(s['rules']['max_opens'], 3)
        self.assertAlmostEqual(s['expires'], time.time() + 7200, delta=30)
        self.assertIn('Guest link: https://flagtest.tunnel.cush.rocks/?k=' + s['rules']['guest'],
                      p.stdout)
        self.assertNotIn('flagpass1', json.dumps(s))

    def test_defaults_and_never(self):
        p, s = self.run_flags('x')
        self.assertEqual(s['rules'], {})
        self.assertAlmostEqual(s['expires'], time.time() + 3600, delta=30)
        self.assertEqual(p.stdout.strip(), 'rest=x')     # no summary without door flags
        p, s = self.run_flags('--expires', 'never')
        self.assertIsNone(s['expires'])
        self.assertTrue(s['keep_alive'])

    def test_bad_flags(self):
        p, s = self.run_flags('--expires', 'soonish')
        self.assertEqual(p.returncode, 2)
        self.assertIsNone(s)
        p, s = self.run_flags('--password=hunter2')
        self.assertEqual(p.returncode, 2)
        self.assertIn('ps', p.stderr)
        # --password without the env var and without a terminal fails closed.
        p, s = self.run_flags('--password')
        self.assertEqual(p.returncode, 2)
        self.assertIn('PORCH_DOOR_PASSWORD', p.stderr)
        p, s = self.run_flags('--burn', '--max-opens', '2')
        self.assertEqual(p.returncode, 2)


if __name__ == '__main__':
    unittest.main()

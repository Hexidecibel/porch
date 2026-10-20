"""Tests for the request inspector and capture-only webhooks: lib/inspect_store.py,
its use in lib/doorproxy.py, the status API's /requests endpoints, `porch inspect`,
the --inspect/--inspect-raw door flags and bin/hook's argument handling.
Stdlib unittest only; everything runs against temp dirs on 127.0.0.1:0.
"""

import hashlib
import http.client
import importlib.util
import io
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zlib
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
_LIB = os.path.join(_HERE, '..', 'lib')
_BIN = os.path.join(_HERE, '..', 'bin')
sys.path.insert(0, _LIB)
sys.path.insert(0, _HERE)
import door_state  # noqa: E402
import doorproxy  # noqa: E402
import inspect_store  # noqa: E402
from porch_setup import cmd_inspect  # noqa: E402
from test_doorproxy import DoorCase, Upstream, NAME, HOST, iso  # noqa: E402,F401

_spec = importlib.util.spec_from_file_location('statusserver_insp', os.path.join(_LIB, 'statusserver.py'))
ss = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ss)


class InspCase(DoorCase):
    """A DoorCase whose door has a Recorder writing to a temp store."""
    raw = False

    def setUp(self):
        super().setUp()
        self.base = tempfile.mkdtemp()
        os.chmod(self.base, 0o700)
        self.addCleanup(lambda: subprocess.run(['rm', '-rf', self.base]))
        self.rec = inspect_store.Recorder(self.door, raw=self.raw, base=self.base)
        self.rec.start_control()
        self.addCleanup(self.rec.close)
        self.door.add_observer(self.rec)
        self.store = inspect_store.store_path(NAME, self.base)

    def records(self):
        # on_exchange runs after the response is written: give it a moment.
        for _ in range(50):
            recs = inspect_store.read_records(self.store)
            if recs:
                return recs
            time.sleep(0.02)
        return []

    def wait_for(self, n):
        for _ in range(100):
            recs = inspect_store.read_records(self.store)
            if len(recs) >= n:
                return recs
            time.sleep(0.02)
        self.fail(f'expected {n} records, got {len(inspect_store.read_records(self.store))}')


class CaptureTest(InspCase):
    def test_heads_bodies_and_truncation(self):
        body = json.dumps({'hello': 'world'}).encode()
        st, _, _ = self.req('POST', '/up?x=1', body=body,
                            headers={'Content-Type': 'application/json', 'X-Trace': 'abc'})
        self.assertEqual(st, 200)
        r = self.wait_for(1)[0]
        self.assertEqual((r['method'], r['target'], r['status'], r['handled_by']),
                         ('POST', '/up?x=1', 200, 'upstream'))
        self.assertIn(['X-Trace', 'abc'], r['req_headers'])
        self.assertEqual(r['req_body']['kind'], 'text')
        self.assertEqual(json.loads(r['req_body']['data']), {'hello': 'world'})
        self.assertEqual(r['req_bytes'], len(body))
        self.assertEqual(r['resp_body']['kind'], 'text')
        self.assertIn('sha', json.loads(r['resp_body']['data']))
        self.assertGreaterEqual(r['ms'], 0)
        self.assertEqual(r['client_ip'], '127.0.0.1')

        big = b'a' * (inspect_store.BODY_CAP + 5000)
        self.req('POST', '/up', body=big, headers={'Content-Type': 'text/plain'})
        r = self.wait_for(2)[1]
        self.assertTrue(r['req_body']['truncated'])
        self.assertEqual(len(r['req_body']['data']), inspect_store.BODY_CAP)
        self.assertEqual(r['req_body']['size'], len(big))
        self.assertEqual(r['req_bytes'], len(big))
        self.assertEqual(stat.S_IMODE(os.stat(self.store).st_mode), 0o600)

    def test_binary_bodies_are_metadata_only(self):
        self.req('GET', '/big')             # application/octet-stream, 1 MiB
        r = self.wait_for(1)[0]
        b = r['resp_body']
        self.assertEqual(b['kind'], 'binary')
        self.assertNotIn('data', b)
        self.assertEqual(b['hex'], bytes(range(32)).hex())
        self.assertEqual(r['resp_bytes'], 1024 * 1024)
        self.assertLess(os.path.getsize(self.store), 8192)

    def test_websocket_is_metadata_only(self):
        s = socket.create_connection(('127.0.0.1', self.port), timeout=10)
        try:
            s.sendall(f'GET /ws HTTP/1.1\r\nHost: {HOST}\r\nUpgrade: websocket\r\n'
                      'Connection: Upgrade\r\nSec-WebSocket-Key: x\r\n\r\n'.encode())
            head = b''
            while b'\r\n\r\n' not in head:
                head += s.recv(1024)
            s.sendall(b'secret frame')
            got = b''
            while len(got) < 12:
                got += s.recv(1024)
        finally:
            s.close()
        r = self.wait_for(1)[0]
        self.assertTrue(r['upgraded'])
        self.assertEqual(r['req_body']['kind'], 'none')
        self.assertNotIn('SECRET', open(self.store).read().upper().replace('SEC-WEBSOCKET', ''))

    def test_gzip_is_decoded_for_display(self):
        b = inspect_store.body_repr(zlib.compress(b'{"a": 1}'), 16, False,
                                    [('Content-Type', 'application/json'),
                                     ('Content-Encoding', 'deflate')])
        self.assertEqual((b['kind'], b['data'], b['decoded']), ('text', '{"a": 1}', 'deflate'))
        import gzip
        g = gzip.compress(b'x' * (inspect_store.BODY_CAP * 3))
        b = inspect_store.body_repr(g, len(g), False, [('Content-Encoding', 'gzip')])
        self.assertEqual(len(b['data']), inspect_store.BODY_CAP)
        self.assertTrue(b['decoded_truncated'])
        # A truncated compressed body is never decoded.
        b = inspect_store.body_repr(g[:100], 9999999, True, [('Content-Encoding', 'gzip')])
        self.assertEqual(b['kind'], 'binary')

    def test_ring_cap_and_compaction(self):
        path = os.path.join(self.base, 'ring.jsonl')
        st = inspect_store.Store(path, ring=20, slack=5)
        for _ in range(60):
            st.append({'id': st.new_id(), 'x': 'y' * 10})
        recs = inspect_store.read_records(path)
        self.assertLessEqual(len(recs), 25)
        self.assertGreaterEqual(len(recs), 20)
        self.assertEqual(recs[-1]['id'], 60)
        self.assertEqual([r['id'] for r in recs], sorted(r['id'] for r in recs))
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        # byte cap
        st = inspect_store.Store(path + '2', ring=500, max_bytes=4000)
        for _ in range(100):
            st.append({'id': st.new_id(), 'x': 'z' * 200})
        self.assertLessEqual(os.path.getsize(path + '2'), 4000 + 300)
        # a reopened store continues the ids
        self.assertEqual(inspect_store.Store(path).next_id, 61)

    def test_tail_follows_across_compaction(self):
        path = os.path.join(self.base, 'tail.jsonl')
        st = inspect_store.Store(path, ring=5, slack=1)
        t = inspect_store.Tail(path)
        st.append({'id': st.new_id()})
        self.assertEqual([r['id'] for r in t.poll()], [1])
        for _ in range(10):
            st.append({'id': st.new_id()})
        got = [r['id'] for r in t.poll()]
        self.assertEqual(got[-1], 11)
        self.assertNotIn(1, got)
        self.assertEqual(t.poll(), [])

    def test_assets_are_not_recorded(self):
        self.door.add_observer(doorproxy.DoorObserver())
        self.req('GET', '/echo')
        self.assertEqual(len(self.wait_for(1)), 1)


class MaskingTest(InspCase):
    def test_secret_headers_are_masked(self):
        self.req('GET', '/echo', headers={
            'Authorization': 'Bearer sk_live_abcdefghijklmnop',
            'X-Api-Key': 'shortkey', 'X-Hub-Signature-256': 'sha256=deadbeefdeadbeef',
            'Cookie': 'sid=topsecretvalue1234; ' + doorproxy.COOKIE + '=v1.1.x'})
        r = self.wait_for(1)[0]
        h = dict((k.lower(), v) for k, v in r['req_headers'])
        self.assertEqual(h['authorization'], 'Bear…[masked, 31 chars]')
        self.assertEqual(h['x-api-key'], '…[masked, 8 chars]')
        self.assertTrue(h['x-hub-signature-256'].startswith('sha2…[masked'))
        self.assertIn('[masked', h['cookie'])
        rh = [v for k, v in r['resp_headers'] if k.lower() == 'set-cookie']
        self.assertTrue(rh and all('[masked' in v for v in rh))
        # (/echo reflects the headers in its JSON body, masked there too.)
        raw = open(self.store).read()
        for secret in ('sk_live_abcdefghijklmnop', 'shortkey', 'deadbeefdeadbeef',
                       'topsecretvalue1234', doorproxy.COOKIE):
            self.assertNotIn(secret, raw)
        self.assertIn('authorization', r['masked'])
        self.assertFalse(r['raw'])


class BodyMaskingTest(InspCase):
    def test_form_and_json_secret_fields_are_masked(self):
        self.req('POST', '/up?token=abcdefghijklmnopq&page=2',
                 body=b'user=bob&password=hunter2222&API-Key=abcdefghijklmnop&n=1',
                 headers={'Content-Type': 'application/x-www-form-urlencoded'})
        # Records land when each exchange finishes; wait for each one so the
        # order below is the request order even on a loaded machine.
        self.wait_for(1)
        self.req('POST', '/up', body=json.dumps({
            'user': 'bob', 'client_secret': 'sssssssssssssssss', 'n': 7,
            'auth': {'user': 'u', 'pass': 'verysecretpass'},
            'items': [{'sessionId': 'ffffffffffffffffff'}]}).encode(),
            headers={'Content-Type': 'application/json'})
        self.wait_for(2)
        self.req('POST', '/up', body=b'\xff\xfepassword=binarybinary',
                 headers={'Content-Type': 'application/octet-stream'})
        recs = self.wait_for(3)
        stored = open(self.store).read()
        for secret in ('hunter2222', 'abcdefghijklmnop', 'sssssssssssssssss',
                       'verysecretpass', 'ffffffffffffffffff', 'abcdefghijklmnopq'):
            self.assertNotIn(secret, stored)
        form = recs[0]['req_body']
        self.assertIn('user=bob', form['data'])
        self.assertIn('password=…[masked, 10 chars]', form['data'])
        self.assertIn('API-Key=abcd…[masked, 16 chars]', form['data'])
        self.assertEqual(form['masked_fields'], ['password', 'API-Key'])
        self.assertEqual(recs[0]['target'], '/up?token=abcd…[masked, 17 chars]&page=2')
        js = json.loads(recs[1]['req_body']['data'])
        self.assertEqual(js['user'], 'bob')
        self.assertEqual(js['n'], 7)
        self.assertEqual(js['client_secret'], 'ssss…[masked, 17 chars]')
        self.assertEqual(js['auth']['user'], '…[masked, 1 chars]')
        self.assertTrue(js['items'][0]['sessionId'].startswith('ffff…[masked'))
        self.assertEqual(recs[2]['req_body']['kind'], 'binary')

    def test_truncated_json_still_masks(self):
        body = ('{"password": "truncatedsecret1", "pad": "' + 'x' * inspect_store.BODY_CAP
                + '"}').encode()
        self.req('POST', '/up', body=body, headers={'Content-Type': 'application/json'})
        r = self.wait_for(1)[0]
        self.assertTrue(r['req_body']['truncated'])
        self.assertNotIn('truncatedsecret1', open(self.store).read())

    def test_masked_response_body(self):
        text = inspect_store.mask_body_text('{"access_token": "abcdefghijklmnopqrstu"}',
                                            'application/json; charset=utf-8')[0]
        self.assertNotIn('abcdefghijklmnopqrstu', text)
        self.assertEqual(inspect_store.mask_body_text('password=x', 'text/plain'),
                         ('password=x', []))

    def test_replay_uses_the_original_body_while_held(self):
        body = b'user=bob&password=hunter2222'
        self.req('POST', '/up?sig=abcdefghijklmnopqr', body=body,
                 headers={'Content-Type': 'application/x-www-form-urlencoded'})
        r = self.wait_for(1)[0]
        Upstream.seen = []
        reply = inspect_store.request_replay(NAME, r['id'], self.base)
        new = inspect_store.get_record(self.store, reply['id'])
        self.assertEqual(json.loads(new['resp_body']['data'])['sha'],
                         hashlib.sha256(body).hexdigest())
        self.assertEqual(Upstream.seen[-1][1], '/up?sig=abcdefghijklmnopqr')
        self.assertNotIn('hunter2222', open(self.store).read())
        # Forgotten (a new proxy): a masked body or query is refused, not sent.
        self.rec._originals.clear()
        with self.assertRaisesRegex(inspect_store.InspectError, 'masked'):
            inspect_store.request_replay(NAME, r['id'], self.base)

    def test_login_password_is_never_recorded(self):
        self.write_state({'password': door_state.hash_password('gate-pass-1')})
        body = 'password=gate-pass-1&next=/'
        self.req('POST', doorproxy.LOGIN_PATH, body=body,
                 headers={'Origin': f'https://{HOST}',
                          'Content-Type': 'application/x-www-form-urlencoded'})
        self.wait_for(1)
        self.assertNotIn('gate-pass-1', open(self.store).read())


class RawBodyTest(InspCase):
    raw = True

    def test_raw_keeps_bodies(self):
        self.req('POST', '/up', body=b'password=hunter2222',
                 headers={'Content-Type': 'application/x-www-form-urlencoded'})
        self.assertEqual(self.wait_for(1)[0]['req_body']['data'], 'password=hunter2222')


class RawTest(InspCase):
    raw = True

    def test_raw_keeps_values_but_never_the_door_cookie(self):
        self.req('GET', '/echo', headers={'Authorization': 'Bearer abcdefghijklmnop',
                                          'Cookie': 'a=1; ' + doorproxy.COOKIE + '=v1.1.x'})
        r = self.wait_for(1)[0]
        self.assertIn(['Authorization', 'Bearer abcdefghijklmnop'], r['req_headers'])
        self.assertTrue(r['raw'])
        self.assertNotIn(doorproxy.COOKIE, open(self.store).read())


class GuestMaskTest(InspCase):
    rules = {'guest': 'G' * 24}

    def test_guest_key_is_masked_in_the_target(self):
        st, _, _ = self.req('GET', '/page?k=' + 'G' * 24)
        self.assertEqual(st, 303)
        r = self.wait_for(1)[0]
        self.assertEqual(r['handled_by'], 'gate')
        self.assertNotIn('G' * 24, open(self.store).read())
        self.assertIn('k=', r['target'])


class ReplayTest(InspCase):
    def test_replay_goes_to_the_local_upstream_with_original_secrets(self):
        self.req('POST', '/up', body=b'replay me',
                 headers={'Authorization': 'Bearer abcdefghijklmnopqr',
                          'Content-Type': 'text/plain'})
        r = self.wait_for(1)[0]
        Upstream.seen = []
        reply = inspect_store.request_replay(NAME, r['id'], self.base)
        self.assertTrue(reply['ok'])
        self.assertEqual(reply['status'], 200)
        self.assertEqual(reply['dropped'], [])
        seen = [s for s in Upstream.seen if s[1] == '/up']
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][2].get('Authorization'), 'Bearer abcdefghijklmnopqr')
        self.assertEqual(seen[0][2].get('X-Porch-Replay'), str(r['id']))
        new = inspect_store.get_record(self.store, reply['id'])
        self.assertEqual(new['replay_of'], r['id'])
        self.assertEqual(json.loads(new['resp_body']['data'])['len'], len(b'replay me'))
        self.assertNotIn('abcdefghijklmnopqr', open(self.store).read())

    def test_forgotten_secrets_are_dropped(self):
        self.req('GET', '/echo', headers={'Authorization': 'Bearer abcdefghijklmnopqr'})
        r = self.wait_for(1)[0]
        self.rec._originals.clear()          # as if the proxy restarted
        reply = inspect_store.request_replay(NAME, r['id'], self.base)
        self.assertEqual(reply['dropped'], ['Authorization'])
        seen = [s for s in Upstream.seen if s[1] == '/echo']
        self.assertNotIn('Authorization', seen[-1][2])

    def test_refusals(self):
        self.req('POST', '/up', body=b'b' * (inspect_store.BODY_CAP + 1),
                 headers={'Content-Type': 'text/plain'})
        self.req('POST', '/up', body=bytes(range(256)),
                 headers={'Content-Type': 'application/octet-stream'})
        recs = self.wait_for(2)
        with self.assertRaisesRegex(inspect_store.InspectError, 'truncated'):
            inspect_store.request_replay(NAME, recs[0]['id'], self.base)
        with self.assertRaisesRegex(inspect_store.InspectError, 'binary'):
            inspect_store.request_replay(NAME, recs[1]['id'], self.base)
        with self.assertRaisesRegex(inspect_store.InspectError, 'no request'):
            inspect_store.request_replay(NAME, 9999, self.base)
        with self.assertRaisesRegex(inspect_store.InspectError, 'no inspector'):
            inspect_store.request_replay('nosuchdoor', 1, self.base)

    def test_replay_never_leaves_loopback(self):
        self.req('GET', '/echo')
        r = self.wait_for(1)[0]
        self.door.upstream = ('192.0.2.1', 80)
        reply = inspect_store.request_replay(NAME, r['id'], self.base)
        self.assertIn('local app', reply['error'] or '')

    def test_control_socket_is_private(self):
        st = os.stat(inspect_store.socket_path(NAME, self.base))
        self.assertTrue(stat.S_ISSOCK(st.st_mode))
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o600)


class HookCase(DoorCase):
    """Capture mode: no upstream at all."""

    def setUp(self):
        super().setUp()
        self.base = tempfile.mkdtemp()
        os.chmod(self.base, 0o700)
        self.addCleanup(lambda: subprocess.run(['rm', '-rf', self.base]))
        self.door.upstream = None
        self.door.max_body = 1024
        self.rec = inspect_store.Recorder(self.door, base=self.base)
        self.rec.start_control()
        self.addCleanup(self.rec.close)
        self.door.add_observer(self.rec)
        self.door.add_observer(inspect_store.CaptureResponder.from_state(
            {'status': 202, 'body': '{"ok":true}', 'content_type': 'application/json'}))
        self.store = inspect_store.store_path(NAME, self.base)


class HookTest(HookCase):
    def test_answers_and_records_without_upstream(self):
        self.up.shutdown()
        st, r, body = self.req('POST', '/hook', body=b'{"event":"push"}',
                               headers={'Content-Type': 'application/json',
                                        'Authorization': 'token abcdefghijklmnop'})
        self.assertEqual((st, body), (202, b'{"ok":true}'))
        self.assertEqual(r.getheader('Content-Type'), 'application/json')
        for _ in range(50):
            recs = inspect_store.read_records(self.store)
            if recs:
                break
            time.sleep(0.02)
        rec = recs[0]
        self.assertEqual((rec['handled_by'], rec['status']), ('intercept', 202))
        self.assertEqual(rec['req_body']['data'], '{"event":"push"}')
        self.assertEqual(rec['resp_body']['data'], '{"ok":true}')
        self.assertNotIn('abcdefghijklmnop', open(self.store).read())
        with self.assertRaisesRegex(inspect_store.InspectError, 'hook door'):
            inspect_store.request_replay(NAME, rec['id'], self.base)

    def test_body_cap(self):
        st, _, _ = self.req('POST', '/hook', body=b'x' * 2000)
        self.assertEqual(st, 413)
        # chunked over the cap
        s = socket.create_connection(('127.0.0.1', self.port), timeout=10)
        try:
            s.sendall(f'POST /hook HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n\r\n'
                      .encode() + b'800\r\n' + b'y' * 2048 + b'\r\n0\r\n\r\n')
            self.assertIn(b' 413 ', s.recv(1024).split(b'\r\n')[0] + b' ')
        finally:
            s.close()

    def test_rules_still_apply(self):
        self.write_state({'password': door_state.hash_password('hookpass1')})
        st, _, _ = self.req('POST', '/hook', body=b'{}')
        self.assertEqual(st, 401)


class NoUpstreamTest(DoorCase):
    def test_no_upstream_and_no_intercept_is_a_502(self):
        self.door.upstream = None
        st, _, body = self.req('GET', '/')
        self.assertEqual(st, 502)
        self.assertIn(b'Nothing behind this door', body)


class StoreLifecycleTest(unittest.TestCase):
    def test_stop_door_and_cleanup_remove_the_store(self):
        base = tempfile.mkdtemp()
        os.chmod(base, 0o700)
        self.addCleanup(lambda: subprocess.run(['rm', '-rf', base]))
        sd = tempfile.mkdtemp()
        self.addCleanup(lambda: subprocess.run(['rm', '-rf', sd]))
        orig = inspect_store.store_dir
        inspect_store.store_dir = lambda: base
        self.addCleanup(lambda: setattr(inspect_store, 'store_dir', orig))
        p = inspect_store.store_path('lifedoor')
        open(p, 'w').write('{"id":1}\n')
        open(inspect_store.socket_path('lifedoor'), 'w').close()
        door_state.write_state_atomic(os.path.join(sd, 'lifedoor.json'),
                                      {'name': 'lifedoor', 'pid': 999999999})
        door_state.stop_door('lifedoor', sd)
        self.assertFalse(os.path.exists(p))
        self.assertFalse(os.path.exists(inspect_store.socket_path('lifedoor')))

    def test_recorder_close_removes_store_and_socket(self):
        base = tempfile.mkdtemp()
        os.chmod(base, 0o700)
        self.addCleanup(lambda: subprocess.run(['rm', '-rf', base]))

        class D:
            name = 'closedoor'
            upstream = None
            clock = staticmethod(time.time)

            def rules(self):
                return {}
        rec = inspect_store.Recorder(D(), base=base)
        rec.start_control()
        rec.store.append({'id': rec.store.new_id()})
        rec.close()
        self.assertEqual(os.listdir(base), [])
        rec.store.append({'id': 99})        # a late exchange must not recreate it
        self.assertEqual(os.listdir(base), [])

    def test_tunnel_state_cleanup_removes_the_store(self):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: subprocess.run(['rm', '-rf', d]))
        env = dict(os.environ, XDG_RUNTIME_DIR=d)
        os.chmod(d, 0o700)
        script = (f'source "{_LIB}/tunnel-state.sh"; TUNNEL_STATE_DIR="{d}/st"; '
                  'dir="$(tunnel_run_dir inspect)"; touch "$dir/clean1.jsonl" "$dir/keep.jsonl"; '
                  'tunnel_state_cleanup clean1; ls "$dir"')
        p = subprocess.run(['bash', '-c', script], capture_output=True, text=True, env=env,
                           timeout=30)
        self.assertEqual(p.stdout.split(), ['keep.jsonl'])


class StatusCase(unittest.TestCase):
    OWNER = 'owner-cookie-value'

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = Path(self.tmp.name)
        self.devices = d / 'devices.json'
        with open(self.devices, 'w') as f:
            json.dump({'devices': [{'id': 'o', 'type': 'browser', 'role': 'admin',
                                    'apps': ['*'],
                                    'token_sha256': hashlib.sha256(self.OWNER.encode()).hexdigest()}]}, f)
        self.state_dir = d / 'state'
        self.state_dir.mkdir()
        self.base = d / 'insp'
        self.base.mkdir(mode=0o700)
        door_state.write_state_atomic(str(self.state_dir / 'idoor.json'), {
            'name': 'idoor', 'type': 'serve', 'pid': os.getpid(), 'port': 1,
            'started': int(time.time()), 'expires': int(time.time()) + 3600,
            'rules': {}, 'inspect': {'raw': False}})
        door_state.write_state_atomic(str(self.state_dir / 'plain.json'), {
            'name': 'plain', 'type': 'serve', 'pid': os.getpid(), 'port': 1,
            'started': int(time.time()), 'expires': int(time.time()) + 3600, 'rules': {}})
        self.store = inspect_store.Store(str(self.base / 'idoor.jsonl'))
        for i in range(5):
            self.store.append({'id': self.store.new_id(), 'ts': time.time(), 'method': 'GET',
                               'target': f'/p{i}', 'status': 200, 'req_headers': [],
                               'resp_headers': [], 'req_body': {'kind': 'none'},
                               'resp_body': {'kind': 'none'}, 'handled_by': 'upstream'})
        base, sd, dev = str(self.base), self.state_dir, str(self.devices)

        class H(ss.StatusHandler):
            state_dir = sd
            devices_path = dev
            inspect_base = base
            sse_max_seconds = 1.5
            sse_heartbeat = 0.3

            def log_message(self, *a):
                pass
        self.srv = ss.StatusServer(('127.0.0.1', 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.port = self.srv.server_address[1]

    def req(self, method, path, owner=True, csrf=True, headers=None):
        h = {'Host': 'panel.cush.rocks'}
        if owner:
            h['Cookie'] = f'cush_auth={self.OWNER}'
            if csrf:
                h['X-CSRF-Token'] = ss.csrf_token_for(self.OWNER)
        h.update(headers or {})
        c = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        try:
            c.request(method, path, headers=h)
            r = c.getresponse()
            raw = r.read()
            try:
                return r.status, json.loads(raw)
            except ValueError:
                return r.status, raw
        finally:
            c.close()


class StatusApiTest(StatusCase):
    def test_owner_gate(self):
        self.assertEqual(self.req('GET', '/api/tunnels/idoor/requests', owner=False)[0], 403)
        self.assertEqual(self.req('GET', '/api/tunnels/idoor/requests/1', owner=False)[0], 403)
        self.assertEqual(self.req('GET', '/api/tunnels/idoor/requests/events', owner=False)[0], 403)

    def test_list_since_and_detail(self):
        st, data = self.req('GET', '/api/tunnels/idoor/requests')
        self.assertEqual(st, 200)
        self.assertEqual([r['id'] for r in data['records']], [1, 2, 3, 4, 5])
        self.assertEqual(data['last'], 5)
        st, data = self.req('GET', '/api/tunnels/idoor/requests?since=3')
        self.assertEqual([r['id'] for r in data['records']], [4, 5])
        st, data = self.req('GET', '/api/tunnels/idoor/requests?since=1&limit=2')
        self.assertEqual(([r['id'] for r in data['records']], data['more']), ([2, 3], True))
        self.assertNotIn('req_headers', data['records'][0])
        st, rec = self.req('GET', '/api/tunnels/idoor/requests/2')
        self.assertEqual((st, rec['target']), (200, '/p1'))
        self.assertEqual(self.req('GET', '/api/tunnels/idoor/requests/99')[0], 404)
        self.assertEqual(self.req('GET', '/api/tunnels/plain/requests')[0], 404)
        self.assertEqual(self.req('GET', '/api/tunnels/nope/requests')[0], 404)
        self.assertEqual(self.req('GET', '/api/tunnels/BAD_name/requests')[0], 400)

    def test_tunnel_list_flags(self):
        st, data = self.req('GET', '/api/tunnels')
        by = {t['name']: t for t in data}
        self.assertTrue(by['idoor']['inspect'])
        self.assertFalse(by['plain']['inspect'])
        self.assertFalse(by['idoor']['capture'])

    def test_replay_csrf_and_no_proxy(self):
        st, _ = self.req('POST', '/api/tunnels/idoor/requests/1/replay', csrf=False)
        self.assertEqual(st, 403)
        self.assertEqual(self.req('POST', '/api/tunnels/idoor/requests/1/replay', owner=False)[0], 403)
        st, data = self.req('POST', '/api/tunnels/idoor/requests/1/replay')
        self.assertEqual(st, 409)                       # no proxy socket in this test
        self.assertIn('no inspector', data['message'])

    def test_sse_stream(self):
        c = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        c.request('GET', '/api/tunnels/idoor/requests/events?since=3',
                  headers={'Host': 'panel.cush.rocks', 'Cookie': f'cush_auth={self.OWNER}'})
        r = c.getresponse()
        self.assertEqual(r.status, 200)
        self.assertTrue(r.getheader('Content-Type').startswith('text/event-stream'))
        threading.Timer(0.3, lambda: self.store.append(
            {'id': self.store.new_id(), 'method': 'POST', 'target': '/late', 'status': 201})).start()
        body = r.read().decode()          # the stream ends after sse_max_seconds
        c.close()
        ids = [int(ln[4:]) for ln in body.splitlines() if ln.startswith('id: ')]
        self.assertEqual(ids, [4, 5, 6])
        self.assertIn('/late', body)
        self.assertIn(': ping', body)
        # Last-Event-ID wins over since=
        c = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        c.request('GET', '/api/tunnels/idoor/requests/events?since=0',
                  headers={'Host': 'panel.cush.rocks', 'Cookie': f'cush_auth={self.OWNER}',
                           'Last-Event-ID': '5'})
        body = c.getresponse().read().decode()
        c.close()
        self.assertEqual([int(ln[4:]) for ln in body.splitlines() if ln.startswith('id: ')], [6])

    def test_sse_cap(self):
        held = []
        for _ in range(ss.SSE_MAX_STREAMS):
            self.assertTrue(ss._sse_slots.acquire(blocking=False))
            held.append(1)
        try:
            self.assertEqual(self.req('GET', '/api/tunnels/idoor/requests/events')[0], 429)
        finally:
            for _ in held:
                ss._sse_slots.release()

    def test_console_has_inspect_view(self):
        st, html = self.req('GET', '/')
        self.assertEqual(st, 200)
        self.assertIn(b'id="inspView"', html)
        self.assertNotIn(b'.innerHTML =', html)


class CliTest(InspCase):
    def run_cli(self, *args):
        out = io.StringIO()
        err = io.StringIO()
        old = sys.stderr
        sys.stderr = err
        try:
            rc = cmd_inspect.main(list(args), out=out, state_dir=self.state_dir, base=self.base)
        finally:
            sys.stderr = old
        return rc, out.getvalue(), err.getvalue()

    def test_list_json_show_replay(self):
        self.write_state({}, inspect={'raw': False})
        rc, out, _ = self.run_cli(NAME)
        self.assertEqual((rc, out.strip()), (0, f'{NAME}: no requests yet'))
        self.req('POST', '/up', body=b'{"a":1}', headers={'Content-Type': 'application/json',
                                                          'Authorization': 'Bearer abcdefghijklmn'})
        self.wait_for(1)
        rc, out, _ = self.run_cli(NAME)
        self.assertEqual(rc, 0)
        self.assertRegex(out, r'#1 +\d\d:\d\d:\d\d POST +/up 200 +\d+ms')
        rc, out, _ = self.run_cli(NAME, '--json')
        data = json.loads(out)
        self.assertEqual((data[0]['id'], data[0]['method'], data[0]['status']), (1, 'POST', 200))
        rc, out, _ = self.run_cli(NAME, '--show', '1')
        self.assertIn('Authorization: Bear…[masked, 21 chars]', out)
        self.assertIn('"a": 1', out)
        rc, out, _ = self.run_cli(NAME, '--show', '1', '--json')
        self.assertEqual(json.loads(out)['id'], 1)
        rc, out, _ = self.run_cli(NAME, '--replay', '1')
        self.assertEqual(rc, 0)
        self.assertIn('(replay of #1)', out)
        rc, _, err = self.run_cli(NAME, '--show', '42')
        self.assertEqual(rc, 1)

    def test_follow(self):
        self.write_state({}, inspect={'raw': False})
        threading.Timer(0.2, lambda: self.req('GET', '/echo')).start()
        out = io.StringIO()
        cmd_inspect.main([NAME, '--follow', '--json'], out=out, state_dir=self.state_dir,
                         base=self.base, poll=0.05, follow_for=1.5)
        lines = [json.loads(x) for x in out.getvalue().splitlines() if x.strip()]
        self.assertEqual([r['target'] for r in lines], ['/echo'])

    def test_not_inspected_and_hook_replay(self):
        rc, _, err = self.run_cli(NAME)
        self.assertEqual(rc, 1)
        self.assertIn('not inspected', err)
        self.write_state({}, capture={'status': 200})
        rc, _, err = self.run_cli(NAME, '--replay', '1')
        self.assertEqual(rc, 3)
        self.assertIn('no app', err)


class FlagsTest(unittest.TestCase):
    SCRIPT = r'''
source "$1/tunnel-state.sh"
TUNNEL_STATE_DIR="$2"
shift 2
door_flags_parse "$@" || exit 2
set -- "${DOOR_REST[@]}"
echo "rest=$*"
door_spec_build "" || exit 2
tunnel_state_register flagtest serve $$ 1234
door_print_summary flagtest
door_needs_proxy "$TUNNEL_STATE_DIR/flagtest.json" && echo NEEDS_PROXY
echo "args=$(door_proxy_args "$TUNNEL_STATE_DIR/flagtest.json" | tr '\n' ' ')"
'''

    def run_flags(self, *args):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: subprocess.run(['rm', '-rf', d]))
        e = {k: v for k, v in os.environ.items() if not k.startswith('PORCH_DOOR')}
        e['CUSH_HISTORY_FILE'] = os.path.join(d, 'history.jsonl')
        p = subprocess.run(['bash', '-c', self.SCRIPT, 'x', _LIB, d, *args],
                           capture_output=True, text=True, env=e, stdin=subprocess.DEVNULL,
                           timeout=30)
        state = None
        if os.path.exists(os.path.join(d, 'flagtest.json')):
            with open(os.path.join(d, 'flagtest.json')) as f:
                state = json.load(f)
        return p, state

    def test_inspect_flags(self):
        p, s = self.run_flags('a', '--inspect', 'b')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('rest=a b', p.stdout)
        self.assertEqual(s['inspect'], {'raw': False})
        self.assertIn('NEEDS_PROXY', p.stdout)
        self.assertIn('args=--inspect ', p.stdout)
        self.assertIn('Inspector: on (secret headers masked)', p.stdout)
        p, s = self.run_flags('--inspect-raw')
        self.assertEqual(s['inspect'], {'raw': True})
        self.assertIn('args=--inspect-raw ', p.stdout)
        self.assertIn('unmasked', p.stderr)
        p, s = self.run_flags('x')
        self.assertNotIn('inspect', s)
        self.assertNotIn('NEEDS_PROXY', p.stdout)

    def test_set_capture_cli(self):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: subprocess.run(['rm', '-rf', d]))
        sp = os.path.join(d, 'h.json')
        door_state.write_state_atomic(sp, {'name': 'h', 'pid': 1})
        dsp = os.path.join(_LIB, 'door_state.py')
        p = subprocess.run([sys.executable, dsp, 'set-capture', sp, '201', 'application/json', '5'],
                           input=b'{"ok":1}', capture_output=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        cap = door_state.read_state(sp)['capture']
        self.assertEqual(cap, {'status': 201, 'content_type': 'application/json',
                               'body': '{"ok":1}', 'max_body_mb': 5})
        self.assertEqual(door_state.capture_max_body(cap), 5 * 1024 * 1024)
        self.assertEqual(door_state.proxy_args(door_state.read_state(sp)), ['--capture'])
        for bad in (['99', 'text/plain'], ['200', 'nope'], ['200', 'text/plain', '0']):
            p = subprocess.run([sys.executable, dsp, 'set-capture', sp, *bad], input=b'',
                               capture_output=True)
            self.assertEqual(p.returncode, 2, bad)


class HookArgsTest(unittest.TestCase):
    def run_hook(self, *args):
        return subprocess.run([os.path.join(_BIN, 'hook'), *args], capture_output=True,
                              text=True, stdin=subprocess.DEVNULL, timeout=30)

    def test_bad_args_fail_before_anything_starts(self):
        self.assertEqual(self.run_hook().returncode, 1)
        self.assertEqual(self.run_hook('a', 'b').returncode, 1)
        self.assertEqual(self.run_hook('bad_name!').returncode, 2)
        self.assertEqual(self.run_hook('h1', '--status', '700').returncode, 2)
        self.assertEqual(self.run_hook('h1', '--status').returncode, 2)
        self.assertEqual(self.run_hook('h1', '--content-type', 'plain').returncode, 2)
        self.assertEqual(self.run_hook('h1', '--max-body-mb', '0').returncode, 2)
        self.assertEqual(self.run_hook('h1', '--frobnicate').returncode, 2)
        self.assertEqual(self.run_hook('h1', '--expires', 'soonish').returncode, 2)
        self.assertIn('Usage: hook', self.run_hook('--help').stdout)

    def test_tunnel_refuses_port_dash_standalone(self):
        p = subprocess.run([os.path.join(_BIN, 'tunnel'), '-', 'h1'], capture_output=True,
                           text=True, stdin=subprocess.DEVNULL, timeout=30,
                           env={k: v for k, v in os.environ.items() if k != 'TUNNEL_NO_STATE'})
        self.assertEqual(p.returncode, 2)
        self.assertIn('bin/hook', p.stderr)


if __name__ == '__main__':
    unittest.main()


class TestTerminalSafety(unittest.TestCase):
    """Request bytes come from anyone; porch inspect prints them to a terminal."""

    def rec(self):
        return {'id': 3, 'ts': 0, 'method': 'POST', 'target': '/x\x1b]52;c;cHdu\x07', 'status': 200, 'ms': 1,
                'req_headers': [['X-A', 'v\x9b2J']], 'resp_headers': [],
                'req_body': {'kind': 'text', 'size': 20, 'type': 'text/plain',
                             'data': 'hi \x1b[31mRED‮ end\n\tok'},
                'resp_body': {'kind': 'text', 'size': 9, 'type': 'application/json',
                              'data': '{"s": "…[masked]"}'}}

    def test_details_escapes_control_characters(self):
        out = inspect_store.details(self.rec())
        for bad in ('\x1b', '\x07', '\x9b', '‮'):
            self.assertNotIn(bad, out)
        self.assertIn('hi \\x1b[31mRED\\u202e end\n    \tok', out)
        self.assertIn('\\x9b2J', out)
        self.assertIn('"s": "…[masked]"', out)       # JSON shown as text, not \\u2026

    def test_one_line_escapes_the_target(self):
        for color in (False, True):
            out = inspect_store.one_line(self.rec(), color)
            self.assertNotIn('\x07', out)
            self.assertNotIn('\x1b]52', out)
            self.assertIn('/x\\x1b]52;c;cHdu\\x07', out)

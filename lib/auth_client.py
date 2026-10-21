"""Client for porch-auth's CLI-token API (/auth/admin/* on 127.0.0.1:9512),
shared by bin/auth-admin and Pocket.

The token is the one the running server writes to data/.admin-cli-token
(0600, new on every start). It is read from the file on each call (cached on
mtime/size/inode, so a restart's new token is picked up at once), sent only
as the X-Cush-CLI-Token header, and never logged, echoed or put in an
exception: every error here is built from the server's own `error` text or
the transport error, and raised `from None`.

Requests never go through an HTTP proxy from the environment
(ProxyHandler({})) and never carry Origin or forwarded headers: the server
ignores the token on anything that looks proxied, and it must not leave the
box. A 401 re-reads the token file once and, if it changed (porch-auth
restarted between the read and the call), retries with the new token.

PORCH_AUTH_URL (old name: CUSH_AUTH_URL) overrides the base URL (tests); it must stay a loopback URL.
"""

import json
import os
import threading
import urllib.error
import urllib.request

DEFAULT_URL = 'http://127.0.0.1:9512'
CLI_TOKEN_FILENAME = '.admin-cli-token'
CLI_TOKEN_HEADER = 'X-Cush-CLI-Token'
TIMEOUT = 15
# verify-password's 401 text for a wrong password (any other 401 is the token).
WRONG_PASSWORD = 'invalid password'


class AuthError(Exception):
    """porch-auth answered with an error. `status` is the HTTP code (0 when
    there was no usable answer), `message` the server's `error` text (may be
    empty), `reason` the HTTP reason phrase."""

    def __init__(self, status, message='', reason=''):
        super().__init__(message or reason or f'HTTP {status}')
        self.status = status
        self.message = message
        self.reason = reason


class TokenError(AuthError):
    """The CLI token file is missing, unreadable or empty."""

    def __init__(self, message):
        super().__init__(0, message)


class BadReply(AuthError):
    """A 2xx answer that is not a JSON object."""

    def __init__(self):
        super().__init__(0, 'server sent a reply that is not JSON')


class AuthDown(Exception):
    """porch-auth could not be reached at all."""

    def __init__(self, url, detail):
        super().__init__(f'could not reach authserver at {url}: {detail}')
        self.url = url
        self.detail = detail


def base_url():
    return os.environ.get('PORCH_AUTH_URL') or os.environ.get('CUSH_AUTH_URL') or DEFAULT_URL


class Client:
    """One porch-auth endpoint + the data dir holding its CLI token."""

    def __init__(self, data_dir, url=None, timeout=TIMEOUT):
        self.data_dir = data_dir
        self._url = url
        self.timeout = timeout
        self._lock = threading.Lock()
        self._cache = (None, None)       # (stat key, token)
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    @property
    def url(self):
        return self._url or base_url()

    @property
    def token_path(self):
        return os.path.join(self.data_dir, CLI_TOKEN_FILENAME)

    def token(self, fresh=False):
        path = self.token_path
        try:
            st = os.stat(path)
        except OSError as e:
            raise TokenError(f"could not read {path}: {e} "
                             "(is porch-auth running? it writes the token on start)") from None
        key = (st.st_mtime_ns, st.st_size, st.st_ino)
        with self._lock:
            if not fresh and self._cache[0] == key:
                return self._cache[1]
        try:
            with open(path, 'r') as f:
                token = f.read().strip()
        except OSError as e:
            raise TokenError(f"could not read {path}: {e} "
                             "(is porch-auth running? it writes the token on start)") from None
        if not token:
            raise TokenError(f"{path} is empty; restart porch-auth with bin/auth-deploy")
        with self._lock:
            self._cache = (key, token)
        return token

    def answers(self, timeout=3):
        """True when something answers at the auth URL (any HTTP status)."""
        try:
            with self._opener.open(self.url + '/healthz', timeout=timeout):
                return True
        except urllib.error.HTTPError:
            return True
        except (urllib.error.URLError, OSError, ValueError):
            return False

    def _send(self, method, path, payload, token):
        headers = {CLI_TOKEN_HEADER: token}
        if payload is not None:
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(self.url + path, data=payload, headers=headers,
                                     method=method)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read().decode('utf-8')).get('error') or ''
            except (ValueError, AttributeError, OSError):
                msg = ''
            finally:
                e.close()
            raise AuthError(e.code, msg if isinstance(msg, str) else '',
                            str(e.reason or '')) from None
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise AuthDown(self.url, e) from None

    def request(self, method, path, body=None):
        """Call /auth/admin/... and return the decoded JSON object. Raises
        AuthError (incl. TokenError, BadReply) or AuthDown."""
        payload = None if body is None else json.dumps(body).encode('utf-8')
        token = self.token()
        try:
            raw = self._send(method, path, payload, token)
        except AuthError as e:
            if e.status != 401:
                raise
            # porch-auth writes a new token on every start: one retry, only
            # when the file really changed (a wrong password is also a 401).
            fresh = self.token(fresh=True)
            if fresh == token:
                raise
            raw = self._send(method, path, payload, fresh)
        try:
            data = json.loads(raw.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            raise BadReply() from None
        if not isinstance(data, dict):
            raise BadReply()
        return data

    # ---- endpoints -----------------------------------------------------------

    def state(self):
        return self.request('GET', '/auth/admin/state')

    def approve(self, code, apps=None):
        body = {'code': code}
        if apps is not None:
            body['apps'] = apps
        return self.request('POST', '/auth/admin/approve', body)

    def reject(self, code):
        return self.request('POST', '/auth/admin/reject', {'code': code})

    def revoke(self, device_id):
        return self.request('POST', '/auth/admin/revoke', {'device_id': device_id})

    def device_role(self, device_id, role):
        return self.request('POST', '/auth/admin/device-role',
                            {'device_id': device_id, 'role': role})

    def device_apps(self, device_id, apps):
        return self.request('POST', '/auth/admin/device-apps',
                            {'device_id': device_id, 'apps': apps})

    def device_rename(self, device_id, name):
        return self.request('POST', '/auth/admin/device-rename',
                            {'device_id': device_id, 'name': name})

    def apps(self, host, action):
        return self.request('POST', '/auth/admin/apps', {'host': host, 'action': action})

    def public_paths(self):
        return self.request('GET', '/auth/admin/public-paths')

    def public_path(self, action, by=None, **fields):
        """action add (host, path, app, why) or enable|disable|remove (id).
        `by` is cli or pocket (recorded as created_by on add)."""
        body = {'action': action}
        body.update({k: v for k, v in fields.items() if v is not None})
        if by:
            body['by'] = by
        return self.request('POST', '/auth/admin/public-paths', body)

    def invite_create(self, body):
        return self.request('POST', '/auth/admin/invites', body)

    def invite_revoke(self, invite_id, revoke_devices=False):
        return self.request('POST', '/auth/admin/invite-revoke',
                            {'id': invite_id, 'revoke_devices': bool(revoke_devices)})

    def access_requests(self):
        """Ask for access: pending + recently decided asks (no tokens, no links)."""
        return self.request('GET', '/auth/admin/access-requests')

    def access_decide(self, rid, decision, device_ttl_minutes=None):
        """allow | deny one ask. Allow adds the host to an asking device's
        scope, or mints a single-use invite whose link only the visitor sees."""
        body = {'id': rid, 'decision': decision}
        if device_ttl_minutes is not None:
            body['device_ttl_minutes'] = device_ttl_minutes
        return self.request('POST', '/auth/admin/access-requests/decide', body)

    def set_password(self, new):
        return self.request('POST', '/auth/admin/set-password', {'new': new})

    def verify_password(self, password, ip=None):
        """True for the admin password, False for a wrong one. A 429 (the
        login limiter) or 503 (scrypt busy) raises AuthError; a porch-auth
        without the endpoint raises AuthError(404)."""
        body = {'password': password}
        if ip:
            body['ip'] = ip
        try:
            return self.request('POST', '/auth/admin/verify-password', body).get('ok') is True
        except AuthError as e:
            if e.status == 401 and e.message == WRONG_PASSWORD:
                return False
            raise

    def server(self, addr, port=None):
        body = {'addr': addr}
        if port is not None:
            body['port'] = port
        return self.request('POST', '/auth/admin/server', body)

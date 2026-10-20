"""Pocket's audit log: one JSON line per privileged action, in
~/pocket/<name>/.audit.jsonl (0600, appended with O_APPEND).

Only the fact of an action goes in: what (`action`), on what (`target`: a
door name, device id, invite id, host, passkey label), how the owner was
stepped up (`method`: passkey | password | ''), from where (`ip`), and the
outcome (`result`: ok | failed | refused, plus a stable `code` on failure).
Never a password, an invite URL, a token, a guest link or a request body:
`append()` refuses field names that look like one, and every value is
cut to a short single line.

The file is a ring: past COMPACT_AT lines it is rewritten (atomically) to
the newest KEEP. GET /api/activity reads it newest first.
"""

import json
import os
import re
import sys
import threading
import time
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from porch_http import atomic_write_bytes  # noqa: E402

KEEP = 1000
COMPACT_AT = 1100
MAX_VALUE = 120
FIELDS = ('action', 'target', 'method', 'ip', 'result', 'code', 'detail')
# Never stored, whatever a caller passes.
_SECRETISH = re.compile(r'pass|secret|token|url|key|cookie|credential|signature', re.I)
_CTRL = re.compile(r'[\x00-\x1f\x7f]')


def _clean(v):
    if v is None:
        return ''
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, (int, float)):
        return v
    return _CTRL.sub(' ', str(v))[:MAX_VALUE]


class AuditLog:

    def __init__(self, path, keep=KEEP, compact_at=COMPACT_AT, clock=time.time):
        self.path = str(path)
        self.keep = keep
        self.compact_at = compact_at
        self.clock = clock
        self.lock = threading.Lock()
        self._lines = None          # counted lazily

    def _count(self):
        try:
            with open(self.path, 'rb') as f:
                return sum(1 for _ in f)
        except OSError:
            return 0

    def append(self, action, target='', method='', ip='', result='ok', code='', detail=''):
        rec = {'ts': int(self.clock())}
        for k, v in zip(FIELDS, (action, target, method, ip, result, code, detail)):
            v = _clean(v)
            if v != '' or k in ('action', 'target'):
                rec[k] = v
        # A caller that put something secret-looking in `detail` loses it.
        if 'detail' in rec and _SECRETISH.search(str(rec['detail'])):
            rec.pop('detail')
        line = (json.dumps(rec, separators=(',', ':')) + '\n').encode('utf-8')
        with self.lock:
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
                             0o600)
            except OSError as e:
                sys.stderr.write(f"[pocketserver] audit log unwritable: {e.__class__.__name__}\n")
                return rec
            try:
                os.fchmod(fd, 0o600)
                os.write(fd, line)
            finally:
                os.close(fd)
            if self._lines is None:
                self._lines = self._count()
            else:
                self._lines += 1
            if self._lines > self.compact_at:
                self._compact()
        return rec

    def _compact(self):
        recs = self._read_all()[-self.keep:]
        data = b''.join((json.dumps(r, separators=(',', ':')) + '\n').encode('utf-8')
                        for r in recs)
        try:
            atomic_write_bytes(Path(self.path), data, mode=0o600)
            self._lines = len(recs)
        except OSError:
            self._lines = None

    def _read_all(self):
        out = []
        try:
            with open(self.path, 'rb') as f:
                for raw in f:
                    try:
                        r = json.loads(raw)
                    except ValueError:
                        continue
                    if isinstance(r, dict) and isinstance(r.get('ts'), int):
                        out.append(r)
        except OSError:
            pass
        return out

    def recent(self, limit=100):
        """The newest `limit` records, newest first."""
        limit = max(1, min(self.keep, int(limit)))
        with self.lock:
            recs = self._read_all()
        return list(reversed(recs[-limit:]))

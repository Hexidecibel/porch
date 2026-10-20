"""Setup state: data/porch-setup.json (0600, atomic) + data/.porch-setup.lock.

Schema (version 1) is documented in docs/porch-setup-design.md, section 1.
Only refs to secrets are ever stored here, and the serialized text still goes
through the redactor on save as a second line of defence.

The data dir is <repo>/data, or $PORCH_SETUP_DIR when set (tests, a second
install). Callers normally go through engine.make_context(), not this module.
"""

import datetime
import errno
import fcntl
import json
import os
import secrets
import stat

from . import redact as _redact

SCHEMA_VERSION = 1
STATE_NAME = "porch-setup.json"
LOCK_NAME = ".porch-setup.lock"
LOG_NAME = "porch-setup.log"
BACKUP_DIR_NAME = "porch-setup-backups"

STATUSES = ("pending", "running", "done", "failed", "skipped", "adopted", "rolled_back")

PKG_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(os.path.dirname(PKG_DIR))


class StateError(Exception):
    pass


class Locked(StateError):
    """Another porch setup (CLI or web) holds the lock."""


def default_data_dir(env=None):
    env = os.environ if env is None else env
    return env.get("PORCH_SETUP_DIR") or os.path.join(REPO_DIR, "data")


def now_iso(clock=None):
    t = clock() if clock else None
    dt = (datetime.datetime.fromtimestamp(t, datetime.timezone.utc) if t is not None
          else datetime.datetime.now(datetime.timezone.utc))
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def new_state(clock=None):
    return {
        "version": SCHEMA_VERSION,
        "run_id": secrets.token_hex(8),
        "created_at": now_iso(clock),
        "mode": "fresh",
        "inputs": {},
        "secret_refs": {},
        "facts": {},
        "steps": {},
        "files": {},
        "connection": {"active": None, "history": [], "relay": None},
    }


def new_step_entry():
    return {"status": "pending", "attempts": 0, "started_at": None, "finished_at": None,
            "outputs": {}, "error": None, "undo": []}


# from-version -> function(data) returning data at from-version + 1.
# Version 0 is "no version key" (never shipped; kept so the hook is exercised).
def _m0(data):
    data["version"] = 1
    return data


MIGRATIONS = {0: _m0}


def migrate(data):
    v = data.get("version", 0)
    if not isinstance(v, int) or v > SCHEMA_VERSION:
        raise StateError(f"state file version {v!r} is newer than this porch "
                         f"(knows {SCHEMA_VERSION}); upgrade porch")
    while v < SCHEMA_VERSION:
        data = MIGRATIONS[v](data)
        v = data["version"]
    # fill keys added without a version bump
    base = new_state()
    for k, val in base.items():
        data.setdefault(k, val)
    for entry in data["steps"].values():
        for k, val in new_step_entry().items():
            entry.setdefault(k, val)
    return data


def _ensure_dir(d):
    if not os.path.isdir(d):
        os.makedirs(d, mode=0o700, exist_ok=True)


class StateLock:
    """fcntl.flock on <data>/.porch-setup.lock. Non-blocking by default:
    a second front-end gets Locked instead of waiting."""

    def __init__(self, path):
        self.path = path
        self._fd = None

    def acquire(self, blocking=False):
        if self._fd is not None:
            return self
        _ensure_dir(os.path.dirname(self.path))
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except OSError as e:
            os.close(fd)
            if e.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                raise Locked("another porch setup is running (lock: %s)" % self.path) from None
            raise
        self._fd = fd
        return self

    def release(self):
        if self._fd is not None:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            self._fd = None

    @property
    def held(self):
        return self._fd is not None

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *a):
        self.release()


def _atomic_write(path, data):
    d, base = os.path.split(path)
    tmp = os.path.join(d or ".", f".{base}.{secrets.token_hex(6)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class State:
    """The parsed state file. `data` is the raw dict; the properties below
    are live views into it. Call save() after changing it (the engine does)."""

    def __init__(self, path, data=None, redactor=None, clock=None):
        self.path = path
        self.redactor = redactor or _redact.REDACTOR
        self.clock = clock
        self.data = migrate(data) if data is not None else new_state(clock)
        self.persist = True  # engine sets False in dry-run: save() is a no-op

    @classmethod
    def load(cls, path, redactor=None, clock=None):
        st = cls(path, None, redactor, clock)
        st.reload()
        return st

    def reload(self):
        try:
            fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            self.data = new_state(self.clock)
            return self
        except OSError as e:
            raise StateError(f"cannot open {self.path}: {e}") from None
        with os.fdopen(fd, "rb") as f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode):
                raise StateError(f"{self.path} is not a regular file")
            raw = f.read()
        if st.st_mode & 0o077:
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            raise StateError(f"{self.path} is not valid JSON: {e}") from None
        if not isinstance(data, dict):
            raise StateError(f"{self.path} must hold a JSON object")
        self.data = migrate(data)
        return self

    def to_json(self):
        return self.redactor.redact(json.dumps(self.data, indent=2, sort_keys=True)) + "\n"

    def save(self):
        if not self.persist:
            return
        _ensure_dir(os.path.dirname(self.path))
        _atomic_write(self.path, self.to_json().encode("utf-8"))

    # ---- views ---------------------------------------------------------------
    @property
    def inputs(self):
        return self.data["inputs"]

    @property
    def secret_refs(self):
        return self.data["secret_refs"]

    @property
    def facts(self):
        return self.data["facts"]

    @property
    def steps(self):
        return self.data["steps"]

    @property
    def files(self):
        return self.data["files"]

    @property
    def connection(self):
        return self.data["connection"]

    @property
    def mode(self):
        return self.data["mode"]

    @mode.setter
    def mode(self, v):
        self.data["mode"] = v

    @property
    def run_id(self):
        return self.data["run_id"]

    def step(self, step_id):
        """The step's entry, created as pending if new."""
        return self.data["steps"].setdefault(step_id, new_step_entry())

    def status_of(self, step_id):
        e = self.data["steps"].get(step_id)
        return e["status"] if e else "pending"

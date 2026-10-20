"""Ref-based secrets for porch setup. Owned by W2 after the Day-0 freeze.

Only refs are ever kept in state / porch.toml; values live in a backend:

    inf://<env>/<path>/<KEY>         Infisical (default for new secrets)
    op://<vault>/<item>/<field>      1Password (legacy)
    file://~/.config/porch/secrets/<name>   0600 file in a 0700 dir
    file:///abs/path/under/the/root         (absolute form, same rule)

Every value read or written is registered with the redactor, so it is masked
in state, logs, IO events and recorded Runner calls.

    store = SecretStore()                 # ctx.secrets is one of these
    store.put("file://~/.config/porch/secrets/cloudflare", token)
    store.get(ref) -> str                 # raises SecretNotFound
    store.exists(ref) -> bool
    store.remember(ref, value)            # in-memory only (dry-run)
    default_ref(name, backend="file")     # where a new secret goes

file:// refs must resolve inside `file_root` (default ~/.config/porch/secrets,
or $PORCH_SECRETS_DIR); anything else is refused.
"""

import os
import re
import stat

from . import redact as _redact

SCHEMES = ("inf", "op", "file")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


class SecretError(Exception):
    pass


class SecretNotFound(SecretError):
    pass


def default_file_root(env=None):
    env = os.environ if env is None else env
    return env.get("PORCH_SECRETS_DIR") or os.path.expanduser("~/.config/porch/secrets")


def scheme_of(ref):
    if not isinstance(ref, str) or "://" not in ref:
        # never echo it: a value passed where a ref belongs is the secret itself
        raise SecretError("not a secret ref (want inf://, op:// or file://)")
    s = ref.split("://", 1)[0]
    if s not in SCHEMES:
        raise SecretError("unknown secret ref scheme (want inf://, op:// or file://)")
    return s


def is_ref(s):
    try:
        scheme_of(s)
        return True
    except SecretError:
        return False


def default_ref(name, backend="file", env_name="prod", file_root=None):
    """The ref a new secret called `name` is stored at (file:// unless asked;
    callers that know Infisical is authenticated pass backend="inf")."""
    if not _NAME_RE.match(name):
        raise SecretError(f"bad secret name {name!r}")
    if backend == "inf":
        return f"inf://{env_name}/porch/{name.upper().replace('-', '_')}"
    if backend == "file":
        if file_root:
            return "file://" + os.path.join(os.path.abspath(file_root), name)
        return f"file://~/.config/porch/secrets/{name}"
    raise SecretError(f"no default ref for backend {backend!r}")


class SecretStore:
    """`backend` (tests) is an object with read(ref) and item_upsert(ref, value)
    raising cush_secrets-style exceptions; default: lib/cush_secrets.py."""

    def __init__(self, redactor=None, file_root=None, backend=None):
        self.redactor = redactor or _redact.REDACTOR
        self.file_root = os.path.abspath(file_root or default_file_root())
        self._memory = {}
        self._backend = backend

    # ---- file:// -------------------------------------------------------------
    def _file_path(self, ref):
        rest = ref[len("file://"):]
        if rest.startswith("~/"):
            # ~ means the store's root's conventional home: map
            # ~/.config/porch/secrets/<x> onto file_root/<x> so tests can relocate it.
            conv = "~/.config/porch/secrets/"
            if rest.startswith(conv):
                path = os.path.join(self.file_root, rest[len(conv):])
            else:
                path = os.path.expanduser(rest)
        else:
            path = rest
        if not os.path.isabs(path):
            raise SecretError("file:// ref must be absolute or start with ~/")
        path = os.path.normpath(path)
        root = self.file_root.rstrip("/") + "/"
        if not path.startswith(root) or path == self.file_root:
            raise SecretError(f"file:// secrets must live under {self.file_root}")
        return path

    def _ensure_root(self):
        os.makedirs(self.file_root, mode=0o700, exist_ok=True)
        st = os.lstat(self.file_root)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
            raise SecretError(f"{self.file_root} must be a directory owned by you")
        if st.st_mode & 0o077:
            os.chmod(self.file_root, 0o700)

    def _file_get(self, ref):
        path = self._file_path(ref)
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            raise SecretNotFound("secret not found (file:// ref points at no file)") from None
        except OSError as e:
            raise SecretError(f"cannot read the file:// secret: {e.strerror or type(e).__name__}") from None
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            return f.read()

    def _file_put(self, ref, value):
        path = self._file_path(ref)
        self._ensure_root()
        d = os.path.dirname(path)
        if d != self.file_root:
            os.makedirs(d, mode=0o700, exist_ok=True)
        tmp = f"{path}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(value)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    # ---- api -----------------------------------------------------------------
    def get(self, ref) -> str:
        scheme = scheme_of(ref)
        if ref in self._memory:
            value = self._memory[ref]
        elif scheme == "file":
            value = self._file_get(ref)
        else:
            value = self._backend_get(scheme, ref)
        self.redactor.add(value)
        return value

    def put(self, ref, value) -> None:
        if not isinstance(value, str) or value == "":
            raise SecretError("secret value must be a non-empty string")
        scheme = scheme_of(ref)
        self.redactor.add(value)
        if scheme == "file":
            self._file_put(ref, value)
        else:
            self._backend_put(scheme, ref, value)
        self._memory.pop(ref, None)

    def remember(self, ref, value) -> None:
        """Hold a value for this process only (dry-run: nothing is stored)."""
        scheme_of(ref)
        self.redactor.add(value)
        self._memory[ref] = value

    def exists(self, ref) -> bool:
        try:
            self.get(ref)
            return True
        except SecretNotFound:
            return False

    # ---- inf:// op:// --------------------------------------------------------
    # Dispatched through lib/cush_secrets.py. Its exceptions carry the ref (and
    # the backend CLI's stderr) in their text, so none of that is passed on:
    # a mistyped flag may hold the secret itself.
    def _backend_mod(self):
        if self._backend is None:
            try:
                import cush_secrets  # lib/ is on sys.path whenever porch_setup is
            except ImportError:
                raise SecretError("secret backends unavailable (lib/cush_secrets.py not importable)") from None
            self._backend = cush_secrets
        return self._backend

    @staticmethod
    def _map_error(scheme, e, writing):
        name = type(e).__name__
        mro = {c.__name__ for c in type(e).__mro__}
        cli = "infisical" if scheme == "inf" else "op"
        cfg = "~/.config/cush-tools/infisical.env" if scheme == "inf" else "~/.config/cush-tools/op.env"
        if "SecretsRefNotFound" in mro and not writing:
            return SecretNotFound(f"{scheme}:// secret not found (check the vault/project, path and key)")
        if "SecretsAuthError" in mro:
            return SecretError(f"{scheme}:// backend not authenticated: the {cli} CLI is missing "
                               f"or its credentials in {cfg} need a refresh")
        if "SecretsAccessError" in mro:
            return SecretError(f"{scheme}:// backend refused access to that "
                               f"{'project/path' if scheme == 'inf' else 'vault'}")
        if isinstance(e, ValueError):
            return SecretError(f"malformed {scheme}:// ref "
                               + ("(want inf://<env>/<path>/<KEY>)" if scheme == "inf"
                                  else "(want op://<vault>/<item>/<field>)"))
        return SecretError(f"{scheme}:// backend {'write' if writing else 'read'} failed ({name})")

    def _backend_get(self, scheme, ref):
        mod = self._backend_mod()
        try:
            value = mod.read(ref)
        except Exception as e:  # noqa: BLE001 - mapped, never echoed
            raise self._map_error(scheme, e, writing=False) from None
        if not isinstance(value, str) or value == "":
            raise SecretNotFound(f"{scheme}:// secret is empty")
        return value

    def _backend_put(self, scheme, ref, value):
        mod = self._backend_mod()
        try:
            mod.item_upsert(ref, value)
        except Exception as e:  # noqa: BLE001
            raise self._map_error(scheme, e, writing=True) from None


_DEFAULT = None


def default_store():
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = SecretStore()
    return _DEFAULT


def get(ref):
    return default_store().get(ref)


def put(ref, value):
    default_store().put(ref, value)

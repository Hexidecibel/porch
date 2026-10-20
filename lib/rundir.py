#!/usr/bin/env python3
"""Per-user private runtime directories and safe file writes.

Tools used to drop received text and secrets into shared, world-traversable
paths such as /tmp/exchange/<name> and /tmp/secure-entry/<label>, opened with
plain open(path, 'w'). On a multi-user box another account could pre-create
the directory or plant a symlink at the target and have the next write land
wherever it pointed (or read what was written).

Everything here lives under one directory per user:

    $XDG_RUNTIME_DIR/porch/<tool>        (tmpfs, owner-only, per login)
    /tmp/porch-<uid>/<tool>              (fallback when XDG_RUNTIME_DIR is unset)

Each level is created 0700 and then *verified*: it must be a real directory
(not a symlink), owned by us, with no group/other bits. Anything else is
refused rather than silently used.

CLI (for the bash launchers):

    python3 lib/rundir.py <tool>      prints the verified directory path
"""

import os
import stat
import sys
import tempfile


class UnsafeDirError(RuntimeError):
    pass


def _ensure_private_dir(path):
    """mkdir 0700 if missing, then verify owner/mode/type. Returns path."""
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise UnsafeDirError(f"{path} is not a real directory")
    if st.st_uid != os.getuid():
        raise UnsafeDirError(f"{path} is owned by uid {st.st_uid}, not {os.getuid()}")
    if st.st_mode & 0o077:
        # Our own directory with loose bits (e.g. made by an older version):
        # tighten it, then re-check.
        os.chmod(path, 0o700)
        if os.lstat(path).st_mode & 0o077:
            raise UnsafeDirError(f"{path} is not mode 0700")
    return path


def base_dir():
    """The per-user porch root, created and verified."""
    xdg = os.environ.get('XDG_RUNTIME_DIR')
    if xdg and os.path.isabs(xdg) and os.path.isdir(xdg):
        try:
            st = os.stat(xdg)
            if st.st_uid == os.getuid() and not (st.st_mode & 0o077):
                return _ensure_private_dir(os.path.join(xdg, 'porch'))
        except OSError:
            pass
    return _ensure_private_dir(os.path.join(tempfile.gettempdir(), f'porch-{os.getuid()}'))


def tool_dir(tool):
    """The per-user directory for one tool (exchange, secure-entry, form, ...)."""
    if not tool or '/' in tool or tool.startswith('.'):
        raise ValueError(f"bad tool name: {tool!r}")
    return _ensure_private_dir(os.path.join(base_dir(), tool))


def ensure_private_subdir(path):
    """Create/verify a private subdirectory (e.g. multi-field secure-entry)."""
    return _ensure_private_dir(path)


def write_private(path, data):
    """Atomically write `data` (str or bytes) to `path` with mode 0600.

    Writes a fresh O_EXCL temp file in the same directory, then rename()s it
    over the target. rename replaces a symlink at `path` rather than following
    it, so a planted link can never redirect the write.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    d = os.path.dirname(os.path.abspath(path)) or '.'
    fd, tmp = tempfile.mkstemp(dir=d, prefix='.tmp-')   # O_EXCL, 0600
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: rundir.py <tool>\n")
        return 2
    try:
        print(tool_dir(argv[1]))
    except (UnsafeDirError, ValueError, OSError) as e:
        sys.stderr.write(f"Error: refusing unsafe runtime dir: {e}\n")
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))

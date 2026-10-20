"""Managed-file writer (ctx.files).

Porch only overwrites files it wrote itself and that nobody has edited since.
The manifest lives in state["files"]:  {abs path: {"sha256", "backup", "step"}}.

    r = ctx.files.write(path, text, mode=0o644)   # "created" | "updated" | "unchanged"
                                                  #  (dry-run: "would-create" | "would-update")
    ctx.files.status(path)    # "missing" | "managed" | "edited" | "unmanaged"
    ctx.files.remove(path)    # managed files only; records undo

Rules:
- An existing file not in the manifest is refused (UnmanagedFileError) unless
  write(..., take_over=True); then it is backed up first.
- A managed file whose sha256 no longer matches the manifest was edited by
  the user: refused (UserEditedError) unless force=True (backed up first).
- Before each change a write-ahead undo entry
  {"kind": "file.restore", "path", "backup", "sha256", "prev"} is recorded on
  the current step, so Step.rollback restores it (base Step.undo handles
  "file.restore"; you never write that code yourself).
- Backups go to <data>/porch-setup-backups/ (0700 dir, 0600 files).

This writes files the current user can write. Root-owned files (/etc/haproxy)
go through their own installer (bin/haproxy-apply) instead.
"""

import hashlib
import os
import secrets
import shutil
import stat

from .state import BACKUP_DIR_NAME


class FileError(Exception):
    pass


class UserEditedError(FileError):
    pass


class UnmanagedFileError(FileError):
    pass


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(path):
    try:
        with open(path, "rb") as f:
            return sha256_bytes(f.read())
    except FileNotFoundError:
        return None


def _to_bytes(content):
    return content.encode("utf-8") if isinstance(content, str) else bytes(content)


def _atomic(path, data, mode):
    d, base = os.path.split(path)
    os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, f".{base}.{secrets.token_hex(6)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class FileManager:
    def __init__(self, ctx, backup_dir=None):
        self.ctx = ctx
        self.backup_dir = backup_dir or os.path.join(ctx.data_dir, BACKUP_DIR_NAME)

    @property
    def manifest(self):
        return self.ctx.state.files

    def status(self, path):
        path = os.path.abspath(path)
        cur = sha256_file(path)
        entry = self.manifest.get(path)
        if cur is None:
            return "missing"
        if entry is None:
            return "unmanaged"
        return "managed" if entry["sha256"] == cur else "edited"

    def _backup(self, path):
        os.makedirs(self.backup_dir, mode=0o700, exist_ok=True)
        with open(path, "rb") as f:
            data = f.read()
        st = os.stat(path)
        name = f"{sha256_bytes(data)[:12]}-{secrets.token_hex(3)}-{os.path.basename(path)}"
        dest = os.path.join(self.backup_dir, name)
        _atomic(dest, data, 0o600)
        return {"path": dest, "mode": stat.S_IMODE(st.st_mode)}

    def write(self, path, content, *, mode=0o644, take_over=False, force=False):
        path = os.path.abspath(path)
        data = _to_bytes(content)
        new_sha = sha256_bytes(data)
        cur = sha256_file(path)
        entry = self.manifest.get(path)
        if os.path.islink(path):
            raise FileError(f"refusing to write through a symlink: {path}")
        if cur is not None:
            if entry is None and not take_over:
                raise UnmanagedFileError(
                    f"{path} exists and porch did not write it; move it aside or adopt it")
            if entry is not None and entry["sha256"] != cur and not force:
                raise UserEditedError(
                    f"{path} was edited since porch wrote it; porch will not overwrite your changes")
            if cur == new_sha:
                if entry is None:
                    if self.ctx.dry_run:
                        return "would-adopt"
                    self.manifest[path] = {"sha256": cur, "backup": None,
                                           "step": self.ctx.step_id}
                    self.ctx.state.save()
                return "unchanged"
        if self.ctx.dry_run:
            return "would-update" if cur is not None else "would-create"
        backup = self._backup(path) if cur is not None else None
        self.ctx.record_undo("file.restore", path=path, backup=backup, sha256=new_sha,
                             prev=dict(entry) if entry else None)
        _atomic(path, data, mode)
        self.manifest[path] = {"sha256": new_sha,
                               "backup": backup["path"] if backup else None,
                               "step": self.ctx.step_id}
        self.ctx.state.save()
        return "updated" if cur is not None else "created"

    def remove(self, path, *, force=False):
        path = os.path.abspath(path)
        st = self.status(path)
        if st == "missing":
            self.manifest.pop(path, None)
            return False
        if st == "unmanaged":
            raise UnmanagedFileError(f"{path}: porch did not write it")
        if st == "edited" and not force:
            raise UserEditedError(f"{path} was edited since porch wrote it")
        if self.ctx.dry_run:
            return True
        backup = self._backup(path)
        self.ctx.record_undo("file.unremove", path=path, backup=backup,
                             prev=dict(self.manifest[path]))
        os.unlink(path)
        self.manifest.pop(path, None)
        self.ctx.state.save()
        return True

    def restore(self, entry, *, force=False):
        """Undo one file.restore / file.unremove entry."""
        path = entry["path"]
        backup = entry.get("backup")
        if entry["kind"] == "file.restore":
            cur = sha256_file(path)
            if cur is not None and cur != entry["sha256"] and not force:
                raise UserEditedError(
                    f"{path} was edited after porch wrote it; not rolling it back")
            if backup is None:
                if cur is not None:
                    os.unlink(path)
            else:
                shutil.copyfile(backup["path"], path + ".porch-restore")
                os.chmod(path + ".porch-restore", backup.get("mode", 0o644))
                os.replace(path + ".porch-restore", path)
        elif entry["kind"] == "file.unremove":
            shutil.copyfile(backup["path"], path + ".porch-restore")
            os.chmod(path + ".porch-restore", backup.get("mode", 0o644))
            os.replace(path + ".porch-restore", path)
        else:
            raise FileError(f"not a file undo entry: {entry['kind']}")
        if entry.get("prev"):
            self.manifest[path] = entry["prev"]
        else:
            self.manifest.pop(path, None)
        self.ctx.state.save()

#!/usr/bin/env python3
"""Which files of this checkout are distributable (the install tarball).

    python3 lib/porch_files.py list ROOT              # one path per line (stdout)
    python3 lib/porch_files.py manifest ROOT [--ref R]  # the share/porch-files.txt body

`list` uses git when ROOT is the top of a git work tree (tracked plus
untracked-but-not-ignored files, so anything gitignored such as
devices.json, history.jsonl, admin tokens, locks, logs and real *.toml
configs can never ship). Without git (an install unpacked from the tarball,
or a `git archive` upload) it reads the manifest share/porch-files.txt that
was written from git when that tarball or upload was made. Either way the
same denylist drops build artefacts and the same hard check refuses
anything under data/ but the allowlisted files, or a secret-looking name:
exit 1 listing them. Exit 2: neither git nor a manifest.

`manifest` prints the git-derived list (of the work tree, or of commit
--ref, which is what `git archive REF` uploads) plus the manifest's own path.
"""

import fnmatch
import os
import re
import subprocess
import sys

MANIFEST = "share/porch-files.txt"
# Paths bin/public-export keeps out of the public repo (working notes,
# assistant instructions, the private marker list). The install tarball drops
# them too, so a landing page never serves more than the public repo has.
PUBLIC_EXCLUDE = "share/public-exclude.txt"

DENY = [
    re.compile(r"^\.git(/|$)"),
    re.compile(r"^\.claude/(?!commands/)"),      # only the slash-command docs ship
    re.compile(r"^logs(/|$)"),
    re.compile(r"(^|/)__pycache__(/|$)"),
    re.compile(r"^bin/frp[cs]$"),
    re.compile(r"^config/.*\.toml$"),             # *.toml.example still ships
    re.compile(r"^share/public-export-markers\.txt$"),   # bin/public-export's private marker list
]

DATA_ALLOWED = ("data/links.json", "data/porch/router-guides.json", "data/porch/oui.json")
SECRETISH = re.compile(r"^\.admin-|^\.authserver|\.lock(\.|$)|token|\.bak-|^\.env($|\.)(?!example$)")


class FilesError(Exception):
    def __init__(self, msg, code=1, bad=()):
        super().__init__(msg)
        self.code, self.bad = code, list(bad)


def _git(root, *args):
    return subprocess.run(["git", "-C", root, *args], capture_output=True)


def git_toplevel(root):
    """True when root is itself the top of a git work tree (not merely
    somewhere inside another repository)."""
    p = _git(root, "rev-parse", "--show-toplevel")
    if p.returncode != 0:
        return False
    top = p.stdout.decode().strip()
    return bool(top) and os.path.realpath(top) == os.path.realpath(root)


def git_names(root, ref=None):
    if ref:
        p = _git(root, "ls-tree", "-r", "-z", "--name-only", ref)
    else:
        p = _git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    if p.returncode != 0:
        raise FilesError(f"git failed: {p.stderr.decode(errors='replace').strip()}", 2)
    return [n for n in p.stdout.decode().split("\0") if n]


def manifest_names(root):
    path = os.path.join(root, MANIFEST)
    try:
        with open(path, encoding="utf-8") as f:
            lines = [ln.rstrip("\n") for ln in f]
    except FileNotFoundError:
        raise FilesError(f"{root} is not a git checkout and has no {MANIFEST}", 2)
    out = []
    for ln in lines:
        if not ln or ln.startswith("#"):
            continue
        if ln.startswith("/") or "\\" in ln or any(part in ("", ".", "..") for part in ln.split("/")):
            raise FilesError(f"{MANIFEST}: not a plain relative path: {ln!r}", 1, [ln])
        out.append(ln)
    return out


def public_excludes(root):
    """The share/public-exclude.txt patterns under root ([] without one).
    Same syntax as bin/public-export: a trailing "/" is a directory, else an
    exact path or an fnmatch glob; blank lines and "#" comments ignored."""
    try:
        with open(os.path.join(root, PUBLIC_EXCLUDE), encoding="utf-8") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        return []
    out = []
    for ln in lines:
        ln = ln.strip()
        if ln and not ln.startswith("#"):
            out.append(ln.lstrip("/"))
    return out


def excluded(path, excludes):
    for e in excludes:
        if e.endswith("/"):
            if path.startswith(e):
                return True
        elif path == e or fnmatch.fnmatchcase(path, e):
            return True
    return False


def keep(names, root=None, excludes=()):
    """Denylist + public-exclude list + (with root) only regular, non-symlink
    files that exist."""
    out = []
    for p in sorted(set(names)):
        if any(d.search(p) for d in DENY) or excluded(p, excludes):
            continue
        if root is not None:
            full = os.path.join(root, p)
            if not os.path.isfile(full) or os.path.islink(full):
                continue
        out.append(p)
    return out


def bad_names(names):
    bad = []
    for p in names:
        base = p.rsplit("/", 1)[-1]
        if p.startswith("data/") and p not in DATA_ALLOWED:
            bad.append(p)
        elif SECRETISH.search(base):
            bad.append(p)
        elif re.match(r"^config/.*\.toml$", p) or p.startswith("logs/"):
            bad.append(p)
    return bad


def distributable(root):
    """(names, source) where source is "git" or "manifest". Raises FilesError."""
    if git_toplevel(root):
        names, source = git_names(root), "git"
    else:
        names, source = manifest_names(root), "manifest"
    names = keep(names, root, public_excludes(root))
    bad = bad_names(names)
    if bad:
        raise FilesError("refusing to package sensitive paths", 1, bad)
    return names, source


def manifest_text(root, ref=None):
    if not ref and not git_toplevel(root):
        raise FilesError(f"{root} is not a git checkout: the manifest is made from git", 2)
    names = keep(git_names(root, ref), None if ref else root, public_excludes(root))
    names = [n for n in names if n != MANIFEST]
    bad = bad_names(names)
    if bad:
        raise FilesError("refusing to list sensitive paths", 1, bad)
    return "".join(n + "\n" for n in sorted(names + [MANIFEST]))


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 2 or argv[0] not in ("list", "manifest"):
        print(__doc__.strip().split("\n\n")[1], file=sys.stderr)
        return 2
    cmd, root, rest = argv[0], argv[1], argv[2:]
    try:
        if cmd == "list":
            names, source = distributable(root)
            print(f"(file list from {source})", file=sys.stderr)
            sys.stdout.write("".join(n + "\n" for n in names))
        else:
            ref = None
            if rest[:1] == ["--ref"] and len(rest) == 2:
                ref = rest[1]
            elif rest:
                print("usage: porch_files.py manifest ROOT [--ref REF]", file=sys.stderr)
                return 2
            sys.stdout.write(manifest_text(root, ref))
    except FilesError as e:
        print(f"✗ {e}" + (":" if e.bad else ""), file=sys.stderr)
        for b in e.bad:
            print(f"    {b}", file=sys.stderr)
        return e.code
    return 0


if __name__ == "__main__":
    sys.exit(main())

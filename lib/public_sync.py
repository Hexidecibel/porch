"""Shared helpers for bin/release and bin/public-pull.

The public repo (github.com/Hexidecibel/porch) is a filtered copy of this
private repo: same paths, minus share/public-exclude.txt. Its history only
grows: every release is one normal commit on top of public main, and commits
made on GitHub (merged pull requests) are brought back here with
bin/public-pull before the next release.

share/public-release.json (private, excluded from the export) records the
last release:

    {"version": "v0.1.1",                  # also a tag on the public repo
     "public_commit": "<sha>",             # the public commit of that release
     "private_commit": "<sha>",            # the private commit it was built from
     "public_synced": "<sha>"}             # optional: public main as of the last
                                           # bin/public-pull (commits up to it are
                                           # already in this repo)
"""

import json
import os
import re
import subprocess

RECORD = "share/public-release.json"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class SyncError(Exception):
    pass


def git(*args, cwd, check=True, env=None, text=True):
    p = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=text, env=env)
    if check and p.returncode != 0:
        err = (p.stderr or p.stdout)
        if not text:
            err = err.decode(errors="replace")
        raise SyncError(f"git {' '.join(args[:3])} failed: {err.strip()[:400]}")
    return p


def clean_env(extra=None):
    env = dict(os.environ)
    for k in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        env.pop(k, None)
    if extra:
        env.update(extra)
    return env


def read_record(repo, rev="HEAD"):
    """The release record at rev (None when there is none). Raises SyncError
    when it exists but is malformed."""
    p = git("show", f"{rev}:{RECORD}", cwd=repo, check=False)
    if p.returncode != 0:
        return None
    try:
        rec = json.loads(p.stdout)
    except ValueError:
        raise SyncError(f"{RECORD} is not valid JSON") from None
    if not isinstance(rec, dict):
        raise SyncError(f"{RECORD} must be a JSON object")
    for k in ("public_commit", "private_commit"):
        if not SHA_RE.match(str(rec.get(k, ""))):
            raise SyncError(f"{RECORD}: {k} must be a full 40-hex commit id")
    if rec.get("public_synced") is not None and not SHA_RE.match(str(rec["public_synced"])):
        raise SyncError(f"{RECORD}: public_synced must be a full 40-hex commit id")
    if not re.match(r"^v\d+\.\d+\.\d+$", str(rec.get("version", ""))):
        raise SyncError(f"{RECORD}: version must look like v1.2.3")
    return rec


def synced_commit(rec):
    """Public commit up to which this repo has everything."""
    return rec.get("public_synced") or rec["public_commit"]


def write_record(repo, rec):
    path = os.path.join(repo, RECORD)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


def commit_record(repo, message):
    """Commit only the record file (other staged changes stay staged)."""
    git("add", "--", RECORD, cwd=repo, env=clean_env())
    git("-c", "commit.gpgsign=false", "commit", "-q", "--only", "-m", message, "--", RECORD,
        cwd=repo, env=clean_env())
    return git("rev-parse", "HEAD", cwd=repo).stdout.strip()


def record_dirty(repo):
    return bool(git("status", "--porcelain", "--", RECORD, cwd=repo).stdout.strip())


def clone_public(remote, dest):
    """Read-only: a full clone of the public repo (tags too). Returns the
    main commit, or None when the remote has no main yet."""
    git("init", "-q", dest, cwd=os.path.dirname(dest), env=clean_env())
    git("remote", "add", "origin", remote, cwd=dest)
    git("fetch", "-q", "--tags", "origin", "+refs/heads/main:refs/remotes/origin/main",
        cwd=dest, env=clean_env(), check=False)
    p = git("rev-parse", "--verify", "-q", "refs/remotes/origin/main", cwd=dest, check=False)
    return p.stdout.strip() if p.returncode == 0 else None


def is_ancestor(repo, a, b):
    return git("merge-base", "--is-ancestor", a, b, cwd=repo, check=False).returncode == 0


def has_commit(repo, sha):
    return git("cat-file", "-e", f"{sha}^{{commit}}", cwd=repo, check=False).returncode == 0


def commits_between(repo, a, b, fmt="%H"):
    """Non-merge commits in a..b, oldest first."""
    out = git("log", "--reverse", "--no-merges", f"--format={fmt}", f"{a}..{b}", cwd=repo).stdout
    return [ln for ln in out.splitlines() if ln.strip()]


def check_public_state(pub, main, rec):
    """Raise SyncError unless public main == the last synced commit.

    main None (empty remote) is fine only without a record (first release)."""
    if rec is None:
        if main is None:
            return
        raise SyncError(
            f"the public repo already has a main ({main[:12]}) but this repo has no {RECORD}; "
            "seed it with the last release's version, public commit and private commit")
    if main is None:
        raise SyncError(f"{RECORD} says {rec['version']} was released, but the public repo has no main")
    base = synced_commit(rec)
    if not has_commit(pub, base):
        raise SyncError(f"public commit {base[:12]} from {RECORD} is not in the public repo "
                        "(was its history rewritten?)")
    if main == base:
        return
    if not is_ancestor(pub, base, main):
        raise SyncError(f"public main ({main[:12]}) no longer contains {base[:12]}: "
                        "its history was rewritten; sort it out by hand")
    n = git("rev-list", "--count", f"{base}..{main}", cwd=pub).stdout.strip()
    raise SyncError(
        f"public main has {n} commit(s) after {base[:12]} that this repo does not have "
        "(a pull request merged on GitHub?). Run bin/public-pull first, then release again.")

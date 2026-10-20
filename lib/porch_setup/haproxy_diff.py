"""Adopt diff: does a live haproxy.cfg contain everything porch renders?

    parse(text) -> [(section header, [directive, ...])]      normalized
    diff(rendered_text, live_text, allow=()) -> Report

Normalizing drops comments and blank lines and collapses whitespace outside
quotes. For every section in the rendered config, every directive must exist
in the live section of the same header:

  missing    no live directive with the same key
  different  a live directive has the same key (`bind *:443`, `server panel`,
             `http-request redirect code` ...) but other arguments
  order      present, but out of the rendered relative order (longest
             increasing subsequence over the matched live positions), which
             matters for use_backend and for gate-before-strip
  extra live directives and sections are ignored: the live file may serve
  other things.

`allow` entries accept deltas: "<section header>: <directive prefix>" (e.g.
"frontend www-https: bind *:443 ssl crt") matches a finding when the section
is equal and the rendered directive OR the live one starts with the prefix.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional

SECTION_KW = {"global", "defaults", "frontend", "backend", "listen", "resolvers",
              "peers", "userlist", "cache", "program", "http-errors", "ring",
              "mailers", "crt-store", "traces"}
_THREE = {"http-request", "http-response", "tcp-request", "tcp-response",
          "http-after-response"}


def _strip_comment(line):
    out, q, prev = [], None, " "
    for ch in line:
        if q:
            if ch == q and prev != "\\":
                q = None
        elif ch in "'\"":
            q = ch
        elif ch == "#" and prev in " \t":
            break
        out.append(ch)
        prev = ch
    return "".join(out)


def _collapse(line):
    out, q, space = [], None, False
    for ch in line.strip():
        if q:
            out.append(ch)
            if ch == q:
                q = None
            continue
        if ch in " \t":
            space = True
            continue
        if space and out:
            out.append(" ")
        space = False
        out.append(ch)
        if ch in "'\"":
            q = ch
    return "".join(out)


def normalize(line):
    if line.lstrip().startswith("#"):
        return ""
    return _collapse(_strip_comment(line))


def parse(text):
    sections, cur = [], None
    for raw in text.splitlines():
        line = normalize(raw)
        if not line:
            continue
        kw = line.split(" ", 1)[0]
        if kw in SECTION_KW:
            cur = (line, [])
            sections.append(cur)
        elif cur is not None:
            cur[1].append(line)
    return sections


def key(directive):
    toks = directive.split(" ")
    n = 3 if toks[0] in _THREE else 2
    return " ".join(toks[:n])


@dataclass
class Finding:
    kind: str                 # missing | different | order
    section: str
    directive: str            # the rendered directive
    live: Optional[str] = None
    allowed: bool = False

    def __str__(self):
        s = f"{self.kind:<9} [{self.section}] {self.directive}"
        if self.live and self.live != self.directive:
            s += f"\n          live: {self.live}"
        return s + ("   (allowed)" if self.allowed else "")


@dataclass
class Report:
    findings: List[Finding] = field(default_factory=list)
    checked: int = 0

    def of(self, kind, include_allowed=False):
        return [f for f in self.findings if f.kind == kind and (include_allowed or not f.allowed)]

    @property
    def missing(self):
        return self.of("missing")

    @property
    def different(self):
        return self.of("different")

    @property
    def order(self):
        return self.of("order")

    @property
    def allowed(self):
        return [f for f in self.findings if f.allowed]

    @property
    def ok(self):
        return not (self.missing or self.different or self.order)

    def counts(self):
        return {"checked": self.checked, "missing": len(self.missing),
                "different": len(self.different), "order": len(self.order),
                "allowed": len(self.allowed)}

    def text(self, show_allowed=True):
        lines = [str(f) for f in self.findings if show_allowed or not f.allowed]
        c = self.counts()
        lines.append(f"adopt diff: {c['checked']} directives checked, {c['missing']} missing, "
                     f"{c['different']} different, {c['order']} out of order, "
                     f"{c['allowed']} allowed by adopt.allow")
        return "\n".join(lines)

    def as_dict(self):
        return {"counts": self.counts(),
                "findings": [f.__dict__ for f in self.findings]}


def _lis(seq):
    """Indices (into seq) of one longest strictly increasing subsequence."""
    import bisect
    tails, tails_i, prev = [], [], [None] * len(seq)
    for i, v in enumerate(seq):
        j = bisect.bisect_left(tails, v)
        if j == len(tails):
            tails.append(v)
            tails_i.append(i)
        else:
            tails[j] = v
            tails_i[j] = i
        prev[i] = tails_i[j - 1] if j else None
    out, i = [], tails_i[-1] if tails_i else None
    while i is not None:
        out.append(i)
        i = prev[i]
    return set(out)


def _parse_allow(allow):
    out = []
    for a in allow or ():
        sec, sep, prefix = a.partition(":")
        if not sep:
            continue
        out.append((_collapse(sec), _collapse(prefix)))
    return out


def diff(rendered, live, allow=()):
    rules = _parse_allow(allow)
    live_secs = {}
    for header, dirs in parse(live):
        live_secs.setdefault(header, []).extend(dirs)
    rep = Report()

    def add(kind, sec, d, live_d=None):
        ok = any(sec == s and (d.startswith(p) or (live_d or "").startswith(p)) for s, p in rules)
        rep.findings.append(Finding(kind, sec, d, live_d, ok))

    for header, dirs in parse(rendered):
        rep.checked += len(dirs)
        ldirs = live_secs.get(header)
        if ldirs is None:
            for d in dirs:
                add("missing", header, d)
            continue
        used = set()
        matched = []  # (template index, live index)
        pending = []
        last = -1
        for ti, d in enumerate(dirs):
            cands = [i for i, l in enumerate(ldirs) if l == d and i not in used]
            if cands:
                i = next((c for c in cands if c > last), cands[0])
                used.add(i)
                matched.append((ti, i))
                last = i
            else:
                pending.append((ti, d))
        for ti, d in pending:
            k = key(d)
            cands = [i for i, l in enumerate(ldirs) if i not in used and key(l) == k]
            if cands:
                used.add(cands[0])
                add("different", header, d, ldirs[cands[0]])
            else:
                add("missing", header, d)
        matched.sort()
        keep = _lis([li for _, li in matched])
        for n, (ti, li) in enumerate(matched):
            if n not in keep:
                add("order", header, dirs[ti], ldirs[li])
    return rep


def section_filter(text, headers):
    """Only the given sections of a config (for focused reports)."""
    return [s for s in parse(text) if s[0] in headers]

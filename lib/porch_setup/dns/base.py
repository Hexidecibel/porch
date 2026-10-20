"""DNS provider contract (dns/<name>.py defines PROVIDER = <a Provider subclass>).

    p = Cloudflare({"token": "..."}, http=ctx.http)      # base_url= for tests
    p.check("example.com")                 # raises ProviderError (code + hint)
    p.list("example.com", name="auth.example.com", rtype="A") -> [Record]
    p.create("example.com", Record("auth.example.com", "A", "203.0.113.7")) -> id
    p.update("example.com", id, Record(...)); p.delete("example.com", id)

Names are fully qualified, lower case, no trailing dot ("*.tunnel.example.com"
for a wildcard). TXT content is the bare value (no surrounding quotes).
Error messages never contain the credentials, and response bodies are cut
short and run through the caller's redactor by the engine.
"""

import base64
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

from ..dnsq import norm


@dataclass
class Record:
    name: str
    type: str
    content: str
    ttl: int = 300
    id: Optional[str] = None
    extra: dict = field(default_factory=dict, compare=False)   # provider-specific fields

    def __post_init__(self):
        self.name = norm(self.name)
        self.type = self.type.upper()

    def key(self):
        return (self.name, self.type)

    def same_value(self, other):
        return (self.name, self.type, self.content.strip()) == (other.name, other.type,
                                                                other.content.strip())

    def as_dict(self):
        return {"name": self.name, "type": self.type, "content": self.content, "ttl": self.ttl,
                "id": self.id}


class ProviderError(Exception):
    """code: dns.auth | dns.zone | dns.rate | dns.api | dns.conflict | dns.manual"""

    def __init__(self, code, message, hint=""):
        self.code, self.message, self.hint = code, message, hint
        super().__init__(f"{code}: {message}")


def relative_name(name, zone):
    """'auth.example.com' in 'example.com' -> 'auth'; the apex -> ''."""
    name, zone = norm(name), norm(zone)
    if name == zone:
        return ""
    if not name.endswith("." + zone):
        raise ProviderError("dns.zone", f"{name} is not inside the zone {zone}")
    return name[: -len(zone) - 1]


class Provider:
    name = ""
    title = ""
    # credential fields; "token" is always the secret one, the rest are plain inputs
    CREDENTIALS = ("token",)
    DEFAULT_BASE_URL = ""
    # shown with an auth failure: what the token needs
    TOKEN_HINT = ""
    # True for providers that need no API at all (manual)
    MANUAL = False

    def __init__(self, creds=None, http=None, base_url=None, timeout=20):
        self.creds = dict(creds or {})
        self.http = http or urllib.request.urlopen
        self.base_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self.timeout = timeout

    # ---- contract -------------------------------------------------------------
    def check(self, zone):
        raise NotImplementedError

    def list(self, zone, name=None, rtype=None):
        raise NotImplementedError

    def create(self, zone, record):
        raise NotImplementedError

    def update(self, zone, rid, record):
        raise NotImplementedError

    def delete(self, zone, rid):
        raise NotImplementedError

    # ---- helpers ----------------------------------------------------------------
    def _filter(self, records, name=None, rtype=None):
        out = []
        for r in records:
            if name is not None and r.name != norm(name):
                continue
            if rtype is not None and r.type != rtype.upper():
                continue
            out.append(r)
        return out

    def _headers(self):
        return {}

    def _basic(self, user, password):
        raw = f"{user}:{password}".encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def _auth_error(self, zone, status):
        return ProviderError(
            "dns.auth", f"{self.title or self.name} refused the credentials (HTTP {status})",
            self.TOKEN_HINT.format(zone=zone or "the zone"))

    def request(self, method, path, body=None, zone=None, query=None):
        """JSON request -> parsed JSON (or {} for an empty body)."""
        url = self.base_url + path
        if query:
            from urllib.parse import urlencode
            url += ("&" if "?" in url else "?") + urlencode(query)
        data = None
        headers = {"Accept": "application/json", "User-Agent": "porch-setup"}
        headers.update(self._headers())
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with self.http(req, timeout=self.timeout) as resp:
                raw = resp.read()
                status = getattr(resp, "status", 200)
        except urllib.error.HTTPError as e:
            status = e.code
            try:
                raw = e.read()
            except Exception:  # noqa: BLE001
                raw = b""
            self._raise_status(status, raw, zone, method, path)
        except (urllib.error.URLError, OSError) as e:
            reason = getattr(e, "reason", e)
            raise ProviderError("dns.api", f"cannot reach {self.title or self.name} API: {reason}",
                                "check this machine's internet connection and DNS") from None
        if status >= 400:
            self._raise_status(status, raw, zone, method, path)
        if not raw.strip():
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ProviderError("dns.api", f"{self.title or self.name} API sent a non-JSON answer") from None

    def _api_message(self, raw):
        try:
            j = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, AttributeError):
            return ""
        return self.error_text(j)[:200]

    def error_text(self, j):
        if isinstance(j, dict):
            for k in ("message", "details", "error"):
                if isinstance(j.get(k), str):
                    return j[k]
        return ""

    def _raise_status(self, status, raw, zone, method, path):
        msg = self._api_message(raw)
        if status in (401, 403):
            raise self._auth_error(zone, status)
        if status == 404:
            raise ProviderError("dns.zone", f"{self.title or self.name}: not found (HTTP 404)"
                                + (f": {msg}" if msg else ""),
                                f"is {zone} in this {self.title or self.name} account?" if zone else "")
        if status == 429:
            raise ProviderError("dns.rate", f"{self.title or self.name} rate limit (HTTP 429)",
                                "wait a minute and re-run; porch setup resumes where it stopped")
        raise ProviderError("dns.api", f"{self.title or self.name} {method} failed (HTTP {status})"
                            + (f": {msg}" if msg else ""))


def provider_class(name):
    """The PROVIDER registered under `name` (dns/<file>.py), or None."""
    from .. import registry
    return registry.providers().get(name)


def make_provider(ctx, name, creds):
    """A provider instance for a step. Tests set ctx.provider_factory =
    fn(name, creds) -> Provider to bypass the registry and the network."""
    factory = getattr(ctx, "provider_factory", None)
    if factory is not None:
        return factory(name, creds)
    cls = provider_class(name)
    if cls is None:
        raise ProviderError("dns.unknown", f"no DNS provider called {name!r}",
                            "pick one of: " + ", ".join(sorted(provider_names())))
    if isinstance(cls, Provider):
        return cls
    return cls(creds, http=ctx.http)


def provider_names():
    from .. import registry
    return list(registry.providers())

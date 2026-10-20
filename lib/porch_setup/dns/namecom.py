"""name.com DNS (API v4, HTTP Basic auth with username + API token).

Credentials: {"username": <name.com account username>, "token": <API token>}
(name.com -> Account -> Settings -> Security -> API Token). The API also
requires "Name.com API Access" to be on, and 2FA accounts need the IP allow
list or the API's 2FA bypass. Records use `host` relative to the domain
("" for the apex) and TTL >= 300."""

from .base import Provider, ProviderError, Record, relative_name
from ..dnsq import norm, txt_unquote


class NameCom(Provider):
    name = "namecom"
    title = "name.com"
    CREDENTIALS = ("username", "token")
    DEFAULT_BASE_URL = "https://api.name.com/v4"
    TOKEN_HINT = ("name.com needs your account username (--dns-username) and an API token "
                  "for the production API (name.com -> Account -> Settings -> Security -> "
                  "API Token), with API access turned on for {zone}")
    PER_PAGE = 1000
    MIN_TTL = 300

    def _headers(self):
        return {"Authorization": self._basic(self.creds.get("username", ""),
                                             self.creds.get("token", ""))}

    def check(self, zone):
        if not self.creds.get("username"):
            raise ProviderError("dns.auth", "name.com needs the account username",
                                "pass --dns-username <name.com username>")
        zone = norm(zone)
        self.request("GET", f"/domains/{zone}", zone=zone)
        self.request("GET", f"/domains/{zone}/records", zone=zone, query={"perPage": 1})

    def _to_record(self, zone, r):
        host = r.get("host") or ""
        fqdn = norm(r.get("fqdn") or (f"{host}.{zone}" if host else zone))
        content = r.get("answer", "")
        if r.get("type") == "TXT":
            content = txt_unquote(content)
        return Record(fqdn, r.get("type", ""), content, int(r.get("ttl") or 300),
                      id=str(r.get("id")) if r.get("id") is not None else None,
                      extra={"host": host})

    def list(self, zone, name=None, rtype=None):
        zone = norm(zone)
        out, page = [], 1
        while page:
            j = self.request("GET", f"/domains/{zone}/records", zone=zone,
                             query={"perPage": self.PER_PAGE, "page": page})
            out.extend(self._to_record(zone, r) for r in j.get("records") or [])
            nxt = j.get("nextPage")
            page = int(nxt) if nxt and int(nxt) > page else 0
        return self._filter(out, name, rtype)

    def _body(self, zone, rec):
        return {"host": relative_name(rec.name, zone), "type": rec.type, "answer": rec.content,
                "ttl": max(int(rec.ttl or self.MIN_TTL), self.MIN_TTL)}

    def create(self, zone, record):
        zone = norm(zone)
        j = self.request("POST", f"/domains/{zone}/records", self._body(zone, record), zone=zone)
        rid = j.get("id")
        return str(rid) if rid is not None else None

    def update(self, zone, rid, record):
        zone = norm(zone)
        self.request("PUT", f"/domains/{zone}/records/{rid}", self._body(zone, record), zone=zone)

    def delete(self, zone, rid):
        zone = norm(zone)
        self.request("DELETE", f"/domains/{zone}/records/{rid}", zone=zone)


PROVIDER = NameCom

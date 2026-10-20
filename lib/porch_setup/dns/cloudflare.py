"""Cloudflare DNS (API v4, scoped API token as a Bearer token).

Records porch creates are DNS-only (proxied=false): HAProxy at home
terminates TLS, and the orange-cloud proxy would break frp and the cert."""

from .base import Provider, ProviderError, Record
from ..dnsq import norm, txt_unquote

PROXIABLE = ("A", "AAAA", "CNAME")


class Cloudflare(Provider):
    name = "cloudflare"
    title = "Cloudflare"
    DEFAULT_BASE_URL = "https://api.cloudflare.com/client/v4"
    TOKEN_HINT = ("the Cloudflare API token needs Zone:DNS:Edit (and Zone:Zone:Read) on {zone}: "
                  "dash.cloudflare.com -> My Profile -> API Tokens -> Create Token -> "
                  "'Edit zone DNS' template")
    PER_PAGE = 100

    def __init__(self, creds=None, http=None, base_url=None, timeout=20):
        super().__init__(creds, http, base_url, timeout)
        self._zone_ids = {}

    def _headers(self):
        return {"Authorization": "Bearer " + self.creds.get("token", "")}

    def error_text(self, j):
        errs = j.get("errors") if isinstance(j, dict) else None
        if errs and isinstance(errs, list) and isinstance(errs[0], dict):
            return str(errs[0].get("message", ""))
        return super().error_text(j)

    def _ok(self, j, what):
        if isinstance(j, dict) and j.get("success") is False:
            raise ProviderError("dns.api", f"Cloudflare {what} failed: {self.error_text(j)[:200]}")
        return j

    def zone_id(self, zone):
        zone = norm(zone)
        if zone in self._zone_ids:
            return self._zone_ids[zone]
        j = self._ok(self.request("GET", "/zones", zone=zone, query={"name": zone}), "zone lookup")
        res = j.get("result") or []
        if not res:
            raise ProviderError("dns.zone", f"Cloudflare has no zone {zone} visible to this token",
                                f"add {zone} to Cloudflare, or give the token access to it "
                                "(Zone Resources: Include -> Specific zone)")
        self._zone_ids[zone] = res[0]["id"]
        return res[0]["id"]

    def check(self, zone):
        zid = self.zone_id(zone)
        # proves DNS read access, not just zone read
        self._ok(self.request("GET", f"/zones/{zid}/dns_records", zone=zone,
                              query={"per_page": 5}), "record list")

    def _to_record(self, r):
        content = r.get("content", "")
        if r.get("type") == "TXT":
            content = txt_unquote(content)
        return Record(r.get("name", ""), r.get("type", ""), content, int(r.get("ttl") or 1),
                      id=r.get("id"), extra={"proxied": r.get("proxied")})

    def list(self, zone, name=None, rtype=None):
        zid = self.zone_id(zone)
        q = {"per_page": self.PER_PAGE}
        if name:
            q["name"] = norm(name)
        if rtype:
            q["type"] = rtype.upper()
        out, page = [], 1
        while True:
            q["page"] = page
            j = self._ok(self.request("GET", f"/zones/{zid}/dns_records", zone=zone, query=q),
                         "record list")
            out.extend(self._to_record(r) for r in j.get("result") or [])
            info = j.get("result_info") or {}
            if page >= int(info.get("total_pages") or 1):
                break
            page += 1
        return self._filter(out, name, rtype)

    def _body(self, rec):
        b = {"type": rec.type, "name": rec.name, "content": rec.content, "ttl": rec.ttl}
        if rec.type in PROXIABLE:
            b["proxied"] = False
        return b

    def create(self, zone, record):
        zid = self.zone_id(zone)
        j = self._ok(self.request("POST", f"/zones/{zid}/dns_records", self._body(record),
                                  zone=zone), "record create")
        return (j.get("result") or {}).get("id")

    def update(self, zone, rid, record):
        zid = self.zone_id(zone)
        self._ok(self.request("PUT", f"/zones/{zid}/dns_records/{rid}", self._body(record),
                              zone=zone), "record update")

    def delete(self, zone, rid):
        zid = self.zone_id(zone)
        self._ok(self.request("DELETE", f"/zones/{zid}/dns_records/{rid}", zone=zone),
                 "record delete")


PROVIDER = Cloudflare

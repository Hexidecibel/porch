"""VPS provider clients for `porch connect paid` (stdlib only).

    p = PROVIDERS["digitalocean"](token, http=None)
    p.check()                                   # token works (raises ProviderError)
    p.plan(region=None, size=None)              # {"region", "size", "monthly", "hourly", "currency"}
    p.create(name, region, size, user_data, tags) -> server
    p.get(id) -> server | None                  # None: gone (404)
    p.list_tagged(tag) -> [server]
    p.delete(id)                                # 404 counts as done

A server is normalized to {"id", "name", "status", "ready", "ipv4", "tags"}.
`http(method, url, headers, body) -> (status, bytes)` is injectable (tests).
The token only ever goes into the Authorization header; error messages are
scrubbed of it. Every server porch creates carries the porch-relay tag,
and deletion refuses a server without it.
"""

import base64
import json
import urllib.error
import urllib.parse
import urllib.request


class ProviderError(Exception):
    pass


def urllib_http(method, url, headers, body, timeout=30):
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except (urllib.error.URLError, OSError) as e:
        raise ProviderError(f"{method} {url.split('?')[0]}: {getattr(e, 'reason', e)}") from None


class Provider:
    name = ""
    title = ""
    api = ""
    currency = "USD"
    default_region = ""
    sizes = ()                  # preferred plan slugs, cheapest first
    image = ""
    refused = "the API token was refused (wrong token, or it lacks write access)"

    def __init__(self, token, http=None):
        if not token:
            raise ProviderError(f"{self.title}: empty API token")
        self._token = token
        self.http = http or urllib_http

    def _scrub(self, s):
        return s.replace(self._token, "<token>")

    def request(self, method, path, body=None, ok=(200, 201, 202, 204), missing_ok=False):
        headers = {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json",
                   "Accept": "application/json"}
        data = json.dumps(body).encode() if body is not None else None
        try:
            status, raw = self.http(method, self.api + path, headers, data)
        except ProviderError as e:
            raise ProviderError(self._scrub(str(e))) from None
        if status == 404 and missing_ok:
            return None
        if status not in ok:
            msg = (raw or b"").decode("utf-8", "replace")[:300]
            if status in (401, 403):
                # Keep the provider's own reason when it names one (Vultr:
                # "Unauthorized IP address: <ip>", e.g. an IPv6 address the
                # key's access list does not allow).
                why = ""
                try:
                    why = str(json.loads(raw or b"{}").get("error") or "")[:160]
                except (ValueError, AttributeError):
                    pass
                msg = self.refused + (f" (the provider said: {why})" if why else "")
            raise ProviderError(self._scrub(f"{self.title} {method} {path.split('?')[0]}: HTTP {status}: {msg}"))
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except ValueError:
            raise ProviderError(f"{self.title} {method} {path}: not JSON") from None

    @staticmethod
    def _cheapest(cands):
        return min(cands, key=lambda c: (c["monthly"], c["size"])) if cands else None

    def summary(self, plan):
        return f"{plan['monthly']:.2f} {plan['currency']}/month ({plan['hourly']:.4f}/hour)"


# ---- DigitalOcean ------------------------------------------------------------------

class DigitalOcean(Provider):
    name = "digitalocean"
    title = "DigitalOcean"
    api = "https://api.digitalocean.com/v2"
    default_region = "nyc3"
    sizes = ("s-1vcpu-512mb-10gb", "s-1vcpu-1gb")
    image = "ubuntu-24-04-x64"
    REGIONS = ("nyc3", "nyc1", "sfo3", "tor1", "ams3", "fra1", "lon1", "sgp1")

    def check(self):
        acct = (self.request("GET", "/account") or {}).get("account") or {}
        if acct.get("status") not in (None, "active"):
            raise ProviderError(f"DigitalOcean account status is {acct.get('status')}")
        return acct

    def plan(self, region=None, size=None):
        sizes = {z["slug"]: z for z in (self.request("GET", "/sizes?per_page=200") or {}).get("sizes", [])
                 if z.get("available")}
        if size:
            if size not in sizes:
                raise ProviderError(f"DigitalOcean size {size!r} is not available")
            order = [size]
        else:
            order = [s for s in self.sizes if s in sizes] or sorted(
                sizes, key=lambda s: float(sizes[s].get("price_monthly") or 1e9))
        for slug in order:
            regions = sizes[slug].get("regions") or []
            want = region or self.default_region
            pick = want if want in regions else (None if region else next(
                (r for r in self.REGIONS if r in regions), regions[0] if regions else None))
            if pick:
                z = sizes[slug]
                return {"region": pick, "size": slug, "monthly": float(z.get("price_monthly") or 0),
                        "hourly": float(z.get("price_hourly") or 0), "currency": "USD"}
        raise ProviderError(f"no DigitalOcean size {'/'.join(order)} is offered in {region or 'any region'}")

    @staticmethod
    def norm(d):
        ip = next((n.get("ip_address") for n in (d.get("networks") or {}).get("v4", [])
                   if n.get("type") == "public"), None)
        return {"id": d.get("id"), "name": d.get("name"), "status": d.get("status"),
                "ready": d.get("status") == "active" and bool(ip), "ipv4": ip,
                "tags": list(d.get("tags") or [])}

    def create(self, name, region, size, user_data, tags):
        body = {"name": name, "region": region, "size": size, "image": self.image,
                "user_data": user_data, "tags": list(tags), "ipv6": False, "monitoring": False,
                "backups": False}
        return self.norm(self.request("POST", "/droplets", body)["droplet"])

    def get(self, sid):
        r = self.request("GET", f"/droplets/{int(sid)}", missing_ok=True)
        return self.norm(r["droplet"]) if r else None

    def list_tagged(self, tag):
        out = (self.request("GET", f"/droplets?tag_name={urllib.parse.quote(tag)}&per_page=200")
               or {}).get("droplets", [])
        return [self.norm(d) for d in out if tag in (d.get("tags") or [])]

    def delete(self, sid):
        self.request("DELETE", f"/droplets/{int(sid)}", ok=(204,), missing_ok=True)


# ---- Vultr -------------------------------------------------------------------------

class Vultr(Provider):
    name = "vultr"
    title = "Vultr"
    api = "https://api.vultr.com/v2"
    default_region = "ewr"
    # vc2-1c-0.5gb is IPv6-only in most regions: the relay needs IPv4
    sizes = ("vc2-1c-1gb",)
    # Vultr keys carry an IP access list (Account > API > Access Control): a
    # key that works from your laptop is refused from the box that runs porch.
    refused = ("the API token was refused: a wrong key, or this machine's public address is not "
               "in the key's Access Control list (Vultr: Account > API)")

    def check(self):
        return (self.request("GET", "/account") or {}).get("account") or {}

    def plan(self, region=None, size=None):
        loc = region or self.default_region
        plans = {p["id"]: p for p in (self.request("GET", "/plans?type=vc2&per_page=500") or {}).get("plans", [])}
        order = [size] if size else [s for s in self.sizes if s in plans]
        for pid in order:
            p = plans.get(pid)
            if p and loc in (p.get("locations") or []):
                m = float(p.get("monthly_cost") or 0)
                return {"region": loc, "size": pid, "monthly": m, "hourly": round(m / 730, 4),
                        "currency": "USD"}
        raise ProviderError(f"Vultr plan {'/'.join(order) or '?'} is not offered in {loc}")

    def os_id(self):
        for o in (self.request("GET", "/os?per_page=500") or {}).get("os", []):
            if str(o.get("name", "")).startswith("Ubuntu 24.04") and o.get("arch") == "x64":
                return o["id"]
        raise ProviderError("Vultr does not list Ubuntu 24.04 x64")

    @staticmethod
    def norm(i):
        ip = i.get("main_ip")
        ip = None if ip in (None, "", "0.0.0.0") else ip
        return {"id": i.get("id"), "name": i.get("label"), "status": i.get("status"),
                "ready": i.get("status") == "active" and bool(ip), "ipv4": ip,
                "tags": list(i.get("tags") or [])}

    def create(self, name, region, size, user_data, tags):
        body = {"region": region, "plan": size, "os_id": self.os_id(), "label": name,
                "hostname": name, "tags": list(tags), "backups": "disabled",
                "enable_ipv6": False,
                "user_data": base64.b64encode(user_data.encode()).decode()}
        return self.norm(self.request("POST", "/instances", body)["instance"])

    @staticmethod
    def _id(sid):
        s = str(sid)
        if not s or any(ch not in "0123456789abcdef-" for ch in s.lower()):
            raise ProviderError(f"not a Vultr instance id: {sid!r}")
        return s

    def get(self, sid):
        r = self.request("GET", f"/instances/{self._id(sid)}", missing_ok=True)
        return self.norm(r["instance"]) if r else None

    def list_tagged(self, tag):
        out = (self.request("GET", f"/instances?tag={urllib.parse.quote(tag)}&per_page=500")
               or {}).get("instances", [])
        return [self.norm(i) for i in out if tag in (i.get("tags") or [])]

    def delete(self, sid):
        self.request("DELETE", f"/instances/{self._id(sid)}", ok=(204,), missing_ok=True)


PROVIDERS = {p.name: p for p in (DigitalOcean, Vultr)}

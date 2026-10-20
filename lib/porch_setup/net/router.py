"""Router brand detection and port-forwarding guides.

Detection order (first hit wins):
  1. the UPnP device description (manufacturer / model / friendly name),
  2. the gateway's web page: <title>, Server header, WWW-Authenticate realm,
  3. the gateway's MAC OUI from /proc/net/arp against data/porch/oui.json.

    detect_brand(gateway="192.168.1.1", upnp_text="NETGEAR Orbi", http=urlopen)
      -> {"brand": "netgear", "name": "NETGEAR (Nighthawk / Orbi)", "source": "upnp", "evidence": "..."}
    guide_for("netgear") -> the router-guides.json entry (or the generic one)
"""

import html
import json
import os
import re
import urllib.error
import urllib.request

from ..state import REPO_DIR

DATA_DIR = os.path.join(REPO_DIR, "data", "porch")
GUIDES_PATH = os.path.join(DATA_DIR, "router-guides.json")
OUI_PATH = os.path.join(DATA_DIR, "oui.json")

_GENERIC = {"id": "generic", "name": "your router", "match": [], "admin_url": "http://<gateway>",
            "menu": "Look for 'Port Forwarding', 'Virtual Server' or 'NAT', usually under Advanced.",
            "notes": "Forward each port to this box's LAN IP and give the box a DHCP reservation."}

_cache = {}


def _load(path):
    if path not in _cache:
        try:
            with open(path, encoding="utf-8") as f:
                _cache[path] = json.load(f)
        except (OSError, ValueError):
            _cache[path] = {}
    return _cache[path]


def load_guides(path=GUIDES_PATH):
    d = _load(path)
    return list(d.get("brands") or []), dict(d.get("generic") or _GENERIC)


def load_oui(path=OUI_PATH):
    d = _load(path)
    return dict(d.get("oui") or {}), dict(d.get("names") or {})


def guide_for(brand, path=GUIDES_PATH):
    brands, generic = load_guides(path)
    for b in brands:
        if b.get("id") == brand:
            return dict(b)
    return dict(generic)


def brand_name(brand, guides_path=GUIDES_PATH, oui_path=OUI_PATH):
    if not brand:
        return ""
    g = guide_for(brand, guides_path)
    if g.get("id") == brand:
        return g.get("name", brand)
    return load_oui(oui_path)[1].get(brand, brand.capitalize())


def match_text(text, guides_path=GUIDES_PATH):
    """Brand id whose keywords appear (as whole words) in text, else None."""
    if not text:
        return None
    low = " " + re.sub(r"\s+", " ", text.lower()) + " "
    for b in load_guides(guides_path)[0]:
        for kw in b.get("match") or ():
            kw = kw.lower().strip()
            if kw and re.search(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])", low):
                return b["id"]
    return None


def arp_mac(ip, path="/proc/net/arp"):
    try:
        with open(path, encoding="ascii", errors="replace") as f:
            next(f, None)
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip and parts[3] != "00:00:00:00:00:00":
                    return parts[3].lower()
    except OSError:
        pass
    return None


def oui_brand(mac, path=OUI_PATH):
    if not mac:
        return None
    prefix = mac.upper().replace("-", ":")[:8]
    return load_oui(path)[0].get(prefix)


_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


def gateway_http_text(gateway, http=urllib.request.urlopen, timeout=3):
    """'<title> | Server | realm' from http://<gateway>/ (read-only GET)."""
    if not gateway:
        return ""
    req = urllib.request.Request(f"http://{gateway}/", headers={"User-Agent": "porch-setup"})
    headers, body = None, b""
    try:
        resp = http(req, timeout=timeout)
        try:
            headers, body = resp.headers, resp.read(64 * 1024)
        finally:
            resp.close()
    except urllib.error.HTTPError as e:
        headers = e.headers
        try:
            body = e.read(64 * 1024)
        except Exception:  # noqa: BLE001
            body = b""
    except (OSError, urllib.error.URLError, ValueError):
        return ""
    parts = []
    m = _TITLE.search(body or b"")
    if m:
        parts.append(html.unescape(m.group(1).decode("utf-8", "replace")).strip())
    if headers is not None:
        for k in ("Server", "WWW-Authenticate"):
            v = headers.get(k)
            if v:
                parts.append(v.strip())
    return " | ".join(p[:120] for p in parts if p)


def detect_brand(gateway=None, upnp_text="", http=urllib.request.urlopen, arp_path="/proc/net/arp",
                 guides_path=GUIDES_PATH, oui_path=OUI_PATH, fetch_http=True):
    """{"brand", "name", "source", "evidence"}; brand None when unknown."""
    b = match_text(upnp_text, guides_path)
    if b:
        return {"brand": b, "name": brand_name(b, guides_path, oui_path), "source": "upnp",
                "evidence": upnp_text[:160]}
    text = gateway_http_text(gateway, http) if fetch_http else ""
    b = match_text(text, guides_path)
    if b:
        return {"brand": b, "name": brand_name(b, guides_path, oui_path), "source": "http",
                "evidence": text[:160]}
    mac = arp_mac(gateway, arp_path) if gateway else None
    b = oui_brand(mac, oui_path)
    if b:
        return {"brand": b, "name": brand_name(b, guides_path, oui_path), "source": "oui",
                "evidence": mac[:8]}
    return {"brand": None, "name": "", "source": None, "evidence": text[:160]}

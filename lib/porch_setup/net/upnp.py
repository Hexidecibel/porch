"""Minimal UPnP IGD client (stdlib): SSDP discovery, device description,
SOAP calls on WANIPConnection:1/2 and WANPPPConnection:1.

    locs = discover(timeout=2)                       # LOCATION urls
    igd = find_igd(http=urlopen)                     # IGD or None
    igd.external_ip()                                # GetExternalIPAddress (read-only)
    igd.get_mapping(443, "TCP")                      # GetSpecificPortMappingEntry -> dict | None
    igd.list_mappings()                              # GetGenericPortMappingEntry 0.. (read-only)
    igd.add_mapping(443, "TCP", "192.168.1.48", 443, "porch 443", lease=604800)
    igd.delete_mapping(443, "TCP")

`http` is an urlopen-compatible callable (ctx.http); tests inject one or
point discovery at a loopback responder with `ssdp_addr`.
"""

import ipaddress
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

SSDP_ADDR = ("239.255.255.250", 1900)
SEARCH_TARGETS = (
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
)
# Preferred first.
WAN_SERVICES = (
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
)
MAX_BODY = 256 * 1024
DEFAULT_LEASE = 7 * 24 * 3600

# UPnP error codes we act on.
ERR_NO_SUCH_ENTRY = 714            # GetSpecificPortMappingEntry: none
ERR_INDEX_INVALID = 713            # GetGenericPortMappingEntry: past the end
ERR_CONFLICT = 718                 # ConflictInMappingEntry
ERR_ONLY_PERMANENT = 725           # OnlyPermanentLeasesSupported (IGDv1)
ERR_SAME_PORT = 724                # SamePortValuesRequired
ERR_NOT_AUTHORIZED = 606


class UPnPError(Exception):
    def __init__(self, message, code=None):
        self.code = code
        super().__init__(message if code is None else f"{message} (UPnP error {code})")


def _msearch(st, mx):
    return ("M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {SSDP_ADDR[0]}:{SSDP_ADDR[1]}\r\n"
            'MAN: "ssdp:discover"\r\n'
            f"MX: {mx}\r\n"
            f"ST: {st}\r\n\r\n").encode()


def parse_ssdp(data):
    """Headers of an SSDP response as a lower-cased dict (None if not one)."""
    try:
        text = data.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None
    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    if not lines or not lines[0].upper().startswith("HTTP/1.1 200"):
        return None
    h = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            h[k.strip().lower()] = v.strip()
    return h


def _ok_location(loc):
    """Only http:// to an IP-literal or plain host; never another scheme."""
    try:
        u = urllib.parse.urlsplit(loc)
    except ValueError:
        return False
    return u.scheme == "http" and bool(u.hostname)


def discover(timeout=2.0, mx=2, targets=SEARCH_TARGETS, ssdp_addr=SSDP_ADDR, bind=("", 0)):
    """Send M-SEARCH for IGD devices; return unique LOCATION urls (in order)."""
    locs = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.bind(bind)
        for st in targets:
            try:
                sock.sendto(_msearch(st, mx), ssdp_addr)
            except OSError:
                pass
        end = time.monotonic() + timeout
        while True:
            left = end - time.monotonic()
            if left <= 0:
                break
            sock.settimeout(left)
            try:
                data, _ = sock.recvfrom(8192)
            except (socket.timeout, OSError):
                break
            h = parse_ssdp(data)
            loc = h and h.get("location")
            if loc and _ok_location(loc) and loc not in locs:
                locs.append(loc)
    finally:
        sock.close()
    return locs


def _fetch(http, req, timeout=5):
    """(status, headers, body bytes) for an urlopen-compatible callable;
    HTTP errors still return their body (SOAP faults come back as 500)."""
    try:
        resp = http(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(MAX_BODY)
        except Exception:  # noqa: BLE001
            body = b""
        return e.code, e.headers, body
    try:
        body = resp.read(MAX_BODY)
        status = getattr(resp, "status", None) or resp.getcode()
        return status, resp.headers, body
    finally:
        try:
            resp.close()
        except Exception:  # noqa: BLE001
            pass


def _strip_ns(tag):
    return tag.rsplit("}", 1)[-1]


def _child_text(el, name):
    for c in el:
        if _strip_ns(c.tag) == name:
            return (c.text or "").strip()
    return ""


class Device:
    """Parsed root device description."""

    def __init__(self, location, base_url, info, services):
        self.location = location
        self.base_url = base_url
        self.info = info            # friendlyName, manufacturer, modelName, modelNumber, modelDescription
        self.services = services    # [(serviceType, absolute controlURL)]

    def wan_service(self):
        for want in WAN_SERVICES:
            for st, ctl in self.services:
                if st == want:
                    return st, ctl
        return None

    def describe(self):
        """Short text naming the router (for brand detection / display)."""
        i = self.info
        return " ".join(x for x in (i.get("manufacturer"), i.get("modelName"),
                                     i.get("modelNumber"), i.get("friendlyName")) if x)


def parse_description(xml_bytes, location):
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as e:
        raise UPnPError(f"bad device description: {e}") from None
    base = location
    for el in root:
        if _strip_ns(el.tag) == "URLBase" and (el.text or "").strip():
            base = el.text.strip()
    info, services = {}, []
    root_dev = None
    for el in root:
        if _strip_ns(el.tag) == "device":
            root_dev = el
    if root_dev is not None:
        for k in ("friendlyName", "manufacturer", "modelName", "modelNumber", "modelDescription"):
            info[k] = _child_text(root_dev, k)
    for el in root.iter():
        if _strip_ns(el.tag) != "service":
            continue
        st = _child_text(el, "serviceType")
        ctl = _child_text(el, "controlURL")
        if st and ctl:
            services.append((st, urllib.parse.urljoin(base, ctl)))
    return Device(location, base, info, services)


def fetch_description(location, http=urllib.request.urlopen, timeout=5):
    status, _h, body = _fetch(http, urllib.request.Request(location), timeout)
    if status != 200:
        raise UPnPError(f"device description returned HTTP {status}")
    return parse_description(body, location)


def _soap_body(service, action, args):
    from xml.sax.saxutils import escape
    inner = "".join(f"<{k}>{escape(str(v))}</{k}>" for k, v in args)
    return ('<?xml version="1.0"?>\r\n'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            f'<s:Body><u:{action} xmlns:u="{service}">{inner}</u:{action}></s:Body>'
            '</s:Envelope>').encode()


def _parse_soap(body, action):
    """(values dict, fault code or None, fault description)."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return {}, None, "unparseable SOAP response"
    fault = None
    for el in root.iter():
        tag = _strip_ns(el.tag)
        if tag == "UPnPError":
            code = _child_text(el, "errorCode")
            desc = _child_text(el, "errorDescription")
            try:
                return {}, int(code), desc
            except ValueError:
                return {}, -1, desc
        if tag == "Fault":
            fault = el
    if fault is not None:
        return {}, -1, _child_text(fault, "faultstring") or "SOAP fault"
    for el in root.iter():
        if _strip_ns(el.tag) == f"{action}Response":
            return {_strip_ns(c.tag): (c.text or "").strip() for c in el}, None, ""
    return {}, -1, "no response element"


class IGD:
    """One WAN connection service of an Internet Gateway Device."""

    def __init__(self, device, service_type, control_url, http=urllib.request.urlopen, timeout=5):
        self.device = device
        self.service_type = service_type
        self.control_url = control_url
        self.http = http
        self.timeout = timeout

    @property
    def version(self):
        return 2 if self.service_type.endswith(":2") else 1

    def as_dict(self):
        return {"location": self.device.location, "service": self.service_type,
                "control_url": self.control_url, "info": dict(self.device.info)}

    def soap(self, action, args=()):
        req = urllib.request.Request(
            self.control_url, data=_soap_body(self.service_type, action, args), method="POST",
            headers={"Content-Type": 'text/xml; charset="utf-8"',
                     "SOAPAction": f'"{self.service_type}#{action}"'})
        try:
            status, _h, body = _fetch(self.http, req, self.timeout)
        except (OSError, urllib.error.URLError) as e:
            raise UPnPError(f"{action}: {e}") from None
        values, code, desc = _parse_soap(body, action)
        if code is not None:
            raise UPnPError(f"{action} failed: {desc or 'fault'}", code)
        if status != 200:
            raise UPnPError(f"{action}: HTTP {status}")
        return values

    # read-only
    def external_ip(self):
        ip = self.soap("GetExternalIPAddress").get("NewExternalIPAddress", "")
        try:
            return str(ipaddress.IPv4Address(ip))
        except ValueError:
            return None

    def get_mapping(self, ext_port, proto="TCP"):
        """{internal_client, internal_port, enabled, description, lease} or None."""
        try:
            v = self.soap("GetSpecificPortMappingEntry",
                          (("NewRemoteHost", ""), ("NewExternalPort", int(ext_port)),
                           ("NewProtocol", proto.upper())))
        except UPnPError as e:
            if e.code == ERR_NO_SUCH_ENTRY:
                return None
            raise
        return _mapping(v, ext_port, proto)

    def list_mappings(self, limit=128):
        out = []
        for i in range(limit):
            try:
                v = self.soap("GetGenericPortMappingEntry", (("NewPortMappingIndex", i),))
            except UPnPError as e:
                if e.code in (ERR_INDEX_INVALID, ERR_NO_SUCH_ENTRY, 402) or e.code == -1:
                    break
                raise
            out.append(_mapping(v, v.get("NewExternalPort", ""), v.get("NewProtocol", "")))
        return out

    # mutating
    def add_mapping(self, ext_port, proto, internal_client, internal_port, description,
                    lease=DEFAULT_LEASE):
        """AddPortMapping; falls back to a permanent lease on IGDv1 routers
        that only take those (725). Returns the lease actually used."""
        def call(ls):
            self.soap("AddPortMapping", (
                ("NewRemoteHost", ""), ("NewExternalPort", int(ext_port)),
                ("NewProtocol", proto.upper()), ("NewInternalPort", int(internal_port)),
                ("NewInternalClient", internal_client), ("NewEnabled", 1),
                ("NewPortMappingDescription", description), ("NewLeaseDuration", int(ls))))
        try:
            call(lease)
            return lease
        except UPnPError as e:
            if e.code == ERR_ONLY_PERMANENT and lease:
                call(0)
                return 0
            raise

    def delete_mapping(self, ext_port, proto="TCP"):
        try:
            self.soap("DeletePortMapping", (("NewRemoteHost", ""), ("NewExternalPort", int(ext_port)),
                                            ("NewProtocol", proto.upper())))
            return True
        except UPnPError as e:
            if e.code == ERR_NO_SUCH_ENTRY:
                return False
            raise


def _mapping(v, ext_port, proto):
    def num(k):
        try:
            return int(v.get(k, "") or 0)
        except ValueError:
            return 0
    return {"external_port": int(ext_port) if str(ext_port).isdigit() else ext_port,
            "protocol": str(proto).upper(),
            "internal_client": v.get("NewInternalClient", ""),
            "internal_port": num("NewInternalPort"),
            "enabled": v.get("NewEnabled", "1") in ("1", "true", "True"),
            "description": v.get("NewPortMappingDescription", ""),
            "lease": num("NewLeaseDuration")}


def igd_from_location(location, http=urllib.request.urlopen, timeout=5):
    dev = fetch_description(location, http, timeout)
    svc = dev.wan_service()
    if not svc:
        return None
    return IGD(dev, svc[0], svc[1], http, timeout)


def find_igd(http=urllib.request.urlopen, timeout=2.0, discover_fn=None, locations=None):
    """The first reachable IGD with a WAN connection service, or None."""
    if locations is None:
        locations = (discover_fn or discover)(timeout=timeout)
    for loc in locations:
        try:
            igd = igd_from_location(loc, http)
        except (UPnPError, OSError, urllib.error.URLError, ValueError):
            continue
        if igd:
            return igd
    return None


_DESC_RE = re.compile(r"^porch \d+$")


def is_porch_mapping(m):
    return bool(_DESC_RE.match(m.get("description", "")))

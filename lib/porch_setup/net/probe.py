"""Read-only network probe for porch setup.

    facts = probe(http=ctx.http)       # everything below, as one JSON-able dict
    {
      "iface": "enp3s0", "gateway": "192.168.1.1", "lan_ipv4": "192.168.1.48",
      "host_public_ipv4": [],            # public v4 on an interface (VPS)
      "public_ipv4": "203.0.113.16",     # 2 echo services agreed
      "public_ipv4_sources": [...], "public_ipv4_error": "",
      "wan_ipv4": "203.0.113.16", "wan_source": "upnp" | "natpmp" | None,
      "upnp": {...} | None, "natpmp": {"natpmp": bool, "pcp": bool, ...},
      "cgnat": False, "cgnat_reason": "",
      "ipv6": ["2001:db8:..."],              # global, non-temporary first
      "router": {"brand", "name", "source", "evidence"},
    }

Every external call is injectable (http, discover/natpmp functions, /proc
paths), so tests never touch the network.
"""

import ipaddress
import os
import socket
import urllib.error
import urllib.request

from . import natpmp as _natpmp
from . import router as _router
from . import upnp as _upnp

ECHO_SERVICES = ("https://api.ipify.org", "https://ipv4.icanhazip.com", "https://v4.ident.me",
                 "https://checkip.amazonaws.com")
CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")


# ---- address classification -------------------------------------------------

def v4(s):
    try:
        return ipaddress.IPv4Address(str(s).strip())
    except (ipaddress.AddressValueError, ValueError):
        return None


def is_cgnat(ip):
    a = v4(ip)
    return bool(a and a in CGNAT_NET)


def is_public_v4(ip):
    a = v4(ip)
    return bool(a and a.is_global and a not in CGNAT_NET)


def is_rfc1918(ip):
    a = v4(ip)
    return bool(a and any(a in ipaddress.ip_network(n)
                          for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))


# ---- local facts --------------------------------------------------------------

def default_route(path="/proc/net/route"):
    """(iface, gateway ip) of the lowest-metric IPv4 default route, else (None, None)."""
    best = None
    try:
        with open(path, encoding="ascii", errors="replace") as f:
            next(f, None)
            for line in f:
                p = line.split()
                if len(p) < 8 or p[1] != "00000000" or p[7] != "00000000":
                    continue
                if not int(p[3], 16) & 0x2:      # RTF_GATEWAY
                    continue
                gw = socket.inet_ntoa(int(p[2], 16).to_bytes(4, "little"))
                metric = int(p[6])
                if best is None or metric < best[0]:
                    best = (metric, p[0], gw)
    except (OSError, ValueError):
        return None, None
    return (best[1], best[2]) if best else (None, None)


def lan_ipv4(gateway=None):
    """The source address the kernel would use toward the gateway (UDP
    connect sends nothing)."""
    target = gateway or "192.0.2.1"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 9))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def local_ipv4s(path="/proc/net/fib_trie"):
    """Every IPv4 address assigned to this host (from the LOCAL table)."""
    out = []
    try:
        with open(path, encoding="ascii", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return out
    for i, line in enumerate(lines):
        if "/32 host LOCAL" in line and i:
            ip = lines[i - 1].strip().lstrip("|-+ ").strip()
            if v4(ip) and ip not in out:
                out.append(ip)
    return out


def host_public_ipv4(path="/proc/net/fib_trie"):
    """Public IPv4s on an interface (a VPS / bridged modem). CGNAT and
    private ranges (Tailscale's 100.x, docker bridges) never count."""
    return [ip for ip in local_ipv4s(path) if is_public_v4(ip)]


IFA_F_TEMPORARY = 0x01
IFA_F_DEPRECATED = 0x20
IFA_F_TENTATIVE = 0x40


def global_ipv6(path="/proc/net/if_inet6"):
    """Global unicast IPv6 (no ULA / link-local / deprecated), stable
    addresses before temporary (privacy) ones."""
    stable, temp = [], []
    try:
        with open(path, encoding="ascii", errors="replace") as f:
            for line in f:
                p = line.split()
                if len(p) < 6:
                    continue
                try:
                    a = ipaddress.IPv6Address(bytes.fromhex(p[0]))
                    scope, flags = int(p[3], 16), int(p[4], 16)
                except ValueError:
                    continue
                if scope != 0 or not a.is_global or a in ipaddress.ip_network("fc00::/7"):
                    continue
                if flags & (IFA_F_DEPRECATED | IFA_F_TENTATIVE):
                    continue
                (temp if flags & IFA_F_TEMPORARY else stable).append(str(a))
    except OSError:
        pass
    return stable + temp


# ---- public IP ----------------------------------------------------------------

def _echo(url, http, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": "porch-setup", "Accept": "text/plain"})
    resp = http(req, timeout=timeout)
    try:
        body = resp.read(256)
    finally:
        try:
            resp.close()
        except Exception:  # noqa: BLE001
            pass
    ip = body.decode("ascii", "replace").strip()
    return str(v4(ip)) if v4(ip) else None


def env_echo_services(env=None):
    """PORCH_IP_ECHO: comma-separated echo URLs in place of the public ones
    (bin/porch-fake-router points it at its fake WAN; two must agree)."""
    raw = (os.environ if env is None else env).get("PORCH_IP_ECHO") or ""
    return tuple(u.strip() for u in raw.split(",") if u.strip())


def public_ipv4(http=urllib.request.urlopen, services=ECHO_SERVICES, need=2, timeout=5):
    """(ip, sources, error). The answer counts only when `need` services agree."""
    seen = {}
    errors = []
    for url in services:
        try:
            ip = _echo(url, http, timeout)
        except (OSError, urllib.error.URLError, ValueError) as e:
            errors.append(f"{url}: {getattr(e, 'reason', e)}")
            continue
        if not ip:
            errors.append(f"{url}: not an IPv4 address")
            continue
        seen.setdefault(ip, []).append(url)
        if len(seen[ip]) >= need:
            return ip, seen[ip], ""
    if len(seen) > 1:
        return None, [], "echo services disagree: " + ", ".join(sorted(seen))
    if seen:
        ip, src = next(iter(seen.items()))
        return None, src, f"only one echo service answered ({ip})"
    return None, [], "; ".join(errors) or "no echo service answered"


# ---- NAT classification -------------------------------------------------------

def classify(facts):
    """(cgnat: bool, reason) from the probe facts."""
    wan, pub = facts.get("wan_ipv4"), facts.get("public_ipv4")
    if facts.get("host_public_ipv4"):
        return False, ""
    if wan and is_cgnat(wan):
        return True, f"the router's WAN address {wan} is in 100.64.0.0/10 (carrier-grade NAT)"
    if wan and (is_rfc1918(wan) or not v4(wan).is_global):
        return True, f"the router's WAN address {wan} is private: there is another NAT upstream (double NAT or CGNAT)"
    if wan and pub and wan != pub:
        return True, f"the router's WAN address {wan} differs from the public address {pub}: another NAT is upstream"
    if pub and is_cgnat(pub):
        return True, f"the public address {pub} is in 100.64.0.0/10"
    return False, ""


# ---- the probe ----------------------------------------------------------------

def probe(http=urllib.request.urlopen, *, route_path="/proc/net/route", fib_path="/proc/net/fib_trie",
          inet6_path="/proc/net/if_inet6", arp_path="/proc/net/arp", find_igd=None,
          natpmp_probe=None, echo_services=ECHO_SERVICES, ssdp_timeout=2.0, lan_ip_fn=None,
          detect_router=True, log=None):
    log = log or (lambda m: None)
    iface, gateway = default_route(route_path)
    facts = {"iface": iface, "gateway": gateway,
             "lan_ipv4": (lan_ip_fn or lan_ipv4)(gateway),
             "host_public_ipv4": host_public_ipv4(fib_path)}

    if echo_services is ECHO_SERVICES:
        echo_services = env_echo_services() or ECHO_SERVICES
    pub, sources, err = public_ipv4(http, echo_services)
    facts.update(public_ipv4=pub, public_ipv4_sources=sources, public_ipv4_error=err)

    igd = None
    try:
        igd = (find_igd or (lambda: _upnp.find_igd(http=http, timeout=ssdp_timeout)))()
    except Exception as e:  # noqa: BLE001
        log(f"UPnP discovery failed: {e}")
    facts["upnp"] = None
    wan, wan_src = None, None
    if igd is not None:
        u = igd.as_dict()
        try:
            u["external_ip"] = igd.external_ip()
        except _upnp.UPnPError as e:
            u["external_ip"], u["error"] = None, str(e)
        facts["upnp"] = u
        if u.get("external_ip"):
            wan, wan_src = u["external_ip"], "upnp"

    facts["natpmp"] = None
    if gateway:
        try:
            facts["natpmp"] = (natpmp_probe or (lambda gw, cip: _natpmp.probe(gw, client_ip=cip)))(
                gateway, facts["lan_ipv4"] or "0.0.0.0")
        except Exception as e:  # noqa: BLE001
            facts["natpmp"] = {"natpmp": False, "pcp": False, "external_ip": None, "error": str(e)}
        if not wan and facts["natpmp"].get("external_ip"):
            wan, wan_src = facts["natpmp"]["external_ip"], "natpmp"
    facts.update(wan_ipv4=wan, wan_source=wan_src)
    facts["cgnat"], facts["cgnat_reason"] = classify(facts)
    facts["ipv6"] = global_ipv6(inet6_path)
    if detect_router:
        facts["router"] = _router.detect_brand(
            gateway, upnp_text=igd.device.describe() if igd is not None else "", http=http,
            arp_path=arp_path)
    else:
        facts["router"] = {"brand": None, "name": "", "source": None, "evidence": ""}
    return facts


def summary(facts):
    """Human lines for the CLI."""
    r = facts.get("router") or {}
    u = facts.get("upnp")
    n = facts.get("natpmp") or {}
    lines = [
        f"LAN: {facts.get('lan_ipv4') or '?'} via {facts.get('gateway') or '?'} ({facts.get('iface') or '?'})",
        f"router: {r.get('name') or 'unknown'}" + (f" (from {r['source']})" if r.get("source") else ""),
        f"public IPv4: {facts.get('public_ipv4') or 'unknown'}"
        + (f"  [{facts['public_ipv4_error']}]" if facts.get("public_ipv4_error") else ""),
        f"router WAN IPv4: {facts.get('wan_ipv4') or 'unknown'}"
        + (f" (from {facts['wan_source']})" if facts.get("wan_source") else ""),
        "UPnP IGD: " + ((u.get("info", {}).get("modelName") or "yes") if u else "not found"),
        "NAT-PMP: " + ("yes" if n.get("natpmp") else "no") + ", PCP: " + ("yes" if n.get("pcp") else "no"),
        "CGNAT / double NAT: " + (f"yes: {facts['cgnat_reason']}" if facts.get("cgnat") else "no"),
        "IPv6: " + (", ".join(facts.get("ipv6") or []) or "none"),
    ]
    if facts.get("host_public_ipv4"):
        lines.insert(1, "public IPv4 on an interface: " + ", ".join(facts["host_public_ipv4"]))
    return lines

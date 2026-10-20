"""lib/porch_setup/net/upnp.py against a loopback SSDP + SOAP responder (no real network)."""

import http.server
import os
import re
import socket
import sys
import threading
import unittest
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "lib"))

from porch_setup.net import upnp  # noqa: E402

WANIP2 = "urn:schemas-upnp-org:service:WANIPConnection:2"
WANIP1 = "urn:schemas-upnp-org:service:WANIPConnection:1"


def description(service):
    return f"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
 <specVersion><major>1</major><minor>0</minor></specVersion>
 <device>
  <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
  <friendlyName>Home Router</friendlyName>
  <manufacturer>NETGEAR, Inc.</manufacturer>
  <modelName>RBR750</modelName>
  <modelNumber>v1</modelNumber>
  <deviceList><device>
   <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
   <deviceList><device>
    <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
    <serviceList><service>
     <serviceType>{service}</serviceType>
     <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
     <controlURL>/ctl/IPConn</controlURL>
     <eventSubURL>/evt/IPConn</eventSubURL>
     <SCPDURL>/WANIPCn.xml</SCPDURL>
    </service></serviceList>
   </device></deviceList>
  </device></deviceList>
 </device>
</root>""".encode()


def fault(code, desc):
    return f"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault>
<faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>
<UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>{code}</errorCode>
<errorDescription>{desc}</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>""".encode()


def ok(service, action, values):
    inner = "".join(f"<{k}>{v}</{k}>" for k, v in values.items())
    return (f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
            f'<s:Body><u:{action}Response xmlns:u="{service}">{inner}</u:{action}Response>'
            f'</s:Body></s:Envelope>').encode()


class FakeRouter:
    """In-memory IGD: mappings {(port, proto): dict}."""

    def __init__(self, service=WANIP2, only_permanent=False, external_ip="203.0.113.16"):
        self.service = service
        self.only_permanent = only_permanent
        self.external_ip = external_ip
        self.mappings = {}
        self.calls = []
        router = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body, ctype="text/xml"):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # noqa: N802
                if self.path == "/rootDesc.xml":
                    self._send(200, description(router.service))
                else:
                    self._send(404, b"")

            def do_POST(self):  # noqa: N802
                body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
                action = self.headers.get("SOAPAction", "").strip('"').split("#")[-1]
                args = dict(re.findall(r"<(New\w+)>([^<]*)</New\w+>", body))
                router.calls.append((action, args))
                code, resp = router.handle(action, args)
                self._send(code, resp)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.location = f"http://127.0.0.1:{self.port}/rootDesc.xml"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

        # SSDP: unicast UDP responder on loopback
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.ssdp_addr = self.udp.getsockname()
        self.searches = []
        threading.Thread(target=self._ssdp, daemon=True).start()

    def _ssdp(self):
        while True:
            try:
                data, addr = self.udp.recvfrom(4096)
            except OSError:
                return
            text = data.decode()
            self.searches.append(text)
            st = re.search(r"(?m)^ST: (.*)\r$", text).group(1)
            if "InternetGatewayDevice:1" not in st:
                continue
            resp = ("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\n"
                    f"ST: {st}\r\nLOCATION: {self.location}\r\nSERVER: test UPnP/1.1\r\n\r\n")
            self.udp.sendto(resp.encode(), addr)
            # a junk reply and a non-http location must be ignored
            self.udp.sendto(b"NOTIFY * HTTP/1.1\r\n\r\n", addr)
            self.udp.sendto(b"HTTP/1.1 200 OK\r\nLOCATION: file:///etc/passwd\r\n\r\n", addr)

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.udp.close()

    def handle(self, action, a):
        s = self.service
        if action == "GetExternalIPAddress":
            return 200, ok(s, action, {"NewExternalIPAddress": self.external_ip})
        if action == "GetSpecificPortMappingEntry":
            m = self.mappings.get((int(a["NewExternalPort"]), a["NewProtocol"]))
            if not m:
                return 500, fault(714, "NoSuchEntryInArray")
            return 200, ok(s, action, {"NewInternalPort": m["iport"], "NewInternalClient": m["client"],
                                       "NewEnabled": 1, "NewPortMappingDescription": m["desc"],
                                       "NewLeaseDuration": m["lease"]})
        if action == "GetGenericPortMappingEntry":
            items = sorted(self.mappings.items())
            i = int(a["NewPortMappingIndex"])
            if i >= len(items):
                return 500, fault(713, "SpecifiedArrayIndexInvalid")
            (port, proto), m = items[i]
            return 200, ok(s, action, {"NewRemoteHost": "", "NewExternalPort": port, "NewProtocol": proto,
                                       "NewInternalPort": m["iport"], "NewInternalClient": m["client"],
                                       "NewEnabled": 1, "NewPortMappingDescription": m["desc"],
                                       "NewLeaseDuration": m["lease"]})
        if action == "AddPortMapping":
            key = (int(a["NewExternalPort"]), a["NewProtocol"])
            lease = int(a["NewLeaseDuration"])
            if self.only_permanent and lease:
                return 500, fault(725, "OnlyPermanentLeasesSupported")
            cur = self.mappings.get(key)
            if cur and cur["client"] != a["NewInternalClient"]:
                return 500, fault(718, "ConflictInMappingEntry")
            self.mappings[key] = {"iport": int(a["NewInternalPort"]), "client": a["NewInternalClient"],
                                  "desc": a["NewPortMappingDescription"], "lease": lease}
            return 200, ok(s, action, {})
        if action == "DeletePortMapping":
            key = (int(a["NewExternalPort"]), a["NewProtocol"])
            if key not in self.mappings:
                return 500, fault(714, "NoSuchEntryInArray")
            del self.mappings[key]
            return 200, ok(s, action, {})
        return 500, fault(401, "Invalid Action")


class UPnPTest(unittest.TestCase):
    def setUp(self):
        self.r = FakeRouter()
        self.addCleanup(self.r.close)

    def test_parse_ssdp(self):
        h = upnp.parse_ssdp(b"HTTP/1.1 200 OK\r\nLocation: http://x/\r\nST: a\r\n\r\n")
        self.assertEqual(h["location"], "http://x/")
        self.assertIsNone(upnp.parse_ssdp(b"NOTIFY * HTTP/1.1\r\n\r\n"))

    def test_discover_and_describe(self):
        locs = upnp.discover(timeout=0.5, ssdp_addr=self.r.ssdp_addr, bind=("127.0.0.1", 0))
        self.assertEqual(locs, [self.r.location])
        self.assertTrue(any("M-SEARCH" in s and 'MAN: "ssdp:discover"' in s for s in self.r.searches))
        igd = upnp.find_igd(locations=locs)
        self.assertEqual(igd.service_type, WANIP2)
        self.assertEqual(igd.version, 2)
        self.assertEqual(igd.control_url, f"http://127.0.0.1:{self.r.port}/ctl/IPConn")
        self.assertIn("NETGEAR", igd.device.describe())
        self.assertEqual(igd.as_dict()["info"]["modelName"], "RBR750")

    def test_find_igd_skips_bad_locations(self):
        bad = f"http://127.0.0.1:{self.r.port}/missing.xml"
        igd = upnp.find_igd(locations=[bad, self.r.location])
        self.assertEqual(igd.device.location, self.r.location)
        self.assertIsNone(upnp.find_igd(locations=[bad]))

    def test_mapping_lifecycle(self):
        igd = upnp.find_igd(locations=[self.r.location])
        self.assertEqual(igd.external_ip(), "203.0.113.16")
        self.assertIsNone(igd.get_mapping(443))
        self.assertEqual(igd.list_mappings(), [])
        self.assertEqual(igd.add_mapping(443, "TCP", "192.168.1.48", 443, "porch 443"), upnp.DEFAULT_LEASE)
        m = igd.get_mapping(443, "tcp")
        self.assertEqual((m["internal_client"], m["internal_port"], m["lease"]), ("192.168.1.48", 443, upnp.DEFAULT_LEASE))
        self.assertTrue(upnp.is_porch_mapping(m))
        igd.add_mapping(80, "TCP", "192.168.1.48", 80, "porch 80")
        self.assertEqual([x["external_port"] for x in igd.list_mappings()], [80, 443])
        add = [a for n, a in self.r.calls if n == "AddPortMapping"][0]
        self.assertEqual(add["NewRemoteHost"] if "NewRemoteHost" in add else "", "")
        self.assertEqual(add["NewProtocol"], "TCP")
        self.assertTrue(igd.delete_mapping(443))
        self.assertFalse(igd.delete_mapping(443))
        self.assertIsNone(igd.get_mapping(443))

    def test_conflict_fault(self):
        igd = upnp.find_igd(locations=[self.r.location])
        igd.add_mapping(443, "TCP", "192.168.1.77", 443, "other")
        with self.assertRaises(upnp.UPnPError) as cm:
            igd.add_mapping(443, "TCP", "192.168.1.48", 443, "porch 443")
        self.assertEqual(cm.exception.code, upnp.ERR_CONFLICT)

    def test_permanent_lease_fallback_igdv1(self):
        self.r.service, self.r.only_permanent = WANIP1, True
        igd = upnp.find_igd(locations=[self.r.location])
        self.assertEqual(igd.version, 1)
        self.assertEqual(igd.add_mapping(7000, "TCP", "192.168.1.48", 7000, "porch 7000"), 0)
        self.assertEqual(self.r.mappings[(7000, "TCP")]["lease"], 0)

    def test_no_wan_service(self):
        self.r.service = "urn:schemas-upnp-org:service:Layer3Forwarding:1"
        self.assertIsNone(upnp.find_igd(locations=[self.r.location]))

    def test_soap_body_escapes(self):
        body = upnp._soap_body(WANIP2, "AddPortMapping", (("NewPortMappingDescription", "<a&b>"),))
        self.assertIn(b"&lt;a&amp;b&gt;", body)

    def test_unreachable_control_url(self):
        dev = upnp.Device("http://127.0.0.1:1/", "", {}, [])
        igd = upnp.IGD(dev, WANIP2, "http://127.0.0.1:1/ctl", http=urllib.request.urlopen, timeout=1)
        with self.assertRaises(upnp.UPnPError):
            igd.external_ip()


if __name__ == "__main__":
    unittest.main()

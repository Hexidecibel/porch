"""Relay modes' base class (helper module: no MODE, so the registry skips it).

paid / byo / oracle all end the same way: a relay host running only frps, the
porch-relay frpc unit at home, and DNS pointing at the relay (ddns off, the
relay's address is static). They differ in how the relay host appears:

  paid    porch creates a small VPS through the provider's API (cloud-init
          installs frps); rollback deletes that VPS (by id, tag checked).
  byo     porch installs frps on your server over ssh (needs sudo there);
          rollback removes only what it installed, never the server.
  oracle  a guide for an Oracle Cloud Always Free VM, then byo.

Every relay mode refuses while the localhost frpc bypass is on (see
relay/common.py), in detect (so preflight fails) and again in apply.

Undo entries (write-ahead, newest first on rollback):
  relay.server_delete  (paid)  recorded before the create call, id filled in after
  relay.ssh_uninstall  (byo)   recorded before the install script runs
  relay.home_remove            recorded before the home config + unit are written
so a rollback stops the home frpc first, then removes the relay side.
"""

import ipaddress
import re
import socket

from ..engine import Check, Input, StepError
from ..relay import common
from .base import LIKELY, UNAVAILABLE, WORKS, Mode

TARGET_RE = re.compile(r"\A[a-z_][a-z0-9_.-]{0,31}@[A-Za-z0-9.:-]{1,253}\Z")
INSTALL_WAIT = 900      # seconds: create -> cloud-init -> frps listening
READY_WAIT = 600


def _valid_target(v):
    if not TARGET_RE.match(str(v or "")):
        return "want user@host (for example ubuntu@203.0.113.7)"
    return None


SSH_KEY_INPUT = Input("relay_ssh_key", "text", "SSH private key for the relay (blank: ssh's default)",
                      required=False, flag="--relay-ssh-key",
                      help="byo/oracle: the key ssh uses; paid: its .pub is added to the relay's root "
                           "account (ssh is open only to this box's public address)")
HOST_INPUT = Input("relay_host", "text", "Relay server (user@host, with passwordless sudo)",
                   validate=_valid_target, flag="--relay-host",
                   help="byo/oracle: the server porch installs the relay on over ssh")


class RelayMode(Mode):
    order = 60
    relay_kind = ""

    def __init__(self):
        self.tcp_open = common.tcp_open        # overridable for tests

    # ---- detection -------------------------------------------------------------
    def detect(self, ctx, facts):
        if common.bypass_on(ctx):
            return UNAVAILABLE, common.BYPASS_REASON
        return self._detect(ctx, facts)

    def _detect(self, ctx, facts):
        return LIKELY, ""

    @staticmethod
    def needs_relay(facts):
        return bool(facts.get("cgnat"))

    # ---- shared apply pieces ---------------------------------------------------
    def wait_control(self, ctx, ip, wait=INSTALL_WAIT):
        t0 = ctx.clock()
        while True:
            if self.tcp_open(ip, common.CONTROL_PORT):
                return
            if ctx.clock() - t0 >= wait:
                raise StepError("connect.relay.control",
                                f"the relay {ip} did not open tcp {common.CONTROL_PORT} in {wait}s",
                                "check /var/log/porch-relay-install.log on the relay")
            ctx.sleep(5)

    def outputs(self, ctx, relay, ip):
        return {"method": "relay", "relay": relay, "ingress_ipv4": ip, "ingress_ipv6": None,
                "ddns": False}

    def verify(self, ctx, facts, outputs):
        ip = (outputs.get("relay") or {}).get("ip") or outputs.get("ingress_ipv4")
        checks = []
        if common.bypass_on(ctx):
            checks.append(Check(False, "connect.relay.bypass", common.BYPASS_REASON, common.BYPASS_HINT))
        return checks + common.health(ctx, ip, tcp=self.tcp_open, wait=30)

    def undo(self, ctx, entry):
        if entry.get("kind") == "relay.home_remove":
            common.remove_home(ctx, entry)
            return
        super().undo(ctx, entry)


def resolve_ipv4(host):
    """The public IPv4 a relay host name / address stands for."""
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        if ip.version != 4:
            raise StepError("connect.relay.ipv6", "the relay needs a public IPv4 address")
        return str(ip)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, 22, socket.AF_INET, socket.SOCK_STREAM)
    except OSError as e:
        raise StepError("connect.relay.resolve", f"cannot resolve {host}: {e}") from None
    return infos[0][4][0]


__all__ = ["RelayMode", "SSH_KEY_INPUT", "HOST_INPUT", "resolve_ipv4", "WORKS", "LIKELY", "UNAVAILABLE"]

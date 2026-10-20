"""oracle: a guide for a free Oracle Cloud (Always Free) VM, then the byo
path over ssh. No OCI API: it needs RSA request signing and an account
setup that is quicker by hand.

    porch connect oracle                 prints the guide
    porch connect oracle ubuntu@<ip>     installs the relay there (as byo)
"""

from ..engine import Input
from ..relay import common
from .byo import ByoMode
from .relay import HOST_INPUT, SSH_KEY_INPUT, LIKELY, WORKS

GUIDE = (
    "Oracle Cloud Always Free relay (about 15 minutes, free):",
    "  1. cloud.oracle.com > Compute > Instances > Create instance.",
    "     Image: Canonical Ubuntu 24.04. Shape: VM.Standard.E2.1.Micro (AMD, 'Always Free-eligible');",
    "     Ampere A1 capacity is scarce and was cut back in 2026, and the micro shape is enough.",
    "     Tip: upgrading the account to Pay As You Go (still $0) stops Oracle reclaiming idle VMs.",
    "  2. Networking: a public subnet with 'Assign a public IPv4 address'. Add your SSH public key.",
    "  3. Networking > Virtual cloud networks > (the VCN) > Security Lists > Default Security List >",
    f"     Add Ingress Rules: source 0.0.0.0/0, TCP, destination ports 80,443,7000,{common.CONTROL_PORT}.",
    "  4. Note the instance's public IP. The user is `ubuntu` (passwordless sudo).",
    "  5. porch connect oracle ubuntu@<public ip> [--ssh-key ~/.ssh/id_ed25519]",
    "     (porch also opens those ports in the VM's own iptables, which Oracle's images close.)",
)

ORACLE_HOST_INPUT = Input(HOST_INPUT.name, HOST_INPUT.kind, "Oracle VM (ubuntu@<public ip>)",
                          validate=HOST_INPUT.validate, flag=HOST_INPUT.flag,
                          help="\n".join(GUIDE))


class OracleMode(ByoMode):
    name = "oracle"
    title = "Relay on an Oracle Cloud Always Free VM (experimental)"
    summary = "Free: you create the VM by hand (guided), then porch installs the relay over SSH."
    order = 65

    def inputs(self, ctx):
        return [ORACLE_HOST_INPUT, SSH_KEY_INPUT]

    def _detect(self, ctx, facts):
        if self.needs_relay(facts):
            return LIKELY, "free relay for carrier-grade NAT; you create the VM by hand (guided)"
        return LIKELY, "free, but you create the VM in Oracle's console first (guided)"

    def steps(self, ctx, facts):
        return list(GUIDE)

    def apply(self, ctx, facts):
        for line in GUIDE:
            ctx.log(line, "debug")
        return super().apply(ctx, facts)


MODE = OracleMode()
__all__ = ["MODE", "GUIDE", "WORKS"]

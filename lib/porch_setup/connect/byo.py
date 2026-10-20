"""byo: make a server you already have the relay, over ssh.

    porch connect byo user@host [--ssh-key K]

Needs passwordless sudo there. install-relay.sh goes over ssh's stdin (the
relay token never appears in argv), installs only frps as
porch-relay-frps.service and adds allow rules for tcp 80, 443, 7000 and 7835
to an active ufw (or to iptables, as on Oracle's images); ssh rules are never
touched. Rollback runs uninstall-relay.sh, which removes exactly what the
install recorded in /etc/porch-relay/installed. The server itself is never
deleted.
"""

from ..engine import Action, StepError
from ..relay import common
from .relay import HOST_INPUT, SSH_KEY_INPUT, LIKELY, RelayMode, resolve_ipv4

INSTALL_TIMEOUT = 900


class ByoMode(RelayMode):
    name = "byo"
    title = "Relay on your own server over SSH"
    summary = "Porch installs a small relay (frps) on a server you control; it forwards 80, 443 and 7000 here."
    order = 70

    def inputs(self, ctx):
        return [HOST_INPUT, SSH_KEY_INPUT]

    def _detect(self, ctx, facts):
        return LIKELY, "needs a server with a public IPv4 that you can ssh into with sudo"

    def steps(self, ctx, facts):
        return ["Install frps on the server over ssh (sudo), open tcp 80, 443, 7000 and 7835 there.",
                "Run the porch-relay frpc here; point DNS at the server."]

    def plan(self, ctx, facts):
        target = ctx.input("relay_host") or "user@host"
        return [Action("relay.install", target, "ssh: install-relay.sh (frps, firewall rules)"),
                Action("relay.home", common.UNIT, "frpc -> relay tcp 80, 443, 7000")]

    def _target(self, ctx):
        target = ctx.input("relay_host")
        if not target:
            raise StepError(f"connect.{self.name}.host", "no relay server given",
                            f"porch connect {self.name} user@host")
        return target, ctx.input("relay_ssh_key") or None

    def _ssh(self, ctx, target, key, script, timeout=INSTALL_TIMEOUT):
        return ctx.run.run(common.ssh_argv(target, key, "sudo -n bash -s"), input=script,
                           timeout=timeout)

    def apply(self, ctx, facts):
        common.refuse_bypass(ctx)
        target, key = self._target(ctx)
        host = target.split("@", 1)[1]
        ip = resolve_ipv4(host)
        if not ctx.confirm(f"Install the porch relay on {target} ({ip}): frps {common.FRP_VERSION} as "
                           f"porch-relay-frps.service and allow rules for tcp 80, 443, {ctx.cfg.frp_port} "
                           f"and {common.CONTROL_PORT}? It uses sudo there.", default=False):
            raise StepError(f"connect.{self.name}.not_confirmed", "relay not installed",
                            f"run `porch connect {self.name}` interactively, or pass --yes")
        token, admin_pw = common.tokens_for(ctx, ip)
        script = common.render_install(token, self.name, ctx.cfg.frp_port)
        if not any(e.get("kind") == "relay.ssh_uninstall" and e.get("target") == target
                   for e in ctx.undo_entries()):
            self.record_undo(ctx, "relay.ssh_uninstall", target=target, ssh_key=key, ip=ip)
        ctx.log(f"installing the relay on {target} over ssh (a minute or two)")
        r = self._ssh(ctx, target, key, script)
        if not r.ok or "PORCH_RELAY_OK" not in r.stdout:
            tail = ctx.redactor.redact((r.stderr or r.stdout).strip())[-400:]
            hint = ("passwordless sudo is needed there" if "password" in tail.lower()
                    else "ssh in and read /var/log/porch-relay-install.log")
            raise StepError(f"connect.{self.name}.install", f"install-relay.sh on {target} failed "
                            f"(exit {r.returncode}): {tail}", hint)
        self.wait_control(ctx, ip, wait=60)
        common.install_home(ctx, self, ip, token, admin_pw)
        relay = {"kind": self.name, "target": target, "ip": ip}
        return self.outputs(ctx, relay, ip)

    def undo(self, ctx, entry):
        if entry.get("kind") != "relay.ssh_uninstall":
            return super().undo(ctx, entry)
        # Only what install-relay.sh recorded; never the server itself.
        r = self._ssh(ctx, entry["target"], entry.get("ssh_key"), common.render_uninstall(), timeout=300)
        if not r.ok:
            raise StepError(f"connect.{self.name}.uninstall",
                            f"uninstall-relay.sh on {entry['target']} failed (exit {r.returncode}): "
                            + (r.stderr or r.stdout).strip()[-300:],
                            "fix ssh access and roll back again, or remove porch-relay-frps by hand")
        ctx.log(f"relay removed from {entry['target']} (the server itself is untouched)")


MODE = ByoMode()

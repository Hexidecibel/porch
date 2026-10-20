"""paid: porch rents a small VPS (DigitalOcean or Vultr) and
makes it the relay. The API token is a secret input (a ref, or
PORCH_RELAY_TOKEN); the price comes from the provider's API and is shown
before anything is created, behind a confirm (--yes when unattended).

The server is created with user_data = install-relay.sh (frps only, ufw:
22 from this box's public address, 80/443/7000/7835 from anywhere), tagged
porch-relay (plus --relay-tag). Rollback / `porch connect --off` deletes
exactly that server: by the recorded id, and only when it still carries the
tag; a crash between create and recording the id is covered by the
recorded unique name + tag.
"""

import secrets

from ..engine import Action, Check, Input, StepError
from ..relay import common
from ..relay import providers as _prov
from .relay import INSTALL_WAIT, READY_WAIT, SSH_KEY_INPUT, LIKELY, WORKS, RelayMode

DEFAULT_PROVIDER = "digitalocean"


def _valid_tag(v):
    if v in (None, ""):
        return None
    import re
    if not re.match(r"\A[a-z0-9][a-z0-9-]{0,30}\Z", str(v)):
        return "a tag is 1-31 lowercase letters, digits or dashes"
    return None


INPUTS = (
    Input("relay_provider", "choice", "VPS provider for the relay", default=DEFAULT_PROVIDER,
          choices=sorted(_prov.PROVIDERS), flag="--relay-provider",
          help="digitalocean (about $4/month), vultr (about $5/month)"),
    Input("relay_token", "secret", "API token for the relay provider (read + write)",
          flag="--relay-token-ref", env="PORCH_RELAY_TOKEN",
          help="DigitalOcean: API > Tokens (write scope); Vultr: Account > API"),
    Input("relay_region", "text", "Region (blank: the provider's default)", required=False,
          flag="--relay-region", help="e.g. nyc3 (DigitalOcean), ewr (Vultr)"),
    Input("relay_size", "text", "Server size (blank: the cheapest that fits)", required=False,
          flag="--relay-size"),
    SSH_KEY_INPUT,
    Input("relay_tag", "text", "Extra tag for the relay server (blank: none)", required=False,
          validate=_valid_tag, flag="--relay-tag", help="porch always adds porch-relay"),
)


class PaidMode(RelayMode):
    name = "paid"
    title = "Relay on a small paid VPS (DigitalOcean / Vultr)"
    summary = "Porch rents a ~$4-6/month server that forwards ports 80, 443 and 7000 to this box."
    order = 60

    def __init__(self):
        super().__init__()
        self.http = None            # tests: fake HTTP for the provider client

    def inputs(self, ctx):
        return list(INPUTS)

    def _detect(self, ctx, facts):
        if self.needs_relay(facts):
            return WORKS, ("the fix for carrier-grade NAT: a small VPS (about $4-6/month) "
                           "forwards 80, 443 and 7000 here; needs a provider API token")
        return LIKELY, "works anywhere with outbound internet; needs a provider API token, about $4-6/month"

    def steps(self, ctx, facts):
        return ["Create a small VPS at the provider (price shown first, you confirm).",
                "Install only frps on it; open tcp 80, 443, 7000 and 7835.",
                "Run the porch-relay frpc here; point DNS at the VPS."]

    def plan(self, ctx, facts):
        prov = ctx.input("relay_provider") or DEFAULT_PROVIDER
        return [Action("relay.create", f"{prov} server",
                       f"{ctx.input('relay_size') or 'cheapest'} in {ctx.input('relay_region') or 'default region'}"),
                Action("relay.home", common.UNIT, "frpc -> relay tcp 80, 443, 7000")]

    # ---- provider --------------------------------------------------------------
    def provider(self, ctx, name=None, token_ref=None):
        name = name or ctx.input("relay_provider") or DEFAULT_PROVIDER
        cls = _prov.PROVIDERS.get(name)
        if cls is None:
            raise StepError("connect.paid.provider", f"unknown provider {name!r}",
                            "choose one of: " + ", ".join(sorted(_prov.PROVIDERS)))
        try:
            token = ctx.secrets.get(token_ref) if token_ref else ctx.secret("relay_token")
        except Exception as e:  # noqa: BLE001 - never echo the value
            raise StepError("connect.paid.token", f"cannot read the {cls.title} API token: "
                            f"{type(e).__name__}", "pass --relay-token-ref inf://... (or PORCH_RELAY_TOKEN)") from None
        token = (token or "").strip()
        ctx.redactor.add(token)
        return cls(token, http=self.http)

    def _server_entry(self, ctx):
        for e in ctx.undo_entries():
            if e.get("kind") == "relay.server_delete" and e.get("mode") == self.name:
                return e
        return None

    def _wait_ready(self, ctx, prov, sid):
        t0 = ctx.clock()
        while True:
            s = prov.get(sid)
            if s is None:
                raise StepError("connect.paid.gone", f"{prov.title} server {sid} disappeared")
            if s["ready"]:
                return s
            if ctx.clock() - t0 >= READY_WAIT:
                raise StepError("connect.paid.timeout", f"{prov.title} server {sid} is still {s['status']}",
                                "porch connect --off deletes it; then try another region")
            ctx.sleep(5)

    # ---- apply -------------------------------------------------------------------
    def apply(self, ctx, facts):
        common.refuse_bypass(ctx)
        prov = self.provider(ctx)
        try:
            return self._apply(ctx, facts, prov)
        except _prov.ProviderError as e:
            raise StepError("connect.paid.api", str(e), "check the token's scope and the provider's status") from None

    def _apply(self, ctx, facts, prov):
        entry = self._server_entry(ctx)
        server = None
        if entry and entry.get("id") is not None:
            server = prov.get(entry["id"])
            if server is not None and server["ipv4"] and common.read_frpc(ctx).get("serverAddr") != server["ipv4"]:
                # the relay's token is lost with the home config: start over
                ctx.log(f"relay server {entry['id']} exists but this box no longer has its token; replacing it")
                self.undo(ctx, entry)
                ctx.drop_undo(entry)
                entry, server = None, None
        elif entry is not None:
            self.undo(ctx, entry)        # crashed mid-create: delete by name + tag
            ctx.drop_undo(entry)
            entry = None
        if server is None:
            prov.check()
            plan = prov.plan(ctx.input("relay_region") or None, ctx.input("relay_size") or None)
            cost = prov.summary(plan)
            ctx.log(f"{prov.title}: {plan['size']} in {plan['region']} costs {cost}, billed to your "
                    f"{prov.title} account until `porch connect --off` (or --rollback) deletes it")
            if not ctx.confirm(f"Create a {plan['size']} server at {prov.title} ({plan['region']}) "
                               f"for {cost}?", default=False):
                raise StepError("connect.paid.not_confirmed", "relay server not created",
                                "run `porch connect paid` interactively, or pass --yes")
            name = "porch-relay-" + secrets.token_hex(4)
            tags = [common.TAG] + ([ctx.input("relay_tag")] if ctx.input("relay_tag") else [])
            token, admin_pw = common.new_token(), common.new_token()
            ctx.redactor.add(token)
            ctx.redactor.add(admin_pw)
            user_data = common.render_install(token, "paid", ctx.cfg.frp_port,
                                              ssh_from=facts.get("public_ipv4") or "",
                                              ssh_pubkey=common.public_key_for(ctx.input("relay_ssh_key")))
            entry = self.record_undo(ctx, "relay.server_delete", provider=prov.name, name=name,
                                     tag=common.TAG, id=None, token_ref=ctx.secret_ref("relay_token"),
                                     region=plan["region"], size=plan["size"])
            created = prov.create(name, plan["region"], plan["size"], user_data, tags)
            entry["id"] = created["id"]
            entry["monthly"] = plan["monthly"]
            entry["currency"] = plan["currency"]
            ctx.state.save()
            ctx.log(f"{prov.title} server {created['id']} ({name}) created; waiting for it to boot")
            server = self._wait_ready(ctx, prov, created["id"])
        else:
            token, admin_pw = common.tokens_for(ctx, server["ipv4"])
        ip = server["ipv4"]
        ctx.log(f"relay {ip}: waiting for frps on tcp {common.CONTROL_PORT} (cloud-init installs it)")
        self.wait_control(ctx, ip, INSTALL_WAIT)
        common.install_home(ctx, self, ip, token, admin_pw)
        relay = {"kind": "paid", "provider": prov.name, "id": server["id"], "name": server["name"],
                 "ip": ip, "region": entry.get("region"), "size": entry.get("size"),
                 "monthly": entry.get("monthly"), "currency": entry.get("currency")}
        return self.outputs(ctx, relay, ip)

    # ---- undo ----------------------------------------------------------------------
    def undo(self, ctx, entry):
        if entry.get("kind") != "relay.server_delete":
            return super().undo(ctx, entry)
        prov = self.provider(ctx, entry.get("provider"), entry.get("token_ref"))
        tag = entry.get("tag") or common.TAG
        try:
            if entry.get("id") is not None:
                s = prov.get(entry["id"])
                if s is None:
                    ctx.log(f"relay server {entry['id']} is already gone")
                    return
                if tag not in s["tags"]:
                    raise StepError("connect.paid.untagged",
                                    f"{prov.title} server {entry['id']} does not carry the {tag} tag; "
                                    "porch only deletes servers it created", "delete it by hand if it is yours")
                prov.delete(entry["id"])
                ctx.log(f"deleted {prov.title} relay server {entry['id']} ({s.get('ipv4')})")
                return
            for s in prov.list_tagged(tag):
                if s["name"] == entry.get("name"):
                    prov.delete(s["id"])
                    ctx.log(f"deleted {prov.title} relay server {s['id']} ({s['name']})")
        except _prov.ProviderError as e:
            raise StepError("connect.paid.delete", str(e),
                            f"delete the server tagged {tag} in the {prov.title} console") from None


MODE = PaidMode()

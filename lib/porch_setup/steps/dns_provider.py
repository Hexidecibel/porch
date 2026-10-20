"""dns_provider: find who serves the zone, collect API credentials, prove they work.

NS -> provider (dns/detect.py). The token is a secret input: only its ref is
kept (state["secret_refs"]["dns_token"]); name.com also needs the account
username (a plain input). verify == provider.check(zone), so --adopt and
doctor prove the stored credentials still work. Nothing to roll back."""

from ..dnsq import DNSError
from ..dns import detect as _detect
from ..dns import zone as _zone
from ..dns.base import ProviderError, provider_class, provider_names
from ..engine import Action, Check, Input, Step, StepError

ORDER = 60


def _detection(ctx, network=True):
    """Detection from the zone's NS. With network=False (input defaults: the
    engine computes them before preflight, also for --non-interactive checks)
    only facts the domain step already recorded are used."""
    ns = ctx.facts.get("ns")
    if not ns:
        if not network:
            return None
        try:
            _z, ns = _zone.zone_info(ctx)
        except DNSError:
            return None
    try:
        return _detect.detect(ns, available=set(provider_names()))
    except Exception:  # noqa: BLE001
        return None


def _default_provider(ctx):
    """Detected provider; None (so --dns-provider is required) when the NS are
    not known yet and nobody is at the terminal to wait for a lookup."""
    d = _detection(ctx, network=bool(getattr(ctx.io, "interactive", False)))
    return d.provider if d else None


def _choices(ctx):
    return sorted(provider_names())


PROVIDER_INPUT = Input(
    "dns_provider", "choice", "DNS provider for your domain", default=_default_provider,
    choices=_choices, flag="--dns-provider",
    help="who runs your domain's DNS (detected from its NS records); manual = you add records by hand")
USERNAME_INPUT = Input(
    "dns_username", "text", "DNS provider account username", flag="--dns-username",
    required=False, help="name.com: your account username (the API token is separate)")
TOKEN_INPUT = Input(
    "dns_token", "secret", "DNS provider API token", flag="--dns-token-ref", env="PORCH_DNS_TOKEN",
    help="Cloudflare: a token with Zone:DNS:Edit on the zone; name.com: an API token")


class DnsProviderStep(Step):
    id = "dns_provider"
    title = "DNS provider"
    requires = ("domain",)
    INPUTS = (PROVIDER_INPUT, USERNAME_INPUT, TOKEN_INPUT)

    def _guess(self, ctx):
        stored = ctx.input("dns_provider")
        answers = getattr(ctx.io, "answers", None) or {}
        return answers.get("dns_provider") or stored or _default_provider(ctx)

    def inputs(self, ctx):
        out = [PROVIDER_INPUT]
        guess = self._guess(ctx)
        cls = provider_class(guess) if guess else None
        need = getattr(cls, "CREDENTIALS", ("token",)) if cls is not None else ("token",)
        if "username" in need:
            out.append(Input(USERNAME_INPUT.name, "text", USERNAME_INPUT.prompt,
                             flag=USERNAME_INPUT.flag, required=True, help=USERNAME_INPUT.help))
        if "token" in need:
            out.append(TOKEN_INPUT)
        return out

    def _checks_zone(self, ctx):
        try:
            zone, ns = _zone.zone_info(ctx)
        except DNSError as e:
            return None, [Check(False, "dns.zone", f"cannot find the DNS zone of {ctx.cfg.root}: {e}",
                                "is the domain registered, and are its NS records set at the registrar?")]
        return zone, [Check(True, "dns.zone", f"zone {zone}, served by {', '.join(ns)}")]

    def preflight(self, ctx):
        zone, checks = self._checks_zone(ctx)
        if zone is None:
            return checks
        name = ctx.input("dns_provider")
        if provider_class(name) is None:
            checks.append(Check(False, "dns.unknown", f"no DNS provider called {name!r}",
                                "choose one of: " + ", ".join(_choices(ctx))))
            return checks
        d = _detection(ctx)
        if d and d.supported and d.provider != name and name != "manual":
            ctx.log(f"the zone's name servers belong to {d.title}, not {name}: records made "
                    f"there will not be served until the NS change at the registrar", level="warn")
        if d and not d.supported and name == "manual" and d.lexicon:
            ctx.log(f"{zone} is on {d.title}; porch has no API client for it yet, so DNS "
                    "records are added by hand", level="info")
        return checks

    def plan(self, ctx):
        zone = ctx.facts.get("zone_apex") or ctx.cfg.root
        name = ctx.input("dns_provider")
        if name == "manual":
            return [Action("dns.manual", zone, "you will add the records at your DNS host")]
        return [Action("dns.check", f"{name} {zone}", "list the zone with the API token (read-only)")]

    def _check(self, ctx):
        zone, ns = _zone.zone_info(ctx)
        name = ctx.input("dns_provider")
        p = _zone.provider(ctx, name)
        p.check(zone)
        return {"provider": name, "zone": zone, "ns": ns,
                "manual": bool(getattr(p, "MANUAL", False))}

    def apply(self, ctx):
        try:
            return self._check(ctx)
        except ProviderError as e:
            raise StepError(e.code, e.message, e.hint) from None
        except DNSError as e:
            raise StepError("dns.zone", str(e), "check the domain's NS records") from None

    def verify(self, ctx):
        try:
            out = self._check(ctx)
        except ProviderError as e:
            return [Check(False, e.code, e.message, e.hint)]
        except DNSError as e:
            return [Check(False, "dns.zone", str(e), "check the domain's NS records")]
        if out["manual"]:
            return [Check(True, "dns.provider", f"manual DNS for {out['zone']}")]
        return [Check(True, "dns.provider", f"{out['provider']} API can read {out['zone']}")]

    def rollback(self, ctx, outputs):
        for e in ctx.undo_entries():
            ctx.drop_undo(e)


STEP = DnsProviderStep()

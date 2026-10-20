"""certificate: one Let's Encrypt certificate for every porch name, via DNS-01.

certbot runs unprivileged (acme.py: --config-dir/--work-dir/--logs-dir under
~/.local/share/porch/acme) with bin/porch-acme-hook as its manual hook and
bin/porch-cert-deploy as its deploy hook, which writes the HAProxy combined
PEM to ~/.local/share/porch/certs/porch-<root>.pem. A staging `--dry-run`
runs first, so a broken hook or token never burns a production rate limit.

verify: the lineage's certificate covers every desired name with more than
20 days left and the combined PEM exists. In adopt mode (this box keeps its
own /etc/letsencrypt certs) it checks what HAProxy actually serves for each
name at 127.0.0.1:443 instead. Rollback removes the combined PEM it wrote and
keeps the Let's Encrypt lineage (no revoke).
"""

import os

from .. import acme
from ..dns import zone as _zone
from ..engine import Action, Check, Input, Step, StepError

ORDER = 80

EMAIL_INPUT = Input("acme_email", "text", "Email for Let's Encrypt expiry notices (blank: none)",
                    flag="--acme-email", required=False,
                    validate=lambda v: None if not v or ("@" in v and " " not in v.strip())
                    else "not an email address")
STAGING_INPUT = Input("acme_staging", "bool", "Use the Let's Encrypt staging CA (untrusted test cert)?",
                      default=False, flag="--acme-staging")


def domains(ctx):
    return _zone.desired_hosts(ctx)


def cert_name(ctx):
    return acme.cert_name_for(ctx.cfg.root)


class CertificateStep(Step):
    id = "certificate"
    title = "TLS certificate"
    requires = ("dns_provider", "dns_records")
    INPUTS = (EMAIL_INPUT, STAGING_INPUT)

    def _base(self, ctx):
        return acme.acme_dir(ctx.env)

    def _env(self, ctx):
        return acme.hook_env(ctx.env, ctx.data_dir, ctx.secrets.file_root)

    def _lineage(self, ctx):
        return acme.lineage(self._base(ctx), cert_name(ctx))

    def _pem(self, ctx):
        return acme.combined_pem_path(cert_name(ctx), ctx.env)

    def _probe(self, ctx):
        return getattr(ctx, "tls_probe", None) or acme.served_pem

    def preflight(self, ctx):
        checks = []
        try:
            v = acme.version_check(ctx.run)
            checks.append(Check(True, "cert.certbot", "certbot " + ".".join(map(str, v))))
        except acme.AcmeError as e:
            return [Check(False, e.code, e.message, e.hint)]
        r = ctx.run.run(["openssl", "version"], mutating=False, timeout=30)
        if r.returncode != 0:
            return checks + [Check(False, "cert.openssl", "openssl is not installed",
                                   "sudo apt install openssl")]
        name = _zone.provider_name(ctx)
        if name in (None, "manual"):
            cmd = "certbot certonly --manual --preferred-challenges dns " + " ".join(
                f"-d '{d}'" for d in domains(ctx))
            return checks + [Check(
                False, "cert.manual", "automatic DNS-01 needs a DNS provider API",
                "use --dns-provider cloudflare|namecom, or run certbot yourself: " + cmd)]
        checks.append(Check(True, "cert.domains", ", ".join(domains(ctx))))
        return checks

    def plan(self, ctx):
        name, base = cert_name(ctx), self._base(ctx)
        ds = domains(ctx)
        if self._lineage_ok(ctx)[0]:
            return [Action("cert.keep", name, "valid certificate already covers every name")]
        return [Action("acme.dry_run", name, "staging --dry-run for " + " ".join(ds)),
                Action("acme.issue", name, ("staging " if ctx.input("acme_staging") else "")
                       + f"certbot certonly (config dir {base})"),
                Action("file.write", self._pem(ctx), "combined PEM via bin/porch-cert-deploy")]

    # ---- inspection -------------------------------------------------------------
    def _lineage_info(self, ctx):
        pem = acme.read_cert_file(self._lineage(ctx)["fullchain"])
        if pem is None:
            return None
        return acme.inspect_pem(ctx.run, pem)

    def _lineage_ok(self, ctx):
        """(ok, info, problems) for the porch lineage."""
        try:
            info = self._lineage_info(ctx)
        except acme.AcmeError as e:
            return False, None, [e.message]
        if info is None:
            return False, None, ["no porch certificate issued yet"]
        problems = []
        missing = [d for d in domains(ctx) if not info.covers(d)]
        if missing:
            problems.append("does not cover " + ", ".join(missing))
        left = info.days_left(ctx.clock())
        if left is None or left <= acme.RENEW_DAYS:
            problems.append(f"expires in {0 if left is None else int(left)} days")
        return not problems, info, problems

    # ---- apply ------------------------------------------------------------------
    def _certbot(self, ctx, argv, what):
        # Re-runs certbot while Let's Encrypt is only busy; a real rate limit
        # stops at once with its retry-after date (acme.run_certbot).
        try:
            r = acme.run_certbot(ctx.run, argv, env=self._env(ctx), timeout=1800,
                                 sleep=ctx.sleep, log=lambda m: ctx.log(m, "warn"))
        except acme.AcmeError as e:
            raise StepError(e.code, e.message, e.hint) from None
        if r.returncode != 0:
            raise StepError(f"cert.{what}", f"certbot {what.replace('_', ' ')} failed: "
                            + acme.tail(r.stderr or r.stdout, 4),
                            f"details: {os.path.join(self._base(ctx), 'logs', 'letsencrypt.log')}")
        return r

    def apply(self, ctx):
        name, base = cert_name(ctx), self._base(ctx)
        ds = domains(ctx)
        pem_path = self._pem(ctx)
        ok, info, _p = self._lineage_ok(ctx)
        email = ctx.input("acme_email") or None
        staging = bool(ctx.input("acme_staging", False))
        if not ok:
            for d in ("config", "work", "logs"):
                os.makedirs(os.path.join(base, d), mode=0o700, exist_ok=True)
            self._certbot(ctx, acme.certonly_argv(ds, name, base=base, repo_dir=ctx.repo_dir,
                                                  email=email, dry_run=True), "dry_run")
            ctx.record_undo("cert.remove_pem", path=pem_path)
            self._certbot(ctx, acme.certonly_argv(ds, name, base=base, repo_dir=ctx.repo_dir,
                                                  email=email, staging=staging), "issue")
            ok, info, problems = self._lineage_ok(ctx)
            if info is None:
                raise StepError("cert.issue", "certbot finished but left no certificate in "
                                + self._lineage(ctx)["live"])
        if not os.path.exists(pem_path):
            # certbot skips the deploy hook when it kept a still-valid cert
            ctx.record_undo("cert.remove_pem", path=pem_path)
            env = dict(self._env(ctx), RENEWED_LINEAGE=self._lineage(ctx)["live"])
            r = ctx.run.run([os.path.join(ctx.repo_dir, "bin", "porch-cert-deploy")], env=env,
                            timeout=120)
            if r.returncode != 0:
                raise StepError("cert.deploy", "porch-cert-deploy failed: " + acme.tail(r.stderr, 3),
                                "the sudoers line for `systemctl reload haproxy` may be missing")
        return {"cert_name": name, "domains": ds, "pem": pem_path,
                "sans": list(info.sans) if info else [],
                "not_after": acme.utc_iso(info.not_after) if info else None,
                "staging": staging}

    # ---- verify -------------------------------------------------------------------
    def verify(self, ctx):
        if ctx.adopt and acme.read_cert_file(self._lineage(ctx)["fullchain"]) is None:
            return self._verify_served(ctx)
        ok, info, problems = self._lineage_ok(ctx)
        if not ok:
            return [Check(False, "cert.lineage", f"{cert_name(ctx)}: " + "; ".join(problems),
                          "porch cert issue")]
        pem = self._pem(ctx)
        if not os.path.exists(pem):
            return [Check(False, "cert.pem", f"combined PEM {pem} is missing",
                          "porch cert issue (re-runs the deploy hook)")]
        if os.stat(pem).st_mode & 0o077:
            return [Check(False, "cert.pem_mode", f"{pem} is readable by other users",
                          f"chmod 600 {pem}")]
        left = int(info.days_left(ctx.clock()))
        return [Check(True, "cert.valid", f"{cert_name(ctx)} covers {len(domains(ctx))} name(s), "
                      f"{left} days left")]

    def _verify_served(self, ctx):
        """Adopt: whatever certificate HAProxy serves for each name must cover
        it, be trusted, and have more than 20 days left."""
        probe = self._probe(ctx)
        now = ctx.clock()
        lows, bad = [], []
        for d in domains(ctx):
            host = d if not d.startswith("*.") else "porch-check." + d[2:]
            try:
                pem, trusted = probe(host)
                info = acme.inspect_pem(ctx.run, pem)
            except (OSError, acme.AcmeError) as e:
                bad.append(f"{host}: {getattr(e, 'message', None) or e}")
                continue
            left = info.days_left(now)
            if not info.covers(host):
                bad.append(f"{host}: served certificate is for {', '.join(info.sans) or info.subject}")
            elif not trusted and not ctx.input("acme_staging"):
                bad.append(f"{host}: served certificate is not trusted")
            elif left is None or left <= acme.RENEW_DAYS:
                bad.append(f"{host}: expires in {0 if left is None else int(left)} days")
            else:
                lows.append(int(left))
        if bad:
            return [Check(False, "cert.served", "; ".join(bad[:4]),
                          "renew the certificate (porch cert issue, or the box's own renew-cert)")]
        return [Check(True, "cert.served", f"HAProxy serves valid certificates for "
                      f"{len(lows)} name(s); soonest expiry in {min(lows)} days")]

    def undo(self, ctx, entry):
        if entry.get("kind") == "cert.remove_pem":
            try:
                os.unlink(entry["path"])
            except FileNotFoundError:
                pass
            return
        super().undo(ctx, entry)


STEP = CertificateStep()

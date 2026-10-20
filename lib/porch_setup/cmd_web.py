"""`porch setup --web` / `porch web`: run the setup wizard in a browser.

    sudo bin/porch setup --web                    # fresh VPS: IP certificate, wizard on :8443
    bin/porch setup --web --tls self-signed       # 127.0.0.1:8443, use ssh -L
    bin/porch setup --web --cert C --key K --bind 0.0.0.0 --port 8443 --host setup.example.com

TLS, in order: --cert/--key; the domain certificate once the setup's
certificate step is done (HAProxy owns :80 after the haproxy step, so no
new IP certificate is possible: serve $PORCH_CERT_DIR/porch-<root>.pem as
<auth_host>:8443 instead); an IP certificate from Let's Encrypt (needs
root to bind :80 for the http-01 challenge, a public IP and port 80 reachable; `--tls ip`);
otherwise a self-signed certificate whose SHA-256 fingerprint is printed.
Started with sudo, the wizard binds its ports and then drops to SUDO_UID /
SUDO_GID before doing anything else (certbot and the engine never run as
root). Setup step flags (--domain, --connection, ...) prefill answers.
"""

import argparse
import ipaddress
import json
import os
import sys

from . import acme as _acme
from . import registry
from . import web as _web
from .runner import Runner

DEFAULT_SELF_PORT = 8443


def parser():
    p = argparse.ArgumentParser(prog="porch setup --web",
                                description="Run the porch setup wizard in a browser.")
    p.add_argument("--tls", choices=("auto", "ip", "self-signed"), default="auto",
                   help="certificate source (default: --cert/--key, else ip when root with a "
                        "public IP, else self-signed)")
    p.add_argument("--cert", help="PEM certificate (chain) to serve")
    p.add_argument("--key", help="PEM private key for --cert")
    p.add_argument("--ip", help="public IP for the IP certificate (default: this host's public IPv4)")
    p.add_argument("--staging", action="store_true",
                   help="IP certificate from Let's Encrypt staging (browsers will warn)")
    p.add_argument("--email", help="ACME account email (default: none)")
    p.add_argument("--bind", help="listen address (default 0.0.0.0 for an IP or given cert, "
                                  "127.0.0.1 for self-signed)")
    p.add_argument("--port", type=int, help=f"HTTPS port (default {DEFAULT_SELF_PORT}; never 443, which the haproxy step needs)")
    p.add_argument("--http-port", type=int, default=80, help="ACME http-01 port (default 80)")
    p.add_argument("--host", help="host name to print in the URL")
    p.add_argument("--idle-timeout", type=int, default=_web.IDLE_TIMEOUT,
                   help="exit after this many seconds without a request (default 3600)")
    p.add_argument("--no-qr", action="store_true", help="do not print a QR code")
    return p


def _preset(rest, steps):
    """Answers from setup step flags (`porch setup --web --domain x ...`)."""
    from . import cli as _cli
    sp = _cli.setup_parser(steps)
    args, unknown = sp.parse_known_args(rest)
    if unknown:
        raise SystemExit(f"porch setup --web: unknown arguments: {' '.join(unknown)}")
    out = {}
    for inp in _cli._flag_inputs(steps):
        v = getattr(args, _cli._dest(inp))
        if v is not None:
            out[inp.name] = v
    return out


def _host_ip(probe_fn=None):
    """First public IPv4 on an interface, or None. (host_public_ipv4 returns
    a list; the wizard needs one address.)"""
    if probe_fn is None:
        from .net import probe as _probe
        probe_fn = _probe.host_public_ipv4
    ips = probe_fn() or []
    return ips[0] if ips else None


def _target_env(env, os_mod=os, pwd_mod=None):
    """env as the user the wizard will run as: under sudo, HOME is the sudo
    user's (the cert dir defaults to ~/.local/share/porch/certs)."""
    if os_mod.geteuid() != 0 or not env.get("SUDO_UID", "").isdigit():
        return env
    import pwd as _pwd
    pwd_mod = pwd_mod or _pwd
    try:
        home = pwd_mod.getpwuid(int(env["SUDO_UID"])).pw_dir
    except KeyError:
        return env
    return dict(env, HOME=home)


def domain_cert(env, ctx_kwargs=None, os_mod=os, pwd_mod=None):
    """(pem, auth_host) when the setup state says the certificate step is
    done and its combined PEM exists, else None. Read-only (runs before the
    privilege drop: only stats the PEM, never opens it as root)."""
    kw = ctx_kwargs or {}
    tenv = _target_env(env, os_mod, pwd_mod)
    from . import state as _state
    data_dir = kw.get("data_dir") or _state.default_data_dir(tenv)
    try:
        with open(os.path.join(data_dir, _state.STATE_NAME)) as f:
            st = json.load(f)
        status = ((st.get("steps") or {}).get("certificate") or {}).get("status")
    except (OSError, ValueError, AttributeError):
        return None
    if status not in ("done", "adopted"):
        return None
    cfg = kw.get("cfg")
    if cfg is None:
        import porch_config
        p = tenv.get("PORCH_CONFIG")
        path = p if p and p != "none" else porch_config.DEFAULT_PATH
        try:
            cfg = porch_config.load(path=path if os.path.exists(path) else None,
                                    env={k: v for k, v in tenv.items() if k != "PORCH_CONFIG"}
                                    | ({} if os.path.exists(path) else {"PORCH_CONFIG": "none"}))
        except Exception:  # noqa: BLE001 - a broken config just means "no domain cert"
            return None
    pem = _acme.combined_pem_path(_acme.cert_name_for(cfg.root), tenv)
    return (pem, cfg.auth_host) if os.path.isfile(pem) else None


def _url_host(h):
    try:
        if ipaddress.ip_address(h).version == 6:
            return f"[{h}]"
    except ValueError:
        pass
    return h


def banner(url, *, fingerprint=None, ssh_port=None, qr=True, out=None, note=""):
    out = out or sys.stderr
    p = lambda s="": print(s, file=out, flush=True)  # noqa: E731
    p()
    p("Porch setup wizard")
    if note:
        p(note)
    if qr:
        art = _web.qr_text(url)
        if art:
            p(art)
    p("Open this link (it works once; keep it private):")
    p(f"    {url}")
    if fingerprint:
        p("The certificate is self-signed. Your browser will warn; check that its SHA-256")
        p("fingerprint is exactly:")
        p(f"    {fingerprint}")
    if ssh_port:
        p("From your own computer, forward the port first:")
        p(f"    ssh -L {ssh_port}:127.0.0.1:{ssh_port} <this-server>")
    p("The wizard exits after an hour idle, or when setup is done. Ctrl-C stops it.")
    p()


def _acme_kwargs(ctx_kwargs, runner, env):
    kw = dict(ctx_kwargs or {})
    kw.update(runner=runner, env=env, log=False)
    return kw


def main(argv, *, steps=None, env=None, out=None, runner=None, os_mod=os, serve=True,
         ctx_kwargs=None, host_ip=None, pwd_mod=None):
    env = os.environ if env is None else env
    out = out or sys.stderr
    args, rest = parser().parse_known_args(argv)
    steps = registry.steps() if steps is None else steps
    try:
        preset = _preset(rest, steps)
    except SystemExit as e:
        print(e, file=out)
        return 2
    if bool(args.cert) != bool(args.key):
        print("porch setup --web: --cert and --key go together", file=out)
        return 2
    root = os_mod.geteuid() == 0
    tls = args.tls
    ip = args.ip
    host_default = None
    if tls == "auto" and not args.cert:
        dc = domain_cert(env, ctx_kwargs, os_mod, pwd_mod)
        if dc:
            args.cert = args.key = dc[0]
            host_default = dc[1]
            print(f"Setup has a domain certificate: serving it as {dc[1]}", file=out)
    if tls == "auto":
        if args.cert:
            tls = "files"
        else:
            if ip is None and root:
                ip = _host_ip(host_ip)
            tls = "ip" if (root and ip) else "self-signed"
    elif args.cert:
        print("porch setup --web: --cert/--key replace --tls", file=out)
        return 2
    if tls == "ip" and not ip:
        ip = _host_ip(host_ip)
        if not ip:
            print("porch setup --web: no public IPv4 on this host; pass --ip", file=out)
            return 2
    bind = args.bind or ("127.0.0.1" if tls == "self-signed" else ("::" if ip and ":" in ip else "0.0.0.0"))
    # Not 443 even with an IP certificate: the setup it drives installs
    # HAProxy there, and preflight refuses while anything else holds it.
    port = args.port if args.port is not None else DEFAULT_SELF_PORT
    if not root and (0 < port < 1024 or (tls == "ip" and 0 < args.http_port < 1024)):
        print(f"porch setup --web: ports below 1024 need root; run it with sudo "
              f"(it drops to your user right after binding), or pass --port {DEFAULT_SELF_PORT} "
              "--tls self-signed", file=out)
        return 2

    # 1) bind (as root if need be), 2) drop privileges, 3) everything else.
    acme_srv = webroot = None
    try:
        srv = _web.bind_tls((bind, port))
        port = srv.server_address[1]
        if tls == "ip":
            acme_srv = _web.bind_acme((bind, args.http_port), None)
    except OSError as e:
        print(f"porch setup --web: cannot listen on {bind}:{port}: {e.strerror or e}", file=out)
        return 2
    try:
        _web.drop_privileges(env, os_mod=os_mod)
    except _web.WebError as e:
        print(f"porch setup --web: {e}", file=out)
        srv.server_close()
        if acme_srv is not None:
            acme_srv.server_close()
        _web.rmtree_quiet(webroot)
        return 2

    if acme_srv is not None:
        # Made after the drop: certbot's hook runs as the sudo user and must be
        # able to write the token here (a root-owned dir made it fail on a VPS).
        webroot = _web.private_tempdir("porch-acme-")
        os.chmod(webroot, 0o755)     # the hook (same user) writes, the server reads
        acme_srv.webroot = webroot
    runner = runner or Runner()
    tmp = _web.private_tempdir()
    fp = None
    host = args.host or host_default
    note = ""
    issued_ip = served = False
    try:
        cert, key = args.cert, args.key
        if tls == "ip":
            import threading
            t = threading.Thread(target=acme_srv.serve_forever, daemon=True)
            t.start()
            from .engine import make_context
            ctx = make_context(**_acme_kwargs(ctx_kwargs, runner, env))
            try:
                print(f"Requesting a Let's Encrypt certificate for {ip} (http-01 on port "
                      f"{args.http_port}{', staging' if args.staging else ''})...", file=out)
                lin = _acme.issue_ip_cert(ctx, ip, webroot=webroot, staging=args.staging,
                                          email=args.email)
                cert, key = lin["fullchain"], lin["privkey"]
                issued_ip = True
                host = host or ip
            except _acme.AcmeError as e:
                print(f"porch setup --web: IP certificate failed: {e.message}"
                      + (f" ({e.hint})" if e.hint else ""), file=out)
                print("Falling back to a self-signed certificate.", file=out)
                tls = "self-signed"
            finally:
                acme_srv.shutdown()
                acme_srv.server_close()
        if tls == "self-signed":
            cert, key, fp = _web.make_self_signed(runner, os.path.join(tmp, "tls"),
                                                  extra_ips=[ip] if ip else [])
            if host is None:
                host = "localhost" if bind in ("127.0.0.1", "::1") else (ip or bind)
        host = host or (ip or bind)
        srv.sslctx = _web.server_context(cert, key)
        wiz = _web.Wizard(steps, ctx_kwargs=ctx_kwargs, env=env, preset=preset,
                          idle_timeout=args.idle_timeout, host_label=host)
        url = f"https://{_url_host(host)}{'' if port == 443 else ':' + str(port)}/#k={wiz.key}"
        if issued_ip and args.staging:
            note = "(staging certificate: your browser will warn)"
        banner(url, fingerprint=fp, ssh_port=port if (tls == "self-signed" and bind in
                                                       ("127.0.0.1", "::1")) else None,
               qr=not args.no_qr, out=out, note=note)
        if not serve:
            return 0
        served = True
        reason = wiz.serve(srv)
        print(f"porch setup --web: exiting ({reason})", file=out)
        return 0
    except _web.WebError as e:
        print(f"porch setup --web: {e}", file=out)
        return 2
    finally:
        if not served:
            srv.server_close()
        if issued_ip:
            from .engine import make_context
            _acme.delete_ip_cert(make_context(**_acme_kwargs(ctx_kwargs, runner, env)))
        _web.rmtree_quiet(tmp)
        _web.rmtree_quiet(webroot)

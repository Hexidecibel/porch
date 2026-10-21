#!/bin/sh
#
# Porch server installer: from a fresh Ubuntu 22.04/24.04 or Debian 12/13 VPS to
# the Porch setup wizard in one line.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/Hexidecibel/porch/main/site/porch.sh | sudo sh
#   curl -sSL https://raw.githubusercontent.com/Hexidecibel/porch/main/site/porch.sh | sudo sh -s -- --domain example.com
#   curl -sSL https://raw.githubusercontent.com/Hexidecibel/porch/main/site/porch.sh | sudo sh -s -- --check   # read-only report first
#   sudo sh porch.sh --url          # show the wizard link again
#
# Flags:
#   --staging          the wizard's own IP certificate comes from Let's Encrypt
#                      staging (browsers warn; spares the rate limits)
#   --domain D         prefill the wizard's domain
#   --dns-provider P   prefill the wizard's DNS provider (cloudflare, namecom, manual)
#   --dir DIR          install location (default: /home/porch/porch)
#   --no-wizard        install everything but do not start the wizard
#   --url              only print the running wizard's link (re-reads its log)
#   --check            read-only: report everything the installer would change
#                      (packages, user, sudoers, units, firewall, ports, dirs)
#                      and anything that would stop it; changes nothing, exits 0
#   -h, --help         this help
#
# Environment:
#   PORCH_TARBALL         code tarball URL (default: the latest GitHub release,
#                         https://github.com/Hexidecibel/porch/releases/latest/download/porch.tar.gz;
#                         a Porch landing page's copy of this script defaults to that
#                         box's own /porch.tar.gz; file:// works). Its sha256 is
#                         read from "$PORCH_TARBALL.sha256". The tarball holds one
#                         top-level directory (porch/; cush-tools/ in older ones) with bin/porch.
#   PORCH_TARBALL_SHA256  expected sha256 of the tarball (skips the .sha256 download)
#   PORCH_USER            service account (default: porch)
#   PORCH_DIR             same as --dir
#   PORCH_WIZARD_TIMEOUT  seconds to wait for the wizard's link (default 180)
#   PORCH_INSTALL_DRY_RUN=1  print every command that changes the system instead
#                         of running it; skips the root and OS checks
#
# Before changing anything it refuses a box where Porch would clash with
# something else: ports 80/443 or Porch's internal ports (7000 7080 7500 9411
# 9471 9473 9512 9785, the wizard's 8443) held by another program, a docker
# container publishing 80/443, an existing `porch` user it did not create
# (marker: ~porch/.porch-installer), or systemd units named porch-* it did
# not make. It warns about nginx/apache/caddy, an HAProxy config that already
# serves sites (porch setup refuses to replace it) and certificates in
# /etc/letsencrypt (left alone: Porch's certbot keeps its own directory).
#
# What it does: apt installs haproxy, python3 (+ qrcode, cryptography for
# `porch share --e2e`), openssl, curl and snapd; snap
# installs certbot (the apt one cannot issue IP certificates); creates the
# `porch` user with passwordless sudo (porch setup installs HAProxy, systemd
# units, certificates and firewall rules through `sudo -n`); downloads Porch
# (sha256-checked) and frp 0.67.0 (sha256-pinned); opens 80 and 8443 in an
# active ufw; starts `porch setup --web` as the systemd unit porch-wizard and
# prints its one-time link. Re-running upgrades the code in place and leaves
# data/, config/porch.toml, config/frps.toml and logs/ alone.
#
# The whole script is one function called on the last line, so `curl | sh`
# never runs a half-downloaded script and nothing it runs can eat the rest
# of it from stdin.

main() {
set -eu
umask 022

# The repo copy installs the latest GitHub release; bin/deploy renders this
# file (lib/porch_config.py site_render) so a Porch landing page's copy
# installs that box's own tarball. Set PORCH_TARBALL to override either.
PORCH_TARBALL="${PORCH_TARBALL:-https://github.com/Hexidecibel/porch/releases/latest/download/porch.tar.gz}"
PORCH_TARBALL_SHA256="${PORCH_TARBALL_SHA256:-}"
PORCH_USER="${PORCH_USER:-porch}"
PORCH_DIR="${PORCH_DIR:-}"
PORCH_WIZARD_TIMEOUT="${PORCH_WIZARD_TIMEOUT:-180}"
DRY="${PORCH_INSTALL_DRY_RUN:-0}"
# Read-only checks look under ROOT (tests point it at a fake tree; dry runs only).
ROOT=""
[ "$DRY" = 1 ] && ROOT="${PORCH_INSTALL_ROOT:-}"
# Porch's own listeners (loopback): frps 7000 (bind) 7080 (vhost) 7500
# (dashboard), shortener 9411, status 9471, landing 9473, auth 9512, ACME
# http-01 9785. tests/test_porch_installer.py checks this against render.PORTS.
INTERNAL_PORTS="7000 7080 7500 9411 9471 9473 9512 9785"
MARKER=.porch-installer
CHECK=0 PROBLEMS=0
INSTALLER_URL="https://raw.githubusercontent.com/Hexidecibel/porch/main/site/porch.sh"
UNIT=porch-wizard
WIZARD_PORT=8443
WIZARD_UFW=0   # 1 once open_firewall added the 8443 rule (the wizard unit removes it)
FRP_VERSION=0.67.0
FRP_SHA256_AMD64=f8629ca7ca56b8e7e7a9903779b8d5c47c56ad1b75b99b2d7138477acc4c7105
FRP_SHA256_ARM64=0e9683226acdcbbb2ac8d073f35ba8be2a8b1e7584684d2073f39d337ebd6de7

if [ -t 1 ]; then
    ESC=$(printf '\033')
    C_RESET="${ESC}[0m" C_DIM="${ESC}[2m" C_BOLD="${ESC}[1m" C_GREEN="${ESC}[32m"
    C_RED="${ESC}[31m" C_YELLOW="${ESC}[33m" C_CYAN="${ESC}[36m"
else
    C_RESET="" C_DIM="" C_BOLD="" C_GREEN="" C_RED="" C_YELLOW="" C_CYAN=""
fi

STAGING=0 NO_WIZARD=0 URL_ONLY=0 DOMAIN="" DNS_PROVIDER=""
while [ $# -gt 0 ]; do
    case "$1" in
        --staging) STAGING=1 ;;
        --no-wizard) NO_WIZARD=1 ;;
        --url) URL_ONLY=1 ;;
        --check) CHECK=1 ;;
        --domain) [ $# -ge 2 ] || die "--domain needs a value"; DOMAIN=$2; shift ;;
        --domain=*) DOMAIN=${1#*=} ;;
        --dns-provider) [ $# -ge 2 ] || die "--dns-provider needs a value"; DNS_PROVIDER=$2; shift ;;
        --dns-provider=*) DNS_PROVIDER=${1#*=} ;;
        --dir) [ $# -ge 2 ] || die "--dir needs a value"; PORCH_DIR=$2; shift ;;
        --dir=*) PORCH_DIR=${1#*=} ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1 (see --help)" ;;
    esac
    shift
done

DOMAIN=$(printf '%s' "$DOMAIN" | tr 'A-Z' 'a-z')
if [ -n "$DOMAIN" ] && ! printf '%s\n' "$DOMAIN" | grep -Eq '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'; then
    die "not a domain name: $DOMAIN"
fi
if [ -n "$DNS_PROVIDER" ] && ! printf '%s\n' "$DNS_PROVIDER" | grep -Eq '^[a-z0-9]{1,32}$'; then
    die "not a DNS provider name: $DNS_PROVIDER"
fi
printf '%s\n' "$PORCH_USER" | grep -Eq '^[a-z_][a-z0-9_-]{0,31}$' || die "bad PORCH_USER: $PORCH_USER"
case "$PORCH_WIZARD_TIMEOUT" in ''|*[!0-9]*) die "PORCH_WIZARD_TIMEOUT must be a number of seconds" ;; esac

PORCH_HOME=$(getent passwd "$PORCH_USER" 2>/dev/null | cut -d: -f6 || true)
[ -n "$PORCH_HOME" ] || PORCH_HOME="/home/$PORCH_USER"
[ -n "$PORCH_DIR" ] || PORCH_DIR="$PORCH_HOME/porch"
case "$PORCH_DIR" in /*) ;; *) die "--dir must be an absolute path" ;; esac
case "$PORCH_DIR" in *[!A-Za-z0-9/._-]*) die "--dir may only use letters, digits and / . _ -" ;; esac
WIZARD_LOG="$PORCH_HOME/wizard.log"

if [ "$URL_ONLY" = 1 ]; then
    [ "$DRY" = 1 ] || [ "$(id -u)" = 0 ] || die "run it as root: sudo sh porch.sh --url"
    show_url || die "no wizard link in $WIZARD_LOG (is it running? systemctl status $UNIT)"
    exit 0
fi

if [ "$CHECK" = 1 ]; then
    report
    exit 0
fi

printf '%sPorch server installer%s\n' "$C_BOLD" "$C_RESET"
[ "$DRY" = 1 ] && warn "dry run (PORCH_INSTALL_DRY_RUN=1): printing commands, changing nothing"

check_system
check_ports
check_existing
sudoers_warning
install_packages
install_certbot
make_user
install_code
install_frp
open_firewall

if [ "$NO_WIZARD" = 1 ]; then
    echo
    ok "Porch is installed in $PORCH_DIR (wizard not started: --no-wizard)"
    printf '  start it later:  %scurl -sSL %s | sudo sh%s\n' "$C_DIM" "$INSTALLER_URL" "$C_RESET"
    printf '  or set up in the terminal:  %ssudo -u %s -i sh -c "cd %s && bin/porch setup"%s\n' \
        "$C_DIM" "$PORCH_USER" "$PORCH_DIR" "$C_RESET"
    exit 0
fi

start_wizard
wait_for_url
}

# ---------- output ----------------------------------------------------------

step() { printf '%s->%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
ok()   { printf '%sok%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s!%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die()  { printf '%sx%s %s\n' "${C_RED:-}" "${C_RESET:-}" "$*" >&2; exit 1; }
# refuse MSG: stop before anything changed; under --check only count and report it.
refuse() {
    if [ "$CHECK" = 1 ]; then
        PROBLEMS=$((PROBLEMS + 1))
        printf '%sx would stop here:%s %s\n' "${C_RED:-}" "${C_RESET:-}" "$*"
    else
        die "$*"
    fi
}

usage() {
    if [ -f "$0" ] && head -n 3 "$0" | grep -q 'Porch server installer'; then
        sed -n '3,/^[^#]/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
        return 0
    fi
    echo "usage: curl -sSL $INSTALLER_URL | sudo sh -s -- [--staging] [--domain D] [--dns-provider P] [--dir DIR] [--no-wizard] [--url] [--check]"
}

have() { command -v "$1" >/dev/null 2>&1; }

# run CMD ARGS...: run it, or in a dry run print it.
run() {
    if [ "$DRY" = 1 ]; then
        printf '+ %s\n' "$*"
    else
        "$@"
    fi
}

# run_sh 'shell text': the same for a pipeline or redirection.
run_sh() {
    if [ "$DRY" = 1 ]; then
        printf '+ sh -c %s\n' "$1"
    else
        sh -c "$1"
    fi
}

# ---------- checks ----------------------------------------------------------

check_system() {
    case "$(uname -m)" in
        x86_64|amd64) ARCH=amd64; FRP_SHA=$FRP_SHA256_AMD64 ;;
        aarch64|arm64) ARCH=arm64; FRP_SHA=$FRP_SHA256_ARM64 ;;
        *) refuse "unsupported architecture: $(uname -m) (Porch needs amd64 or arm64)"; ARCH=amd64; FRP_SHA=$FRP_SHA256_AMD64 ;;
    esac
    if [ "$DRY" = 1 ]; then
        step "dry run: skipping the root and OS checks ($ARCH)"
        return 0
    fi
    if [ "$CHECK" = 1 ] && [ "$(id -u)" != 0 ]; then
        warn "not root: the check runs anyway, but names of programs holding ports may be hidden (sudo sh porch.sh --check)"
    elif [ "$(id -u)" != 0 ]; then
        if have sudo; then
            die "run it as root:  curl -sSL $INSTALLER_URL | sudo sh"
        fi
        die "run it as root (log in as root, or install sudo)"
    fi
    have apt-get || refuse "Porch's installer needs a Debian or Ubuntu system (apt-get not found)"
    OS_ID="" OS_VER="" OS_LIKE=""
    if [ -r /etc/os-release ]; then
        OS_ID=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')
        OS_VER=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '"')
        OS_LIKE=$(sed -n 's/^ID_LIKE=//p' /etc/os-release | tr -d '"')
    fi
    case "$OS_ID:$OS_VER" in
        ubuntu:22.04|ubuntu:24.04|debian:12|debian:13) ok "$OS_ID $OS_VER ($ARCH)" ;;
        ubuntu:*|debian:*) warn "$OS_ID $OS_VER is untested (tested: Ubuntu 22.04/24.04, Debian 12/13); continuing" ;;
        *) case " $OS_LIKE " in
               *" debian "*|*" ubuntu "*) warn "${OS_ID:-this system} is untested (Debian-like); continuing" ;;
               *) refuse "unsupported system: ${OS_ID:-unknown} (Porch's installer supports Ubuntu and Debian)" ;;
           esac ;;
    esac
    have systemctl || refuse "systemd is required (systemctl not found)"
}

wizard_active() {
    [ "$DRY" != 1 ] && have systemctl && systemctl is-active --quiet "$UNIT" 2>/dev/null
}

# holders PORT: the `ss` lines (with uid:N) of whatever listens on tcp PORT.
holders() {
    have ss || return 0
    ss -Hltnpe "sport = :$1" 2>/dev/null || true
}

# porch_uid: the porch account's uid, or nothing (no such user).
porch_uid() { id -u "$PORCH_USER" 2>/dev/null || true; }

# ours LINES [NAMES...]: every holder line is ours: the porch account's uid,
# or one of the program NAMES (haproxy, frps).
ours() {
    lines=$1; shift
    uid=$(porch_uid)
    printf '%s\n' "$lines" | while IFS= read -r ln; do
        [ -n "$ln" ] || continue
        [ -n "$uid" ] && case "$ln" in *" uid:$uid "*|*" uid:$uid") continue ;; esac
        ok_name=0
        # the program name (root sees it), else its systemd unit's cgroup
        for n in "$@"; do case "$ln" in *"\"$n\""*|*"/$n.service"*) ok_name=1 ;; esac; done
        [ "$ok_name" = 1 ] && continue
        echo no
    done | grep -q no && return 1
    return 0
}

check_ports() {
    # A previous run's wizard holds :80 (ACME) and :8443: it is replaced anyway.
    WIZ_UP=0
    if wizard_active; then
        WIZ_UP=1
        if [ "$CHECK" = 1 ]; then
            step "the previous setup wizard ($UNIT) is running: it would be stopped and replaced"
        else
            step "stopping the previous setup wizard ($UNIT)"
            run systemctl stop "$UNIT" || true
        fi
    fi
    for port in 80 443; do
        [ "$WIZ_UP" = 1 ] && [ "$CHECK" = 1 ] && [ "$port" = 80 ] && continue
        h=$(holders "$port")
        [ -n "$h" ] || continue
        if ! ours "$h" haproxy; then
            printf '%s\n' "$h" | sed 's/^/    /' >&2
            refuse "port $port is in use by something other than HAProxy (above). Porch needs 80 and 443: stop that service first (e.g. apache2 or nginx)."
        fi
    done
    busy=""
    for port in $INTERNAL_PORTS $WIZARD_PORT; do
        [ "$WIZ_UP" = 1 ] && [ "$CHECK" = 1 ] && [ "$port" = "$WIZARD_PORT" ] && continue
        h=$(holders "$port")
        [ -n "$h" ] || continue
        if ! ours "$h" frps; then
            printf '%s\n' "$h" | sed 's/^/    /' >&2
            busy="$busy $port"
        fi
    done
    if [ -n "$busy" ]; then
        refuse "Porch's internal port(s)$busy are in use by another program (above). Porch's services listen there on 127.0.0.1; stop or move that program first."
    fi
    if have docker; then
        pub=$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -E ":(80|443|7000|$WIZARD_PORT)->" || true)
        if [ -n "$pub" ]; then
            printf '%s\n' "$pub" | sed 's/^/    /' >&2
            refuse "a docker container publishes port 80, 443, 7000 or $WIZARD_PORT (above). Docker's port forwarding bypasses HAProxy; stop it or publish it elsewhere."
        fi
    fi
    [ "$PROBLEMS" = 0 ] && ok "ports 80, 443 and Porch's internal ports are free (or already Porch's)"
    return 0
}

# user_is_ours: the porch account was made by this installer (marker), or is a
# pre-marker install of ours (our sudoers file, our code in its home).
user_is_ours() {
    [ -f "$PORCH_HOME/$MARKER" ] && return 0
    grep -qs '^# Porch (porch.sh)' "$ROOT/etc/sudoers.d/90-porch" && return 0
    [ -x "$PORCH_DIR/bin/porch" ] && [ -f "$PORCH_DIR/lib/porch_setup/engine.py" ] && return 0
    return 1
}

check_existing() {
    if id "$PORCH_USER" >/dev/null 2>&1 && ! user_is_ours; then
        refuse "a user named $PORCH_USER already exists and was not created by Porch (no $PORCH_HOME/$MARKER). Porch gives that account passwordless sudo, so it will not take it over: use another name (PORCH_USER=porchsvc) or remove the account."
    fi
    units=""
    for d in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
        for f in "$ROOT$d"/porch-*; do
            [ -e "$f" ] || continue
            units="$units ${f#"$ROOT"}"
        done
    done
    if [ -n "$units" ]; then
        refuse "systemd units named porch-* already exist and were not made by Porch:$units. Porch's wizard is a transient unit (porch-wizard) and its services are user units of the $PORCH_USER account; rename or remove those first."
    fi
    if [ -f "$ROOT/etc/haproxy/haproxy.cfg" ] && grep -Eq '^[ 	]*(frontend|listen)[ 	]' "$ROOT/etc/haproxy/haproxy.cfg"; then
        warn "/etc/haproxy/haproxy.cfg already serves something (frontend/listen sections). The installer leaves it alone; porch setup's haproxy step refuses to replace a config that serves other sites."
    fi
    certs=""
    for c in "$ROOT"/etc/letsencrypt/live/*/; do
        [ -d "$c" ] || continue
        c=${c%/}; certs="$certs ${c##*/}"
    done
    if [ -n "$certs" ]; then
        warn "existing certificates in /etc/letsencrypt:$certs. Porch leaves them alone: its certbot runs unprivileged in ~$PORCH_USER/.local/share/porch/acme and never renews, revokes or deletes anything in /etc/letsencrypt. (The certbot snap's own renew timer renews /etc/letsencrypt as the apt certbot.timer does.)"
    fi
    if [ -e "$ROOT/usr/local/bin/certbot" ] && [ ! -L "$ROOT/usr/local/bin/certbot" ]; then
        refuse "/usr/local/bin/certbot exists and is not a link: the installer links the certbot snap there. Move it away first."
    fi
    for s in nginx apache2 httpd caddy lighttpd; do
        if have "$s" || [ -d "$ROOT/etc/$s" ]; then
            warn "$s is installed. HAProxy must own ports 80 and 443: $s may stay only on other ports (the port check above stops the install if it holds them now). Keep it from taking them back at boot, e.g. systemctl disable --now $s, or move its listen ports."
        fi
    done
    return 0
}

SUDOERS_LINE='ALL=(ALL) NOPASSWD:ALL'

sudoers_warning() {
    printf '%s! WARNING:%s the %s account gets passwordless sudo for every command\n' "$C_YELLOW$C_BOLD" "$C_RESET" "$PORCH_USER" >&2
    printf '  (/etc/sudoers.d/90-porch: "%s %s"). porch setup installs HAProxy, systemd\n' "$PORCH_USER" "$SUDOERS_LINE" >&2
    printf '  units, certificates and firewall rules through sudo -n, and certificate renewals\n' >&2
    printf '  reload HAProxy through it later. Anything that runs as %s can become root.\n' "$PORCH_USER" >&2
    printf '  The account has no password and no ssh key. Remove the file to take it back.\n' >&2
}

# ---------- check (read-only report) -----------------------------------------

pkg_state() {
    if have dpkg-query && dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; then
        echo "$1 (installed)"
    else
        echo "$1"
    fi
}

report() {
    printf '%sPorch server installer: check%s (read-only; nothing is changed)\n\n' "$C_BOLD" "$C_RESET"
    check_system
    check_ports
    check_existing
    echo
    printf '%sWhat the installer would change%s\n' "$C_BOLD" "$C_RESET"
    pk=""
    for p in haproxy python3 python3-qrcode python3-cryptography openssl curl ca-certificates iproute2 sudo tar gzip snapd; do
        pk="$pk, $(pkg_state "$p")"
    done
    printf '  packages (apt):  %s\n' "${pk#, }"
    printf '  snap:            snapd, certbot (classic); link /usr/local/bin/certbot -> /snap/bin/certbot\n'
    if id "$PORCH_USER" >/dev/null 2>&1; then
        if user_is_ours; then u="exists (Porch's), kept"; else u="exists, NOT Porch's (stops the install)"; fi
    else
        u="create $PORCH_USER (home $PORCH_HOME, no password), marker $PORCH_HOME/$MARKER"
    fi
    printf '  user:            %s\n' "$u"
    printf '  sudoers:         /etc/sudoers.d/90-porch  "%s %s"  (see the warning below)\n' "$PORCH_USER" "$SUDOERS_LINE"
    printf '  linger:          loginctl enable-linger %s (its user services run without a login)\n' "$PORCH_USER"
    if [ -d "$PORCH_DIR" ]; then d="$PORCH_DIR (upgrade in place; data/, config/porch.toml, config/frps.toml, logs/ kept)"; else d="$PORCH_DIR (new)"; fi
    printf '  code:            %s\n' "$d"
    printf '                   from %s (sha256-checked), frp %s into %s/bin\n' "$PORCH_TARBALL" "$FRP_VERSION" "$PORCH_DIR"
    printf '  files:           %s (wizard log, 0600)\n' "$WIZARD_LOG"
    if have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then
        printf '  firewall (ufw):  allow 80/tcp, allow %s/tcp (removed again when the wizard exits)\n' "$WIZARD_PORT"
    else
        printf '  firewall:        nothing now (ufw is not active)\n'
    fi
    printf '  units:           porch-wizard (transient systemd-run unit, runs as %s, stops after setup)\n' "$PORCH_USER"
    printf '  ports:           80 (ACME + then HAProxy), %s (the wizard)\n' "$WIZARD_PORT"
    echo
    printf '%sThen porch setup (in the wizard) would%s\n' "$C_BOLD" "$C_RESET"
    printf '  install HAProxy config (only where HAProxy serves nothing else), open tcp 80/443/7000\n'
    printf '  in ufw/firewalld, add user units porch-{auth,frps,status,shortener,landing} and\n'
    printf '  porch-pocket@pocket, listening on 127.0.0.1:%s, and get a certificate into\n' "$(echo $INTERNAL_PORTS | tr ' ' ',')"
    printf '  ~%s/.local/share/porch (porch setup --rollback undoes its own changes).\n' "$PORCH_USER"
    echo
    sudoers_warning
    echo
    if [ "$PROBLEMS" = 0 ]; then
        ok "nothing would stop the install. Nothing was changed."
    else
        printf '%sx %s problem(s) above would stop the install.%s Nothing was changed.\n' "$C_RED" "$PROBLEMS" "$C_RESET"
    fi
}

# ---------- packages --------------------------------------------------------

install_packages() {
    if [ "$DRY" != 1 ] && have cloud-init; then
        step "waiting for cloud-init to finish"
        cloud-init status --wait >/dev/null 2>&1 || true
    fi
    step "installing packages (apt)"
    # DPkg::Lock::Timeout waits for unattended-upgrades instead of failing.
    run_sh 'export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=600 update -q </dev/null
apt-get -o DPkg::Lock::Timeout=600 install -y -q haproxy python3 python3-qrcode python3-cryptography openssl curl ca-certificates iproute2 sudo tar gzip snapd </dev/null'
    ok "packages installed"
}

install_certbot() {
    step "installing certbot (snap; the apt one cannot issue IP certificates)"
    # A freshly installed snapd (Debian) restarts itself into the snapd snap
    # during the first install, which fails that request ("context
    # canceled"): install snapd first and retry each install a few times.
    run_sh 'snap_retry() {
    n=0
    until snap list "$1" >/dev/null 2>&1 || snap install "$@" </dev/null; do
        n=$((n + 1))
        [ "$n" -lt 5 ] || { echo "snap install $* failed $n times" >&2; return 1; }
        sleep 10
        snap wait system seed.loaded </dev/null || true
    done
}
snap wait system seed.loaded </dev/null
snap_retry snapd
snap_retry certbot --classic'
    # /snap/bin is not on every PATH (sudo secure_path, the porch user's services)
    run ln -sf /snap/bin/certbot /usr/local/bin/certbot
    if [ "$DRY" = 1 ]; then
        printf '+ /snap/bin/certbot --help all | grep -q -- --ip-address\n'
    else
        /snap/bin/certbot --help all 2>/dev/null | grep -q -- --ip-address \
            || die "this certbot ($(/snap/bin/certbot --version 2>&1)) cannot issue IP certificates (needs --ip-address); try: snap refresh certbot"
    fi
    ok "certbot ready"
}

# ---------- user ------------------------------------------------------------

make_user() {
    if id "$PORCH_USER" >/dev/null 2>&1; then
        ok "user $PORCH_USER exists (Porch's)"
    else
        step "creating user $PORCH_USER"
        run useradd -m -s /bin/bash "$PORCH_USER"
        PORCH_HOME="/home/$PORCH_USER"
    fi
    # The marker says this account is Porch's (check_existing reads it on re-runs).
    run_sh "printf '%s\\n' 'Created by Porch (porch.sh). Porch owns this account and its sudoers file.' > '$PORCH_HOME/$MARKER'"
    step "sudoers: $PORCH_USER may run sudo without a password (NOPASSWD:ALL, see the warning above)"
    run_sh "set -e
t=\$(mktemp)
printf '%s\\n' '# Porch (porch.sh): porch setup and certificate renewals run sudo -n' '$PORCH_USER ALL=(ALL) NOPASSWD:ALL' > \"\$t\"
visudo -cf \"\$t\" >/dev/null
install -m 0440 -o root -g root \"\$t\" /etc/sudoers.d/90-porch
rm -f \"\$t\""
    # porch's user services (auth, frps, status, ...) must outlive any login
    run loginctl enable-linger "$PORCH_USER"
    ok "user $PORCH_USER ready (sudoers + linger)"
}

# ---------- code ------------------------------------------------------------

install_code() {
    step "downloading Porch ($PORCH_TARBALL)"
    TMP=$(mktemp -d)
    trap 'rm -rf "$TMP"' EXIT
    if [ "$DRY" = 1 ]; then
        printf '+ curl -fsSL --retry 3 -o %s %s\n' "$TMP/porch.tar.gz" "$PORCH_TARBALL"
    else
        curl -fsSL --retry 3 -o "$TMP/porch.tar.gz" "$PORCH_TARBALL" \
            || die "could not download $PORCH_TARBALL"
    fi
    sha=$PORCH_TARBALL_SHA256
    if [ -z "$sha" ]; then
        if [ "$DRY" = 1 ]; then
            printf '+ curl -fsSL --retry 3 %s.sha256\n' "$PORCH_TARBALL"
            sha=0000000000000000000000000000000000000000000000000000000000000000
        else
            sha=$(curl -fsSL --retry 3 "$PORCH_TARBALL.sha256" | awk 'NR==1{print $1}') \
                || die "could not download $PORCH_TARBALL.sha256 (or set PORCH_TARBALL_SHA256)"
        fi
    fi
    sha=$(printf '%s' "$sha" | tr 'A-F' 'a-f')
    printf '%s\n' "$sha" | grep -Eq '^[0-9a-f]{64}$' || die "not a sha256: $sha"
    # verified before anything is unpacked
    run_sh "echo '$sha  $TMP/porch.tar.gz' | sha256sum -c --quiet -"
    ok "tarball sha256 $sha"

    if [ -d "$PORCH_DIR" ]; then
        step "upgrading $PORCH_DIR (data/, config/porch.toml, config/frps.toml and logs/ are kept)"
    else
        step "unpacking into $PORCH_DIR"
    fi
    run mkdir -p "$TMP/x"
    run tar -xzf "$TMP/porch.tar.gz" -C "$TMP/x" --no-same-owner
    # One top-level directory holding bin/porch, whatever it is called: the
    # porch/ now, cush-tools/ in a landing page's tarball from before the rename.
    if [ "$DRY" = 1 ]; then
        SRC="$TMP/x/porch"
    else
        set -- "$TMP/x"/*
        { [ $# -eq 1 ] && [ -d "$1" ] && [ -x "$1/bin/porch" ]; } \
            || die "the tarball must hold exactly one top-level directory with bin/porch"
        SRC=$1
    fi
    run install -d -m 0755 -o "$PORCH_USER" -g "$PORCH_USER" "$PORCH_DIR"
    # Code: everything but data/ (the tarball never has porch.toml, frps.toml or logs/).
    run_sh "tar -C '$SRC' --exclude=./data -cf - . | tar -C '$PORCH_DIR' --no-same-owner -xf -"
    # data/: only files that are not there yet (the shipped links.json and router tables)
    run_sh "if [ -d '$SRC/data' ]; then tar -C '$SRC' -cf - data | tar -C '$PORCH_DIR' --no-same-owner --skip-old-files -xf -; fi"
    run chown -R "$PORCH_USER:$PORCH_USER" "$PORCH_DIR"
    ok "Porch code in $PORCH_DIR"
}

install_frp() {
    if [ "$DRY" != 1 ] && [ -x "$PORCH_DIR/bin/frps" ] && [ -x "$PORCH_DIR/bin/frpc" ] \
            && "$PORCH_DIR/bin/frps" --version 2>/dev/null | grep -qx "$FRP_VERSION"; then
        ok "frp $FRP_VERSION already installed"
        return 0
    fi
    name="frp_${FRP_VERSION}_linux_${ARCH}"
    step "downloading frp $FRP_VERSION ($ARCH, sha256-pinned)"
    run curl -fsSL --retry 5 -o "$TMP/frp.tar.gz" "https://github.com/fatedier/frp/releases/download/v$FRP_VERSION/$name.tar.gz"
    run_sh "echo '$FRP_SHA  $TMP/frp.tar.gz' | sha256sum -c --quiet -"
    run tar -xzf "$TMP/frp.tar.gz" -C "$TMP" --no-same-owner
    run install -m 0755 -o "$PORCH_USER" -g "$PORCH_USER" "$TMP/$name/frps" "$TMP/$name/frpc" "$PORCH_DIR/bin/"
    ok "frp $FRP_VERSION in $PORCH_DIR/bin"
}

open_firewall() {
    have ufw || return 0
    if [ "$DRY" = 1 ] || ufw status 2>/dev/null | grep -q '^Status: active'; then
        step "ufw is active: allowing 80/tcp (certificate check) and $WIZARD_PORT/tcp (the wizard)"
        run ufw allow 80/tcp
        # Remember whether 8443 is ours: the wizard unit closes it again when
        # it exits (ExecStopPost in start_wizard), but never a rule that was
        # already there.
        if [ "$DRY" = 1 ] || ! ufw status 2>/dev/null | grep -Eq "^$WIZARD_PORT/tcp +ALLOW"; then
            WIZARD_UFW=1
        fi
        run ufw allow "$WIZARD_PORT/tcp"
    fi
}

# ---------- wizard ----------------------------------------------------------

start_wizard() {
    step "starting the setup wizard (systemd unit $UNIT, log $WIZARD_LOG)"
    run_sh "systemctl stop $UNIT 2>/dev/null; systemctl reset-failed $UNIT 2>/dev/null; true"
    if [ "$DRY" != 1 ]; then
        i=0
        while [ $i -lt 60 ] && [ -n "$(holders $WIZARD_PORT)" ]; do sleep 1; i=$((i + 1)); done
    fi
    run rm -f "$WIZARD_LOG"
    run install -m 0600 -o "$PORCH_USER" -g "$PORCH_USER" /dev/null "$WIZARD_LOG"
    # The wizard binds 80/8443 as root, then drops to the sudo user (SUDO_UID):
    # so it runs as porch, through sudo -n. When the installer opened 8443 in
    # ufw, the unit closes it on exit (the wizard stops after setup completes).
    set -- systemd-run --unit="$UNIT" --uid="$PORCH_USER" --gid="$PORCH_USER" \
        -p WorkingDirectory="$PORCH_DIR" -p StandardOutput=append:"$WIZARD_LOG" \
        -p StandardError=append:"$WIZARD_LOG" --setenv=PYTHONUNBUFFERED=1
    if [ "$WIZARD_UFW" = 1 ]; then
        set -- "$@" -p "ExecStopPost=/usr/bin/sudo -n $(command -v ufw || echo /usr/sbin/ufw) delete allow $WIZARD_PORT/tcp"
    fi
    set -- "$@" /usr/bin/sudo -n "$PORCH_DIR/bin/porch" setup --web
    [ "$STAGING" = 1 ] && set -- "$@" --staging
    set -- "$@" --no-qr
    [ -n "$DOMAIN" ] && set -- "$@" --domain "$DOMAIN"
    [ -n "$DNS_PROVIDER" ] && set -- "$@" --dns-provider "$DNS_PROVIDER"
    run "$@"
}

# show_url: print the link (and fingerprint) from the wizard's log; 1 if none.
show_url() {
    [ -r "$WIZARD_LOG" ] || return 1
    url=$(grep -Eo 'https://[^ ]+/#k=[A-Za-z0-9_-]+' "$WIZARD_LOG" | tail -n 1)
    [ -n "$url" ] || return 1
    fp=$(awk 'f{print; f=0} /fingerprint is exactly/{f=1}' "$WIZARD_LOG" | tail -n 1 | tr -d ' ')
    echo
    printf '%sPorch setup wizard%s\n' "$C_BOLD" "$C_RESET"
    if have python3 && python3 -c 'import qrcode' 2>/dev/null; then
        python3 -I -c 'import sys, qrcode
q = qrcode.QRCode(border=1); q.add_data(sys.argv[1]); q.print_ascii(tty=False)' "$url" 2>/dev/null || true
    fi
    echo "Open this link (it works once; keep it private):"
    echo
    printf '    %s%s%s\n' "$C_GREEN$C_BOLD" "$url" "$C_RESET"
    echo
    if [ -n "$fp" ]; then
        echo "The certificate is self-signed. Check that your browser shows the SHA-256 fingerprint:"
        printf '    %s\n' "$fp"
    elif grep -q 'staging certificate' "$WIZARD_LOG"; then
        echo "(Let's Encrypt staging certificate: your browser will warn)"
    fi
    printf 're-show:  %ssudo sh porch.sh --url%s   (or: curl -sSL %s | sudo sh -s -- --url)\n' \
        "$C_DIM" "$C_RESET" "$INSTALLER_URL"
    printf 'logs:     %ssudo tail -f %s%s\n' "$C_DIM" "$WIZARD_LOG" "$C_RESET"
    return 0
}

wait_for_url() {
    if [ "$DRY" = 1 ]; then
        printf '+ wait for the wizard link in %s\n' "$WIZARD_LOG"
        return 0
    fi
    step "waiting for the wizard's link (it may first get a Let's Encrypt certificate for this IP)"
    i=0
    while [ "$i" -lt "$PORCH_WIZARD_TIMEOUT" ]; do
        if show_url; then
            return 0
        fi
        if grep -Eq 'porch setup --web: (exiting|cannot|refusing|running as root|privilege|--|no public|ports below)' "$WIZARD_LOG" 2>/dev/null \
                || ! systemctl is-active --quiet "$UNIT"; then
            tail -n 30 "$WIZARD_LOG" >&2 || true
            die "the wizard stopped before printing its link (log above: $WIZARD_LOG)"
        fi
        sleep 2
        i=$((i + 2))
    done
    tail -n 30 "$WIZARD_LOG" >&2 || true
    die "no wizard link after ${PORCH_WIZARD_TIMEOUT}s (log: $WIZARD_LOG; systemctl status $UNIT)"
}

main "$@"

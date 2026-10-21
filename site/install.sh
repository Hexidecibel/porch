#!/bin/sh
#
# Porch client installer: pair this machine with a Porch server.
#
# Usage (from your Porch server's landing page, which serves a copy of this
# script filled in with its own address):
#   curl -sSL @PORCH_LANDING_URL@/install.sh | sh
#
# The copy in the source repo is a template: it has no server to pair with and
# stops at once unless PORCH_AUTH_URL and PORCH_REPO_TARBALL are set. To set up
# a Porch server itself, see site/porch.sh.
#
# Environment variables (override defaults; each also answers to its old
# CUSH_* name, e.g. CUSH_DIR, when the PORCH_* one is unset):
#   PORCH_DIR          Install location   (default: $HOME/porch, or an existing
#                      $HOME/cush-tools from before the rename, kept in place)
#   PORCH_AUTH_URL     Pairing / auth server base URL  (default: @PORCH_LANDING_URL@)
#   PORCH_FRP_VERSION  frp client version to fetch     (default: 0.67.0)
#   PORCH_FRP_SHA256   sha256 of that frp tarball      (needed only for a version that is not pinned)
#   PORCH_REPO_TARBALL URL of the Porch tarball        (default: @PORCH_LANDING_URL@/porch.tar.gz)
#   PORCH_FORCE        Set to 1 to overwrite an existing PORCH_DIR
#
# Supported platforms: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64.
#
# The frp download is sha256-pinned per platform (the release's official
# frp_sha256_checksums.txt). The repo tarball is checked against the .sha256
# published next to it when there is one.
#
# Plain POSIX sh on purpose: `curl ... | sh` runs dash on Debian and Ubuntu,
# and a piped script cannot re-exec itself under bash (its body is not
# re-readable from the pipe). The whole script is one function called on the
# last line, so a truncated download never runs half a script.

main() {
set -eu

# ---------- config ----------------------------------------------------------

# PORCH_* wins; the CUSH_* names are what this script read before the rename.
PORCH_DIR="${PORCH_DIR:-${CUSH_DIR:-}}"
if [ -z "$PORCH_DIR" ]; then
    # A machine paired before the rename has ~/cush-tools: keep using it (a
    # re-install upgrades it in place) instead of making a second copy.
    if [ -d "$HOME/cush-tools" ] && [ ! -e "$HOME/porch" ]; then
        PORCH_DIR="$HOME/cush-tools"
    else
        PORCH_DIR="$HOME/porch"
    fi
fi
# bin/deploy renders this file (lib/porch_config.py site_render) with your
# landing host in place of the marker; the raw repo copy refuses to run (below).
PORCH_AUTH_URL="${PORCH_AUTH_URL:-${CUSH_AUTH_URL:-@PORCH_LANDING_URL@}}"
PORCH_FRP_VERSION="${PORCH_FRP_VERSION:-${CUSH_FRP_VERSION:-0.67.0}}"
PORCH_FRP_SHA256="${PORCH_FRP_SHA256:-${CUSH_FRP_SHA256:-}}"
PORCH_REPO_TARBALL="${PORCH_REPO_TARBALL:-${CUSH_REPO_TARBALL:-@PORCH_LANDING_URL@/porch.tar.gz}}"
PORCH_FORCE="${PORCH_FORCE:-${CUSH_FORCE:-0}}"

# frp 0.67.0 release tarballs (frp_sha256_checksums.txt)
FRP_PINNED_VERSION=0.67.0
FRP_SHA256_LINUX_AMD64=f8629ca7ca56b8e7e7a9903779b8d5c47c56ad1b75b99b2d7138477acc4c7105
FRP_SHA256_LINUX_ARM64=0e9683226acdcbbb2ac8d073f35ba8be2a8b1e7584684d2073f39d337ebd6de7
FRP_SHA256_DARWIN_AMD64=3ad25e7626c24fc9c9d098afadb3e52beca9f74aa65efe8e39ede8aeb9ec9ab2
FRP_SHA256_DARWIN_ARM64=56a63847aaaf7dc0f75204ae37cf65806dd9cdf64596d2c2f2a66cc8ae039e4c

# ---------- pretty output ---------------------------------------------------

if [ -t 1 ]; then
    ESC=$(printf '\033')
    C_RESET="${ESC}[0m"
    C_DIM="${ESC}[2m"
    C_BOLD="${ESC}[1m"
    C_GREEN="${ESC}[32m"
    C_RED="${ESC}[31m"
    C_YELLOW="${ESC}[33m"
    C_CYAN="${ESC}[36m"
else
    C_RESET="" C_DIM="" C_BOLD="" C_GREEN="" C_RED="" C_YELLOW="" C_CYAN=""
fi

printf '%sPorch installer%s\n\n' "$C_BOLD" "$C_RESET"

# An unrendered marker (the raw repo copy): there is no server to pair with.
case "$PORCH_AUTH_URL $PORCH_REPO_TARBALL" in
    *@PORCH_LANDING*)
        die "this is the template copy of install.sh: run it from your Porch server's landing page
    (curl -sSL https://<your Porch landing host>/install.sh | sh), or set PORCH_AUTH_URL and
    PORCH_REPO_TARBALL. To set up a Porch server, see site/porch.sh." ;;
esac

detect_os_arch
step "detected $OS/$ARCH"

check_deps
frp_sha=$(frp_pin)

case "$PORCH_DIR" in
    /*) ;;
    *) die "PORCH_DIR must be an absolute path: $PORCH_DIR" ;;
esac
case "$(printf '%s' "$PORCH_DIR" | sed 's#/*$##')" in
    ''|"$(printf '%s' "$HOME" | sed 's#/*$##')"|/usr|/etc|/bin|/var|/opt|/home|/Users|/tmp)
        die "refusing to install into $PORCH_DIR (it would be replaced on PORCH_FORCE=1)" ;;
esac
if [ -e "$PORCH_DIR" ] && [ "$PORCH_FORCE" != "1" ]; then
    warn "$PORCH_DIR already exists"
    printf '  re-run with force to overwrite:\n'
    printf '    %sPORCH_FORCE=1 curl -sSL %s/install.sh | sh%s\n' \
        "$C_DIM" "$PORCH_AUTH_URL" "$C_RESET"
    exit 1
fi

# staging dir for downloads; cleaned on exit. Everything is downloaded and
# verified here first: an existing PORCH_DIR is only replaced once both the
# tarball and frpc are in hand, so a failed download never leaves you with no
# install (or without its config/frpc.toml pairing).
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# ---- download + extract repo tarball ---------------------------------------

step "downloading the Porch tarball"
fetch "$PORCH_REPO_TARBALL" "$tmp/porch.tar.gz" || die "could not download $PORCH_REPO_TARBALL"
if fetch "$PORCH_REPO_TARBALL.sha256" "$tmp/porch.tar.gz.sha256" 2>/dev/null; then
    want=$(awk 'NR==1{print $1}' "$tmp/porch.tar.gz.sha256")
    verify_sha "$tmp/porch.tar.gz" "$want" || die "the Porch tarball does not match its published sha256"
    ok "tarball sha256 verified"
else
    warn "no $PORCH_REPO_TARBALL.sha256 published; skipping the tarball check"
fi

step "extracting repo"
mkdir -p "$tmp/repo"
tar -xzf "$tmp/porch.tar.gz" -C "$tmp/repo"

# If tarball has a single top-level dir (porch/, or cush-tools/ in older ones), flatten it.
set -- "$tmp/repo"/*
if [ $# -eq 1 ] && [ -d "$1" ]; then
    repo_src="$1"
else
    repo_src="$tmp/repo"
fi

# ---- download frp client ----------------------------------------------------

frp_name="frp_${PORCH_FRP_VERSION}_${OS}_${ARCH}"
frp_url="https://github.com/fatedier/frp/releases/download/v${PORCH_FRP_VERSION}/${frp_name}.tar.gz"

step "downloading frp ${PORCH_FRP_VERSION} ($OS/$ARCH)"
fetch "$frp_url" "$tmp/frp.tar.gz" || die "could not download $frp_url"
verify_sha "$tmp/frp.tar.gz" "$frp_sha" || die "frp download does not match its pinned sha256 ($frp_sha)"
ok "frp sha256 verified"

step "extracting frpc binary"
mkdir -p "$tmp/frp"
tar -xzf "$tmp/frp.tar.gz" -C "$tmp/frp"

frpc_src="$tmp/frp/$frp_name/frpc"
if [ ! -f "$frpc_src" ]; then
    # Fall back to a find in case the archive layout changes.
    frpc_src="$(find "$tmp/frp" -type f -name frpc | head -n 1)"
fi
[ -n "$frpc_src" ] && [ -f "$frpc_src" ] || die "frpc binary not found in release archive"

if [ -e "$PORCH_DIR" ]; then
    step "replacing existing $PORCH_DIR (PORCH_FORCE=1)"
    rm -rf "$PORCH_DIR"
fi
step "installing into $PORCH_DIR"
mkdir -p "$PORCH_DIR"
# Copy contents (including dotfiles) into $PORCH_DIR.
# Use tar for portable "cp -a including dotfiles" behaviour.
tar -C "$repo_src" -cf - . | tar -C "$PORCH_DIR" -xf -
mkdir -p "$PORCH_DIR/bin"
cp "$frpc_src" "$PORCH_DIR/bin/frpc"
chmod 0755 "$PORCH_DIR/bin/frpc"

# ---- run bootstrap ----------------------------------------------------------

bootstrap="$PORCH_DIR/bin/bootstrap"
if [ ! -x "$bootstrap" ]; then
    if [ -f "$bootstrap" ]; then
        chmod +x "$bootstrap"
    else
        die "bin/bootstrap missing from repo tarball — cannot complete pairing"
    fi
fi

step "starting pairing flow"
echo

# We are likely being piped from curl, so stdin is the pipe (not a TTY).
# Re-attach the terminal via /dev/tty if we have one, else tell bootstrap
# to run non-interactively and rely on env vars / defaults.
if [ -r /dev/tty ] && [ -w /dev/tty ] && (: < /dev/tty) 2>/dev/null; then
    "$bootstrap" --auth-url "$PORCH_AUTH_URL" < /dev/tty
else
    warn "no /dev/tty available — running bootstrap non-interactively"
    "$bootstrap" --auth-url "$PORCH_AUTH_URL" --non-interactive < /dev/null
fi

# ---- done -------------------------------------------------------------------

echo
ok "Porch installed at $PORCH_DIR"
echo
echo "  Add to your PATH:"
printf '    %sexport PATH="%s/bin:$PATH"%s\n' "$C_DIM" "$PORCH_DIR" "$C_RESET"
echo
echo "  Try it:"
printf '    %s%s/bin/tunnel 3000 myapp%s\n' "$C_DIM" "$PORCH_DIR" "$C_RESET"
echo
}

step() { printf '%s→%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
ok()   { printf '%s✓%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s!%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die()  { printf '%sx%s %s\n' "${C_RED:-}" "${C_RESET:-}" "$*" >&2; exit 1; }

# ---------- detect platform -------------------------------------------------

detect_os_arch() {
    uname_s="$(uname -s)"
    uname_m="$(uname -m)"

    case "$uname_s" in
        Linux)  OS="linux" ;;
        Darwin) OS="darwin" ;;
        *) die "unsupported OS: $uname_s (need Linux or macOS)" ;;
    esac

    case "$uname_m" in
        x86_64|amd64)  ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) die "unsupported architecture: $uname_m (need amd64 or arm64)" ;;
    esac
}

# frp_pin: the expected sha256 of frp_<version>_<os>_<arch>.tar.gz.
frp_pin() {
    if [ -n "$PORCH_FRP_SHA256" ]; then
        printf '%s\n' "$PORCH_FRP_SHA256"
        return 0
    fi
    [ "$PORCH_FRP_VERSION" = "$FRP_PINNED_VERSION" ] \
        || die "frp $PORCH_FRP_VERSION is not pinned: set PORCH_FRP_SHA256 to its sha256 (frp_sha256_checksums.txt)"
    case "$OS/$ARCH" in
        linux/amd64)  printf '%s\n' "$FRP_SHA256_LINUX_AMD64" ;;
        linux/arm64)  printf '%s\n' "$FRP_SHA256_LINUX_ARM64" ;;
        darwin/amd64) printf '%s\n' "$FRP_SHA256_DARWIN_AMD64" ;;
        darwin/arm64) printf '%s\n' "$FRP_SHA256_DARWIN_ARM64" ;;
    esac
}

# ---------- dependency check ------------------------------------------------

have() { command -v "$1" >/dev/null 2>&1; }

need_tool() {
    if ! have "$1"; then
        die "missing required tool: $1 ($2)"
    fi
}

check_deps() {
    need_tool tar    "install with: sudo apt install tar  /  brew install gnu-tar"
    need_tool python3 "install with: sudo apt install python3  /  brew install python"
    if ! have curl && ! have wget; then
        die "need either curl or wget (install with: sudo apt install curl)"
    fi
    if ! have sha256sum && ! have shasum; then
        die "need sha256sum or shasum to verify downloads"
    fi
}

# ---------- download + verify helpers ---------------------------------------

fetch() {
    # fetch <url> <output_path>
    if have curl; then
        curl -fsSL --retry 3 -o "$2" "$1"
    else
        wget -q -O "$2" "$1"
    fi
}

# verify_sha <file> <hex>: 0 when the file's sha256 is exactly <hex>.
verify_sha() {
    want=$(printf '%s' "$2" | tr 'A-F' 'a-f')
    printf '%s\n' "$want" | grep -Eq '^[0-9a-f]{64}$' || return 1
    if have sha256sum; then
        got=$(sha256sum "$1" | awk '{print $1}')
    else
        got=$(shasum -a 256 "$1" | awk '{print $1}')
    fi
    [ "$got" = "$want" ]
}

main "$@"

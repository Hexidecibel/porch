# porch-config.sh — sourced: sets the resolved Porch domain config as shell
# variables (not exported). lib/tunnel-state.sh sources it, so every launcher
# has them:
#   PORCH_BRAND PORCH_DOMAIN PORCH_TUNNEL_BASE PORCH_AUTH_HOST PORCH_PANEL_HOST
#   PORCH_LANDING_HOST PORCH_COOKIE_DOMAIN PORCH_FRP_ADDR PORCH_FRP_PORT
# Source of truth is lib/porch_config.py (config/porch.toml, PORCH_* env, then
# the cush.rocks defaults). An invalid config aborts the sourcing script.

_porch_cfg_lib="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

porch_config_load() {
    local out
    if command -v python3 >/dev/null 2>&1 \
        && out="$(python3 -I "$_porch_cfg_lib/porch_config.py" shell)"; then
        eval "$out"
        return 0
    fi
    if command -v python3 >/dev/null 2>&1; then
        echo "Error: Porch config is invalid (see above). Fix config/porch.toml or the PORCH_* variables." >&2
        exit 1
    fi
    # No python3 at all: only the built-in defaults are possible.
    local cfg="${PORCH_CONFIG:-$_porch_cfg_lib/../config/porch.toml}"
    if [ "${PORCH_CONFIG:-}" != "none" ] && [ -f "$cfg" ]; then
        echo "Error: python3 is needed to read $cfg" >&2
        exit 1
    fi
    PORCH_BRAND="${PORCH_BRAND:-Porch}"
    PORCH_DOMAIN="${PORCH_DOMAIN:-cush.rocks}"
    PORCH_TUNNEL_BASE="${PORCH_TUNNEL_BASE:-tunnel.$PORCH_DOMAIN}"
    PORCH_AUTH_HOST="${PORCH_AUTH_HOST:-auth.$PORCH_DOMAIN}"
    PORCH_PANEL_HOST="${PORCH_PANEL_HOST:-panel.$PORCH_DOMAIN}"
    PORCH_LANDING_HOST="${PORCH_LANDING_HOST:-$PORCH_TUNNEL_BASE}"
    PORCH_COOKIE_DOMAIN="${PORCH_COOKIE_DOMAIN:-.$PORCH_DOMAIN}"
    PORCH_FRP_ADDR="${PORCH_FRP_ADDR:-$PORCH_TUNNEL_BASE}"
    PORCH_FRP_PORT="${PORCH_FRP_PORT:-7000}"
}

porch_config_load

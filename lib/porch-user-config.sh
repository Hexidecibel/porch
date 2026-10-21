# lib/porch-user-config.sh: where per-user Porch config files live.
# Sourced by the launchers and lib/op.sh / lib/infisical.sh.
#
# porch_user_config_file NAME prints the path of ~/.config/porch/NAME. Files
# written before the rename live in ~/.config/cush-tools/: when only that one
# exists it is used, so an existing setup keeps working without a move.
porch_user_config_file() {
    local new="$HOME/.config/porch/$1" legacy="$HOME/.config/cush-tools/$1"
    if [ ! -e "$new" ] && [ -e "$legacy" ]; then
        printf '%s\n' "$legacy"
    else
        printf '%s\n' "$new"
    fi
}

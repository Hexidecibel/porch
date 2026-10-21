"""Per-user Porch config paths (the Python side of lib/porch-user-config.sh).

user_config_file(name) is ~/.config/porch/<name>. Files written before the
rename live in ~/.config/cush-tools/: when only that one exists it is used,
so an existing setup keeps working without a move.
"""

import os

CONFIG_DIR = '~/.config/porch'
LEGACY_CONFIG_DIR = '~/.config/cush-tools'


def user_config_file(name, home=None):
    base = home if home is not None else os.path.expanduser('~')
    new = os.path.join(base, '.config', 'porch', name)
    legacy = os.path.join(base, '.config', 'cush-tools', name)
    if not os.path.lexists(new) and os.path.lexists(legacy):
        return legacy
    return new


def env_first(*names, default=None, env=None):
    """The first set (non-empty) environment variable among names: callers
    pass the PORCH_* name first and the old CUSH_* name after it."""
    env = os.environ if env is None else env
    for n in names:
        v = env.get(n)
        if v:
            return v
    return default

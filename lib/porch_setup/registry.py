"""Discovery of steps, DNS providers, connection modes and CLI subcommands.

No central list: drop a module into the package and it is picked up.

  steps/<id>.py      STEP = MyStep()          (a Step instance)
                     ORDER = 60               (int; sort key, ties broken by STEP.id)
  dns/<name>.py      PROVIDER = MyProvider    (class or instance with .name)
  connect/<name>.py  MODE = MyMode            (class or instance with .name)
  cmd_<name>.py      def main(argv: list[str]) -> int   (`porch <name> ...`)

Modules without the attribute (base.py, detect.py, helpers) are ignored.
Modules whose name starts with "_" are never imported. An import error is
raised (RegistryError naming the module), never silently skipped.

Reserved ORDER values (graph order from docs/porch-setup-design.md):
  preflight 10, domain 20, network_probe 30, connection 40, firewall 50,
  dns_provider 60, dns_records 70, certificate 80, haproxy 90, frps 100,
  services 110, admin 120, landing 130, smoke 140.
"""

import importlib
import importlib.util
import pkgutil

PKG = __name__.rsplit(".", 1)[0]  # "porch_setup"


class RegistryError(Exception):
    pass


def _modules(subpkg):
    pkg_name = f"{PKG}.{subpkg}" if subpkg else PKG
    pkg = importlib.import_module(pkg_name)
    for m in sorted(pkgutil.iter_modules(pkg.__path__), key=lambda m: m.name):
        if m.name.startswith("_") or m.ispkg:
            continue
        name = f"{pkg_name}.{m.name}"
        try:
            yield m.name, importlib.import_module(name)
        except Exception as e:  # noqa: BLE001
            raise RegistryError(f"cannot import {name}: {type(e).__name__}: {e}") from e


def discover(subpkg, attr):
    """[(module short name, module.<attr>, module)] for modules defining attr."""
    out = []
    for short, mod in _modules(subpkg):
        if hasattr(mod, attr):
            out.append((short, getattr(mod, attr), mod))
    return out


def steps():
    """All registered Step instances in ORDER."""
    found = []
    for short, step, mod in discover("steps", "STEP"):
        order = getattr(mod, "ORDER", None)
        if not isinstance(order, int):
            raise RegistryError(f"{PKG}.steps.{short} defines STEP but no int ORDER")
        found.append((order, step.id, step))
    found.sort(key=lambda t: (t[0], t[1]))
    ids = [t[1] for t in found]
    dup = {i for i in ids if ids.count(i) > 1}
    if dup:
        raise RegistryError(f"duplicate step ids: {sorted(dup)}")
    return [t[2] for t in found]


def _named(subpkg, attr):
    out = {}
    for short, obj, _mod in discover(subpkg, attr):
        name = getattr(obj, "name", None) or short
        if name in out:
            raise RegistryError(f"duplicate {attr} name {name!r} in {PKG}.{subpkg}")
        out[name] = obj
    return out


def providers():
    """{provider name: PROVIDER} from dns/*.py."""
    return _named("dns", "PROVIDER")


def modes():
    """{mode name: MODE} from connect/*.py."""
    return _named("connect", "MODE")


def command(name):
    """The `main` of porch_setup/cmd_<name>.py, or None if not built yet."""
    mod_name = name.replace("-", "_")
    if not mod_name.replace("_", "").isalnum():
        return None
    try:
        spec = importlib.util.find_spec(f"{PKG}.cmd_{mod_name}")
    except (ImportError, ValueError):
        return None
    if spec is None:
        return None
    mod = importlib.import_module(spec.name)
    return getattr(mod, "main", None)


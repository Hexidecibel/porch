"""Porch setup engine (stdlib only). See docs/porch-setup-design.md.

    from porch_setup.engine import Engine, Step, Check, Action, Input, make_context
    from porch_setup import registry
    Engine(registry.steps(), make_context(io=CliIO(...))).run()
"""

SCHEMA_VERSION = 1

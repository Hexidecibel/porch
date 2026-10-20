"""porch mcp: run the porch Model Context Protocol server over stdio.

    porch mcp                   serve MCP (JSON-RPC 2.0, one message per line)
    porch mcp --print-config    print the Claude Code / .mcp.json / generic config

The server and its tools live in lib/porch_mcp.py; see docs/mcp.md.
stdout carries protocol messages only; logs go to stderr.
"""

import os
import sys

_LIB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
import porch_mcp  # noqa: E402


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv in (['-h'], ['--help']):
        print(__doc__.strip())
        return 0
    if argv == ['--print-config']:
        return porch_mcp.print_config()
    if argv:
        print(f'porch mcp: unknown arguments: {" ".join(argv)}', file=sys.stderr)
        print(__doc__.strip(), file=sys.stderr)
        return 2
    try:
        return porch_mcp.serve()
    except KeyboardInterrupt:
        return 0


if __name__ == '__main__':
    sys.exit(main())

"""porch tail: a live, read-only log door for a growing file.

    porch tail <file> [--name N] [--dry-run] [door flags]

= bin/view <file> <name> --follow --bg: the file is followed like `tail -F`
(truncation and rotation handled) and lines reach the page over SSE. The
name defaults to a slug of the file name plus a short random suffix. Door
flags (--expires, --password, --guest-link, --max-opens, --burn, --inspect)
pass through to bin/view unchanged.

Exit codes: 0 ok, 1 launcher failed, 2 usage.
"""

import os
import shlex
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import cmd_share  # noqa: E402

USAGE = __doc__.split('\n\n')[1]


def build(argv):
    """(argv to run, dry_run) for porch tail's arguments; raises UsageError."""
    door, rest = cmd_share.split_door_flags(list(argv))
    path = name = None
    dry = False
    i = 0
    while i < len(rest):
        a = rest[i]
        if a == '--name':
            if i + 1 >= len(rest):
                raise cmd_share.UsageError('--name needs a value')
            name = rest[i + 1]
            i += 2
            continue
        if a.startswith('--name='):
            name = a.split('=', 1)[1]
        elif a == '--dry-run':
            dry = True
        elif a in ('--bg', '--follow'):
            pass
        elif a in ('-h', '--help'):
            raise cmd_share.UsageError('help')
        elif a.startswith('-'):
            raise cmd_share.UsageError(f'unknown flag {a}')
        elif path is None:
            path = a
        else:
            raise cmd_share.UsageError(f'unexpected argument {a}')
        i += 1
    if path is None:
        raise cmd_share.UsageError('give the file to follow')
    if not os.path.isfile(path):
        raise cmd_share.UsageError(f'not a file: {path}')
    if name is not None and not cmd_share.valid_name(name):
        raise cmd_share.UsageError(f'invalid --name {name!r}')
    path = os.path.realpath(path)
    name = name or cmd_share.default_name(path)
    return [os.path.join(cmd_share.BIN_DIR, 'view'), path, name, '--follow', '--bg'] + door, dry


def main(argv=None, run=subprocess.call):
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        cmd, dry = build(argv)
    except cmd_share.UsageError as e:
        if str(e) == 'help':
            print(__doc__.strip())
            return 0
        print(f'porch tail: {e}', file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 2
    if dry:
        print('command: ' + shlex.join(cmd))
        return 0
    return 0 if run(cmd) == 0 else 1


if __name__ == '__main__':
    sys.exit(main())

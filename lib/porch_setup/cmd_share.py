"""porch share: share a file, a folder or stdin as a door, picking the app.

    porch share <path|-> [--as TYPE] [--name N] [--dry-run] [door flags] [--bg]
    porch share --e2e <file|-> [--seal-password] [--name N] [--dry-run] [door flags]

Routing looks at the content first (magic bytes), then the extension
(lib/viewserver.py sniff_file):

    image / video       bin/media --no-guest-upload  (a copy is staged in ~/media/<name>/:
                        mediaserver refuses symlinks, on purpose)
    audio               bin/music              (a copy is staged in ~/music/<name>/)
    directory           bin/serve              (never --allow-scripts; --list
                                                unless it has an index.html)
    everything else     bin/view               (markdown, pdf, csv/tsv, json, zip,
                                                diff, code, text, other)
    -  (stdin)          read up to MAX_STDIN into a 0600 file in the private run
                        dir (lib/rundir.py, tool "share"), sniffed like a file.
                        That copy is removed when the door closes (bin/view
                        --owned-file), right after staging (media/music), or
                        never written (paste reads the bytes on its stdin)
                        An expired or owner-closed door keeps its copies for 7
                        days so it can be reopened (lib/door_recipe.py); a
                        burned or used-up one shreds them at once.

--as overrides: media | music | serve | paste | view | view:<mode> (a viewer
mode: markdown code text pdf csv tsv json zip diff image video audio other).
The name defaults to a slug of the file name plus a short random suffix.
--e2e: end-to-end encrypted (lib/porch_seal.py, docs/porch-seal.md). The file
(or stdin, sealed straight from memory) is sealed into a 0600 file in the
private run dir and shared with bin/seal --owned-file; the box only ever holds
ciphertext. The printed link carries the key in its #k= fragment (browsers
never send it). --seal-password seals with a password instead (from
PORCH_SEAL_PASSWORD, else a prompt on the terminal; never argv), so the link
has no key and the recipient types the password. That is separate from the
door gate's --password. With --e2e, --burn / --max-opens count complete
downloads. Needs python3-cryptography (exit 3 without it).

Door flags (--expires, --password, --guest-link, --max-opens, --burn,
--inspect, --inspect-raw) pass through to the launcher unchanged; --bg is
always on, since a door has to outlive this command. The launcher prints the URL (and the guest link).

Exit codes: 0 ok, 1 launcher failed / nothing to share, 2 usage, 3 --e2e without
python3-cryptography.
"""

import contextlib
import getpass
import io
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys

_LIB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
import door_recipe  # noqa: E402
import door_state  # noqa: E402
import porch_seal  # noqa: E402
import rundir  # noqa: E402
import viewserver  # noqa: E402
from porch_http import sanitize_filename  # noqa: E402

REPO_DIR = os.path.dirname(_LIB)
BIN_DIR = os.path.join(REPO_DIR, 'bin')
MAX_STDIN = 64 * 1024 * 1024
NAME_RE = re.compile(r'^[a-z0-9][a-z0-9-]{0,40}$')
AS_TOOLS = ('media', 'music', 'serve', 'paste', 'view')
MIN_SEAL_PASSWORD = 8
KEY_PLACEHOLDER = '<key, made at run time>'

# What bin/media and bin/music will list (they go by extension), and the
# extension a staged copy gets when the original's does not fit.
MEDIA_EXT = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.heic', '.heif', '.bmp', '.tif',
             '.tiff', '.avif', '.mp4', '.m4v', '.mov', '.webm', '.mkv', '.ogv', '.avi', '.3gp'}
MUSIC_EXT = {'.mp3', '.wav', '.flac', '.m4a', '.aac', '.ogg', '.oga', '.opus', '.weba',
             '.aiff', '.aif', '.alac', '.wma'}
EXT_FOR_MIME = {
    'image/png': '.png', 'image/jpeg': '.jpg', 'image/gif': '.gif', 'image/webp': '.webp',
    'image/bmp': '.bmp', 'image/tiff': '.tiff', 'image/avif': '.avif', 'image/heic': '.heic',
    'video/mp4': '.mp4', 'video/quicktime': '.mov', 'video/webm': '.webm', 'video/ogg': '.ogv',
    'video/x-msvideo': '.avi', 'video/3gpp': '.3gp',
    'audio/mpeg': '.mp3', 'audio/wav': '.wav', 'audio/flac': '.flac', 'audio/mp4': '.m4a',
    'audio/ogg': '.ogg', 'audio/aiff': '.aiff',
}


# Boolean door flags; keep in step with door_flags_parse in lib/door-flags.sh.
DOOR_BOOL_FLAGS = ('--password', '--guest-link', '--burn', '--inspect', '--inspect-raw')


class UsageError(Exception):
    pass


# ---- door flags (same grammar as lib/door-flags.sh) ---------------------------

def split_door_flags(argv):
    """(door flags, the rest). Door flags are passed through unchanged."""
    door, rest = [], []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ('--expires', '--max-opens'):
            if i + 1 >= len(argv) or not argv[i + 1]:
                raise UsageError(f'{a} needs a value')
            door += [a, argv[i + 1]]
            i += 2
            continue
        if a.startswith(('--expires=', '--max-opens=')):
            k, v = a.split('=', 1)
            door += [k, v]
        elif a in DOOR_BOOL_FLAGS:
            door.append(a)
        elif a.startswith('--password='):
            raise UsageError('--password takes no value on the command line (it would show '
                             'in ps); set PORCH_DOOR_PASSWORD or type it at the prompt')
        else:
            rest.append(a)
        i += 1
    return door, rest


def parse_args(argv):
    door, rest = split_door_flags(list(argv))
    opts = {'path': None, 'as': None, 'name': None, 'dry_run': False, 'door': door,
            'e2e': False, 'seal_password': False}
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in ('--as', '--name'):
            if i + 1 >= len(rest):
                raise UsageError(f'{a} needs a value')
            opts[a[2:]] = rest[i + 1]
            i += 2
            continue
        if a.startswith(('--as=', '--name=')):
            k, v = a.split('=', 1)
            opts[k[2:]] = v
        elif a == '--dry-run':
            opts['dry_run'] = True
        elif a == '--e2e':
            opts['e2e'] = True
        elif a == '--seal-password':
            opts['seal_password'] = True
        elif a.startswith('--seal-password='):
            raise UsageError('--seal-password takes no value on the command line (it would '
                             'show in ps); set PORCH_SEAL_PASSWORD or type it at the prompt')
        elif a == '--bg':
            pass                                 # always on
        elif a in ('-h', '--help'):
            raise UsageError('help')
        elif a.startswith('-') and a != '-':
            raise UsageError(f'unknown flag {a}')
        elif opts['path'] is None:
            opts['path'] = a
        else:
            raise UsageError(f'unexpected argument {a}')
        i += 1
    if opts['path'] is None:
        raise UsageError('nothing to share: give a path, or - for stdin')
    if opts['seal_password'] and not opts['e2e']:
        raise UsageError('--seal-password goes with --e2e')
    if opts['e2e'] and opts['as']:
        raise UsageError('--e2e always uses the sealed viewer; drop --as')
    if opts['name'] is not None and not valid_name(opts['name']):
        raise UsageError(f"invalid --name {opts['name']!r}: 1-41 chars of [a-z0-9-], "
                         "starting with a letter or digit, not ending with '-'")
    return opts


# ---- names ------------------------------------------------------------------

def valid_name(name):
    return bool(NAME_RE.match(name or '')) and not name.endswith('-')


def slug(text, max_len=30):
    s = re.sub(r'[^a-z0-9]+', '-', str(text).lower()).strip('-')
    s = s[:max_len].strip('-')
    return s or 'share'


def default_name(path, rand=None):
    """<slug of the file name>-<4 hex>, always a valid door name."""
    base = os.path.basename(os.path.normpath(str(path))) or 'share'
    stem = base if os.path.isdir(path) else os.path.splitext(base)[0] or base
    suffix = rand if rand is not None else secrets.token_hex(2)
    name = f'{slug(stem)}-{suffix}'
    return name if valid_name(name) else f'share-{suffix}'


# ---- routing ------------------------------------------------------------------

def route(path, as_=None):
    """(tool, viewer mode or None, sniff or None, why) for a path."""
    if as_:
        tool, _, mode = as_.partition(':')
        if tool not in AS_TOOLS:
            raise UsageError(f'--as must be one of {", ".join(AS_TOOLS)} or view:<mode>')
        if mode and (tool != 'view' or mode not in viewserver.MODES):
            raise UsageError(f'--as view:<mode>, mode one of: {" ".join(viewserver.MODES)}')
        if tool == 'serve' and not os.path.isdir(path):
            raise UsageError('--as serve needs a directory')
        if tool != 'serve' and os.path.isdir(path):
            raise UsageError(f'--as {tool} needs a file; a directory goes to serve')
        sn = None if os.path.isdir(path) else viewserver.sniff_file(path)
        return tool, (mode or None), sn, f'--as {as_}'
    if os.path.isdir(path):
        return 'serve', None, None, 'a directory'
    sn = viewserver.sniff_file(path)
    if sn.mode in ('image', 'video') and sn.mime in EXT_FOR_MIME:
        return 'media', None, sn, f'{sn.mime} by content'
    if sn.mode == 'audio' and sn.mime in EXT_FOR_MIME:
        return 'music', None, sn, f'{sn.mime} by content'
    return 'view', sn.mode, sn, f'viewer mode {sn.mode}'


def staged_name(path, sn, allowed):
    """A file name the target app will list: the original when its extension
    fits, else the sanitized stem plus the extension the content calls for."""
    base = sanitize_filename(os.path.basename(path))
    stem, ext = os.path.splitext(base)
    want = EXT_FOR_MIME.get(sn.mime) if sn else None
    if ext.lower() in allowed and (want is None or _same_kind(ext.lower(), want)):
        return base
    return (stem or 'shared') + (want or '.bin')


def _same_kind(ext, want):
    """A .jpeg staged as itself is fine; a .mp3 that holds a PNG is not."""
    kinds = ({'.jpg', '.jpeg'}, {'.tif', '.tiff'}, {'.heic', '.heif'}, {'.aiff', '.aif'},
             {'.ogg', '.oga'}, {'.mp4', '.m4v'})
    return ext == want or any(ext in k and want in k for k in kinds)


def read_stdin(stream, max_bytes=None):
    max_bytes = max_bytes or MAX_STDIN
    data = stream.read(max_bytes + 1)
    if not data:
        raise UsageError('nothing on stdin')
    if len(data) > max_bytes:
        raise UsageError(f'stdin is over {max_bytes // (1024 * 1024)} MiB; share a file instead')
    return data


def plan(opts, stdin=None, home=None):
    """Work out what to run. Returns a dict: tool, mode, why, argv, stage
    (src, dest) or None, stdin_data (bytes to write first) or None, path."""
    home = home or os.path.expanduser('~')
    path = opts['path']
    stdin_data = None
    if path == '-':
        stdin_data = read_stdin(stdin if stdin is not None else sys.stdin.buffer)
        name = opts['name'] or f'stdin-{secrets.token_hex(2)}'
        path = os.path.join(rundir.tool_dir('share'),
                            name if name.startswith('stdin-') else f'stdin-{name}')
        sniff_src = stdin_data
    else:
        if not os.path.exists(path):
            raise UsageError(f'no such file or directory: {path}')
        path = os.path.realpath(path)
        if not (os.path.isdir(path) or os.path.isfile(path)):
            # a FIFO would block the sniff; a device is not a file to share
            raise UsageError(f'not a regular file or directory: {opts["path"]}')
        name = opts['name'] or default_name(path)
        sniff_src = None

    if opts.get('e2e'):
        return _plan_e2e(opts, path, name, stdin_data)

    if sniff_src is not None:
        # Route stdin from the bytes we hold (nothing on disk yet).
        sn = viewserver.sniff_bytes(sniff_src[:viewserver.SNIFF_BYTES], '',
                                    complete=len(sniff_src) <= viewserver.SNIFF_BYTES)
        tool, mode, why = _route_sniff(sn, opts['as'])
    else:
        tool, mode, sn, why = route(path, opts['as'])

    stage = None
    door = list(opts['door'])
    if tool == 'media':
        dest_dir = os.path.join(home, 'media', name)
        stage = (path, os.path.join(dest_dir, staged_name(path if stdin_data is None else 'stdin', sn, MEDIA_EXT)))
        argv = [os.path.join(BIN_DIR, 'media'), name, '--no-guest-upload', '--bg'] + door
    elif tool == 'music':
        dest_dir = os.path.join(home, 'music', name)
        stage = (path, os.path.join(dest_dir, staged_name(path if stdin_data is None else 'stdin', sn, MUSIC_EXT)))
        argv = [os.path.join(BIN_DIR, 'music'), name, '--bg'] + door
    elif tool == 'serve':
        # A folder without an index.html is shared as a listing: without
        # --list its door would answer 404 at /, which shares nothing.
        listing = [] if os.path.isfile(os.path.join(path, 'index.html')) else ['--list']
        argv = [os.path.join(BIN_DIR, 'serve'), path, name] + listing + ['--bg'] + door
    elif tool == 'paste':
        if stdin_data is not None:
            # bin/paste captures stdin itself and deletes its copy at exit
            argv = [os.path.join(BIN_DIR, 'paste'), name, '--bg'] + door
        else:
            argv = [os.path.join(BIN_DIR, 'paste'), name, path, '--bg'] + door
    else:
        argv = [os.path.join(BIN_DIR, 'view'), path, name]
        if opts['as'] and ':' in opts['as']:
            argv += ['--as', mode]
        if stdin_data is not None:
            argv += ['--owned-file']             # bin/view deletes it when the door closes
        argv += ['--bg'] + door
    return {'tool': tool, 'mode': mode, 'why': why, 'argv': argv, 'stage': stage,
            'stdin_data': stdin_data, 'path': path, 'name': name}


def _plan_e2e(opts, path, name, stdin_data):
    """--e2e: seal into the run dir, then bin/seal --owned-file."""
    if stdin_data is None and os.path.isdir(path):
        raise UsageError('--e2e shares one file; zip the folder first')
    if stdin_data is not None:
        sn = viewserver.sniff_bytes(stdin_data[:viewserver.SNIFF_BYTES], '',
                                    complete=len(stdin_data) <= viewserver.SNIFF_BYTES)
        ext = EXT_FOR_MIME.get(sn.mime) or ('.pdf' if sn.mime == 'application/pdf' else
                                           '.txt' if sn.mime.startswith('text/') else '')
        meta_name = 'stdin' + ext
    else:
        sn = viewserver.sniff_file(path)
        meta_name = os.path.basename(path)
    sealed = os.path.join(rundir.tool_dir('share'), f'{name}.pseal')
    argv = [os.path.join(BIN_DIR, 'seal'), sealed, name, '--owned-file', '--bg'] \
        + list(opts['door'])
    mode = 'password' if opts['seal_password'] else 'key'
    return {'tool': 'seal', 'mode': mode, 'why': f'end-to-end encrypted ({sn.mime})',
            'argv': argv, 'stage': None, 'stdin_data': stdin_data, 'path': path,
            'name': name, 'sealed': sealed, 'mime': sn.mime, 'meta_name': meta_name}


def read_seal_password(env=None, tty='/dev/tty'):
    """PORCH_SEAL_PASSWORD, else typed twice on the terminal. Never argv."""
    env = os.environ if env is None else env
    pw = env.get('PORCH_SEAL_PASSWORD')
    if not pw:
        try:
            with open(tty, 'r+'):
                pass
        except OSError:
            raise UsageError('--seal-password needs PORCH_SEAL_PASSWORD or a terminal to type it on')
        pw = getpass.getpass('Seal password: ')
        if getpass.getpass('Again: ') != pw:
            raise UsageError('the passwords do not match')
    if len(pw) < MIN_SEAL_PASSWORD:
        raise UsageError(f'the seal password needs at least {MIN_SEAL_PASSWORD} characters '
                         '(anyone with the ciphertext can guess offline)')
    return pw


def e2e_links(name, key, state_dir=None, tunnel_base=None):
    """(link, guest link or None), both carrying #k=<key> when there is one."""
    import porch_config
    base = tunnel_base or porch_config.get().tunnel_base
    frag = f'#k={key}' if key else ''
    link = f'https://{name}.{base}/{frag}'
    guest = None
    try:
        st = door_state.read_state(door_state.state_path(name, state_dir))
        tok = door_state.clean_rules(st.get('rules')).get('guest')
        if tok:
            guest = door_state.guest_url(name, tok, base) + frag
    except (OSError, ValueError):
        pass
    return link, guest


def _route_sniff(sn, as_):
    if as_:
        tool, _, mode = as_.partition(':')
        if tool not in AS_TOOLS or tool == 'serve':
            raise UsageError('stdin can go --as media, music, paste, view or view:<mode>')
        if mode and (tool != 'view' or mode not in viewserver.MODES):
            raise UsageError(f'--as view:<mode>, mode one of: {" ".join(viewserver.MODES)}')
        return tool, mode or None, f'--as {as_}'
    if sn.mode in ('image', 'video') and sn.mime in EXT_FOR_MIME:
        return 'media', None, f'{sn.mime} by content'
    if sn.mode == 'audio' and sn.mime in EXT_FOR_MIME:
        return 'music', None, f'{sn.mime} by content'
    return 'view', sn.mode, f'viewer mode {sn.mode}'


def do_stage(src, dest):
    """Copy src into the app's directory. Refuses a directory that already
    holds other files (they would be shared too), a directory that is a
    symlink, and a destination that appeared meanwhile (O_EXCL|O_NOFOLLOW:
    never written through a link)."""
    d = os.path.dirname(dest)
    if os.path.islink(d):
        raise UsageError(f'{d} is a symlink; pick another --name')
    if os.path.isdir(d) and any(not n.startswith('.') for n in os.listdir(d)):
        raise UsageError(f'{d} already has files in it (they would be shared too); '
                         'pick another --name')
    os.makedirs(d, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(dest, flags, 0o644)
    except FileExistsError:
        raise UsageError(f'{dest} already exists; pick another --name')
    try:
        with open(src, 'rb') as fin, os.fdopen(fd, 'wb') as fout:
            fd = None
            shutil.copyfileobj(fin, fout, 1024 * 1024)
    except BaseException:
        if fd is not None:
            os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(dest)
        raise


USAGE = __doc__.split('\n\n')[1]


def _run_with_input(argv, data):
    return subprocess.run(argv, input=data).returncode


def main(argv=None, stdin=None, run=subprocess.call, run_input=_run_with_input):
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        opts = parse_args(argv)
        p = plan(opts, stdin=stdin)
    except UsageError as e:
        if str(e) == 'help':
            print(__doc__.strip())
            return 0
        print(f'porch share: {e}', file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 2
    except OSError as e:
        print(f'porch share: {e}', file=sys.stderr)
        return 1
    what = 'stdin' if p['stdin_data'] is not None else p['path']
    detail = f" ({p['mode']})" if p['mode'] and p['tool'] in ('view', 'seal') else ''
    print(f"porch share: {what} -> {p['tool']}{detail}, {p['why']}")
    if p['tool'] == 'seal':
        return _run_e2e(opts, p, run)
    pipe = p['stdin_data'] is not None and p['tool'] == 'paste'
    if opts['dry_run']:
        if pipe:
            print(f"would pipe {len(p['stdin_data'])} bytes of stdin to bin/paste")
        elif p['stdin_data'] is not None:
            print(f"would write {len(p['stdin_data'])} bytes of stdin to {p['path']} (0600)")
        if p['stage']:
            print(f"would copy {p['stage'][0]} -> {p['stage'][1]}")
        print('command: ' + shlex.join(p['argv']))
        return 0
    if pipe:
        sys.stdout.flush()
        return 0 if run_input(p['argv'], p['stdin_data']) == 0 else 1
    owned = p['stdin_data'] is not None            # our 0600 copy in the run dir
    try:
        if owned:
            rundir.write_private(p['path'], p['stdin_data'])
        if p['stage']:
            do_stage(*p['stage'])
    except UsageError as e:
        print(f'porch share: {e}', file=sys.stderr)
        _forget(p['path'], owned)
        return 2
    except OSError as e:
        print(f'porch share: {e}', file=sys.stderr)
        _forget(p['path'], owned)
        return 1
    if p['stage']:
        _forget(p['path'], owned)                  # the app has its own copy now
    sys.stdout.flush()
    rc = run(p['argv'])
    if rc != 0 and not p['stage']:
        _forget(p['path'], owned)                  # no door came up to own it
    if rc == 0 and p['stage']:
        # The staged copy belongs to the door: kept 7 days after it expires or
        # is closed (reopen), shredded at once when it burns.
        with contextlib.suppress(Exception):
            door_recipe.add_staged(p['name'], p['stage'][1])
    return 0 if rc == 0 else 1


def _run_e2e(opts, p, run):
    if opts['dry_run']:
        if not porch_seal.available():
            print(f'note: python3-cryptography is missing ({porch_seal.APT_HINT})')
        src = f"{len(p['stdin_data'])} bytes of stdin (from memory)" if p['stdin_data'] is not None \
            else p['path']
        print(f"would seal {src} -> {p['sealed']} (0600, {p['mode']} mode)")
        print('command: ' + shlex.join(p['argv']))
        if p['mode'] == 'key':
            print(f"link: {e2e_links(p['name'], None)[0]}#k={KEY_PLACEHOLDER}")
        return 0
    if not porch_seal.available():
        print(f'porch share: --e2e needs python3-cryptography; install it with: '
              f'{porch_seal.APT_HINT}', file=sys.stderr)
        return 3
    try:
        password = read_seal_password() if opts['seal_password'] else None
        src = io.BytesIO(p['stdin_data']) if p['stdin_data'] is not None else p['path']
        key = porch_seal.seal_file(src, p['sealed'], p['meta_name'], p['mime'], password=password)
    except UsageError as e:
        print(f'porch share: {e}', file=sys.stderr)
        return 2
    except FileExistsError:
        print(f"porch share: {p['sealed']} already exists; pick another --name", file=sys.stderr)
        return 2
    except (OSError, ValueError) as e:
        print(f'porch share: {e}', file=sys.stderr)
        return 1
    sys.stdout.flush()
    rc = run(p['argv'])
    if rc != 0:
        _forget(p['sealed'], True)                 # no door came up to own it
        return 1
    link, guest = e2e_links(p['name'], key)
    if key:
        print(f'Link (end-to-end encrypted; the key is the part after #, share it whole): {link}')
    else:
        print(f'Link: {link}  (sealed with a password: send it to the recipient separately)')
    if guest:
        print(f'Guest link (door gate skipped{", key included" if key else ""}): {guest}')
    sys.stdout.flush()
    return 0


def _forget(path, owned):
    if owned:
        with contextlib.suppress(OSError):
            os.unlink(path)


if __name__ == '__main__':
    sys.exit(main())

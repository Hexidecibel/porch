"""porch mcp: a Model Context Protocol server over stdio (lib/porch_setup/cmd_mcp.py).

Hand-written JSON-RPC 2.0, one JSON message per line on stdin/stdout (the MCP
stdio transport). stdout carries protocol messages only; every log line goes
to stderr. The tools drive the existing launchers (bin/*, bin/porch ...)
through argv lists with a timeout and bounded output: never a shell.

Safety rules (docs/mcp.md):
- paths are resolved and must exist; obvious secret files are refused unless
  allow_sensitive is true, and private keys / data/devices.json always are;
- a door password is never an argument: `password_env` names an env var of
  this server, whose value reaches the launcher as PORCH_DOOR_PASSWORD (env);
- ask_secret never reads the secret: waiting only watches a signal file that
  bin/secure-entry touches after it has stored the value.
"""

import contextlib
import json
import os
import pty
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import time

LIB_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(LIB_DIR)
BIN_DIR = os.path.join(REPO_DIR, 'bin')
if LIB_DIR not in sys.path:
    sys.path.insert(0, LIB_DIR)
import rundir  # noqa: E402

SERVER_NAME = 'porch'
SERVER_VERSION = '0.1.0'
PROTOCOL_VERSIONS = ('2025-06-18', '2025-03-26', '2024-11-05')   # newest first

PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL_ERROR = (
    -32700, -32600, -32601, -32602, -32603)

NAME_RE = re.compile(r'^[a-z0-9][a-z0-9-]{0,40}$')
ENV_NAME_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,63}$')
EXPIRES_RE = re.compile(r'^(?:never|[0-9]{1,6}[smhd]|[0-9]{4}-[0-9]{2}-[0-9]{2}[0-9T:.+Z-]{0,24})$')
FIELD_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}(?::(?:string|file|ssh))?$')
REF_RE = re.compile(r'^(?:inf|op)://[A-Za-z0-9][^\s]{0,500}$')
AS_RE = re.compile(r'^(?:media|music|serve|paste|view)(?::[a-z]{1,16})?$')
URL_RE = re.compile(r'https://[^\s)\'"<>]+')
PRIVATE_KEY_RE = re.compile(rb'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----')

MAX_OUTPUT = 64 * 1024          # bytes kept from each of a child's stdout/stderr
MAX_TEXT = 8 * 1024 * 1024      # text sent to share/paste/exchange/clip
RUN_TIMEOUT = 60                # seconds for one launcher run
MAX_WAIT = 3600
POLL = 1.0
DIR_SCAN_LIMIT = 20000          # entries looked at when vetting a shared directory


def log(msg):
    sys.stderr.write(f'porch mcp: {msg}\n')
    sys.stderr.flush()


class ToolError(Exception):
    """A tool failed: reported as an isError result, not a protocol error."""


class ParamsError(Exception):
    """Arguments do not match the tool's inputSchema: JSON-RPC -32602."""


class LaunchTimeout(ToolError):
    """A launcher ran past its timeout (its process group was killed)."""


# ---- running launchers ----------------------------------------------------------

def _clip(data):
    if len(data) > MAX_OUTPUT:
        data = data[:MAX_OUTPUT] + b'\n[... output truncated]'
    return data.decode('utf-8', 'replace')


def run_cmd(argv, stdin=None, env=None, timeout=RUN_TIMEOUT, tty_stdin=False):
    """Run argv (a list; never a shell). Returns (rc, stdout, stderr), each
    output bounded. stdout/stderr go to temp files, not pipes, so a daemon that
    kept a descriptor cannot hang us; stdin is the given bytes, /dev/null, or
    (tty_stdin) a fresh pty for launchers that pick a mode with `[ -t 0 ]`.
    The child gets its own session: no controlling terminal, so a launcher can
    never stop to prompt."""
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        raise TypeError('argv must be a list of strings')
    master = slave = None
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err, \
            tempfile.TemporaryFile() as inp:
        if tty_stdin:
            master, slave = pty.openpty()
            stdin_arg = slave
        elif stdin is not None:
            inp.write(stdin if isinstance(stdin, bytes) else stdin.encode('utf-8'))
            inp.seek(0)
            stdin_arg = inp
        else:
            stdin_arg = subprocess.DEVNULL
        try:
            proc = subprocess.Popen(argv, stdin=stdin_arg, stdout=out, stderr=err, env=env,
                                    cwd=REPO_DIR, start_new_session=True, close_fds=True)
        except OSError as e:
            raise ToolError(f'could not run {os.path.basename(argv[0])}: {e}')
        finally:
            if slave is not None:
                os.close(slave)
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(OSError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            raise LaunchTimeout(f'{os.path.basename(argv[0])} timed out after {timeout}s')
        finally:
            if master is not None:
                os.close(master)
        out.seek(0)
        err.seek(0)
        return rc, _clip(out.read(MAX_OUTPUT + 1)), _clip(err.read(MAX_OUTPUT + 1))


def porch_argv(*args):
    return [sys.executable, os.path.join(BIN_DIR, 'porch')] + list(args)


def bin_argv(tool, *args):
    return [os.path.join(BIN_DIR, tool)] + list(args)


def _trim(text, n=2000):
    text = (text or '').strip()
    return text if len(text) <= n else '...' + text[-n:]


# ---- sensitive paths ------------------------------------------------------------

def _home():
    return os.path.realpath(os.path.expanduser('~'))


def _under(path, root):
    """path is root or below it. Case-insensitive, so ~/.SSH on a
    case-insensitive filesystem (macOS) counts as ~/.ssh; on Linux that only
    ever refuses more."""
    path, root = path.casefold(), (root.rstrip('/') or '/').casefold()
    return path == root or path.startswith(root.rstrip('/') + '/')


# Credential stores under $HOME: refused unless allow_sensitive (soft).
SENSITIVE_HOME = ('.ssh', '.gnupg', '.aws', '.azure', '.kube', '.docker/config.json',
                  '.netrc', '.git-credentials', '.pgpass', '.password-store',
                  '.config/cush-tools', '.config/porch', '.config/infisical', '.config/gh/hosts.yml',
                  '.config/gcloud', '.local/share/porch', '.config/namecom')
SENSITIVE_SCAN_LIMIT = 5000      # files looked at when matching hardlinks


def _sensitive_roots(repo, home):
    roots = [os.path.join(home, r) for r in SENSITIVE_HOME]
    roots += [os.path.join(repo, 'data'), os.path.join(repo, 'config', 'frps.toml'),
              os.path.join(repo, 'config', 'frpc.toml')]
    return roots


def _sensitive_inodes(repo, home):
    """(dev, ino) of the files in the sensitive places: a hard link to one of
    them has another name and another directory, but the same inode."""
    out, seen = set(), 0
    links = os.path.join(repo, 'data', 'links.json')
    for root in _sensitive_roots(repo, home):
        if os.path.isfile(root):
            walk = [(os.path.dirname(root), [], [os.path.basename(root)])]
        else:
            walk = os.walk(root)
        for d, _dirs, files in walk:
            for fn in files:
                full = os.path.join(d, fn)
                if full == links:
                    continue
                seen += 1
                if seen > SENSITIVE_SCAN_LIMIT:
                    return out
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                out.add((st.st_dev, st.st_ino))
    return out


def _has_private_key(path):
    try:
        with open(path, 'rb') as f:
            return bool(PRIVATE_KEY_RE.search(f.read(256 * 1024)))
    except OSError:
        return False


def classify(path, repo=None, home=None):
    """(level, reason) for one resolved path: level 'hard' (always refused),
    'soft' (refused unless allow_sensitive) or None."""
    repo = os.path.realpath(repo or REPO_DIR)
    home = home or _home()
    base = os.path.basename(path)
    low = base.lower()
    if path == os.path.join(repo, 'data', 'devices.json'):
        return 'hard', 'the device registry (data/devices.json)'
    if re.match(r'^id_(rsa|dsa|ecdsa|ed25519)(_sk)?$', low) or low.endswith('.key'):
        return 'hard', f'a private key ({base})'
    if os.path.isfile(path) and _has_private_key(path):
        return 'hard', f'a file holding a private key ({base})'
    if low.startswith('.env'):
        return 'soft', f'an environment file ({base})'
    if low.endswith(('.pem', '.p12', '.pfx')) or low.startswith('id_rsa'):
        return 'soft', f'a key or certificate file ({base})'
    for r in SENSITIVE_HOME:
        if _under(path, os.path.join(home, r)):
            return 'soft', f'~/{r}'
    if path in (os.path.join(repo, 'config', 'frps.toml'), os.path.join(repo, 'config', 'frpc.toml')):
        return 'soft', f'the frp config with its token (config/{base})'
    data = os.path.join(repo, 'data')
    if _under(path, data) and path != os.path.join(data, 'links.json'):
        return 'soft', 'porch data/ (only data/links.json is shareable)'
    try:
        st = os.stat(path)
    except OSError:
        st = None
    if st is not None and st.st_nlink > 1 and os.path.isfile(path) and \
            (st.st_dev, st.st_ino) in _sensitive_inodes(repo, home):
        return 'soft', f'a hard link to a file in a sensitive place ({base})'
    return None, None


def vet_path(path, allow_sensitive=False, want=None, repo=None, home=None):
    """Resolve an agent-given path and refuse what must not be shared.
    want: 'file', 'dir' or None. Returns the resolved path."""
    if not isinstance(path, str) or not path.strip():
        raise ToolError('path is empty')
    p = os.path.realpath(os.path.expanduser(path))
    if not os.path.exists(p):
        raise ToolError(f'no such file or directory: {path}')
    if want == 'file' and not os.path.isfile(p):
        raise ToolError(f'not a file: {path}')
    if want == 'dir' and not os.path.isdir(p):
        raise ToolError(f'not a directory: {path}')
    repo_r = os.path.realpath(repo or REPO_DIR)
    home_r = home or _home()

    def check(one, label=None):
        level, why = classify(one, repo_r, home_r)
        where = f' ({label})' if label else ''
        if level == 'hard':
            raise ToolError(f'refused: {why}{where} is never shared')
        if level == 'soft' and not allow_sensitive:
            raise ToolError(f'refused: {why}{where} looks sensitive; pass allow_sensitive: true '
                            'if you really mean to share it')

    check(p)
    if os.path.isdir(p):
        # A folder that holds porch's own secrets is refused outright.
        for inner in (os.path.join(repo_r, 'data'), os.path.join(repo_r, 'config')):
            if _under(inner, p) and os.path.isdir(inner):
                if os.path.exists(os.path.join(repo_r, 'data', 'devices.json')) or \
                        os.path.exists(os.path.join(repo_r, 'config', 'frps.toml')):
                    raise ToolError('refused: this folder contains porch data/ or config/ '
                                    '(device registry, frp tokens); share a subfolder')
        for inner in (os.path.join(home_r, '.ssh'), os.path.join(home_r, '.config', 'cush-tools')):
            if _under(inner, p) and os.path.isdir(inner) and not allow_sensitive:
                raise ToolError(f'refused: this folder contains {inner}; share a subfolder '
                                '(or pass allow_sensitive: true)')
        # bin/serve never serves dotfiles; look at what it would serve.
        seen = 0
        for root, dirs, files in os.walk(p):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for d in dirs:
                full = os.path.join(root, d)
                if os.path.islink(full):
                    # os.walk does not descend into it; bin/serve refuses a
                    # link that leaves the folder, but say no up front when
                    # it points somewhere sensitive.
                    check(os.path.realpath(full), os.path.relpath(full, p))
            for fn in files:
                if fn.startswith('.'):
                    continue
                seen += 1
                if seen > DIR_SCAN_LIMIT:
                    raise ToolError(f'refused: the folder has over {DIR_SCAN_LIMIT} files; '
                                    'share a smaller one')
                full = os.path.join(root, fn)
                check(os.path.realpath(full), os.path.relpath(full, p))
    return p


# ---- argument helpers -------------------------------------------------------------

def _default_share_name(target):
    """The name porch share would pick: <slug>-<4 hex>, stdin-<4 hex> for text."""
    if target == '-':
        return f'stdin-{secrets.token_hex(2)}'
    try:
        from porch_setup import cmd_share
        return cmd_share.default_name(target)
    except Exception:                                   # noqa: BLE001
        return f'share-{secrets.token_hex(2)}'


def check_name(name, what='name'):
    if not isinstance(name, str) or not NAME_RE.match(name) or name.endswith('-'):
        raise ToolError(f'invalid {what} {name!r}: 1-41 chars of [a-z0-9-], starting with a '
                        "letter or digit, not ending with '-'")
    return name


def door_flags(args, env):
    """argv flags for expires/password_env/guest_link/burn/max_opens/inspect;
    fills env with PORCH_DOOR_PASSWORD when a password is asked for."""
    out = []
    exp = args.get('expires')
    if exp is not None:
        if not EXPIRES_RE.match(exp):
            raise ToolError(f'invalid expires {exp!r}: use 30m, 2h, 1d, an ISO-8601 time or never')
        out += ['--expires', exp]
    pw_env = args.get('password_env')
    if pw_env is not None:
        if not ENV_NAME_RE.match(pw_env):
            raise ToolError('password_env must be the NAME of an environment variable')
        value = os.environ.get(pw_env)
        if not value:
            raise ToolError(f'password_env: ${pw_env} is not set (or empty) in the MCP '
                            "server's environment")
        env['PORCH_DOOR_PASSWORD'] = value
        out.append('--password')
    if args.get('guest_link'):
        out.append('--guest-link')
    if args.get('burn'):
        out.append('--burn')
    elif args.get('max_opens') is not None:
        out += ['--max-opens', str(args['max_opens'])]
    if args.get('inspect'):
        out.append('--inspect')
    return out


def child_env():
    env = dict(os.environ)
    env.pop('PORCH_DOOR_PASSWORD', None)        # only ever set from password_env
    env.pop('_PORCH_DOOR_SPEC', None)
    env.pop('_CUSH_DAEMONIZED', None)
    return env


def parse_urls(text):
    """(main url, guest link) from a launcher's output."""
    guest = None
    main = None
    for line in text.splitlines():
        urls = URL_RE.findall(line)
        if not urls:
            continue
        if line.strip().lower().startswith('guest link'):
            guest = guest or urls[0]
        elif main is None:
            main = urls[0]
    return main, guest


def _redact(text, env):
    pw = env.get('PORCH_DOOR_PASSWORD')
    if pw and text:
        text = text.replace(pw, '[password]')
    return text


def _label(argv):
    if argv[0] == sys.executable and len(argv) > 1:
        if argv[1].endswith('cmd_share.py'):
            return 'porch share'
        if os.path.basename(argv[1]) == 'porch' and len(argv) > 2:
            return 'porch ' + argv[2]
        return os.path.basename(argv[1])
    return os.path.basename(argv[0])


def _launch(argv, env, stdin=None, tty_stdin=False, runner=None):
    rc, out, err = (runner or run_cmd)(argv, stdin=stdin, env=env, tty_stdin=tty_stdin)
    out, err = _redact(out, env), _redact(err, env)
    if rc != 0:
        raise ToolError(f'{_label(argv)} failed (exit {rc}): '
                        f'{_trim(err) or _trim(out) or "no output"}')
    return out, err


def _text_arg(args, key):
    t = args.get(key)
    if t is None:
        return None
    if not t:
        raise ToolError(f'{key} is empty')
    data = t.encode('utf-8')
    if len(data) > MAX_TEXT:
        raise ToolError(f'{key} is over {MAX_TEXT // (1024 * 1024)} MiB; write it to a file and share that')
    if PRIVATE_KEY_RE.search(data):
        raise ToolError(f'refused: {key} contains a private key')
    return data


# ---- tool schemas -------------------------------------------------------------------

_NAME = {'type': 'string', 'pattern': NAME_RE.pattern, 'maxLength': 41,
         'description': 'Door name: becomes https://<name>.<tunnel base>. 1-41 chars of '
                        "[a-z0-9-], starting with a letter or digit."}
_DOOR_PROPS = {
    'expires': {'type': 'string', 'maxLength': 40,
                'description': 'When the door closes: 30m, 2h, 1d, an ISO-8601 time, or "never". '
                               'Default 1h.'},
    'password_env': {'type': 'string', 'pattern': ENV_NAME_RE.pattern,
                     'description': 'Password-protect the door. This is the NAME of an environment '
                                    "variable in the MCP server's environment (e.g. "
                                    '"PORCH_SHARE_PW") whose value becomes the password; never pass '
                                    'the password itself. It is handed to the launcher as '
                                    'PORCH_DOOR_PASSWORD, not on the command line.'},
    'guest_link': {'type': 'boolean',
                   'description': 'Also mint a guest link (?k=token) that opens the door without '
                                  'the password. Returned as guest_link.'},
    'burn': {'type': 'boolean', 'description': 'Close the door after its first open (= max_opens 1).'},
    'max_opens': {'type': 'integer', 'minimum': 1, 'maximum': 100000,
                  'description': 'Close the door after this many page opens.'},
}
_WAIT = {'type': 'integer', 'minimum': 0, 'maximum': MAX_WAIT,
         'description': 'Block up to this many seconds for the result before returning '
                        '(0 = return right away). Max 3600.'}


def _schema(props, required=()):
    return {'type': 'object', 'properties': props, 'required': list(required),
            'additionalProperties': False}


TOOLS = [
    {
        'name': 'share',
        'description': 'Share a local file, folder, or a piece of text as a public web page '
                       '("door") and return its https URL. The app is picked from the content: '
                       'images/video -> gallery, audio -> player, folder -> static site, anything '
                       'else -> a read-only viewer (markdown, code, pdf, csv, json, zip, diff). '
                       'Give either path or text. The door expires after 1h unless expires says '
                       'otherwise. Secret-looking files (.env, keys, ~/.ssh, porch data) are '
                       'refused unless allow_sensitive is true; private keys always are.',
        'inputSchema': _schema(dict({
            'path': {'type': 'string', 'description': 'File or folder to share (absolute, ~ or '
                                                      'relative to the server cwd).'},
            'text': {'type': 'string', 'description': 'Text to share instead of a path (sent on '
                                                      'stdin, routed like a file).'},
            'as': {'type': 'string', 'pattern': AS_RE.pattern,
                   'description': 'Force the app: media, music, serve, paste, view, or '
                                  'view:<mode> (markdown code text pdf csv tsv json zip diff '
                                  'image video audio other).'},
            'name': dict(_NAME, description='Door name (default: derived from the file name). '
                                            + _NAME['description']),
            'allow_sensitive': {'type': 'boolean',
                                'description': 'Allow sharing a file that looks secret (.env, '
                                               '.pem, ~/.ssh, porch data/). Private keys and the '
                                               'device registry are refused regardless.'},
            'e2e': {'type': 'boolean',
                    'description': 'End-to-end encrypt (porch share --e2e): the box only holds '
                                   'ciphertext and the returned url carries the decryption key '
                                   'in its #k= fragment, so hand the url over whole and treat '
                                   'it like the file itself. One file or text only (no folders, '
                                   'no "as"). With burn/max_opens, complete downloads are '
                                   'counted, not page views. Needs python3-cryptography.'},
        }, **_DOOR_PROPS)),
    },
    {
        'name': 'receive_file',
        'description': 'Open an upload page where anyone with the link can send files to this '
                       'machine. Returns the public URL and the folder files land in '
                       '(~/drops/<name>/). With wait_seconds it waits for the first completed '
                       'upload and returns its path and size. The page expires after 1h unless '
                       'expires says otherwise.',
        'inputSchema': _schema({
            'name': dict(_NAME, description='Drop name (default: drop-<random>). '
                                            + _NAME['description']),
            'wait_seconds': _WAIT,
            'expires': _DOOR_PROPS['expires'],
        }),
    },
    {
        'name': 'ask_secret',
        'description': 'Ask the user for a secret (API key, password) through a one-time web form '
                       'instead of the chat. Returns the exact form URL to give the user and where '
                       'the secret will be stored (a 0600 file path, or the inf:// / op:// ref '
                       'given in save_to). The secret value is NEVER returned: read it yourself '
                       'from the path only if the task needs it. With wait_seconds it waits until '
                       'the secret has been stored and reports only that it arrived. The form '
                       'expires after 1h.',
        'inputSchema': _schema({
            'label': {'type': 'string', 'pattern': NAME_RE.pattern, 'maxLength': 41,
                      'description': 'Short label; the form is at '
                                     'https://entry-<label>.<tunnel base>/<token>/.'},
            'fields': {'type': 'array', 'maxItems': 20,
                       'items': {'type': 'string', 'pattern': FIELD_RE.pattern},
                       'description': 'Several secrets in one form: field names, optionally '
                                      'name:file or name:ssh.'},
            'save_to': {'type': 'string', 'pattern': REF_RE.pattern,
                        'description': 'Store straight into a secrets backend instead of disk: '
                                       'inf://<env>/<project>/<KEY> (Infisical) or '
                                       'op://Vault/Item/field (1Password). With fields, give the '
                                       'item/path without the trailing key.'},
            'wait_seconds': _WAIT,
        }, ['label']),
    },
    {
        'name': 'open_door',
        'description': 'Start one porch door directly and return its public https URL. type: '
                       'tunnel (expose a local port), serve (a folder as a static site), paste '
                       '(text with syntax highlighting), exchange (send text with a Copy button, '
                       'or without content a form the user pastes text into), hook (a webhook '
                       'catcher; see inspect_requests), pocket (owner-only phone share target + '
                       'clipboard; never expires by default), view (one file in a read-only '
                       'viewer). Doors expire after 1h unless expires says otherwise.',
        'inputSchema': _schema(dict({
            'type': {'type': 'string', 'enum': ['tunnel', 'serve', 'paste', 'exchange', 'hook',
                                                'pocket', 'view']},
            'name': _NAME,
            'port': {'type': 'integer', 'minimum': 1, 'maximum': 65535,
                     'description': 'tunnel: the local port to expose.'},
            'path': {'type': 'string', 'description': 'serve: a folder; view: a file. Must exist.'},
            'content': {'type': 'string', 'description': 'paste: the text (required). exchange: '
                                                         'text to send; omit to receive.'},
            'allow_sensitive': {'type': 'boolean', 'description': 'serve/view: allow a path that '
                                                                  'looks secret (see share).'},
            'inspect': {'type': 'boolean', 'description': 'Record every request (see '
                                                          'inspect_requests). Hooks always do.'},
        }, **_DOOR_PROPS), ['type', 'name']),
    },
    {
        'name': 'close_door',
        'description': 'Close a running door (any porch tool) by name; its URL stops working.',
        'inputSchema': _schema({'name': _NAME}, ['name']),
    },
    {
        'name': 'list_doors',
        'description': 'List running doors: name, type, public url, expiry (epoch, null = never), '
                       'share rules, open count, guest link.',
        'inputSchema': _schema({}),
    },
    {
        'name': 'extend_door',
        'description': "Change a running door's expiry: 30m, 2h, 1d (from now), an ISO-8601 time, "
                       'or "never".',
        'inputSchema': _schema({'name': _NAME, 'expires': dict(_DOOR_PROPS['expires'], description=(
            'New expiry: 30m, 2h, 1d from now, an ISO-8601 time, or "never".'))},
            ['name', 'expires']),
    },
    {
        'name': 'inspect_requests',
        'description': 'Requests an inspected door or webhook (open_door type hook, or inspect: '
                       'true) received, oldest first when since_id is given, else the newest. '
                       'Secret headers (Authorization, Cookie, *token*) are already masked.',
        'inputSchema': _schema({
            'name': _NAME,
            'since_id': {'type': 'integer', 'minimum': 0,
                         'description': 'Only requests with a larger id (for polling).'},
            'limit': {'type': 'integer', 'minimum': 1, 'maximum': 500,
                      'description': 'How many to return (default 20).'},
        }, ['name']),
    },
    {
        'name': 'clip_get',
        'description': "Read the current text of the user's Pocket clipboard (shared with their "
                       'phone). Needs a running pocket door (open_door type pocket).',
        'inputSchema': _schema({'pocket': dict(_NAME, description='Pocket door name (default '
                                                                  'pocket).')}),
    },
    {
        'name': 'clip_set',
        'description': "Set the user's Pocket clipboard text; every signed-in device (their phone) "
                       'sees it live. Needs a running pocket door.',
        'inputSchema': _schema({
            'text': {'type': 'string', 'minLength': 1},
            'pocket': dict(_NAME, description='Pocket door name (default pocket).'),
        }, ['text']),
    },
]
TOOL_BY_NAME = {t['name']: t for t in TOOLS}


def validate(schema, value, where='arguments'):
    """A small JSON Schema subset: the keywords the TOOLS above use."""
    t = schema.get('type')
    types = {'object': dict, 'array': list, 'string': str, 'boolean': bool}
    if t == 'integer':
        if not isinstance(value, int) or isinstance(value, bool):
            raise ParamsError(f'{where} must be an integer')
    elif t in types and not isinstance(value, types[t]):
        raise ParamsError(f'{where} must be a{"n" if t[0] in "ao" else ""} {t}')
    if 'enum' in schema and value not in schema['enum']:
        raise ParamsError(f'{where} must be one of {", ".join(map(str, schema["enum"]))}')
    if t == 'integer':
        if 'minimum' in schema and value < schema['minimum']:
            raise ParamsError(f'{where} must be >= {schema["minimum"]}')
        if 'maximum' in schema and value > schema['maximum']:
            raise ParamsError(f'{where} must be <= {schema["maximum"]}')
    if t == 'string':
        if 'minLength' in schema and len(value) < schema['minLength']:
            raise ParamsError(f'{where} is too short')
        if 'maxLength' in schema and len(value) > schema['maxLength']:
            raise ParamsError(f'{where} is too long')
        if 'pattern' in schema and not re.search(schema['pattern'], value):
            raise ParamsError(f'{where} has an invalid format')
    if t == 'array':
        if 'maxItems' in schema and len(value) > schema['maxItems']:
            raise ParamsError(f'{where} has too many items')
        for i, item in enumerate(value):
            validate(schema.get('items', {}), item, f'{where}[{i}]')
    if t == 'object':
        props = schema.get('properties', {})
        for k in schema.get('required', []):
            if k not in value:
                raise ParamsError(f'missing required argument: {k}')
        for k, v in value.items():
            if k not in props:
                if schema.get('additionalProperties') is False:
                    raise ParamsError(f'unknown argument: {k}')
                continue
            validate(props[k], v, k)


# ---- tools ------------------------------------------------------------------------

class Tools:
    """The tool implementations. `runner(argv, stdin=, env=, tty_stdin=)` ->
    (rc, out, err) is injectable for tests, as are sleep/clock and home."""

    def __init__(self, runner=None, sleep=time.sleep, clock=time.monotonic, home=None,
                 secret_dir=None):
        self.runner = runner or run_cmd
        self.sleep = sleep
        self.clock = clock
        self.home = home
        self.secret_dir = secret_dir

    def _home(self):
        return self.home or _home()

    def _launch(self, argv, env, stdin=None, tty_stdin=False, door=None):
        """door: the door name this launch opens. A launcher that times out
        may already have daemonized (its own session, so killing the group
        misses it) and opened the door: close it, so nothing is left open
        that the agent was never told about."""
        try:
            return _launch(argv, env, stdin=stdin, tty_stdin=tty_stdin, runner=self.runner)
        except LaunchTimeout as e:
            if not door:
                raise
            try:
                self.runner(bin_argv('status', 'close', door), env=child_env())
            except Exception as e2:                     # noqa: BLE001
                log(f'closing {door} after a timeout: {type(e2).__name__}')
            raise LaunchTimeout(f'{e}; closed door {door} in case it had opened')

    def _json(self, argv):
        out, _ = self._launch(argv, child_env())
        try:
            return json.loads(out)
        except ValueError:
            raise ToolError(f'unexpected output from {" ".join(argv[1:3])}: {_trim(out, 300)}')

    # share -----------------------------------------------------------------
    def share(self, a):
        if ('path' in a) == ('text' in a):
            raise ToolError('give exactly one of path or text')
        env = child_env()
        flags = door_flags(a, env)
        if a.get('name') is not None:
            check_name(a['name'])
        share_py = os.path.join(LIB_DIR, 'porch_setup', 'cmd_share.py')
        if not os.path.exists(share_py):
            raise ToolError('porch share is not installed on this machine yet '
                            '(lib/porch_setup/cmd_share.py is missing)')
        e2e = bool(a.get('e2e'))
        if e2e and a.get('as'):
            raise ToolError('e2e always uses the sealed viewer; drop "as"')
        stdin = None
        if 'text' in a:
            stdin = _text_arg(a, 'text')
            target = '-'
        else:
            target = vet_path(a['path'], bool(a.get('allow_sensitive')), home=self._home())
            if e2e and os.path.isdir(target):
                raise ToolError('e2e shares one file; zip the folder first')
        # Always name the door here, so a timed-out launch can be closed.
        name = a.get('name') or _default_share_name(target)
        argv = porch_argv('share', target)
        if a.get('as'):
            argv += ['--as', a['as']]
        argv += ['--name', name]
        if e2e:
            argv.append('--e2e')
        argv += flags
        try:
            out, err = self._launch(argv, env, stdin=stdin, door=name)
        except ToolError as e:
            if e2e and 'python3-cryptography' in str(e):
                raise ToolError('e2e needs python3-cryptography on this machine '
                                '(sudo apt install python3-cryptography)')
            raise
        if e2e:
            # The key-bearing lines porch share prints after the launcher's
            # own (keyless) URL. Returned to the caller, never logged.
            url = guest = None
            for line in out.splitlines():
                urls = URL_RE.findall(line)
                low = line.strip().lower()
                if urls and low.startswith('link'):
                    url = url or urls[0]
                elif urls and low.startswith('guest link (door gate skipped'):
                    guest = guest or urls[0]
            if not url:
                raise ToolError(f'porch share --e2e printed no link (exit 0); see logs/{name}.log')
        else:
            url, guest = parse_urls(out)
        if not url:
            raise ToolError(f'porch share printed no URL: {_trim(out + err, 500)}')
        m = re.search(r'^porch share: .* -> (\w+)(?: \(([\w-]+)\))?, ', out, re.M)
        tool = m.group(1) if m else None
        mode = m.group(2) if m else None
        name_m = re.match(r'https://([a-z0-9-]+)\.', url)
        res = {'url': url, 'name': name_m.group(1) if name_m else name,
               'type': tool, 'viewer_mode': mode, 'guest_link': guest,
               'expires': a.get('expires', '1h')}
        if e2e:
            res['e2e'] = True
            res['viewer_mode'] = None
            text = (f'Shared end-to-end encrypted at {url}\nThe key is the part after #: '
                    'share the whole link; whoever holds it can decrypt the file.')
            if guest:
                text += f'\nGuest link: {guest}'
            return text, res
        text = f'Shared at {url}' + (f' (as {tool}{" " + mode if mode else ""})' if tool else '')
        if guest:
            text += f'\nGuest link: {guest}'
        return text, res

    # receive_file -------------------------------------------------------------
    def _drop_files(self, d):
        found = {}
        try:
            names = os.listdir(d)
        except OSError:
            return found
        for n in names:
            if n.startswith('.') or n.endswith(('.part', '.tmp')):
                continue
            p = os.path.join(d, n)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if os.path.isfile(p) and not os.path.islink(p):
                found[p] = (st.st_size, st.st_mtime_ns)
        return found

    def receive_file(self, a):
        name = a.get('name') or f'drop-{secrets.token_hex(3)}'
        check_name(name)
        env = child_env()
        flags = door_flags({'expires': a.get('expires')}, env)
        d = os.path.join(self._home(), 'drops', name)
        before = self._drop_files(d)
        out, _ = self._launch(bin_argv('drop', name, '--bg', *flags), env, door=name)
        url, _g = parse_urls(out)
        url = url or None
        res = {'url': url, 'name': name, 'directory': d + '/', 'expires': a.get('expires', '1h')}
        text = f'Upload page: {url}\nFiles land in: {d}/'
        wait = a.get('wait_seconds') or 0
        if wait:
            files = self._wait_files(d, before, wait)
            res['files'] = files
            res['timed_out'] = not files
            text += ('\nReceived:\n' + '\n'.join(f'  {f["path"]} ({f["size"]} bytes)' for f in files)
                     if files else f'\nNo file arrived within {wait}s.')
        return text, res

    def _wait_files(self, d, before, wait):
        deadline = self.clock() + wait
        last = {}
        while True:
            now = self._drop_files(d)
            new = {p: v for p, v in now.items() if before.get(p) != v}
            # Completed = unchanged since the previous look (uploads go to a
            # dot .part file first, but be safe against a slow rename).
            stable = [p for p, v in new.items() if last.get(p) == v]
            if stable:
                return [{'path': p, 'size': new[p][0]} for p in sorted(stable)]
            last = new
            if self.clock() >= deadline:
                return []
            self.sleep(POLL)

    # ask_secret -----------------------------------------------------------------
    def ask_secret(self, a):
        label = check_name(a['label'], 'label')
        fields = a.get('fields') or []
        save_to = a.get('save_to')
        sig_dir = self.secret_dir
        if sig_dir is None:
            sig_dir = rundir.tool_dir('mcp')
        signal_file = os.path.join(sig_dir, f'secret-{label}-{secrets.token_hex(6)}.signal')
        argv = bin_argv('secure-entry', label)
        if save_to:
            argv += ['--save-to-secrets', save_to]
        for f in fields:
            argv += ['--field', f]
        argv += ['--signal-file', signal_file, '--bg']
        out, err = self._launch(argv, child_env(), door=f'entry-{label}')
        url = None
        stored = save_to
        for line in out.splitlines():
            if line.startswith('Secure entry:'):
                m = URL_RE.search(line)
                url = m.group(0) if m else None
            m = re.match(r'^Secrets? will be (?:saved|written) to: (.+?)(?: \(no disk\))?$', line)
            if m:
                stored = m.group(1).strip()
        if not url:
            raise ToolError(f'secure-entry printed no URL: {_trim(err, 300)}')
        res = {'url': url, 'label': label, 'stored_at': stored, 'fields': fields or None}
        text = (f'Give the user this exact URL: {url}\nThe secret will be stored at: {stored}\n'
                'The value is never shown here.')
        wait = a.get('wait_seconds') or 0
        if wait:
            deadline = self.clock() + wait
            arrived = os.path.exists(signal_file)
            while not arrived and self.clock() < deadline:
                self.sleep(POLL)
                arrived = os.path.exists(signal_file)
            res['arrived'] = arrived
            text += ('\nThe secret has arrived and is stored at: ' + stored if arrived
                     else f'\nNo secret yet after {wait}s.')
            if arrived:
                with contextlib.suppress(OSError):
                    os.unlink(signal_file)
        return text, res

    # open_door ----------------------------------------------------------------------
    def open_door(self, a):
        typ, name = a['type'], check_name(a['name'])
        env = child_env()
        flags = door_flags(a, env)
        stdin, tty = None, False
        allow = bool(a.get('allow_sensitive'))
        for k, only in (('port', ('tunnel',)), ('path', ('serve', 'view')),
                        ('content', ('paste', 'exchange'))):
            if k in a and typ not in only:
                raise ToolError(f'{k} is for type {" / ".join(only)}, not {typ}')
        if typ == 'tunnel':
            if 'port' not in a:
                raise ToolError('type tunnel needs port')
            argv = bin_argv('tunnel', str(a['port']), name, '--bg', *flags)
        elif typ == 'serve':
            if 'path' not in a:
                raise ToolError('type serve needs path (a folder)')
            p = vet_path(a['path'], allow, want='dir', home=self._home())
            argv = bin_argv('serve', p, name, '--bg', *flags)
        elif typ == 'view':
            if 'path' not in a:
                raise ToolError('type view needs path (a file)')
            p = vet_path(a['path'], allow, want='file', home=self._home())
            argv = bin_argv('view', p, name, '--bg', *flags)
        elif typ == 'paste':
            if 'content' not in a:
                raise ToolError('type paste needs content')
            stdin = _text_arg(a, 'content')
            argv = bin_argv('paste', name, '--bg', *flags)
        elif typ == 'exchange':
            if 'content' in a:
                stdin = _text_arg(a, 'content')
            else:
                tty = True          # bin/exchange receives when stdin is a terminal
            argv = bin_argv('exchange', name, '--bg', *flags)
        elif typ == 'hook':
            argv = bin_argv('hook', name, *[f for f in flags if f != '--inspect'], '--bg')
        else:  # pocket
            argv = bin_argv('pocket', name, '--bg', *flags)
        out, _ = self._launch(argv, env, stdin=stdin, tty_stdin=tty, door=name)
        url, guest = parse_urls(out)
        res = {'url': url, 'name': name, 'type': typ, 'guest_link': guest,
               'expires': a.get('expires', 'never' if typ == 'pocket' else '1h')}
        m = re.search(r'^(?:Text will be saved to|Inbox|Files will be saved to): (.+)$', out, re.M)
        if m:
            res['saved_to'] = m.group(1).strip()
        text = f'{typ} door {name}: {url}'
        if guest:
            text += f'\nGuest link: {guest}'
        if res.get('saved_to'):
            text += f'\nReceived content lands in: {res["saved_to"]}'
        return text, res

    # the rest ------------------------------------------------------------------------
    def close_door(self, a):
        name = check_name(a['name'])
        out, _ = self._launch(bin_argv('status', 'close', name), child_env())
        return f'Closed {name}. ' + _trim(out, 300), {'name': name, 'closed': True}

    def list_doors(self, a):
        doors = self._json(porch_argv('door', 'ls', '--json'))
        if isinstance(doors, dict):
            doors = doors.get('doors', [])
        lines = [f"{d.get('name')}  {d.get('type', '')}  {d.get('url', '')}  "
                 f"expires={'never' if d.get('expires') is None else d.get('expires')}  "
                 f"opens={d.get('opens', 0)}" for d in doors if isinstance(d, dict)]
        return ('\n'.join(lines) or 'No doors are open.'), {'doors': doors}

    def extend_door(self, a):
        name = check_name(a['name'])
        exp = a['expires']
        if not EXPIRES_RE.match(exp):
            raise ToolError(f'invalid expires {exp!r}: use 30m, 2h, 1d, an ISO-8601 time or never')
        out, _ = self._launch(porch_argv('door', 'expire', name, exp), child_env())
        return _trim(out, 500) or f'{name} now expires {exp}', {'name': name, 'expires': exp}

    def inspect_requests(self, a):
        name = check_name(a['name'])
        limit = a.get('limit', 20)
        since = a.get('since_id')
        n = 500 if since is not None else limit
        recs = self._json(porch_argv('inspect', name, '-n', str(n), '--json'))
        if not isinstance(recs, list):
            raise ToolError('unexpected output from porch inspect')
        if since is not None:
            recs = [r for r in recs if isinstance(r, dict) and isinstance(r.get('id'), int)
                    and r['id'] > since]
            recs.sort(key=lambda r: r['id'])
            recs = recs[:limit]
        last = max((r.get('id', 0) for r in recs if isinstance(r, dict)), default=since)
        lines = [f"#{r.get('id')} {r.get('method', '')} {r.get('target', r.get('path', ''))} "
                 f"-> {r.get('status', '')}" for r in recs if isinstance(r, dict)]
        return ('\n'.join(lines) or 'No requests.'), {'requests': recs, 'last_id': last}

    def _clip_argv(self, a, *rest):
        base = ['clip']
        if a.get('pocket'):
            base += ['--name', check_name(a['pocket'], 'pocket')]
        return porch_argv(*base, *rest)

    def clip_get(self, a):
        out, _ = self._launch(self._clip_argv(a), child_env())
        return (out if out else '(the clipboard is empty)'), {'text': out}

    def clip_set(self, a):
        data = _text_arg(a, 'text')
        self._launch(self._clip_argv(a, 'set', '-'), child_env(), stdin=data)
        return 'Clipboard set.', {'ok': True, 'length': len(a['text'])}

    def call(self, name, args):
        return getattr(self, name)(args)


# ---- JSON-RPC server ----------------------------------------------------------------

INSTRUCTIONS = ('porch exposes this machine to the internet through short-lived public URLs '
                '("doors"). Use share to publish a file/folder/text, receive_file and ask_secret '
                'to get things from the user (never ask for secrets in chat), open_door for a '
                'port, paste, webhook or pocket, and list_doors / extend_door / close_door to '
                'manage them. Doors expire after 1h by default.')


def _err(id_, code, message):
    return {'jsonrpc': '2.0', 'id': id_, 'error': {'code': code, 'message': message}}


def _ok(id_, result):
    return {'jsonrpc': '2.0', 'id': id_, 'result': result}


class Server:
    def __init__(self, tools=None):
        self.tools = tools or Tools()
        self.initialized = False
        self.protocol = None

    def handle_line(self, line):
        """One input line -> a response object/list to write, or None."""
        if isinstance(line, bytes):
            try:
                line = line.decode('utf-8')
            except UnicodeDecodeError:
                return _err(None, PARSE_ERROR, 'Parse error: not UTF-8')
        if not line.strip():
            return None
        try:
            msg = json.loads(line)
        except ValueError:
            return _err(None, PARSE_ERROR, 'Parse error')
        if isinstance(msg, list):
            if not msg:
                return _err(None, INVALID_REQUEST, 'Invalid Request: empty batch')
            out = [r for r in (self.handle(m) for m in msg) if r is not None]
            return out or None
        return self.handle(msg)

    def handle(self, msg):
        if not isinstance(msg, dict) or msg.get('jsonrpc') != '2.0':
            return _err(msg.get('id') if isinstance(msg, dict) and _valid_id(msg.get('id')) else None,
                        INVALID_REQUEST, 'Invalid Request')
        method = msg.get('method')
        if method is None and ('result' in msg or 'error' in msg):
            return None                              # a response to us: we send no requests
        is_request = 'id' in msg
        id_ = msg.get('id')
        if not isinstance(method, str) or (is_request and not _valid_id(id_)):
            return _err(id_ if _valid_id(id_) else None, INVALID_REQUEST, 'Invalid Request')
        params = msg.get('params', {})
        if not is_request:
            if method == 'notifications/initialized':
                self.initialized = True
            return None                              # notifications: never answered
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return _err(id_, INVALID_PARAMS, 'Invalid params: params must be an object')
        try:
            if method == 'initialize':
                return _ok(id_, self.initialize(params))
            if method == 'ping':
                return _ok(id_, {})
            if method == 'tools/list':
                return _ok(id_, {'tools': TOOLS})
            if method == 'tools/call':
                return _ok(id_, self.tools_call(params))
        except ParamsError as e:
            return _err(id_, INVALID_PARAMS, f'Invalid params: {e}')
        except Exception as e:                       # noqa: BLE001 - never kill the server
            log(f'internal error in {method}: {type(e).__name__}: {e}')
            return _err(id_, INTERNAL_ERROR, 'Internal error')
        return _err(id_, METHOD_NOT_FOUND, f'Method not found: {method}')

    def initialize(self, params):
        want = params.get('protocolVersion')
        if want is not None and not isinstance(want, str):
            raise ParamsError('protocolVersion must be a string')
        self.protocol = want if want in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
        return {'protocolVersion': self.protocol,
                'capabilities': {'tools': {'listChanged': False}},
                'serverInfo': {'name': SERVER_NAME, 'version': SERVER_VERSION},
                'instructions': INSTRUCTIONS}

    def tools_call(self, params):
        name = params.get('name')
        if not isinstance(name, str):
            raise ParamsError('name must be a string')
        tool = TOOL_BY_NAME.get(name)
        if tool is None:
            raise ParamsError(f'unknown tool: {name}')
        args = params.get('arguments', {})
        if args is None:
            args = {}
        validate(tool['inputSchema'], args)
        log(f'tools/call {name}')
        try:
            text, structured = self.tools.call(name, args)
        except ToolError as e:
            log(f'{name}: {e}')
            return {'content': [{'type': 'text', 'text': str(e)}], 'isError': True}
        res = {'content': [{'type': 'text', 'text': text}]}
        if structured is not None and self.protocol != '2024-11-05':
            res['structuredContent'] = structured
        elif structured is not None:
            res['content'].append({'type': 'text', 'text': json.dumps(structured)})
        return res


def _valid_id(v):
    return v is None or isinstance(v, str) or (isinstance(v, int) and not isinstance(v, bool))


def serve(stdin=None, stdout=None, server=None):
    """Read messages line by line until EOF. Anything a tool prints by
    accident goes to stderr; only this function writes stdout."""
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    server = server or Server()
    with contextlib.redirect_stdout(sys.stderr):
        for line in stdin:
            resp = server.handle_line(line)
            if resp is None:
                continue
            data = json.dumps(resp, separators=(',', ':'), ensure_ascii=False) + '\n'
            stdout.write(data.encode('utf-8'))
            stdout.flush()
    return 0


def print_config(out=None):
    out = out or sys.stdout
    porch = os.path.join(BIN_DIR, 'porch')
    cfg = {'mcpServers': {'porch': {'type': 'stdio', 'command': porch, 'args': ['mcp']}}}
    generic = {'mcpServers': {'porch': {'command': porch, 'args': ['mcp']}}}
    out.write('# Claude Code (this project only: --scope local; everywhere: --scope user)\n')
    out.write(f'claude mcp add porch --scope user -- {porch} mcp\n\n')
    out.write('# .mcp.json (project-shared Claude Code config)\n')
    out.write(json.dumps(cfg, indent=2) + '\n\n')
    out.write('# Generic MCP clients (Claude Desktop, Cursor, ...: stdio transport)\n')
    out.write(json.dumps(generic, indent=2) + '\n')
    return 0

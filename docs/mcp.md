# `porch mcp`: Porch as an MCP server

`porch mcp` is a [Model Context Protocol](https://modelcontextprotocol.io)
server over stdio. It gives an agent (Claude Code, Claude Desktop, Cursor, any
MCP client) the Porch tools: share a file and get a public URL, receive files
or secrets from the user, open and manage doors, read webhook requests, and use
the Pocket clipboard.

- Code: `lib/porch_mcp.py` (server + tools), `lib/porch_setup/cmd_mcp.py`
  (entry point), tests in `tests/test_porch_mcp.py`.
- Transport: JSON-RPC 2.0, one message per line on stdin/stdout. stdout carries
  protocol messages only; logs go to stderr.
- Protocol versions: `2025-06-18`, `2025-03-26`, `2024-11-05`. The client's
  version is accepted when it is one of these, else the server answers with
  `2025-06-18`. Under `2024-11-05` results carry no `structuredContent`; the
  same JSON comes as a second text item instead.
- Methods: `initialize`, `notifications/initialized`, `ping`, `tools/list`,
  `tools/call`. Unknown notifications are ignored. Errors: -32700 parse,
  -32600 invalid request (also an empty batch), -32601 unknown method, -32602
  invalid params (unknown tool, or arguments that fail the tool's
  `inputSchema`). A tool that runs but fails (a missing file, a refused path, a
  launcher error) answers with `isError: true` and the reason as text.

## Install

Claude Code, for every project:

```bash
claude mcp add porch --scope user -- /path/to/porch/bin/porch mcp
claude mcp list            # porch: ... - Connected
```

Use `--scope local` for the current project only. Shared project config
(`.mcp.json` in the project root):

```json
{
  "mcpServers": {
    "porch": {
      "type": "stdio",
      "command": "/path/to/porch/bin/porch",
      "args": ["mcp"]
    }
  }
}
```

Other clients (Claude Desktop `claude_desktop_config.json`, Cursor, ...) take
the same `command` + `args` under `mcpServers`. `bin/porch mcp --print-config`
prints all three forms with this checkout's absolute path.

To protect shares with a password, start the client with the password in an
environment variable (for example `PORCH_SHARE_PW`) and pass its name as
`password_env` (see Safety).

**Other machines.** On a machine paired with `bin/bootstrap` the launchers work
the same, so `porch mcp` does too: install it there with that checkout's path.
The URLs are still `https://<name>.<tunnel base>`; owner-only features (Pocket,
the drop file list) need the owner's browser to be signed in as usual.

## Tools

Every door expires after **1h** unless `expires` says otherwise (`30m`, `2h`,
`1d`, an ISO-8601 time, or `never`). Names are 1-41 characters of `[a-z0-9-]`,
starting with a letter or digit, not ending with `-`. Door options shared by
`share` and `open_door`: `expires`, `password_env`, `guest_link`, `burn`,
`max_opens` (and `inspect` on `open_door`).

| Tool | Arguments | Runs |
|---|---|---|
| `share` | `path` or `text`, `as?`, `name?`, door options, `allow_sensitive?`, `e2e?` | `porch share <path\|-> ...` (picks view / media / music / serve from the content) |
| `receive_file` | `name?`, `wait_seconds?` (0-3600), `expires?` | `bin/drop <name> --bg`; waits for a completed upload in `~/drops/<name>/` |
| `ask_secret` | `label`, `fields?`, `save_to?` (`inf://` / `op://`), `wait_seconds?` | `bin/secure-entry <label> ... --signal-file F --bg` |
| `open_door` | `type` (tunnel, serve, paste, exchange, hook, pocket, view), `name`, `port?`, `path?`, `content?`, door options | `bin/<type> ... --bg` |
| `close_door` | `name` | `bin/status close <name>` |
| `list_doors` | none | `porch door ls --json` |
| `extend_door` | `name`, `expires` | `porch door expire <name> <expires>` |
| `inspect_requests` | `name`, `since_id?`, `limit?` (default 20) | `porch inspect <name> -n N --json` |
| `clip_get` | `pocket?` | `porch clip` |
| `clip_set` | `text`, `pocket?` | `porch clip set -` (text on stdin) |

`open_door` details: `tunnel` needs `port`; `serve` needs a folder `path`;
`view` a file `path`; `paste` needs `content`; `exchange` sends `content` with a
Copy button, or without it opens a form the user pastes into (the reply names
the file the text lands in); `hook` is a webhook catcher (always inspected);
`pocket` defaults to `expires: never`.

### Examples

```json
{"name": "share", "arguments": {"path": "~/reports/q3.pdf", "expires": "2h"}}
```
```json
{"content": [{"type": "text", "text": "Shared at https://q3-1a2b.tunnel.cush.rocks (as view pdf)"}],
 "structuredContent": {"url": "https://q3-1a2b.tunnel.cush.rocks", "name": "q3-1a2b",
   "type": "view", "viewer_mode": "pdf", "guest_link": null, "expires": "2h"}}
```

Password + guest link (the server was started with `PORCH_SHARE_PW` set):

```json
{"name": "share", "arguments": {"text": "draft notes...", "password_env": "PORCH_SHARE_PW", "guest_link": true}}
```
```json
{"structuredContent": {"url": "https://stdin-9f0c.tunnel.cush.rocks", "type": "view",
   "viewer_mode": "text", "guest_link": "https://stdin-9f0c.tunnel.cush.rocks/?k=...", "expires": "1h"}}
```

End-to-end encrypted (`porch share --e2e`, docs/porch-seal.md). The returned
`url` carries the decryption key after `#k=`: hand it to the user whole and
treat it like the file. The server returns it but never logs it. One file or
text only (no folders, no `as`); with `burn`/`max_opens`, complete downloads
count, not page views. Without python3-cryptography the call fails with the
apt hint.

```json
{"name": "share", "arguments": {"path": "~/reports/q3.pdf", "e2e": true, "burn": true}}
```
```json
{"structuredContent": {"url": "https://q3-1a2b.tunnel.cush.rocks/#k=...", "type": "seal",
   "viewer_mode": null, "guest_link": null, "expires": "1h", "e2e": true}}
```

Receive a file and wait up to 10 minutes for it:

```json
{"name": "receive_file", "arguments": {"name": "logs", "wait_seconds": 600}}
```
```json
{"structuredContent": {"url": "https://logs.tunnel.cush.rocks", "name": "logs",
   "directory": "/home/alice/drops/logs/", "expires": "1h", "timed_out": false,
   "files": [{"path": "/home/alice/drops/logs/app.log", "size": 48213}]}}
```

Ask for an API key straight into Infisical:

```json
{"name": "ask_secret", "arguments": {"label": "stripe", "save_to": "inf://prod/myapp/STRIPE_KEY", "wait_seconds": 300}}
```
```json
{"structuredContent": {"url": "https://entry-stripe.tunnel.cush.rocks/<token>/", "label": "stripe",
   "stored_at": "inf://prod/myapp/STRIPE_KEY", "fields": null, "arrived": true}}
```

A webhook catcher, then poll what it received:

```json
{"name": "open_door", "arguments": {"type": "hook", "name": "stripe-hook", "expires": "2h"}}
{"name": "inspect_requests", "arguments": {"name": "stripe-hook", "since_id": 0}}
```
```json
{"structuredContent": {"requests": [{"id": 1, "method": "POST", "target": "/", "status": 200,
   "ms": 0.6, "req_bytes": 812, "client_ip": "54.187.x.x", "handled_by": "intercept"}], "last_id": 1}}
```

Pass `last_id` back as `since_id` to get only newer requests (oldest first).

## Safety

- **No shell.** Every launcher runs from an argv list with a 60s timeout, in
  its own session (no controlling terminal, so nothing can stop at a prompt),
  stdin set to the given text or `/dev/null`, and at most 64KB kept from each
  of stdout/stderr. Failures come back as `isError` with stderr trimmed. A
  launcher that times out may already have opened its door in the
  background: the server then runs `bin/status close <name>` (`share` always
  names its door, the default being what `porch share` would pick).
- **Paths** are resolved (`~`, relative, symlinks) and must exist. Refused
  unless `allow_sensitive: true`: `.env*`, `*.pem` / `*.p12` / `*.pfx`,
  `id_rsa*`, anything under `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.azure`,
  `~/.kube`, `~/.config/{cush-tools,porch,infisical,gcloud,namecom}`,
  `~/.config/gh/hosts.yml`, `~/.local/share/porch`, `~/.docker/config.json`,
  `~/.netrc`, `~/.git-credentials`, `~/.pgpass`, `~/.password-store`
  (compared case-insensitively), a hard link to any file in those places,
  `config/frps.toml` / `config/frpc.toml`, and anything under porch's `data/`
  except `data/links.json`. **Always refused**, even with `allow_sensitive`:
  `data/devices.json`, private keys (`id_rsa`, `id_ed25519`, ... without
  `.pub`, `*.key`, and any file or `text` containing a `-----BEGIN ... PRIVATE
  KEY-----` block). A folder is checked file by file (dotfiles skipped, since
  `bin/serve` never serves them); a folder containing porch's `data/` or
  `config/` (with the device registry or frp config in it) is refused outright,
  and so is one containing `~/.ssh` unless `allow_sensitive`; a symlinked
  subfolder pointing at a sensitive place is refused too.
- **Passwords** never travel as arguments. `password_env` is the *name* of an
  environment variable in the MCP server's own environment; its value is handed
  to the launcher as `PORCH_DOOR_PASSWORD` in the child's environment (the
  launchers store only an scrypt hash). An inherited `PORCH_DOOR_PASSWORD` is
  removed from every child's environment, and the password is scrubbed from any
  output before it is returned.
- **Secrets.** `ask_secret` returns the exact form URL the launcher printed
  (the path token included, so share it only with the user) and where the
  value will be stored. It never opens the stored file: waiting watches a
  signal file in the private run dir (`<run dir>/mcp/`) that
  `bin/secure-entry` touches after the value is saved, and reports only
  `arrived: true` with the path or ref. Read the file yourself only if the task
  needs the value.
- **Inspector.** `inspect_requests` returns summaries from the store, whose
  secret headers are already masked (unless the door was started with
  `--inspect-raw` outside MCP).

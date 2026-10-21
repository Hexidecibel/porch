# Features

## Doors and launchers

<p align="center">
  <img src="assets/apps.svg" alt="The Porch apps: tunnel, serve, drop, media, photos, music, secure-entry, paste, exchange, form, chat, and qr, snap and shorten" width="100%">
</p>

| Command | Your guests get | You get |
|---|---|---|
| `tunnel <port> <name>` | Your local app at a real HTTPS URL | Expiry, extend, keep alive, stop |
| `serve <dir> <name>` | A folder as a website (`--list` for an index) | Dotfiles and symlink escapes refused; HTML sandboxed unless `--allow-scripts` |
| `view <file> [name]` | A read-only viewer: markdown, code, PDF, CSV/TSV, JSON, zip, diff, media; `--follow` for a live log | One file, opened `O_NOFOLLOW`; no URL part names a path |
| `drop [name]` | A drag-and-drop upload page with resumable uploads | Files in `~/drops/<name>/`; listing is owner-only; size, count and free-space limits |
| `media [name]` | Photos **and** video with real seeking (iOS too), light copies for phones | Uploads checked by magic bytes; `--view-only`, `--no-guest-upload` |
| `photos [name]` | A gallery they can add to | Delete and drag-to-reorder, for you only |
| `music [name]` | A player with waveforms and cover art | Owner uploads, reorder, delete |
| `secure-entry [label]` | A one-time form for a secret (or several fields) | The value in Infisical, 1Password or a 0600 file, never in a chat log |
| `paste <name>` · `exchange <name>` | Highlighted text, or a copy box / paste box | Whatever you piped in, or whatever they pasted |
| `form <name> --fields …` | A web form | Submissions as JSON |
| `hook <name>` | A webhook endpoint with a fixed answer | Every request recorded for `porch inspect` |
| `chat [name]` | A chat UI | A proxy to your local LLM (llama.cpp-compatible API) |
| `qr` · `snap` · `shorten` | A QR page, a screenshot, `<domain>/l/<slug>` | Sensitive QR data from stdin; private targets refused for snap |

Every page shares one design system (night and day themes, self-hosted fonts)
and ships a strict nonce-based CSP. Full flags and limits:
**[docs/tools.md](tools.md)**.

## Rules, expiry, burn and guest links

Every launcher takes the same door flags:

```bash
porch tunnel 3000 demo --expires 2h --bg          # 30m | 2h | 1d | <ISO-8601> | never (default 1h)
porch serve ./build preview --password --bg       # password from PORCH_DOOR_PASSWORD or a prompt, never argv
porch view notes.md --guest-link --bg             # prints an extra ?k=<token> link that skips the gate
porch paste secret-note --burn --bg < note.txt    # closes after one open (= --max-opens 1)
porch tunnel 8080 api --inspect --bg              # record every request (secrets masked)
```

Rules can change on a live door, usually without a restart:

```bash
porch door ls
porch door rules demo --password --max-opens 5
porch door expire demo 2h         # from now; or an ISO time; or: porch door keep demo
porch door reopen demo --expires 1h
porch status close demo
```

A closed door keeps its recipe for 7 days, so it can be reopened exactly as it
was. Burned and used-up doors shred their files at once.

## Share anything (`porch share`)

`porch share` looks at the content (magic bytes first, then the extension) and
picks the right door: images and video go to a media gallery, audio to the
music player, a folder to `serve`, everything else to the viewer.

```bash
porch share report.pdf                 # -> https://report-1a2b.tunnel.<domain>
porch share ./dist --name site         # -> serve
git diff | porch share -               # -> diff viewer
porch tail /var/log/app.log --name applog   # live, read-only log
porch share report.pdf --dry-run       # show the routing decision only
```

## End-to-end encrypted shares

```bash
porch share --e2e report.pdf --burn
# -> https://report-1a2b.tunnel.<domain>/#k=<key>   (share the whole link)
porch share --e2e secrets.txt --seal-password      # recipient types a password instead
```

The file is sealed (porch-seal v1: AES-256-GCM records) before it is served.
Your box, its logs, the inspector and HAProxy only ever see ciphertext; the key
lives in the URL fragment, which browsers never send. The page decrypts in the
browser, progressively, and `--burn` counts complete downloads, not page
views. Format, threat model and test vectors: [docs/porch-seal.md](porch-seal.md).

## Ask to reopen, with notifications

A visitor who reaches a closed door sees a "the light's off" page with an
**Ask to reopen** button. You get a Web Push notification on your phone with
**Allow 1 hour / Allow 24 hours** buttons, or answer from the Porch app or the
panel. Requests are rate-limited, carry no credentials, and answer identically
for doors that don't exist.

## The Porch app (phone, iPad, desktop)

```bash
porch pocket --bg                       # https://pocket.tunnel.<domain>, owner only, never expires
bin/pocket --install-service            # keep it up across reboots (systemd user unit)
```

An installable web app that runs the whole box: open doors with live
countdowns, opens and rules; recent doors with Reopen; the request inspector;
pending device pairings and reopen requests; paired devices, invites and gated
apps, with **public paths** (open one URL, such as `/s/` for share links, on a
gated app to anyone while the rest stays gated; also `porch public add <host>
<path> --app <who>`); push notification settings. On Android it is a share target (share
photos, files and links straight into it); on iOS a Shortcut does the same with
a per-device key. It also syncs a clipboard across your devices
(`porch clip`, `porch clip set <text>`).

Risky actions (stop all doors, approve a device, revoke, invites, loosening a
door's rules) need a fresh **step-up**: a passkey (Face ID / Touch ID /
Windows Hello) or your admin password, valid for 5 minutes.
Owner guide: [docs/pocket-app.md](pocket-app.md). API:
[docs/pocket-api.md](pocket-api.md).

## Request inspector and webhooks

```bash
porch hook github --bg                       # every request answered 200 "ok" and recorded
porch inspect github --follow                # live one-liners
porch inspect github --show <id>             # full headers and body
porch inspect api --replay <id>              # re-send a recorded request to your app
```

Authorization, cookies and anything that looks like a token, password or
secret are masked before they are written (`--inspect-raw` opts out, with a
warning). The store is a bounded ring in your private runtime dir and is
deleted when the door closes. The Porch app and the panel show the same
requests live, with Copy as curl and Replay.

## Secrets tooling

```bash
porch secure-entry api-key --save-to-secrets inf://prod/app/API_KEY --bg   # someone types it; it lands in your vault
bin/porch-init                     # scaffold a .cush-secrets manifest of refs (safe to commit)
bin/inject                        # refs -> .env (0600); missing ones open a secure-entry form
bin/stash                         # move an existing .env into your vault
bin/porch-hooks-install --global   # refuse commits containing .env files or live-looking keys
bin/porch-audit                    # find projects whose .env drifted from the manifest
```

Backends: Infisical (`inf://`) and 1Password (`op://`).

## MCP server

```bash
claude mcp add porch --scope user -- /path/to/porch/bin/porch mcp
porch mcp --print-config          # the same, plus the .mcp.json form
```

`porch mcp` is a Model Context Protocol server over stdio. An agent can share a
file or folder, ask you for a file or a secret (it never sees the secret's
value), open, list, extend and close doors, read the inspector and use the
Pocket clipboard. Secret-looking paths are refused. See [docs/mcp.md](mcp.md).

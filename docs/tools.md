# Porch tool reference

Self-hosted toolkit for exposing local services, sharing content, and receiving files — powered by [frp](https://github.com/fatedier/frp) (Fast Reverse Proxy). Runs on a NAS that is both the frp server and a client, allowing local services to be exposed via subdomains of `tunnel.cush.rocks`.

## Prerequisites

- DNS wildcard record: `*.tunnel.cush.rocks` pointing to this machine's public IP
- frp binaries in `bin/` (frps and frpc) -- downloaded during setup

## Pair a new machine

Each non-home machine authenticates with its own revocable device token. On a fresh box:

```bash
curl -sSL https://tunnel.<your-porch-domain>/install.sh | sh   # from your Porch landing page
```

The installer extracts cush-tools to `~/cush-tools`, grabs the frpc binary, and runs `bin/bootstrap`, which prints a pairing code like `ABCD-1234`. Approve it at `https://tunnel.cush.rocks/auth/` (log in with the admin password, enter the code, click Approve). Bootstrap then writes `config/frpc.toml` and the usual `bin/tunnel` / `bin/serve` commands work on the new machine.

Manage paired devices from the home box:

```bash
bin/auth-admin list          # list paired devices
bin/auth-admin pending       # list pending pairing codes
bin/auth-admin revoke <name> # revoke a device
```

The home box's own frpc authenticates with its own `home` device token (see "Home frpc token and the localhost bypass" in CLAUDE.md).

## Usage

All tools accept a `--bg` flag that daemonizes the process so it survives parent shell exit. This is essential when launching from scripts, subagents, or any context where the parent shell may terminate.

When running with `--bg`:
- Daemon output goes to `logs/<name>.log`
- Tools auto-terminate after 1 hour (extend with `bin/status extend <name>`, or
  set it with `--expires` / `bin/status expire <name> <when>`; see "Door flags")
- Check running tools with `bin/status`; kill with `bin/status close <name>`

Every local server binds `127.0.0.1`; frpc is the only way in. Text and secrets
received by secure-entry, exchange and form land in a per-user private run dir,
`$XDG_RUNTIME_DIR/porch/<tool>/` (falling back to `/tmp/porch-$UID/<tool>/`),
created 0700 and written 0600 by `lib/rundir.py`. Each launcher prints the exact
path. The run dir is tmpfs, so those files vanish at logout unless lingering is
enabled (`loginctl enable-linger`).

Agents can drive all of this through `porch mcp`, a Model Context Protocol
server over stdio (share, receive files, ask for secrets, open/close/list
doors, inspect webhooks, the Pocket clipboard): see [mcp.md](mcp.md).

### Door flags (expiry and share rules)

Every door launcher (`tunnel`, `serve`, `paste`, `drop`, `media`, `photos`,
`music`, `exchange`) takes the same flags, parsed in one place
(`lib/door-flags.sh` + `lib/door_state.py`):

| Flag | Meaning |
|---|---|
| `--expires 30m\|2h\|1d\|<ISO-8601 time>\|never` | exact expiry (default 1 hour). A bare number is minutes; a naive ISO time is local time; at most a year out. |
| `--password` | visitors must enter a password. Read from `PORCH_DOOR_PASSWORD` or prompted on the terminal, never argv or stdin; only a salted scrypt hash is stored. |
| `--guest-link` | prints `https://<name>.tunnel.cush.rocks/?k=<token>`; opening it lets the holder in (the `k` is stripped from the URL). Either the password or the link admits. |
| `--max-opens N` | the door closes after N page views by non-owners |
| `--burn` | `--max-opens 1` |
| `--inspect` | record every request (see "Request inspector and webhooks") |
| `--inspect-raw` | the same, with secret headers unmasked (prints a warning) |

```bash
PORCH_DOOR_PASSWORD='s3cret-pw' bin/serve ./dist demo --password --expires 2h --bg
echo "one-time note" | bin/paste note --burn --bg
bin/drop inbox --guest-link --expires 1d --bg
bin/tunnel 3000 app --password --bg          # prompts on the terminal
```

A door with any rule gets `lib/doorproxy.py` in front of it (frpc talks to the
proxy, the proxy to the app); a door without rules keeps the direct path. The
owner's enrolled browser always passes and is never counted. An "open" is a
top-level page view (plus, on a door with no password or guest link, any
request without a door session, so `curl` cannot read a burn link for free);
images, video ranges and XHR of a visitor already in do not count. A session
from the password form or a guest link always costs one open, on its first
request, whatever that request looks like. When the
limit is reached, visitors already in get 60 seconds to finish loading, new
visitors get a "this door is closed" page (410), then the door is stopped.

Change a running door:

```bash
bin/status                      # expiry ("never" or the exact time), rules, opens
bin/status keep demo            # never expire
bin/status expire demo 2026-10-20T18:00     # or 30m, 2h, 1d, never
porch door ls [--json]          # doors with expiry, rules, opens and guest links
porch door expire demo never
porch door rules demo --guest-link            # mints a new link (the old one stops working)
porch door rules demo --no-password --max-opens 5
```

Rules change live. On a door started without rules, `porch door rules` starts
the door proxy and restarts only the tunnel connection (one reconnect, about a
second; the app keeps running). If the proxy doesn't come up, the rules are
rolled back (exit 4). Doors started before this existed, and tcp/udp tunnels,
can't switch: the command exits 3 and prints the exact relaunch command. The panel at panel.cush.rocks shows each door's rules,
open count and exact expiry, and can set the expiry.

### Reopening a closed door, and "Ask to reopen"

`view`, `seal`, `serve`, `paste`, `media`, `photos`, `music` and `drop` (so
everything `porch share` and Pocket's Make link open) write a launch recipe as
they start: `data/doors/<name>.json` (0600) with the door's file or folder, its
flags and its rules. A door that **expired** or that **you closed** can be
opened again under the same name for 7 days, exactly as it was: the same link,
password, guest link and inspector; the open count starts at zero.

```bash
porch door reopen deck --expires 24h      # or 1h (default), 30m, 2d...
```

The panel's **Recently closed** list shows **Reopen 1h / Reopen 24h** for these
doors (Revive stays for the rest). Files the door owned (stdin copies, sealed
ciphertext, paste captures, `porch share`'s media/music copies) are kept those
7 days, then deleted with the recipe. A door that **burned or was used up**
(`--burn`, `--max-opens`) is shredded at once and can never be reopened.

**Ask to reopen.** A visitor who opens a link after its door closed gets the
closed-door page with **Ask to reopen** (and an optional name, 40 characters).
You get a notification from Pocket: `Reopen "deck"?`, with who asked, when the
door closed and the visitor's address. On Android it has **Allow 1h** and
**Allow 24h** buttons; a tap anywhere else (and every tap on iPhone) opens the
request in Pocket with Allow 1h / Allow 24h / Deny. Pending requests also show
at the top of Pocket and in the panel. Once you allow it, the visitor's page
lights up and loads the door by itself; Deny shows them "The owner said not
now"; after 30 minutes they see "No answer yet".

Turn notifications on once per device in Pocket (**Notifications**, then the
switch; it needs a tap). On iPhone and iPad they only work in the home-screen
app (Share, Add to Home Screen, then open Pocket from the icon). **Send a
test** checks the whole path. Notifications are Web Push sent by this box
(VAPID, end-to-end encrypted to the browser), so nobody else sees them.

The public ask is limited: 3 asks per address per hour, one pending request
per door (later visitors join it), 50 pending in all, and the answer looks the
same whether or not the name can be reopened, so it says nothing about which
doors exist. Nobody is notified about a name that can't be reopened.

### Request inspector and webhooks

`--inspect` on any door records what comes through it: method, URL, headers
both ways, status, timing, sizes, and request/response bodies up to 64KB each
(binary and media bodies keep only their size, type and first bytes;
WebSocket connections only their metadata). Authorization, Cookie,
Set-Cookie and any header whose name contains token, secret, key or signature
are stored masked (`Bear…[masked, 31 chars]`) unless `--inspect-raw`. So are
the values of fields named like password, passwd, secret, token, api_key,
apikey, access_key, private, auth, signature, session or cookie in
form-encoded and JSON bodies (both directions) and in query strings. The last
500 requests live in `$XDG_RUNTIME_DIR/porch/inspect/<name>.jsonl` (0600) and
are deleted when the door closes.

```bash
bin/serve ./dist demo --inspect --bg
porch inspect demo                 # the last 20 requests, one line each
porch inspect demo --follow        # ... and new ones as they arrive
porch inspect demo --show 12       # one request in full (--json for raw JSON)
porch inspect demo --replay 12     # re-send it to the app, recorded as a new request
```

A replay goes only to the door's own app on 127.0.0.1. Masked headers are sent
with their real values while the door is still running (the door proxy keeps
them in memory only); otherwise they are left out and the command says so.
A masked body or query string is replayed with the originals under the same
rule; once they are gone, the replay is refused instead.
Requests whose body was truncated or binary are not replayed.

`bin/hook` opens a webhook catcher with no app behind it: every request gets a
fixed answer and is recorded.

```bash
bin/hook stripe --bg                           # https://stripe.tunnel.cush.rocks, answers 200 "ok"
bin/hook gh --status 202 --body '{"ok":true}' --content-type application/json --bg
porch hook ci --password --expires 2h --bg     # door flags work as usual
porch inspect stripe --follow
```

Request bodies over 10MB get a 413 (`--max-body-mb`). A hook has nothing to
replay to. The panel shows inspected doors with an "inspecting" (or "webhook")
badge and an Inspect button: a live request list, headers and bodies (JSON
pretty-printed), Copy as curl (masked values stay masked) and Replay.

### Tunnel (expose a local port)

```bash
# Start the frp server daemon
bin/start-server

# Expose a local port as a subdomain
bin/tunnel 3000 myapp       # -> https://myapp.tunnel.cush.rocks
bin/tunnel 8080 api         # -> https://api.tunnel.cush.rocks
bin/tunnel 22 ssh tcp       # -> TCP tunnel
bin/tunnel 3000 myapp --bg  # -> daemonized, survives shell exit

# Check status
bin/status

# Stop the server
bin/stop-server
```

### Serve (serve a directory)

```bash
bin/serve ./dist myapp      # -> https://myapp.tunnel.cush.rocks
bin/serve /tmp/report report --bg  # -> daemonized
bin/serve ./site docs --list --allow-scripts   # opt in to listings and JavaScript
```

Runs `lib/serveserver.py` (`GET`/`HEAD` only). Dotfiles, path traversal and
symlinks that escape the directory are refused; there is no directory listing
unless `--list` (an `index.html` is still served); HTML is CSP-sandboxed so it
runs no JavaScript unless `--allow-scripts`. The launcher warns when the
directory contains `.env` or `.git`.

### Share and view (one file, read-only)

```bash
porch share report.pdf               # sniffs the file, starts the right door, prints the URL
porch share ./dist --name site       # a directory -> bin/serve
porch share holiday.jpg              # image/video -> bin/media --no-guest-upload (a copy in ~/media/<name>/)
git diff | porch share -             # stdin -> the diff viewer
porch share notes.txt --as view:markdown --expires 2h --password
porch share data.csv --dry-run       # print the routing decision and the command only
porch tail /var/log/app.log          # a live log door (= bin/view <file> --follow)
bin/view README.md readme --bg       # the viewer directly; --as MODE overrides the sniffed type
```

`porch share` looks at magic bytes first, then the extension: images and
video go to `bin/media` (guests watch + download, cannot add), audio to `bin/music`, a directory to
`bin/serve`, everything else to `bin/view`. The name defaults to the file
name's slug plus four random hex characters. Text from stdin is kept in a
private file only while its door is open. Door flags pass through, and
`--bg` is always on.

`bin/view` renders: markdown (raw HTML is not rendered, links only
http(s)/mailto), code and text (highlighted, line numbers, wrap), PDF (pdf.js:
pages, zoom, fit width; fonts a PDF does not embed, CJK included, render with the bundled CMaps and standard fonts), CSV/TSV (sortable, filterable, first 10,000 rows),
JSON (collapsible tree and raw, up to 8 MiB), zip (browse the entries and open
text, images, PDFs, CSV, JSON and diffs inside without extracting; encrypted,
oversized and zip-bomb entries are refused and unsafe names are never served),
diffs (side by side on wide screens, unified on narrow ones), images, video
and audio. Everything else gets a download button. With `--follow` the page is
a live log: new lines stream in, the last 5,000 are kept, it autoscrolls
until you scroll up or press Pause, search highlights matches (Enter jumps to
the next), and ANSI colours are kept.

### End-to-end encrypted shares

```bash
porch share --e2e report.pdf             # prints https://report-1a2b.<tunnel base>/#k=<key>
porch share --e2e report.pdf --burn      # closes after one COMPLETE download
porch share --e2e notes.txt --seal-password   # PORCH_SEAL_PASSWORD or a prompt; no key in the link
git diff | porch share --e2e -           # sealed from memory, never written in clear
bin/seal <file.pseal> [name] [--owned-file] [--owned-dir DIR] [door flags] --bg
```

The file is encrypted here (AES-256-GCM, porch-seal v1) before it is shared;
the door holds only ciphertext and the recipient's browser decrypts it with
the key in the link's `#k=` part (browsers never send it) or a password. The
page shows images, video, audio, PDFs and text, or offers a download; it
removes the key from the address bar once the file opens. With `--burn` /
`--max-opens`, a complete download is an open (page views and partial
downloads are free); at the limit the encrypted file is deleted and the door
closes 30 seconds later. Anyone holding the whole link can decrypt, and the
box sees file size and access times. Needs `python3-cryptography`. Details and
threat model: `docs/porch-seal.md`.

### Drop (receive files)

```bash
bin/drop                    # -> https://drop-XXXX.tunnel.cush.rocks
bin/drop photos             # -> https://photos.tunnel.cush.rocks
bin/drop photos --bg        # -> daemonized
# Files saved to ~/drops/<name>/
```

Guests can only upload. Listing and downloading are owner-only, unlocked for a
browser enrolled with cush-auth (`--devices data/devices.json`, same gate as
media). Defaults: 2GB per file, 20GB and 5000 files per drop, a 1GB free-disk
floor, 4 concurrent uploads (2 per client). `lib/dropserver.py` takes
`--max-file-mb`, `--max-total-mb`, `--max-files`, `--min-free-mb`,
`--max-uploads` and `--max-connections`. Executable types (.exe, .bat, .sh,
.dll, etc.) are blocked.

Uploads are **resumable**: the page speaks tus 1.0.0 to `/tus/`
(`lib/porch_tus.py`), sending chunks of up to 8MB and asking the server for
the real offset after any failure, so a phone whose screen locks mid-upload
carries on when it wakes, and re-picking the same file after a reload resumes
it. Without `/tus/` the page falls back to a single multipart POST. Partial
uploads sit in `.tus/` (never listed, their full size reserved against the
quota) and are swept after 24 hours idle.

### Photos (collect into a gallery)

```bash
bin/photos                  # -> https://photos-XXXX.tunnel.cush.rocks
bin/photos album            # -> https://album.tunnel.cush.rocks
bin/photos album --bg       # -> daemonized
# Photos saved to ~/photos/<name>/
```

A browser gallery where anyone can add photos ("Choose Photos" or "Take Photo"
— camera on mobile) and open a lightbox. Deleting and drag-to-reorder are
owner-only, behind the same cush-auth gate as `bin/media`. Drag-reorder works on
both mobile and desktop, and the arranged order is preserved across reloads. Image types only: .jpg .jpeg .png .gif .webp .heic
.heif .bmp .tif .tiff .avif (100MB max per file).

### Media (photos + video in one gallery)

```bash
bin/media                   # -> https://media-XXXX.tunnel.cush.rocks
bin/media wedding           # -> https://wedding.tunnel.cush.rocks
bin/media wedding --bg      # -> daemonized
bin/media reel --view-only  # -> guests can watch, not add or download
# Media saved to ~/media/<name>/
```

The photo gallery grown up to hold **images and video together**, with the
owner/guest split from `bin/music`. Anyone with the link can browse, play,
download and **add**; **only the owner can delete or reorder** — unlocked
automatically for any browser enrolled with cush-auth, validated server-side on
every write against `data/devices.json`. Guests never see a delete control, and
with no enrolled browser the gallery fails closed to view+add.

`--view-only` is for sharing your own videos and photos with people who should
only watch. Guests can browse, play and seek, but the server refuses their
uploads and the forced-download link (`?dl=`) with a 403, and their page is
served without the add controls or the lightbox download button. Videos get
`controlsList="nodownload"` and no picture-in-picture, and the lightbox
suppresses the right-click menu. The owner keeps upload, delete, reorder and
download. With no enrolled browser nobody can upload at all. Be clear about
what this is: it deters casual saving, but anything a browser can play it can
also save, so a determined viewer with dev tools or a screen recorder will
still get a copy. The flag survives `--bg` and a revive from the status
console.

Video plays inline in the lightbox and is streamed with HTTP Range support, so
seeking works and iOS Safari will play it at all (it refuses a video served
without ranges). Poster frames come from `ffmpeg` if it is installed; otherwise
the page draws a generative poster, so nothing looks broken without it.

HEIC and TIFF get a lightbox preview from `GET /preview/<name>` (HEIC needs
`pillow-heif`). A thumbnail that fails to render is cached as
`.thumbs/<name>.fail` and not retried.

Uploads are resumable through `/tus/` like the drop's, and a wrong file type
is refused as soon as its first 64 bytes arrive.

**Light copies.** When `ffmpeg` and `ffprobe` are installed, a background
worker gives every video taller than 720p (short edge), heavier than 5 Mbps or
in a codec not every browser plays a phone-sized copy: 720p H.264/AAC MP4 at
about 3 Mbps with faststart, stored as `.thumbs/<name>.light.mp4` and served at
`/light/<name>`. Phones and slow connections get it in the lightbox; desktops
on a good link and every download get the original. Without ffmpeg nothing
changes.

Uploads are typed by **magic bytes, not by extension** (BMP header checks, an
`ftyp` brand allowlist, Pillow `verify()` on images), and the stored name's
extension is chosen by the server from the sniffed type. SVG is rejected under
any name (it can carry `<script>`), uploads stream to disk with the size cap
enforced mid-stream, and mutating requests need a same-origin `Origin`/`Referer`.

512MB per file, 8GB per gallery, 2000 items. Images: .jpg .jpeg .png .gif .webp
.heic .heif .bmp .tif .tiff .avif — video: .mp4 .m4v .mov .webm .mkv .ogv .avi
.3gp. Both `bin/media` and `bin/photos` run on `lib/mediaserver.py`; `bin/photos`
passes `--kinds image` with the same cush-auth gate. `--open` (everyone is the
owner) is still available on `lib/mediaserver.py` as an explicit opt-in, and
prints a warning at startup.

### Music (host a shareable player)

```bash
bin/music                   # -> https://music-XXXX.tunnel.cush.rocks
bin/music mixtape           # -> https://mixtape.tunnel.cush.rocks
bin/music mixtape --bg      # -> daemonized
# Tracks saved to ~/music/<name>/
```

A modern, **play-only** music player for anyone with the link: a waveform
(click-to-seek), generative per-track cover art, prev/next, and per-track
download. Peaks and durations are computed server-side by `ffmpeg` into
`.peaks/` (served at `GET /peaks/<name>`); without ffmpeg a track shows
"waveform n/a". The owner reorders tracks with a drag grip. Audio streams with HTTP Range
support, so seeking is instant.

Uploading, deleting, and reordering are unlocked **automatically for the owner**
— any browser enrolled with cush-auth, recognized by its host-only `porch_host`
cookie (or, during the migration, the domain-wide `cush_auth` cookie),
validated server-side against `data/devices.json` by `lib/porch_auth.py`;
every write is re-checked. A guest sees a small "Owner? Sign in" link that
runs the per-host `/__porch/` handoff. Guests and unenrolled browsers stay play-only. Enroll a
browser once at `https://auth.cush.rocks/auth/` → "enroll this browser". Audio
types only: .mp3 .wav .flac .m4a .aac .ogg .oga .opus .weba .aiff .aif .alac
.wma (100MB max per file).

### Secure Entry (receive secrets)

```bash
bin/secure-entry            # -> https://entry-secret.tunnel.cush.rocks/<token>/
bin/secure-entry apikey     # -> https://entry-apikey.tunnel.cush.rocks/<token>/
bin/secure-entry apikey --bg  # -> daemonized
# Secret saved to $XDG_RUNTIME_DIR/porch/secure-entry/<label> (path is printed)
```

Single-use form for receiving secrets without exposing them in chat or logs.
The form lives under a random `/<token>/` path and the bare host returns 404,
so share the exact URL the launcher prints. A claim lock accepts only the first
submission.

#### 1Password writeback

`secure-entry` can write the submitted value straight into a 1Password vault
instead of (or in addition to) disk:

```bash
bin/secure-entry mykey --save-to-op op://cush/myapp/api_key --bg
# -> https://entry-mykey.tunnel.cush.rocks/<token>/; value lands in 1Password,
#    nothing is written to disk.

bin/secure-entry mykey --save-to-op op://cush/myapp/api_key --keep-disk
# -> writes to both 1Password and the run-dir file.
```

Flags:
- `--save-to-op <op://Vault/Item/field>` — write into 1Password as a concealed
  field. Item is created if missing; existing items get the field upserted.
- `--keep-disk` — when used with `--save-to-op`, also writes to disk.
- `--signal-file <path>` — touch a sentinel after a successful persist (used
  by `bin/inject` for auto-spawned forms).
- `--type {string|file|ssh}` — single-field submission type (default: string).
- `--field <name>[:<type>]` — multi-field mode. Repeat to collect several
  secrets in a single form. Type defaults to `string`; per-field overrides
  use `name:type` syntax.

If the `op` (or `infisical`) CLI is missing, the launcher exits 3 before any
tunnel opens. Failed op writes leave the form alive so the user can retry — the 30-second
self-shutdown timer only fires after a successful persist. If `--save-to-op`
is set without an explicit label, the label is slugified from the ref
(e.g. `op://cush/myapp/api_key` → `cush-myapp-api-key`).

##### Multi-field forms

Repeat `--field` to render multiple inputs on a single page (one tunnel, one
Submit button). Useful when you'd otherwise need four separate `secure-entry`
tunnels for four related secrets:

```bash
bin/secure-entry myapp \
    --field secret_key --field master_password --field api_token --field deploy_key:ssh
# -> https://entry-myapp.tunnel.cush.rocks/<token>/ (4 inputs, 1 Submit)
# Files: $XDG_RUNTIME_DIR/porch/secure-entry/myapp/<field>  (dir 700, files 600)
```

If only some fields save, the page says which were saved and which failed, and
a retry resends only the failed ones.

With `--save-to-op`, multi-field uses a 2-segment ref (no trailing field —
each form field is written as a same-named field on the op item):

```bash
bin/secure-entry myapp --save-to-op op://cush/myapp \
    --field secret_key --field master_password --field api_token --bg
```

Validation: passing both `--field` and a 3-segment `op://V/I/F` ref exits 2;
passing a 2-segment `op://V/I` ref without `--field` also exits 2.

##### Type variants

- **`string`** — `<textarea>`. Stored as plain text.
- **`file`** — `<input type="file">`. Upload is base64-encoded before storage
  (in 1Password as a concealed field, on disk as base64 text). The success
  page reports the byte size.
- **`ssh`** — monospace `<textarea>` with a banner: "SSH private key — do not
  paste a public key here." Stored as plain multi-line text.

`bin/inject` materialization for `file`-typed secrets writes the decoded
binary to `<env-dir>/.cush-secrets.materialized/<env_name>` (chmod 600) and
exposes `<env_name>_FILE=<absolute path>` in `.env`. For `ssh` and `string`,
the value lands directly in `.env` with shell-safe quoting.

**One-time setup** required: see [1Password setup](#1password-setup) below.

### Inject (materialize a `.env` from 1Password)

```bash
cd ~/code/myapp
bin/inject              # walks up for .cush-secrets, writes ./.env (mode 600)
bin/inject --check      # dry run; non-zero exit if anything missing
bin/inject --env        # emit `export KEY=value` to stdout (no file)
eval "$(bin/inject --env)"  # populate the current shell directly
```

Drop a `.cush-secrets` TOML manifest at the project root, then run
`bin/inject`. Each `op://Vault/Item/field` ref is resolved via the 1Password
CLI; refs that aren't yet in 1Password trigger an auto-spawned
`bin/secure-entry --save-to-op` form so you can fill them in via a web form
(the value lands in 1Password, never on disk).

#### Manifest format

```toml
schema = 1

[defaults]
target_vault   = "cush"
target_item    = "{project}"     # {project} = parent dir basename
field_template = "{key}"

[secrets]
DATABASE_URL = "op://cush/myapp/database_url"
STRIPE_KEY   = { ref = "op://cush/myapp/stripe", fallback = "sk_test_dev" }
GITHUB_TOKEN = { ref = "op://Work/shared/gh_token" }

[secrets.WEIRD_ONE]
ref          = "op://Shared/legacy/api"
target_vault = "Shared"
required     = true
```

The manifest is **safe to commit** — refs are pointers, not secrets. Bare-string
entries are shorthand for `{ ref = "..." }`. Inline-table entries can override
`target_vault`, `target_item`, `type`, `required`, and supply a `fallback`
literal (only used when `--allow-fallback` is passed).

#### Auto-spawn flow

When refs are missing in 1Password, `bin/inject` prints a table of forms
and ASCII QR codes:

```
Missing secrets — fill these in:
┌──────────────┬────────────────────────────┬──────────────────────────────┐
│ ENV          │ OP REF                     │ URL                          │
├──────────────┼────────────────────────────┼──────────────────────────────┤
│ DATABASE_URL │ op://cush/myapp/db         │ https://entry-...cush.rocks  │
└──────────────┴────────────────────────────┴──────────────────────────────┘
```

Each form spawns via `bin/secure-entry --save-to-op <ref> --signal-file <path> --bg`.
Submissions write directly into 1Password. `bin/inject` polls the sentinel
files at 1Hz, then re-renders all values from the vault and writes `.env`.
Ctrl-C cleans up all spawned tunnels.

Forms run in parallel (capped at `--max-parallel`, default 5) and inherit
the 1-hour tunnel auto-expiry; override with `--timeout <minutes>`.

#### Flags and exit codes

| Flag                  | Description                                                |
|-----------------------|------------------------------------------------------------|
| `--manifest <path>`   | Explicit manifest path (default: parent walkup)            |
| `--out <path>`        | Output `.env` path (default: `./.env`)                     |
| `--env`               | Emit `export KEY=value` to stdout (no `.env` file)         |
| `--check`             | Dry run; report status, exit 6 if any missing              |
| `--validate`          | Schema-only check (no op calls). Exit 0 if valid, 2 if not |
| `--no-prompt`         | Don't auto-spawn forms; exit 6 on any missing ref          |
| `--allow-fallback`    | Use manifest fallbacks for missing values                  |
| `--serial`            | Spawn forms one at a time (default: parallel)              |
| `--max-parallel <n>`  | Cap on concurrent forms (default: 5)                       |
| `--timeout <minutes>` | Total wait timeout (default: 60)                           |
| `--no-qr`             | Suppress ASCII QR output                                   |
| `--json`              | Machine-readable status output (also applies to `--validate`) |

Exit codes: `0` ok, `2` arg/manifest error, `3` op auth, `4` op error,
`5` user aborted, `6` `--no-prompt` + missing, `7` `.env` write failed,
`8` partial / timeout.

#### Safety nets

- `.env` is written `chmod 600`.
- The output file's basename is appended to `.gitignore` if not already listed.
- A loud warning is printed if the output file is currently tracked by git.
- Inject refuses to write into a world-writable parent directory (exit 7).

**One-time setup** required: see [1Password setup](#1password-setup).

### Stash (migrate `.env` into 1Password)

```bash
cd ~/code/myapp           # has an existing .env
bin/stash                 # interactive: walks each line, writes to 1Password,
                          # emits .cush-secrets, appends .env to .gitignore
bin/stash --dry-run --yes # preview without touching 1Password
bin/stash --keep-env      # leave .env entirely alone (no gitignore touch)
bin/stash --delete-env    # rm .env after success (confirmation unless --yes)
```

`bin/stash` is the on-ramp for migrating an existing `.env` into 1Password.
After it runs, `bin/inject` reproduces the `.env` from the resulting
`.cush-secrets` manifest — the round-trip preserves the key/value pairs
(ordering and inline comments may differ).

#### Per-line prompt

For each parsed dotenv line, stash shows:

```
[3/12] DATABASE_URL  → op://Personal/myapp/database_url
       value: postgres://...alhost (32 chars)
       [Y]es / [n]o-skip / [e]dit-ref / [s]how-value-then-ask :
```

- `Y` (default on Enter) — proceed with the default ref
- `n` — skip this line; do not write to 1Password
- `e` — edit the ref before writing (validates `op://Vault/Item/field`)
- `s` — print the full secret value, then re-prompt without `s` available

Default ref: `op://<vault>/<item-template>/<env_name lowercased>`. Field
names are lowercased because 1Password fields are case-insensitive in
practice and lowercase reads better in `op://...` URIs.

#### Flags and exit codes

| Flag                       | Description                                                |
|----------------------------|------------------------------------------------------------|
| `--in <path>`              | Source `.env` (default: `./.env`)                          |
| `--out <path>`             | Destination manifest (default: `./.cush-secrets`)          |
| `--vault <name>`           | Default vault (default: `Personal`)                        |
| `--item-template <tmpl>`   | Item name template (default: `{project}`)                  |
| `--project-name <name>`    | Override `{project}` substitution                          |
| `--dry-run`                | Show what would be created; do not call `op`               |
| `--yes`                    | Non-interactive: accept all defaults, no prompts           |
| `--gitignore-env` (default)| Append `.env` to `.gitignore`, leave file in place         |
| `--keep-env`               | Leave `.env` entirely alone                                |
| `--delete-env`             | `rm .env` after success (confirmation unless `--yes`)      |

Exit codes: `0` ok, `2` arg/input error, `3` op auth, `4` op vault/error or
aborted, `5` user aborted, `7` manifest write failed.

#### Safety nets

- The source `.env` stays on disk by default. Only `--delete-env` removes it.
- A loud warning prints if `.env` is currently tracked by git
  (`git rm --cached .env` to fix).
- The manifest is written atomically (temp file + `os.rename`).
- If `.cush-secrets` already exists, stash prompts merge / overwrite / abort
  (default merge — last-write-wins per env name, preserving entries not in
  the new run).
- **Not reversible without manual cleanup.** 1Password items written by stash
  must be removed via the 1Password UI or `op item delete` to undo. Use
  `--dry-run` first if unsure.

**One-time setup** required: see [1Password setup](#1password-setup).

### Cush-init (scaffold a new project)

```bash
bin/cush-init                          # init in $PWD (default vault: cush)
bin/cush-init ./fresh                  # mkdir + init in ./fresh
bin/cush-init --vault Work             # override default vault
bin/cush-init --no-direnv              # skip writing .envrc
bin/cush-init --git-init               # also `git init` if not a repo
```

Bootstraps a project for the cush-tools workflow. Writes `.cush-secrets`
(empty manifest), `.envrc` (if `direnv` is on PATH), and appends `.env`,
`.env.*`, `!.env.example`, and `.cush-secrets.materialized/` to
`.gitignore`. Idempotent. After init, edit `.cush-secrets` to declare the
env vars the project needs, then run `bin/inject` (which spawns
`secure-entry` forms for any values not yet in 1Password). The `.envrc`
hook runs `bin/inject --env` on `cd` (`direnv allow` once to enable).

Other flags: `--project-name <name>` overrides `{project}` substitution.

### Cush-hooks-install (block `.env` commits)

```bash
bin/cush-hooks-install                 # install in current repo
bin/cush-hooks-install ~/code/myproj   # install in a specific repo
bin/cush-hooks-install --global        # system-wide (covers every repo)
bin/cush-hooks-install --uninstall [--global]
bin/cush-hooks-install --check         # report install status
```

Installs `hooks/pre-commit-cush` as a pre-commit hook that blocks staged
`.env`-style files and values matching live-secret patterns (`sk_live_*`,
`ghp_*`, `AKIA*`, ...). Runs `gitleaks` too if it's on PATH. The
`--global` install uses git's `core.hooksPath` so every repo on the
machine inherits the hook without per-repo setup.

Allowlist intentional paths (e.g. `.env.example`) by adding them to
`~/.config/cush-tools/hook-bypass`, one per line.

### Cush-audit (drift detector)

```bash
bin/cush-audit                              # scan ~/local/src
bin/cush-audit --root ~/code --root ~/work  # multiple roots (repeatable)
bin/cush-audit --format json                # machine-readable output
bin/cush-audit --quiet                      # only show projects with drift
bin/cush-audit --strict                     # exit 1 on any drift (cron-friendly)
```

Read-only. Walks each root, finds `.env*` files and `.cush-secrets`
manifests per project, and reports drift. No 1Password auth required.

| State               | Meaning                                                         |
|---------------------|-----------------------------------------------------------------|
| `CLEAN`             | Manifest present, every `.env` key in manifest                  |
| `MISSING_MANIFEST`  | `.env` exists, no `.cush-secrets`. Run `bin/stash`.             |
| `MANIFEST_MISMATCH` | `.env` has keys not in `.cush-secrets`                          |
| `MANIFEST_ORPHAN`   | Manifest has keys no `.env` uses (often fine)                   |
| `TRACKED_ENV`       | `.env` is git-tracked. Run `git rm --cached .env`.              |
| `TRACKED_ENV_HOT`   | Tracked `.env` matches live-secret patterns. **Rotate first.**  |
| `MANIFEST_INVALID`  | Manifest TOML is malformed                                      |

Exit codes: `0` no drift (or `--strict` not passed), `1` drift + `--strict`,
`2` invalid args / scan failure.

### Paste (share text)

```bash
echo "hello world" | bin/paste msg    # -> https://msg.tunnel.cush.rocks
cat script.py | bin/paste code --bg   # -> daemonized
```

Syntax-highlighted text sharing. highlight.js 11.9.0 (and marked 12.0.0, for
`bin/chat`) are served from `lib/vendor/` rather than a CDN; `lib/vendor/SOURCES`
lists their SRI hashes.

### Exchange (bidirectional text)

```bash
bin/exchange mydata                     # receive mode -> https://mydata.tunnel.cush.rocks
echo "content" | bin/exchange mydata    # send mode -> https://mydata.tunnel.cush.rocks
bin/exchange mydata --bg                # -> daemonized
# Received text saved to $XDG_RUNTIME_DIR/porch/exchange/<name> (path is printed)
```

Auto-detects direction from stdin. Send mode serves text with a Copy button. Receive mode shows a paste form, saves to the printed path, and auto-shuts down after submission.

### Pocket (phone share target + clipboard)

```bash
bin/pocket                    # -> https://pocket.tunnel.cush.rocks (default name: pocket)
bin/pocket work --bg          # -> https://work.tunnel.cush.rocks, daemonized
# Files land in ~/pocket/<name>/inbox/; the clipboard lives in ~/pocket/<name>/.clip.json (0600)
porch clip                    # print the current clipboard text
porch clip set "some text"    # or: echo hi | porch clip set -
porch clip ls                 # current + last 20
porch clip watch              # print each new clip as it arrives
bin/pocket --install-service  # keep it up across reboots (systemd user unit)
bin/pocket --uninstall-service
```

Owner only: only a browser enrolled with cush-auth gets past the sign-in page.
Open it on your phone and add it to the home screen; on Android it then shows
up in the share sheet, so sharing a photo, file or link sends it to Pocket.
Text and links become the clipboard, which every open Pocket page (and
`porch clip watch`) sees live. iOS cannot add web apps to the share sheet: the
page's **iPhone setup** makes a device share key for an iOS Shortcut that
shares to Pocket (step by step: [pocket-ios-shortcut.md](pocket-ios-shortcut.md)).
A key can only add to the pocket, never read it, and is revocable. The door does not
expire unless you pass `--expires`. `porch clip` only works on this box (it
uses a local token the server refuses through the tunnel); `--name` or
`PORCH_POCKET` picks the pocket.

**Make link.** Every inbox file and clipboard entry has a **Link** button: pick
an expiry (1h, 24h, 7d, never), an optional password, burn or max opens, and a
guest link, and Pocket opens a door for it (`porch share` for you, named
`pk-...`) and shows the URL with Copy, Share (the phone's share sheet) and a
QR code. Right after you share something to Pocket from the phone, it offers
to make a link for it. The **Links** panel lists the doors Pocket made, with
their opens, rules and a live countdown, and lets you add an hour, make one
never expire, or close it. At most 20 are open at once.

**Send encrypted.** Pick a file (or type a message) and Pocket encrypts it on
the phone before it uploads (porch-seal, the same format as
`porch share --e2e`). The server only ever stores ciphertext. The link carries
the key after `#k=`, which browsers never send, or you pick a password that you
tell the recipient another way. The QR code is drawn on the phone, so it can
include the key.

**Photos & videos.** Next to Upload files, a Photos & videos button opens the
phone's gallery (Android shows its photo picker only for an image/video-only
picker); Send encrypted has one too.

**Notifications and requests.** The Notifications switch subscribes this
device to Web Push (see "Reopening a closed door" above); Send a test sends one.
Asks to reopen a closed door appear at the top as **Asked to reopen** cards
with Allow 1h / Allow 24h / Deny, and each notification opens
`/reopen/<id>` with the same three choices.

### Form, snap and qr

```bash
bin/form survey --fields 'name:text,email:email,feedback:textarea'
# Submissions: $XDG_RUNTIME_DIR/porch/form/survey.json; 10 POSTs/min per IP
bin/snap https://example.com shot          # screenshot at https://shot.tunnel.cush.rocks
printf '%s' "$WIFI" | bin/qr - wifi       # QR from stdin (keeps it out of ps)
bin/qr --data-file ./secret.txt wifi       # or from a file
```

`snap` takes only `http://`/`https://` URLs and refuses targets that resolve to
loopback, private, link-local or CGNAT addresses unless `--allow-private`.
Chrome keeps its sandbox unless running as root or given `--no-sandbox`.

### Expose (permanent *.cush.rocks subdomain)

```bash
bin/expose myapi 9500                     # -> https://myapi.cush.rocks
bin/expose hexbooth-app 9485 \
    --expo ~/local/src/hexbooth/apps/mobile  # + starts Expo with proxy env vars
bin/expose myapi --remove                 # tear down subdomain + delete cert
```

Unlike `tunnel`/`serve` (which use frp and live under `*.tunnel.cush.rocks`),
`expose` wires a local port directly into HAProxy under `*.cush.rocks` with a
dedicated Let's Encrypt cert. The mapping is permanent across reboots and
cert renewals are picked up automatically by the HAProxy deploy hook at
`/etc/letsencrypt/renewal-hooks/deploy/10-haproxy.sh`.

Requires sudo (HAProxy + certbot).

### Managing running tools

```bash
bin/status                  # List all active tools and tunnels
bin/status close myapp      # Kill a running tool by name
bin/status extend myapp     # Reset the 1-hour auto-expiry timer
```

## 1Password setup

`bin/secure-entry --save-to-op`, `bin/inject`, and `bin/stash` need the `op`
CLI authenticated. `lib/op.sh` supports two modes, picked automatically based
on which env vars are exported in `~/.config/cush-tools/op.env` (Mode 1 wins
if both are configured).

### Mode 1 — Service account token (Teams / Business plans)

Stateless: every `op` call carries the token, no signin step.

```bash
mkdir -p ~/.config/cush-tools && chmod 700 ~/.config/cush-tools
cat > ~/.config/cush-tools/op.env <<'EOF'
export OP_SERVICE_ACCOUNT_TOKEN=ops_REPLACE_ME
EOF
chmod 600 ~/.config/cush-tools/op.env
```

Create a service account with scope on the vaults you want cush-tools to
access: <https://developer.1password.com/docs/service-accounts/>

### Mode 2 — Stored credentials (Family / Personal plans)

For accounts without service-account access, `lib/op.sh` runs `op account add`
once and `op signin` as needed, caching the resulting session token in
`$XDG_RUNTIME_DIR/cush-op-session` (tmpfs, cleared on reboot).

```bash
mkdir -p ~/.config/cush-tools && chmod 700 ~/.config/cush-tools
cat > ~/.config/cush-tools/op.env <<'EOF'
export OP_SUBDOMAIN=my              # the subdomain in your 1password.com URL
export OP_EMAIL=you@example.com
export OP_SECRET_KEY=A3-XXXXXX-...  # from 1password.com → My Profile → Get the app
export OP_MASTER_PASSWORD='your-master-password'
EOF
chmod 600 ~/.config/cush-tools/op.env
```

Wrap the master password in single quotes (not double) so `$`, `!`, `` ` ``,
and `\` aren't shell-expanded.

The session token is auto-refreshed when it expires (~30 min idle). The
master password stays in the environment for that refresh path; the file is
chmod 600 regardless.

### Common requirement

Both modes need the 1Password CLI on PATH:

<https://developer.1password.com/docs/cli/get-started/>

If `op` is missing or no credentials are configured, `bin/secure-entry
--save-to-op`, `bin/inject`, and `bin/stash` exit 3 with a setup hint and
do not spawn a tunnel.

## Recommended setup

Once 1Password is configured, the typical end-to-end flow is:

```bash
# One-time per machine: block accidental .env commits everywhere
bin/cush-hooks-install --global

# New project
cd ~/code/newproj
bin/cush-init                       # scaffold .cush-secrets + .envrc + .gitignore
$EDITOR .cush-secrets               # declare needed env vars (op:// refs)
bin/inject                          # spawn secure-entry forms for any missing values
direnv allow                        # (optional) auto-load .env on cd

# Existing project with a live .env
cd ~/code/myapp
bin/stash                           # interactive walk → 1Password + manifest
bin/inject --check                  # verify the round-trip

# Periodic drift check across every project
bin/cush-audit --strict             # cron-friendly; exits 1 on drift
```

## Landing Page

The tunnel landing page is served at `https://tunnel.cush.rocks` (nginx on port 8091).

- Source: `site/index.html` (its **Admin** link goes to `https://panel.cush.rocks`,
  the cush-auth-gated tunnel console served by `lib/statusserver.py`)
- Installer: `site/install.sh` (served at `https://tunnel.cush.rocks/install.sh`)
- Deploy: `bin/deploy` (copies both to `/var/www/tunnel/`)

## Device auth

Per-device pairing is handled by `lib/authserver.py` (listens on `127.0.0.1:9512`). It implements the frp `[[httpPlugins]]` webhook for the `Login`, `NewProxy`, `NewWorkConn` and `Ping` ops and serves the admin web UI. A remote device may only open `http`/`https` proxies on a plain subdomain; `tcp`/`udp`, `custom_domains`, `entry-*` names and the reserved names (auth, www, api, admin, panel, status) need the `tunnel_admin` flag (`bin/auth-admin role <device> admin`). Generated frpc configs set `transport.heartbeatInterval = 30` so a revoked device is dropped at its next heartbeat.

`bin/auth-admin` sends every change through the running server (`CUSH_AUTH_URL` overrides the URL); `revoke`, `set-password` and `server` fall back to editing `data/devices.json` under `data/.devices.lock` when the server is down. `approve` needs `--apps` for web pairings. Login, enroll and setup share one limiter (5/min per IP, global stop after 30 failures/min), and auth pages send a strict nonce CSP. Device registry lives in `data/devices.json` (gitignored). See the [Pair a new machine](#pair-a-new-machine) section for the user-facing flow.

The console, `/login` and the invite page load no third-party assets. Their Tailwind classes are compiled into `lib/auth.css` (committed, served at `/auth/static/auth.css`) by `bin/auth-css`, which uses a version- and sha256-pinned Tailwind standalone CLI cached in `~/.cache/cush-tools/`. After changing classes in `lib/authserver.py`, run `bin/auth-css` and commit the result; `bin/auth-deploy` refuses to restart the service while the file is missing or stale. Write class names out whole: one assembled from fragments in JS gets no rule.

Install the systemd unit (it is a template: edit `/opt/porch` and `User=` first):

```bash
sudo cp config/cush-auth.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now cush-auth
```

Add an nginx location block to the `tunnel.cush.rocks` server (port 8091) so the admin UI is reachable at `/auth/`:

```
location /auth/ {
    proxy_pass http://127.0.0.1:9512/;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
}
```

Reload nginx after adding the block. On first visit to `/auth/`, set the admin password (at least 12 characters); setup asks for the one-time token in `data/.admin-setup-token` (0600, also in the server log). Subsequent visits use the password to log in.

## Ports

| Port | Purpose |
|------|---------|
| 7000 | frp protocol (server <-> client) |
| 7080 | HTTP virtual host routing |
| 7443 | HTTPS virtual host routing |
| 7500 | Dashboard (localhost only) |
| 9512 | Device-auth server (localhost only) |

## Configuration

- `config/frps.toml` -- Server configuration (gitignored, contains secrets)
- `config/frpc.toml` -- Client base template (gitignored, contains secrets)
- `config/frps.toml.example` -- Server config template
- `config/frpc.toml.example` -- Client config template

## Authentication

Per-device tokens, validated by the auth server (see [Device auth](#device-auth)). frps runs with an empty shared `auth.token` and delegates real checks to `lib/authserver.py` via the frp `[[httpPlugins]]` webhook (Login, NewProxy, NewWorkConn, Ping); each client presents its own `metadatas.device_token`. Localhost clients bypass the check. New machines onboard via [Pair a new machine](#pair-a-new-machine); revoke individual devices with `bin/auth-admin revoke <name>`.

## SSL / Wildcard Cert Renewal

The `*.tunnel.cush.rocks` wildcard certificate is issued via Let's Encrypt using DNS-01 challenge with the name.com API.

### Scripts

- `bin/certbot-auth-hook` -- Creates the `_acme-challenge.tunnel` TXT record via name.com API
- `bin/certbot-cleanup-hook` -- Deletes the TXT record after validation
- `bin/renew-cert` -- Runs certbot, combines certs into HAProxy PEM, reloads HAProxy

### Manual renewal

```bash
bin/renew-cert
```

### Automated renewal (cron)

Add this crontab entry to run renewal at 3 AM on the 1st of every other month:

```
0 3 1 */2 * /path/to/porch/bin/renew-cert >> /path/to/porch/logs/renew.log 2>&1
```

### Credentials

API credentials for name.com are read from `$NAMECOM_CREDENTIALS`, else `~/.config/namecom/credentials` (chmod 600). The hooks run as root under certbot; there `~` means the home of the user who owns the checkout.

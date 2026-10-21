# Pocket control-plane API

The contract Pocket's app UI (WS3) wires against. Server side:
`lib/pocketserver.py` (route table `ROUTES`, `/api/app`, `/api/activity`,
`/api/push/topics`, SSE), `lib/pocket_doors.py`, `lib/pocket_people.py`,
`lib/pocket_stepup.py`, `lib/pocket_audit.py`. Tests:
`tests/test_pocket_api.py`, `tests/test_pocket_stepup.py`.

Existing routes (clip, inbox, `/share`, `/tus/`, `/tus-sealed/`, keys, links,
`/api/reopen*`, `/reopen/<id>`, `/api/push`, `/api/push/{subscribe,unsubscribe,test}`,
`/api/events`) are unchanged except where noted below.

## Conventions

- **Owner only.** Every route here needs the owner cookie (`porch_host` for
  this host, or the legacy `cush_auth`), checked by `porch_auth` against
  `--devices`. Anyone else gets **403** `{"status":"error","message":"Only the
  owner can use this pocket"}` (no `code`). The `porch clip` CLI token
  (`X-Porch-CLI-Token`) is **never** accepted on these routes.
- **Writes are POST** with `Content-Type: application/json` (parameters such as
  `; charset=utf-8` are fine) and a same-origin `Origin` (or `Referer`).
  The body is a JSON **object** (`{}` when there is nothing to send).
  Refusals, checked in this order after the owner check:
  - 403 `csrf`: no/foreign/`null` Origin and Referer
  - 415 `bad_content_type`: not `application/json`
  - 413 `too_large`: body over the route's cap (8 KB unless noted)
  - 400 `bad_request`: not a JSON object
- **Success**: HTTP 200 (201 where noted) and `{"status":"ok", ...}`. A few
  list reads answer a bare JSON array (noted).
- **Error**: `{"status":"error","message":str,"code"?:str, ...extra}`. The
  `message` is user-facing (safe to show via textContent).
- **Codes** (stable):

  | code | HTTP | meaning / extra fields |
  |---|---|---|
  | `step_up` | 401 | ★ route without a fresh step-up. `methods: ["passkey","password"]` or `["password"]`, `passkeys: N` (usable passkeys) |
  | `step_up_password` | 401 | first passkey needs a password step-up. `methods: ["password"]`, `passkeys: 0` |
  | `stepup_failed` | 401 | a step-up/registration ceremony or password check failed (generic message; the precise reason is in the audit log) |
  | `rate_limited` | 429 | `retry_after` (seconds) + `Retry-After` header |
  | `auth_down` | 503 | porch-auth not answering / not configured / token unreadable |
  | `auth_busy` | 503 | porch-auth's scrypt is busy (password check) |
  | `auth_old` | 501 | porch-auth lacks the endpoint: "update porch-auth (bin/auth-deploy)" |
  | `auth_error` | 502 | porch-auth answered something unexpected |
  | `relaunch_needed` | 409 | rules can't switch live. `why`, `command` (exact shell command) |
  | `switch_failed` | 502 | live first-rule switch failed; rules rolled back |
  | `not_found` | 404 | |
  | `conflict` | 409 | already running, own door, launch busy, passkey limit, ... |
  | `confirm_all` | 400 | `apps: ["*"]` needs `confirm_all: true` |
  | `confirm_self` | 400 | revoking this browser needs `confirm_self: true` |
  | `unavailable` | 501 | passkeys need python3-cryptography on the box |
  | `csrf`, `bad_content_type`, `too_large`, `bad_request` | 403/415/413/400 | see above |
  | `server_error` | 500 | |

  Other 400s (validation) come without a code or with the backend's message.
- ★ = needs a **fresh step-up** (see Step-up). "★ when ..." = conditional.
- Door names: `^[a-z0-9][a-z0-9-]{0,40}$`. A path that does not match a
  route's pattern (e.g. an upper-case door name) is a plain 404 `not_found`.

## App

### `GET /api/app`
```json
{"status":"ok","now":1800000000,
 "pocket":{"name":"pocket","title":"Pocket","host":"pocket.tunnel.cush.rocks","origin":"https://pocket.tunnel.cush.rocks"},
 "me":{"device_id":"dev_ab12cd34","device_name":"My iPhone"},
 "stepup":{"active":false,"expires_at":null,"method":null},
 "passkeys":{"count":1,"unusable":0,"rp_id":"pocket.tunnel.cush.rocks"},
 "push":{"supported":true},
 "auth":{"state":"ok","can_rename":true,"can_verify_password":true},
 "counts":{"doors":3,"requests":1,"public_paths":2}}
```
- `stepup.method`: `"passkey" | "password" | null`; `expires_at` epoch s.
- `passkeys.count`: usable passkeys; `unusable`: stored under another rp_id
  (the pocket was renamed): re-enroll.
- `auth.state`: `ok` | `down` (last poll failed) | `stale` (no good poll for
  90 s) | `old` (porch-auth lacks verify-password or device-rename).
  `can_rename` false hides device rename; `can_verify_password` false means
  the password step-up will answer 501 `auth_old`.
- `counts.requests` = pending reopen asks + pending pairings + pending asks for access.
- `counts.public_paths` = active public paths (from the auth watcher's last
  snapshot; 0 before the first poll).

### `GET /api/activity?limit=100` (bare array, newest first)
```json
[{"ts":1800000000,"action":"door.extend","target":"deck","method":"passkey","ip":"203.0.113.9","result":"ok"},
 {"ts":1799999990,"action":"stepup","target":"password","ip":"203.0.113.9","result":"failed","code":"bad_password"}]
```
Fields `method`, `ip`, `result`, `code`, `detail` are omitted when empty.
Actions: `stepup`, `passkey.add|rename|delete`, `door.extend|expire|stop|stop_all|rules|reopen|revive|forget|launch|replay`,
`pairing.approve|reject`, `access.allow|deny` (target the host, detail `device|invite`), `device.revoke|role|apps|rename`, `invite.create|revoke`,
`app.protect|unprotect|forget`, `public.add|on|off|remove` (target `<host><path>`),
`password.change`. `limit` 1..1000.

## Doors

### `GET /api/doors`
```json
{"status":"ok","now":1800000000,"doors":[
 {"name":"deck","type":"serve","url":"https://deck.tunnel.cush.rocks","guest_url":"https://deck.tunnel.cush.rocks/?k=TOKEN"|null,
  "expires":1800003600|null,"never":false,"time_remaining":3600|null,
  "rules":{"password":true,"guest":true,"max_opens":5|null},
  "opens":2,"last_open":1799999000|null,"inspect":false,"inspect_raw":false,"capture":false,
  "started":1799990000|null,"unmanaged":false,"self":false,"pocket":{"kind":"inbox","label":"a.pdf"}|null}]}
```
- Newest first. `unmanaged`: an frpc with no state file (`type: "unmanaged"`,
  no rules/guest). `self`: Pocket's own door (name = this pocket, or type
  `pocket`). `pocket`: the Make-link tag of a `pk-` door.
- `guest_url` is owner-only data (the panel's API keeps hiding it).

### `POST /api/doors/<name>/extend` `{"seconds"?: 3600|86400}` (default 3600)
### `POST /api/doors/<name>/expire` `{"at": epoch | "+2h" | "30m" | ISO-8601 | "never" | null}`
Both answer the expiry reply:
```json
{"status":"ok","expires":1800003600|null,"never":false,"keep_alive":false,"time_remaining":3600|null}
```
A never-expiring door is left alone by extend. 404 `not_found` (no such
door), 400 bad `seconds`/`at`.

### `POST /api/doors/<name>/stop` `{}`
`{"status":"ok"}` (or `{"status":"ok","killed":n}` for an unmanaged name).
409 `conflict` for Pocket's own door.

### `POST /api/doors/stop-all` `{}` ★
`{"status":"ok","stopped":["a","b"],"skipped":[{"name":"pocket","why":"excluded"}]}`.
Never stops Pocket's own door or any type `pocket` door.

### `POST /api/doors/<name>/rules`
Body keys, each optional (absent = keep): `password: str (6..1024) | null`,
`guest: "new" | null`, `max_opens: int (1..1000000) | null`. At least one.
★ **only when it widens access**: `password: null` on a door that has one, or
`max_opens: null` on a door that has a limit. Adding/changing a password, a
new guest link (the old one stops working), a limit, or removing the guest
link are not ★.
```json
{"status":"ok","rules":{"password":true,"guest":true,"max_opens":null},
 "guest_url":"https://deck.tunnel.cush.rocks/?k=NEW"|null,"live_switch":true}
```
`live_switch: true` = a first rule put a door proxy in front (can take up to
15 s). 409 `relaunch_needed` `{why, command}`; 502 `switch_failed`;
404 `not_found`; 400 validation. The password is never echoed or logged.

### `GET /api/doors/history` (bare array, newest first, at most 25)
```json
[{"name":"deck","type":"serve","started":1799990000,"url":"https://deck.tunnel.cush.rocks",
  "revivable":true,"reopenable":true,"reopen_why":"","closed":1799999999|null,"reason":"expired"|null}]
```
`reason`: `expired`, `closed`, `used up`, `burned` (from the launch recipe).

### `POST /api/doors/history/<name>/reopen` `{"expires": "1h"|"24h"}`
`{"status":"ok","name":"deck","url":"https://deck.tunnel.cush.rocks"}`; 409 with the recipe's reason.
### `POST /api/doors/history/<name>/revive` `{}`
`{"status":"ok","url":...,"name":...,"type":...}`; 404 no history, 409 running / launch busy, 400 not revivable, 500 launcher failed.
### `POST /api/doors/history/<name>/forget` `{}`
`{"status":"ok"}`.

### `POST /api/doors/launch` (cap 2 MB)
```json
{"type":"drop|photos|media|music|exchange|secure-entry|paste","name":"my-door",
 "content":"(paste only)","view_only":false,
 "expires":"30m|1h|24h|7d|never",
 "rules":{"password":"6..1024 chars","guest":true,"max_opens":5}}
```
All but `type`/`name` optional (`view_only` strict boolean, media only).
Answer `{"status":"ok","url":...,"name":...,"type":...,"guest_url"?:...}`.
For secure-entry, `name` is the tunnel name (`entry-<label>`) and `url` the
tokenized form URL. One launch at a time (409 `conflict`), 30 s timeout; 409
when the name is already open; 500 with the launcher's error. The password
reaches the launcher only in env `PORCH_DOOR_PASSWORD`.

### Inspector (doors launched with `--inspect`, and `bin/hook` doors)
- `GET /api/doors/<name>/requests?since=ID&limit=N` →
  `{"status":"ok","records":[summary...],"last":ID,"more":bool,"body_cap":65536}`.
  Without `since`: the newest page; with it: oldest-first after `since`.
  404 `not_found` when the door is gone or not inspected.
- `GET /api/doors/<name>/requests/<id>` → `{"status":"ok","record":{...full record...}}`.
- `POST /api/doors/<name>/requests/<id>/replay` `{}` → `{"status":"ok","id":newId,"record":summary|null,"http_status":int|null,"dropped":[...]?}`;
  409 `conflict` with the refusal (`message`).
- `GET /api/doors/<name>/requests/events?since=ID` (SSE; `Last-Event-ID` resumes):
  `retry: 3000`, then `id: <n>` + `event: request` + `data: <summary>` per
  new record, `: ping` every 15 s, `event: closed` (`data: {}`) when the door
  goes; each stream ends after 300 s. At most 2 at once across the pocket
  (separate from `/api/events`), else 429 `rate_limited`.

Summary shape (`inspect_store.summary`): `{id, ts, ms, method, target, status, ...}` as in statusserver's inspector.

## Requests

### `GET /api/requests`
```json
{"status":"ok",
 "reopen":[...the existing /api/reopen records...],
 "pairings":[{"code":"ABCD-1234","device_name":"build-box","kind":"tunnel|web","created_at":1799999000,"expires_at":1799999600}],
 "access":[{"id":"16 chars","host":"grab.cush.rocks","note":"Robin","ip":"203.0.113.5","kind":"device|stranger|expired",
            "device_id":"dev_...|null","device_name":"...|null","state":"pending|granting|approved|denied|expired",
            "how":"device|invite|null","invite_id":"inv_...|null","created":1799999000,"decided":null,
            "until":1800000800,"waiting":1}],
 "accepts":[{"invite_id":"inv_1a2b3c4d","note":"Sam","device_name":"Sam's Pixel","at":1799999900}],
 "auth":{"state":"ok|down|old|stale","can_rename":true,"can_verify_password":true}}
```
Always 200: with porch-auth down, `pairings` and `access` are `[]` and `auth.state` says so.
`access`: Ask for access from the auth server's gate pages (pending + decided
in the last 30 minutes; never a visitor token or an invite link).
`accepts`: the last 20 invite redemptions seen by the watcher since start
(memory only).

### `POST /api/reopen/<id>` (existing, unchanged, not ★)
### `POST /api/requests/pairings/<code>/approve` ★
`code`: `^[A-Z]{4}-[0-9]{4}$`. Body: `{"apps"?: ["host",...] | ["*"], "confirm_all"?: true, "tunnel_admin"?: bool}`.
- Web pairing: `apps` required; `["*"]` also needs `confirm_all: true` (400 `confirm_all`). `tunnel_admin` refused.
- Tunnel pairing: `apps` ignored; `tunnel_admin: true` approves then sets the device's tunnel_admin flag.

`{"status":"ok","device_id":"dev_...","kind":"tunnel|web","tunnel_admin":bool}`. 404 `not_found` (no such pending pairing).
### `POST /api/requests/pairings/<code>/reject` `{}` (not ★) → `{"status":"ok"}`
### `POST /api/requests/access/<id>/allow` ★ `{"device_ttl_minutes"?: 1..43200 | null}`
A `device` ask: the host is added to that browser's scope (the gate lets it
straight in). Anyone else: porch-auth mints a single-use invite for exactly
that host (1 hour); its link goes only to the visitor's own poll.
`device_ttl_minutes` makes the browser it enrolls a pass of that length.
→ `{"status":"ok","request":{...as above, state "approved", how, invite_id}}`.
404 `not_found` (not waiting any more), 409 (the host is no longer gated;
the ask stays pending), 501 `auth_old` (porch-auth without the endpoint).
### `POST /api/requests/access/<id>/deny` `{}` (not ★) → `{"status":"ok","request":{...}}`

## People (through porch-auth; every field whitelisted)

### `GET /api/people`
```json
{"status":"ok",
 "devices":[{"id":"dev_1","name":"My iPhone","type":"browser|tunnel","apps":["*"]|[...]|null,
   "pass":{"apps":[...],"expires_at":1800086400|null,"invite_id":"inv_..."|null}|null,
   "role":"admin|guest"|null,"tunnel_admin":true|false|null,"revoked":false,
   "created_at":1790000000,"expires_at":null,"last_seen":1799999999|null,"invite_id":null,
   "run_ids":["r1"],"this":true}],
 "invites":[{"id":"inv_1","note":"Sam","apps":["trendlab.cush.rocks"],"landing":null,"uses":0,"max_uses":1,
   "live":0,"standing":false,"device_ttl_minutes":null,"status":"active","expires_at":1800086400|null,
   "created_at":1799999000,"devices":[{"id":"dev_9","name":"Sam's Pixel"}]}],
 "apps":[{"host":"music.tunnel.cush.rocks","protected":true}],
 "auth":{"state":"ok","can_rename":true,"can_verify_password":true}}
```
`role` is set for browsers, `tunnel_admin` for tunnel devices. `this`: the
browser making the request. 503 `auth_down` / 501 `auth_old` when porch-auth
can't answer.

### Device writes
- `POST /api/people/devices/<id>/revoke` `{"confirm_self"?: true}` ★ — revoking this browser needs `confirm_self` (400 `confirm_self`).
- `POST /api/people/devices/<id>/role` `{"role":"admin|guest"}` ★ → `{"status":"ok","role":...,"tunnel_admin":bool|null}`
- `POST /api/people/devices/<id>/apps` `{"apps":[hosts] | ["*"], "confirm_all"?: true}` ★ → `{"status":"ok","apps":[...]}`
- `POST /api/people/devices/<id>/rename` `{"name":"1..64 printable"}` (not ★) → `{"status":"ok","name":...}`; 501 `auth_old` on an old porch-auth.

`<id>`: `^[A-Za-z0-9_-]{1,64}$`. 404 `not_found` for an unknown device.

### Invites
- `POST /api/people/invites` ★
  `{"note":"≤80","apps":[hosts],"landing"?:host,"standing":bool,"expires_hours":int|null,"max_uses":int,"device_ttl_minutes":int|null}`
  → **201** `{"status":"ok","invite":{...as in GET /api/people...},"url":"https://auth.cush.rocks/i/..."}`.
  The `url` is in this answer **only** (never stored, logged or audited): show
  it once with a QR. `apps: ["*"]` is refused. porch-auth's own validation
  (ranges, standing needs device_ttl_minutes, ...) comes back as 400.
- `POST /api/people/invites/<id>/revoke` `{"revoke_devices": bool}` — ★ only when `revoke_devices` is true.

### Apps
- `POST /api/people/apps` `{"host":"a.example.com","action":"protect|unprotect|forget"}` ★ → `{"status":"ok","host":...,"action":...}`

### Public paths (open URLs on a gated app)
`GET /api/people` also carries `"public_paths": [entry, ...]`, and so does the `people` SSE event. An entry:
```json
{"id":"pp_0a1b2c3d","host":"promo.cush.rocks","path":"/s/","kind":"prefix|exact","app":"promo-studio",
 "why":"share links","created_at":1800000000,"created_by":"cli|pocket|admin-ui","enabled":true,
 "active":true,"inactive":null}
```
`inactive` says why an entry is not live: `"switched off"` or `"host not gated"`.
- `GET /api/people/public-paths` → `{"status":"ok","public_paths":[...],"max":100}`
- `POST /api/people/public-paths` `{"host","path","app":"1..40","why"?:"≤120"}` ★ → 201
  `{"status":"ok","entry":{...},"public_paths":[...],"haproxy":"ok"|"failed: ..."}`.
  A path ending in `/` is a prefix. porch-auth's rules (no `/`, `..`, `//`, `%`, `/__porch…`;
  host must be gated; no duplicates; at most 100) come back as 400 / 409 with its message.
- `POST /api/people/public-paths/<id>/on` `{}` ★, `/off` `{}` (not ★), `/remove` `{}` (not ★)
  → `{"status":"ok","entry":{...}|null,"public_paths":[...],"haproxy":...}`; 404 `not_found` for an unknown id.
  A porch-auth without the route answers 501 `auth_old`.

### Admin password
- `POST /api/people/password` `{"current":"...","new":"12..1024 chars"}` ★.
  `current` is checked through porch-auth's verify-password (wrong: 401
  `stepup_failed`, counted in the step-up failure limits), then set-password.
  → `{"status":"ok"}`. Logs out porch-auth's admin UI sessions.

## Step-up and passkeys

A step-up lasts **5 minutes from the ceremony** (fixed, not sliding). It is
the cookie `__Host-pocket_stepup` (Secure, HttpOnly, SameSite=Strict, Path=/,
Max-Age=300) plus a server record bound to the owner's device **and** owner
cookie; it is lost on a Pocket restart. The page can't read the cookie: use
`/api/app` `stepup` or the SSE `stepup` event. On a 401 `step_up`, open the
step-up sheet, run a ceremony, then retry the original request once.

Failure limits (passkey and password together): 5 per 5 min per client IP,
10 per 15 min per owner device → 429 `rate_limited` before any check.
Options endpoints: 30 per minute per device. porch-auth adds its own password
limit (5/min per IP), surfaced as 429 `rate_limited` (`retry_after: 60`).

### `POST /api/stepup/options` `{}`
- With usable passkeys:
  `{"status":"ok","passkeys":1,"publicKey":{"challenge":"b64url","rpId":"pocket.tunnel.cush.rocks","allowCredentials":[{"type":"public-key","id":"b64url","transports":["internal"]}],"userVerification":"required","timeout":60000}}`
- Without: `{"status":"ok","passkeys":0}` (`"why":"unavailable"` when the box lacks python3-cryptography).

The challenge is single use and lives 120 s.

### `POST /api/stepup/passkey` (cap 64 KB)
`{"credential":{"id","rawId","type":"public-key","response":{"clientDataJSON","authenticatorData","signature","userHandle"}}}`
(the `PublicKeyCredential.toJSON()` shape, base64url strings).
→ `{"status":"ok","expires_at":1800000300,"method":"passkey"}` + `Set-Cookie`.
401 `stepup_failed` (message "That passkey didn't check out"), 429, 501 `unavailable`.

### `POST /api/stepup/password` `{"password":"..."}`
→ same answer with `"method":"password"`. 401 `stepup_failed` ("That password
is not right"), 429 `rate_limited`, 501 `auth_old`, 503 `auth_down`/`auth_busy`.

### `POST /api/stepup/end` `{}`
→ `{"status":"ok"}`; clears the cookie and the server record.

### `GET /api/passkeys` (bare array)
```json
[{"id":"b64url credential id","short_id":"AbCdEfGh…wXyZ","label":"iPhone","created_at":1799990000,
  "last_used_at":1799999000|null,"synced":true,"transports":["internal","hybrid"],"unusable":false}]
```
`synced` = backup-eligible (a synced passkey). `unusable` = made for another
rp_id (pocket renamed).

### `POST /api/passkeys/register/options` `{}` ★
With no usable passkey yet, the current step-up must be `method: "password"`,
else 401 `step_up_password`. 409 `conflict` at 10 passkeys.
→ `{"status":"ok","publicKey":{"rp":{"id","name"},"user":{"id","name":"owner@<host>","displayName"},"challenge","pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],"authenticatorSelection":{"residentKey":"preferred","requireResidentKey":false,"userVerification":"required"},"attestation":"none","excludeCredentials":[...],"timeout":120000}}`
(feed it to `PublicKeyCredential.parseCreationOptionsFromJSON` where available).

### `POST /api/passkeys/register` (cap 160 KB)
`{"credential":{"id","rawId","type","response":{"clientDataJSON","attestationObject","transports"?}},"label"?:"≤40 chars"}`.
Needs a still-fresh step-up (401 `step_up`) and the pending challenge from
register/options issued to this device + owner cookie. Label defaults to the
device hint ("iPhone", ...).
→ **201** `{"status":"ok","passkey":{...as in GET /api/passkeys...}}`. 401 `stepup_failed`, 409 `conflict` (limit / already registered).

### `POST /api/passkeys/<id>/rename` `{"label":"1..40"}` (not ★) → `{"status":"ok","passkey":{...}}`
### `POST /api/passkeys/<id>/delete` `{}` ★ → `{"status":"ok","passkeys":[...remaining...]}`

`<id>`: the credential id, `^[A-Za-z0-9_-]{16,1400}$` (URL-safe as is).

## Notifications

- `GET /api/push` (existing) → `{"supported":true,"public_key":"...","subscriptions":[{"id":"16 hex","endpoint_host":"fcm.googleapis.com","label":"Android","created":...,"topics":["reopen","pairing","invite"]}],"this_endpoint_hint":null}`.
  The page finds its own subscription by hashing its endpoint: `id` =
  first 16 hex of sha256(endpoint).
- `POST /api/push/topics` `{"endpoint":"..."}` or `{"id":"16 hex"}` plus `{"topics":["reopen","pairing","invite","access"]}`
  → `{"status":"ok","topics":[...],"subscriptions":[...]}`; 400 unknown topic, 404 no such subscription.
- `subscribe`, `unsubscribe`, `test` are unchanged.

Push payloads (service worker v2, `lib/pocket_static/sw.js`):
- `{"t":"reopen","id","name","title","body"}`: Allow 1h / Allow 24h buttons; tap → `/reopen/<id>`.
- `{"t":"pairing","code","device_name","kind","title","body"}`: no buttons, `requireInteraction`; tap → `/#/requests/pairing/<code>`.
- `{"t":"invite","invite_id","note","device_name","title","body"}`: tap → `/#/people/guests/<invite_id>`.
- `{"t":"access","id","host","title","body"}`: no buttons (allowing needs a step-up), `requireInteraction`; tap → `/#/requests/access/<id>`.
- `{"t":"test","title","body"}`.

## SSE `/api/events` (existing stream)

Existing events: `clip`, `inbox`, `links`, `requests` (reopen records).
New, **owner cookie only** (a `porch clip` CLI-token stream never gets them),
each sent once on connect and then on change:

| event | data | when |
|---|---|---|
| `doors` | `{"status":"ok","now","doors":[...]}` as `GET /api/doors` | any door state file added/removed/rewritten, or a door write from Pocket |
| `history` | the `GET /api/doors/history` array | history.jsonl or the launch recipes change (at most every 5 s) |
| `people` | `{"devices","invites","apps","public_paths","pairings","access","accepts","auth"}` (shapes as above) | the auth watcher sees a change (from its last snapshot; no extra porch-auth call) |
| `stepup` | `{"active":bool,"expires_at":epoch|null,"method":"passkey"|"password"|null}` | a step-up starts, ends (`/api/stepup/end`) or runs out |

The stream sends `: ping` every 15 s and is recycled after 25 min
(EventSource reconnects). 16 streams total, 4 per client (429 beyond).

## Page headers

HTML responses carry `Permissions-Policy: publickey-credentials-get=(self),
publickey-credentials-create=(self), camera=(), microphone=(), geolocation=()`.

`GET /` is the Porch app shell (`lib/pocket_static/app.html`, filled by
`pocket_assets.render_shell`), `Cache-Control: no-store`, with exactly this CSP
(a fresh nonce per response):
```
default-src 'none'; script-src 'self' 'nonce-N'; style-src 'self' 'nonce-N'; font-src 'self';
img-src 'self' data: blob:; connect-src 'self'; manifest-src 'self'; worker-src 'self';
form-action 'none'; base-uri 'none'; frame-ancestors 'none'
```
Every script and the stylesheet are hashed `/static/<stem>.<sha256[:12]>.<ext>`
files (plus `/static/seal.js`); the only nonced element is the config block
`<script type="application/json" id="cfg">` = `{"maxFile", "ios", "title",
"tunnel_base", "version"?}` (`version`: the checkout's short git hash, read at
start; absent outside git), with `<` escaped. A share-target POST still
redirects to `/?shared=1&files=N&text=0|1&f=<name>...&c=<clip id>`; Home shows
"Make a link?" for those and then drops the query.

`/sw.js` names a hashed `/static/precache.<hash>.json` (every hashed asset,
plus porch.css and its fonts under `/__porch-assets/`); the worker precaches
it on install (dropping what an older deploy cached), serves those files
cache-first and `/` network-first, and never caches API answers.

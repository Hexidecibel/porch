# Security model

Found a vulnerability? Report it privately: see [SECURITY.md](../SECURITY.md).

- **The one-line installer creates a `porch` user with passwordless sudo.**
  `site/porch.sh` writes `/etc/sudoers.d/90-porch` (`porch ALL=(ALL)
  NOPASSWD:ALL`, checked with `visudo -cf`; the account has no password).
  Setup and later certificate renewals run unattended and need root for
  HAProxy, the firewall, systemd units and reloads, so they go through
  `sudo -n`. If that is too broad for you, install by hand and give your own
  user the sudo rules you are comfortable with.
- **Loopback only.** Every app server binds `127.0.0.1`; HAProxy and frp are
  the only way in.
- **Per-device tokens** for frp, minted by an interactive pairing flow and
  checked at login and on every heartbeat. Paired machines may only open plain
  HTTP(S) subdomains; raw TCP, custom domains and reserved names need an admin
  role.
- **Owner sign-in is per host.** Owner controls (delete, list, admin) appear
  only for an enrolled admin browser, proven by a host-only `porch_host`
  cookie handed off through the auth server with single-use codes bound to the
  browser that started the flow. No shared passwords in URLs; everything fails
  closed when the device registry is missing.
- **Public paths stay narrow.** A public path on a gated app is never `/`;
  `..`, `//`, encoded dots/slashes and `;` fall back to the login page, and
  the app gets no identity headers on a public hit, even from the owner.
- **Door proxy gates**: scrypt-hashed door passwords (5 tries per minute per
  IP), HMAC session cookies bound to the current password and guest token,
  request-smuggling defences, open counting that a script can't bypass.
- **Step-up** for risky actions in the Porch app: WebAuthn passkeys (strict
  CBOR, ES256/RS256, user verification required) or the admin password, bound
  to the owner cookie, 5 minutes.
- **Strict CSP everywhere**: per-response nonces, no `unsafe-inline`, no
  `innerHTML`; untrusted strings go into the DOM as text only.
- **No secrets in argv or logs.** Passwords come from the environment or a
  prompt; setup stores only refs (`inf://`, `op://`, `file://`) and masks every
  value in state, logs and output; received secrets go to a 0700 tmpfs dir by
  atomic 0600 rename; the inspector masks before it writes.
- **Admin login** is rate-limited per IP, with a global slowdown during a
  password spray that never locks the owner out.

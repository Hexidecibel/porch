# Security policy

Porch puts a home machine on the internet, so security reports are welcome
and taken seriously. How the pieces are meant to be protected is described
in [docs/security.md](docs/security.md).

## Supported versions

Only the **latest release** on
[GitHub releases](https://github.com/Hexidecibel/porch/releases) gets
security fixes. Fixes ship as a new release; there are no backports to older
versions. If you run an older install, re-run the installer to upgrade
(`curl -sSL https://raw.githubusercontent.com/Hexidecibel/porch/main/site/porch.sh | sudo sh`).

## Reporting a vulnerability

Report privately, never in a public issue, pull request or discussion:

1. Open the repository's **Security** tab and choose **Report a
   vulnerability** (GitHub private vulnerability reporting), or go straight to
   <https://github.com/Hexidecibel/porch/security/advisories/new>.
2. Say what is affected (file, endpoint or command), the version or commit,
   how to reproduce it, and what an attacker gains. A proof of concept helps;
   please keep it against your own install.

Please don't test against Porch installs you don't own, and don't access,
change or keep other people's data. Give us a reasonable chance to ship a fix
before you disclose; we will agree on a date with you.

## What to expect

- An acknowledgement within **7 days**.
- An assessment (confirmed, needs more information, or not a vulnerability)
  within **14 days**.
- For confirmed issues, a fixed release as soon as practical, usually within
  **30 days** for serious problems, and a GitHub security advisory crediting
  you unless you prefer to stay anonymous.

Porch is maintained by one person in their spare time, so these are goals,
not guarantees. There is **no bug bounty**.

## In scope

- **The auth server** (`lib/authserver.py`, `lib/porch_auth.py`): device
  pairing, frp plugin checks, owner sign-in, invites, the admin UI and its
  CLI token.
- **The door proxy** (`lib/doorproxy.py`, `lib/door_*.py`,
  `lib/inspect_store.py`): passwords, guest links, open limits and burn
  links, request smuggling, the inspector's masking and replay.
- **Tunnels and the app servers** behind them: `bin/tunnel`, `serve`, `view`,
  `drop`, `media`, `music`, `paste`, `exchange`, `secure-entry`, `hook`, the
  status console, and the shared HTTP core (`lib/porch_http.py`): path
  traversal, owner-gate bypasses, XSS or CSP bypasses, upload validation.
- **The Porch app** (Pocket, `lib/pocket*.py`, `lib/pocket_static/`):
  owner-only routes, share keys, step-up (passkeys and password), Web Push.
- **Seal crypto** (`lib/porch_seal.py`, `lib/seal.js`, `lib/sealserver.py`;
  format in `docs/porch-seal.md`) and the passkey verifier
  (`lib/porch_webauthn.py`).
- **The installers and setup**: `site/porch.sh`, `site/install.sh`,
  `bin/bootstrap`, `bin/porch setup` and its web wizard, the relay scripts,
  and how release tarballs are built and verified.

## Out of scope

- Vulnerabilities in frp, HAProxy, certbot, Python or the OS themselves
  (report those upstream; tell us if Porch's configuration makes one worse).
- The documented trade-offs in [docs/security.md](docs/security.md), such as
  the installer's passwordless-sudo `porch` user, unless you find a way to
  abuse them beyond what is described.
- Anything that needs an already-compromised owner device or root on the
  box, denial of service by sheer traffic volume, missing hardening headers
  with no demonstrated impact, and reports from automated scanners without a
  working issue.

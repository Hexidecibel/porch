# The Porch app (Pocket): owner guide

Pocket is your private page at `https://pocket.<tunnel base>/` (for this box,
`https://pocket.tunnel.cush.rocks/`). It started as a share target and a
clipboard; it is now the **Porch app**, the place to run the whole box from a
phone: the doors you have open, the people and machines you let in, and the
requests waiting on you. Only you can open it: it checks your owner cookie
(`porch_host`, from "Owner? Sign in") on every request.

## Install it on your phone

The quickest way is the QR code on the setup wizard's last screen ("Your porch
is ready", also printed by `porch setup` in the terminal). It points at
`https://pocket.<tunnel base>/__porch/start`: scan it, type the admin password
once (that enrolls the phone as the owner), and you land in Pocket signed in.

Pocket then offers to install itself, on Home (a card you can hide) and under
You > About:

- **Android, and Chrome or Edge on a computer**: an **Install Porch** button.
  It only appears when the browser says the app can be installed, and goes
  away once it is. Installed, Pocket appears in the share sheet, so
  "Share → Pocket" drops files and text straight into it.
- **iPhone / iPad in Safari**: the card shows the steps: tap **Share**, then
  **Add to Home Screen**, then **Add**, and from then on open Pocket from its
  icon. It runs full screen, and two things only work there:
  **notifications** (iOS allows web push only for home-screen apps, iOS 16.4
  and later) and the most reliable Face ID prompt.
- **Chrome, Firefox or Edge on iPhone/iPad**: only Safari can add a web app to
  the home screen, so the card says to open the page in Safari (with a Copy
  link button).

Nothing is shown when Pocket already runs from the home screen.

The first time you open it on a device without the QR you may land on "This
pocket is private": tap **Owner? Sign in**, sign in on the auth host, and you
come back signed in.

## The tabs

On a phone the five tabs sit at the bottom; on an iPad they become a rail
on the left with a list and a detail side by side; on a laptop or an iPad
in landscape, a sidebar with counts.

**Home**: what needs you right now.
- *Waiting on you*: up to three cards. An ask to reopen a closed door gets
  **Allow 1h / Allow 24h / Deny** right on the card; a machine or browser that
  wants to pair gets **Review** (approving needs an unlock, see below).
- *Open now*: the doors closing soonest, with a countdown and how many times
  each was opened.
- *Share something*: your clipboard (Copy, Paste from this device), Upload
  files, Photos & videos, Send encrypted, Make a link, New door.
- *Recent inbox* and *Your links* (the doors Pocket made for you, with +1h,
  Never and Close).
- After you share to Pocket from another app, a "Make a link?" card offers
  to turn what arrived into its own door.

**Doors**: every door on the box. *Open* and *Recent* segments, plus
**New door**.
- Tap a door for its link (copy, share, QR), its guest link, **Expiry** (+1h,
  +24h, 30 min / 1 hour / 24 hours / 7 days / Never, or an exact time),
  **Share rules** (password, guest link, max opens / burn after one) and
  **Stop door**. A door without rules can get its first one live: Pocket
  puts a door proxy in front (up to 15 s). An old door that can't switch
  live shows **Restart needed** with the exact command to copy.
- Doors started with `--inspect` (and `bin/hook` webhooks) have an
  **Inspector**: every request live, the full record (headers, body, secrets
  masked), **Copy as curl** and **Replay**.
- *Recent*: closed doors for 7 days. **Reopen 1h / 24h** brings one back
  exactly as it was (same link, password, guest link); **Revive** starts a
  fresh one; the x forgets it. **Stop all** (in the ⋯ menu) stops every door
  except Pocket itself.
- New door: drop, photos, media, music, exchange, secret, paste; a name (a
  free one is suggested), expiry, and optional password, guest link, max opens
  or burn after one. The result shows the link with a QR.

**Requests**: everything that asked for you. Reopen asks, people asking for
access, machines and browsers that want to pair, and guest activity (who
used an invite).
- **Asked for access**: someone landed on a private app's gate page ("This
  one's private", "Not on your pass", "Your pass ran out") and asked to be
  let in. The card shows the app, their name if they gave one, and who they
  are: a browser with a pass that lacks this app (**Add to their pass**
  adds it, and their page goes straight in), or someone without a pass
  (**Allow** sends their page a one-time invite for that app only, good for
  an hour; *Allow for 24h* makes the browser it enrolls a 24-hour pass).
  Only their page ever sees that invite link. Letting someone in needs an
  unlock; **Deny** doesn't. Asks run out after 30 minutes.
- A pairing shows its **code** big: check it matches the code on the machine
  (or the browser) before you approve. A machine can be made a *tunnel admin*
  (raw TCP/UDP, custom domains, reserved names): leave it off unless it's
  yours. A browser needs the apps it may open picked; *All apps* asks you to
  confirm. **Reject** needs no unlock.

**People**: *Devices* (this browser, admin browsers, guest browsers with
their pass expiry, machines, revoked), *Guests* (invites and guest passes)
and *Apps* (which hosts are gated, and their public paths).
- A device: rename it, change its role or its apps, revoke it. Revoking the
  browser you're holding asks you to type a confirmation.
- **New invite / New guest pass**: who it's for, the apps, how long the link
  works, how many uses (or how many browsers at once for a pass) and how long
  each browser lasts. The link and its QR are **shown once**: Pocket keeps no
  copy, so share it from that screen.
- *Apps*: switch a gate on and only browsers you approved get in.
- **Public paths**: under a gated app, its open URLs (say `/s/` for share
  links, or one webhook path): path, who asked, why and since when, with an
  on/off switch and a remove button. **Open a path** picks the app and the
  path; a path ending in `/` opens everything under it, anything else exactly
  that path. Opening one, or switching it back on, needs an unlock;
  switching off or removing doesn't. Visitors on a public path are anonymous
  to the app, even you, and odd paths (`..`, `//`, encoded slashes) still get
  the login page. Home shows "Open to the public: N paths" while any are on.
  From a terminal: `porch public ls|add|on|off|rm`.

**You**: *Security* (the unlock, passkeys, admin password), *Notifications*,
*Share from iPhone* (the Shortcut and its device keys), *Activity* (every
privileged action, newest first: what, which door or device, unlocked by
passkey or password, from where) and *About* (pocket name, porch-auth status,
version).

## Unlocking (step-up) and Face ID

Reading things and day-to-day door work (extend, stop, a new password, a new
guest link, launching, reopen asks) need nothing extra. Actions that **let
more people in or cut people off** ask you to **unlock** first:

- removing a password or a max-opens limit from a door, Stop all;
- approving a pairing; revoking a device, changing its role or its apps;
- making an invite or guest pass, revoking an invite *with* its browsers;
- gating or un-gating an app; changing the admin password;
- adding or deleting a passkey.

Unlocking lasts **5 minutes** (the chip at the top says "Unlocked 4:12"; tap it
to end early). It is tied to this browser and its sign-in, and it ends if
Pocket restarts. After you unlock, the action you tapped goes ahead by
itself.

**Set up Face ID / fingerprint once** (per device):

1. You → Security → Passkeys → **Add a passkey**.
2. The first passkey needs the **porch-auth admin password** (the one for
   auth.cush.rocks): type it in the unlock sheet.
3. Your phone asks for Face ID / fingerprint and saves the passkey (iCloud
   Keychain or Google Password Manager sync it to your other devices; it
   shows a "synced" badge).

From then on the unlock sheet's first button is **Use Face ID / fingerprint**
(on a laptop, **Use passkey**). The admin password always works too (*Use
admin password*), so a lost phone never locks you out. If Face ID is
cancelled the sheet says so and you can try again. Too many wrong tries (5 in
5 minutes from one address, 10 in 15 minutes from one device) pause unlocking
for a while; the sheet counts down.

Passkeys belong to the pocket's exact address. If you rename the pocket,
old passkeys show as *unusable*: delete them and add new ones (the password
still works meanwhile). Up to 10 passkeys.

## Notifications

You → Notifications → switch on *This device* (iOS: only inside the
home-screen app). Then pick what this device hears about:

- **Reopen asks**: someone opened a closed link and asked you to reopen it.
  On Android the notification has *Allow 1h / Allow 24h* buttons; anywhere
  else a tap opens the ask.
- **New machines and pairings**: a machine or browser wants to pair. No
  buttons (approving needs an unlock); a tap opens the pairing with its code.
- **Guest invite used**: someone joined through one of your invites or guest
  passes; a tap opens that invite.
- **Asks for access**: someone at a private app's gate page asks to be let
  in. No buttons (letting someone in needs an unlock); a tap opens the ask.
  A device that picked its topics before this one existed has it off until
  you tick it.

**Send a test** checks the whole path. Other devices that subscribed are
listed with their own topics; you can mute or remove them from here.

## Offline and when something is down

- Offline, Pocket still opens (the app is cached on the device) and shows
  "You're offline", with the last data it had; changes are disabled until
  you're back.
- If porch-auth isn't answering, People and Requests say so in a banner;
  doors keep working.
- If your sign-in for this host ends, Pocket shows "Signed out on this host"
  with a Sign in button that brings you back where you were.

## For the box (operator notes)

- Service: `porch-pocket@pocket` (systemd user unit). After a code change:
  `systemctl --user restart porch-pocket@pocket`. The page is cached by the
  service worker; a restart serves new hashed files and the app picks them up
  on the next launch.
- Data: `~/pocket/<name>/` (inbox, `.clip.json`, `.passkeys.json`,
  `.push.json`, `.audit.jsonl`, `.share-keys.json`, all 0600).
- The API contract is `docs/pocket-api.md`; the iPhone Shortcut is
  `docs/pocket-ios-shortcut.md`.

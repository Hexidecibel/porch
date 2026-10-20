# Sharing to Pocket from an iPhone (Shortcuts)

iOS has no Web Share Target, so a Pocket installed from Safari never shows up
in the share sheet. A Shortcut can do the same job: it appears in the share
sheet and POSTs what you shared to Pocket's `/share` endpoint, authorised by a
**device share key**.

## What a device key can do

- It works on `POST /share` and nowhere else. It can add files to the inbox
  and set the clipboard. It cannot read the clipboard, list or download the
  inbox, upload via `/tus/`, open the page, or make more keys.
- Pocket keeps only its SHA-256 (in `~/pocket/<name>/.share-keys.json`, 0600).
  The key is shown once, when you create or rotate it.
- Each key has a label ("My iPhone"). You can have up to 10, and revoke or
  rotate each one from the page.
- Rate limits: 60 shares per key per 10 minutes, and 10 wrong keys per client
  address per 10 minutes. After that the address gets 429 (even with a right
  key) until the window has passed.
- The key is never logged. The log says `share via device key 'My iPhone'`.

## 1. Make a key

1. Open your pocket (for example `https://pocket.tunnel.cush.rocks`) in a
   browser where you are signed in as the owner.
2. Open **iPhone setup** at the bottom of the page (it opens by itself on an
   iPhone).
3. Type a device name and tap **Create device key**.
4. Copy the key (`pks_...`). It will not be shown again. If you lose it, tap
   **Rotate**: you get a new key and the old one stops working.

Tip: create the key on the iPhone itself and tap **Copy key**, so you can paste
it straight into the Shortcut.

## 2. Shortcut "Send to Porch" (photos, videos, files)

1. Open **Shortcuts**, tap **+** (new shortcut), and rename it **Send to Porch**.
2. Tap the **(i)** details button (on older iOS: the settings toggle icon) and
   turn on **Show in Share Sheet**. Then tap the "Receive ... from Share Sheet"
   line at the top of the editor and leave only **Images**, **Media**,
   **Files** and **PDFs** selected. For "If there's no input", choose **Stop
   and Respond** (or Continue, it doesn't matter).
3. Add the action **Repeat with Each**. Its input should be **Shortcut Input**
   (tap the blue field to pick it if it isn't).
4. Inside the repeat, add **Get Contents of URL**.
   - URL: `https://pocket.tunnel.cush.rocks/share` (your pocket's address plus
     `/share`; the page shows the exact URL).
   - Tap **Show More**.
   - **Method**: `POST`.
   - **Headers**: tap **Add new header**. Key: `Authorization`. Value:
     `Bearer ` (with one space) followed by your key, for example
     `Bearer pks_AbC...`.
   - **Request Body**: `Form`.
   - Tap **Add new field**, choose **File**. Key: `files`. Value: tap and
     choose **Repeat Item**.
5. Optional, after **End Repeat**: add **Show Notification** with the text
   "Sent to Pocket".
6. Tap **Done**.

To use it: in Photos (or Files, or any app), select one or more items, tap
**Share**, scroll the app row or the action list, and tap **Send to Porch**.
The files land in the inbox and appear on every open Pocket page at once.

The repeat sends one request per item. That keeps each request small and
means one failed item doesn't lose the rest.

## 3. Shortcut "Porch: text" (links and text to the clipboard)

1. New shortcut, named **Porch: text**.
2. **Show in Share Sheet** on; receive only **Text**, **URLs** and **Safari
   web pages**.
3. Add **Get Contents of URL** with the same URL, **Method** `POST`, and the
   same `Authorization` header.
4. **Request Body**: `Form`. **Add new field**, choose **Text**. Key: `text`.
   Value: **Shortcut Input**.
5. Optional: **Show Notification**.

Sharing a page from Safari sends its URL. It becomes the current clipboard
entry, one tap from **Copy** on the desktop (or `porch clip` in a terminal).

## 4. Optional: "Clipboard to Pocket"

The same shortcut as in step 3, without the share sheet: add **Get Clipboard**
first and set the `text` field to **Clipboard**. Put it on the Home Screen, or
bind it to Back Tap (Settings > Accessibility > Touch > Back Tap), and the
phone's clipboard reaches the desktop in one tap.

## What Pocket answers

Every answer is JSON. Add **Get Dictionary Value** (`message`) and **Show
Notification** after the request if you want to see it.

| Status | Meaning |
|---|---|
| 200 `{"status":"ok","message":"Got 1 file."}` | Saved. |
| 401 `Unknown or revoked device key` | Wrong key, or it was revoked or rotated. |
| 413 | Over the per-file limit (1 GB by default) or the inbox quota. |
| 429 | Too fast, or too many wrong keys from this address. Wait a few minutes. |
| 503 | Too many uploads at once. Try again. |

## Sharing onward: links from the app

Anything that lands in Pocket can be passed on without the Shortcut. Open
Pocket, tap **Link** next to an inbox file or a clip, choose how long it lasts
(and optionally a password, burn after one open, or a guest link), and you get
a link with Copy, Share and a QR code. **Send encrypted** does the same for a
file you pick on the iPhone itself, encrypting it before it leaves the phone.
Doors made this way show up under **Links**, where you can extend or close them.

## Revoking a lost phone

Open **iPhone setup** and tap **Revoke** next to its key (tap twice to
confirm). It stops working at once. **Rotate** keeps the label and gives a new
key; paste it into the Shortcut's header.

## Testing from a terminal

```bash
curl -sS -H "Authorization: Bearer $KEY" \
     -F text='hello from curl' -F files=@photo.jpg \
     https://pocket.tunnel.cush.rocks/share
```

`X-Porch-Share-Key: <key>` works in place of the `Authorization` header.

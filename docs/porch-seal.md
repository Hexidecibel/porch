# porch-seal: end-to-end encrypted shares

`porch share --e2e <file>` encrypts a file on your machine before it is
shared. The door (`bin/seal`, `lib/sealserver.py`) only ever holds the
encrypted bytes. The recipient's browser decrypts them with a key that is in
the link's `#k=` fragment, or with a password the recipient types.

```bash
porch share --e2e report.pdf                      # prints https://report-1a2b.<tunnel base>/#k=...
porch share --e2e report.pdf --burn               # closes after one complete download
porch share --e2e notes.txt --seal-password       # no key in the link; the recipient types it
git diff | porch share --e2e -                    # stdin is sealed from memory, never written in clear
```

Code: `lib/porch_seal.py` (Python: sealing, opening, CLI), `lib/seal.js`
(browsers and node: the same format, used by the page and by Pocket's
uploader), `lib/sealserver.py` and `bin/seal` (the door),
`lib/porch_setup/cmd_share.py` (`--e2e`). Tests: `tests/test_porch_seal.py`
(both implementations, fixed vectors, the fail-closed cases) and
`tests/test_sealserver.py`.

## What it protects, and what it does not

**Protected.** The plaintext and its name and type never exist on the box
in readable form. The sealed file in the run dir, the HAProxy and frp logs,
the door's log, the request inspector (`--inspect`), backups and anyone who
copies the disk see only ciphertext. Browsers do not send a URL's fragment
to the server, so the key never reaches the box either. A password is
stretched in the recipient's browser and is never sent. Every 64 KiB record
is authenticated, so a changed, reordered, cut or padded file is refused,
and the page shows nothing from it. `--burn` refuses the ciphertext after
the first complete download, deletes the sealed file at once and closes the
door shortly after.

**Not protected.**

- **The page's JavaScript.** Whoever runs the box serves the page that
  decrypts. They could serve a modified page that sends the key or the
  plaintext somewhere. End-to-end encryption here protects against the
  box's storage, logs and middleboxes. It does not protect against a
  malicious operator of the box. On your own box, that operator is you.
- **Metadata.** The file's size (to within 16 bytes per 64 KiB) and the
  times it was fetched, by which addresses, are visible to the box. So is
  whether it was opened completely.
- **The link is the key.** Anyone who has the whole link can decrypt the
  file. That includes chat history, email, a shared screen and browser
  history before the page removes the fragment. Use `--seal-password` and
  send the password another way if the link might be seen by others. Add
  the door gate (`--password`, `--guest-link`) to keep strangers from even
  downloading the ciphertext.
- **Weak passwords.** In password mode anyone with the ciphertext can guess
  offline. PBKDF2 with 600,000 iterations slows this down but does not stop
  it. `porch share` requires at least 8 characters; use a long passphrase.
- **Deletion.** A burned or closed share's sealed file is deleted. It is not
  overwritten: it was only ever ciphertext.

## The page

- The key is read from `location.hash` and never sent anywhere. The page
  fetches `/blob` with Range requests, about 4 MiB at a time, and decrypts
  as it goes.
- **The key stays in the address bar until the file opens.** Then
  `history.replaceState` removes it. While something is wrong, a reload or
  retry still works. After it opens, the key is gone from the address bar,
  from history and from screen shares. The trade-off: reloading after a
  successful open needs the original link again. With `--burn`, the
  ciphertext is gone by then anyway.
- Images (png, jpeg, gif, webp, avif, bmp), video, audio and PDF (the
  vendored pdf.js, loaded while the file decrypts) are shown from a `blob:`
  URL. Text is shown with `textContent`, up to 4 MiB. Anything else gets a
  Download button. Only those media types get their real type on the Blob.
  Everything else is `application/octet-stream`, so a `blob:` URL can never
  become a page on this origin. The file's name is shown with `textContent`
  only.
- The in-memory limit is 1 GiB on desktops and 300 MiB on iOS and iPadOS
  (detected from the user agent and touch points). Above it, the page shows
  the size and offers "Decrypt and download". That streams to disk through
  `showSaveFilePicker` where the browser has it, and otherwise builds the
  download from parts.
- Errors are shown as banners: a missing key, a wrong key ("the link may be
  cut short"), a wrong password (the prompt comes back), a changed file
  ("failed the integrity check, nothing is shown"), a broken file, or a gone
  share (410/404: burned, expired or closed).
- CSP: `default-src 'none'; script-src 'self' 'nonce-…'; style-src 'self'
  'nonce-…'; font-src 'self'; connect-src 'self'; worker-src 'self';
  img-src 'self' blob:; media-src 'self' blob:; form-action 'none';
  base-uri 'none'; frame-ancestors 'none'`, plus `Referrer-Policy:
  no-referrer`, nosniff and `X-Frame-Options: DENY`. The page uses
  `data-app="secret"`, the green of secure-entry, the other tool built so
  that the box never sees the plaintext.

## Opens and burn on a seal door

On other doors, the door proxy counts page views. On a seal door, an
**open is a complete download of the ciphertext**. bin/seal writes
`opens_by: "app"` to the door's state file. The door proxy then counts
nothing and never closes the door for `max_opens`, though password and
guest-link gates still apply. sealserver tracks, per client, the byte
ranges of `/blob` it has actually written. A client is the right-most
non-loopback `X-Forwarded-For` hop from a loopback peer. When one client
has received every byte, sealserver counts one open
(`door_state.count_open`) and starts that client over, so a second
complete download counts again. Partial downloads never count. Neither
does the owner (`porch_auth`, `data/devices.json`). Link previewers that
fetch only `/` cost nothing. When the count reaches the door's live
`max_opens` (`--burn` = 1; `porch door rules` changes apply to the next
open), `/blob` answers 410, an owned sealed file is deleted at once, and
`door_state.stop_door` runs 30 s later. The grace lets a page that just
finished still load pdf.js and its fonts. Two clients behind one address
share one coverage record.

`bin/seal <file.pseal> [name] [--owned-file] [--owned-dir DIR] [door flags]
[--bg]`: `--owned-file` deletes the sealed file when the door closes or
burns. That is honoured only for a file directly in the private share run
dir (`$XDG_RUNTIME_DIR/porch/share/`), or directly in an `--owned-dir`.
That directory must be yours, must not be group or world writable, and
must not be `/` or `$HOME`. Pocket stores sealed uploads under
`~/pocket/<name>/sealed/` and passes that directory.

## Format: porch-seal v1

All integers are big-endian.

**Key.** 32 random bytes. Links carry `#k=<base64url(K), no padding>`.
**Password mode.** There is no key in the link. K =
PBKDF2-HMAC-SHA256(password as UTF-8, salt, 600000 iterations, 32 bytes).

**Header H, 48 bytes.**

| bytes | field |
|---|---|
| 0-7 | magic `PSEAL1\n\0` (`50 53 45 41 4C 31 0A 00`) |
| 8 | version `0x01` |
| 9 | mode: 0 = key, 1 = password |
| 10-25 | salt (16 bytes; zeros in key mode) |
| 26-33 | nonce prefix (8 random bytes) |
| 34-37 | record size R (= 65536) |
| 38-47 | zero |

**Record 0 (metadata).** The plaintext is exactly 4096 bytes: a 4-byte
length L, then the UTF-8 JSON `{"name":…, "type":…, "size":…}` (L ≤ 4092),
then zero padding. `type` is a MIME type and `size` is the plaintext byte
count. Names longer than 255 characters are cut, keeping a short extension.

**Content records 1..n.** Each holds R plaintext bytes, except the last,
which holds 1..R. An empty file has n = 0.

**Encryption.** AES-256-GCM with the 16-byte tag appended. The nonce for
record i is prefix(8) ‖ uint32(i). The AAD is H ‖ final_flag. final_flag is
`0x01` on the last record (record 0 when n = 0, else record n) and `0x00`
otherwise.

**Offsets in the ciphertext.** Record 0 is at 48, 4112 bytes long. Record
i ≥ 1 is at 48 + 4112 + (i-1)·(R+16), R+16 bytes long, except the last,
which is shorter. Total size = 48 + 4112 + n·16 + size. The plaintext size
follows from the total, so a reader knows n before record 0 is opened.

**Opening fails closed** on a bad tag (kind `key` for record 0, `tamper`
after it), a wrong magic, version, record size, reserved bytes or a salt in
key mode (`format`), a length no plaintext size fits (`format`), a length
that disagrees with the metadata (truncation, a dropped final record,
trailing bytes: `tamper`), and a final flag on the wrong record (`tamper`,
or `key` for record 0). Content decrypted before an error is discarded.

**Test vectors.** These are in `tests/test_porch_seal.py`. The plaintext is
`"porch-seal v1 test vector\n" * 3`, the name `vector.txt`, the type
`text/plain` and the nonce prefix `0102030405060708`. Key mode uses the key
bytes 0..31. Password mode uses `correct horse` with salt bytes 16..31.
Each vector has the header hex, the hex of the single content record and
the SHA-256 of the whole file. Both implementations must produce them
byte for byte. The salt and prefix can be fixed only through test-only
arguments (`_test_salt`/`_test_prefix`, `_salt`/`_prefix`).

## Interfaces

`lib/porch_seal.py`: `seal_file(src, dst, name, mime, key=None,
password=None)` returns the key as base64url, or None in password mode.
`src` is a path or a seekable file object, `dst` is created 0600 with
O_EXCL, and it streams. `open_file(src, key_b64=None, password=None)`
returns `(meta, iterator of plaintext chunks)`. Helpers: `build_header`,
`parse_header`, `record_span`, `ciphertext_size`, `plaintext_size`, `info`,
`available()`. Without python3-cryptography, `SealUnavailable` says `sudo
apt install python3-cryptography`. The CLI is `python3 lib/porch_seal.py
seal|open|info`.

`lib/seal.js` (`window.PorchSeal`, or `module.exports` in node): see the
comment block at the top of the file. The API is frozen. `newKey()`,
`deriveKey(password, salt)`, `new Sealer(file, {name, type, key |
password})` with `.key`, `.totalSize()`, `.nextChunk()` and async
iteration, `open(blob | bytes | url | fetchRange, {key | password})` →
`{meta, size, records, chunks}`, `keyFromFragment(location.hash)`,
`ciphertextSize`, `plaintextSize`, and `SealError` with `.kind` (`format`,
`key`, `tamper`, `gone`, `network`).

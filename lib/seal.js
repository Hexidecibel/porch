/*
 * seal.js: porch-seal v1 for browsers and node (>= 20), the twin of
 * lib/porch_seal.py (byte-compatible; tests/test_porch_seal.py checks both
 * directions and fixed vectors). Spec and threat model: docs/porch-seal.md.
 *
 * Load it as a classic script (it defines window.PorchSeal / self.PorchSeal)
 * or require() it in node (module.exports is the same object). It uses only
 * WebCrypto (globalThis.crypto.subtle): AES-256-GCM and PBKDF2-SHA256.
 * Nothing here touches the DOM, and it never sends a key anywhere.
 *
 * API (frozen: lib/sealserver.py's page and Pocket's uploader depend on it)
 *
 *   PorchSeal.VERSION            'porch-seal/1'
 *   PorchSeal.RECORD_SIZE        65536
 *   PorchSeal.newKey()           -> base64url (no padding) of 32 random bytes
 *   PorchSeal.deriveKey(password, salt)
 *                                -> Promise<Uint8Array(32)>; salt is a
 *                                   Uint8Array(16); PBKDF2-HMAC-SHA256, 600000
 *   PorchSeal.ciphertextSize(plainSize) -> exact sealed length
 *   PorchSeal.plaintextSize(ctSize)     -> inverse (throws SealError 'format')
 *   PorchSeal.keyFromFragment(location.hash)
 *                                -> the base64url key from "#k=..." (also
 *                                   "#a=b&k=..."), or null if absent/invalid
 *
 *   const s = new PorchSeal.Sealer(fileOrBlob, {name, type, key | password})
 *       source: a File/Blob, or a Uint8Array/ArrayBuffer. name/type default
 *       to the File's own. With neither key nor password a fresh key is made.
 *       s.key           base64url key (key mode), null in password mode
 *       s.totalSize()   exact ciphertext length, known up front (tus
 *                       Upload-Length)
 *       s.nextChunk()   -> Promise<Uint8Array|null>: header + record 0 on the
 *                       first call (4160 bytes), then one record per call
 *                       (65552 bytes, the last shorter), null when done. Calls
 *                       are serialised; only one record is in memory at once.
 *       for await (const piece of s) { ... }   same pieces, in order
 *       s.sent          ciphertext bytes produced so far
 *
 *   const {meta, size, records, chunks} = await PorchSeal.open(source, {key | password, batch})
 *       source: a Blob, a Uint8Array/ArrayBuffer, a URL string (fetched with
 *       Range requests, same-origin credentials, no referrer), or
 *       async fetchRange(start, endExclusive) -> {data: Uint8Array, total}.
 *       Record 0 is decrypted and the length checked before open() resolves.
 *       meta = {name, type, size}; size = ciphertext length; chunks = async
 *       iterator of plaintext Uint8Arrays, decrypted progressively (batch
 *       records per fetch, default 64 = 4 MiB). Content yielded before an
 *       error must be discarded by the caller.
 *   PorchSeal.httpRange(url)     -> the fetchRange open() uses for a URL
 *   PorchSeal.SealError          .kind: 'format' (not a v1 file / bad length),
 *                                'key' (wrong key or password, or record 0
 *                                changed), 'tamper' (a later record changed,
 *                                reordered, cut, or a misplaced final flag),
 *                                'gone' (404/410), 'network'
 *   Low-level (tests, tooling): buildHeader, parseHeader, recordSpan,
 *   b64url, fromB64url, HEADER_LEN, DATA_START.
 */
(function (root) {
  'use strict';

  const cryptoObj = root.crypto;
  const subtle = cryptoObj && cryptoObj.subtle;

  const MAGIC = Uint8Array.of(0x50, 0x53, 0x45, 0x41, 0x4c, 0x31, 0x0a, 0x00);
  const VERSION_BYTE = 1;
  const MODE_KEY = 0;
  const MODE_PASSWORD = 1;
  const HEADER_LEN = 48;
  const RECORD_SIZE = 65536;
  const TAG_LEN = 16;
  const META_PLAIN = 4096;
  const META_JSON_MAX = META_PLAIN - 4;
  const META_CT = META_PLAIN + TAG_LEN;
  const DATA_START = HEADER_LEN + META_CT;
  const KEY_LEN = 32;
  const SALT_LEN = 16;
  const PREFIX_LEN = 8;
  const PBKDF2_ITERATIONS = 600000;
  const MAX_NAME = 255;

  class SealError extends Error {
    constructor(kind, message) {
      super(message);
      this.name = 'SealError';
      this.kind = kind;
    }
  }

  function needCrypto() {
    if (!subtle) throw new SealError('format', 'WebCrypto is not available here (an https page is needed)');
  }

  // ---- bytes and keys -------------------------------------------------------

  function b64url(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function fromB64url(text) {
    if (typeof text !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(text)) {
      throw new SealError('key', 'the key is missing or malformed');
    }
    let bin;
    try {
      bin = atob(text.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((text.length + 3) % 4));
    } catch (e) {
      throw new SealError('key', 'the key is not base64url');
    }
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function random(n) {
    needCrypto();
    return cryptoObj.getRandomValues(new Uint8Array(n));
  }

  function keyBytes(key) {
    const raw = key instanceof Uint8Array ? key : fromB64url(key);
    if (raw.length !== KEY_LEN) throw new SealError('key', 'the key must be 32 bytes');
    return raw;
  }

  function newKey() {
    return b64url(random(KEY_LEN));
  }

  async function deriveKey(password, salt) {
    needCrypto();
    if (typeof password !== 'string' || !password) throw new SealError('key', 'empty password');
    const base = await subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2',
      false, ['deriveBits']);
    const bits = await subtle.deriveBits({name: 'PBKDF2', hash: 'SHA-256', salt: salt,
      iterations: PBKDF2_ITERATIONS}, base, KEY_LEN * 8);
    return new Uint8Array(bits);
  }

  function importAes(raw) {
    needCrypto();
    return subtle.importKey('raw', raw, {name: 'AES-GCM'}, false, ['encrypt', 'decrypt']);
  }

  function keyFromFragment(hash) {
    const h = String(hash || '').replace(/^#/, '');
    for (const part of h.split('&')) {
      if (part.slice(0, 2) !== 'k=') continue;
      const v = part.slice(2);
      try {
        return keyBytes(v).length === KEY_LEN ? v : null;
      } catch (e) {
        return null;
      }
    }
    return null;
  }

  // ---- header and offsets -----------------------------------------------------

  function buildHeader(mode, salt, prefix) {
    const h = new Uint8Array(HEADER_LEN);
    h.set(MAGIC, 0);
    h[8] = VERSION_BYTE;
    h[9] = mode;
    h.set(salt, 10);
    h.set(prefix, 26);
    new DataView(h.buffer).setUint32(34, RECORD_SIZE);
    return h;
  }

  function parseHeader(bytes) {
    if (!bytes || bytes.length < HEADER_LEN) throw new SealError('format', 'too short to be a sealed file');
    const h = bytes.subarray(0, HEADER_LEN);
    for (let i = 0; i < 8; i++) {
      if (h[i] !== MAGIC[i]) throw new SealError('format', 'not a porch-seal file (bad magic)');
    }
    if (h[8] !== VERSION_BYTE) throw new SealError('format', 'unsupported porch-seal version ' + h[8]);
    const mode = h[9];
    if (mode !== MODE_KEY && mode !== MODE_PASSWORD) throw new SealError('format', 'unknown porch-seal mode');
    const rs = new DataView(h.buffer, h.byteOffset, HEADER_LEN).getUint32(34);
    if (rs !== RECORD_SIZE) throw new SealError('format', 'unsupported record size ' + rs);
    for (let i = 38; i < 48; i++) {
      if (h[i] !== 0) throw new SealError('format', 'reserved header bytes are not zero');
    }
    const salt = h.slice(10, 26);
    if (mode === MODE_KEY && salt.some(function (b) { return b !== 0; })) {
      throw new SealError('format', 'key-mode header carries a salt');
    }
    return {mode: mode, salt: salt, prefix: h.slice(26, 34), recordSize: rs, header: h.slice()};
  }

  function recordCount(size) {
    return size > 0 ? Math.ceil(size / RECORD_SIZE) : 0;
  }

  function ciphertextSize(size) {
    return DATA_START + recordCount(size) * TAG_LEN + size;
  }

  function plaintextSize(ct) {
    const rest = ct - DATA_START;
    if (rest < 0) throw new SealError('format', 'the sealed file is cut short');
    if (rest === 0) return 0;
    const n = Math.ceil(rest / (RECORD_SIZE + TAG_LEN));
    const size = rest - n * TAG_LEN;
    if (size <= (n - 1) * RECORD_SIZE) throw new SealError('format', 'the sealed file has a broken length');
    return size;
  }

  // [offset, length] of record i in the ciphertext of a `size`-byte file.
  function recordSpan(i, size) {
    if (i === 0) return [HEADER_LEN, META_CT];
    const n = recordCount(size);
    if (i < 1 || i > n) throw new RangeError('record ' + i + ' out of range');
    const plain = i < n ? RECORD_SIZE : size - (n - 1) * RECORD_SIZE;
    return [DATA_START + (i - 1) * (RECORD_SIZE + TAG_LEN), plain + TAG_LEN];
  }

  function nonce(prefix, i) {
    const n = new Uint8Array(12);
    n.set(prefix, 0);
    new DataView(n.buffer).setUint32(8, i);
    return n;
  }

  function aad(header, final) {
    const a = new Uint8Array(HEADER_LEN + 1);
    a.set(header, 0);
    a[HEADER_LEN] = final ? 1 : 0;
    return a;
  }

  async function encrypt(key, iv, data, ad) {
    return new Uint8Array(await subtle.encrypt({name: 'AES-GCM', iv: iv, additionalData: ad,
      tagLength: 128}, key, data));
  }

  async function decrypt(key, iv, data, ad) {
    return new Uint8Array(await subtle.decrypt({name: 'AES-GCM', iv: iv, additionalData: ad,
      tagLength: 128}, key, data));
  }

  function metaPlaintext(name, type, size) {
    let cps = Array.from(String(name || 'file'));
    if (cps.length > MAX_NAME) {
      const s = cps.join('');
      const dot = s.lastIndexOf('.');
      let ext = dot > 0 ? Array.from(s.slice(dot)) : [];
      if (ext.length > 16) ext = [];
      const stem = Array.from(dot > 0 && ext.length ? s.slice(0, dot) : s);
      cps = stem.slice(0, MAX_NAME - ext.length).concat(ext);
    }
    const body = new TextEncoder().encode(JSON.stringify({name: cps.join(''),
      type: String(type || 'application/octet-stream'), size: size}));
    if (body.length > META_JSON_MAX) throw new Error('metadata does not fit in record 0');
    const out = new Uint8Array(META_PLAIN);
    new DataView(out.buffer).setUint32(0, body.length);
    out.set(body, 4);
    return out;
  }

  function parseMeta(plain) {
    if (plain.length !== META_PLAIN) throw new SealError('format', 'metadata record has the wrong size');
    const n = new DataView(plain.buffer, plain.byteOffset, 4).getUint32(0);
    if (n > META_JSON_MAX) throw new SealError('format', 'metadata record is malformed');
    for (let i = 4 + n; i < META_PLAIN; i++) {
      if (plain[i] !== 0) throw new SealError('format', 'metadata record is malformed');
    }
    let meta;
    try {
      meta = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(plain.subarray(4, 4 + n)));
    } catch (e) {
      throw new SealError('format', 'metadata is not JSON');
    }
    if (!meta || typeof meta !== 'object' || typeof meta.name !== 'string'
        || typeof meta.type !== 'string' || !Number.isSafeInteger(meta.size) || meta.size < 0) {
      throw new SealError('format', 'metadata is missing name/type/size');
    }
    return {name: meta.name, type: meta.type, size: meta.size};
  }

  // ---- sources ------------------------------------------------------------------

  function asBytes(src) {
    if (src instanceof Uint8Array) return src;
    if (src instanceof ArrayBuffer) return new Uint8Array(src);
    if (ArrayBuffer.isView(src)) return new Uint8Array(src.buffer, src.byteOffset, src.byteLength);
    return null;
  }

  function isBlob(src) {
    return src && typeof src === 'object' && typeof src.slice === 'function'
      && typeof src.size === 'number' && !asBytes(src);
  }

  // A reader: {size, read(start, endExclusive) -> Promise<Uint8Array>}.
  function reader(src) {
    const bytes = asBytes(src);
    if (bytes) {
      return {size: bytes.length, read: function (a, b) { return Promise.resolve(bytes.subarray(a, b)); }};
    }
    if (isBlob(src)) {
      return {size: src.size, read: async function (a, b) {
        return new Uint8Array(await src.slice(a, b).arrayBuffer());
      }};
    }
    throw new TypeError('PorchSeal: the source must be a Blob, File, Uint8Array or ArrayBuffer');
  }

  function httpRange(url) {
    return async function (start, end) {
      let r;
      try {
        r = await fetch(url, {headers: {Range: 'bytes=' + start + '-' + (end - 1)},
          cache: 'no-store', credentials: 'same-origin', redirect: 'error',
          referrerPolicy: 'no-referrer'});
      } catch (e) {
        throw new SealError('network', 'could not fetch the sealed file');
      }
      if (r.status === 404 || r.status === 410) {
        throw new SealError('gone', 'this share is gone (already opened, expired or closed)');
      }
      if (r.status === 416) throw new SealError('format', 'the sealed file is cut short');
      if (r.status !== 206 && r.status !== 200) {
        throw new SealError('network', 'the server answered ' + r.status);
      }
      const data = new Uint8Array(await r.arrayBuffer());
      if (r.status === 200) return {data: data.subarray(start, end), total: data.length};
      const m = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(r.headers.get('Content-Range') || '');
      if (!m || Number(m[1]) !== start) throw new SealError('network', 'bad Content-Range from the server');
      return {data: data, total: Number(m[3])};
    };
  }

  function fetcher(src) {
    if (typeof src === 'function') return src;
    if (typeof src === 'string' || (root.URL && src instanceof root.URL)) return httpRange(String(src));
    const rd = reader(src);
    return async function (a, b) { return {data: await rd.read(a, b), total: rd.size}; };
  }

  // ---- seal ---------------------------------------------------------------------

  class Sealer {
    constructor(source, opts) {
      opts = opts || {};
      if (opts.key != null && opts.password != null) throw new Error('PorchSeal: give a key or a password, not both');
      this._src = reader(source);
      this.size = this._src.size;
      this.name = opts.name || (source && source.name) || 'file';
      this.type = opts.type || (source && source.type) || 'application/octet-stream';
      this._prefix = opts._prefix || random(PREFIX_LEN);          // _prefix/_salt: test vectors only
      if (opts.password != null) {
        if (typeof opts.password !== 'string' || !opts.password) throw new SealError('key', 'empty password');
        this.mode = MODE_PASSWORD;
        this._salt = opts._salt || random(SALT_LEN);
        this._password = opts.password;
        this.key = null;
      } else {
        this.mode = MODE_KEY;
        this._salt = new Uint8Array(SALT_LEN);
        this._raw = opts.key != null ? keyBytes(opts.key) : random(KEY_LEN);
        this.key = b64url(this._raw);
      }
      this.header = buildHeader(this.mode, this._salt, this._prefix);
      this._n = recordCount(this.size);
      this._i = 0;
      this._queue = Promise.resolve();
      this.sent = 0;
      this.done = false;
    }

    totalSize() {
      return ciphertextSize(this.size);
    }

    async _key() {
      if (!this._ck) {
        const raw = this.mode === MODE_PASSWORD ? await deriveKey(this._password, this._salt) : this._raw;
        this._ck = await importAes(raw);
        this._password = null;
        this._raw = null;
      }
      return this._ck;
    }

    async _next() {
      if (this._i > this._n) {
        this.done = true;
        return null;
      }
      const key = await this._key();
      const i = this._i, n = this._n;
      let out;
      if (i === 0) {
        const ct = await encrypt(key, nonce(this._prefix, 0), metaPlaintext(this.name, this.type, this.size),
          aad(this.header, n === 0));
        out = new Uint8Array(HEADER_LEN + ct.length);
        out.set(this.header, 0);
        out.set(ct, HEADER_LEN);
      } else {
        const start = (i - 1) * RECORD_SIZE;
        const want = i < n ? RECORD_SIZE : this.size - start;
        const plain = await this._src.read(start, start + want);
        if (plain.length !== want) throw new Error('PorchSeal: the file changed while it was being sealed');
        out = await encrypt(key, nonce(this._prefix, i), plain, aad(this.header, i === n));
      }
      this._i = i + 1;
      if (this._i > n) this.done = true;
      this.sent += out.length;
      return out;
    }

    nextChunk() {
      const p = this._queue.then(() => this._next());
      this._queue = p.catch(function () {});
      return p;
    }

    [Symbol.asyncIterator]() {
      const self = this;
      return {next: async function () {
        const c = await self.nextChunk();
        return c ? {value: c, done: false} : {value: undefined, done: true};
      }};
    }
  }

  // ---- open -----------------------------------------------------------------------

  async function open(source, opts) {
    opts = opts || {};
    needCrypto();
    const fetchRange = fetcher(source);
    const first = await fetchRange(0, DATA_START);
    const total = first.total;
    const n = recordCount(plaintextSize(total));
    if (first.data.length < DATA_START) throw new SealError('format', 'the sealed file is cut short');
    const hdr = parseHeader(first.data);
    let raw;
    if (hdr.mode === MODE_PASSWORD) {
      if (opts.password == null || opts.password === '') throw new SealError('key', 'this file is sealed with a password');
      raw = await deriveKey(opts.password, hdr.salt);
    } else {
      if (opts.key == null) throw new SealError('key', 'this link is missing its key (#k=...)');
      raw = keyBytes(opts.key);
    }
    const key = await importAes(raw);
    let plain0;
    try {
      plain0 = await decrypt(key, nonce(hdr.prefix, 0), first.data.subarray(HEADER_LEN, DATA_START),
        aad(hdr.header, n === 0));
    } catch (e) {
      throw new SealError('key', hdr.mode === MODE_PASSWORD ? 'wrong password, or the file was changed'
        : 'wrong key, or the file was changed');
    }
    const meta = parseMeta(plain0);
    if (ciphertextSize(meta.size) !== total) {
      throw new SealError('tamper', 'the sealed file has the wrong length (cut or padded)');
    }
    const batch = Math.max(1, Math.min(1024, (opts.batch | 0) || 64));

    async function* chunks() {
      let i = 1;
      while (i <= n) {
        const last = Math.min(n, i + batch - 1);
        const s = recordSpan(i, meta.size)[0];
        const ls = recordSpan(last, meta.size);
        const end = ls[0] + ls[1];
        const got = await fetchRange(s, end);
        if (got.total !== total || got.data.length !== end - s) {
          throw new SealError('tamper', 'the sealed file changed while it was being read');
        }
        for (let j = i; j <= last; j++) {
          const sp = recordSpan(j, meta.size);
          let plain;
          try {
            plain = await decrypt(key, nonce(hdr.prefix, j), got.data.subarray(sp[0] - s, sp[0] - s + sp[1]),
              aad(hdr.header, j === n));
          } catch (e) {
            throw new SealError('tamper', 'record ' + j + ' was changed, reordered or cut');
          }
          yield plain;
        }
        i = last + 1;
      }
    }

    return {meta: meta, size: total, records: n, mode: hdr.mode === MODE_PASSWORD ? 'password' : 'key',
      chunks: chunks()};
  }

  const PorchSeal = Object.freeze({
    VERSION: 'porch-seal/1',
    RECORD_SIZE: RECORD_SIZE,
    HEADER_LEN: HEADER_LEN,
    DATA_START: DATA_START,
    SealError: SealError,
    newKey: newKey,
    deriveKey: deriveKey,
    ciphertextSize: ciphertextSize,
    plaintextSize: plaintextSize,
    keyFromFragment: keyFromFragment,
    Sealer: Sealer,
    open: open,
    httpRange: httpRange,
    buildHeader: buildHeader,
    parseHeader: parseHeader,
    recordSpan: recordSpan,
    b64url: b64url,
    fromB64url: fromB64url,
  });

  root.PorchSeal = PorchSeal;
  if (typeof module === 'object' && module && module.exports) module.exports = PorchSeal;
})(typeof globalThis !== 'undefined' ? globalThis : this);

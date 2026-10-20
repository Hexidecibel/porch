#!/usr/bin/env node
// Capture a real WebAuthn registration + assertion from headless Chrome's
// virtual authenticator (CDP WebAuthn domain) into chrome-es256.json, which
// tests/test_porch_webauthn.py verifies with lib/porch_webauthn.py. Guards
// against encoding drift between real browsers and tests/webauthn_soft.py.
//
// Not run by bin/test. Usage (Node >= 22, global WebSocket):
//   node tests/fixtures/webauthn/capture.mjs [--chrome /usr/bin/google-chrome] [--out FILE]
//
// It serves a throwaway page as http://localhost/ (localhost is a
// secure context, rpId "localhost") through CDP's Fetch domain, so no server
// listens anywhere, and stops Chrome on exit (or after 60s).
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
const opt = (name, dflt) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : dflt; };
const CHROME = opt('--chrome', '/usr/bin/google-chrome');
const OUT = opt('--out', join(dirname(fileURLToPath(import.meta.url)), 'chrome-es256.json'));

const b64u = (b) => Buffer.from(b).toString('base64url');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// The page never touches the network: Fetch.requestPaused answers every
// request for ORIGIN from here (http://localhost is a secure context).
const origin = 'http://localhost';
const PAGE = '<!doctype html><title>webauthn capture</title><p>capture</p>';

const profile = mkdtempSync(join(tmpdir(), 'webauthn-capture-'));
const chrome = spawn(CHROME, [
  '--headless=new', '--no-first-run', '--no-default-browser-check', '--disable-gpu',
  `--user-data-dir=${profile}`, '--remote-debugging-port=0', 'about:blank',
  '--password-store=basic',
  // A session D-Bus that never answers stalls every http navigation here.
], { stdio: 'ignore', env: { ...process.env, DBUS_SESSION_BUS_ADDRESS: 'disabled:' } });

let ws;
function cleanup() {
  try { ws && ws.close(); } catch {}
  try { chrome.kill('SIGTERM'); } catch {}
}
process.on('exit', () => {
  try { chrome.kill('SIGKILL'); } catch {}
  try { rmSync(profile, { recursive: true, force: true, maxRetries: 3 }); } catch {}
});
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { cleanup(); process.exit(1); });
const watchdog = setTimeout(() => { console.error('timed out'); cleanup(); process.exit(1); }, 60000);

try {
  const portFile = join(profile, 'DevToolsActivePort');
  for (let i = 0; i < 100 && !existsSync(portFile); i++) await sleep(100);
  const devPort = readFileSync(portFile, 'utf8').split('\n')[0];
  let targets = [];
  for (let i = 0; i < 50; i++) {
    targets = await (await fetch(`http://127.0.0.1:${devPort}/json/list`)).json();
    if (targets.some((t) => t.type === 'page')) break;
    await sleep(100);
  }
  const page = targets.find((t) => t.type === 'page');
  ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });
  let n = 0;
  const pending = new Map();
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data);
    if (m.method === 'Fetch.requestPaused') {
      call('Fetch.fulfillRequest', { requestId: m.params.requestId, responseCode: 200,
        responseHeaders: [{ name: 'Content-Type', value: 'text/html; charset=utf-8' }],
        body: Buffer.from(PAGE).toString('base64') }).catch((e) => console.error(e));
      return;
    }
    if (m.id && pending.has(m.id)) {
      const { res, rej, method } = pending.get(m.id);
      pending.delete(m.id);
      m.error ? rej(new Error(`${method}: ${JSON.stringify(m.error)}`)) : res(m.result);
    }
  };
  const call = (method, params = {}) => new Promise((res, rej) => {
    const id = ++n;
    pending.set(id, { res, rej, method });
    ws.send(JSON.stringify({ id, method, params }));
  });
  const evaluate = async (expression) => {
    const r = await call('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails));
    return r.result.value;
  };

  await call('Page.enable');
  await call('Fetch.enable', { patterns: [{ urlPattern: `${origin}/*` }] });
  await call('Page.navigate', { url: `${origin}/` });
  await sleep(800);
  await call('WebAuthn.enable', { enableUI: false });
  await call('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });

  const regChallenge = randomBytes(32);
  const authChallenge = randomBytes(32);
  const userHandle = randomBytes(16);
  const helpers = `
    const b64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
    const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));`;
  const registration = await evaluate(`(async () => { ${helpers}
    const c = await navigator.credentials.create({ publicKey: {
      rp: { id: 'localhost', name: 'Porch' },
      user: { id: unb64u('${b64u(userHandle)}'), name: 'owner@localhost', displayName: 'Porch owner' },
      challenge: unb64u('${b64u(regChallenge)}'),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      attestation: 'none', timeout: 120000 } });
    return { id: c.id, rawId: b64u(c.rawId), type: c.type,
      response: { clientDataJSON: b64u(c.response.clientDataJSON),
        attestationObject: b64u(c.response.attestationObject),
        transports: c.response.getTransports ? c.response.getTransports() : [] },
      clientExtensionResults: c.getClientExtensionResults() };
  })()`);
  const assertion = await evaluate(`(async () => { ${helpers}
    const c = await navigator.credentials.get({ publicKey: {
      challenge: unb64u('${b64u(authChallenge)}'), rpId: 'localhost',
      allowCredentials: [{ type: 'public-key', id: unb64u('${registration.id}') }],
      userVerification: 'required', timeout: 120000 } });
    return { id: c.id, rawId: b64u(c.rawId), type: c.type,
      response: { clientDataJSON: b64u(c.response.clientDataJSON),
        authenticatorData: b64u(c.response.authenticatorData),
        signature: b64u(c.response.signature),
        userHandle: c.response.userHandle ? b64u(c.response.userHandle) : null },
      clientExtensionResults: c.getClientExtensionResults() };
  })()`);
  const version = await call('Browser.getVersion');
  writeFileSync(OUT, JSON.stringify({
    captured_with: version.product, origin, rp_id: 'localhost',
    reg_challenge: b64u(regChallenge), auth_challenge: b64u(authChallenge),
    user_handle: b64u(userHandle), registration, assertion,
  }, null, 2) + '\n');
  console.log(`wrote ${OUT} (${version.product})`);
} catch (e) {
  console.error(e);
  process.exitCode = 1;
} finally {
  clearTimeout(watchdog);
  cleanup();
  await Promise.race([new Promise((r) => chrome.once('exit', r)), sleep(5000)]);
  process.exit();
}

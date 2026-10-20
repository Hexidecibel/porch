#!/usr/bin/env python3
"""The auth host's gate pages: what a visitor sees when HAProxy turns them
away from a gated app (lib/authserver.py /login, /auth/handoff).

One page, four states, picked by the auth server from the cush_auth cookie it
sees and the host the visitor was going to:

  private   no device at all: "This one's private."
  scope     a live device whose pass lacks the host: "Not on your pass."
  expired   a device cookie that ran out or was revoked: "Your pass ran out."
  in        a device that can open the host after all: "You're on the list."

The first three offer **Ask for access** (lib/access_requests.py): an
optional name, POST /auth/access-requests, then the page polls until the
owner answers. Approved: a device is sent on to the app (its pass now has the
host), a stranger to the one-time invite link the poll answer carries.
A small "Owner? Sign in" keeps the admin-password page reachable
(/login?owner=1).

Same look as site/door-closed.html (night porch, the house mark and its lamp),
plus a day palette. Fonts come from the auth server's own
/auth/__porch-assets/fonts/ (font-src 'self'); the one <style> and <script>
carry the response nonce (lib/authserver.py _send_html). The view object is
embedded with authserver._js_string; every string reaches the DOM through
textContent.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import porch_http  # noqa: E402

STATES = ('private', 'scope', 'expired', 'in')
FONT_PREFIX = '/auth' + porch_http.ASSET_PREFIX + 'fonts/'

TITLES = {
    'private': "This one's private",
    'scope': 'Not on your pass',
    'expired': 'Your pass ran out',
    'in': "You're on the list",
}

GATE_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex">
<meta name="color-scheme" content="dark light">
<title>__TITLE__ · __BRAND__</title>
<style nonce="__NONCE__">
__FONTS__
:root {
  --ground: #121014; --surface: #1B181E; --line: #2C2630;
  --text: #F3ECE4; --muted: #A79E95; --faint: #6F6670;
  --light: #F5A524; --light-ink: #F5A524; --on-light: #1B1206;
  --light-off: #3A2F22; --light-warm: #6A4A1C; --light-mid: #C78418;
  --house: #4A424F; --glow: 245,165,36; --moth: #CFC6BB;
  --display: "Bricolage Grotesque", "Avenir Next", system-ui, sans-serif;
  --body: "Geist", "Segoe UI", system-ui, sans-serif;
  --mono: "Geist Mono", ui-monospace, "SFMono-Regular", Menlo, monospace;
  color-scheme: dark;
}
@media (prefers-color-scheme: light) {
  :root:not([data-theme="dark"]) {
    --ground: #F7F3EE; --surface: #FFFDFA; --line: #E4DCD2;
    --text: #221C17; --muted: #6B6158; --faint: #9A9087;
    --light: #F5A524; --light-ink: #9A560A; --on-light: #1B1206;
    --light-off: #D9CBB8; --light-warm: #E9C27A; --light-mid: #E0A040;
    --house: #8C8279; --glow: 230,150,30; --moth: #8C8279;
    color-scheme: light;
  }
}
* { box-sizing: border-box; }
[hidden] { display: none !important; }
html, body { height: 100%; }
body {
  margin: 0; background: var(--ground); color: var(--text);
  font: 16px/1.6 var(--body);
  display: flex; flex-direction: column;
  padding: max(24px, env(safe-area-inset-top)) max(16px, env(safe-area-inset-right))
           max(24px, env(safe-area-inset-bottom)) max(16px, env(safe-area-inset-left));
}
main {
  flex: 1; width: 100%; max-width: 560px; margin: 0 auto;
  display: flex; flex-direction: column; justify-content: center; gap: 28px;
}
.scene {
  position: relative; width: 168px; height: 168px; margin-bottom: 4px;
  border: 0; padding: 0; background: none; cursor: pointer; color: var(--house);
  -webkit-tap-highlight-color: transparent;
}
.scene:focus-visible { outline: 2px solid var(--light); outline-offset: 8px; border-radius: 12px; }
.scene svg { position: relative; width: 100%; height: 100%; overflow: visible; }
.scene .line { fill: none; stroke: currentColor; stroke-width: 4.5; stroke-linecap: round; stroke-linejoin: round; }
.scene .lamp { fill: var(--light-off); }
.scene .door { fill: none; }
.halo {
  position: absolute; left: 50%; top: 34.4%; width: 150px; height: 150px;
  margin: -75px 0 0 -75px; border-radius: 50%; pointer-events: none;
  background: radial-gradient(circle, rgba(var(--glow),.42) 0%, rgba(var(--glow),.10) 38%, rgba(var(--glow),0) 68%);
  opacity: 0;
}
.moth {
  position: absolute; left: 50%; top: 34.4%; width: 4px; height: 3px; margin: -1.5px 0 0 -2px;
  border-radius: 50%; background: var(--moth); opacity: .55; pointer-events: none;
}
.moth.a { animation: orbit-a 9s linear infinite; }
.moth.b { animation: orbit-b 13s linear infinite; opacity: .35; }
@keyframes orbit-a {
  from { transform: rotate(0deg) translateX(30px) rotate(0deg) scaleX(1.6); }
  to   { transform: rotate(360deg) translateX(30px) rotate(-360deg) scaleX(1.6); }
}
@keyframes orbit-b {
  from { transform: rotate(140deg) translateX(46px) translateY(6px) scaleX(1.4); }
  to   { transform: rotate(-220deg) translateX(46px) translateY(6px) scaleX(1.4); }
}
/* private / expired: the light is off and sputters now and then */
.scene .lamp { animation: lamp 7s steps(1, end) infinite; }
.halo { animation: halo 7s steps(1, end) infinite; }
@keyframes lamp {
  0%, 88%, 100% { fill: var(--light-off); }
  89% { fill: var(--light); } 90% { fill: var(--light-off); }
  92% { fill: var(--light); } 93.5% { fill: var(--light-off); }
  95% { fill: var(--light-mid); } 96% { fill: var(--light-off); }
}
@keyframes halo {
  0%, 88%, 100% { opacity: 0; }
  89% { opacity: .9; } 90% { opacity: 0; }
  92% { opacity: 1; } 93.5% { opacity: 0; }
  95% { opacity: .45; } 96% { opacity: 0; }
}
/* scope: the light is on, the door stays shut (a bar across it) */
[data-state="scope"] .scene .lamp, [data-state="in"] .scene .lamp { animation: none; fill: var(--light); }
[data-state="scope"] .halo, [data-state="in"] .halo { animation: none; opacity: .75; }
[data-state="scope"] .scene .bar { stroke: var(--light-ink); }
.scene .bar { fill: none; stroke: none; stroke-width: 3.5; stroke-linecap: round; }
/* expired: the moths have gone home */
[data-state="expired"] .moth { display: none; }
[data-state="in"] .scene .door { fill: rgba(var(--glow),.55); }
.scene.try .lamp { animation: lamp-try 1.3s steps(1, end) 1; }
.scene.try .halo { animation: halo-try 1.3s steps(1, end) 1; }
@keyframes lamp-try {
  0% { fill: var(--light); } 12% { fill: var(--light-off); } 22% { fill: var(--light); }
  48% { fill: var(--light-mid); } 56% { fill: var(--light-off); } 70% { fill: var(--light); }
  78%, 100% { fill: var(--light-off); }
}
@keyframes halo-try {
  0% { opacity: 1; } 12% { opacity: 0; } 22% { opacity: 1; }
  48% { opacity: .45; } 56% { opacity: 0; } 70% { opacity: .9; }
  78%, 100% { opacity: 0; }
}
.where { font: 500 13px/1.4 var(--mono); color: var(--light-ink); letter-spacing: .02em; overflow-wrap: anywhere; }
h1 { font: 700 clamp(34px, 9vw, 52px)/1.02 var(--display); letter-spacing: -.02em; margin: 10px 0 0; text-wrap: balance; }
.lede { margin: 0; color: var(--muted); font-size: 17px; max-width: 46ch; overflow-wrap: anywhere; }
.lede b { color: var(--text); font-weight: 500; }
.ways { display: flex; flex-direction: column; border-top: 1px solid var(--line); }
.way { display: grid; grid-template-columns: 9.5em 1fr; gap: 6px 18px; padding: 16px 0; border-bottom: 1px solid var(--line); }
.way b { font-weight: 500; font-size: 15px; color: var(--text); }
.way p { margin: 0; color: var(--muted); font-size: 15px; }
a { color: var(--light-ink); text-decoration: none; font-weight: 500; }
a:hover, a:focus-visible { text-decoration: underline; text-underline-offset: 3px; outline: none; }
.ask {
  display: flex; flex-direction: column; gap: 14px; padding: 20px;
  border: 1px solid var(--line); border-radius: 16px;
  background: linear-gradient(180deg, rgba(var(--glow),.07), rgba(var(--glow),0) 60%), var(--surface);
}
.ask h2 { margin: 0; font: 700 21px/1.2 var(--display); letter-spacing: -.01em; }
.ask p { margin: 0; color: var(--muted); font-size: 15px; }
.ask label { font-size: 13px; color: var(--muted); }
.ask label span { color: var(--faint); }
.ask-row { display: flex; gap: 10px; margin-top: 6px; }
.ask input {
  flex: 1 1 auto; min-width: 0; height: 48px; padding: 0 14px; border-radius: 12px;
  border: 1px solid var(--line); background: var(--ground); color: var(--text);
  font: 400 16px var(--body); outline: none;
}
.ask input::placeholder { color: var(--faint); }
.ask input:focus-visible { border-color: var(--light); box-shadow: 0 0 0 3px rgba(var(--glow),.2); }
.btn {
  display: inline-flex; align-items: center; justify-content: center;
  flex: none; height: 48px; min-width: 44px; padding: 0 20px; border-radius: 12px; border: 0;
  background: var(--light); color: var(--on-light); font: 600 16px var(--body); cursor: pointer;
  text-decoration: none; -webkit-tap-highlight-color: transparent;
}
.btn:hover, .btn:focus-visible { text-decoration: none; }
.btn.ghost { background: transparent; color: var(--light-ink); border: 1px solid rgba(var(--glow),.5); align-self: flex-start; }
.btn:disabled { opacity: .55; cursor: default; }
.btn:focus-visible { outline: 2px solid var(--light); outline-offset: 3px; }
.go { align-self: flex-start; }
.status { display: flex; gap: 12px; align-items: flex-start; font-size: 16px; color: var(--text); }
.status .dot { flex: none; width: 10px; height: 10px; margin-top: 8px; border-radius: 50%; background: var(--light-off); }
.status small { display: block; color: var(--muted); font-size: 14px; margin-top: 2px; }
[data-ask="waiting"] .status .dot { background: var(--light-mid); animation: wait 2.4s ease-in-out infinite; }
[data-ask="approved"] .status .dot { background: var(--light); box-shadow: 0 0 12px 2px rgba(var(--glow),.6); }
[data-ask="denied"] .status .dot, [data-ask="expired"] .status .dot, [data-ask="error"] .status .dot { background: var(--house); }
@keyframes wait { 0%, 100% { opacity: .35; } 50% { opacity: 1; box-shadow: 0 0 10px 1px rgba(var(--glow),.45); } }
[data-ask="waiting"] .scene .lamp { animation: warm 2.4s ease-in-out infinite; }
[data-ask="waiting"] .halo { animation: warm-halo 2.4s ease-in-out infinite; }
@keyframes warm { 0%, 100% { fill: var(--light-off); } 50% { fill: var(--light-warm); } }
@keyframes warm-halo { 0%, 100% { opacity: 0; } 50% { opacity: .18; } }
[data-state="scope"][data-ask="waiting"] .scene .lamp { animation: none; fill: var(--light); }
[data-state="scope"][data-ask="waiting"] .halo { animation: warm-halo 2.4s ease-in-out infinite; }
[data-ask="approved"] .scene .lamp { animation: catch 1.4s steps(1, end) 1 forwards; fill: var(--light); }
[data-ask="approved"] .halo { animation: catch-halo 1.4s steps(1, end) 1 forwards; opacity: 1; }
[data-ask="approved"] .scene .door { fill: rgba(var(--glow),.55); }
[data-ask="approved"] .scene .bar { stroke: none; }
@keyframes catch {
  0% { fill: var(--light); } 10% { fill: var(--light-off); } 22% { fill: var(--light); }
  34% { fill: var(--light-off); } 44% { fill: var(--light-mid); } 52% { fill: var(--light-off); } 64%, 100% { fill: var(--light); }
}
@keyframes catch-halo {
  0% { opacity: 1; } 10% { opacity: 0; } 22% { opacity: 1; } 34% { opacity: 0; }
  44% { opacity: .5; } 52% { opacity: 0; } 64%, 100% { opacity: 1; }
}
[data-ask="approved"] .moth { display: none; }
footer {
  max-width: 560px; width: 100%; margin: 28px auto 0; display: flex; justify-content: space-between;
  gap: 12px; flex-wrap: wrap; font: 400 12px var(--mono); color: var(--faint);
}
@media (max-width: 480px) {
  .way { grid-template-columns: 1fr; }
  .ask { padding: 18px 16px; }
  .ask-row { flex-direction: column; }
  .ask-row .btn { width: 100%; }
  .scene { width: 136px; height: 136px; }
}
@media (prefers-reduced-motion: reduce) {
  .scene .lamp, .halo, .moth, .scene.try .lamp, .scene.try .halo,
  [data-ask] .scene .lamp, [data-ask] .halo, .status .dot { animation: none !important; }
  .moth { display: none; }
}
</style>
</head>
<body>
<main>
  <div>
    <button class="scene" id="scene" type="button" aria-label="The porch light. Tap to flick the switch.">
      <span class="halo" aria-hidden="true"></span>
      <svg viewBox="0 0 64 64" aria-hidden="true">
        <path class="line" d="M8 30 L32 10 L56 30"/>
        <path class="line" d="M16 28 V54 H48 V28"/>
        <path class="door" d="M27 54 V40 H37 V54 Z"/>
        <path class="line" d="M27 54 V40 H37 V54"/>
        <path class="bar" d="M24 47 H40"/>
        <circle class="lamp" cx="32" cy="22" r="5.5"/>
      </svg>
      <span class="moth a" aria-hidden="true"></span>
      <span class="moth b" aria-hidden="true"></span>
    </button>
    <div class="where" id="where"></div>
    <h1 id="title"></h1>
  </div>
  <p class="lede" id="lede"></p>
  <a class="btn go" id="go" hidden>Go in</a>
  <section class="ask" id="ask" aria-labelledby="askTitle" hidden>
    <h2 id="askTitle"></h2>
    <p id="askText"></p>
    <form id="askForm" novalidate>
      <label for="note">Your name <span>(optional, so they know who's asking)</span></label>
      <div class="ask-row">
        <input id="note" name="note" maxlength="40" autocomplete="name" autocapitalize="words" enterkeyhint="send" spellcheck="false" placeholder="e.g. Sam">
        <button class="btn" type="submit" id="askBtn">Ask for access</button>
      </div>
    </form>
    <div class="status" id="status" role="status" aria-live="polite" hidden>
      <span class="dot" aria-hidden="true"></span><span><span id="statusText"></span><small id="statusSub"></small></span>
    </div>
    <button type="button" class="btn ghost" id="again" hidden>Ask again</button>
  </section>
  <div class="ways" id="ways">
    <div class="way"><b id="ownerQ">Owner?</b><p><a id="owner" href="/login?owner=1">Sign in with the admin password</a>. It enrolls this browser for every app.</p></div>
  </div>
</main>
<footer><span id="foot"></span><span>__BRAND__</span></footer>
<script nonce="__NONCE__">
(function () {
  var V = "__VIEW__";
  var $ = function (id) { return document.getElementById(id); };
  var root = document.documentElement;
  var host = String(V.host || 'this app');
  var state = V.state;
  root.setAttribute('data-state', state);
  $('where').textContent = host;
  $('owner').href = V.owner_url || '/login?owner=1';
  var COPY = {
    'private': {
      title: 'This one’s private.',
      lede: ['', host, ' is only open to people the owner has let in.'],
      ask: 'Someone sent you here?',
      text: 'Ask the owner to let you in. They get a note on their phone, and this page moves on by itself when they say yes.',
      foot: '403 · private app'
    },
    scope: {
      title: 'Not on your pass.',
      lede: ['This browser is signed in as ', String(V.device || 'a guest'), ', but its pass doesn’t include ' + host + '.'],
      ask: 'Want it added?',
      text: 'Ask the owner to add this app to your pass. When they do, this page takes you straight in.',
      foot: '403 · not on this pass'
    },
    expired: {
      title: 'Your pass ran out.',
      lede: ['This browser’s pass for ', host, ' has expired or was taken back.'],
      ask: 'Need back in?',
      text: 'Ask the owner for a new pass. They get a note on their phone, and this page moves on by itself when they say yes.',
      foot: '403 · pass expired'
    },
    'in': {
      title: 'You’re on the list.',
      lede: ['This browser can open ', host, '. The door may just have needed a moment.'],
      foot: '200 · come in'
    }
  };
  var C = COPY[state] || COPY['private'];
  $('title').textContent = C.title;
  function lede(parts) {
    var p = $('lede');
    p.replaceChildren();
    p.append(document.createTextNode(parts[0]));
    var b = document.createElement('b'); b.textContent = parts[1]; p.append(b);
    p.append(document.createTextNode(parts[2]));
  }
  lede(C.lede);
  $('foot').textContent = C.foot;
  if (state === 'in') {
    var go = $('go'); go.hidden = false; go.href = V.rd || '/';
    $('ways').hidden = true;
  } else if (V.can_ask === false) {
    // Nothing the owner could grant from here (not a gated app under the
    // root): say who to ask instead of offering a form.
    var more = document.createElement('p');
    more.className = 'lede';
    more.textContent = 'Ask the person who runs this porch to add it for you.';
    $('lede').after(more);
  } else {
    $('ask').hidden = false;
    $('askText').textContent = C.text;
  }
  if (state === 'scope') $('ownerQ').textContent = 'Wrong browser?';

  var scene = $('scene'), timer = null;
  scene.addEventListener('click', function () {
    scene.classList.remove('try'); void scene.offsetWidth; scene.classList.add('try');
    clearTimeout(timer);
    timer = setTimeout(function () { scene.classList.remove('try'); }, 1400);
  });
  if (state === 'in' || V.can_ask === false) return;

  // ---- ask for access ----
  var API = V.api || '/auth/access-requests';
  var KEY = 'porch-access:' + host;
  var WAIT_MS = 31 * 60 * 1000;
  var form = $('askForm'), note = $('note'), btn = $('askBtn'), again = $('again'), status = $('status');
  var pollTimer = null;
  function remember(v) {
    try { if (v) sessionStorage.setItem(KEY, JSON.stringify(v)); else sessionStorage.removeItem(KEY); } catch (e) {}
  }
  function recall() {
    try { var v = JSON.parse(sessionStorage.getItem(KEY) || 'null'); return v && v.id && v.token ? v : null; } catch (e) { return null; }
  }
  function show(st, text, sub) {
    root.setAttribute('data-ask', st);
    form.hidden = st !== 'idle' && st !== 'error';
    status.hidden = st === 'idle';
    $('statusText').textContent = text || '';
    $('statusSub').textContent = sub || '';
    again.hidden = !(st === 'denied' || st === 'expired');
    var asking = st === 'idle' || st === 'error' || st === 'asking';
    $('askText').hidden = !asking;
    $('askTitle').textContent = asking ? C.ask : 'You asked the owner';
    btn.disabled = st === 'asking';
    btn.textContent = st === 'asking' ? 'Asking…' : 'Ask for access';
  }
  function safeNext(u) {
    // Only an https link on this porch: the invite page here, or the app.
    try {
      var x = new URL(u, location.href);
      return x.protocol === 'https:' || x.origin === location.origin ? x.href : null;
    } catch (e) { return null; }
  }
  function poll(ask) {
    clearTimeout(pollTimer);
    if (Date.now() - ask.t > WAIT_MS) { done({state: 'expired'}); return; }
    fetch(API + '/' + encodeURIComponent(ask.id) + '?t=' + encodeURIComponent(ask.token),
          { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { return r.json().catch(function () { return {}; }).then(function (j) { return [r.status, j]; }); })
      .then(function (res) {
        var j = res[1] || {};
        if (res[0] === 404) { done({state: 'expired'}); return; }
        if (j.state === 'approved' || j.state === 'denied' || j.state === 'expired') { done(j); return; }
        pollTimer = setTimeout(function () { poll(ask); }, (j.poll || 4) * 1000);
      })
      .catch(function () { pollTimer = setTimeout(function () { poll(ask); }, 8000); });
  }
  function done(j) {
    remember(null);
    if (j.state === 'approved') {
      var next = j.invite ? safeNext(j.invite) : safeNext(j.rd || V.rd || '');
      root.setAttribute('data-state', 'in');
      $('ways').hidden = true;
      $('title').textContent = 'The porch light is on.';
      if (j.invite) {
        lede(['The owner said yes. Your pass for ', host, ' is ready to pick up.']);
        show('approved', 'The owner let you in.', 'Opening your pass…');
      } else {
        lede(['The owner added ', host, ' to your pass.']);
        show('approved', 'The owner let you in.', 'Coming in…');
      }
      if (next) setTimeout(function () { location.href = next; }, 1600);
    } else if (j.state === 'denied') {
      show('denied', 'The owner said not now.', 'Maybe ask them another way, or try again later.');
    } else {
      show('expired', 'No answer yet.', 'They may be away. You can ask again in a while.');
    }
  }
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    if (btn.disabled) return;
    show('asking', '', '');
    fetch(API, {
      method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host: host, note: note.value.slice(0, 40), rd: V.rd || '' })
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (r.status === 201 && j.id && j.token) {
          var ask = { id: String(j.id), token: String(j.token), t: Date.now() };
          remember(ask);
          show('waiting', 'Asked. Waiting for the owner…', 'Keep this page open; it moves on by itself.');
          pollTimer = setTimeout(function () { poll(ask); }, (j.poll || 4) * 1000);
        } else if (r.status === 429 || r.status === 503) {
          show('error', 'Too many asks right now.', 'Try again in a while.');
        } else {
          show('error', 'This page can’t ask from here.', 'Ask the person who sent you the link.');
        }
      });
    }).catch(function () {
      show('error', 'Couldn’t reach the porch.', 'Check your connection and try again.');
    });
  });
  again.addEventListener('click', function () { show('idle'); note.focus(); });
  var pending = recall();
  if (pending && Date.now() - pending.t < WAIT_MS) {
    show('waiting', 'Asked. Waiting for the owner…', 'Keep this page open; it moves on by itself.');
    poll(pending);
  } else {
    show('idle');
  }
})();
</script>
</body>
</html>
"""


def _esc(s):
    return (s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            .replace('"', '&quot;'))


def render(view, js_string, brand='Porch'):
    """The page for `view` ({state, host, rd, device?, owner_url, api}).
    js_string: authserver._js_string (the </script>-proof JSON encoder)."""
    state = view.get('state') if view.get('state') in STATES else 'private'
    view = dict(view, state=state)
    return (GATE_HTML
            .replace('__FONTS__', porch_http.font_face_rules(FONT_PREFIX))
            .replace('__TITLE__', _esc(TITLES[state]))
            .replace('__BRAND__', _esc(brand or 'Porch'))
            .replace('"__VIEW__"', js_string(view)))

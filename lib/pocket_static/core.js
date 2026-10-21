/* Pocket app core (lib/pocket_static/core.js): the api client with step-up
 * and retry-once, the hash router and its panes, live updates (SSE), sheets,
 * confirm, toasts, the 1s ticker, the step-up sheet and the WebAuthn client.
 *
 * Plain deferred scripts in one global namespace (window.Porch); no modules,
 * because hashed file names break relative imports. Every string reaches the
 * DOM through textContent; nothing here builds markup from text. */
'use strict';

// ---- globals share.js (the make-link sheet) relies on -----------------------
const CFG = (function(){
  try{ return JSON.parse(document.getElementById('cfg').textContent) || {}; }catch(e){ return {}; }
})();
const $ = (id) => document.getElementById(id);
var current = null;                    // the current clip; share.js reads it
function el(tag, cls, text){
  const e = document.createElement(tag);
  if(cls) e.className = cls;
  if(text !== undefined && text !== null) e.textContent = String(text);
  return e;
}
function humanSize(b){
  b = +b || 0;
  if(b < 1024) return b + ' B';
  if(b < 1048576) return (b/1024).toFixed(1) + ' KB';
  if(b < 1073741824) return (b/1048576).toFixed(1) + ' MB';
  return (b/1073741824).toFixed(1) + ' GB';
}
function say(msg, kind){ Porch.toast(msg, kind); }
function copyText(text){
  if(navigator.clipboard && window.isSecureContext){
    return navigator.clipboard.writeText(text).catch(() => copyFallback(text));
  }
  return copyFallback(text);
}
function copyFallback(text){
  const ta = el('textarea', 'copy-scratch');
  ta.value = text; ta.setAttribute('readonly', '');
  document.body.appendChild(ta);
  ta.select(); ta.setSelectionRange(0, text.length);
  let ok = false;
  try{ ok = document.execCommand('copy'); }catch(e){}
  ta.remove();
  return ok ? Promise.resolve() : Promise.reject(new Error('copy blocked'));
}
function copied(p, what){
  p.then(() => say((what || 'Copied') + '.'),
         () => say('This browser blocked copying: select the text and copy it by hand.', 'warn'));
}
// share.js calls api(method, path, body) and expects JSON or a thrown Error.
function api(method, path, body, opts){ return Porch.api(method, path, body, opts); }

window.Porch = (function(){
  const P = {};
  const NS = 'http://www.w3.org/2000/svg';

  // ---- icons (stroke paths on a 24 grid) -----------------------------------
  const ICONS = {
    home: ['M4 11.5 12 5l8 6.5', 'M6.5 10v9.5h11V10', 'M10.5 19.5v-5h3v5'],
    door: ['M6 20.5V4.5h12v16', 'M3.5 20.5h17', 'M14.5 12.5h.01'],
    bell: ['M6 16.5V11a6 6 0 0 1 12 0v5.5l1.5 2h-15z', 'M10 20.5a2.2 2.2 0 0 0 4 0'],
    people: ['M9 5.3a3.2 3.2 0 1 1 0 6.4 3.2 3.2 0 0 1 0-6.4z', 'M3.5 19.5c.6-3.3 2.8-5 5.5-5s4.9 1.7 5.5 5', 'M16.8 7a2.5 2.5 0 1 1 0 5', 'M15.6 14.6c2.4-.3 4.4 1.2 4.9 4.4'],
    shield: ['M12 3.5 5 6.2v5.3c0 4.3 2.9 7.6 7 9 4.1-1.4 7-4.7 7-9V6.2z', 'm9.2 12 2 2 3.8-4'],
    plus: ['M12 5v14', 'M5 12h14'],
    chev: ['m9.5 5.5 6.5 6.5-6.5 6.5'],
    back: ['M14.5 5.5 8 12l6.5 6.5'],
    copy: ['M8.5 8.5h10v11h-10z', 'M15.5 8.5v-4h-10v11h3'],
    share: ['M12 15V4', 'm7.5 8 4.5-4.5L16.5 8', 'M5 12.5v7h14v-7'],
    qr: ['M4.5 4.5h5v5h-5z', 'M14.5 4.5h5v5h-5z', 'M4.5 14.5h5v5h-5z', 'M14.5 14.5h2v2h-2z', 'M17.5 17.5h2v2h-2z'],
    lock: ['M5 10.5h14v10H5z', 'M8.5 10.5V8a3.5 3.5 0 0 1 7 0v2.5'],
    unlock: ['M5 10.5h14v10H5z', 'M8.5 10.5V8a3.5 3.5 0 0 1 6.8-1.2'],
    key: ['M14.5 4.5a5 5 0 1 1-4.2 7.7L4.5 18v2h3v-2h2v-2h2l1.3-1.3', 'M16 8h.01'],
    clock: ['M12 3.5a8.5 8.5 0 1 1 0 17 8.5 8.5 0 0 1 0-17z', 'M12 7.5V12l3 2'],
    trash: ['M4.5 7h15', 'M9.5 7V4.5h5V7', 'M6.5 7l1 13h9l1-13'],
    x: ['M6 6l12 12', 'M18 6 6 18'],
    check: ['m5 12.5 4.5 4.5L19 7.5'],
    eye: ['M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z', 'M12 9a3 3 0 1 1 0 6 3 3 0 0 1 0-6z'],
    link: ['M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1', 'M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1'],
    users: ['M12 4.5a3.5 3.5 0 1 1 0 7 3.5 3.5 0 0 1 0-7z', 'M5 20c.8-3.6 3.6-5.5 7-5.5s6.2 1.9 7 5.5'],
    phone: ['M7.5 3.5h9v17h-9z', 'M11 17.5h2'],
    laptop: ['M5 6h14v9.5H5z', 'M3 18.5h18'],
    server: ['M4.5 4.5h15v6h-15z', 'M4.5 13.5h15v6h-15z', 'M8 7.5h.01', 'M8 16.5h.01'],
    globe: ['M12 3.5a8.5 8.5 0 1 1 0 17 8.5 8.5 0 0 1 0-17z', 'M3.5 12h17', 'M12 3.5c2.4 2.5 3.5 5.3 3.5 8.5S14.4 18 12 20.5C9.6 18 8.5 15.2 8.5 12S9.6 6 12 3.5z'],
    ticket: ['M4 7.5h16v3a2 2 0 0 0 0 3v3H4v-3a2 2 0 0 0 0-3z', 'M14 7.5v9'],
    activity: ['M3.5 12h4l2.5-6 4 12 2.5-6h4'],
    info: ['M12 3.5a8.5 8.5 0 1 1 0 17 8.5 8.5 0 0 1 0-17z', 'M12 11v5', 'M12 7.8h.01'],
    flame: ['M12 20.5c-3.6 0-6-2.4-6-5.6 0-3.4 3-5.4 3.6-9.4 2.5 1.4 4.4 3.6 4.9 6.1.8-.8 1.2-1.8 1.3-2.9 1.4 1.4 2.2 3.6 2.2 6.2 0 3.2-2.4 5.6-6 5.6z'],
    pass: ['M3.5 6.5h17v11h-17z', 'M7.5 10.5h4', 'M7.5 13.5h7'],
    bolt: ['M13 3.5 5.5 13.5H12l-1 7 7.5-10H12z'],
    hook: ['M12 3.5v9.5a4 4 0 1 1-4-4', 'M12 3.5l3 3'],
    refresh: ['M19.5 12a7.5 7.5 0 1 1-2.2-5.3', 'M19.5 4.5v4h-4'],
    pause: ['M8.5 5.5v13', 'M15.5 5.5v13'],
    play: ['M7.5 5v14l11-7z'],
    more: ['M5.5 12h.01', 'M12 12h.01', 'M18.5 12h.01'],
    fingerprint: ['M8 3.5H6A2.5 2.5 0 0 0 3.5 6v2M16 3.5h2A2.5 2.5 0 0 1 20.5 6v2M8 20.5H6A2.5 2.5 0 0 1 3.5 18v-2M16 20.5h2a2.5 2.5 0 0 0 2.5-2.5v-2', 'M9 9.5v1M15 9.5v1M12 9.5v3.5h-1', 'M9.2 15.5a4 4 0 0 0 5.6 0'],
    upload: ['M12 15.5V4.5', 'm7.5 9 4.5-4.5L16.5 9', 'M4.5 15v4.5h15V15'],
    inbox: ['M4.5 13.5 6.5 5h11l2 8.5', 'M4.5 13.5v6h15v-6h-5a2.5 2.5 0 0 1-5 0z'],
    stop: ['M6.5 6.5h11v11h-11z'],
  };
  function icon(name, cls){
    const s = document.createElementNS(NS, 'svg');
    s.setAttribute('viewBox', '0 0 24 24');
    s.setAttribute('class', cls && cls !== 'ico' ? 'ico ' + cls : 'ico');
    s.setAttribute('aria-hidden', 'true');
    for(const d of ICONS[name] || []){
      const p = document.createElementNS(NS, 'path');
      p.setAttribute('d', d);
      s.appendChild(p);
    }
    return s;
  }
  P.icon = icon;
  P.el = el;

  // ---- formatting -------------------------------------------------------------
  let skew = 0;                       // server now - local now, seconds
  P.now = () => Date.now()/1000 + skew;
  P.setServerNow = (t) => { if(typeof t === 'number' && t > 0) skew = t - Date.now()/1000; };
  function left(s){
    s = Math.max(0, Math.round(s));
    const d = Math.floor(s/86400), h = Math.floor(s%86400/3600), m = Math.floor(s%3600/60), x = s%60;
    if(d) return d + 'd ' + h + 'h';
    if(h) return h + 'h ' + String(m).padStart(2, '0') + 'm';
    if(m) return m + 'm ' + String(x).padStart(2, '0') + 's';
    return x + 's';
  }
  function ago(ts){
    if(!ts) return 'never';
    const s = Math.max(0, P.now() - ts);
    if(s < 45) return 'just now';
    if(s < 3600) return Math.round(s/60) + 'm ago';
    if(s < 86400) return Math.round(s/3600) + 'h ago';
    if(s < 86400*14) return Math.round(s/86400) + 'd ago';
    return new Date(ts*1000).toLocaleDateString();
  }
  function when(ts){
    if(!ts) return '—';
    const d = new Date(ts*1000);
    return d.toLocaleString([], {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'});
  }
  function clock(ts){
    return new Date(ts*1000).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
  }
  P.fmt = {left, ago, when, clock, size: humanSize,
           plural: (n, w) => n + ' ' + w + (n === 1 ? '' : 's')};

  // ---- small builders ----------------------------------------------------------
  P.btn = function(label, cls, onClick, o){
    o = o || {};
    const b = el('button', cls || 'p-btn');
    b.type = 'button';
    if(o.icon) b.append(icon(o.icon, 'ico'));
    if(label) b.append(document.createTextNode(label));
    if(o.aria) b.setAttribute('aria-label', o.aria);
    if(o.write){ b.dataset.write = ''; if(P.offline){ b.disabled = true; b.dataset.offdis = '1'; b.title = 'You’re offline'; } }
    if(onClick) b.addEventListener('click', (e) => onClick(e, b));
    return b;
  };
  // A same-origin hash link.
  P.link = function(href, cls, text){
    const a = el('a', cls, text);
    a.href = href;
    return a;
  };
  // An external link, only for https URLs on our own hosts.
  P.safeUrl = function(u, extraHosts){
    try{
      const x = new URL(u);
      if(x.protocol !== 'https:' && !(x.protocol === 'http:' && /^(localhost|127\.0\.0\.1)$/.test(x.hostname))) return null;
      const base = P.tunnelBase();
      const hosts = (extraHosts || []).filter(Boolean);
      if((base && (x.hostname === base || x.hostname.endsWith('.' + base))) || hosts.includes(x.hostname)
         || x.hostname === location.hostname) return x.href;
    }catch(e){}
    return null;
  };
  P.tunnelBase = function(){
    const a = P.app && P.app.pocket && P.app.pocket.host;
    const h = CFG.tunnel_base || (a ? a.split('.').slice(1).join('.') : location.hostname.split('.').slice(1).join('.'));
    return h || '';
  };
  // Door types -> the app accent their chip wears.
  const TYPE_APP = {drop:'drop', photos:'media', media:'media', music:'music', paste:'paste', exchange:'exchange',
                    chat:'paste', form:'paste', hook:'exchange', 'secure-entry':'secret', seal:'secret',
                    serve:'serve', view:'serve', tunnel:'serve', pocket:''};
  P.typeChip = function(type){
    const t = String(type || 'door');
    const c = el('span', 'tchip', t === 'secure-entry' ? 'secret' : t);
    const app = TYPE_APP[t];
    if(app) c.dataset.app = app;
    return c;
  };
  P.badge = function(text, tone, ic){
    const b = el('span', 'rb' + (tone ? ' rb--' + tone : ''));
    if(ic) b.append(icon(ic, 'ico'));
    b.append(document.createTextNode(text));
    return b;
  };
  // Countdown text + meter that the ticker keeps current.
  P.countdown = function(expires, cls){
    const s = el('span', 'cd' + (cls ? ' ' + cls : ''));
    if(expires === null || expires === undefined){ s.textContent = 'never'; s.classList.add('cd--never'); return s; }
    s.dataset.until = String(expires);
    tickOne(s, P.now());
    return s;
  };
  P.meter = function(started, expires){
    const m = el('div', 'meter');
    const f = el('div', 'meter-fill');
    m.append(f);
    m.setAttribute('aria-hidden', 'true');
    if(expires === null || expires === undefined){ m.classList.add('meter--never'); return m; }
    m.dataset.from = String(started || (expires - 3600));
    m.dataset.until = String(expires);
    tickMeter(m, P.now());
    return m;
  };
  P.ago = function(ts, prefix){
    const s = el('span', '', (prefix || '') + ago(ts));
    if(ts){ s.dataset.ago = String(ts); if(prefix) s.dataset.prefix = prefix; }
    return s;
  };
  P.skeleton = function(n, card){
    const box = el('div', card ? 'sec' : 'skel-rows');
    box.setAttribute('aria-busy', 'true');
    box.setAttribute('aria-label', 'Loading');
    for(let i = 0; i < (n || 3); i++) box.append(el('div', card ? 'skel-card' : 'skel'));
    if(!card){ const w = el('div', 'items'); w.append(box); return w; }
    return box;
  };
  P.empty = function(title, text, action, ic){
    const e = el('div', 'p-empty');
    if(ic){ const i = el('div', 'empty-ico'); i.append(icon(ic)); e.append(i); }
    e.append(el('div', 'p-empty-title', title));
    if(text) e.append(el('div', 'p-empty-text', text));
    if(action) e.append(action);
    return e;
  };
  P.errorBox = function(err, retry){
    const box = el('div', 'pane-error');
    const n = el('div', 'p-notice p-notice--' + (err && err.code === 'offline' ? 'warn' : 'error'));
    n.setAttribute('role', 'alert');
    n.append(el('span', '', err && err.code === 'offline'
      ? 'You’re offline. This shows up again when the connection is back.'
      : (err && err.message) || 'Something went wrong.'));
    box.append(n);
    if(retry){ const a = el('div', 'actions'); a.append(P.btn('Retry', 'p-btn p-btn--ghost p-btn--sm', retry, {icon:'refresh'})); box.append(a); }
    return box;
  };
  P.paneHead = function(title, o){
    o = o || {};
    const h = el('header', 'pane-head');
    if(o.kicker){ const k = el('div', 'p-kicker'); k.append(el('span', '', o.kicker)); h.append(k); }
    const row = el('div', 'pane-head-row');
    const t = el('h1', 'p-title pane-title' + (o.mono ? ' pane-title--mono' : ''), title);
    t.tabIndex = -1;
    t.dataset.focus = '';
    row.append(t);
    if(o.actions && o.actions.length){ const a = el('div', 'pane-actions'); a.append(...o.actions); row.append(a); }
    h.append(row);
    if(o.sub){ const s = el('div', 'pane-sub'); s.append(...(Array.isArray(o.sub) ? o.sub : [o.sub])); h.append(s); }
    return h;
  };
  P.section = function(title, o){
    o = o || {};
    const s = el('section', 'sec');
    const head = el('div', 'sec-head');
    head.append(el('h2', 'sec-title', title));
    if(o.action) head.append(o.action);
    s.append(head);
    return s;
  };
  P.seg = function(items, cur){
    const s = el('nav', 'seg');
    s.setAttribute('aria-label', 'Sections');
    for(const [href, label, n] of items){
      const a = P.link(href, 'seg-btn', label);
      if(n !== undefined && n !== null && n !== '') a.append(el('span', 'seg-n', String(n)));
      if(href === cur) a.setAttribute('aria-current', 'page');
      s.append(a);
    }
    return s;
  };
  // A radio group of .chip buttons; returns {node, get, set}.
  P.chips = function(options, value, onPick, label){
    const g = el('div', 'chips');
    g.setAttribute('role', 'radiogroup');
    if(label) g.setAttribute('aria-label', label);
    let v = value;
    const set = (x) => { v = x; g.querySelectorAll('.chip').forEach(c => c.setAttribute('aria-checked', String(c.dataset.v === String(x)))); };
    for(const [val, text] of options){
      const c = el('button', 'chip', text);
      c.type = 'button'; c.setAttribute('role', 'radio'); c.dataset.v = String(val);
      c.addEventListener('click', () => { set(val); if(onPick) onPick(val); });
      g.append(c);
    }
    set(value);
    return {node: g, get: () => v, set};
  };
  P.switchBtn = function(on, labelledBy, onToggle){
    const s = el('button', 'switch');
    s.type = 'button'; s.setAttribute('role', 'switch');
    s.setAttribute('aria-checked', on ? 'true' : 'false');
    if(labelledBy) s.setAttribute('aria-labelledby', labelledBy);
    if(onToggle) s.addEventListener('click', () => onToggle(s.getAttribute('aria-checked') !== 'true', s));
    return s;
  };
  P.field = function(labelText, input, help){
    const f = el('div', 'p-field');
    if(!input.id) input.id = 'f' + Math.random().toString(36).slice(2, 9);
    const l = el('label', 'p-label', labelText); l.htmlFor = input.id;
    f.append(l, input);
    if(help) f.append(el('div', 'p-help', help));
    return f;
  };
  P.input = function(type, o){
    o = o || {};
    const i = el('input', 'p-input' + (o.mono ? ' p-input--mono' : ''));
    i.type = type || 'text';
    for(const k of ['maxLength', 'placeholder', 'autocomplete', 'inputMode', 'value', 'min', 'max', 'name']) if(o[k] !== undefined) i[k] = o[k];
    if(o.spell === false){ i.spellcheck = false; i.autocapitalize = 'off'; i.setAttribute('autocorrect', 'off'); }
    return i;
  };
  // QR as an SVG drawn in the page (the URL never goes to a QR service).
  P.qr = function(text, big){
    const f = el('div', 'qr-frame');
    try{
      const q = PorchQR.svg(text, {ecl:'M'});
      q.setAttribute('aria-label', 'QR code of the link');
      if(big) q.classList.add('qr--big');
      f.append(q);
    }catch(e){ f.append(el('span', 'small', 'Too long for a QR code.')); }
    return f;
  };
  P.urlBox = function(label, url, o){
    o = o || {};
    const box = el('div', 'urlbox' + (o.accent ? ' urlbox--accent' : ''));
    const lab = el('div', 'urlbox-label');
    lab.append(el('span', '', label));
    if(o.badge) lab.append(o.badge);
    box.append(lab);
    const safe = P.safeUrl(url, o.hosts);
    const u = safe ? el('a', 'urlbox-url', url) : el('code', 'urlbox-url', url);
    if(safe){ u.href = safe; u.target = '_blank'; u.rel = 'noopener noreferrer'; }
    box.append(u);
    const acts = el('div', 'actions');
    acts.append(P.btn('Copy', 'p-btn p-btn--sm' + (o.accent ? '' : ' p-btn--ghost'), () => copied(copyText(url), o.copied || 'Link copied'), {icon:'copy', aria: 'Copy ' + label}));
    if(typeof navigator.share === 'function' && o.share !== false)
      acts.append(P.btn('Share', 'p-btn p-btn--ghost p-btn--sm', () => navigator.share({url}).catch(() => {}), {icon:'share', aria:'Share ' + label}));
    if(o.qr !== false)
      acts.append(P.btn('QR', 'p-btn p-btn--ghost p-btn--sm', () => P.showQr(label, url), {icon:'qr', aria:'Show a QR code of ' + label}));
    if(o.extra) acts.append(...o.extra);
    box.append(acts);
    return box;
  };
  P.showQr = function(title, url){
    const body = el('div', 'sec');
    body.append(P.qr(url, true));
    const c = el('code', 'urlbox-url', url);
    body.append(c);
    P.sheet.open({kicker:'Scan to open', title, body,
      actions:[{label:'Copy', cls:'p-btn p-btn--lg', run: () => { copied(copyText(url), 'Link copied'); return false; }},
               {label:'Done', cls:'p-btn p-btn--quiet p-btn--lg'}]});
  };
  // Rule badges for a door or link.
  P.ruleBadges = function(d){
    const b = el('div', 'badges');
    const r = d.rules || {};
    if(r.password) b.append(P.badge('password', 'accent', 'lock'));
    if(r.guest_link || r.guest) b.append(P.badge('guest link', 'accent', 'ticket'));
    if(r.max_opens === 1) b.append(P.badge('burn · ' + (d.opens || 0) + '/1', 'warn', 'flame'));
    else if(r.max_opens) b.append(P.badge((d.opens || 0) + '/' + r.max_opens + ' opens', 'warn'));
    if(d.capture) b.append(P.badge('webhook', 'accent', 'hook'));
    else if(d.inspect) b.append(P.badge('inspecting', 'accent', 'eye'));
    if(d.inspect_raw) b.append(P.badge('raw: unmasked', 'danger'));
    if(d.self) b.append(P.badge('this is the Porch app', 'self'));
    if(d.unmanaged) b.append(P.badge('unmanaged'));
    return b;
  };

  // ---- toasts ------------------------------------------------------------------
  P.toast = function(msg, kind){
    const box = $('toasts');
    const t = el('div', 'toast');
    t.dataset.kind = kind || 'ok';
    if(kind === 'error') t.setAttribute('role', 'alert');
    t.append(el('span', '', msg));
    const x = el('button', 'toast-x', '×');
    x.type = 'button'; x.setAttribute('aria-label', 'Dismiss');
    x.addEventListener('click', () => t.remove());
    t.append(x);
    box.append(t);
    while(box.childElementCount > 3) box.firstElementChild.remove();
    setTimeout(() => t.remove(), kind === 'error' ? 9000 : 5000);
  };
  // An error from a user action: a toast, except a cancelled step-up.
  P.fail = function(err){
    if(!err || err.code === 'cancelled') return;
    P.toast(err.message || String(err), err.code === 'offline' ? 'warn' : 'error');
  };

  // ---- api ---------------------------------------------------------------------
  class ApiError extends Error{
    constructor(message, status, code, data){ super(message); this.status = status; this.code = code || null; this.data = data || {}; }
  }
  P.ApiError = ApiError;
  async function request(method, path, body, o){
    o = o || {};
    const opts = {method, credentials:'same-origin', headers:{'Accept':'application/json'}, cache:'no-store'};
    if(body !== undefined){ opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    let timer = null;
    if(o.timeout){ const c = new AbortController(); opts.signal = c.signal; timer = setTimeout(() => c.abort(), o.timeout); }
    let r;
    try{ r = await fetch(path, opts); }
    catch(e){
      if(e && e.name === 'AbortError') throw new ApiError('That took too long. Check again in a moment.', 0, 'timeout');
      if(navigator.onLine === false) setOffline(true);
      throw new ApiError(navigator.onLine === false ? 'You’re offline.' : 'Can’t reach Porch right now.', 0, 'offline');
    }finally{ clearTimeout(timer); }
    let j = null;
    try{ j = await r.json(); }catch(e){ j = null; }
    if(r.ok){ setOffline(false); return j === null ? {} : j; }
    const d = j && typeof j === 'object' ? j : {};
    const code = d.code || null;
    if(r.status === 401 && (code === 'step_up' || code === 'step_up_password') && o.stepup !== false){
      await P.stepup.prompt({passwordOnly: code === 'step_up_password', passkeys: d.passkeys, why: o.why, code});
      return request(method, path, body, Object.assign({}, o, {stepup:false}));
    }
    if(r.status === 403 && !code) checkSignedIn();
    if(code === 'auth_down') setAuth('down');
    let msg = d.message || d.error || ('HTTP ' + r.status);
    if(code === 'rate_limited' && d.retry_after) msg = (d.message || 'Too many tries') + ' (try again in ' + left(d.retry_after) + ')';
    throw new ApiError(msg, r.status, code, d);
  }
  P.api = request;
  P.get = (path, o) => request('GET', path, undefined, o);
  P.post = (path, body, o) => request('POST', path, body === undefined ? {} : body, o);

  // ---- signed out / auth / offline ------------------------------------------------
  let signedOutShown = false;
  function checkSignedIn(){
    if(signedOutShown) return;
    fetch('/api/app', {credentials:'same-origin', cache:'no-store'}).then((r) => { if(r.status === 403) P.signedOut(); }).catch(() => {});
  }
  P.signedOut = function(){
    signedOutShown = true;
    $('signInLink').href = '/__porch/start?rd=' + encodeURIComponent(location.href);
    $('signedOut').hidden = false;
    $('app').setAttribute('inert', '');
    if(P.events) P.events.stop();
  };
  function setAuth(state){
    if(P.app && P.app.auth) P.app.auth.state = state;
    const b = $('authBanner');
    const sec = currentSection();
    const show = state === 'down' && (sec === 'people' || sec === 'requests');
    if(show){
      b.replaceChildren(el('span', '', 'porch-auth isn’t answering, so people and machine requests can’t load. Doors still work.'));
    }else if(state === 'old' && (sec === 'people' || sec === 'you')){
      b.replaceChildren(el('span', '', 'porch-auth needs an update for some of this (bin/auth-deploy).'));
    }
    b.hidden = !(show || (state === 'old' && (sec === 'people' || sec === 'you')));
  }
  P.setAuth = setAuth;
  P.offline = false;
  let lastData = 0;
  P.markFresh = () => { lastData = Date.now(); };
  function setOffline(on){
    if(P.offline === on){ if(on) renderOffline(); return; }
    P.offline = on;
    document.documentElement.classList.toggle('is-offline', on);
    document.querySelectorAll('[data-write]').forEach((b) => {
      if(on && !b.disabled){ b.disabled = true; b.dataset.offdis = '1'; b.title = 'You’re offline'; }
      else if(!on && b.dataset.offdis){ b.disabled = false; delete b.dataset.offdis; b.removeAttribute('title'); }
    });
    renderOffline();
    if(!on) P.emit('online');
  }
  function renderOffline(){
    const b = $('offlineBanner');
    if(!P.offline){ b.hidden = true; return; }
    b.textContent = lastData ? 'You’re offline, showing the last update from ' + ago(lastData/1000) + '.' : 'You’re offline.';
    b.hidden = false;
  }
  P.setOffline = setOffline;
  window.addEventListener('offline', () => setOffline(true));
  window.addEventListener('online', () => { setOffline(false); P.events && P.events.connect(); });

  // ---- tiny event bus ----------------------------------------------------------------
  const subs = {};
  P.on = (name, fn) => { (subs[name] = subs[name] || []).push(fn); return () => { subs[name] = subs[name].filter((x) => x !== fn); }; };
  P.emit = (name, data) => { for(const fn of subs[name] || []){ try{ fn(data); }catch(e){ console.error(e); } } };

  // ---- live updates (SSE /api/events) ---------------------------------------------------
  P.events = (function(){
    let es = null, backoff = 1000, timer = null, stopped = false;
    const NAMES = ['clip', 'inbox', 'links', 'requests', 'doors', 'people', 'history', 'stepup'];
    function setLive(state, text){
      for(const id of ['topLive', 'navLive']){
        const p = $(id);
        p.dataset.state = state;
        p.querySelector('.live-text').textContent = text;
        p.title = text;
      }
    }
    function connect(){
      if(stopped) return;
      clearTimeout(timer);
      if(es) es.close();
      es = new EventSource('/api/events');
      es.addEventListener('open', () => { backoff = 1000; setLive('live', 'live'); setOffline(false); });
      for(const n of NAMES){
        es.addEventListener(n, (e) => {
          let d = null;
          try{ d = JSON.parse(e.data); }catch(x){ return; }
          P.markFresh();
          P.emit(n, d);
        });
      }
      es.addEventListener('error', () => {
        setLive('down', navigator.onLine === false ? 'offline' : 'reconnecting');
        if(es.readyState === 2){
          timer = setTimeout(connect, backoff);
          backoff = Math.min(30000, backoff * 2);
        }
      });
    }
    document.addEventListener('visibilitychange', () => {
      if(!document.hidden && (!es || es.readyState === 2)) connect();
    });
    return {connect, stop(){ stopped = true; if(es) es.close(); }};
  })();

  // ---- ticker: countdowns, meters, "ago" -------------------------------------------------
  function tickOne(e, now){
    const left_ = +e.dataset.until - now;
    e.textContent = left_ <= 0 ? (e.dataset.done || 'expired') : left(left_);
    e.classList.toggle('cd--soon', left_ > 0 && left_ < 300);
  }
  function tickMeter(m, now){
    const from = +m.dataset.from, until = +m.dataset.until;
    const total = Math.max(1, until - from);
    const pct = Math.max(0, Math.min(100, (until - now) / total * 100));
    m.firstChild.style.width = pct.toFixed(2) + '%';
    m.classList.toggle('meter--soon', until - now < 300);
  }
  let tickN = 0;
  function tick(){
    const now = P.now();
    document.querySelectorAll('.cd[data-until]').forEach((e) => tickOne(e, now));
    document.querySelectorAll('.meter[data-until]').forEach((m) => tickMeter(m, now));
    if(++tickN % 15 === 0){
      document.querySelectorAll('[data-ago]').forEach((e) => { e.textContent = (e.dataset.prefix || '') + ago(+e.dataset.ago); });
      renderOffline();
    }
    P.emit('tick', now);
  }
  setInterval(tick, 1000);

  // ---- generic sheet ---------------------------------------------------------------------
  P.sheet = (function(){
    const d = $('appSheet');
    let onClose = null, busy = false;
    function close(){
      if(!d.open) return;
      if(typeof d.close === 'function') d.close(); else d.removeAttribute('open');
    }
    d.addEventListener('close', () => {
      // `close` arrives as a task after d.close(): if another sheet has
      // opened since (a result sheet right after a form), it is stale and
      // must not wipe the new body or run the new sheet's onClose.
      if(d.open) return;
      $('appSheetBody').replaceChildren();
      const f = onClose; onClose = null;
      if(f) f();
    });
    d.addEventListener('cancel', (e) => { if(busy) e.preventDefault(); });
    function error(msg){
      const n = $('appSheetErr');
      n.textContent = msg || ''; n.hidden = !msg;
    }
    // actions: [{label, cls, run(): false keeps it open / Promise, write, id}]
    function open(o){
      if(d.open){ const f = onClose; onClose = null; close(); if(f) f(); }
      $('appSheetKicker').textContent = o.kicker || '';
      $('appSheetKicker').parentElement.hidden = !o.kicker;
      $('appSheetTitle').textContent = o.title || '';
      const t = $('appSheetText');
      t.textContent = o.text || ''; t.hidden = !o.text;
      $('appSheetBody').replaceChildren();
      if(o.body) $('appSheetBody').append(o.body);
      $('appSheetBody').hidden = !o.body;
      error('');
      const acts = $('appSheetActions');
      acts.replaceChildren();
      const buttons = [];
      for(const a of o.actions || [{label:'Done', cls:'p-btn p-btn--quiet p-btn--lg'}]){
        const b = P.btn(a.label, a.cls || 'p-btn p-btn--lg', null, {write: a.write});
        if(a.id) b.id = a.id;
        b.addEventListener('click', async () => {
          if(!a.run){ close(); return; }
          error('');
          const label = b.textContent;
          busy = true;
          buttons.forEach((x) => { x.disabled = true; });
          if(a.busy) b.textContent = a.busy;
          let keep = false;
          try{ keep = (await a.run(b)) === false; }
          catch(err){
            keep = true;
            if(err && err.code !== 'cancelled') error(err.message || String(err));
          }finally{
            busy = false;
            buttons.forEach((x) => { if(!(x.dataset.offdis)) x.disabled = !!x.dataset.locked; });
            if(a.busy) b.textContent = label;
          }
          if(!keep) close();
        });
        buttons.push(b);
        acts.append(b);
      }
      onClose = o.onClose || null;
      if(typeof d.showModal === 'function'){ if(!d.open) d.showModal(); } else d.setAttribute('open', '');
      d.scrollTop = 0;
      const focus = o.focus || $('appSheetTitle');
      setTimeout(() => focus.focus({preventScroll: focus === $('appSheetTitle')}), 30);
      return {close, error, buttons, el: d};
    }
    return {open, close, error, get isOpen(){ return d.open; }};
  })();

  // A confirm sheet; resolves true/false. typed: the text the user must type.
  P.confirm = function(o){
    return new Promise((resolve) => {
      let answer = false;
      const body = el('div', 'sheet-body');
      let input = null;
      if(o.detail) body.append(o.detail);
      if(o.typed){
        input = P.input('text', {spell:false, autocomplete:'off'});
        body.append(P.field('Type ' + o.typed + ' to confirm', input));
      }
      const h = P.sheet.open({kicker: o.kicker || 'Are you sure?', title: o.title, text: o.text, body: (o.detail || o.typed) ? body : null,
        actions:[{label: o.confirm || 'Confirm', cls: 'p-btn p-btn--lg ' + (o.danger ? 'p-btn--danger' : ''), write: true, run: () => {
                    if(input && input.value.trim() !== o.typed) throw new Error('Type ' + o.typed + ' exactly.');
                    answer = true;
                  }},
                 {label: o.cancel || 'Cancel', cls: 'p-btn p-btn--quiet p-btn--lg'}],
        onClose: () => resolve(answer), focus: input || undefined});
      return h;
    });
  };

  // ---- WebAuthn client (manual b64url <-> ArrayBuffer) -----------------------------------
  const b64u = {
    enc(buf){
      const b = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
      let s = '';
      for(let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
      return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    },
    dec(str){
      let s = String(str || '').replace(/-/g, '+').replace(/_/g, '/');
      while(s.length % 4) s += '=';
      const bin = atob(s);
      const out = new Uint8Array(bin.length);
      for(let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out.buffer;
    },
  };
  const PKC = window.PublicKeyCredential;
  const webauthn = {
    supported: !!(PKC && navigator.credentials && navigator.credentials.get && window.isSecureContext),
    b64u,
    requestOptions(pk){
      if(PKC && typeof PKC.parseRequestOptionsFromJSON === 'function'){
        try{ return PKC.parseRequestOptionsFromJSON(pk); }catch(e){}
      }
      const o = Object.assign({}, pk, {challenge: b64u.dec(pk.challenge)});
      if(Array.isArray(pk.allowCredentials))
        o.allowCredentials = pk.allowCredentials.map((c) => Object.assign({}, c, {id: b64u.dec(c.id)}));
      return o;
    },
    creationOptions(pk){
      if(PKC && typeof PKC.parseCreationOptionsFromJSON === 'function'){
        try{ return PKC.parseCreationOptionsFromJSON(pk); }catch(e){}
      }
      const o = Object.assign({}, pk, {challenge: b64u.dec(pk.challenge),
                                       user: Object.assign({}, pk.user, {id: b64u.dec(pk.user.id)})});
      if(Array.isArray(pk.excludeCredentials))
        o.excludeCredentials = pk.excludeCredentials.map((c) => Object.assign({}, c, {id: b64u.dec(c.id)}));
      return o;
    },
    assertionJSON(c){
      const r = c.response;
      return {id: c.id, rawId: b64u.enc(c.rawId), type: c.type,
              response: {clientDataJSON: b64u.enc(r.clientDataJSON), authenticatorData: b64u.enc(r.authenticatorData),
                         signature: b64u.enc(r.signature), userHandle: r.userHandle ? b64u.enc(r.userHandle) : null}};
    },
    attestationJSON(c){
      const r = c.response;
      return {id: c.id, rawId: b64u.enc(c.rawId), type: c.type, authenticatorAttachment: c.authenticatorAttachment || null,
              response: {clientDataJSON: b64u.enc(r.clientDataJSON), attestationObject: b64u.enc(r.attestationObject),
                         transports: typeof r.getTransports === 'function' ? r.getTransports() : []}};
    },
    // A device hint for a new passkey's default label.
    deviceHint(){
      const ua = navigator.userAgent;
      if(/iPhone/.test(ua)) return 'iPhone';
      if(/iPad/.test(ua) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1)) return 'iPad';
      if(/Android/.test(ua)) return /Mobile/.test(ua) ? 'Android phone' : 'Android tablet';
      if(/Mac/.test(ua)) return 'Mac';
      if(/Windows/.test(ua)) return 'Windows PC';
      if(/Linux/.test(ua)) return 'Linux computer';
      return 'This device';
    },
    // Add a passkey: options -> create() -> register. Step-up happens in api().
    async register(label){
      const o = await request('POST', '/api/passkeys/register/options', {}, {why:'Adding a passkey lets this device unlock with Face ID or a fingerprint.'});
      let cred;
      try{ cred = await navigator.credentials.create({publicKey: webauthn.creationOptions(o.publicKey)}); }
      catch(e){
        if(e && (e.name === 'NotAllowedError' || e.name === 'AbortError')) throw new ApiError('Cancelled. Nothing was added.', 0, 'cancelled');
        if(e && e.name === 'InvalidStateError') throw new ApiError('This device already has a passkey for this pocket.', 0, 'exists');
        throw new ApiError('This device couldn’t make a passkey (' + (e && e.name || 'error') + ').', 0, 'webauthn');
      }
      return request('POST', '/api/passkeys/register', {credential: webauthn.attestationJSON(cred), label});
    },
  };
  P.webauthn = webauthn;
  const COARSE = window.matchMedia && matchMedia('(pointer:coarse)').matches;

  // ---- step-up --------------------------------------------------------------------------
  P.stepup = (function(){
    const d = $('stepSheet');
    let pending = null;               // {resolve, reject}
    let rateTimer = null;
    const msg = $('stepMsg');
    $('stepPasskeyLabel').textContent = COARSE ? 'Use Face ID / fingerprint' : 'Use passkey';
    function setMsg(text, kind){
      msg.textContent = text || '';
      msg.className = 'p-notice' + (kind ? ' p-notice--' + kind : '');
      msg.hidden = !text;
    }
    function setState(s){ d.dataset.state = s; }
    function lock(on){
      $('stepPasskey').disabled = on; $('stepPwGo').disabled = on; $('stepPw').disabled = on;
    }
    function rateLimited(secs){
      clearInterval(rateTimer);
      setState('limited');
      lock(true);
      let n = Math.max(1, Math.round(secs || 60));
      const show = () => setMsg('Too many tries. Try again in ' + left(n) + '.', 'warn');
      show();
      rateTimer = setInterval(() => {
        n -= 1;
        if(n <= 0){ clearInterval(rateTimer); lock(false); setState('idle'); setMsg(''); return; }
        show();
      }, 1000);
    }
    function finish(res){
      if(P.app){ P.app.stepup = {active:true, expires_at: res.expires_at, method: res.method}; }
      renderUnlock();
      P.emit('stepup', {active:true, expires_at: res.expires_at, method: res.method});
      const p = pending; pending = null;
      close();
      if(p) p.resolve(res);
      P.toast('Unlocked for 5 minutes.');
    }
    function failed(err){
      if(err && err.code === 'rate_limited'){ rateLimited(err.data && err.data.retry_after); return; }
      setState('failed');
      lock(false);
      setMsg(err && err.status === 401 ? (err.message || 'That didn’t check out. Try again.') : (err && err.message) || 'That didn’t work. Try again.', 'error');
    }
    async function viaPasskey(){
      setState('waiting'); setMsg('Waiting for your passkey…'); lock(true);
      try{
        const o = await request('POST', '/api/stepup/options', {}, {stepup:false});
        if(!o.publicKey){ showPasswordOnly(true); lock(false); setState('idle'); setMsg('No passkey yet: use the admin password this time.', 'warn'); return; }
        let cred;
        try{ cred = await navigator.credentials.get({publicKey: webauthn.requestOptions(o.publicKey)}); }
        catch(e){
          lock(false);
          if(e && (e.name === 'NotAllowedError' || e.name === 'AbortError')){ setState('cancelled'); setMsg('Cancelled, try again. Or use the admin password.', 'warn'); }
          else{ setState('failed'); setMsg('This device couldn’t use a passkey (' + (e && e.name || 'error') + '). Use the admin password.', 'error'); }
          return;
        }
        const res = await request('POST', '/api/stepup/passkey', {credential: webauthn.assertionJSON(cred)}, {stepup:false});
        finish(res);
      }catch(err){ failed(err); }
    }
    async function viaPassword(e){
      e.preventDefault();
      const pw = $('stepPw').value;
      if(!pw){ setMsg('Type the admin password.', 'warn'); $('stepPw').focus(); return; }
      setState('waiting'); setMsg('Checking…'); lock(true);
      try{
        const res = await request('POST', '/api/stepup/password', {password: pw}, {stepup:false});
        $('stepPw').value = '';
        finish(res);
      }catch(err){
        $('stepPw').value = '';
        failed(err);
        if(err && err.code !== 'rate_limited') $('stepPw').focus();
      }
    }
    function showPasswordOnly(on){
      $('stepPasskeyBox').hidden = on;
      $('stepOr').hidden = on;
      $('stepPwGo').className = 'p-btn p-btn--lg p-btn--block' + (on ? '' : ' p-btn--ghost');
    }
    function close(){
      if(d.open){ if(typeof d.close === 'function') d.close(); else d.removeAttribute('open'); }
    }
    d.addEventListener('close', () => {
      if(d.open) return;                 // stale: prompted again since
      clearInterval(rateTimer);
      $('stepPw').value = '';
      lock(false);
      const p = pending; pending = null;
      if(p) p.reject(new ApiError('Cancelled.', 0, 'cancelled'));
    });
    $('stepPasskey').addEventListener('click', viaPasskey);
    $('stepPwForm').addEventListener('submit', viaPassword);
    $('stepCancel').addEventListener('click', close);
    // o: {passwordOnly, passkeys, why}
    function prompt(o){
      o = o || {};
      if(pending) return new Promise((res, rej) => { const p = pending; const r0 = p.resolve, j0 = p.reject;
        p.resolve = (x) => { r0(x); res(x); }; p.reject = (x) => { j0(x); rej(x); }; });
      const known = typeof o.passkeys === 'number' ? o.passkeys : (P.app && P.app.passkeys ? P.app.passkeys.count : 0);
      const pwOnly = !!o.passwordOnly || !known || !webauthn.supported;
      showPasswordOnly(pwOnly);
      $('stepNudge').hidden = !(pwOnly && !o.passwordOnly && webauthn.supported && !known);
      $('stepTitle').textContent = o.passwordOnly ? 'Admin password needed' : 'Unlock for 5 minutes';
      $('stepWhy').textContent = o.passwordOnly
        ? 'Your first passkey is added with the admin password, once. After that, Face ID or a fingerprint is enough.'
        : (o.why || 'This changes who can get in. Confirm once and everything stays unlocked for 5 minutes.');
      setMsg(''); setState('idle'); lock(false);
      if(!webauthn.supported && !o.passwordOnly && known){
        setMsg('This browser can’t use passkeys here, so use the admin password.', 'warn');
      }
      return new Promise((resolve, reject) => {
        pending = {resolve, reject};
        if(typeof d.showModal === 'function'){ if(!d.open) d.showModal(); } else d.setAttribute('open', '');
        setTimeout(() => (pwOnly ? $('stepPw') : $('stepPasskey')).focus(), 40);
      });
    }
    async function end(){
      await request('POST', '/api/stepup/end', {}, {stepup:false});
      if(P.app) P.app.stepup = {active:false, expires_at:null, method:null};
      renderUnlock();
      P.emit('stepup', {active:false});
    }
    return {prompt, end, close};
  })();
  function renderUnlock(){
    const s = P.app && P.app.stepup;
    const on = !!(s && s.active && s.expires_at && s.expires_at > P.now());
    for(const id of ['topUnlock', 'navUnlock']){
      const c = $(id);
      c.hidden = !on;
      if(on){
        const t = left(s.expires_at - P.now());
        c.textContent = 'Unlocked ' + t.replace(/^(\d+)m (\d+)s$/, '$1:$2');
        c.setAttribute('aria-label', 'Unlocked for ' + t + '. Tap to manage.');
      }
    }
    if(s && s.active && !on){ s.active = false; P.emit('stepup', {active:false}); }
  }
  P.renderUnlock = renderUnlock;
  P.on('tick', renderUnlock);
  P.on('stepup', (d) => {
    if(d && P.app){ P.app.stepup = Object.assign(P.app.stepup || {}, d); if(!d.active){ P.app.stepup.expires_at = null; } }
    renderUnlock();
  });
  for(const id of ['topUnlock', 'navUnlock']) $(id).addEventListener('click', () => { location.hash = '#/you'; });

  // ---- request badge -----------------------------------------------------------------------
  P.setRequestCount = function(n){
    n = Math.max(0, n | 0);
    const b = $('navReq');
    b.textContent = n > 99 ? '99+' : String(n);
    b.hidden = !n;
    const link = b.closest('a');
    link.setAttribute('aria-label', 'Requests' + (n ? ', ' + n + ' waiting' : ''));
    const base = (P.app && P.app.pocket && P.app.pocket.title) || CFG.title || 'Porch';
    document.title = (n ? '(' + n + ') ' : '') + base;
    try{
      if(n && navigator.setAppBadge) navigator.setAppBadge(n).catch(() => {});
      else if(!n && navigator.clearAppBadge) navigator.clearAppBadge().catch(() => {});
    }catch(e){}
  };
  P.setDoorCount = function(n){
    const c = $('navDoors');
    c.textContent = String(n || 0);
    c.hidden = !n;
  };

  // ---- router ------------------------------------------------------------------------------
  // A section: {label, resolve(parts) -> view}. A view: {key, title, back,
  // backLabel, single, list(pane) -> cleanup?, detail(pane) -> cleanup?,
  // empty(pane)}. The list pane re-renders only when its key changes, so it
  // keeps its scroll while details change beside it.
  const sections = {};
  P.sectionDef = (name, def) => { sections[name] = def; };
  let route = {section:null, parts:[]};
  let listKey = null, listCleanup = null, detailCleanup = null;
  const WIDE = window.matchMedia('(min-width:700px)');
  function parse(){
    const h = (location.hash || '').replace(/^#\/?/, '');
    const parts = h.split('?')[0].split('/').filter(Boolean).map((p) => { try{ return decodeURIComponent(p); }catch(e){ return p; } });
    return {section: parts[0] && sections[parts[0]] ? parts[0] : 'home', parts: parts.slice(1)};
  }
  function currentSection(){ return route.section; }
  P.route = () => route;
  P.wide = () => WIDE.matches;
  // Park persistent widgets (share.js's) before a pane is emptied.
  function park(pane){
    pane.querySelectorAll('[data-persist]').forEach((n) => $('parking').append(n));
  }
  function runCleanup(f){ if(typeof f === 'function'){ try{ f(); }catch(e){} } }
  function render(force){
    const r = parse();
    const def = sections[r.section];
    const view = def.resolve(r.parts) || {};
    const changedSection = route.section !== r.section;
    route = r;
    const split = $('main'), lp = $('listPane'), dp = $('detailPane');
    // nav state
    document.querySelectorAll('.nav-item').forEach((a) => {
      if(a.dataset.tab === r.section) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
    });
    const key = r.section + ':' + (view.key || '');
    if(force || key !== listKey){
      runCleanup(listCleanup); listCleanup = null;
      park(lp);
      lp.replaceChildren();
      listKey = key;
      if(view.list) listCleanup = view.list(lp);
    }else if(view.listUpdate){
      view.listUpdate(lp);
    }
    markCurrent(lp);
    runCleanup(detailCleanup); detailCleanup = null;
    park(dp);
    dp.replaceChildren();
    if(view.single){
      split.dataset.single = '';
      split.dataset.view = 'list';
    }else{
      delete split.dataset.single;
      split.dataset.view = view.detail ? 'detail' : 'list';
      if(view.detail) detailCleanup = view.detail(dp);
      else if(view.empty) view.empty(dp);
    }
    // top bar (phones)
    const back = $('topBack');
    const showBack = !!(view.detail && view.back);
    back.hidden = !showBack;
    if(showBack){ back.href = view.back; $('topBackLabel').textContent = view.backLabel || def.label; }
    $('topTitle').textContent = view.title || def.label;
    setAuth(P.app && P.app.auth ? P.app.auth.state : 'ok');
    // focus the view heading (the detail's on a push, else the list's)
    const target = (view.detail && (!WIDE.matches || !changedSection) ? dp : lp).querySelector('[data-focus]');
    if(target && !force) target.focus({preventScroll:true});
    if(!force){
      if(!WIDE.matches || changedSection) window.scrollTo(0, 0);
      else if(view.detail) dp.scrollIntoView({block:'nearest'});
    }
  }
  P.render = render;
  // The list row whose detail is open wears aria-current.
  function markCurrent(lp){
    const h = location.hash;
    lp.querySelectorAll('a.item, a.menu-item, a.req').forEach((a) => {
      const href = a.getAttribute('href');
      if(href && (h === href || h.startsWith(href + '/'))) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    });
  }
  P.markCurrent = () => markCurrent($('listPane'));
  // Re-render only the detail pane / only the list pane (data changed).
  // True while the user is typing in `box` (a text field, select or
  // editable): live redraws hold off then. A focused button (the one just
  // tapped, or the opener a sheet hands focus back to) doesn't count.
  P.typingIn = function(box){
    const a = document.activeElement;
    return !!(a && a !== document.body && box.contains(a) &&
      a.matches('input:not([type=checkbox]):not([type=radio]):not([type=button]):not([type=submit]), textarea, select, [contenteditable]'));
  };
  P.refreshDetail = function(){
    const r = parse();
    if(r.section !== route.section) return;
    const view = sections[r.section].resolve(r.parts) || {};
    const dp = $('detailPane');
    runCleanup(detailCleanup); detailCleanup = null;
    const y = window.scrollY;
    park(dp);
    dp.replaceChildren();
    if(view.detail) detailCleanup = view.detail(dp);
    else if(view.empty && !view.single) view.empty(dp);
    window.scrollTo(0, y);
  };
  P.refreshList = function(){
    const r = parse();
    const view = sections[r.section].resolve(r.parts) || {};
    const lp = $('listPane');
    const y = window.scrollY, ly = lp.scrollTop;
    runCleanup(listCleanup); listCleanup = null;
    park(lp);
    lp.replaceChildren();
    if(view.list) listCleanup = view.list(lp);
    markCurrent(lp);
    window.scrollTo(0, y); lp.scrollTop = ly;
  };
  P.go = (hash) => { if(location.hash === hash) render(); else location.hash = hash; };
  window.addEventListener('hashchange', () => render());
  WIDE.addEventListener && WIDE.addEventListener('change', () => render(true));

  // Detail placeholder on wide layouts.
  P.detailEmpty = function(pane, title, text, ic){
    const box = el('div', 'detail-empty');
    const m = el('div', 'detail-empty-mark');
    m.append(icon(ic || 'door'));
    box.append(m, el('div', 'detail-empty-title', title));
    if(text) box.append(el('div', 'small', text));
    pane.append(box);
  };

  // Load into a container with skeleton / error / retry. key caches the last
  // good answer in memory (never in storage) so an offline pane still shows it.
  const memo = {};
  P.memo = memo;
  P.load = function(box, key, fetcher, draw, o){
    o = o || {};
    let alive = true;
    const go = () => {
      if(memo[key] !== undefined) draw(memo[key], true);
      else box.replaceChildren(o.skeleton ? o.skeleton() : P.skeleton(o.rows || 3));
      fetcher().then((d) => {
        if(!alive) return;
        memo[key] = d; P.markFresh();
        draw(d, false);
      }, (err) => {
        if(!alive) return;
        if(memo[key] !== undefined && err.code === 'offline') return;
        box.replaceChildren(P.errorBox(err, go));
      });
    };
    go();
    return () => { alive = false; };
  };

  // ---- app info -------------------------------------------------------------------------------
  P.app = null;
  P.loadApp = function(){
    return request('GET', '/api/app').then((a) => {
      P.app = a;
      P.setServerNow(a.now);
      if(a.counts){ P.setRequestCount(a.counts.requests || 0); P.setDoorCount(a.counts.doors || 0); }
      renderUnlock();
      setAuth(a.auth ? a.auth.state : 'ok');
      P.emit('app', a);
      return a;
    });
  };
  P.on('online', () => { P.loadApp().catch(() => {}); });

  // ---- shared data (memory only; never written to storage) ---------------------------------
  P.store = (function(){
    function make(path, pick){
      const s = {data:null, err:null, loading:null, subs:[]};
      s.load = () => {
        if(s.loading) return s.loading;
        s.loading = request('GET', path).then((d) => {
          if(d && typeof d.now === 'number') P.setServerNow(d.now);
          s.data = pick ? pick(d) : d; s.err = null; s.loading = null;
          P.markFresh();
          s.subs.slice().forEach((f) => { try{ f(s.data); }catch(e){ console.error(e); } });
          return s.data;
        }, (e) => { s.loading = null; s.err = e; throw e; });
        return s.loading;
      };
      s.set = (d) => { s.data = pick ? pick(d) : d; s.subs.slice().forEach((f) => { try{ f(s.data); }catch(e){ console.error(e); } }); };
      s.on = (f) => { s.subs.push(f); return () => { s.subs = s.subs.filter((x) => x !== f); }; };
      let t = null;
      s.soon = () => { clearTimeout(t); t = setTimeout(() => s.load().catch(() => {}), 250); };
      return s;
    }
    const list = (k) => (d) => Array.isArray(d) ? d : (d && Array.isArray(d[k]) ? d[k] : []);
    return {
      doors: make('/api/doors', list('doors')),
      history: make('/api/doors/history', list('history')),
      requests: make('/api/requests', (d) => ({reopen: (d && d.reopen) || [], pairings: (d && d.pairings) || [],
                                               access: (d && d.access) || [], accepts: (d && d.accepts) || [], auth: (d && d.auth) || {state:'ok'}})),
      people: make('/api/people', (d) => ({devices: (d && d.devices) || [], invites: (d && d.invites) || [],
                                           apps: (d && d.apps) || [], public_paths: (d && d.public_paths) || [],
                                           auth: (d && d.auth) || {state:'ok'}})),
    };
  })();
  // Bind a container to a store: skeleton until the first answer, an error
  // box with Retry when there is nothing to show, redraw on every change.
  P.bind = function(box, store, draw, o){
    o = o || {};
    let first = true;
    const paint = (d) => { first = false; draw(d); if($('listPane').contains(box)) P.markCurrent(); };
    const off = store.on(paint);
    if(store.data !== null) paint(store.data);
    else box.replaceChildren(o.skeleton ? o.skeleton() : P.skeleton(o.rows || 4));
    const fetch_ = () => store.load().catch((err) => {
      if(store.data !== null && err.code === 'offline') return;
      if(first || store.data === null) box.replaceChildren(P.errorBox(err, () => { box.replaceChildren(P.skeleton(o.rows || 4)); fetch_(); }));
      else P.fail(err);
    });
    if(o.fresh !== false || store.data === null) fetch_();
    return off;
  };
  P.pendingAsks = (reopen) => (reopen || []).filter((r) => r.state === 'pending' && (!r.until || r.until > P.now()));
  // Ask for access (the gate pages): same shape of pending as reopen asks.
  P.pendingAccess = (access) => P.pendingAsks(access);
  P.waitingCount = (d) => P.pendingAsks(d.reopen).length + (d.pairings || []).length + P.pendingAccess(d.access).length;
  P.store.requests.on((d) => {
    P.setRequestCount(P.waitingCount(d));
    if(d.auth && d.auth.state) setAuth(d.auth.state);
  });
  P.store.people.on((d) => { if(d.auth && d.auth.state) setAuth(d.auth.state); });
  P.store.doors.on((d) => P.setDoorCount(d.filter((x) => !x.self).length));
  P.on('doors', (d) => { if(d && (Array.isArray(d) || Array.isArray(d.doors))) P.store.doors.set(d); else P.store.doors.soon(); });
  P.on('history', (d) => { if(d && (Array.isArray(d) || Array.isArray(d.history))) P.store.history.set(d); else P.store.history.soon(); });
  // `requests` carries the reopen records; `people` the porch-auth snapshot
  // (devices, invites, apps, pairings, accepts, auth): no refetch needed.
  P.on('requests', (d) => {
    const cur = P.store.requests.data;
    if(Array.isArray(d) && cur) P.store.requests.set(Object.assign({}, cur, {reopen: d}));
    else P.store.requests.soon();
  });
  P.on('people', (d) => {
    if(d && Array.isArray(d.devices)) P.store.people.set(d); else P.store.people.soon();
    const cur = P.store.requests.data;
    if(d && Array.isArray(d.pairings) && cur)
      P.store.requests.set(Object.assign({}, cur, {pairings: d.pairings, access: d.access || cur.access, accepts: d.accepts || cur.accepts, auth: d.auth || cur.auth}));
    else P.store.requests.soon();
  });

  P.ios = !!CFG.ios || /iPhone|iPad|iPod/.test(navigator.userAgent)
    || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  P.standalone = (window.matchMedia && matchMedia('(display-mode: standalone)').matches) || navigator.standalone === true;
  P.coarse = COARSE;
  return P;
})();

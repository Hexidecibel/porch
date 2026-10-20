'use strict';
// Pocket's service worker (served at /sw.js, no-cache). v2:
//  * precaches the page's hashed assets, listed in the precache manifest the
//    server names below (its hash changes with any asset, and so does this
//    file, so a deploy installs a new worker);
//  * cache-first for hashed /static/ and /__porch-assets/ files (immutable),
//    network-first for the page itself (an offline launch still opens the
//    last copy);
//  * never caches anything else: API answers, events and files always go to
//    the network.
const SHELL = 'pocket-shell-v2';
const PRECACHE = '__PRECACHE_URL__';
const HASHED = /^\/static\/[A-Za-z0-9_-]+\.[0-9a-f]{12}\.(js|css|json)$/;
// porch.css and its fonts (lib/porch_http.py's /__porch-assets/ table).
const PORCH = /^\/__porch-assets\/(porch\.[0-9a-f]{12}\.css|fonts\/[a-z0-9-]+\.[0-9a-f]{12}\.woff2)$/;
const immutable = (p) => HASHED.test(p) || PORCH.test(p);
self.addEventListener('install', (e) => {
  self.skipWaiting();
  e.waitUntil(caches.open(SHELL).then((c) => fetch(PRECACHE, {credentials: 'same-origin'})
    .then((r) => (r.ok ? r.json() : []))
    .then((list) => {
      const keep = (Array.isArray(list) ? list : []).filter(immutable);
      // Drop what an older deploy cached (everything but these and the page).
      return c.addAll(keep).then(() => c.keys()).then((ks) => Promise.all(ks
        .filter((k) => { const p = new URL(k.url).pathname; return p !== '/' && keep.indexOf(p) < 0; })
        .map((k) => c.delete(k))));
    })
    .catch(() => null)));
});
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys()
    .then((ks) => Promise.all(ks.filter((k) => k !== SHELL).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});
self.addEventListener('fetch', (e) => {
  const r = e.request;
  if (r.method !== 'GET') return;
  const u = new URL(r.url);
  if (u.origin !== location.origin) return;
  if (immutable(u.pathname)) {
    e.respondWith(caches.match(r).then((m) => m || fetch(r).then((res) => {
      if (res.ok) { const c = res.clone(); caches.open(SHELL).then((x) => x.put(r, c)); }
      return res;
    })));
    return;
  }
  if (r.mode !== 'navigate' || u.pathname !== '/') return;
  e.respondWith(fetch(r).then((res) => {
    if (res.ok) { const c = res.clone(); caches.open(SHELL).then((x) => x.put('/', c)); }
    return res;
  }).catch(() => caches.match('/').then((m) => m || Response.error())));
});

// Web Push (lib/porch_push.py). Types:
//  reopen  {t, id, name, title, body}: Android shows Allow 1h / Allow 24h; a
//          tap anywhere else (every tap on iOS) opens /reopen/<id>.
//  pairing {t, code, device_name, kind, title, body}: a machine or browser
//          wants in. No buttons (approving needs a step-up); a tap opens
//          /#/requests/pairing/<code>.
//  invite  {t, invite_id, note, device_name, title, body}: an invite or guest
//          pass was used; a tap opens /#/people/guests/<id>.
//  access  {t, id, host, title, body}: someone at a gated app's gate page
//          asks for access. No buttons (allowing needs a step-up); a tap
//          opens /#/requests/access/<id>.
//  test    {t, title, body}.
const RID = /^[A-Za-z0-9_-]{16}$/;
const CODE = /^[A-Z]{4}-[0-9]{4}$/;
const INV = /^[A-Za-z0-9_-]{1,64}$/;
function target(d) {
  if (d.t === 'reopen' && RID.test(d.id || '')) return '/reopen/' + d.id;
  if (d.t === 'pairing' && CODE.test(d.code || '')) return '/#/requests/pairing/' + d.code;
  if (d.t === 'invite' && INV.test(d.invite_id || '')) return '/#/people/guests/' + encodeURIComponent(d.invite_id);
  if (d.t === 'access' && RID.test(d.id || '')) return '/#/requests/access/' + d.id;
  return '/';
}
self.addEventListener('push', (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (x) { d = {}; }
  if (!d || typeof d !== 'object') d = {};
  const reopen = d.t === 'reopen' && RID.test(d.id || '');
  const pairing = d.t === 'pairing' && CODE.test(d.code || '');
  const invite = d.t === 'invite' && INV.test(d.invite_id || '');
  const access = d.t === 'access' && RID.test(d.id || '');
  const tag = reopen ? 'reopen-' + d.id : pairing ? 'pairing-' + d.code
    : invite ? 'invite-' + d.invite_id : access ? 'access-' + d.id : 'pocket';
  const opts = {body: String(d.body || '').slice(0, 200), icon: '/icon-192.png', badge: '/icon-192.png',
                tag: tag, renotify: true,
                data: {t: d.t, id: reopen ? d.id : null, name: String(d.name || ''), url: target(d)}};
  if (reopen) {
    opts.requireInteraction = true;
    opts.actions = [{action: 'allow-1h', title: 'Allow 1h'}, {action: 'allow-24h', title: 'Allow 24h'}];
  } else if (pairing || access) {
    opts.requireInteraction = true;
  }
  e.waitUntil(self.registration.showNotification(String(d.title || 'Porch').slice(0, 120), opts));
});
function openPage(url) {
  return self.clients.matchAll({type: 'window', includeUncontrolled: true}).then((ws) => {
    for (const w of ws) {
      if (new URL(w.url).origin === location.origin && 'navigate' in w) {
        return w.navigate(url).then((c) => (c || w).focus()).catch(() => self.clients.openWindow(url));
      }
    }
    return self.clients.openWindow(url);
  });
}
self.addEventListener('notificationclick', (e) => {
  const d = e.notification.data || {};
  e.notification.close();
  const m = /^allow-(1h|24h)$/.exec(e.action || '');
  if (d.t === 'reopen' && m && RID.test(d.id || '')) {
    // Same-origin POST with the owner's cookie; Pocket checks both.
    e.waitUntil(fetch('/api/reopen/' + d.id, {
      method: 'POST', credentials: 'same-origin',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({decision: 'allow', expires: m[1]})
    }).then((r) => {
      if (!r.ok) return openPage(d.url);
      return self.registration.showNotification('"' + d.name + '" is open again', {
        body: 'For ' + (m[1] === '1h' ? 'an hour' : '24 hours') + '. Their page comes in by itself.',
        icon: '/icon-192.png', badge: '/icon-192.png', tag: 'reopen-' + d.id});
    }).catch(() => openPage(d.url)));
    return;
  }
  e.waitUntil(openPage(typeof d.url === 'string' && d.url.charAt(0) === '/' ? d.url : '/'));
});

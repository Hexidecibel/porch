/* You (#/you/...): security (step-up, passkeys, admin password),
 * notifications with per-device topics, Share from iPhone (device share
 * keys, ported), the activity log and About. */
'use strict';
(function(){
  const P = window.Porch;
  const {icon, fmt} = P;
  const enc = encodeURIComponent;

  /* ---- push state (ported, plus topics) ---- */
  const PUSH_OK = 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
  let pushInfo = null, pushSub = null, myId = null;
  const TOPICS = [['reopen', 'Reopen asks', 'Someone asks you to reopen a closed door.'],
                  ['pairing', 'New machines and pairings', 'A machine or browser asks to pair.'],
                  ['invite', 'Guest invite used', 'Someone joins through one of your invite links.'],
                  ['access', 'Asks for access', 'Someone at a private app’s door asks you to let them in.']];
  function keyBytes(s){
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(s + '==='.slice((s.length + 3) % 4));
    return Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
  }
  async function subId(endpoint){
    try{
      const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(endpoint));
      return Array.from(new Uint8Array(h)).map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
    }catch(e){ return null; }
  }
  function publish(){ P.pushState = {on: !!pushSub, supported: !!(pushInfo && pushInfo.supported && PUSH_OK)}; P.emit('push', P.pushState); }
  P.loadPush = function(){
    return api('GET', '/api/push').then((info) => {
      pushInfo = info;
      if(!PUSH_OK || !info.supported) return null;
      return navigator.serviceWorker.ready.then((reg) => reg.pushManager.getSubscription());
    }).then(async (sub) => { pushSub = sub || null; myId = sub ? await subId(sub.endpoint) : null; })
      .catch(() => {}).then(publish);
  };
  async function pushOn(permission){
    const perm = await permission;
    if(perm !== 'granted'){ say('Notifications were not allowed on this device.', 'warn'); return; }
    const reg = await navigator.serviceWorker.ready;
    const key = keyBytes(pushInfo.public_key);
    let sub;
    try{ sub = await reg.pushManager.subscribe({userVisibleOnly:true, applicationServerKey:key}); }
    catch(e){
      const old = await reg.pushManager.getSubscription();
      if(!old) throw e;
      await old.unsubscribe();
      sub = await reg.pushManager.subscribe({userVisibleOnly:true, applicationServerKey:key});
    }
    const r = await api('POST', '/api/push/subscribe', {subscription: sub.toJSON()});
    pushSub = sub; myId = await subId(sub.endpoint); pushInfo.subscriptions = r.subscriptions;
    say('Notifications are on for this device. Try Send a test.');
  }
  async function pushOff(){
    const sub = pushSub;
    pushSub = null; myId = null;
    if(sub){
      const r = await api('POST', '/api/push/unsubscribe', {endpoint: sub.endpoint}).catch(() => null);
      if(r) pushInfo.subscriptions = r.subscriptions;
      await sub.unsubscribe().catch(() => {});
    }
    say('Notifications are off for this device.');
  }

  /* ---- the menu ---- */
  const MENU = [
    ['security', 'shield', 'Security', () => {
      const s = P.app && P.app.stepup;
      return s && s.active && s.expires_at > P.now() ? 'Unlocked · ' + fmt.left(s.expires_at - P.now()) : 'Step-up, admin password';
    }],
    ['passkeys', 'fingerprint', 'Passkeys', () => { const n = P.app && P.app.passkeys ? P.app.passkeys.count : 0; return n ? P.fmt.plural(n, 'passkey') : 'Face ID, fingerprint'; }],
    ['notifications', 'bell', 'Notifications', () => P.pushState ? (P.pushState.on ? 'On for this device' : 'Off on this device') : 'Reopen asks, pairings, invites'],
    ['iphone', 'phone', 'Share from iPhone', () => 'Shortcut and device keys'],
    ['activity', 'activity', 'Activity', () => 'Every privileged change'],
    ['about', 'info', 'About', () => (P.app && P.app.pocket && P.app.pocket.name) || 'This pocket'],
  ];
  function menuPane(pane){
    pane.append(P.paneHead('You'));
    const m = el('nav', 'menu');
    m.setAttribute('aria-label', 'Settings');
    const subs = [];
    for(const [key, ic, name, sub] of MENU){
      const a = P.link('#/you/' + key, 'menu-item');
      const i = el('span', 'menu-ico'); i.append(icon(ic));
      const mm = el('span', 'menu-main');
      const s = el('span', 'menu-sub', sub());
      subs.push([s, sub]);
      mm.append(el('span', 'menu-name', name), s);
      a.append(i, mm, icon('chev', 'item-chev'));
      m.append(a);
    }
    pane.append(m);
    const upd = () => subs.forEach(([s, f]) => { s.textContent = f(); });
    const offs = [P.on('push', upd), P.on('stepup', upd), P.on('app', upd)];
    const t = setInterval(upd, 1000);
    return () => { offs.forEach((f) => f()); clearInterval(t); };
  }

  /* ---- security ---- */
  function security(pane){
    pane.append(P.paneHead('Security', {kicker:'You'}));
    const card = el('div', 'card');
    const draw = () => {
      const s = P.app && P.app.stepup;
      const on = !!(s && s.active && s.expires_at > P.now());
      const st = el('div', 'sec-state');
      if(on) st.dataset.on = '';
      const i = el('div', 'sec-state-ico'); i.append(icon(on ? 'unlock' : 'lock'));
      const t = el('div', 'grow');
      const head = el('div', 'card-title', on ? 'Unlocked' : 'Locked');
      const sub = el('div', 'card-sub');
      if(on){ sub.append(document.createTextNode('by ' + (s.method === 'passkey' ? 'passkey' : 'admin password') + ' · ')); const cd = P.countdown(s.expires_at); cd.dataset.done = 'locking'; sub.append(cd, document.createTextNode(' left')); }
      else sub.textContent = 'Changing who can get in asks for Face ID, a fingerprint or the admin password first. It then stays unlocked for 5 minutes.';
      t.append(head, sub);
      st.append(i, t);
      const acts = el('div', 'actions');
      if(on) acts.append(P.btn('Lock now', 'p-btn p-btn--ghost', async (e, b) => { b.disabled = true; try{ await P.stepup.end(); say('Locked.'); }catch(err){ P.fail(err); } b.disabled = false; }, {icon:'lock'}));
      else acts.append(P.btn('Unlock now', 'p-btn', () => P.stepup.prompt({why:'Unlock now, so the next changes don’t ask again for 5 minutes.'}).catch(P.fail), {icon:'unlock', write:true}));
      card.replaceChildren(st, acts);
    };
    draw();
    pane.append(card);
    const pk = el('div', 'card');
    const n = P.app && P.app.passkeys ? P.app.passkeys.count : 0;
    const ph = el('div', 'card-head'); const pt = el('div', 'card-title'); pt.append(icon('fingerprint'), document.createTextNode('Passkeys')); ph.append(pt);
    pk.append(ph, el('div', 'card-sub', n ? P.fmt.plural(n, 'passkey') + ' can unlock this pocket.' : 'None yet. Add one and unlock with Face ID or a fingerprint instead of the password.'));
    const un = P.app && P.app.passkeys ? P.app.passkeys.unusable : 0;
    if(un) pk.append(el('div', 'p-notice p-notice--warn', P.fmt.plural(un, 'passkey') + ' stopped working when this pocket was renamed. Add this device again; the admin password still works.'));
    const pa = el('div', 'actions'); pa.append(P.link('#/you/passkeys', 'p-btn p-btn--ghost', n ? 'Manage passkeys' : 'Add a passkey'));
    pk.append(pa);
    pane.append(pk);
    const pw = el('div', 'card');
    const wh = el('div', 'card-head'); const wt = el('div', 'card-title'); wt.append(icon('key'), document.createTextNode('Admin password')); wh.append(wt);
    pw.append(wh, el('div', 'card-sub', 'The password for auth and the fallback here. Changing it signs other admin sessions out of the auth console.'));
    const wa = el('div', 'actions'); wa.append(P.btn('Change password', 'p-btn p-btn--ghost', passwordSheet, {write:true}));
    pw.append(wa);
    pane.append(pw);
    const offs = [P.on('stepup', draw), P.on('app', draw)];
    return () => offs.forEach((f) => f());
  }
  function passwordSheet(){
    const cur = P.input('password', {autocomplete:'current-password', maxLength:1024, spell:false});
    const nw = P.input('password', {autocomplete:'new-password', maxLength:1024, spell:false});
    const again = P.input('password', {autocomplete:'new-password', maxLength:1024, spell:false});
    const body = el('div', 'sheet-body');
    body.append(P.field('Current password', cur), P.field('New password', nw, 'At least 12 characters.'), P.field('New password again', again));
    const wipe = () => { cur.value = ''; nw.value = ''; again.value = ''; };
    P.sheet.open({kicker:'Security', title:'Change the admin password', body, focus: cur,
      text:'This needs an unlock and the current password.',
      actions:[{label:'Change password', write:true, busy:'Changing…', run: async () => {
        if(!cur.value) throw new Error('Type the current password.');
        if(nw.value.length < 12) throw new Error('The new password needs at least 12 characters.');
        if(nw.value !== again.value) throw new Error('The new passwords don’t match.');
        await P.post('/api/people/password', {current: cur.value, new: nw.value}, {why:'Changing the admin password needs an unlock.'});
        wipe();
        say('Admin password changed.');
      }}, {label:'Cancel', cls:'p-btn p-btn--quiet p-btn--lg'}],
      onClose: wipe});
  }

  /* ---- passkeys ---- */
  function passkeys(pane){
    let alive = true;
    pane.append(P.paneHead('Passkeys', {kicker:'You', sub:[el('span', '', 'Face ID, Touch ID, a fingerprint or a security key, for this pocket only.')]}));
    const addCard = el('div', 'card card--accent');
    const lab = P.input('text', {maxLength:40, value: P.webauthn.deviceHint(), autocomplete:'off'});
    const add = P.btn('Add a passkey', 'p-btn', async (e, b) => {
      const label = lab.value.trim() || P.webauthn.deviceHint();
      b.disabled = true;
      try{
        await P.webauthn.register(label);
        say('Passkey added. Next time, unlock with ' + (P.ios ? 'Face ID' : 'it') + '.');
        if(P.app && P.app.passkeys) P.app.passkeys.count = (P.app.passkeys.count || 0) + 1;
        P.emit('app', P.app);
        load();
      }catch(err){
        if(err.code === 'cancelled') say(err.message, 'warn'); else P.fail(err);
      }
      b.disabled = false;
    }, {icon:'plus', write:true});
    const ah = el('div', 'card-head'); const at = el('div', 'card-title'); at.append(icon('fingerprint'), document.createTextNode('Add this device')); ah.append(at);
    addCard.append(ah);
    if(!P.webauthn.supported){
      addCard.append(el('div', 'p-notice p-notice--warn', window.isSecureContext ? 'This browser can’t make passkeys. The admin password still works for every unlock.'
                                                                              : 'Passkeys need the https page.'));
      add.disabled = true;
    }
    addCard.append(P.field('Name it', lab, 'So you can tell your passkeys apart.'));
    const aa = el('div', 'actions'); aa.append(add); addCard.append(aa);
    const box = el('div', 'sec');
    pane.append(addCard, box);
    const rpNote = el('p', 'small', '');
    pane.append(rpNote);
    function row(k){
      const r = el('div', 'item');
      const av = el('span', 'avatar'); av.dataset.kind = k.unusable ? 'revoked' : 'admin'; av.append(icon('fingerprint'));
      const main = el('div', 'item-main');
      const top = el('div', 'item-top');
      top.append(el('span', 'item-name item-name--ui', k.label || 'Passkey'));
      if(k.synced) top.append(P.badge('synced', 'accent'));
      if(k.unusable) top.append(P.badge('unusable: pocket renamed', 'danger'));
      const meta = el('div', 'item-meta');
      meta.append(el('span', 'mono', k.short_id || String(k.id || '').slice(0, 10) + '…'), P.ago(k.created_at, 'added '),
                  el('span', '', k.last_used_at ? 'used ' + fmt.ago(k.last_used_at) : 'never used'));
      main.append(top, meta);
      const acts = el('div', 'item-acts');
      acts.append(P.btn('Rename', 'p-btn p-btn--ghost p-btn--sm', () => renameSheet(k), {write:true}),
                  P.btn('', 'p-btn p-btn--quiet p-btn--sm p-btn--icon', async (e, b) => {
                    const ok = await P.confirm({title:'Delete ' + (k.label || 'this passkey') + '?', danger:true, confirm:'Delete passkey',
                      text:'That device can’t unlock with it any more. Deleting needs an unlock.'});
                    if(!ok) return;
                    b.disabled = true;
                    try{
                      await P.post('/api/passkeys/' + enc(k.id) + '/delete', {}, {why:'Deleting a passkey needs an unlock.'});
                      say('Passkey deleted.');
                      if(P.app && P.app.passkeys) P.app.passkeys.count = Math.max(0, (P.app.passkeys.count || 1) - 1);
                      load();
                    }catch(err){ b.disabled = false; P.fail(err); }
                  }, {icon:'trash', write:true, aria:'Delete ' + (k.label || 'passkey')}));
      main.append(acts);
      r.append(av, main);
      return r;
    }
    function renameSheet(k){
      const inp = P.input('text', {maxLength:40, value: k.label || ''});
      const body = el('div', 'sheet-body'); body.append(P.field('Name', inp));
      P.sheet.open({kicker:'Passkey', title:'Rename', body, focus: inp,
        actions:[{label:'Save', write:true, run: async () => {
          const v = inp.value.trim();
          if(!v) throw new Error('Give it a name.');
          await P.post('/api/passkeys/' + enc(k.id) + '/rename', {label: v});
          say('Renamed.'); load();
        }}, {label:'Cancel', cls:'p-btn p-btn--quiet p-btn--lg'}]});
    }
    function load(){
      box.replaceChildren(P.skeleton(2));
      P.get('/api/passkeys').then((d) => {
        if(!alive) return;
        const list = Array.isArray(d) ? d : (d.passkeys || []);
        if(P.app && P.app.passkeys){
          P.app.passkeys.count = list.filter((x) => !x.unusable).length;
          P.app.passkeys.unusable = list.filter((x) => x.unusable).length;
          P.emit('app', P.app);
        }
        const rp = (d && d.rp_id) || (P.app && P.app.passkeys && P.app.passkeys.rp_id);
        rpNote.textContent = rp ? 'Passkeys are bound to ' + rp + '. Renaming the pocket makes them unusable; the admin password always works.' : '';
        if(!list.length){
          box.replaceChildren(P.empty('No passkeys yet', 'Add one: you’ll need the admin password once, then Face ID or a fingerprint is enough.', null, 'fingerprint'));
          return;
        }
        const items = el('div', 'items'); items.append(...list.map(row));
        box.replaceChildren(items);
      }, (err) => { if(alive) box.replaceChildren(P.errorBox(err, load)); });
    }
    load();
    return () => { alive = false; };
  }

  /* ---- notifications ---- */
  function notifications(pane){
    pane.append(P.paneHead('Notifications', {kicker:'You'}));
    const card = el('div', 'card');
    const topics = el('div', 'card');
    const devs = el('div', 'sec');
    pane.append(card, topics, devs);
    const draw = () => {
      const on = !!pushSub;
      const row = el('div', 'notif-row');
      const txt = el('div');
      const st = el('b', '', on ? 'On for this device' : 'Off on this device'); st.id = 'notifState';
      txt.append(st, el('span', 'small', 'Reopen asks, new machines and guests using your invites, as notifications on this device.'));
      const sw = P.switchBtn(on, 'notifState', () => {
        if(sw.disabled) return;
        sw.disabled = true;
        // The permission prompt has to start inside the tap (iOS insists).
        const job = pushSub ? pushOff() : pushOn(Notification.requestPermission());
        job.catch((err) => say('Could not change notifications: ' + err.message, 'error')).then(() => { sw.disabled = false; publish(); draw(); });
      });
      let why = '';
      if(pushInfo && !pushInfo.supported) why = pushInfo.why || 'Push isn’t set up on this pocket.';
      else if(!PUSH_OK) why = P.ios && !P.standalone
        ? 'On iPhone and iPad, notifications only work in the home-screen app: tap Share, then Add to Home Screen, and open Porch from there.'
        : 'This browser can’t receive web notifications.';
      else if(Notification.permission === 'denied') why = 'Notifications are blocked for this site. Allow them in the browser’s site settings, then turn this on again.';
      sw.disabled = !pushInfo || !pushInfo.supported || !PUSH_OK;
      row.append(txt, sw);
      card.replaceChildren(row);
      if(why) card.append(el('div', 'p-notice p-notice--warn', why));
      const subs = (pushInfo && pushInfo.subscriptions) || [];
      if(subs.length){
        const a = el('div', 'actions');
        a.append(P.btn('Send a test', 'p-btn p-btn--ghost p-btn--sm', (e, b) => {
          b.disabled = true;
          api('POST', '/api/push/test', {}).then((r) => {
            pushInfo.subscriptions = r.subscriptions || pushInfo.subscriptions;
            say(r.sent ? 'Sent to ' + r.sent + ' device' + (r.sent === 1 ? '' : 's') + '.' : 'Nothing was delivered' + (r.dropped ? ': ' + r.dropped + ' stale device(s) removed' : '') + '.', r.sent ? 'ok' : 'warn');
            draw();
          }).catch(P.fail).then(() => { b.disabled = false; });
        }));
        card.append(a);
      }
      // topics for this device
      const mine = subs.find((s) => myId && s.id === myId);
      topics.hidden = !on;
      if(on){
        const th = el('div', 'card-head'); const tt = el('div', 'card-title'); tt.append(icon('bell'), document.createTextNode('On this device, tell me about')); th.append(tt);
        topics.replaceChildren(th);
        const cur = mine && Array.isArray(mine.topics) ? mine.topics : TOPICS.map((x) => x[0]);
        for(const [k, name, sub] of TOPICS){
          const r = el('div', 'notif-row');
          const t = el('div'); const b = el('b', '', name); b.id = 'topic-' + k;
          t.append(b, el('span', 'small', sub));
          r.append(t, P.switchBtn(cur.includes(k), 'topic-' + k, async (v, s) => {
            const next = TOPICS.map((x) => x[0]).filter((x) => x === k ? v : cur.includes(x));
            s.disabled = true;
            try{
              const res = await P.post('/api/push/topics', {endpoint: pushSub.endpoint, topics: next});
              if(res && res.subscriptions) pushInfo.subscriptions = res.subscriptions;
              else if(mine) mine.topics = next;
              else pushInfo.subscriptions = subs.map((x) => x).concat([]);
              say(name + (v ? ' on.' : ' off.'));
            }catch(err){ P.fail(err); }
            s.disabled = false;
            draw();
          }));
          topics.append(r);
        }
      }
      devs.replaceChildren();
      if(subs.length){
        devs.append(el('div', 'group-label', 'Devices notified · ' + subs.length));
        const items = el('div', 'items');
        for(const s of subs){
          const r = el('div', 'item');
          const av = el('span', 'avatar'); av.append(icon('bell'));
          const m = el('div', 'item-main');
          const top = el('div', 'item-top'); top.append(el('span', 'item-name item-name--ui', s.label || s.endpoint_host || 'A device'));
          if(myId && s.id === myId) top.append(P.badge('this device', 'self'));
          const meta = el('div', 'item-meta');
          meta.append(el('span', '', s.endpoint_host || ''));
          if(s.created) meta.append(P.ago(s.created, 'added '));
          if(Array.isArray(s.topics)) meta.append(el('span', '', s.topics.length + ' of 3 topics'));
          m.append(top, meta);
          if(!(myId && s.id === myId)){
            const acts = el('div', 'item-acts');
            // Another device's subscription can only be muted from here
            // (unsubscribing needs its endpoint, which only it knows).
            const muted = Array.isArray(s.topics) && !s.topics.length;
            acts.append(P.btn(muted ? 'Unmute' : 'Mute', 'p-btn p-btn--quiet p-btn--sm', async (e, b) => {
              b.disabled = true;
              try{
                const res = await P.post('/api/push/topics', {id: s.id, topics: muted ? TOPICS.map((x) => x[0]) : []});
                if(res && res.subscriptions) pushInfo.subscriptions = res.subscriptions;
                say(muted ? 'Unmuted.' : 'Muted: it gets nothing until you unmute it.'); draw();
              }catch(err){ b.disabled = false; P.fail(err); }
            }, {write:true, aria:(muted ? 'Unmute ' : 'Mute ') + (s.label || s.endpoint_host)}));
            m.append(acts);
          }
          r.append(av, m);
          items.append(r);
        }
        devs.append(items);
      }
    };
    card.append(P.skeleton(1));
    P.loadPush().then(draw);
    return () => {};
  }

  /* ---- share from iPhone: device keys (ported) ---- */
  function iphone(pane){
    pane.append(P.paneHead('Share from iPhone', {kicker:'You'}));
    pane.append(el('p', 'small', 'iPhone and iPad can’t share to web apps, but a Shortcut can. Make a device key for it here (it can only add to this pocket: it can’t read the clipboard or the inbox), then build the Shortcut once.'));
    const form = el('div', 'card');
    const kf = el('div', 'key-form');
    const lab = P.input('text', {maxLength:40, placeholder:'Device name, e.g. My iPhone'});
    lab.setAttribute('aria-label', 'Device name');
    const keyBox = el('div', 'key-box'); keyBox.hidden = true;
    const keyVal = el('code', '');
    function showKey(k){ keyVal.textContent = k.key; keyBox.hidden = false; }
    kf.append(lab, P.btn('Create device key', 'p-btn', () => {
      api('POST', '/api/keys', {label: lab.value}).then((k) => { lab.value = ''; showKey(k); loadKeys(); }).catch(P.fail);
    }, {write:true}));
    keyBox.append(el('div', 'small', 'Your new key. It is shown once: copy it into the Shortcut now.'), keyVal);
    const ka = el('div', 'actions');
    ka.append(P.btn('Copy key', 'p-btn p-btn--sm', () => copied(copyText(keyVal.textContent), 'Key copied')),
              P.btn('Done', 'p-btn p-btn--quiet p-btn--sm', () => { keyVal.textContent = ''; keyBox.hidden = true; }));
    keyBox.append(ka);
    form.append(kf, keyBox);
    const list = el('div', 'p-list');
    list.append(P.skeleton(1));
    pane.append(form, list);
    function keyRow(k){
      const r = el('div', 'p-row');
      const main = el('div', 'p-row-main');
      main.append(el('div', 'p-row-name', k.label),
                  el('div', 'p-row-meta', 'made ' + fmt.ago(k.created) + ' · ' +
                     (k.last_used ? 'last used ' + fmt.ago(k.last_used) + ' · ' + k.uses + ' share' + (k.uses === 1 ? '' : 's') : 'never used')));
      const acts = el('div', 'row-actions');
      acts.append(P.btn('Rotate', 'p-btn p-btn--ghost p-btn--sm', () => api('POST', '/api/keys/' + enc(k.id) + '/rotate', {})
        .then(showKey).then(loadKeys).catch(P.fail), {write:true, aria:'New key for ' + k.label}));
      const rev = P.btn('Revoke', 'p-btn p-btn--quiet p-btn--sm', null, {write:true, aria:'Revoke the key for ' + k.label});
      rev.addEventListener('click', () => {
        if(rev.dataset.armed !== '1'){
          rev.dataset.armed = '1'; rev.textContent = 'Really?'; rev.className = 'p-btn p-btn--danger p-btn--sm';
          setTimeout(() => { rev.dataset.armed = ''; rev.textContent = 'Revoke'; rev.className = 'p-btn p-btn--quiet p-btn--sm'; }, 4000);
          return;
        }
        api('POST', '/api/keys/' + enc(k.id) + '/delete', {}).then(render).then(() => say('Key revoked.')).catch(P.fail);
      });
      acts.append(rev);
      r.append(main, acts);
      return r;
    }
    function render(keys){
      keys = Array.isArray(keys) ? keys : [];
      if(!keys.length){ list.replaceChildren(el('div', 'p-row', '')); list.firstChild.append(el('span', 'small', 'No device keys yet.')); return; }
      list.replaceChildren(...keys.map(keyRow));
    }
    function loadKeys(){ return api('GET', '/api/keys').then(render).catch((err) => list.replaceChildren(P.errorBox(err, loadKeys))); }
    loadKeys();
    const steps = el('ol', 'ios-steps');
    const li = (...parts) => { const l = el('li'); parts.forEach((p) => l.append(typeof p === 'string' ? document.createTextNode(p) : p)); steps.append(l); };
    const b = (t) => el('b', '', t), c = (t) => el('code', '', t);
    li('Open ', b('Shortcuts'), ', tap ', b('+'), ', name it ', b('Send to Porch'), '.');
    li('Tap the ', b('(i)'), ' details button, turn on ', b('Show in Share Sheet'), ', and set it to receive ', b('Images, Media, Files and PDFs'), '.');
    li('Add ', b('Repeat with Each'), ' on ', b('Shortcut Input'), '.');
    li('Inside the repeat, add ', b('Get Contents of URL'), '. URL: ', c(location.origin + '/share'));
    li('Tap ', b('Show More'), '. Method ', b('POST'), '. Under ', b('Headers'), ', add ', c('Authorization'), ' with the value ', c('Bearer '), ' followed by your key.');
    li(b('Request Body'), ': ', b('Form'), '. Add a ', b('File'), ' field named ', c('files'), ' set to ', b('Repeat Item'), '.');
    li('Done. In any app, tap Share, then ', b('Send to Porch'), '. Photos and files land in the inbox.');
    li('For text and links to become the clipboard, make a second Shortcut, ', b('Porch: text'), ': receive ', b('Text, URLs and Safari web pages'),
       ', one ', b('Get Contents of URL'), ' as above, but with a ', b('Text'), ' field named ', c('text'), ' set to ', b('Shortcut Input'), '.');
    const sc = P.section('Build the Shortcut');
    const scard = el('div', 'card'); scard.append(steps, el('p', 'small', 'Lost a phone? Revoke its key; Rotate gives the same device a new key (update the Shortcut’s header).'));
    sc.append(scard);
    pane.append(sc);
    return () => { keyVal.textContent = ''; };
  }

  /* ---- activity ---- */
  const TONE = [[/revoke|delete|stop|remove|reject|deny|unprotect|forget|fail|regress/i, 'danger'],
                [/approve|add|register|create|protect|allow|reopen|launch/i, 'ok'],
                [/step.?up|unlock|password|role|apps/i, 'accent']];
  function activity(pane){
    pane.append(P.paneHead('Activity', {kicker:'You', sub:[el('span', '', 'Privileged changes made from this pocket, newest first.')]}));
    const box = el('div');
    pane.append(box);
    return P.load(box, 'activity', () => P.get('/api/activity?limit=100'), (d) => {
      const list = Array.isArray(d) ? d : (d.items || d.activity || []);
      if(!list.length){ box.replaceChildren(P.empty('Nothing yet', 'Unlocks, approvals, revokes and rule changes show up here.', null, 'activity')); return; }
      const items = el('div', 'items activity');
      list.slice().sort((a, b) => b.ts - a.ts).forEach((a) => {
        const r = el('div', 'act');
        const tone = a.result && a.result !== 'ok' ? 'danger' : (TONE.find(([re]) => re.test(a.action || '')) || [null, ''])[1];
        if(tone) r.dataset.tone = tone;
        r.append(el('span', 'act-dot'), el('div', 'act-what', String(a.action || '').replace(/[._]/g, ' ') + (a.target ? ' · ' + a.target : '')));
        const bits = [fmt.when(a.ts)];
        if(a.method) bits.push('via ' + a.method);
        if(a.ip) bits.push(a.ip);
        if(a.result && a.result !== 'ok') bits.push(a.result + (a.code ? ' (' + a.code + ')' : ''));
        r.append(el('div', 'act-meta', bits.join(' · ')));
        items.append(r);
      });
      box.replaceChildren(items);
    }, {rows:6});
  }

  /* ---- about ---- */
  function about(pane){
    pane.append(P.paneHead('About', {kicker:'You'}));
    const card = el('div', 'card');
    const draw = () => {
      const a = P.app || {};
      const dl = el('dl', 'kv');
      const kv = (k, v, mono) => { dl.append(el('dt', '', k), el('dd', mono ? 'mono' : '', v)); };
      kv('Instance', (a.pocket && a.pocket.name) || '—', true);
      kv('Address', (a.pocket && (a.pocket.origin || a.pocket.host)) || location.origin, true);
      const auth = a.auth ? a.auth.state : 'unknown';
      kv('Auth server', {ok:'answering', down:'not answering', stale:'slow to answer', old:'needs an update (bin/auth-deploy)'}[auth] || auth);
      kv('Passkeys bound to', (a.passkeys && a.passkeys.rp_id) || '—', true);
      kv('This browser', (a.me && a.me.device_name) || '—');
      kv('Version', a.version || CFG.version || '—', true);
      card.replaceChildren(dl);
    };
    draw();
    pane.append(card);
    const live = el('div', 'actions');
    live.append(P.btn('Check again', 'p-btn p-btn--ghost p-btn--sm', () => P.loadApp().then(draw).catch(P.fail), {icon:'refresh'}));
    pane.append(live);
    const offs = [P.on('app', draw)];
    if(P.installCard){
      const inst = P.installCard('about');
      pane.append(inst);
      offs.push(inst.cleanup);
    }
    return () => offs.forEach((f) => f());
  }

  const VIEWS = {security, passkeys, notifications, iphone, activity, about};
  const TITLES = {security:'Security', passkeys:'Passkeys', notifications:'Notifications', iphone:'Share from iPhone', activity:'Activity', about:'About'};
  P.sectionDef('you', {
    label: 'You',
    resolve(parts){
      const k = VIEWS[parts[0]] ? parts[0] : null;
      const base = {key:'menu', title:'You', list: menuPane};
      if(k) return Object.assign(base, {title: TITLES[k], back:'#/you', backLabel:'You', detail: (p) => VIEWS[k](p)});
      // Wide layouts open Security beside the menu; phones show the menu.
      if(P.wide()) return Object.assign(base, {detail: security});
      return base;
    },
  });
})();

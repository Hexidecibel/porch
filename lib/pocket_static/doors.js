/* Doors (#/doors, #/doors/recent, #/doors/<name>): every door on this box,
 * its expiry and share rules, stop, recent doors (reopen / revive / forget)
 * and the New door sheet. The inspector lives in inspect.js. */
'use strict';
(function(){
  const P = window.Porch;
  const {icon, fmt} = P;
  const NAME_RE = /^[a-z0-9][a-z0-9-]{0,40}$/;
  const enc = encodeURIComponent;
  const doorPath = (name, what) => '/api/doors/' + enc(name) + (what ? '/' + what : '');
  P.NAME_RE = NAME_RE;

  /* ---- rows ---- */
  P.doorRow = function(d, compact){
    if(d.self) return selfRow(d);
    const a = P.link('#/doors/' + enc(d.name), 'item');
    const r = P.route();
    if(r.section === 'doors' && r.parts[0] === d.name) a.setAttribute('aria-current', 'page');
    const main = el('div', 'item-main');
    const top = el('div', 'item-top');
    top.append(el('span', 'item-name', d.name), P.typeChip(d.type));
    main.append(top);
    const meta = el('div', 'item-meta');
    if(d.unmanaged) meta.append(el('span', '', 'not managed by Porch'));
    else{
      const cd = P.countdown(d.expires);
      meta.append(cd);
      if(d.expires !== null && d.expires !== undefined) cd.dataset.done = 'closing';
      meta.append(el('span', '', P.fmt.plural(d.opens || 0, 'open')));
      if(!compact && d.last_open) meta.append(P.ago(d.last_open, 'last '));
    }
    main.append(meta);
    if(!d.unmanaged) main.append(P.meter(d.started, d.expires));
    const b = P.ruleBadges(d);
    if(b.childElementCount && !compact) main.append(b);
    a.append(main, icon('chev', 'item-chev'));
    a.setAttribute('aria-label', d.name + ', ' + (d.type || 'door') + (d.expires ? ', closes in ' + fmt.left(d.expires - P.now()) : ', never expires'));
    return a;
  };
  // The Porch app's own door: always on, run by the box, not something you opened.
  function selfRow(d){
    const a = P.link('#/doors/' + enc(d.name), 'item item--system');
    const r = P.route();
    if(r.section === 'doors' && r.parts[0] === d.name) a.setAttribute('aria-current', 'page');
    const main = el('div', 'item-main');
    const top = el('div', 'item-top');
    top.append(icon('home', 'item-ico'), el('span', 'item-name item-name--ui', 'Porch app'), P.badge('system', 'self'));
    const meta = el('div', 'item-meta');
    meta.append(el('span', '', 'Always on · runs this app'), el('span', 'mono', d.name));
    main.append(top, meta);
    a.append(main, icon('chev', 'item-chev'));
    a.setAttribute('aria-label', 'Porch app, system door, always on');
    return a;
  }
  P.yourDoors = (ds) => (ds || []).filter((d) => !d.self);
  const sortDoors = (ds) => ds.slice().sort((a, b) =>
    (a.expires === null ? Infinity : a.expires) - (b.expires === null ? Infinity : b.expires) || a.name.localeCompare(b.name));

  /* ---- the list pane ---- */
  function listPane(pane, seg){
    const offs = [];
    const more = P.btn('', 'p-btn p-btn--ghost p-btn--icon', () => overflow(), {icon:'more', aria:'More door actions'});
    const add = P.btn('New', 'p-btn', () => P.newDoor(), {icon:'plus', write:true, aria:'New door'});
    pane.append(P.paneHead('Doors', {actions:[more, add]}));
    const segBox = el('div');
    pane.append(segBox);
    const box = el('div');
    pane.append(box);
    const drawSeg = () => {
      const n = P.store.doors.data ? P.yourDoors(P.store.doors.data).length : '';
      const h = P.store.history.data ? P.store.history.data.length : '';
      segBox.replaceChildren(P.seg([['#/doors', 'Open', n], ['#/doors/recent', 'Recent', h]], seg === 'recent' ? '#/doors/recent' : '#/doors'));
    };
    drawSeg();
    if(seg === 'recent'){
      offs.push(P.bind(box, P.store.history, (items) => { drawSeg(); drawHistory(box, items); }));
      offs.push(P.store.doors.on(drawSeg));
      if(!P.store.doors.data) P.store.doors.load().catch(() => {});
    }else{
      offs.push(P.bind(box, P.store.doors, (doors) => {
        drawSeg();
        const mine = P.yourDoors(doors), sys = doors.filter((d) => d.self);
        const parts = [];
        if(!mine.length){
          parts.push(P.empty('No doors open', 'A door is one thing you share: a folder, an upload box, a secret form.',
            P.btn('New door', 'p-btn p-btn--sm', () => P.newDoor(), {icon:'plus', write:true}), 'door'));
        }else{
          const list = el('div', 'items');
          list.append(...sortDoors(mine).map((d) => P.doorRow(d)));
          parts.push(list);
        }
        if(sys.length){
          const s = P.section('System');
          s.classList.add('sec--system');
          const list = el('div', 'items');
          list.append(...sys.map((d) => P.doorRow(d)));
          s.append(list);
          parts.push(s);
        }
        box.replaceChildren(...parts);
      }));
      offs.push(P.store.history.on(drawSeg));
      if(!P.store.history.data) P.store.history.load().catch(() => {});
    }
    return () => offs.forEach((f) => f());
  }
  function overflow(){
    const body = el('div', 'sec');
    const items = el('div', 'menu');
    const mk = (ic, name, sub, run, danger) => {
      const b = el('button', 'menu-item');
      b.type = 'button';
      const i = el('span', 'menu-ico'); i.append(icon(ic));
      const m = el('span', 'menu-main'); m.append(el('span', 'menu-name', name), el('span', 'menu-sub', sub));
      if(danger){ m.firstChild.classList.add('p-err-text'); }
      b.append(i, m);
      b.addEventListener('click', run);
      return b;
    };
    items.append(
      mk('refresh', 'Refresh', 'Read every door’s state again', () => { P.sheet.close(); P.store.doors.load().catch(P.fail); P.store.history.load().catch(() => {}); }),
      mk('clock', 'Recent doors', 'Reopen, revive or forget closed doors', () => { P.sheet.close(); P.go('#/doors/recent'); }),
      mk('stop', 'Stop all doors', 'Everything except the Porch app itself (needs unlock)', () => { P.sheet.close(); setTimeout(stopAll, 80); }, true));
    body.append(items);
    P.sheet.open({kicker:'Doors', title:'More', body, actions:[{label:'Close', cls:'p-btn p-btn--quiet p-btn--lg'}]});
  }
  async function stopAll(){
    const doors = (P.store.doors.data || []).filter((d) => !d.self && d.type !== 'pocket');
    if(!doors.length){ say('No doors to stop besides the Porch app.', 'warn'); return; }
    const list = el('div', 'badges');
    doors.slice(0, 24).forEach((d) => list.append(P.badge(d.name)));
    const ok = await P.confirm({title:'Stop ' + P.fmt.plural(doors.length, 'door') + '?', danger:true, confirm:'Stop all',
      text:'Every link to them stops working at once. The Porch app stays up. You can reopen them from Recent.', detail:list});
    if(!ok) return;
    try{
      const r = await P.post('/api/doors/stop-all', {}, {why:'Stopping every door at once needs an unlock.'});
      const n = (r.stopped || []).length, sk = (r.skipped || []).length;
      say('Stopped ' + P.fmt.plural(n, 'door') + (sk ? '; ' + sk + ' skipped' : '') + '.', sk ? 'warn' : 'ok');
      P.store.doors.soon(); P.store.history.soon();
    }catch(err){ P.fail(err); }
  }

  /* ---- recent ---- */
  const REASON = {expired:['expired', ''], closed:['closed', ''], used:['used up', 'warn'], burned:['burned', 'warn'],
                  'used up':['used up', 'warn'], stopped:['stopped', '']};
  function drawHistory(box, items){
    if(!items.length){
      box.replaceChildren(P.empty('Nothing closed lately', 'Doors you close or that expire show up here for 7 days, ready to reopen.', null, 'clock'));
      return;
    }
    const list = el('div', 'items');
    for(const h of items){
      const row = el('div', 'item');
      const main = el('div', 'item-main');
      const top = el('div', 'item-top');
      top.append(el('span', 'item-name', h.name), P.typeChip(h.type));
      main.append(top);
      const meta = el('div', 'item-meta');
      const rs = REASON[h.reason] || [h.reason || 'closed', ''];
      meta.append(P.badge(rs[0], rs[1]));
      if(h.closed) meta.append(P.ago(h.closed, 'closed '));
      else if(h.started) meta.append(P.ago(h.started, 'started '));
      main.append(meta);
      const acts = el('div', 'item-acts');
      if(h.reopenable){
        acts.append(P.btn('Reopen 1h', 'p-btn p-btn--sm', (e, b) => histAct(h, 'reopen', {expires:'1h'}, b), {write:true, aria:'Reopen ' + h.name + ' for an hour'}),
                    P.btn('24h', 'p-btn p-btn--ghost p-btn--sm', (e, b) => histAct(h, 'reopen', {expires:'24h'}, b), {write:true, aria:'Reopen ' + h.name + ' for 24 hours'}));
      }else if(h.reopen_why){
        main.append(el('div', 'small', h.reopen_why));
      }
      if(h.revivable) acts.append(P.btn('Revive', 'p-btn p-btn--ghost p-btn--sm', (e, b) => histAct(h, 'revive', {}, b), {write:true, aria:'Revive ' + h.name}));
      acts.append(P.btn('', 'p-btn p-btn--quiet p-btn--sm p-btn--icon', (e, b) => histAct(h, 'forget', {}, b), {icon:'x', write:true, aria:'Forget ' + h.name}));
      main.append(acts);
      row.append(main);
      list.append(row);
    }
    box.replaceChildren(list);
  }
  async function histAct(h, what, body, b){
    b.disabled = true;
    try{
      const r = await P.post('/api/doors/history/' + enc(h.name) + '/' + what, body, {timeout: 40000});
      if(what === 'forget') say('Forgot ' + h.name + '.');
      else say(h.name + ' is open again' + (r && r.url ? '.' : '.'));
      P.store.history.soon(); P.store.doors.soon();
      if(what !== 'forget' && r && r.name) P.go('#/doors/' + enc(r.name));
    }catch(err){ b.disabled = false; P.fail(err); }
  }

  /* ---- door detail ---- */
  function findDoor(name){ return (P.store.doors.data || []).find((d) => d.name === name) || null; }
  function detailPane(pane, name){
    const offs = [];
    const draw = () => {
      const d = findDoor(name);
      pane.replaceChildren();
      if(!d){
        if(P.store.doors.data === null){ pane.append(P.skeleton(2, true)); return; }
        pane.append(P.paneHead(name, {mono:true, kicker:'Door'}),
          P.empty('This door is closed', 'It may have expired or been stopped. Recent doors can reopen it.',
            P.link('#/doors/recent', 'p-btn p-btn--sm', 'Recent doors'), 'door'));
        return;
      }
      drawDoor(pane, d);
    };
    offs.push(P.store.doors.on(() => { if(!P.typingIn(pane)) draw(); else softUpdate(pane, name); }));
    draw();
    if(P.store.doors.data === null) P.store.doors.load().catch((err) => pane.replaceChildren(P.errorBox(err, () => P.refreshDetail())));
    return () => offs.forEach((f) => f());
  }
  // Data changed while the user is typing in the pane: refresh only the
  // ticking bits so focus and half-typed values survive.
  function softUpdate(pane, name){
    const d = findDoor(name);
    if(!d) return;
    const exp = pane.querySelector('[data-exp-big]');
    if(exp) exp.replaceChildren(P.countdown(d.expires));
  }
  function drawDoor(pane, d){
    const kick = el('div', 'door-hero');
    const sub = [P.typeChip(d.type), el('span', '', P.fmt.plural(d.opens || 0, 'open'))];
    if(d.last_open) sub.push(P.ago(d.last_open, 'last '));
    if(d.started) sub.push(P.ago(d.started, 'opened '));
    pane.append(P.paneHead(d.name, {mono:true, kicker:'Door', sub,
      actions: (d.inspect || d.capture) ? [P.link('#/doors/' + enc(d.name) + '/inspect', 'p-btn p-btn--ghost p-btn--sm', d.capture ? 'Requests' : 'Inspect')] : []}));
    const badges = P.ruleBadges(d);
    if(badges.childElementCount){ kick.append(badges); pane.append(kick); }
    if(d.unmanaged){
      pane.append(el('div', 'p-notice p-notice--warn', 'This tunnel was started outside Porch, so it has no expiry or rules to change. Stop it from the box.'));
    }
    // links
    const links = el('div', 'sec');
    links.append(P.urlBox('Door link', d.url, {accent:true}));
    if(d.guest_url) links.append(P.urlBox('Guest link', d.guest_url, {copied:'Guest link copied', badge: P.badge('lets its holder in', 'accent')}));
    pane.append(links);
    if(d.unmanaged){ pane.append(stopCard(d)); return; }
    pane.append(expiryCard(d), rulesCard(d));
    if(d.inspect || d.capture){
      const c = el('div', 'card');
      const h = el('div', 'card-head');
      const t = el('div', 'card-title'); t.append(icon(d.capture ? 'hook' : 'eye'), document.createTextNode(d.capture ? 'Webhook capture' : 'Request inspector'));
      h.append(t);
      c.append(h, el('div', 'card-sub', d.capture ? 'Every request to this hook is recorded; nothing is forwarded.' :
        'Every request through this door is recorded' + (d.inspect_raw ? ' unmasked (raw).' : ', secrets masked.')));
      const a = el('div', 'actions');
      a.append(P.link('#/doors/' + enc(d.name) + '/inspect', 'p-btn p-btn--ghost', 'Open the inspector'));
      c.append(a);
      pane.append(c);
    }
    pane.append(stopCard(d));
  }
  function card(title, ic, sub){
    const c = el('div', 'card');
    const h = el('div', 'card-head');
    const t = el('div', 'card-title'); t.append(icon(ic), document.createTextNode(title));
    h.append(t);
    c.append(h);
    if(sub) c.append(el('div', 'card-sub', sub));
    return c;
  }
  function expiryCard(d){
    const c = card('Expiry', 'clock');
    const big = el('div', 'exp-big');
    const cdBox = el('span'); cdBox.dataset.expBig = '';
    cdBox.append(P.countdown(d.expires));
    big.append(cdBox, el('span', 'small', d.expires ? 'left · closes ' + fmt.when(d.expires) : 'stays open until you stop it'));
    c.append(big);
    if(d.expires) c.append(P.meter(d.started, d.expires));
    const row = el('div', 'exp-row');
    const act = (body, what, label) => P.btn(label, 'p-btn p-btn--ghost', async (e, b) => {
      b.disabled = true;
      try{
        await P.post(doorPath(d.name, what), body);
        say(d.name + ': ' + (what === 'extend' ? label + ' added.' : (body.at === 'never' ? 'never expires now.' : 'expiry set.')));
        P.store.doors.soon();
      }catch(err){ P.fail(err); }
      b.disabled = false;
    }, {write:true});
    if(d.expires !== null) row.append(act({seconds:3600}, 'extend', '+1h'), act({seconds:86400}, 'extend', '+24h'));
    c.append(row);
    const lab = el('div', 'p-label', 'Or set it to');
    const chips = el('div', 'chips');
    for(const [at, text] of [['+30m', '30 min'], ['+1h', '1 hour'], ['+24h', '24 hours'], ['+7d', '7 days'], ['never', 'Never']]){
      const ch = el('button', 'chip', text);
      ch.type = 'button'; ch.dataset.write = '';
      ch.setAttribute('aria-checked', String(at === 'never' && d.expires === null));
      ch.addEventListener('click', async () => {
        ch.disabled = true;
        try{ await P.post(doorPath(d.name, 'expire'), {at}); say(d.name + ': ' + (at === 'never' ? 'never expires now.' : 'closes in ' + text + '.')); P.store.doors.soon(); }
        catch(err){ P.fail(err); }
        ch.disabled = false;
      });
      chips.append(ch);
    }
    c.append(lab, chips);
    // custom date and time
    const custom = el('div', 'custom-exp');
    const inp = P.input('datetime-local');
    const pad = (n) => String(n).padStart(2, '0');
    const def = new Date((d.expires || (P.now() + 3600)) * 1000);
    inp.value = def.getFullYear() + '-' + pad(def.getMonth() + 1) + '-' + pad(def.getDate()) + 'T' + pad(def.getHours()) + ':' + pad(def.getMinutes());
    const f = P.field('Close at an exact time', inp);
    custom.append(f, P.btn('Set', 'p-btn p-btn--ghost', async (e, b) => {
      const t = Date.parse(inp.value);
      if(!inp.value || isNaN(t)){ say('Pick a date and time.', 'warn'); return; }
      if(t / 1000 <= P.now() + 30){ say('Pick a time in the future.', 'warn'); return; }
      b.disabled = true;
      try{ await P.post(doorPath(d.name, 'expire'), {at: Math.round(t / 1000)}); say(d.name + ' closes ' + fmt.when(t / 1000) + '.'); P.store.doors.soon(); }
      catch(err){ P.fail(err); }
      b.disabled = false;
    }, {write:true}));
    c.append(custom);
    return c;
  }

  /* rules: each change goes to POST /api/doors/<name>/rules. Removing a
     password or a limit widens access, so the server asks for a step-up. */
  function rulesCard(d){
    const r = d.rules || {};
    const c = card('Share rules', 'shield', 'Who gets in, and how many times. Changes apply to the running door.');
    const status = el('div', 'busy-note'); status.hidden = true;
    const hasProxy = !!(r.password || r.guest_link || r.guest || r.max_opens || d.inspect || d.capture);
    async function setRules(body, done, why){
      status.replaceChildren(el('span', 'spin'), el('span', '', hasProxy ? 'Saving…' : 'Putting a door proxy in front… (up to 15s)'));
      status.hidden = false;
      c.querySelectorAll('button').forEach((b) => { b.disabled = true; });
      try{
        const res = await P.post(doorPath(d.name, 'rules'), body, {timeout: 30000, why});
        status.hidden = true;
        c.querySelectorAll('button').forEach((b) => { b.disabled = false; });
        say(done);
        if(res && res.guest_url && body.guest === 'new') P.showQr('New guest link', res.guest_url);
        P.store.doors.load().catch(() => {});
      }catch(err){
        if(err.code === 'relaunch_needed') relaunchSheet(d, err.data.command, err.data.why || err.message);
        else if(err.code === 'switch_failed') say('The door couldn’t switch to the proxy, so nothing changed. ' + (err.message || ''), 'error');
        else P.fail(err);
        P.refreshDetail();
      }
    }
    // password
    const pwOn = !!r.password;
    const pwRule = rule('lock', 'Password', pwOn ? 'On: visitors type it before they see anything.' : 'Off: anyone with the link gets in.', pwOn);
    pwRule.acts.append(P.btn(pwOn ? 'Change' : 'Set a password', 'p-btn p-btn--ghost p-btn--sm', () => passwordSheet(d, setRules), {write:true}));
    if(pwOn) pwRule.acts.append(P.btn('Remove', 'p-btn p-btn--quiet p-btn--sm', async () => {
      const ok = await P.confirm({title:'Remove the password?', text:'Anyone with the link gets in straight away. This needs an unlock.', confirm:'Remove password', danger:true});
      if(ok) setRules({password:null}, 'Password removed.', 'Removing a password opens the door to anyone with the link.');
    }, {write:true, icon:'lock'}));
    c.append(pwRule.node);
    // guest link
    const gOn = !!(r.guest_link || r.guest);
    const gRule = rule('ticket', 'Guest link', gOn ? 'On: a second link that skips the password.' : 'Off.', gOn);
    gRule.acts.append(P.btn(gOn ? 'New guest link' : 'Make a guest link', 'p-btn p-btn--ghost p-btn--sm', async () => {
      if(gOn){
        const ok = await P.confirm({title:'Make a new guest link?', text:'The old guest link stops working at once.', confirm:'New guest link'});
        if(!ok) return;
      }
      setRules({guest:'new'}, gOn ? 'New guest link made; the old one is dead.' : 'Guest link made.');
    }, {write:true}));
    if(gOn) gRule.acts.append(P.btn('Turn off', 'p-btn p-btn--quiet p-btn--sm', () => setRules({guest:null}, 'Guest link turned off.'), {write:true}));
    c.append(gRule.node);
    // max opens
    const mo = r.max_opens || null;
    const mRule = rule('flame', 'Max opens', mo ? (mo === 1 ? 'Burns after one open' : 'Closes after ' + mo + ' opens') + ' · ' + (d.opens || 0) + ' used' : 'No limit.', !!mo);
    const step = el('div', 'stepper');
    const num = el('input');
    num.type = 'number'; num.min = '1'; num.max = '1000'; num.inputMode = 'numeric';
    num.value = String(mo || Math.max(5, (d.opens || 0) + 1));
    num.setAttribute('aria-label', 'Max opens');
    const minus = el('button', '', '−'); minus.type = 'button'; minus.setAttribute('aria-label', 'One fewer');
    const plus = el('button', '', '+'); plus.type = 'button'; plus.setAttribute('aria-label', 'One more');
    minus.addEventListener('click', () => { num.value = String(Math.max(1, (+num.value || 1) - 1)); });
    plus.addEventListener('click', () => { num.value = String(Math.min(1000, (+num.value || 0) + 1)); });
    step.append(minus, num, plus);
    mRule.acts.append(step, P.btn('Save', 'p-btn p-btn--ghost p-btn--sm', () => {
      const n = +num.value;
      if(!Number.isInteger(n) || n < 1 || n > 1000){ say('Max opens is a whole number from 1 to 1000.', 'warn'); return; }
      setRules({max_opens:n}, 'Closes after ' + n + ' opens.');
    }, {write:true}));
    if(mo !== 1) mRule.acts.append(P.btn('Burn after 1', 'p-btn p-btn--quiet p-btn--sm', () => setRules({max_opens:1}, 'Burns after the next open.'), {write:true, icon:'flame'}));
    if(mo) mRule.acts.append(P.btn('No limit', 'p-btn p-btn--quiet p-btn--sm', async () => {
      const ok = await P.confirm({title:'Remove the limit?', text:'The door stays open however many times it’s opened. This needs an unlock.', confirm:'Remove limit', danger:true});
      if(ok) setRules({max_opens:null}, 'No limit now.', 'Removing a limit lets more people in.');
    }, {write:true}));
    c.append(mRule.node, status);
    return c;
  }
  function rule(ic, name, state, on){
    const n = el('div', 'rule');
    if(on) n.dataset.on = '';
    const i = el('div', 'rule-ico'); i.append(icon(ic));
    const m = el('div', 'rule-main');
    m.append(el('div', 'rule-name', name), el('div', 'rule-state', state));
    const acts = el('div', 'rule-acts');
    m.append(acts);
    n.append(i, m);
    return {node:n, acts};
  }
  function passwordSheet(d, setRules){
    const inp = P.input('password', {autocomplete:'new-password', maxLength:1024, spell:false});
    const show = el('label', 'toggle');
    const cb = el('input'); cb.type = 'checkbox';
    cb.addEventListener('change', () => { inp.type = cb.checked ? 'text' : 'password'; });
    show.append(cb, el('span', '', 'Show it'));
    const body = el('div', 'sheet-body');
    body.append(P.field('New password', inp, 'At least 6 characters. Tell it to people another way, not in the same message as the link.'), show);
    P.sheet.open({kicker: d.name, title: d.rules && d.rules.password ? 'Change the password' : 'Set a password', body, focus: inp,
      actions:[{label:'Save password', write:true, run: () => {
                 const v = inp.value;
                 if(v.length < 6) throw new Error('Use at least 6 characters.');
                 inp.value = '';
                 setRules({password:v}, 'Password set. Visitors type it first.');
               }},
               {label:'Cancel', cls:'p-btn p-btn--quiet p-btn--lg'}],
      onClose: () => { inp.value = ''; }});
  }
  function relaunchSheet(d, command, message){
    const body = el('div', 'sheet-body');
    body.append(el('p', 'small', message || 'This door was started before live rule changes existed, so it has to be started again with the new rules.'));
    if(command){
      body.append(el('pre', 'cmd', command));
    }
    P.sheet.open({kicker: d.name, title:'Restart needed', body,
      actions: (command ? [{label:'Copy command', run: () => { copied(copyText(command), 'Command copied'); return false; }}] : [])
        .concat([{label:'Done', cls:'p-btn p-btn--quiet p-btn--lg'}])});
  }
  function stopCard(d){
    const c = el('div', 'card card--danger');
    const z = el('div', 'danger-zone');
    const txt = el('div', 'grow');
    txt.append(el('div', 'card-title', 'Stop this door'),
               el('div', 'card-sub', d.self ? 'This is the Porch app itself: stopping it from here would cut you off. Use the box for that.' :
                                     'The link stops working at once. It stays in Recent for 7 days.'));
    const b = P.btn('Stop door', 'p-btn p-btn--danger', async (e, btn) => {
      const ok = await P.confirm({title:'Stop ' + d.name + '?', text:'Everyone loses the link at once. You can reopen it from Recent.', confirm:'Stop door', danger:true});
      if(!ok) return;
      btn.disabled = true;
      try{
        await P.post(doorPath(d.name, 'stop'), {});
        say(d.name + ' stopped.');
        P.store.doors.soon(); P.store.history.soon();
        P.go('#/doors');
      }catch(err){ btn.disabled = false; P.fail(err); }
    }, {write:true, icon:'stop'});
    if(d.self){ b.disabled = true; b.title = 'The Porch app can’t stop itself'; delete b.dataset.write; }
    z.append(txt, b);
    c.append(z);
    return c;
  }

  /* ---- New door ---- */
  const TYPES = [
    ['drop', 'Drop', 'Anyone can upload; you download'],
    ['photos', 'Photos', 'A gallery people add to'],
    ['media', 'Media', 'Photos and video, streamable'],
    ['music', 'Music', 'A player for your tracks'],
    ['exchange', 'Exchange', 'They paste text to you'],
    ['secure-entry', 'Secret', 'One-time secret form'],
    ['paste', 'Paste', 'Share a block of text'],
  ];
  function suggest(type){
    const taken = new Set((P.store.doors.data || []).map((d) => d.name));
    const base = type === 'secure-entry' ? 'secret' : type;
    for(let i = 0; i < 20; i++){
      const n = base + '-' + Math.random().toString(16).slice(2, 6);
      if(!taken.has(n)) return n;
    }
    return base + '-' + Date.now().toString(16).slice(-5);
  }
  P.newDoor = function(preset){
    let type = (preset && preset.type) || 'drop';
    let expires = '1h';
    const body = el('div', 'sheet-body');
    // type
    const tf = el('div', 'p-field');
    tf.append(el('div', 'p-label', 'What kind of door'));
    const grid = el('div', 'type-grid');
    grid.setAttribute('role', 'radiogroup'); grid.setAttribute('aria-label', 'Door type');
    for(const [t, name, sub] of TYPES){
      const b = el('button', 'type-opt');
      b.type = 'button'; b.setAttribute('role', 'radio'); b.dataset.v = t;
      b.append(P.typeChip(t), el('span', 'type-opt-sub', sub));
      b.setAttribute('aria-label', name + ': ' + sub);
      b.addEventListener('click', () => setType(t));
      grid.append(b);
    }
    tf.append(grid);
    // name
    const name = P.input('text', {maxLength:41, spell:false, autocomplete:'off', mono:true});
    name.classList.add('p-input--mono');
    const hint = el('div', 'field-hint');
    const nf = el('div', 'p-field');
    const nl = el('label', 'p-label', 'Name'); nl.htmlFor = name.id = 'ndName';
    const row = el('div', 'name-row');
    const sugg = P.btn('', 'p-btn p-btn--ghost p-btn--icon', () => { name.value = suggest(type); checkName(); }, {icon:'refresh', aria:'Suggest a free name'});
    row.append(name, sugg);
    nf.append(nl, row, hint);
    const tb = P.tunnelBase();
    function checkName(){
      const v = name.value.trim();
      delete hint.dataset.bad; delete hint.dataset.ok;
      if(!v){ hint.textContent = 'Lowercase letters, digits and dashes.'; return false; }
      if(!NAME_RE.test(v)){ hint.dataset.bad = ''; hint.textContent = 'Use lowercase letters, digits and dashes, starting with a letter or digit (up to 41).'; return false; }
      if((P.store.doors.data || []).some((d) => d.name === v)){ hint.dataset.bad = ''; hint.textContent = 'A door called ' + v + ' is already open.'; return false; }
      hint.dataset.ok = ''; hint.textContent = 'https://' + v + (tb ? '.' + tb : '');
      return true;
    }
    name.addEventListener('input', () => { name.value = name.value.toLowerCase().replace(/[^a-z0-9-]/g, '-'); checkName(); });
    // content (paste) / view-only (media)
    const content = el('textarea', 'p-textarea p-textarea--mono');
    content.rows = 5; content.maxLength = 1048576; content.id = 'ndContent';
    const cf = P.field('Text to share', content, 'Shown with syntax highlighting. Up to 1 MB.');
    const vo = el('label', 'toggle');
    const voIn = el('input'); voIn.type = 'checkbox';
    const voTxt = el('span'); voTxt.append(el('b', '', 'View only'), el('span', 'p-help', 'Guests watch; they can’t add or download.'));
    vo.append(voIn, voTxt);
    // expiry
    const ef = el('div', 'p-field');
    ef.append(el('div', 'p-label', 'Expires in'));
    const exp = P.chips([['30m', '30 min'], ['1h', '1 hour'], ['24h', '24 hours'], ['7d', '7 days'], ['never', 'Never']], expires, (v) => { expires = v; }, 'Expires in');
    ef.append(exp.node);
    // rules
    const opts = el('div', 'opts');
    const pw = P.input('password', {autocomplete:'new-password', maxLength:1024, spell:false});
    const burn = el('input'); burn.type = 'checkbox';
    const max = P.input('number', {min:1, max:1000, inputMode:'numeric', placeholder:'no limit'});
    const guest = el('input'); guest.type = 'checkbox';
    const burnL = el('label', 'toggle'); const bt = el('span'); bt.append(el('b', '', 'Burn after one open'), el('span', 'p-help', 'The door closes after the first visitor.')); burnL.append(burn, bt);
    const gL = el('label', 'toggle'); const gt = el('span'); gt.append(el('b', '', 'Guest link'), el('span', 'p-help', 'A second link that lets its holder straight in.')); gL.append(guest, gt);
    const mf = P.field('Max opens (optional)', max); mf.classList.add('max-field');
    burn.addEventListener('change', () => { max.disabled = burn.checked; });
    opts.append(P.field('Password (optional)', pw, 'Visitors type it before they see anything.'), burnL, mf, gL);
    body.append(tf, nf, cf, vo, ef, opts);

    function setType(t){
      type = t;
      grid.querySelectorAll('.type-opt').forEach((b) => b.setAttribute('aria-checked', String(b.dataset.v === t)));
      cf.hidden = t !== 'paste';
      vo.hidden = t !== 'media';
      if(!name.value || name.dataset.auto === name.value){ name.value = suggest(t); name.dataset.auto = name.value; }
      checkName();
    }
    setType(type);

    P.sheet.open({kicker:'New door', title:'Open a door', body, text:'Each door is its own link with its own expiry.',
      actions:[{label:'Open door', write:true, busy:'Opening…', run: async () => {
        if(!checkName()) throw new Error(hint.textContent || 'Pick a name.');
        const req = {type, name: name.value.trim(), expires};
        if(type === 'paste'){
          if(!content.value.trim()) throw new Error('Type or paste the text to share.');
          req.content = content.value;
        }
        if(type === 'media' && voIn.checked) req.view_only = true;
        const rules = {};
        if(pw.value){ if(pw.value.length < 6) throw new Error('The password needs at least 6 characters.'); rules.password = pw.value; }
        if(guest.checked) rules.guest = true;
        if(burn.checked) rules.max_opens = 1;
        else if(max.value.trim()){
          const n = Number(max.value);
          if(!Number.isInteger(n) || n < 1 || n > 1000) throw new Error('Max opens is a whole number from 1 to 1000.');
          rules.max_opens = n;
        }
        if(Object.keys(rules).length) req.rules = rules;
        const res = await P.post('/api/doors/launch', req, {timeout: 40000});
        pw.value = '';
        P.store.doors.soon();
        setTimeout(() => doorReady(res, req), 60);
      }}, {label:'Cancel', cls:'p-btn p-btn--quiet p-btn--lg'}],
      onClose: () => { pw.value = ''; content.value = ''; }});
  };
  function doorReady(res, req){
    const body = el('div', 'sheet-body');
    body.append(P.urlBox('Door link', res.url, {accent:true, qr:false}));
    body.append(el('div', 'qr-box'));
    body.lastChild.append(P.qr(res.url));
    if(res.guest_url) body.append(P.urlBox('Guest link', res.guest_url, {copied:'Guest link copied'}));
    const bits = [req.expires === 'never' ? 'never expires' : 'closes in ' + req.expires];
    if(req.rules && req.rules.password) bits.push('password');
    if(req.rules && req.rules.max_opens === 1) bits.push('burns after one open');
    else if(req.rules && req.rules.max_opens) bits.push('closes after ' + req.rules.max_opens + ' opens');
    body.append(el('p', 'small', bits.join(' · ')));
    P.sheet.open({kicker:'Door open', title: res.name || req.name, body,
      actions:[{label:'Open details', run: () => { P.go('#/doors/' + enc(res.name || req.name)); }},
               {label:'Done', cls:'p-btn p-btn--quiet p-btn--lg'}]});
  }

  /* ---- routes ---- */
  P.sectionDef('doors', {
    label: 'Doors',
    resolve(parts){
      const seg = parts[0] === 'recent' ? 'recent' : 'open';
      const base = {key: seg, title: 'Doors', list: (p) => listPane(p, seg),
                    empty: (p) => P.detailEmpty(p, seg === 'recent' ? 'Recent doors' : 'Pick a door',
                      seg === 'recent' ? 'Closed doors stay here for 7 days: reopen one for an hour or a day.' :
                      'Its link, expiry, share rules and requests show up here.', seg === 'recent' ? 'clock' : 'door')};
      if(seg === 'recent' || !parts[0]) return base;
      const name = parts[0];
      if(parts[1] === 'inspect' && P.inspectView){
        const id = parts[2] || null;
        return Object.assign(base, {title: id ? 'Request' : 'Inspect', back: id ? '#/doors/' + enc(name) + '/inspect' : '#/doors/' + enc(name),
          backLabel: id ? 'Requests' : name, detail: (p) => P.inspectView(p, name, id)});
      }
      return Object.assign(base, {title: name, back:'#/doors', backLabel:'Doors', detail: (p) => detailPane(p, name)});
    },
  });
})();

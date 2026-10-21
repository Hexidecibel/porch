/* People (#/people/devices|guests|apps): paired browsers and machines,
 * invite links and guest passes, and which apps are gated. Everything that
 * changes who can get in needs an unlock; the server enforces it and the
 * api() client opens the step-up sheet and retries once. */
'use strict';
(function(){
  const P = window.Porch;
  const {icon, fmt} = P;
  const enc = encodeURIComponent;

  function kindOf(d){
    if(d.revoked) return 'revoked';
    if(d.type !== 'browser') return 'machine';
    return d.role === 'admin' ? 'admin' : 'guest';
  }
  function avatar(d){
    const k = kindOf(d);
    const a = el('span', 'avatar'); a.dataset.kind = k === 'admin' ? 'admin' : k === 'machine' ? 'machine' : k === 'revoked' ? 'revoked' : '';
    a.append(icon(d.type !== 'browser' ? 'server' : /iphone|ipad|android|pixel|phone/i.test(d.name || '') ? 'phone' : 'laptop'));
    return a;
  }
  function deviceRow(d){
    const a = P.link('#/people/devices/' + enc(d.id), 'item');
    const main = el('div', 'item-main');
    const top = el('div', 'item-top');
    top.append(el('span', 'item-name item-name--ui', d.name || 'Unnamed'));
    if(d.this) top.append(P.badge('this browser', 'self'));
    main.append(top);
    const meta = el('div', 'item-meta');
    if(d.type === 'browser'){
      meta.append(el('span', '', d.role === 'admin' ? 'admin' : 'guest'));
      const apps = d.apps || [];
      meta.append(el('span', '', apps.includes('*') ? 'all apps' : P.fmt.plural(apps.length, 'app')));
      if(d.pass && d.pass.expires_at){ const s = el('span', ''); s.append(document.createTextNode('pass ')); const c = P.countdown(d.pass.expires_at); c.dataset.done = 'over'; s.append(c); meta.append(s); }
    }else{
      meta.append(el('span', '', 'machine'));
      if(d.tunnel_admin) meta.append(P.badge('tunnel admin', 'accent'));
    }
    meta.append(P.ago(d.last_seen, 'seen '));
    main.append(meta);
    a.append(avatar(d), main, icon('chev', 'item-chev'));
    return a;
  }
  const INV_TONE = {active:'ok', full:'warn', used:'', expired:'', revoked:'danger'};
  function inviteRow(i){
    const a = P.link('#/people/guests/' + enc(i.id), 'item');
    const av = el('span', 'avatar'); av.append(icon(i.standing ? 'pass' : 'ticket'));
    if(i.status === 'active') av.dataset.kind = 'admin';
    const main = el('div', 'item-main');
    const top = el('div', 'item-top');
    top.append(el('span', 'item-name item-name--ui', i.note || (i.standing ? 'Guest pass' : 'Invite')), P.badge(i.status, INV_TONE[i.status]));
    const meta = el('div', 'item-meta');
    meta.append(el('span', '', i.standing ? 'guest pass · ' + (i.live || 0) + '/' + i.max_uses + ' live' : (i.uses || 0) + '/' + i.max_uses + ' used'));
    meta.append(el('span', '', (i.apps || []).join(', ') || 'no apps'));
    if(i.expires_at && i.status === 'active'){ const s = el('span'); s.append(document.createTextNode('ends in '), P.countdown(i.expires_at)); meta.append(s); }
    else if(!i.expires_at && i.standing) meta.append(el('span', '', 'no end date'));
    main.append(top, meta);
    a.append(av, main, icon('chev', 'item-chev'));
    return a;
  }

  /* ---- list ---- */
  function listPane(pane, seg){
    const actions = seg === 'guests' ? [P.btn('Invite', 'p-btn', () => inviteSheet(false), {icon:'plus', write:true, aria:'New invite'})] : [];
    pane.append(P.paneHead('People', {actions}));
    const segBox = el('div');
    const box = el('div', 'sec');
    pane.append(segBox, box);
    const draw = (d) => {
      const live = d.devices.filter((x) => !x.revoked);
      const openInv = d.invites.filter((i) => i.status === 'active' || i.status === 'full');
      segBox.replaceChildren(P.seg([['#/people/devices', 'Devices', live.length], ['#/people/guests', 'Guests', openInv.length],
                                    ['#/people/apps', 'Apps', d.apps.length]], '#/people/' + seg));
      box.replaceChildren();
      if(d.auth && d.auth.state === 'down' && !d.devices.length){
        box.append(P.empty('porch-auth isn’t answering', 'People and invites can’t load until it’s back. Doors still work.', null, 'users'));
        return;
      }
      if(seg === 'devices') drawDevices(box, d);
      else if(seg === 'guests') drawGuests(box, d);
      else drawApps(box, d);
    };
    return P.bind(box, P.store.people, draw);
  }
  function group(box, title, rows, collapsed){
    if(!rows.length) return;
    const g = el(collapsed ? 'details' : 'div', 'group');
    const label = el(collapsed ? 'summary' : 'div', 'group-label', title + ' · ' + rows.length);
    const items = el('div', 'items'); items.append(...rows);
    g.append(label, items);
    box.append(g);
  }
  function drawDevices(box, d){
    const live = d.devices.filter((x) => !x.revoked);
    const me = live.filter((x) => x.this);
    const rest = live.filter((x) => !x.this);
    group(box, 'This browser', me.map(deviceRow));
    group(box, 'Admin browsers', rest.filter((x) => x.type === 'browser' && x.role === 'admin').map(deviceRow));
    group(box, 'Guest browsers', rest.filter((x) => x.type === 'browser' && x.role !== 'admin').map(deviceRow));
    group(box, 'Machines', rest.filter((x) => x.type !== 'browser').map(deviceRow));
    group(box, 'Revoked', d.devices.filter((x) => x.revoked).map(deviceRow), true);
    if(!box.childElementCount) box.append(P.empty('No devices yet', 'Pair a machine with bin/bootstrap, or send an invite.', null, 'users'));
  }
  function drawGuests(box, d){
    const acts = el('div', 'actions');
    acts.append(P.btn('New invite', 'p-btn p-btn--ghost p-btn--sm', () => inviteSheet(false), {icon:'ticket', write:true}),
                P.btn('New guest pass', 'p-btn p-btn--ghost p-btn--sm', () => inviteSheet(true), {icon:'pass', write:true}));
    box.append(acts);
    const open = d.invites.filter((i) => i.status === 'active' || i.status === 'full');
    const done = d.invites.filter((i) => !(i.status === 'active' || i.status === 'full'));
    group(box, 'Guest passes', open.filter((i) => i.standing).map(inviteRow));
    group(box, 'Invites', open.filter((i) => !i.standing).map(inviteRow));
    group(box, 'Finished', done.map(inviteRow), true);
    if(!d.invites.length) box.append(P.empty('No invites', 'An invite is a link that lets someone’s browser into the apps you pick. A guest pass stays up for many visitors.', null, 'ticket'));
  }
  function drawApps(box, d){
    const paths = d.public_paths || [];
    const gated = d.apps.filter((a) => a.protected);
    const c = el('div', 'card');
    c.append(el('div', 'card-sub', 'A gated app only lets in browsers you approved. Ungated apps are open to anyone with the link.'));
    const list = el('div', 'host-list');
    for(const a of d.apps){
      const row = el('div', 'host');
      const id = 'app-' + a.host.replace(/[^a-z0-9]/gi, '-');
      const n = el('span', 'host-name', a.host); n.id = id;
      row.append(n);
      if(!a.protected) row.append(P.btn('', 'p-btn p-btn--quiet p-btn--sm p-btn--icon', async () => {
        const ok = await P.confirm({title:'Forget ' + a.host + '?', text:'It drops off this list. It isn’t gated now, so nothing else changes.', confirm:'Forget'});
        if(ok) appAction(a.host, 'forget', 'Forgot ' + a.host + '.');
      }, {icon:'trash', write:true, aria:'Forget ' + a.host}));
      const sw = P.switchBtn(a.protected, id, async (on, s) => {
        s.disabled = true;
        await appAction(a.host, on ? 'protect' : 'unprotect', a.host + (on ? ' is gated now.' : ' is open to anyone now.'));
        s.disabled = false;
      });
      sw.setAttribute('aria-label', 'Gate ' + a.host);
      sw.dataset.write = '';
      row.append(sw);
      list.append(row);
      const mine = paths.filter((p) => p.host === a.host);
      if(mine.length) list.append(pathList(mine));
    }
    if(!d.apps.length) list.append(el('p', 'small', 'No apps known yet.'));
    c.append(list);
    box.append(c);
    box.append(el('p', 'small', 'Changing a gate needs an unlock.'));

    // Public paths: a few URLs on a gated app that anyone may open.
    const sec = P.section('Public paths', {action: gated.length ? P.btn('Open a path', 'p-btn p-btn--ghost p-btn--sm', () => publicSheet(gated), {icon:'plus', write:true}) : null});
    const live = paths.filter((p) => p.active).length;
    sec.append(el('p', 'small', paths.length
      ? P.fmt.plural(live, 'path') + ' open to anyone, no sign-in. Opening one (or switching it back on) needs an unlock; switching off doesn’t.'
      : 'Share links or a webhook on a gated app: open just that path to anyone, the rest stays gated.'));
    const orphans = paths.filter((p) => !d.apps.some((a) => a.host === p.host));
    if(orphans.length){ const l = el('div', 'host-list'); l.append(pathList(orphans, true)); const oc = el('div', 'card'); oc.append(l); sec.append(oc); }
    box.append(sec);
  }
  function pathRow(p, withHost){
    const row = el('div', 'pp' + (p.active ? '' : ' pp--off'));
    const id = 'pp-' + p.id;
    const main = el('div', 'pp-main');
    const top = el('div', 'pp-top');
    const name = el('span', 'pp-path', (withHost ? p.host : '') + p.path); name.id = id;
    top.append(name);
    top.append(P.badge(p.kind === 'prefix' ? 'and below' : 'exact', p.kind === 'prefix' ? 'accent' : ''));
    if(p.enabled && !p.active) top.append(P.badge(p.inactive || 'inactive', 'warn'));
    const meta = el('div', 'item-meta');
    meta.append(el('span', '', p.app));
    if(p.why) meta.append(el('span', 'pp-why', p.why));
    if(p.created_at) meta.append(P.ago(p.created_at, 'since '));
    main.append(top, meta);
    const sw = P.switchBtn(p.enabled, id, async (on, s) => {
      s.disabled = true;
      try{
        await P.post('/api/people/public-paths/' + enc(p.id) + (on ? '/on' : '/off'), {},
          {why:'Switching a public path on lets anyone open it without signing in.'});
        say(on ? p.host + p.path + ' is public again.' : p.host + p.path + ' is behind the gate again.');
      }catch(err){ P.fail(err); }
      s.disabled = false;
      P.store.people.load().catch(() => {});
    });
    sw.setAttribute('aria-label', 'Public: ' + p.host + p.path);
    sw.dataset.write = '';
    const rm = P.btn('', 'p-btn p-btn--quiet p-btn--sm p-btn--icon', async () => {
      const ok = await P.confirm({title:'Remove ' + p.path + '?', text:'It goes back behind the gate and drops off this list. Opening it again needs an unlock.', confirm:'Remove', danger:true});
      if(!ok) return;
      try{ await P.post('/api/people/public-paths/' + enc(p.id) + '/remove', {}); say('Removed ' + p.path + '.'); }
      catch(err){ P.fail(err); }
      P.store.people.load().catch(() => {});
    }, {icon:'trash', write:true, aria:'Remove ' + p.host + p.path});
    row.append(main, rm, sw);
    return row;
  }
  function pathList(paths, withHost){
    const box = el('div', 'pp-list');
    paths.slice().sort((x, y) => x.path < y.path ? -1 : x.path > y.path ? 1 : 0).forEach((p) => box.append(pathRow(p, withHost)));
    return box;
  }
  // The same rules porch-auth enforces, so most mistakes show before the unlock.
  function pathProblem(path){
    if(!path) return 'Enter a path.';
    if(path[0] !== '/') return 'A path starts with /.';
    if(path === '/') return 'Not the whole site: pick a path such as /s/.';
    if(path.length > 128) return 'At most 128 characters.';
    if(/\.\.|\/\/|[*?#%]/.test(path)) return 'No .., //, *, ?, # or %.';
    if(!/^[A-Za-z0-9._~\/-]+$/.test(path)) return 'Letters, digits and . _ ~ / - only.';
    if(/^\/__porch/i.test(path)) return '/__porch… belongs to Porch.';
    return null;
  }
  function publicSheet(gated, host){
    const body = el('div', 'sheet-body');
    const sel = el('select', 'p-select');
    for(const a of gated){ const o = el('option', '', a.host); o.value = a.host; sel.append(o); }
    if(host) sel.value = host;
    body.append(P.field('App', sel, 'Only gated apps: anything else is open already.'));
    const path = P.input('text', {maxLength:128, placeholder:'/s/', autocomplete:'off', spell:false, mono:true});
    const hint = el('div', 'p-help');
    const pf = P.field('Path', path); pf.append(hint);
    body.append(pf);
    const app = P.input('text', {maxLength:40, placeholder:'e.g. promo-studio', autocomplete:'off', spell:false});
    body.append(P.field('Who needs it', app, 'The app or person that asked: 1 to 40 characters.'));
    const why = P.input('text', {maxLength:120, placeholder:'e.g. share links', autocomplete:'off'});
    body.append(P.field('Why', why, 'Optional; shown next to it here.'));
    const preview = el('div', 'p-notice p-notice--warn pp-preview');
    body.append(preview);
    const sync = () => {
      const v = path.value.trim();
      const bad = v ? pathProblem(v) : null;
      hint.textContent = bad || (!v ? 'End it in / to open everything under it; anything else opens exactly that path.'
        : v.endsWith('/') ? 'Everything under ' + v + ' (not ' + v.slice(0, -1) + ' itself).' : 'Exactly ' + v + ', nothing below it.');
      hint.classList.toggle('pp-bad', !!bad);
      preview.textContent = 'Anyone with the link can open https://' + sel.value + (v && !bad ? v + (v.endsWith('/') ? '…' : '') : '/…') + ' without signing in. They’re anonymous to the app, even you.';
    };
    path.addEventListener('input', sync); sel.addEventListener('change', sync);
    sync();
    P.sheet.open({kicker:'Public paths', title:'Open a path', body, focus: path,
      text:'The rest of the app stays gated. Opening needs an unlock.',
      actions:[{label:'Open it', write:true, busy:'Opening…', run: async () => {
        const v = path.value.trim();
        const bad = pathProblem(v);
        if(bad) throw new Error(bad);
        const who = app.value.trim();
        if(!who) throw new Error('Say who needs it (1 to 40 characters).');
        const res = await P.post('/api/people/public-paths', {host: sel.value, path: v, app: who, why: why.value.trim()},
          {why:'Opening a path lets anyone in without signing in.'});
        say((res.entry ? res.entry.host + res.entry.path : v) + ' is public now.');
        if(res.haproxy && res.haproxy !== 'ok' && res.haproxy !== 'skipped') say('HAProxy didn’t take it live yet: ' + res.haproxy, 'warn');
        P.store.people.load().catch(() => {});
      }}, {label:'Cancel', cls:'p-btn p-btn--quiet p-btn--lg'}]});
  }
  P.publicSheet = publicSheet;
  async function appAction(host, action, done){
    try{
      await P.post('/api/people/apps', {host, action}, {why:'Changing which apps are gated changes who can get in.'});
      say(done);
      P.store.people.load().catch(() => {});
    }catch(err){ P.fail(err); P.store.people.load().catch(() => {}); }
  }

  /* ---- device detail ---- */
  function deviceDetail(pane, id){
    let painted = false;
    const draw = (d) => {
      const dev = d.devices.find((x) => String(x.id) === String(id));
      // Keep the form steady while the user edits it.
      if(painted && dev && P.typingIn(pane)) return;
      painted = true;
      pane.replaceChildren();
      if(!dev){
        pane.append(P.paneHead('Device', {kicker:'People'}), P.empty('Not found', 'It may have expired or been removed.', P.link('#/people/devices', 'p-btn p-btn--sm', 'All devices'), 'users'));
        return;
      }
      const browser = dev.type === 'browser';
      const sub = [P.badge(browser ? 'browser' : 'machine')];
      if(dev.this) sub.push(P.badge('this browser', 'self'));
      if(dev.revoked) sub.push(P.badge('revoked', 'danger'));
      pane.append(P.paneHead(dev.name || 'Unnamed', {kicker:'Device', sub}));
      // rename
      if(!dev.revoked){
        const can = !P.app || !P.app.auth || P.app.auth.can_rename !== false;
        if(can){
          const c = el('div', 'card');
          const r = el('div', 'rename');
          const inp = P.input('text', {maxLength:64, value: dev.name || '', autocomplete:'off'});
          inp.setAttribute('aria-label', 'Name');
          r.append(inp, P.btn('Rename', 'p-btn p-btn--ghost', async (e, b) => {
            const v = inp.value.trim();
            if(!v || v.length > 64){ say('A name is 1 to 64 characters.', 'warn'); return; }
            b.disabled = true;
            try{ await P.post('/api/people/devices/' + enc(dev.id) + '/rename', {name:v}); say('Renamed.'); painted = false; P.store.people.load().catch(() => {}); }
            catch(err){ P.fail(err); }
            b.disabled = false;
          }, {write:true}));
          c.append(el('div', 'p-label', 'Name'), r);
          pane.append(c);
        }
      }
      // facts
      const facts = el('div', 'card');
      const dl = el('dl', 'kv');
      const kv = (k, v) => { dl.append(el('dt', '', k)); const dd = el('dd'); dd.append(typeof v === 'string' ? document.createTextNode(v) : v); dl.append(dd); };
      kv('Kind', browser ? 'browser' : 'machine (frpc)');
      if(browser) kv('Role', dev.role || 'guest');
      kv('Paired', fmt.when(dev.created_at));
      kv('Last seen', dev.last_seen ? fmt.ago(dev.last_seen) : 'never');
      if(dev.expires_at) kv('Expires', P.countdown(dev.expires_at));
      if(dev.pass) kv('Guest pass', (dev.pass.apps || []).join(', ') + (dev.pass.expires_at ? ' · ends ' + fmt.when(dev.pass.expires_at) : ''));
      if(dev.invite_id){ const a = P.link('#/people/guests/' + enc(dev.invite_id), '', 'from an invite'); kv('Joined', a); }
      const runs = dev.run_ids || dev.run_id_history;
      if(Array.isArray(runs) && runs.length) kv('Recent runs', runs.slice(-3).join(', '));
      kv('Id', dev.id);
      facts.append(dl);
      pane.append(facts);
      if(dev.revoked) return;
      // role / tunnel admin
      if(browser){
        const c = el('div', 'card');
        const h = el('div', 'card-head'); const t = el('div', 'card-title'); t.append(icon('shield'), document.createTextNode('Role')); h.append(t);
        c.append(h, el('div', 'card-sub', 'An admin browser is you: it can open every app and this pocket. A guest only opens its apps.'));
        const ch = P.chips([['guest', 'Guest'], ['admin', 'Admin']], dev.role === 'admin' ? 'admin' : 'guest', async (v) => {
          if(v === (dev.role === 'admin' ? 'admin' : 'guest')) return;
          if(v === 'admin'){
            const ok = await P.confirm({title:'Make ' + (dev.name || 'it') + ' an admin?', text:'It gets owner-level reach to every app and this pocket.', confirm:'Make admin', danger:true});
            if(!ok){ ch.set(dev.role === 'admin' ? 'admin' : 'guest'); return; }
          }
          try{ await P.post('/api/people/devices/' + enc(dev.id) + '/role', {role:v}, {why:'Changing a role changes what it can open.'}); say('Role changed.'); }
          catch(err){ P.fail(err); }
          painted = false; P.store.people.load().catch(() => {});
        }, 'Role');
        c.append(ch.node);
        pane.append(c);
        pane.append(appsCard(dev, () => { painted = false; }));
      }else{
        const c = el('div', 'card');
        const row = el('div', 'notif-row');
        const txt = el('div'); const lb = el('b', '', 'Tunnel admin'); lb.id = 'devAdmin';
        txt.append(lb, el('span', 'small', 'Raw TCP/UDP, custom domains and reserved names. Changing it needs an unlock.'));
        const sw = P.switchBtn(!!dev.tunnel_admin, 'devAdmin', async (on, s) => {
          s.disabled = true;
          try{ await P.post('/api/people/devices/' + enc(dev.id) + '/role', {role: on ? 'admin' : 'guest'}, {why:'Tunnel admin lets a machine open any kind of tunnel.'});
               s.setAttribute('aria-checked', String(on)); say(on ? 'Tunnel admin on.' : 'Tunnel admin off.'); }
          catch(err){ P.fail(err); }
          s.disabled = false; painted = false; P.store.people.load().catch(() => {});
        });
        sw.dataset.write = '';
        row.append(txt, sw);
        c.append(row);
        pane.append(c);
      }
      // revoke
      const c = el('div', 'card card--danger');
      const z = el('div', 'danger-zone');
      const txt = el('div', 'grow');
      txt.append(el('div', 'card-title', 'Revoke'), el('div', 'card-sub', dev.this ? 'This is the browser you’re using: you’ll be signed out here at once.' :
        browser ? 'It’s signed out everywhere at once.' : 'Its tunnels are cut at their next heartbeat (within 90s).'));
      z.append(txt, P.btn('Revoke', 'p-btn p-btn--danger', async (e, b) => {
        const ok = await P.confirm({title:'Revoke ' + (dev.name || 'this device') + '?', danger:true, confirm:'Revoke',
          text: dev.this ? 'This signs you out of this browser. You’ll need another admin device to get back in.' : 'This can’t be undone; it would have to pair again.',
          typed: dev.this ? 'revoke' : null});
        if(!ok) return;
        b.disabled = true;
        try{
          await P.post('/api/people/devices/' + enc(dev.id) + '/revoke', dev.this ? {confirm_self:true} : {}, {why:'Revoking cuts a device off.'});
          say('Revoked.');
          P.store.people.load().catch(() => {});
          P.go('#/people/devices');
        }catch(err){ b.disabled = false; P.fail(err); }
      }, {write:true}));
      c.append(z);
      pane.append(c);
    };
    return P.bind(pane, P.store.people, draw, {skeleton: () => P.skeleton(2, true)});
  }
  function hostPicker(hosts, chosen, o){
    o = o || {};
    const box = el('div', 'host-list');
    for(const h of hosts){
      const lab = el('label', 'check');
      const cb = el('input'); cb.type = 'checkbox'; cb.checked = chosen.has(h.host);
      cb.addEventListener('change', () => { if(cb.checked) chosen.add(h.host); else chosen.delete(h.host); if(o.onChange) o.onChange(); });
      lab.append(cb, el('span', 'check-host', h.host));
      if(h.protected) lab.append(P.badge('gated'));
      box.append(lab);
    }
    if(!hosts.length) box.append(el('p', 'small', 'No apps known yet.'));
    return box;
  }
  function appsCard(dev, dirty){
    const c = el('div', 'card');
    const h = el('div', 'card-head'); const t = el('div', 'card-title'); t.append(icon('globe'), document.createTextNode('Apps it can open')); h.append(t);
    c.append(h);
    const apps = dev.apps || [];
    const all = apps.includes('*');
    const chosen = new Set(apps.filter((x) => x !== '*'));
    let allOn = all;
    const hosts = (P.store.people.data && P.store.people.data.apps) || [];
    const picker = hostPicker(hosts, chosen);
    const allRow = el('div', 'notif-row');
    const at = el('div'); const al = el('b', '', 'All apps'); al.id = 'devAll';
    at.append(al, el('span', 'small', 'Every gated app, including ones added later.'));
    const sync = () => picker.querySelectorAll('input').forEach((x) => { x.disabled = allOn; });
    allRow.append(at, P.switchBtn(allOn, 'devAll', (on, s) => { allOn = on; s.setAttribute('aria-checked', String(on)); sync(); }));
    sync();
    c.append(allRow, picker);
    const acts = el('div', 'actions');
    acts.append(P.btn('Save apps', 'p-btn p-btn--ghost', async (e, b) => {
      const body = {apps: allOn ? ['*'] : Array.from(chosen)};
      if(allOn && !(dev.apps || []).includes('*')){
        const ok = await P.confirm({title:'Give it every app?', danger:true, confirm:'Yes, all apps',
          text:'It can open every gated app on this box, including ones you add later.'});
        if(!ok) return;
        body.confirm_all = true;
      }
      b.disabled = true;
      try{ await P.post('/api/people/devices/' + enc(dev.id) + '/apps', body, {why:'Changing its apps changes what it can open.'}); say('Apps saved.'); }
      catch(err){ P.fail(err); }
      b.disabled = false; dirty(); P.store.people.load().catch(() => {});
    }, {write:true}));
    c.append(acts, el('p', 'small', 'Saving needs an unlock.'));
    return c;
  }

  /* ---- invites ---- */
  function inviteDetail(pane, id){
    const draw = (d) => {
      const i = d.invites.find((x) => String(x.id) === String(id));
      pane.replaceChildren();
      if(!i){
        pane.append(P.paneHead('Invite', {kicker:'Guests'}), P.empty('Not found', 'Finished invites drop off after 7 days.', P.link('#/people/guests', 'p-btn p-btn--sm', 'All guests'), 'ticket'));
        return;
      }
      pane.append(P.paneHead(i.note || (i.standing ? 'Guest pass' : 'Invite'), {kicker: i.standing ? 'Guest pass' : 'Invite',
        sub:[P.badge(i.status, INV_TONE[i.status]), P.ago(i.created_at, 'made ')]}));
      const facts = el('div', 'card');
      const dl = el('dl', 'kv');
      const kv = (k, v) => { dl.append(el('dt', '', k)); const dd = el('dd'); dd.append(typeof v === 'string' ? document.createTextNode(v) : v); dl.append(dd); };
      kv('Apps', (i.apps || []).join(', ') || '—');
      if(i.landing) kv('Lands on', i.landing);
      kv(i.standing ? 'Live passes' : 'Used', i.standing ? (i.live || 0) + ' of ' + i.max_uses : (i.uses || 0) + ' of ' + i.max_uses);
      if(i.standing) kv('Ever used', String(i.uses || 0));
      kv('Link ends', i.expires_at ? (i.status === 'active' || i.status === 'full' ? P.countdown(i.expires_at) : fmt.when(i.expires_at)) : 'never');
      kv('Each browser lasts', i.device_ttl_minutes ? fmt.left(i.device_ttl_minutes * 60) : 'for good');
      facts.append(dl);
      facts.append(el('p', 'small', 'The link itself was shown once, when it was made. Make a new invite to get another.'));
      pane.append(facts);
      const devs = i.devices || [];
      const ds = P.section('Browsers it let in · ' + devs.length);
      if(devs.length){
        const items = el('div', 'items');
        devs.forEach((x) => {
          const a = P.link('#/people/devices/' + enc(x.id), 'item');
          const m = el('div', 'item-main'); m.append(el('div', 'item-name item-name--ui', x.name || 'Unnamed'));
          a.append(m, icon('chev', 'item-chev'));
          items.append(a);
        });
        ds.append(items);
      }else ds.append(el('p', 'small', 'Nobody has used it yet.'));
      pane.append(ds);
      if(i.status === 'active' || i.status === 'full'){
        const c = el('div', 'card card--danger');
        const z = el('div', 'danger-zone');
        const txt = el('div', 'grow');
        txt.append(el('div', 'card-title', 'Revoke the link'), el('div', 'card-sub', 'Nobody new can use it.'));
        z.append(txt, P.btn('Revoke', 'p-btn p-btn--danger', () => revokeInvite(i), {write:true}));
        c.append(z);
        pane.append(c);
      }
    };
    return P.bind(pane, P.store.people, draw, {skeleton: () => P.skeleton(2, true)});
  }
  async function revokeInvite(i){
    const n = (i.devices || []).length;
    const detail = el('div', 'sheet-body');
    let cb = null;
    if(n){
      const lab = el('label', 'toggle');
      cb = el('input'); cb.type = 'checkbox';
      const t = el('span'); t.append(el('b', '', 'Also cut off its ' + P.fmt.plural(n, 'browser')), el('span', 'p-help', 'They’re signed out at once. This needs an unlock.'));
      lab.append(cb, t);
      detail.append(lab);
    }
    let cut = false;
    const ok = await new Promise((resolve) => {
      let ans = false;
      P.sheet.open({kicker:'Revoke', title:'Revoke ' + (i.note || 'this invite') + '?', text:'Nobody new can use the link.', body: n ? detail : null,
        actions:[{label:'Revoke', cls:'p-btn p-btn--lg p-btn--danger', write:true, run: () => { ans = true; cut = !!(cb && cb.checked); }},
                 {label:'Cancel', cls:'p-btn p-btn--quiet p-btn--lg'}],
        onClose: () => resolve(ans)});
    });
    if(!ok) return;
    try{
      await P.post('/api/people/invites/' + enc(i.id) + '/revoke', {revoke_devices: cut}, {why:'Cutting off its browsers needs an unlock.'});
      say(cut ? 'Revoked, and its browsers are out.' : 'Revoked.');
      P.store.people.load().catch(() => {});
    }catch(err){ P.fail(err); }
  }
  function inviteSheet(standing){
    const people = P.store.people.data || {apps:[]};
    const hosts = (people.apps || []).filter((h) => h.host !== '*');
    const chosen = new Set();
    const body = el('div', 'sheet-body');
    const note = P.input('text', {maxLength:80, placeholder: standing ? 'e.g. Party guests' : 'e.g. Sam', autocomplete:'off'});
    body.append(P.field(standing ? 'What it’s for' : 'Who it’s for', note, 'Only you see this.'));
    const modeF = el('div', 'p-field');
    modeF.append(el('div', 'p-label', 'Kind'));
    let isStanding = standing;
    const mode = P.chips([['once', 'One-time invite'], ['standing', 'Guest pass']], standing ? 'standing' : 'once', (v) => { isStanding = v === 'standing'; sync(); }, 'Kind');
    modeF.append(mode.node);
    const modeHelp = el('div', 'p-help');
    modeF.append(modeHelp);
    body.append(modeF);
    const appsF = el('div', 'p-field');
    appsF.append(el('div', 'p-label', 'Apps it opens'));
    const landing = el('select', 'p-select');
    const fillLanding = () => {
      const cur = landing.value;
      landing.replaceChildren(el('option', '', 'The first app'));
      landing.firstChild.value = '';
      for(const h of chosen){ const o = el('option', '', h); o.value = h; landing.append(o); }
      landing.value = chosen.has(cur) ? cur : '';
    };
    appsF.append(hostPicker(hosts, chosen, {onChange: fillLanding}));
    body.append(appsF);
    fillLanding();
    landing.id = 'invLanding';
    body.append(P.field('Lands on', landing));
    let expH = standing ? null : 24, ttl = standing ? 1440 : null;
    const expF = el('div', 'p-field'); expF.append(el('div', 'p-label', 'Link works for'));
    const expBox = el('div'); expF.append(expBox);
    const ttlF = el('div', 'p-field'); ttlF.append(el('div', 'p-label', 'Each browser it lets in lasts'));
    const ttlBox = el('div'); ttlF.append(ttlBox);
    const maxIn = P.input('number', {min:1, max:500, inputMode:'numeric', value: standing ? '20' : '1'});
    const maxF = P.field('', maxIn); maxF.classList.add('max-field');
    body.append(expF, maxF, ttlF);
    function sync(){
      modeHelp.textContent = isStanding ? 'One link that stays up. Every visitor gets their own browser pass that ends on its own.'
                                        : 'A link for one person (or a few). Each use mints a guest browser.';
      const exps = [[1, '1 hour'], [24, '24 hours'], [168, '7 days'], [720, '30 days']].concat(isStanding ? [[null, 'Never']] : []);
      if(!isStanding && expH === null) expH = 24;
      const ec = P.chips(exps, expH, (v) => { expH = v; }, 'Link works for');
      expBox.replaceChildren(ec.node);
      const ttls = [[60, '1 hour'], [1440, '24 hours'], [10080, '7 days'], [43200, '30 days']].concat(isStanding ? [] : [[null, 'For good']]);
      if(isStanding && ttl === null) ttl = 1440;
      const tc = P.chips(ttls, ttl, (v) => { ttl = v; }, 'Each browser lasts');
      ttlBox.replaceChildren(tc.node);
      maxF.querySelector('.p-label').textContent = isStanding ? 'Most browsers in at once' : 'How many times it can be used';
      if(isStanding && maxIn.value === '1') maxIn.value = '20';
      if(!isStanding && maxIn.value === '20') maxIn.value = '1';
    }
    sync();
    P.sheet.open({kicker: 'Guests', title: standing ? 'New guest pass' : 'New invite', body, focus: note,
      text: 'The link is shown once. Making it needs an unlock.',
      actions:[{label:'Make the link', write:true, busy:'Making…', run: async () => {
        const apps = Array.from(chosen);
        if(!apps.length) throw new Error('Pick at least one app.');
        const n = Number(maxIn.value);
        if(!Number.isInteger(n) || n < 1 || n > 500) throw new Error('Use a whole number from 1 to 500.');
        const req = {note: note.value.trim(), apps, standing: isStanding, expires_hours: expH, max_uses: n, device_ttl_minutes: ttl};
        if(landing.value) req.landing = landing.value;
        const res = await P.post('/api/people/invites', req, {why:'An invite lets new people in.'});
        P.store.people.load().catch(() => {});
        setTimeout(() => inviteReady(res, req), 60);
      }}, {label:'Cancel', cls:'p-btn p-btn--quiet p-btn--lg'}]});
  }
  function inviteReady(res, req){
    const url = res.url;
    const body = el('div', 'sheet-body');
    const once = el('div', 'once'); once.append(icon('info'), el('span', '', 'Shown once. Copy or share it now: Porch keeps no copy.'));
    body.append(once);
    const q = el('div', 'qr-box'); q.append(P.qr(url, true)); body.append(q);
    body.append(P.urlBox('Invite link', url, {accent:true, qr:false, hosts:[P.app && P.app.auth_host, res.invite && res.invite.host]}));
    const bits = [req.standing ? 'guest pass, up to ' + req.max_uses + ' at once' : 'works ' + P.fmt.plural(req.max_uses, 'time'),
                  req.expires_hours ? 'link ends in ' + fmt.left(req.expires_hours * 3600) : 'no end date'];
    body.append(el('p', 'small', bits.join(' · ')));
    P.sheet.open({kicker: req.standing ? 'Guest pass ready' : 'Invite ready', title: req.note || 'Your link', body,
      actions:[{label:'Done', cls:'p-btn p-btn--lg'}]});
  }
  P.inviteSheet = inviteSheet;

  P.sectionDef('people', {
    label: 'People',
    resolve(parts){
      const seg = ['devices', 'guests', 'apps'].includes(parts[0]) ? parts[0] : 'devices';
      const base = {key: seg, title:'People', list: (p) => listPane(p, seg),
                    empty: (p) => P.detailEmpty(p, seg === 'apps' ? 'Gates' : 'Pick someone',
                      seg === 'guests' ? 'Invites and guest passes: who used them and what they open.' :
                      seg === 'apps' ? 'Switch a gate on and only browsers you approved get in. A public path opens one URL under it to anyone.' :
                      'Rename it, change what it opens, or revoke it.', seg === 'guests' ? 'ticket' : seg === 'apps' ? 'globe' : 'users')};
      if(seg === 'devices' && parts[1])
        return Object.assign(base, {title:'Device', back:'#/people/devices', backLabel:'People', detail: (p) => deviceDetail(p, parts[1])});
      if(seg === 'guests' && parts[1])
        return Object.assign(base, {title:'Invite', back:'#/people/guests', backLabel:'Guests', detail: (p) => inviteDetail(p, parts[1])});
      return base;
    },
  });
})();

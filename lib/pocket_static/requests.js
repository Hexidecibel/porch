/* Requests (#/requests): reopen asks, people asking for access at a gated
 * app's gate page, machines and browsers asking to pair, and guest activity
 * (invite links being used). Approving a pairing or letting someone in
 * needs an unlock; rejecting, denying and deciding a reopen ask do not. */
'use strict';
(function(){
  const P = window.Porch;
  const {icon, fmt} = P;
  const enc = encodeURIComponent;
  const CODE_RE = /^[A-Z]{4}-[0-9]{4}$/;
  let filter = 'all';

  function pairRow(p){
    const a = P.link('#/requests/pairing/' + enc(p.code), 'item');
    const av = el('span', 'avatar'); av.dataset.kind = p.kind === 'web' ? '' : 'machine';
    av.append(icon(p.kind === 'web' ? 'globe' : 'server'));
    const main = el('div', 'item-main');
    const top = el('div', 'item-top');
    top.append(el('span', 'item-name item-name--ui', p.device_name || 'Unnamed device'));
    const meta = el('div', 'item-meta');
    meta.append(el('span', 'mono', p.code), el('span', '', p.kind === 'web' ? 'browser' : 'machine'), P.ago(p.created_at, 'asked '));
    const cd = P.countdown(p.expires_at); cd.dataset.done = 'expired';
    const side = el('div', 'item-side'); side.append(P.badge('needs you', 'accent'), cd);
    main.append(top, meta);
    a.append(av, main, side);
    return a;
  }
  function askRow(r){
    const a = P.link('#/requests/reopen/' + enc(r.id), 'item');
    const av = el('span', 'avatar'); av.append(icon('door'));
    const main = el('div', 'item-main');
    const top = el('div', 'item-top');
    top.append(el('span', 'item-name', r.name), P.typeChip(r.type));
    const meta = el('div', 'item-meta');
    meta.append(el('span', '', r.note ? '“' + r.note + '”' : 'no name given'));
    if(r.waiting > 1) meta.append(el('span', '', r.waiting + ' waiting'));
    meta.append(P.ago(r.created, 'asked '));
    main.append(top, meta);
    const side = el('div', 'item-side');
    const pending = r.state === 'pending' && (!r.until || r.until > P.now());
    side.append(pending ? P.badge('reopen?', 'accent') :
      P.badge(r.state === 'allowed' ? 'allowed' : r.state === 'denied' ? 'denied' : (r.state || 'expired'), r.state === 'allowed' ? 'ok' : ''));
    a.append(av, main, side);
    return a;
  }
  const ACCESS_WHO = {device: 'has a pass', expired: 'pass ran out', stranger: 'no pass'};
  function accessWho(r){
    return r.kind === 'device' ? (r.device_name || 'a browser') + ' · ' + ACCESS_WHO.device
      : ACCESS_WHO[r.kind] || ACCESS_WHO.stranger;
  }
  function accessRow(r){
    const a = P.link('#/requests/access/' + enc(r.id), 'item');
    const av = el('span', 'avatar'); av.append(icon(r.kind === 'device' ? 'pass' : 'key'));
    const main = el('div', 'item-main');
    const top = el('div', 'item-top');
    top.append(el('span', 'item-name', r.host));
    const meta = el('div', 'item-meta');
    meta.append(el('span', '', r.note ? '“' + r.note + '”' : 'no name given'), el('span', '', accessWho(r)));
    if(r.waiting > 1) meta.append(el('span', '', r.waiting + ' asks'));
    meta.append(P.ago(r.created, 'asked '));
    main.append(top, meta);
    const side = el('div', 'item-side');
    const pending = r.state === 'pending' && (!r.until || r.until > P.now());
    side.append(pending ? P.badge('let in?', 'accent') :
      P.badge(r.state === 'approved' ? 'let in' : r.state === 'denied' ? 'denied' : (r.state || 'expired'), r.state === 'approved' ? 'ok' : ''));
    a.append(av, main, side);
    return a;
  }
  function decideAccess(r, decision, ttl, btn){
    btn.disabled = true;
    const body = decision === 'allow' && ttl ? {device_ttl_minutes: ttl} : {};
    return P.post('/api/requests/access/' + enc(r.id) + '/' + decision, body,
                  decision === 'allow' ? {why: 'Letting someone in widens who can open ' + r.host + '.'} : undefined)
      .then(() => {
        say(decision === 'deny' ? 'Told them not now.' : r.kind === 'device'
          ? r.host + ' is on ' + (r.device_name || 'their') + '’s pass now.'
          : 'Sent them a one-time pass for ' + r.host + '.');
        P.store.requests.soon(); P.store.people.soon();
        return true;
      })
      .catch((err) => { btn.disabled = false; P.fail(err); return false; });
  }
  P.decideAccess = decideAccess;
  P.accessCard = function(r){
    const c = el('div', 'ask');
    const top = el('div', 'ask-top');
    const k = el('span', 'ask-kind'); k.append(icon('key'), document.createTextNode('Asked for access'));
    top.append(k);
    const nm = el('div', 'ask-top');
    const a = el('a', 'ask-name', r.host); a.href = '#/requests/access/' + enc(r.id);
    nm.append(a);
    c.append(top, nm, el('p', 'ask-note', r.note ? '“' + r.note + '”' : 'No name given.'));
    c.append(el('div', 'ask-meta', [accessWho(r), 'asked ' + fmt.ago(r.created)].join(' · ')));
    const acts = el('div', 'ask-acts ask-acts--2');
    acts.append(P.link('#/requests/access/' + enc(r.id), 'p-btn', 'Review'));
    acts.append(P.btn('Deny', 'p-btn p-btn--quiet', (e, b) => decideAccess(r, 'deny', null, b),
      {write:true, aria:'Deny access to ' + r.host}));
    c.append(acts);
    return c;
  };

  function acceptRow(x){
    const a = P.link(x.invite_id ? '#/people/guests/' + enc(x.invite_id) : '#/people/guests', 'item');
    const av = el('span', 'avatar'); av.append(icon('ticket'));
    const main = el('div', 'item-main');
    main.append(el('div', 'item-name item-name--ui', (x.note ? x.note + '’s link' : 'An invite link') + ' let in ' + (x.device_name || 'a browser')));
    const meta = el('div', 'item-meta'); meta.append(P.ago(x.at, 'joined '));
    main.append(meta);
    a.append(av, main, icon('chev', 'item-chev'));
    return a;
  }

  function listPane(pane){
    pane.append(P.paneHead('Requests'));
    const chips = el('div', 'filters');
    chips.setAttribute('role', 'group'); chips.setAttribute('aria-label', 'Show');
    const box = el('div', 'sec');
    pane.append(chips, box);
    const draw = (d) => {
      const asks = P.pendingAsks(d.reopen);
      const decided = (d.reopen || []).filter((r) => !asks.includes(r)).sort((a, b) => (b.decided || b.created) - (a.decided || a.created)).slice(0, 10);
      const pairs = d.pairings || [], acc = d.accepts || [];
      const access = P.pendingAccess(d.access);
      const accessDone = (d.access || []).filter((r) => !access.includes(r)).sort((a, b) => (b.decided || b.created) - (a.decided || a.created)).slice(0, 10);
      chips.replaceChildren();
      for(const [k, label, n] of [['all', 'All', asks.length + pairs.length + access.length], ['access', 'Access', access.length], ['reopen', 'Reopen', asks.length], ['machines', 'Machines', pairs.length], ['guests', 'Guest activity', acc.length]]){
        const b = el('button', 'fchip', label);
        b.type = 'button';
        if(n) b.append(el('span', 'seg-n', String(n)));
        b.setAttribute('aria-pressed', String(filter === k));
        b.addEventListener('click', () => { filter = k; draw(d); });
        chips.append(b);
      }
      box.replaceChildren();
      const group = (title, rows) => {
        if(!rows.length) return;
        const g = el('div', 'group');
        g.append(el('div', 'group-label', title));
        const items = el('div', 'items'); items.append(...rows);
        g.append(items);
        box.append(g);
      };
      const showR = filter === 'all' || filter === 'reopen', showM = filter === 'all' || filter === 'machines', showG = filter === 'all' || filter === 'guests';
      const showA = filter === 'all' || filter === 'access';
      const waiting = (showA ? access.map(accessRow) : []).concat(showM ? pairs.map(pairRow) : [], showR ? asks.map(askRow) : []);
      group('Waiting on you', waiting);
      // porch-auth down: the shell's banner says so (core.js setAuth).
      group('Recently decided', (showA ? accessDone.map(accessRow) : []).concat(showR ? decided.map(askRow) : []));
      if(showG) group('Guest activity', acc.slice(0, 20).map(acceptRow));
      if(!box.childElementCount){
        box.append(P.empty(filter === 'guests' ? 'No guest activity yet' : 'Nothing waiting on you',
          filter === 'guests' ? 'When someone uses an invite link, it shows up here.' :
          filter === 'access' ? 'When someone at a private app’s door asks to be let in, it lands here.' :
          'Reopen asks, people asking for access and new machines land here, and as notifications if they’re on.', null, filter === 'guests' ? 'ticket' : 'check'));
      }
      P.markCurrent();
    };
    return P.bind(box, P.store.requests, draw);
  }

  /* ---- reopen ask ---- */
  function reopenDetail(pane, id){
    const draw = (d) => {
      pane.replaceChildren();
      const r = (d.reopen || []).find((x) => String(x.id) === String(id));
      if(!r){
        pane.append(P.paneHead('Reopen ask', {kicker:'Requests'}),
          P.empty('This ask is gone', 'It was decided, or it ran out. The door’s page tells the visitor either way.', P.link('#/requests', 'p-btn p-btn--sm', 'All requests'), 'door'));
        return;
      }
      const pending = r.state === 'pending' && (!r.until || r.until > P.now());
      pane.append(P.paneHead(r.name, {mono:true, kicker:'Asked to reopen', sub:[P.typeChip(r.type), P.ago(r.created, 'asked ')]}));
      const c = el('div', 'card card--accent');
      c.append(el('p', 'ask-note', r.note ? '“' + r.note + '”' : 'They didn’t give a name.'));
      const dl = el('dl', 'kv');
      const kv = (k, v) => { dl.append(el('dt', '', k)); const dd = el('dd'); dd.append(v); dl.append(dd); };
      kv('Closed', document.createTextNode(r.closed ? (r.reason === 'expired' ? 'expired ' : (r.reason || 'closed') + ' ') + fmt.ago(r.closed) : '—'));
      kv('Waiting', document.createTextNode(P.fmt.plural(r.waiting || 1, 'person')));
      if(r.ip) kv('From', document.createTextNode(r.ip));
      if(pending && r.until) kv('Ask expires in', P.countdown(r.until));
      if(!pending) kv('Decision', document.createTextNode(r.state || 'expired'));
      c.append(dl);
      if(Array.isArray(r.askers) && r.askers.length > 1){
        const l = el('div', 'badges');
        r.askers.slice(0, 12).forEach((x) => l.append(P.badge(x.note || x.ip || 'someone')));
        c.append(el('div', 'p-label', 'Also asking'), l);
      }
      if(pending){
        const acts = el('div', 'ask-acts');
        [['allow', '1h', 'Allow 1h', 'p-btn'], ['allow', '24h', 'Allow 24h', 'p-btn p-btn--ghost'], ['deny', '', 'Deny', 'p-btn p-btn--quiet']]
          .forEach(([dd, x, label, cls]) => acts.append(P.btn(label, cls, (e, b) => P.decideAsk(r, dd, x, b), {write:true})));
        c.append(acts);
      }
      pane.append(c);
    };
    return P.bind(pane, P.store.requests, draw, {skeleton: () => P.skeleton(1, true)});
  }

  /* ---- ask for access ---- */
  function accessDetail(pane, id){
    const draw = (d) => {
      pane.replaceChildren();
      const r = (d.access || []).find((x) => String(x.id) === String(id));
      if(!r){
        pane.append(P.paneHead('Ask for access', {kicker:'Requests'}),
          P.empty('This ask is gone', 'It was decided, or it ran out after 30 minutes. Their page tells them either way.', P.link('#/requests', 'p-btn p-btn--sm', 'All requests'), 'key'));
        return;
      }
      const pending = r.state === 'pending' && (!r.until || r.until > P.now());
      pane.append(P.paneHead(r.host, {mono:true, kicker:'Asked for access', sub:[P.badge(ACCESS_WHO[r.kind] || ACCESS_WHO.stranger), P.ago(r.created, 'asked ')]}));
      const c = el('div', 'card card--accent');
      c.append(el('p', 'ask-note', r.note ? '“' + r.note + '”' : 'They didn’t give a name.'));
      const dl = el('dl', 'kv');
      const kv = (k, v) => { dl.append(el('dt', '', k)); const dd = el('dd'); dd.append(typeof v === 'string' ? document.createTextNode(v) : v); dl.append(dd); };
      kv('Who', r.kind === 'device' ? (r.device_name || 'A browser') + ', on a pass without this app'
        : r.kind === 'expired' ? 'A browser whose pass ran out' : 'Someone without a pass');
      kv('Allow does', r.kind === 'device' ? 'Adds ' + r.host + ' to that browser’s pass. Their page goes straight in.'
        : 'Hands their page a one-time invite for ' + r.host + ' only (good for an hour). Only they see the link.');
      if(r.waiting > 1) kv('Asked', P.fmt.plural(r.waiting, 'time'));
      if(r.ip) kv('From', r.ip);
      if(pending && r.until) kv('Ask expires in', P.countdown(r.until));
      if(!pending) kv('Decision', r.state === 'approved' ? (r.how === 'device' ? 'let in (added to their pass)' : 'let in (one-time invite sent)') : (r.state || 'expired'));
      c.append(dl);
      if(pending){
        const acts = el('div', 'ask-acts');
        const go = (dd, ttl) => (e, b) => decideAccess(r, dd, ttl, b).then((ok) => { if(ok) P.go('#/requests'); });
        acts.append(P.btn(r.kind === 'device' ? 'Add to their pass' : 'Allow', 'p-btn', go('allow', null), {icon:'check', write:true}));
        if(r.kind !== 'device') acts.append(P.btn('Allow for 24h', 'p-btn p-btn--ghost', go('allow', 1440), {write:true}));
        acts.append(P.btn('Deny', 'p-btn p-btn--quiet', go('deny', null), {write:true}));
        c.append(acts);
      }
      pane.append(c);
      if(pending) pane.append(el('p', 'small', 'Letting someone in needs an unlock (Face ID or the admin password). Denying doesn’t.'));
    };
    return P.bind(pane, P.store.requests, draw, {skeleton: () => P.skeleton(1, true)});
  }

  /* ---- pairing ---- */
  function pairingDetail(pane, code){
    let adminOn = false, allApps = false;
    const chosen = new Set();
    const draw = (d) => {
      const p = (d.pairings || []).find((x) => x.code === code);
      pane.replaceChildren();
      if(!CODE_RE.test(code) || !p){
        pane.append(P.paneHead(code, {mono:true, kicker:'Pairing'}),
          P.empty(d.auth && d.auth.state === 'down' ? 'porch-auth isn’t answering' : 'This request is gone',
            d.auth && d.auth.state === 'down' ? 'Pairings can’t load until it’s back. Doors still work.' :
            'It was approved, rejected or ran out (codes last 10 minutes).', P.link('#/requests', 'p-btn p-btn--sm', 'All requests'), 'server'));
        return;
      }
      const web = p.kind === 'web';
      pane.append(P.paneHead(p.device_name || 'Unnamed device', {kicker: web ? 'A browser wants in' : 'A machine wants to pair',
        sub:[P.badge(web ? 'browser' : 'machine'), P.ago(p.created_at, 'asked ')]}));
      const c = el('div', 'card card--accent');
      c.append(el('div', 'p-label', 'Check this code matches the one on ' + (web ? 'that browser' : 'the machine’s screen')));
      c.append(el('div', 'pair-code', p.code));
      const ex = el('div', 'small'); ex.append(document.createTextNode('Expires in '), P.countdown(p.expires_at));
      c.append(ex);
      pane.append(c);
      if(!web){
        const r = el('div', 'card');
        const row = el('div', 'notif-row');
        const txt = el('div');
        const lab = el('b', '', 'Tunnel admin'); lab.id = 'pairAdmin';
        txt.append(lab, el('span', 'small', 'Lets this machine open any kind of tunnel: raw TCP/UDP, custom domains and reserved names. Leave it off unless it’s yours.'));
        row.append(txt, P.switchBtn(adminOn, 'pairAdmin', (on, s) => { adminOn = on; s.setAttribute('aria-checked', String(on)); }));
        r.append(row);
        pane.append(r);
      }else{
        const r = el('div', 'card');
        const h = el('div', 'card-head'); const t = el('div', 'card-title'); t.append(icon('globe'), document.createTextNode('Which apps can it open'));
        h.append(t); r.append(h, el('div', 'card-sub', 'It joins as a guest browser. Pick only what it needs.'));
        const hosts = el('div', 'host-list');
        const drawHosts = (people) => {
          hosts.replaceChildren();
          const list = (people && people.apps) || [];
          if(!list.length) hosts.append(el('p', 'small', 'No known apps yet.'));
          for(const a of list){
            const lab = el('label', 'check');
            const cb = el('input'); cb.type = 'checkbox'; cb.checked = chosen.has(a.host); cb.disabled = allApps;
            cb.addEventListener('change', () => { if(cb.checked) chosen.add(a.host); else chosen.delete(a.host); });
            lab.append(cb, el('span', 'check-host', a.host));
            if(a.protected) lab.append(P.badge('gated'));
            hosts.append(lab);
          }
        };
        r.append(hosts);
        const allRow = el('div', 'notif-row');
        const at = el('div'); const al = el('b', '', 'All apps'); al.id = 'pairAll';
        at.append(al, el('span', 'small', 'Owner-level reach to every gated app. Only for your own devices.'));
        allRow.append(at, P.switchBtn(allApps, 'pairAll', async (on, s) => {
          if(on){
            const ok = await P.confirm({title:'Give it every app?', danger:true, confirm:'Yes, all apps',
              text:'It can open every gated app on this box, including ones you add later. It still joins as a guest, not an admin.'});
            if(!ok) return;
          }
          allApps = on; s.setAttribute('aria-checked', String(on));
          hosts.querySelectorAll('input').forEach((x) => { x.disabled = on; });
        }));
        r.append(allRow);
        pane.append(r);
        if(P.store.people.data) drawHosts(P.store.people.data);
        else{ hosts.append(P.skeleton(2)); P.store.people.load().then(drawHosts, () => drawHosts(null)); }
      }
      const acts = el('div', 'ask-acts ask-acts--2');
      acts.append(P.btn('Approve', 'p-btn p-btn--lg', async (e, b) => {
        const body = {};
        if(web){
          if(allApps){ body.apps = ['*']; body.confirm_all = true; }
          else{
            body.apps = Array.from(chosen);
            if(!body.apps.length){ say('Pick at least one app, or turn on All apps.', 'warn'); return; }
          }
        }else body.tunnel_admin = adminOn;
        b.disabled = true;
        try{
          await P.post('/api/requests/pairings/' + enc(p.code) + '/approve', body, {why:'Approving lets a new device in.'});
          say((p.device_name || p.code) + ' is in.');
          P.store.requests.soon(); P.store.people.soon();
          P.go('#/requests');
        }catch(err){ b.disabled = false; P.fail(err); }
      }, {icon:'check', write:true}),
      P.btn('Reject', 'p-btn p-btn--ghost p-btn--lg', async (e, b) => {
        b.disabled = true;
        try{
          await P.post('/api/requests/pairings/' + enc(p.code) + '/reject');
          say('Rejected ' + p.code + '.');
          P.store.requests.soon();
          P.go('#/requests');
        }catch(err){ b.disabled = false; P.fail(err); }
      }, {write:true}));
      pane.append(acts);
      pane.append(el('p', 'small', 'Approving needs an unlock (Face ID or the admin password). Rejecting doesn’t.'));
    };
    // Redraw on data changes only when nothing in the pane is being edited.
    let painted = false;
    return P.bind(pane, P.store.requests, (d) => {
      const has = (d.pairings || []).some((x) => x.code === code);
      if(painted && has && pane.querySelector('.pair-code')) return;
      painted = true;
      draw(d);
    }, {skeleton: () => P.skeleton(2, true)});
  }

  P.sectionDef('requests', {
    label: 'Requests',
    resolve(parts){
      const base = {key:'list', title:'Requests', list: listPane,
                    empty: (p) => P.detailEmpty(p, 'Nothing selected', 'Pick a request to see who’s asking and decide.', 'bell')};
      if(parts[0] === 'pairing' && parts[1])
        return Object.assign(base, {title:'Pairing', back:'#/requests', backLabel:'Requests', detail: (p) => pairingDetail(p, parts[1])});
      if(parts[0] === 'access' && parts[1])
        return Object.assign(base, {title:'Ask for access', back:'#/requests', backLabel:'Requests', detail: (p) => accessDetail(p, parts[1])});
      if(parts[0] === 'reopen' && parts[1])
        return Object.assign(base, {title:'Reopen ask', back:'#/requests', backLabel:'Requests', detail: (p) => reopenDetail(p, parts[1])});
      return base;
    },
  });
})();

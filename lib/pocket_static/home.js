/* Home (#/home): what is waiting on you, the doors closing soonest, and the
 * share widgets (clipboard, uploads, inbox, links: ported from the old page;
 * share.js binds the make-link sheet to the same nodes). */
'use strict';
(function(){
  const P = window.Porch;
  const {icon, fmt} = P;

  /* ---- clipboard (ported) ---- */
  function asUrl(text){
    const t = text.trim();
    if(!t || /\s/.test(t) || t.length > 4096) return null;
    try{
      const u = new URL(t);
      return (u.protocol === 'https:' || u.protocol === 'http:') ? u.href : null;
    }catch(e){ return null; }
  }
  function textNode(text){
    const url = asUrl(text);
    const pre = el('pre', 'clip-text');
    if(url){
      const a = el('a', '', text.trim());
      a.href = url; a.rel = 'noopener noreferrer'; a.target = '_blank';
      pre.appendChild(a);
    }else{
      pre.textContent = text;
    }
    return pre;
  }
  let clipState = null;
  function renderClip(state){
    if(!state) return;
    clipState = state;
    current = state.current;
    const body = $('clipBody'), meta = $('clipMeta');
    meta.replaceChildren();
    if(!current){
      body.replaceChildren(el('p', 'clip-empty', 'Nothing here yet. Paste something, or share to Porch from your phone.'));
      $('copyBtn').disabled = true;
      $('linkClipBtn').disabled = true;
    }else{
      body.replaceChildren(textNode(current.text));
      meta.append(el('span', '', 'from ' + (current.source || 'somewhere')), el('span', '', '·'), P.ago(current.ts));
      $('copyBtn').disabled = false;
      if(!P.offline) $('linkClipBtn').disabled = false;
    }
    const list = $('history');
    const hist = Array.isArray(state.history) ? state.history : [];
    list.replaceChildren(...hist.map(histRow));
    $('histBox').hidden = !hist.length;
    $('histLabel').textContent = 'Earlier · ' + hist.length;
  }
  function histRow(e){
    const r = el('div', 'p-row');
    const main = el('div', 'p-row-main');
    const t = el('div', 'p-row-name hist-text', e.text.replace(/\s+/g, ' ').slice(0, 200));
    t.title = e.text.slice(0, 500);
    main.append(t, el('div', 'p-row-meta', (e.source || '') + ' · ' + fmt.ago(e.ts)));
    const acts = el('div', 'row-actions');
    acts.append(
      P.btn('Copy', 'p-btn p-btn--ghost p-btn--sm', () => copied(copyText(e.text))),
      P.btn('Link', 'p-btn p-btn--quiet p-btn--sm', () => openSheet(clipReq(e)), {aria:'Make a link for this entry', write:true}),
      P.btn('Delete', 'p-btn p-btn--quiet p-btn--sm', () => api('POST', '/api/clip/' + encodeURIComponent(e.id) + '/delete', {})
        .then(loadClip).catch(P.fail), {aria:'Delete this entry', write:true}));
    r.append(main, acts);
    return r;
  }
  function loadClip(){ return api('GET', '/api/clip').then(renderClip).catch(() => {}); }
  function sendClip(text){
    if(!text || !text.trim()){ say('Nothing to send.', 'warn'); return Promise.resolve(); }
    return api('POST', '/api/clip', {text}).then((s) => { renderClip(s); say('In your pocket.'); }).catch(P.fail);
  }
  function openPasteBox(){ $('pasteBox').hidden = false; $('pasteText').focus(); }
  $('copyBtn').addEventListener('click', () => { if(current) copied(copyText(current.text)); });
  $('linkClipBtn').addEventListener('click', () => { if(current) openSheet(clipReq(current)); });
  $('pasteBtn').addEventListener('click', () => {
    if(navigator.clipboard && navigator.clipboard.readText && window.isSecureContext){
      navigator.clipboard.readText().then((t) => { if(t && t.trim()) return sendClip(t); openPasteBox(); }, openPasteBox);
    }else openPasteBox();
  });
  $('sendBtn').addEventListener('click', () => {
    sendClip($('pasteText').value).then(() => { $('pasteText').value = ''; $('pasteBox').hidden = true; });
  });
  $('cancelBtn').addEventListener('click', () => { $('pasteBox').hidden = true; });

  /* ---- inbox (ported; five newest unless All files) ---- */
  let inboxFiles = null, inboxAll = false;
  function inboxRow(f){
    const r = el('div', 'p-row');
    const main = el('div', 'p-row-main');
    const nm = el('div', 'p-row-name', f.name); nm.title = f.name;
    main.append(nm, el('div', 'p-row-meta', humanSize(f.size) + ' · ' + fmt.ago(f.modified)));
    const acts = el('div', 'row-actions');
    const href = '/inbox/' + encodeURIComponent(f.name);
    const open = el('a', 'p-btn p-btn--quiet p-btn--sm', 'Open');
    open.href = href; open.target = '_blank'; open.rel = 'noopener';
    const dl = el('a', 'p-btn p-btn--ghost p-btn--sm', 'Download');
    dl.href = href + '?dl=1'; dl.download = ''; dl.setAttribute('aria-label', 'Download ' + f.name);
    const del = P.btn('Delete', 'p-btn p-btn--quiet p-btn--sm', null, {aria:'Delete ' + f.name, write:true});
    del.addEventListener('click', () => {
      if(del.dataset.armed !== '1'){
        del.dataset.armed = '1'; del.textContent = 'Really?'; del.className = 'p-btn p-btn--danger p-btn--sm';
        setTimeout(() => { del.dataset.armed = ''; del.textContent = 'Delete'; del.className = 'p-btn p-btn--quiet p-btn--sm'; }, 4000);
        return;
      }
      api('POST', '/api/inbox/' + encodeURIComponent(f.name) + '/delete', {}).then(loadInbox).catch(P.fail);
    });
    const lk = P.btn('Link', 'p-btn p-btn--ghost p-btn--sm', () => openSheet({kind:'inbox', id:f.name, label:f.name}),
                     {aria:'Make a link for ' + f.name, write:true});
    acts.append(lk, open, dl, del);
    r.append(main, acts);
    return r;
  }
  function renderInbox(files){
    if(!Array.isArray(files)) return;
    files.sort((a, b) => b.modified - a.modified);
    inboxFiles = files;
    const list = $('inbox');
    if(!files.length){
      list.replaceChildren(P.empty('Inbox is empty', P.ios ? 'Upload from here, or set up Share from iPhone under You.' :
                                   'Share a photo or file to Porch and it lands here.', null, 'inbox'));
      list.classList.add('is-empty');
    }else{
      list.classList.remove('is-empty');
      list.replaceChildren(...(inboxAll ? files : files.slice(0, 5)).map(inboxRow));
    }
    $('inboxLabel').textContent = files.length ? 'Inbox · ' + files.length : 'Inbox';
    const more = $('inboxAll');
    more.hidden = files.length <= 5;
    more.textContent = inboxAll ? 'Newest 5' : 'All ' + files.length + ' files';
  }
  $('inboxAll').addEventListener('click', () => { inboxAll = !inboxAll; renderInbox(inboxFiles || []); });
  function loadInbox(){
    return api('GET', '/api/inbox').then(renderInbox).catch((err) => {
      if(!inboxFiles) $('inbox').replaceChildren(P.errorBox(err, loadInbox));
    });
  }

  /* ---- uploads (PorchTus, multipart fallback; ported) ---- */
  const pw = $('progressWrap'), pf = $('progressFill'), pt = $('progressText');
  function progress(f, sent, total, i, n){
    const pct = total ? Math.round(sent/total*100) : 0;
    pf.style.width = pct + '%';
    pt.textContent = (n > 1 ? i + ' of ' + n + ' · ' : '') + f.name + ' · ' + pct + '%';
  }
  function sendMultipart(f){
    const fd = new FormData();
    fd.append('files', f, f.name);
    return fetch('/share', {method:'POST', body:fd, credentials:'same-origin', headers:{'X-Porch-Fetch':'1'}})
      .then((r) => r.json().then((j) => r.ok ? {ok:true} : {ok:false, error:j.message || ('HTTP ' + r.status)}))
      .catch(() => ({ok:false, error:'network error'}));
  }
  async function uploadAll(files){
    const list = Array.from(files);
    if(!list.length) return;
    pw.hidden = false;
    let ok = 0, err = '';
    for(let i = 0; i < list.length; i++){
      const f = list[i];
      if(CFG.maxFile && f.size > CFG.maxFile){ err = f.name + ': larger than ' + humanSize(CFG.maxFile); continue; }
      progress(f, 0, f.size, i + 1, list.length);
      let res;
      try{
        res = await PorchTus.upload(f, {endpoint:'/tus/', onProgress:(s, t) => progress(f, s, t, i + 1, list.length)});
        if(res.fallback) res = await sendMultipart(f);
      }catch(e){ res = await sendMultipart(f); }
      if(res.ok) ok++; else err = f.name + ': ' + res.error;
    }
    pw.hidden = true;
    if(err) say(err, 'error'); else say('Uploaded ' + ok + ' file' + (ok === 1 ? '' : 's') + '.');
    loadInbox();
  }
  $('fileInput').addEventListener('change', (e) => { uploadAll(e.target.files); e.target.value = ''; });
  $('photoInput').addEventListener('change', (e) => { uploadAll(e.target.files); e.target.value = ''; });

  /* ---- Make link: pick what ---- */
  $('makeLinkBtn').addEventListener('click', () => {
    const body = el('div', 'sec');
    const items = el('div', 'items');
    const pick = (req) => { P.sheet.close(); setTimeout(() => openSheet(req), 60); };
    if(current){
      const a = el('button', 'item');
      a.type = 'button';
      const m = el('div', 'item-main');
      m.append(el('div', 'item-name item-name--ui', 'The current clip'), el('div', 'item-meta', current.text.replace(/\s+/g, ' ').slice(0, 80)));
      a.append(m, icon('chev', 'item-chev'));
      a.addEventListener('click', () => pick(clipReq(current)));
      items.append(a);
    }
    for(const f of (inboxFiles || []).slice(0, 12)){
      const a = el('button', 'item');
      a.type = 'button';
      const m = el('div', 'item-main');
      m.append(el('div', 'item-name', f.name), el('div', 'item-meta', humanSize(f.size) + ' · ' + fmt.ago(f.modified)));
      a.append(m, icon('chev', 'item-chev'));
      a.addEventListener('click', () => pick({kind:'inbox', id:f.name, label:f.name}));
      items.append(a);
    }
    if(items.childElementCount) body.append(items);
    else body.append(P.empty('Nothing to link yet', 'Upload a file or paste a clip first, or send something encrypted.', null, 'link'));
    P.sheet.open({kicker:'Make a link', title:'What should it open?', body,
      text:'Each link is its own door, with its own expiry and rules.',
      actions:[{label:'Cancel', cls:'p-btn p-btn--quiet p-btn--lg'}]});
  });
  $('newDoorTile').addEventListener('click', () => P.newDoor && P.newDoor());

  /* ---- waiting on you ---- */
  function decideAsk(r, decision, expires, btn){
    btn.disabled = true;
    return api('POST', '/api/reopen/' + encodeURIComponent(r.id), expires ? {decision, expires} : {decision})
      .then(() => {
        say(decision === 'deny' ? 'Told them not now.' : '“' + r.name + '” is open again for ' + (expires === '1h' ? 'an hour' : '24 hours') + '.');
        P.store.requests.soon(); P.store.doors.soon();
      })
      .catch((err) => { P.fail(err); btn.disabled = false; });
  }
  P.decideAsk = decideAsk;
  P.askCard = function(r){
    const c = el('div', 'ask');
    const top = el('div', 'ask-top');
    const k = el('span', 'ask-kind'); k.append(icon('door'), document.createTextNode('Asked to reopen'));
    top.append(k);
    c.append(top);
    const nm = el('div', 'ask-top');
    nm.append(el('a', 'ask-name', r.name));
    nm.firstChild.href = '#/requests/reopen/' + encodeURIComponent(r.id);
    if(r.type) nm.append(P.typeChip(r.type));
    c.append(nm, el('p', 'ask-note', r.note ? '“' + r.note + '”' : 'No name given.'));
    const bits = ['asked ' + fmt.ago(r.created)];
    if(r.waiting > 1) bits.push(r.waiting + ' people waiting');
    if(r.closed) bits.push((r.reason === 'expired' ? 'expired ' : 'closed ') + fmt.ago(r.closed));
    c.append(el('div', 'ask-meta', bits.join(' · ')));
    const acts = el('div', 'ask-acts');
    [['allow', '1h', 'Allow 1h', 'p-btn'], ['allow', '24h', 'Allow 24h', 'p-btn p-btn--ghost'],
     ['deny', '', 'Deny', 'p-btn p-btn--quiet']].forEach(([d, x, label, cls]) => {
      const b = P.btn(label, cls, (e, btn) => decideAsk(r, d, x, btn), {aria: label + ': ' + r.name, write:true});
      acts.append(b);
    });
    c.append(acts);
    return c;
  };
  P.pairCard = function(p){
    const c = el('div', 'ask');
    const top = el('div', 'ask-top');
    const k = el('span', 'ask-kind'); k.append(icon(p.kind === 'web' ? 'globe' : 'server'),
      document.createTextNode(p.kind === 'web' ? 'Browser wants in' : 'New machine'));
    top.append(k);
    c.append(top, el('div', 'ask-name ask-name--ui', p.device_name || 'Unnamed device'));
    const meta = el('div', 'ask-meta');
    meta.append(el('span', 'mono', p.code), document.createTextNode(' · expires in '), P.countdown(p.expires_at));
    c.append(meta);
    const acts = el('div', 'ask-acts ask-acts--2');
    acts.append(P.link('#/requests/pairing/' + encodeURIComponent(p.code), 'p-btn', 'Review'));
    acts.append(P.btn('Reject', 'p-btn p-btn--quiet', (e, b) => {
      b.disabled = true;
      P.post('/api/requests/pairings/' + encodeURIComponent(p.code) + '/reject').then(() => {
        say('Rejected ' + p.code + '.'); P.store.requests.soon();
      }).catch((err) => { b.disabled = false; P.fail(err); });
    }, {write:true, aria:'Reject ' + p.code}));
    c.append(acts);
    return c;
  };

  /* ---- the Home view ---- */
  function greeting(){
    const h = new Date().getHours();
    return h < 5 ? 'Up late' : h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening';
  }
  function stat(href, n, label, hot){
    const a = P.link(href, 'stat' + (hot ? ' stat--hot' : ''));
    a.append(el('span', 'stat-n', String(n)), el('span', 'stat-l', label));
    return a;
  }
  function statText(href, value, label, tone){
    const a = P.link(href, 'stat' + (tone ? ' stat--' + tone : ''));
    a.append(el('span', 'stat-v', value), el('span', 'stat-l', label));
    return a;
  }
  function home(pane){
    const offs = [];
    const head = el('header', 'home-hero');
    const k = el('div', 'p-kicker'); k.append(el('span', '', (P.app && P.app.pocket && P.app.pocket.title) || 'Porch'));
    const h = el('h1', 'home-greet', greeting());
    h.tabIndex = -1; h.dataset.focus = '';
    head.append(k, h);
    pane.append(head);

    const stats = el('div', 'stats');
    pane.append(stats);
    const drawStats = () => {
      const doors = P.store.doors.data ? P.yourDoors(P.store.doors.data) : null, req = P.store.requests.data;
      const waiting = req ? P.waitingCount(req) : null;
      const su = P.app && P.app.stepup;
      const unlocked = su && su.active && su.expires_at > P.now();
      const push = P.pushState;
      stats.replaceChildren(
        stat('#/doors', doors ? doors.length : '–', doors && doors.length === 1 ? 'door open' : 'doors open'),
        stat('#/requests', waiting === null ? '–' : waiting, 'waiting on you', waiting > 0),
        statText('#/you/notifications', push ? (push.on ? 'On' : 'Off') : '–', 'notifications here', push && push.on ? 'ok' : ''),
        statText('#/you', unlocked ? 'Unlocked' : 'Locked', unlocked ? 'for ' + fmt.left(su.expires_at - P.now()) : 'step-up ' + ((P.app && P.app.passkeys && P.app.passkeys.count) ? 'by passkey' : 'by password'), unlocked ? 'warn' : ''));
    };
    drawStats();

    // Install Porch (only where the browser can, never when installed).
    if(P.installCard){
      const inst = P.installCard('home');
      pane.append(inst);
      offs.push(inst.cleanup);
    }

    // "Open to the public: N paths" (only when there are some).
    const pub = P.link('#/people/apps', 'home-public');
    pub.hidden = true;
    pane.append(pub);
    const drawPublic = () => {
      const pp = P.store.people.data && P.store.people.data.public_paths;
      const n = pp ? pp.filter((p) => p.active).length
                   : (P.app && P.app.counts && P.app.counts.public_paths) || 0;
      pub.hidden = !n;
      if(!n) return;
      pub.replaceChildren(icon('globe'), el('span', '', 'Open to the public: '), el('b', '', P.fmt.plural(n, 'path')), icon('chev', 'item-chev'));
    };
    drawPublic();
    offs.push(P.store.people.on(drawPublic), P.on('app', drawPublic));

    const grid = el('div', 'home-grid');
    const left = el('div', 'home-col'), right = el('div', 'home-col');
    grid.append(left, right);
    pane.append(grid);

    // waiting on you
    const wait = P.section('Waiting on you', {action: P.link('#/requests', 'sec-link', 'See all')});
    const waitBox = el('div', 'wait-list');
    wait.append(waitBox);
    left.append(wait);
    offs.push(P.bind(waitBox, P.store.requests, (d) => {
      const asks = P.pendingAsks(d.reopen), pairs = d.pairings || [];
      const cards = P.pendingAccess(d.access).map(P.accessCard).concat(pairs.map(P.pairCard), asks.map(P.askCard)).slice(0, 3);
      if(!cards.length){
        waitBox.replaceChildren(P.empty('Nothing waiting on you', 'Reopen asks, people asking for access and new machines show up here, and as notifications.', null, 'check'));
      }else waitBox.replaceChildren(...cards);
      drawStats();
    }, {skeleton: () => P.skeleton(1, true)}));

    // open now
    const open = P.section('Open now', {action: P.link('#/doors', 'sec-link', 'All doors')});
    const openBox = el('div');
    open.append(openBox);
    left.append(open);
    offs.push(P.bind(openBox, P.store.doors, (all) => {
      drawStats();
      const doors = P.yourDoors(all);
      if(!doors.length){
        openBox.replaceChildren(P.empty('No doors open', 'Open one to share a folder, take uploads or pass a secret.',
          P.btn('New door', 'p-btn p-btn--sm', () => P.newDoor(), {icon:'plus', write:true}), 'door'));
        return;
      }
      const sorted = doors.slice().sort((a, b) => (a.expires === null ? Infinity : a.expires) - (b.expires === null ? Infinity : b.expires));
      const list = el('div', 'items');
      list.append(...sorted.slice(0, 5).map((d) => P.doorRow ? P.doorRow(d, true) : el('div', 'item', d.name)));
      openBox.replaceChildren(list);
    }, {rows: 3}));

    // share
    if($('sharedCard')) right.append($('sharedCard'));
    right.append($('homeShare'));
    offs.push(P.on('stepup', drawStats), P.on('push', drawStats), P.on('app', drawStats));
    return () => { offs.forEach((f) => f()); };
  }

  P.sectionDef('home', {
    label: 'Home',
    resolve: () => ({key:'home', title:'Porch', single:true, list: home}),
  });

  P.homeInit = function(){
    P.on('clip', renderClip);
    P.on('inbox', renderInbox);
    P.on('links', (d) => { try{ renderLinks(d); }catch(e){} });
    loadClip(); loadInbox(); loadLinks();
    const qs = new URLSearchParams(location.search);
    if(qs.get('shared') === '1'){
      const nf = +qs.get('files') || 0, nt = +qs.get('text') || 0;
      const bits = [];
      if(nf) bits.push(nf + ' file' + (nf === 1 ? '' : 's'));
      if(nt) bits.push('a clip');
      say(bits.length ? 'Got ' + bits.join(' and ') + '.' : 'Nothing came through with that share.', bits.length ? 'ok' : 'warn');
      offerLinks(qs.getAll('f').slice(0, 5), qs.get('c'));
      history.replaceState(null, '', '/' + (location.hash || '#/home'));
    }
  };
})();

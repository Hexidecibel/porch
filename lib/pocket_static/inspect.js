/* The request inspector (#/doors/<name>/inspect[/<id>]): a live list from
 * the door's recorded exchanges (SSE, polling fallback, Pause), and one
 * record with headers, bodies, Copy as curl and Replay. Records are masked
 * by the door's recorder before they are stored; this page only shows them. */
'use strict';
(function(){
  const P = window.Porch;
  const {icon, fmt} = P;
  const enc = encodeURIComponent;
  const base = (name) => '/api/doors/' + enc(name) + '/requests';
  const MAX_ROWS = 300;
  const CURL_SKIP = /^(host|connection|content-length|transfer-encoding|keep-alive|x-forwarded-for|x-forwarded-proto|x-porch-replay)$/i;

  function door(name){ return (P.store.doors.data || []).find((d) => d.name === name) || null; }
  function statusClass(s){ return s ? String(s).charAt(0) : '0'; }
  function reqRow(name, r, fresh){
    const a = P.link('#/doors/' + enc(name) + '/inspect/' + enc(r.id), 'req' + (fresh ? ' req-new' : ''));
    const m = el('span', 'meth', r.method || '?'); m.dataset.m = r.method || '';
    const path = el('span', 'req-path', r.target || '/');
    const st = el('span', 'req-status', r.status || (r.upgraded ? '101' : '—'));
    st.dataset.c = r.error ? '0' : statusClass(r.status || (r.upgraded ? 101 : 0));
    const bits = [fmt.clock(r.ts || 0)];
    if(typeof r.ms === 'number') bits.push(Math.round(r.ms) + ' ms');
    if(r.resp_bytes) bits.push(fmt.size(r.resp_bytes));
    if(r.client_ip) bits.push(r.client_ip);
    if(r.replay_of) bits.push('replay of #' + r.replay_of);
    if(r.handled_by && r.handled_by !== 'upstream' && r.handled_by !== 'replay') bits.push('answered by the ' + r.handled_by);
    const sub = el('span', 'req-sub', bits.join(' · '));
    a.append(m, path, st, sub);
    a.setAttribute('aria-label', (r.method || '') + ' ' + (r.target || '') + ', status ' + (r.status || 'none'));
    return a;
  }

  function listView(pane, name){
    const d = door(name);
    let paused = false, buffered = [], last = 0, es = null, poll = null, alive = true;
    const rows = new Map();
    const live = el('span', 'insp-live'); live.append(el('span', 'live-dot'), el('span', '', 'connecting'));
    const setLive = (state, text) => { live.dataset.state = state; live.lastChild.textContent = text; };
    const pauseBtn = P.btn('Pause', 'p-btn p-btn--ghost p-btn--sm', () => {
      paused = !paused;
      pauseBtn.replaceChildren(icon(paused ? 'play' : 'pause'), document.createTextNode(paused ? 'Resume' : 'Pause'));
      if(!paused){ buffered.forEach((r) => add(r, true)); buffered = []; setLive('live', 'live'); }
      else setLive('paused', 'paused');
    }, {icon:'pause'});
    pane.append(P.paneHead(d && d.capture ? 'Webhook' : 'Requests', {kicker: name,
      sub:[live], actions:[pauseBtn]}));
    if(d && d.inspect_raw) pane.append(el('div', 'p-notice p-notice--warn', 'Raw capture: header values and bodies are stored unmasked.'));
    if(d && d.capture) pane.append(P.urlBox('Hook URL', d.url, {accent:true}));
    const list = el('div', 'items');
    const box = el('div');
    box.append(P.skeleton(5));
    pane.append(box);
    function emptyState(){
      return P.empty('No requests yet', d && d.capture ? 'Point a webhook at the hook URL; each call shows up here as it arrives.' :
        'Open the door’s link; every request shows up here as it arrives.', null, 'activity');
    }
    function add(r, fresh){
      if(!r || r.id === undefined || rows.has(r.id)) return;
      if(paused && fresh){ buffered.push(r); setLive('paused', 'paused · ' + buffered.length + ' new'); return; }
      const row = reqRow(name, r, fresh);
      rows.set(r.id, row);
      last = Math.max(last, +r.id || 0);
      // newest first
      let before = null;
      for(const c of list.children){ const id = +c.getAttribute('href').split('/').pop(); if(id < +r.id){ before = c; break; } }
      list.insertBefore(row, before);
      while(list.childElementCount > MAX_ROWS){ const x = list.lastElementChild; rows.delete(+x.getAttribute('href').split('/').pop()); x.remove(); }
      if(box.firstChild !== list) box.replaceChildren(list);
      P.markCurrent();
    }
    function startPoll(){
      if(poll || !alive) return;
      setLive('down', 'polling');
      poll = setInterval(() => {
        P.get(base(name) + '?since=' + last + '&limit=100').then((pg) => {
          (pg.records || []).forEach((r) => add(r, true));
        }).catch(() => setLive('down', 'can’t reach it'));
      }, 4000);
    }
    function connect(){
      if(!alive || typeof EventSource !== 'function'){ startPoll(); return; }
      es = new EventSource(base(name) + '/events?since=' + last);
      es.addEventListener('open', () => { if(!paused) setLive('live', 'live'); });
      es.addEventListener('request', (e) => { try{ add(JSON.parse(e.data), true); }catch(x){} });
      es.addEventListener('closed', () => { setLive('down', 'door closed'); es.close(); });
      es.addEventListener('error', () => {
        if(es.readyState === 2){ es = null; startPoll(); }
        else setLive('down', 'reconnecting');
      });
    }
    P.get(base(name) + '?limit=100').then((pg) => {
      if(!alive) return;
      const recs = (pg.records || []).slice().sort((a, b) => b.id - a.id);
      recs.forEach((r) => add(r, false));
      if(!recs.length) box.replaceChildren(emptyState());
      if(typeof pg.last === 'number') last = Math.max(last, pg.last);
      connect();
    }, (err) => { if(alive) box.replaceChildren(P.errorBox(err, () => P.refreshDetail())); });
    return () => { alive = false; if(es) es.close(); clearInterval(poll); };
  }

  /* ---- one record ---- */
  function replayable(d, rec){
    if(!d || d.capture) return 'A webhook door has no app to replay to.';
    if(rec.upgraded) return 'WebSocket exchanges can’t be replayed.';
    if(rec.handled_by !== 'upstream' && rec.handled_by !== 'replay') return 'The door answered this itself.';
    const b = rec.req_body || {};
    if(b.truncated) return 'The request body was truncated.';
    if(b.kind === 'binary' || b.decoded) return 'The request body wasn’t stored in full.';
    return '';
  }
  function shq(s){ return '\'' + String(s).replace(/'/g, '\'\\\'\'') + '\''; }
  function curlFor(d, rec){
    const url = (d ? d.url.replace(/\/$/, '') : '') + (rec.target || '/');
    const parts = ['curl'];
    if(rec.method && rec.method !== 'GET') parts.push('-X ' + rec.method);
    parts.push(shq(url));
    (rec.req_headers || []).forEach((kv) => { if(Array.isArray(kv) && !CURL_SKIP.test(kv[0])) parts.push('-H ' + shq(kv[0] + ': ' + kv[1])); });
    const b = rec.req_body || {};
    if(b.kind === 'text') parts.push('--data-raw ' + shq(b.data || ''));
    return parts.join(' \\\n  ');
  }
  function headers(list){
    if(!list || !list.length) return el('p', 'small', 'None.');
    const dl = el('dl', 'hdrs');
    for(const kv of list){
      if(!Array.isArray(kv)) continue;
      const v = String(kv[1]);
      const dd = el('dd', /\[masked/.test(v) ? 'masked' : '', v);
      dl.append(el('dt', '', kv[0]), dd);
    }
    return dl;
  }
  // Pretty JSON with token classes: spans built from text, never markup.
  function jsonNode(text){
    const pre = el('pre', 'code');
    let pretty;
    try{ pretty = JSON.stringify(JSON.parse(text), null, 2); }catch(e){ pre.textContent = text; return pre; }
    const re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;
    let i = 0, m;
    while((m = re.exec(pretty))){
      if(m.index > i) pre.append(document.createTextNode(pretty.slice(i, m.index)));
      if(m[1]){
        const sp = el('span', m[2] ? 'k' : 's', m[1]);
        if(/\[masked/.test(m[1])) sp.className = 'masked';
        pre.append(sp);
        if(m[2]) pre.append(document.createTextNode(m[2]));
      }else if(m[3]) pre.append(el('span', 'b', m[3]));
      else pre.append(el('span', 'n', m[4]));
      i = re.lastIndex;
    }
    pre.append(document.createTextNode(pretty.slice(i)));
    return pre;
  }
  function bodyNode(b){
    const box = el('div', 'sec');
    b = b || {};
    if(!b.kind || b.kind === 'none'){ box.append(el('p', 'small', b.websocket ? 'WebSocket: no body recorded.' : 'No body.')); return box; }
    const meta = [];
    if(b.type) meta.push(b.type);
    if(b.size !== undefined) meta.push(fmt.size(b.size));
    if(b.encoding) meta.push(b.encoding);
    const top = el('div', 'badges');
    meta.forEach((x) => top.append(P.badge(x)));
    if(b.truncated) top.append(P.badge('truncated', 'warn'));
    if(b.decoded_truncated) top.append(P.badge('decoded in part', 'warn'));
    if(b.masked_fields && b.masked_fields.length) top.append(P.badge('masked: ' + b.masked_fields.join(', '), 'warn', 'lock'));
    box.append(top);
    if(b.kind === 'binary'){
      box.append(el('p', 'small', 'Binary body; the first bytes:'));
      box.append(el('pre', 'code', (b.hex || '').replace(/(..)/g, '$1 ').trim()));
      return box;
    }
    const text = b.data || '';
    box.append(/json/i.test(b.type || '') || /^\s*[{[]/.test(text) ? jsonNode(text) : el('pre', 'code', text));
    return box;
  }
  function recordView(pane, name, id){
    let alive = true;
    pane.append(P.skeleton(2, true));
    P.get(base(name) + '/' + enc(id)).then((res) => {
      if(!alive) return;
      const rec = res && res.record ? res.record : res;
      const d = door(name);
      pane.replaceChildren();
      const back = P.link('#/doors/' + enc(name) + '/inspect', 'p-btn p-btn--quiet p-btn--sm back-inline');
      back.prepend(icon('back'));
      back.append(document.createTextNode('All requests'));
      const st = el('span', 'req-status', rec.status || '—'); st.dataset.c = rec.error ? '0' : statusClass(rec.status);
      const sub = [st];
      if(typeof rec.ms === 'number') sub.push(el('span', '', Math.round(rec.ms) + ' ms'));
      if(typeof rec.ttfb_ms === 'number') sub.push(el('span', '', 'first byte ' + Math.round(rec.ttfb_ms) + ' ms'));
      sub.push(el('span', '', 'from ' + (rec.client_ip || '?')), el('span', '', fmt.when(rec.ts)));
      pane.append(back, P.paneHead((rec.method || '?') + ' ' + (rec.target || '/'), {mono:true, kicker: name + ' · #' + rec.id, sub}));
      const flags = el('div', 'badges');
      if(rec.replay_of) flags.append(P.badge('replay of #' + rec.replay_of, 'accent'));
      if(rec.raw) flags.append(P.badge('raw: unmasked', 'danger'));
      else if(rec.masked && rec.masked.length) flags.append(P.badge('masked: ' + rec.masked.join(', '), 'warn', 'lock'));
      if(rec.owner) flags.append(P.badge('you (owner)'));
      if(rec.admitted) flags.append(P.badge('admitted by ' + rec.admitted));
      if(rec.handled_by) flags.append(P.badge('answered by ' + rec.handled_by));
      if(flags.childElementCount) pane.append(flags);
      if(rec.error) pane.append(el('div', 'p-notice p-notice--error', 'Error: ' + rec.error));
      const acts = el('div', 'actions');
      const why = replayable(d, rec);
      const rp = P.btn('Replay', 'p-btn', async (e, b) => {
        b.disabled = true;
        try{
          const r = await P.post(base(name) + '/' + enc(rec.id) + '/replay', {});
          let msg = 'Replayed as #' + r.id + ' → ' + (r.http_status || 'no answer');
          if(r.dropped && r.dropped.length) msg += ' (dropped ' + r.dropped.join(', ') + ')';
          say(msg);
          if(r.id !== undefined) P.go('#/doors/' + enc(name) + '/inspect/' + enc(r.id));
        }catch(err){ P.fail(err); b.disabled = false; }
      }, {icon:'refresh', write:true});
      if(why){ rp.disabled = true; rp.title = why; delete rp.dataset.write; }
      acts.append(P.btn('Copy as curl', 'p-btn p-btn--ghost', () => copied(copyText(curlFor(d, rec)), 'curl copied (masked values stay masked)'), {icon:'copy'}), rp);
      pane.append(acts);
      if(why) pane.append(el('p', 'small', 'Replay: ' + why));
      const sec = (title, node) => { const s = P.section(title); s.append(node); pane.append(s); };
      sec('Request headers', headers(rec.req_headers));
      sec('Request body', bodyNode(rec.req_body));
      sec('Response headers', headers(rec.resp_headers));
      sec('Response body', bodyNode(rec.resp_body));
      const dl = el('dl', 'kv');
      const kv = (k, v) => dl.append(el('dt', '', k), el('dd', 'mono', v));
      kv('Request size', fmt.size(rec.req_bytes || 0));
      kv('Response size', fmt.size(rec.resp_bytes || 0));
      if(rec.target_masked) kv('Masked in the URL', rec.target_masked.join(', '));
      sec('Sizes', dl);
    }, (err) => { if(alive) pane.replaceChildren(P.errorBox(err, () => P.refreshDetail())); });
    return () => { alive = false; };
  }

  P.inspectView = function(pane, name, id){
    if(!P.store.doors.data) P.store.doors.load().catch(() => {});
    return id ? recordView(pane, name, id) : listView(pane, name);
  };
})();

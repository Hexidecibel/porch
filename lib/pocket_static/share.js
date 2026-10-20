
/* ---- make link ---- */
const sheet = $('sheet');
let linkReq = null, expiry = '24h', protect = 'key', sealFile = null, resultUrl = '', resultGuest = '';
function clipReq(e){
  const t = e.text.replace(/\s+/g, ' ').trim();
  return {kind:'clip', id:e.id, label: t.length > 60 ? t.slice(0, 60) + '…' : t};
}
function chipGroup(id, pick){
  const cs = document.querySelectorAll('#' + id + ' .chip');
  const set = (v)=>{ cs.forEach(c=>c.setAttribute('aria-checked', String(c.dataset.v === v))); pick(v); };
  cs.forEach(c=>c.addEventListener('click', ()=>set(c.dataset.v)));
  return set;
}
const setExpiry = chipGroup('expChips', (v)=>{ expiry = v; });
const setProtect = chipGroup('protChips', (v)=>{ protect = v; syncPassword(); });
function syncPassword(){
  const sealed = linkReq && linkReq.kind === 'sealed';
  if(sealed && protect === 'password'){
    $('pwLabel').textContent = 'Password';
    $('pwHelp').textContent = 'The file is encrypted with it. Tell it to the recipient another way: it is never in the link and never sent to this server.';
    $('pwField').hidden = false;
  }else if(sealed){
    $('pwField').hidden = true;
  }else{
    $('pwLabel').textContent = 'Password (optional)';
    $('pwHelp').textContent = 'Visitors type it before they see anything.';
    $('pwField').hidden = false;
  }
}
function syncBurn(){ $('linkMax').disabled = $('linkBurn').checked; }
$('linkBurn').addEventListener('change', syncBurn);
function setSealFile(f){
  sealFile = f || null;
  $('sealName').textContent = sealFile ? sealFile.name + ' · ' + humanSize(sealFile.size) : 'No file chosen';
}
function openSheet(req){
  linkReq = req;
  const sealed = req.kind === 'sealed';
  $('sheetForm').hidden = false; $('sheetResult').hidden = true; $('sheetErr').hidden = true;
  $('sealProg').hidden = true;
  $('sheetKicker').textContent = sealed ? 'Send encrypted' : 'Make a link';
  $('sheetTitle').textContent = sealed ? 'Encrypted on this device' : req.label;
  $('sheetWhat').textContent = sealed
    ? 'It is encrypted here before it leaves this device: the server only ever holds ciphertext. The key rides in the link after the #, which browsers never send to a server.'
    : (req.kind === 'clip' ? 'A clipboard entry, shared as its own page.' : 'A file from your inbox, shared as its own door.');
  $('sealPick').hidden = !sealed;
  setSealFile(null); $('sealText').value = '';
  setExpiry('24h'); setProtect('key');
  $('linkPw').value = ''; $('linkBurn').checked = false; $('linkMax').value = ''; $('linkGuest').checked = false;
  syncBurn(); syncPassword(); goIdle();
  if(typeof sheet.showModal === 'function'){ if(!sheet.open) sheet.showModal(); }
  else sheet.setAttribute('open', '');
}
function goIdle(){
  const go = $('sheetGo');
  go.disabled = false;
  go.textContent = linkReq && linkReq.kind === 'sealed' ? 'Encrypt and make link' : 'Make link';
}
function closeSheet(){ if(sheet.open){ if(typeof sheet.close === 'function') sheet.close(); else sheet.removeAttribute('open'); } }
// Whatever way it closes (Done, Cancel, Esc): forget the secrets it held.
sheet.addEventListener('close', ()=>{
  if(sheet.open) return;               // stale: opened again since
  $('linkPw').value = ''; $('sealText').value = ''; setSealFile(null);
  $('resUrl').textContent = ''; $('resGuestUrl').textContent = ''; $('resQr').replaceChildren();
  resultUrl = ''; resultGuest = ''; linkReq = null;
});
$('sheetCancel').addEventListener('click', closeSheet);
$('resDone').addEventListener('click', closeSheet);
$('sealInput').addEventListener('change', (e)=>{ setSealFile(e.target.files[0]); });
$('sealPhotoInput').addEventListener('change', (e)=>{ setSealFile(e.target.files[0]); });
$('sealBtn').addEventListener('click', ()=>openSheet({kind:'sealed'}));
function sheetError(msg){ $('sheetErr').textContent = msg; $('sheetErr').hidden = false; }
function linkRules(withPassword){
  const r = {expires: expiry, burn: $('linkBurn').checked, guest: $('linkGuest').checked};
  const mo = $('linkMax').value.trim();
  if(!r.burn && mo){
    const n = Number(mo);
    if(!Number.isInteger(n) || n < 1 || n > 1000) throw new Error('Max opens is a whole number from 1 to 1000.');
    r.max_opens = n;
  }
  if(withPassword){
    const pw = $('linkPw').value;
    if(pw){
      if(pw.length < 6) throw new Error('The password needs at least 6 characters.');
      r.password = pw;
    }
  }
  return r;
}
function expiryText(exp){
  if(exp === null || exp === undefined) return 'never expires';
  const s = Math.round(exp - Date.now()/1000);
  if(s <= 0) return 'expired';
  const d = Math.floor(s/86400), h = Math.floor(s%86400/3600), m = Math.floor(s%3600/60), sec = s%60;
  if(d) return 'expires in ' + d + 'd ' + h + 'h';
  if(h) return 'expires in ' + h + 'h ' + m + 'm';
  if(m) return 'expires in ' + m + 'm ' + String(sec).padStart(2, '0') + 's';
  return 'expires in ' + sec + 's';
}
function rulesText(r){
  const out = [];
  if(r.password) out.push('password');
  if(r.burn) out.push('burns after one open');
  else if(r.max_opens) out.push('closes after ' + r.max_opens + ' opens');
  if(r.guest) out.push('guest link');
  return out;
}
function showResult(res, url, title, rules, sealed){
  $('sheetForm').hidden = true; $('sheetResult').hidden = false;
  $('resTitle').textContent = title;
  resultUrl = url; resultGuest = res.guest_url || '';
  $('resUrl').textContent = url;
  $('resQr').replaceChildren();
  try{
    const q = PorchQR.svg(url, {ecl:'M'});
    q.setAttribute('aria-label', 'QR code of the link');
    $('resQr').appendChild(q);
  }catch(e){}
  $('resShare').hidden = typeof navigator.share !== 'function';
  $('resGuest').hidden = !resultGuest;
  $('resGuestUrl').textContent = resultGuest;
  const bits = [expiryText(res.expires)].concat(rulesText(rules));
  if(sealed) bits.push(protect === 'password' ? 'opens with the password' : 'the key is the part after #');
  $('resMeta').textContent = bits.join(' · ');
  loadLinks();
}
$('resCopy').addEventListener('click', ()=>copied(copyText(resultUrl)));
$('resGuestCopy').addEventListener('click', ()=>copied(copyText(resultGuest)));
$('resShare').addEventListener('click', ()=>{
  navigator.share({url: resultUrl}).catch(()=>{});
});
$('sheetGo').addEventListener('click', async ()=>{
  $('sheetErr').hidden = true;
  const go = $('sheetGo');
  const req = linkReq;
  if(!req) return;
  try{
    if(req.kind === 'sealed'){ await sendSealed(); return; }
    const rules = linkRules(true);
    go.disabled = true; go.textContent = 'Opening the door…';
    const res = await api('POST', '/api/links', {kind:req.kind, id:req.id, rules});
    $('linkPw').value = '';
    showResult(res, res.url, req.label, rules, false);
  }catch(e){
    sheetError(e.message);
    goIdle();
  }
});

/* ---- send encrypted: seal on this device, tus straight from the Sealer ---- */
function sealProgress(sent, total){
  const pct = total ? Math.round(sent/total*100) : 0;
  $('sealProgFill').style.width = pct + '%';
  $('sealProgText').textContent = 'Encrypting and sending · ' + humanSize(sent) + ' of ' + humanSize(total) + ' · ' + pct + '%';
}
async function sendSealed(){
  const go = $('sheetGo');
  if(!window.PorchSeal) throw new Error('The encryption library did not load; reload the page.');
  if(!window.isSecureContext) throw new Error('Encryption needs an https page.');
  let src, name, type;
  const text = $('sealText').value;
  if(sealFile){ src = sealFile; name = sealFile.name; type = sealFile.type || 'application/octet-stream'; }
  else if(text.trim()){ src = new TextEncoder().encode(text); name = 'message.txt'; type = 'text/plain; charset=utf-8'; }
  else throw new Error('Choose a file or type a message.');
  const opts = {name, type};
  if(protect === 'password'){
    const pw = $('linkPw').value;
    if(pw.length < 8) throw new Error('Use a password of at least 8 characters.');
    opts.password = pw;
  }
  const rules = linkRules(false);
  const sealer = new PorchSeal.Sealer(src, opts);
  const total = sealer.totalSize();
  if(total > CFG.maxFile) throw new Error('Larger than ' + humanSize(CFG.maxFile) + ' once sealed.');
  go.disabled = true; go.textContent = 'Encrypting…';
  $('sealProg').hidden = false; sealProgress(0, total);
  let up;
  try{ up = await sealedUpload(sealer, sealProgress); }
  finally{ $('linkPw').value = ''; }
  if(!up.ok) throw new Error(up.error);
  go.textContent = 'Opening the door…';
  const res = await api('POST', '/api/links', {kind:'sealed', id:up.name, rules});
  // The key is added here, in the page: no request ever carries it.
  const url = sealer.key ? res.url + '#k=' + sealer.key : res.url;
  $('sealProg').hidden = true;
  showResult(res, url, name, rules, true);
}
// A tus client whose bytes come from a PorchSeal.Sealer instead of a File.
// Ciphertext is produced in order, so only the bytes since the last
// acknowledged offset are kept (one chunk, ~4MB): memory stays bounded for
// any size. A dropped PATCH resumes from the server's offset (HEAD) as long
// as that offset is still inside the kept chunk, which it always is.
async function sealedUpload(sealer, onProg){
  const V = '1.0.0', CH = 4*1024*1024, total = sealer.totalSize();
  function x(method, url, headers, body, onp){
    return new Promise((res)=>{
      const r = new XMLHttpRequest();
      let stall = null;
      const kick = ()=>{ clearTimeout(stall); stall = setTimeout(()=>r.abort(), 30000); };
      r.open(method, url);
      r.setRequestHeader('Tus-Resumable', V);
      for(const k in headers) r.setRequestHeader(k, headers[k]);
      if(r.upload && onp) r.upload.onprogress = (e)=>{ kick(); onp(e.loaded); };
      r.onload = ()=>{ clearTimeout(stall); res(r); };
      r.onerror = r.onabort = ()=>{ clearTimeout(stall); res(null); };
      kick();
      r.send(body === undefined ? null : body);
    });
  }
  function msg(r){
    try{ const j = JSON.parse(r.responseText); if(j && j.message) return j.message; }catch(e){}
    return 'HTTP ' + r.status;
  }
  function wait(ms){
    return new Promise((res)=>{
      const t = setTimeout(done, ms);
      function done(){ clearTimeout(t); document.removeEventListener('visibilitychange', vis);
        window.removeEventListener('online', done); res(); }
      function vis(){ if(!document.hidden) done(); }
      document.addEventListener('visibilitychange', vis);
      window.addEventListener('online', done);
    });
  }
  const meta = 'sealed ' + btoa('1') + ',filetype ' + btoa('application/x-porch-seal');
  let fails = 0, c;
  for(;;){
    c = await x('POST', '/tus-sealed/', {'Upload-Length': String(total), 'Upload-Metadata': meta});
    if(c && c.status === 201) break;
    if(c && c.status < 500 && c.status !== 429) return {ok:false, error:msg(c)};
    if(++fails > 6) return {ok:false, error:'connection lost, try again'};
    await wait(1000 * fails);
  }
  const url = new URL(c.getResponseHeader('Location'), location.href).pathname;
  const buf = [];
  let acked = 0, bufStart = 0, bufLen = 0, done = false;
  fails = 0;
  const trim = ()=>{
    while(buf.length && bufStart + buf[0].length <= acked){ bufStart += buf[0].length; bufLen -= buf[0].length; buf.shift(); }
  };
  while(acked < total){
    while(!done && bufStart + bufLen - acked < CH){
      const piece = await sealer.nextChunk();
      if(!piece){ done = true; break; }
      buf.push(piece); bufLen += piece.length;
    }
    const body = new Blob(buf).slice(acked - bufStart);
    if(!body.size) return {ok:false, error:'the encrypted stream ended early'};
    const off = acked;
    const p = await x('PATCH', url, {'Content-Type':'application/offset+octet-stream', 'Upload-Offset': String(off)},
                      body, (n)=>onProg(off + n, total));
    if(p && p.status === 204){
      acked = +p.getResponseHeader('Upload-Offset'); fails = 0; trim();
      onProg(acked, total);
      if(acked >= total) return {ok:true, name: p.getResponseHeader('Porch-Upload-Name')};
      continue;
    }
    if(p && !(p.status === 409 || p.status === 423 || p.status === 429 || p.status >= 500)) return {ok:false, error:msg(p)};
    if(++fails > 12) return {ok:false, error:'connection lost, try again'};
    while(document.hidden || navigator.onLine === false) await wait(30000);
    await wait(Math.min(30000, 1000 * Math.pow(2, Math.min(fails - 1, 5))));
    const h = await x('HEAD', url, {});
    if(h && h.status === 200){
      const o = +h.getResponseHeader('Upload-Offset');
      if(o < bufStart || o > bufStart + bufLen) return {ok:false, error:'the upload cannot resume from here; send it again'};
      acked = o; trim();
    }else if(h && h.status === 404){
      return {ok:false, error:'the upload expired; send it again'};
    }
  }
  return {ok:false, error:'nothing was sent'};
}

/* ---- links panel ---- */
function linkRow(l){
  const r = el('div', 'p-row');
  const main = el('div', 'p-row-main');
  const nm = el('div', 'p-row-name', l.label || l.name); nm.title = l.name;
  const u = el('div', 'link-url', l.url);
  const meta = el('div', 'p-row-meta');
  const exp = el('span', '', expiryText(l.expires));
  if(l.expires !== null) exp.dataset.exp = String(l.expires);
  meta.append(el('span', '', (l.kind === 'sealed' ? 'encrypted' : (l.type || l.kind)) + ' · '
      + l.opens + ' open' + (l.opens === 1 ? '' : 's') + ' · '), exp);
  if(!l.alive) meta.append(el('span', '', ' · not running'));
  const badges = el('div', 'link-badges');
  if(l.rules.password) badges.append(el('span', 'p-badge p-badge--accent', 'password'));
  if(l.rules.max_opens === 1) badges.append(el('span', 'p-badge p-badge--wait', 'burn'));
  else if(l.rules.max_opens) badges.append(el('span', 'p-badge p-badge--wait', 'max ' + l.rules.max_opens));
  if(l.rules.guest_link) badges.append(el('span', 'p-badge p-badge--accent', 'guest link'));
  if(l.kind === 'sealed') badges.append(el('span', 'p-badge p-badge--ok', 'end-to-end'));
  main.append(nm, u, meta);
  if(badges.childElementCount) main.append(badges);
  const acts = el('div', 'row-actions');
  const post = (what)=>api('POST', '/api/links/' + encodeURIComponent(l.name) + '/' + what, {})
    .then(renderLinks).catch(err=>say(err.message, 'error'));
  if(l.kind !== 'sealed'){
    const cp = el('button', 'p-btn p-btn--ghost p-btn--sm', 'Copy');
    cp.type = 'button'; cp.setAttribute('aria-label', 'Copy the link ' + l.name);
    cp.addEventListener('click', ()=>copied(copyText(l.url)));
    acts.append(cp);
  }
  if(l.expires !== null){
    const ext = el('button', 'p-btn p-btn--quiet p-btn--sm', '+1h');
    ext.type = 'button'; ext.setAttribute('aria-label', 'One more hour for ' + l.name);
    ext.addEventListener('click', ()=>post('extend'));
    const nev = el('button', 'p-btn p-btn--quiet p-btn--sm', 'Never');
    nev.type = 'button'; nev.setAttribute('aria-label', 'Never expire ' + l.name);
    nev.addEventListener('click', ()=>post('never'));
    acts.append(ext, nev);
  }
  const cl = el('button', 'p-btn p-btn--quiet p-btn--sm', 'Close');
  cl.type = 'button'; cl.setAttribute('aria-label', 'Close ' + l.name);
  cl.addEventListener('click', ()=>{
    if(cl.dataset.armed !== '1'){
      cl.dataset.armed = '1'; cl.textContent = 'Really?'; cl.className = 'p-btn p-btn--danger p-btn--sm';
      setTimeout(()=>{ cl.dataset.armed = ''; cl.textContent = 'Close'; cl.className = 'p-btn p-btn--quiet p-btn--sm'; }, 4000);
      return;
    }
    cl.disabled = true;
    post('close').then(()=>say('Link closed.'));
  });
  acts.append(cl);
  r.append(main, acts);
  return r;
}
function renderLinks(list){
  if(!Array.isArray(list)) return;
  const box = $('links');
  if(!list.length){
    const empty = el('div', 'p-empty');
    empty.append(el('div', 'p-empty-title', 'No links yet'),
                 el('div', 'p-empty-text', 'Tap Link on an inbox file or a clip, or Send encrypted.'));
    box.replaceChildren(empty);
  }else{
    box.replaceChildren(...list.map(linkRow));
  }
  $('linksLabel').textContent = list.length ? 'Links · ' + list.length : 'Links';
}
function loadLinks(){ return api('GET', '/api/links').then(renderLinks).catch(()=>{}); }
setInterval(()=>{
  document.querySelectorAll('[data-exp]').forEach((e)=>{ e.textContent = expiryText(+e.dataset.exp); });
}, 1000);
// After a share-target upload: offer a link for what just came in.
function offerLinks(files, clipId){
  const box = $('sharedActions');
  box.replaceChildren();
  files.forEach((f)=>{
    const b = el('button', 'p-btn p-btn--ghost p-btn--sm', 'Link ' + (f.length > 28 ? f.slice(0, 27) + '…' : f));
    b.type = 'button';
    b.addEventListener('click', ()=>openSheet({kind:'inbox', id:f, label:f}));
    box.append(b);
  });
  if(clipId){
    const b = el('button', 'p-btn p-btn--ghost p-btn--sm', 'Link the clip');
    b.type = 'button';
    b.addEventListener('click', ()=>{
      const e = current && current.id === clipId ? current : null;
      if(e) openSheet(clipReq(e)); else say('That clip is gone.', 'warn');
    });
    box.append(b);
  }
  if(!box.childElementCount) return;
  const no = el('button', 'p-btn p-btn--quiet p-btn--sm', 'Not now');
  no.type = 'button'; no.addEventListener('click', ()=>{ $('sharedCard').hidden = true; });
  box.append(no);
  $('sharedCard').hidden = false;
}

// Porch setup wizard. Talks to lib/porch_setup/web.py. Every DOM write uses
// textContent / attributes; nothing from the server is parsed as markup.
(function () {
  'use strict';

  var S = { csrf: '', steps: [], byId: {}, pending: null, running: false, run: null,
            lastSeq: 0, es: null, urls: {}, complete: false, phoneStep: null };

  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function clear(e) { while (e.firstChild) e.removeChild(e.firstChild); }
  function show(e, on) { e.hidden = !on; }

  // ---- HTTP ---------------------------------------------------------------
  function api(method, path, body) {
    var opt = { method: method, credentials: 'same-origin', headers: {} };
    if (method === 'POST') {
      opt.headers['Content-Type'] = 'application/json';
      opt.headers['X-Porch-CSRF'] = S.csrf;
      opt.body = JSON.stringify(body || {});
    }
    return fetch(path, opt).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        return { status: r.status, body: j };
      });
    });
  }

  // ---- gate ---------------------------------------------------------------
  function gate(title, text) {
    $('gate-title').textContent = title;
    $('gate-text').textContent = text;
    show($('gate'), true);
    show($('main'), false);
    setLive('down', 'Not connected');
  }

  function start() {
    var m = /(?:^#|&)k=([A-Za-z0-9_-]+)/.exec(location.hash || '');
    if (location.hash) history.replaceState(null, '', location.pathname + location.search);
    if (m) {
      api('POST', '/api/session', { key: m[1] }).then(function (r) {
        if (r.status === 200) { S.csrf = r.body.csrf; boot(); return; }
        if (r.status === 429) {
          gate('Too many tries', 'This wizard is locked for a few minutes after several wrong links. Wait, then use the link from the terminal.');
          return;
        }
        // The key may already have been used by this browser (reload): try the cookie.
        boot(true);
      });
    } else {
      boot(true);
    }
  }

  function boot(fromCookie) {
    api('GET', '/api/state').then(function (r) {
      if (r.status === 401) {
        gate(fromCookie ? 'This link has been used' : 'Link not valid',
             'Each wizard link works once, in one browser. Open the link printed in the terminal, or restart `porch setup --web` for a new one.');
        return;
      }
      show($('gate'), false);
      show($('main'), true);
      applyState(r.body);
      connect();
    }).catch(function () { gate('Cannot reach the wizard', 'The setup server is not answering. Is `porch setup --web` still running?'); });
  }

  function refresh() {
    return api('GET', '/api/state').then(function (r) { if (r.status === 200) applyState(r.body); });
  }

  // ---- state --------------------------------------------------------------
  function applyState(st) {
    if (st.csrf) S.csrf = st.csrf;
    if (S.replayUntil === undefined) S.replayUntil = st.seq || 0;
    if (st.host) $('host').textContent = st.host;
    S.steps = st.steps || [];
    S.byId = {};
    S.steps.forEach(function (s) { S.byId[s.id] = s; });
    S.running = !!st.running;
    S.run = st.run;
    S.urls = st.urls || {};
    S.ready = st.ready || S.ready || null;
    S.complete = !!st.complete;
    S.activeStep = st.active_step || null;
    renderSteps();
    renderIntro();
    if (st.pending) openPrompt(st.pending); else closePrompt();
    if (!st.running && st.last_result) renderResult(st.last_result);
    if (st.phone) phone(st.phone.url, st.phone.step); else hidePhone();
  }

  function setLive(kind, text) {
    var b = $('live');
    b.className = 'p-badge p-badge--dot ' + (kind === 'live' ? 'is-live' : 'is-down');
    b.textContent = text;
  }

  // ---- steps rail ---------------------------------------------------------
  var LABEL = { pending: 'Not started', running: 'Running', done: 'Done', adopted: 'Adopted',
                unchanged: 'Unchanged', planned: 'Planned (dry run)', skipped: 'Skipped',
                failed: 'Failed', rolled_back: 'Rolled back', 'would-roll-back': 'Would roll back' };
  var DONE = { done: 1, adopted: 1, unchanged: 1, skipped: 1, planned: 1 };

  function renderSteps() {
    var ol = $('steps');
    clear(ol);
    var done = 0, current = null;
    S.steps.forEach(function (s, i) {
      var st = s.status || 'pending';
      if (S.running && s.id === S.activeStep && (st === 'pending' || st === 'rolled_back' || st === 'failed' || DONE[st])) st = 'running';
      if (DONE[st]) done++;
      if (st === 'running' || (S.pending && S.pending.step === s.id)) current = { s: s, i: i };
      var li = el('li', 'w-step w-step--' + st.replace(/[^a-z_]/g, '_'));
      if (current && current.s === s) li.classList.add('is-current');
      li.appendChild(el('span', 'w-step-ico'));
      var main = el('span', 'w-step-main');
      main.appendChild(el('span', 'w-step-name', s.title || s.id));
      var meta = (S.pending && S.pending.step === s.id) ? 'Waiting for you' : (LABEL[st] || st);
      var m = el('span', 'w-step-meta', meta);
      if (st === 'failed' && s.error) {
        m.textContent = 'Failed: ' + (s.error.message || s.error.code || '');
        m.classList.add('is-error');
      }
      main.appendChild(m);
      li.appendChild(main);
      ol.appendChild(li);
    });
    var n = S.steps.length;
    $('rail-count').textContent = done + ' of ' + n;
    $('rail-fill').style.width = (n ? Math.round(100 * done / n) : 0) + '%';
    $('rail-current').textContent = current ? ('Step ' + (current.i + 1) + ': ' + (current.s.title || current.s.id)) : '';
  }

  function setStatus(id, status, error) {
    var s = S.byId[id];
    if (!s) return;
    s.status = status;
    s.error = error || null;
    renderSteps();
  }

  // ---- intro / controls ---------------------------------------------------
  function renderIntro() {
    var anyDone = S.steps.some(function (s) { return s.status === 'done' || s.status === 'adopted'; });
    var anyLeft = S.steps.some(function (s) { return !DONE[s.status] && s.status !== 'adopted'; });
    show($('btn-resume'), anyDone && anyLeft);
    $('btn-run').textContent = anyDone ? 'Run every step' : 'Start setup';
    $('btn-run').className = 'p-btn p-btn--lg' + (anyDone && anyLeft ? ' p-btn--ghost' : '');
    $('btn-resume').className = 'p-btn p-btn--lg';
    ['btn-run', 'btn-resume', 'btn-adopt', 'btn-rollback'].forEach(function (id) { $(id).disabled = S.running; });
    show($('intro'), !S.running && !S.complete);
    show($('busy'), S.running && !S.pending);
    if (S.running && S.run) {
      $('busy-title').textContent = S.run.kind === 'rollback' ? 'Undoing setup' :
        (S.run.mode === 'adopt' ? 'Checking this install' : 'Setting up');
      $('busy-sub').textContent = S.run.dry_run ? 'Dry run: nothing will change.' : 'Leave this page open; it follows along.';
    }
  }

  function startRun(mode) {
    var dry = $('opt-dry').checked;
    $('result').hidden = true;
    api('POST', '/api/run', { mode: mode, dry_run: dry }).then(function (r) {
      if (r.status === 202) { S.running = true; S.run = r.body.started; renderIntro(); return; }
      notice('error', r.body.error || ('Could not start (' + r.status + ')'));
    });
  }

  function rollback() {
    var dry = $('opt-dry').checked;
    askLocal(dry ? 'Show what undoing setup would change?' :
      'Undo every change setup made, newest first? Adopted steps are left alone.', function (yes) {
      if (!yes) return;
      api('POST', '/api/rollback', { dry_run: dry }).then(function (r) {
        if (r.status === 202) { S.running = true; S.run = r.body.started; renderIntro(); return; }
        notice('error', r.body.error || ('Could not start (' + r.status + ')'));
      });
    });
  }

  // ---- prompt -------------------------------------------------------------
  function stepIndex(id) {
    for (var i = 0; i < S.steps.length; i++) if (S.steps[i].id === id) return i;
    return -1;
  }

  function openPrompt(p) {
    S.pending = p;
    if (p.type === 'confirm') { closePromptCard(); openConfirm(p); renderSteps(); renderIntro(); return; }
    var dlg = $('confirm');
    if (dlg.open && dlg.dataset.local !== '1') dlg.close();
    var i = stepIndex(p.step);
    $('prompt-kicker').textContent = (i >= 0 ? 'Step ' + (i + 1) + ' of ' + S.steps.length + ' · ' : '') + (p.title || p.step || '');
    var first = (p.fields && p.fields[0]) || {};
    $('prompt-title').textContent = p.fields && p.fields.length > 1 ? (p.title || 'A few questions') : (first.prompt || 'Your answer');
    var box = $('prompt-fields');
    clear(box);
    (p.fields || []).forEach(function (f) { box.appendChild(renderField(f, p.fields.length > 1)); });
    show($('prompt-error'), false);
    show($('prompt'), true);
    show($('busy'), false);
    $('prompt-submit').disabled = false;
    renderSteps();
    var firstInput = box.querySelector('input:not([disabled]),select');
    if (firstInput && window.matchMedia('(min-width: 720px)').matches) firstInput.focus({ preventScroll: true });
    $('prompt').scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }

  function closePromptCard() { show($('prompt'), false); clear($('prompt-fields')); }

  function closePrompt(id) {
    if (id && S.pending && S.pending.id !== id) return;
    S.pending = null;
    closePromptCard();
    var dlg = $('confirm');
    if (dlg.open && dlg.dataset.local !== '1') dlg.close();
    renderSteps();
    renderIntro();
  }

  function flagHint(f) {
    if (!f.flag && !f.env) return '';
    if (f.kind === 'secret') {
      return 'CLI: ' + (f.flag ? f.flag + ' REF' : '') + (f.env ? (f.flag ? ' or ' : '') + 'env ' + f.env : '');
    }
    if (f.kind === 'bool') return 'CLI: ' + f.flag + ' / --no-' + f.flag.replace(/^--/, '');
    return 'CLI: ' + f.flag + ' ' + f.name.toUpperCase();
  }

  function fieldId(name) { return 'f-' + name.replace(/[^A-Za-z0-9_-]/g, '_'); }

  function renderField(f, showPrompt) {
    var wrap = el('div', 'p-field w-field');
    wrap.dataset.name = f.name;
    wrap.dataset.kind = f.kind;
    var id = fieldId(f.name);
    var label = el('label', 'p-label', showPrompt || f.kind === 'bool' ? f.prompt : (f.kind === 'secret' ? 'Value' : 'Answer'));
    label.htmlFor = id;
    if (!f.required) label.appendChild(el('span', 'w-optional', ' (optional)'));
    var hasCards = f.cards && f.cards.length;

    if (f.kind === 'bool') {
      var sw = el('label', 'w-switch');
      var cb = el('input'); cb.type = 'checkbox'; cb.id = id; cb.checked = !!f.default;
      sw.appendChild(cb);
      sw.appendChild(el('span', 'w-switch-track'));
      sw.appendChild(el('span', '', f.prompt));
      wrap.appendChild(sw);
    } else if (f.kind === 'choice' && hasCards) {
      wrap.appendChild(el('p', 'p-small', 'Porch tested this network. Pick how visitors reach this box:'));
      wrap.appendChild(renderCards(f));
    } else if (f.kind === 'choice' && f.choices && f.choices.length && f.choices.length <= 4) {
      wrap.appendChild(label);
      var seg = el('div', 'w-seg'); seg.setAttribute('role', 'radiogroup');
      f.choices.forEach(function (c, i) {
        var l = el('label');
        var r = el('input'); r.type = 'radio'; r.name = id; r.value = c;
        if (i === 0) r.id = id;
        r.checked = (f.default === c) || (f.default == null && i === 0);
        l.appendChild(r); l.appendChild(el('span', '', c));
        seg.appendChild(l);
      });
      wrap.appendChild(seg);
    } else if (f.kind === 'choice') {
      wrap.appendChild(label);
      var sel = el('select', 'p-select'); sel.id = id;
      (f.choices || []).forEach(function (c) {
        var o = el('option', '', c); o.value = c;
        if (f.default === c) o.selected = true;
        sel.appendChild(o);
      });
      wrap.appendChild(sel);
    } else if (f.kind === 'secret') {
      if (showPrompt) wrap.appendChild(label); else { label.textContent = f.prompt; wrap.appendChild(label); }
      var pw = el('input', 'p-input p-input--mono'); pw.type = 'password'; pw.id = id;
      pw.autocomplete = 'new-password'; pw.spellcheck = false; pw.setAttribute('autocapitalize', 'off');
      pw.dataset.role = 'value';
      var ref = el('input', 'p-input p-input--mono'); ref.type = 'text'; ref.hidden = true;
      ref.placeholder = 'inf://prod/porch/NAME, op://vault/item/field or file://...';
      ref.autocomplete = 'off'; ref.spellcheck = false; ref.setAttribute('autocapitalize', 'off');
      ref.dataset.role = 'ref';
      var tog = el('button', 'w-linkish', 'Use a stored secret (ref) instead'); tog.type = 'button';
      tog.addEventListener('click', function () {
        var toRef = ref.hidden;
        ref.hidden = !toRef; pw.hidden = toRef;
        tog.textContent = toRef ? 'Type the value instead' : 'Use a stored secret (ref) instead';
        (toRef ? ref : pw).focus();
      });
      wrap.appendChild(pw); wrap.appendChild(ref);
      if (f.help) wrap.appendChild(el('p', 'p-help', f.help));
      wrap.appendChild(tog);
      wrap.appendChild(el('p', 'w-secret-note', 'Sent once over this encrypted connection and stored as a ref. Porch never shows it again or writes it to a log.'));
    } else {
      if (!showPrompt) label.textContent = f.prompt;
      wrap.appendChild(label);
      var inp = el('input', 'p-input'); inp.type = 'text'; inp.id = id;
      inp.spellcheck = false; inp.setAttribute('autocapitalize', 'off'); inp.autocomplete = 'off';
      if (f.default !== null && f.default !== undefined) inp.value = String(f.default);
      if (/domain|host|ip|email|user|ref|name/.test(f.name)) inp.classList.add('p-input--mono');
      wrap.appendChild(inp);
    }
    if (f.help && !hasCards && f.kind !== 'secret') {
      var h = el('p', 'p-help' + (f.help.indexOf('\n') >= 0 ? ' w-help-pre' : ''), f.help);
      wrap.appendChild(h);
    }
    var fh = flagHint(f);
    if (fh) wrap.appendChild(el('p', 'w-flag', fh));
    var err = el('p', 'w-field-error'); err.hidden = true; err.setAttribute('role', 'alert');
    wrap.appendChild(err);
    if (f.error) setFieldError(wrap, f.error);
    return wrap;
  }

  var BADGE = { works: ['p-badge--ok', 'Works here'], likely: ['p-badge--wait', 'Likely'],
                unavailable: ['p-badge--danger', 'Not here'], later: ['', 'Coming later'] };

  function renderCards(f) {
    var grid = el('div', 'w-cards'); grid.setAttribute('role', 'radiogroup');
    var name = fieldId(f.name);
    var picked = f.default;
    f.cards.forEach(function (c, i) {
      var selectable = c.built && c.status !== 'unavailable' && c.status !== 'later';
      var l = el('label', 'w-cardopt');
      var r = el('input'); r.type = 'radio'; r.name = name; r.value = c.name;
      if (i === 0) r.id = name;
      r.disabled = !selectable;
      r.checked = selectable && c.name === picked;
      l.appendChild(r);
      var body = el('span', 'w-cardopt-body');
      var top = el('span', 'w-cardopt-top');
      top.appendChild(el('span', 'w-cardopt-name', c.name));
      var badges = el('span', 'w-badges');
      if (c.recommended) badges.appendChild(el('span', 'p-badge p-badge--accent', 'Recommended'));
      var b = BADGE[c.status] || ['', c.status];
      badges.appendChild(el('span', 'p-badge p-badge--dot ' + b[0], b[1]));
      top.appendChild(badges);
      body.appendChild(top);
      body.appendChild(el('span', 'w-cardopt-title', c.title));
      body.appendChild(el('span', 'w-cardopt-reason', c.reason));
      l.appendChild(body);
      grid.appendChild(l);
    });
    return grid;
  }

  function setFieldError(wrap, msg) {
    var e = wrap.querySelector('.w-field-error');
    wrap.classList.toggle('has-error', !!msg);
    e.textContent = msg || '';
    e.hidden = !msg;
  }

  function collect() {
    var out = {};
    var wraps = $('prompt-fields').querySelectorAll('.w-field');
    Array.prototype.forEach.call(wraps, function (w) {
      var name = w.dataset.name, kind = w.dataset.kind;
      setFieldError(w, '');
      if (kind === 'bool') { out[name] = w.querySelector('input').checked; return; }
      if (kind === 'secret') {
        var ref = w.querySelector('[data-role=ref]'), val = w.querySelector('[data-role=value]');
        out[name] = !ref.hidden ? { ref: ref.value } : { value: val.value };
        return;
      }
      var radio = w.querySelector('input[type=radio]:checked');
      if (radio) { out[name] = radio.value; return; }
      if (w.querySelector('input[type=radio]')) { out[name] = ''; return; }
      var sel = w.querySelector('select');
      if (sel) { out[name] = sel.value; return; }
      var t = w.querySelector('input');
      out[name] = t ? t.value : '';
    });
    return out;
  }

  function wipeSecrets() {
    Array.prototype.forEach.call($('prompt-fields').querySelectorAll('input[type=password]'), function (i) { i.value = ''; });
  }

  function submitPrompt(ev) {
    ev.preventDefault();
    var p = S.pending;
    if (!p || p.type !== 'inputs') return;
    $('prompt-submit').disabled = true;
    show($('prompt-error'), false);
    api('POST', '/api/inputs/' + encodeURIComponent(p.step), { prompt: p.id, values: collect() }).then(function (r) {
      $('prompt-submit').disabled = false;
      if (r.status === 200) { wipeSecrets(); closePrompt(p.id); show($('busy'), true); return; }
      if (r.status === 422 && r.body.errors) {
        var first = null;
        Object.keys(r.body.errors).forEach(function (n) {
          var w = $('prompt-fields').querySelector('.w-field[data-name="' + CSS.escape(n) + '"]');
          if (w) { setFieldError(w, r.body.errors[n]); first = first || w; }
          else { $('prompt-error').textContent = r.body.errors[n]; show($('prompt-error'), true); }
        });
        if (first) { var i = first.querySelector('input:not([hidden]),select'); if (i) i.focus(); }
        return;
      }
      $('prompt-error').textContent = r.body.error || ('Something went wrong (' + r.status + ')');
      show($('prompt-error'), true);
      if (r.status === 409) refresh();
    });
  }

  function cancelPrompt() {
    var p = S.pending;
    if (!p) return;
    api('POST', '/api/cancel', { prompt: p.id });
  }

  // ---- confirm dialog -----------------------------------------------------
  var localCb = null;

  function openConfirm(p) {
    var dlg = $('confirm');
    dlg.dataset.local = '0';
    var i = stepIndex(p.step);
    $('confirm-kicker').textContent = i >= 0 ? (S.steps[i].title || p.step) : 'Confirm';
    $('confirm-text').textContent = p.prompt;
    $('confirm-yes').textContent = 'Yes';
    $('confirm-no').textContent = 'No';
    if (!dlg.open) dlg.showModal();
    (p.default ? $('confirm-yes') : $('confirm-no')).focus();
  }

  function askLocal(text, cb) {
    var dlg = $('confirm');
    dlg.dataset.local = '1';
    localCb = cb;
    $('confirm-kicker').textContent = 'Undo setup';
    $('confirm-text').textContent = text;
    $('confirm-yes').textContent = 'Undo';
    $('confirm-no').textContent = 'Keep it';
    if (!dlg.open) dlg.showModal();
    $('confirm-no').focus();
  }

  function answerConfirm(yes) {
    var dlg = $('confirm');
    if (dlg.dataset.local === '1') {
      dlg.dataset.local = '0';
      dlg.close();
      var cb = localCb; localCb = null;
      if (cb) cb(yes);
      if (S.pending && S.pending.type === 'confirm') openConfirm(S.pending);
      return;
    }
    var p = S.pending;
    dlg.close();
    if (!p || p.type !== 'confirm') return;
    api('POST', '/api/confirm', { prompt: p.id, answer: yes }).then(function (r) {
      if (r.status !== 200) refresh();
    });
  }

  // ---- phone check ----------------------------------------------------------
  function phone(url, step) {
    S.phoneStep = step;
    $('phone-url').textContent = url || '';
    var box = $('qr');
    clear(box);
    show($('phone'), true);
    api('GET', '/api/qr').then(function (r) {
      if (r.status !== 200 || !r.body.rows) return;
      box.appendChild(fancyQr(r.body.rows));
    });
  }

  // A porch-styled QR: soft-cornered modules in a warm gradient and the porch
  // mark lit in the middle (the server encodes at level H, so the knocked-out
  // centre is recoverable). The finder "eyes" stay plain modules: custom-drawn
  // eyes, round dots and heavier rounding all failed decode tests.
  function fancyQr(rows) {
    var NS = 'http://www.w3.org/2000/svg';
    var n = rows.length, pad = 3, W = n + pad * 2;
    function el(name, attrs, parent) {
      var e = document.createElementNS(NS, name);
      for (var k in attrs) e.setAttribute(k, attrs[k]);
      if (parent) parent.appendChild(e);
      return e;
    }
    var svg = el('svg', { viewBox: '0 0 ' + W + ' ' + W, role: 'img', 'aria-label': 'QR code' });
    var defs = el('defs', {}, svg);
    var g = el('linearGradient', { id: 'qr-ink', x1: '0', y1: '0', x2: '1', y2: '1' }, defs);
    el('stop', { offset: '0', 'stop-color': '#121014' }, g);
    el('stop', { offset: '0.55', 'stop-color': '#2A1D14' }, g);
    el('stop', { offset: '1', 'stop-color': '#6B3A0A' }, g);
    var glow = el('radialGradient', { id: 'qr-light', cx: '0.5', cy: '0.5', r: '0.5' }, defs);
    el('stop', { offset: '0', 'stop-color': '#FFD27A' }, glow);
    el('stop', { offset: '1', 'stop-color': '#E08A0B' }, glow);
    el('rect', { x: 0, y: 0, width: W, height: W, rx: 3.2, fill: '#FBF7F1' }, svg);

    // centre knockout for the mark: ~22% of the width, on whole modules
    var k = Math.max(5, Math.round(n * 0.22)); if (k % 2 !== n % 2) k++;
    var k0 = (n - k) / 2;
    function inLogo(x, y) { return x >= k0 - 0.5 && x < k0 + k + 0.5 && y >= k0 - 0.5 && y < k0 + k + 0.5; }

    var d = '', r0 = 0.18;
    for (var y = 0; y < n; y++) {
      for (var x = 0; x < n; x++) {
        if (rows[y].charAt(x) !== '1' || inLogo(x, y)) continue;
        var X = x + pad, Y = y + pad;
        d += 'M' + (X + r0) + ' ' + Y + 'h' + (1 - 2 * r0) + 'a' + r0 + ' ' + r0 + ' 0 0 1 ' + r0 + ' ' + r0 +
             'v' + (1 - 2 * r0) + 'a' + r0 + ' ' + r0 + ' 0 0 1 ' + (-r0) + ' ' + r0 +
             'h' + (2 * r0 - 1) + 'a' + r0 + ' ' + r0 + ' 0 0 1 ' + (-r0) + ' ' + (-r0) +
             'v' + (2 * r0 - 1) + 'a' + r0 + ' ' + r0 + ' 0 0 1 ' + r0 + ' ' + (-r0) + 'z';
      }
    }
    el('path', { d: d, fill: 'url(#qr-ink)' }, svg);

    // the porch mark: house outline with the light in the door
    var lx = k0 + pad, s = k;
    el('rect', { x: lx - 0.3, y: lx - 0.3, width: s + 0.6, height: s + 0.6, rx: s * 0.26, fill: '#FBF7F1' }, svg);
    var mark = el('g', { transform: 'translate(' + lx + ' ' + lx + ') scale(' + (s / 64) + ')' }, svg);
    var line = { fill: 'none', stroke: '#121014', 'stroke-width': 5.5, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' };
    el('path', Object.assign({ d: 'M10 31 L32 12 L54 31' }, line), mark);
    el('path', Object.assign({ d: 'M17 29 V53 H47 V29' }, line), mark);
    el('circle', { cx: 32, cy: 23, r: 9, fill: '#F5A524', opacity: 0.28, 'class': 'w-qr-halo' }, mark);
    el('circle', { cx: 32, cy: 23, r: 5.5, fill: 'url(#qr-light)' }, mark);
    return svg;
  }

  function hidePhone(step) {
    if (S.phoneStep && step && S.phoneStep !== step) return;
    show($('phone'), false);
    S.phoneStep = null;
  }

  // ---- result -----------------------------------------------------------------
  function safeUrl(u) {
    try { var x = new URL(u); return x.protocol === 'https:' ? x.href : null; } catch (e) { return null; }
  }

  function notice(kind, text, extra) {
    var box = $('result');
    clear(box);
    var n = el('div', 'p-notice p-notice--' + kind);
    var body = el('div', 'w-notice-body');
    body.appendChild(el('strong', '', text));
    if (extra) extra(body);
    n.appendChild(body);
    box.appendChild(n);
    show(box, true);
  }

  var URL_LABELS = [['landing', 'Landing page'], ['admin', 'Admin sign-in'], ['panel', 'Tunnel panel'],
                    ['pocket', 'Porch app (Pocket)'], ['tunnel_example', 'Your apps live at']];

  // "Your porch is ready": the live URLs, a big QR that puts Porch on the
  // owner's phone (scan, sign in, install) and the first command to try.
  function renderReady(res) {
    var box = $('result');
    clear(box);
    hidePhone();
    var ready = res.ready || S.ready || {};
    var c = el('div', 'p-card w-done');
    c.appendChild(el('p', 'p-kicker', 'Setup complete'));
    c.appendChild(el('h2', 'p-title', 'Your porch is ready.'));
    c.appendChild(el('p', 'p-lede', 'Every step is done and verified. Put Porch on your phone, then open your first door. This wizard closes itself in a few minutes.'));

    var signin = safeUrl(ready.pocket_signin);
    if (signin) {
      var ph = el('div', 'w-ready-phone');
      var qr = el('div', 'w-qr w-qr--big');
      qr.setAttribute('aria-hidden', 'true');
      ph.appendChild(qr);
      var txt = el('div', 'w-ready-text');
      txt.appendChild(el('p', 'p-kicker', 'Scan with your phone'));
      txt.appendChild(el('h3', 'p-h2', 'Porch in your pocket'));
      var ol = el('ol', 'w-ready-steps');
      (ready.steps || []).forEach(function (s) { ol.appendChild(el('li', '', s)); });
      txt.appendChild(ol);
      var a = el('a', 'w-url p-mono', signin); a.href = signin; a.target = '_blank'; a.rel = 'noopener noreferrer';
      txt.appendChild(a);
      ph.appendChild(txt);
      c.appendChild(ph);
      api('GET', '/api/qr?for=ready').then(function (r) {
        if (r.status !== 200 || !r.body.rows) return;
        qr.appendChild(fancyQr(r.body.rows));
      });
    }

    var ul = el('ul', 'w-urls');
    var urls = res.urls && Object.keys(res.urls).length ? res.urls : S.urls;
    URL_LABELS.forEach(function (p) {
      var u = safeUrl(urls[p[0]]);
      if (!u) return;
      var li = el('li');
      li.appendChild(el('span', 'p-small', p[1]));
      var a = el('a', '', u); a.href = u; a.target = '_blank'; a.rel = 'noopener noreferrer';
      li.appendChild(a);
      ul.appendChild(li);
    });
    c.appendChild(ul);

    var next = ready.next || [];
    if (next.length) {
      var nx = el('div', 'w-next');
      nx.appendChild(el('p', 'p-kicker', 'Next: open your first door'));
      next.forEach(function (n) {
        var row = el('div', 'w-next-row');
        row.appendChild(el('span', 'p-small', n.label));
        row.appendChild(el('code', 'w-next-cmd', n.command));
        nx.appendChild(row);
      });
      c.appendChild(nx);
    }
    box.appendChild(c);
    show(box, true);
    show($('intro'), false);
  }

  function renderResult(res) {
    if (res.complete || (res.ok && res.kind === 'run' && !res.dry_run && S.complete)) {
      renderReady(res);
      return;
    }
    if (res.ok) {
      var what = res.kind === 'rollback' ? (res.dry_run ? 'Dry run: this is what undoing would change.' : 'Setup was undone.')
        : res.dry_run ? 'Dry run finished. Nothing was changed.'
        : res.mode === 'adopt' ? 'This install checks out. Every step was adopted.'
        : 'All steps ran.';
      notice('ok', what);
      return;
    }
    var e = res.error || {};
    notice('error', (res.failed_step ? (stepTitle(res.failed_step) + ' failed') : 'The run stopped') + (e.code ? ' (' + e.code + ')' : ''), function (body) {
      if (e.message) body.appendChild(el('span', '', e.message));
      if (e.hint) body.appendChild(el('span', 'p-small', 'Hint: ' + e.hint));
      if (res.missing && res.missing.length) body.appendChild(el('span', 'p-small', 'Missing: ' + res.missing.join(' ')));
      var acts = el('div', 'w-actions');
      var again = el('button', 'p-btn p-btn--sm', 'Try again'); again.type = 'button';
      again.addEventListener('click', function () { startRun(res.mode === 'adopt' ? 'adopt' : 'resume'); });
      acts.appendChild(again);
      body.appendChild(acts);
    });
  }

  function stepTitle(id) { var s = S.byId[id]; return s ? (s.title || id) : id; }

  // ---- activity log -------------------------------------------------------------
  var MAX_LOG = 600;

  function logRow(cls, ico, code, msg, hint) {
    var ol = $('log');
    var li = el('li', cls);
    li.appendChild(el('span', 'w-ln-ico', ico));
    var main = el('span', 'w-ln-main');
    if (code) main.appendChild(el('span', 'w-ln-code', code));
    main.appendChild(el('span', 'w-ln-msg', msg));
    if (hint) main.appendChild(el('span', 'w-ln-hint', 'Hint: ' + hint));
    li.appendChild(main);
    ol.appendChild(li);
    while (ol.childNodes.length > MAX_LOG) ol.removeChild(ol.firstChild);
    show($('log-empty'), false);
    if (!replaying) li.scrollIntoView({ block: 'nearest' });
  }

  var replaying = false;
  var lastFail = {};

  function handle(name, d) {
    switch (name) {
      case 'run_started':
        logRow('is-run', '▸', '', (d.kind === 'rollback' ? 'Undo' : d.mode === 'adopt' ? 'Check install' : d.mode === 'resume' ? 'Continue setup' : 'Setup run') + (d.dry_run ? ' (dry run)' : ''));
        if (!replaying) { S.running = true; S.run = d; show($('result'), false); hidePhone(); renderIntro(); }
        break;
      case 'step_started':
        delete lastFail[d.step];
        logRow('is-step', '●', '', d.title || d.step);
        if (!replaying) { S.activeStep = d.step; setStatus(d.step, 'running'); }
        break;
      case 'check':
        if (d.ok) logRow('is-ok', '✓', d.code, d.message);
        else { (lastFail[d.step] = lastFail[d.step] || {})[d.code] = 1; logRow('is-fail', '✗', d.code, d.message, d.hint); }
        break;
      case 'action':
        logRow('is-action', '→', d.kind, d.target + (d.detail ? '  ' + d.detail : ''));
        break;
      case 'step_done':
        if (!replaying) { setStatus(d.step, d.status === 'would-roll-back' ? 'planned' : d.status); hidePhone(d.step); }
        if (d.status === 'skipped') logRow('is-debug', '–', '', 'Skipped: not needed here');
        break;
      case 'step_failed':
        if (!replaying) { setStatus(d.step, 'failed', d); hidePhone(d.step); }
        // The failing check is already in the log; say only which phase stopped.
        if (lastFail[d.step] && lastFail[d.step][d.code]) logRow('is-error', '!', '', stepTitle(d.step) + ' failed (' + d.phase + ')');
        else logRow('is-error', '!', d.code, 'Failed (' + d.phase + '): ' + d.message, d.hint);
        delete lastFail[d.step];
        break;
      case 'log':
        if (d.level === 'error') break;
        logRow(d.level === 'warn' ? 'is-warn' : d.level === 'debug' ? 'is-debug' : 'is-info',
               d.level === 'warn' ? '!' : '·', '', d.message);
        break;
      case 'phone_check':
        if (!replaying) phone(d.url, d.step);
        break;
      case 'prompt':
        if (!replaying) openPrompt(d);
        break;
      case 'prompt_closed':
        if (!replaying) closePrompt(d.id);
        break;
      case 'done':
        if (d.summary) logRow(d.ok ? 'is-ok is-final' : 'is-error', d.ok ? '✓' : '!', '', d.summary);
        break;
      case 'run_finished':
        if (!replaying) {
          S.running = false;
          if (d.complete) { S.complete = true; S.urls = d.urls || S.urls; S.ready = d.ready || S.ready; }
          renderResult(d); refresh();
        }
        break;
    }
  }

  function connect() {
    if (S.es) S.es.close();
    var es = new EventSource('/api/events?since=' + S.lastSeq);
    S.es = es;
    es.addEventListener('open', function () { setLive('live', 'Live'); });
    es.addEventListener('error', function () {
      setLive('down', 'Reconnecting');
      if (es.readyState === 2) setTimeout(function () { refresh().then(connect).catch(function () {}); }, 3000);
    });
    es.addEventListener('porch', function (ev) {
      var seq = parseInt(ev.lastEventId, 10) || 0;
      if (seq <= S.lastSeq) return;
      S.lastSeq = seq;
      var m;
      try { m = JSON.parse(ev.data); } catch (e) { return; }
      // Events up to the state snapshot only rebuild the log: /api/state
      // already gave the statuses, the open prompt and the last result.
      replaying = seq <= S.replayUntil;
      handle(m.name, m.data || {});
      replaying = false;
    });
  }

  // ---- wiring -------------------------------------------------------------------
  document.addEventListener('DOMContentLoaded', function () {
    $('btn-run').addEventListener('click', function () { startRun('run'); });
    $('btn-resume').addEventListener('click', function () { startRun('resume'); });
    $('btn-adopt').addEventListener('click', function () { startRun('adopt'); });
    $('btn-rollback').addEventListener('click', rollback);
    $('prompt-form').addEventListener('submit', submitPrompt);
    $('prompt-cancel').addEventListener('click', cancelPrompt);
    $('confirm-yes').addEventListener('click', function () { answerConfirm(true); });
    $('confirm-no').addEventListener('click', function () { answerConfirm(false); });
    $('confirm').addEventListener('cancel', function (ev) { ev.preventDefault(); answerConfirm(false); });
    var all = $('opt-all');
    var log = $('log');
    log.classList.add('hide-ok');
    all.addEventListener('change', function () { log.classList.toggle('hide-ok', !all.checked); });
    if (window.matchMedia('(max-width: 959px)').matches) $('rail').open = false;
    start();
  });
})();

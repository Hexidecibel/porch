/* "Install Porch": put the app on the home screen.
 *
 * Android and desktop Chrome/Edge: the browser's beforeinstallprompt event is
 * kept, and only then an Install button shows; a tap calls prompt(), and
 * appinstalled hides it. iPhone/iPad (iPadOS reports MacIntel with touch
 * points): Safari gets "tap Share, then Add to Home Screen"; other iOS
 * browsers (Chrome, Firefox, Edge, in-app views) get "open this in Safari".
 * Nothing when already running standalone, on other browsers, or after the
 * Home card was dismissed (localStorage, best effort). All text via
 * textContent. Home and You > About call P.installCard(). */
'use strict';
(function(){
  const P = window.Porch;
  const {el, icon} = P;
  const KEY = 'porch.install.dismissed';
  let deferred = null;

  function standalone(){
    try{
      if(window.matchMedia && (matchMedia('(display-mode: standalone)').matches
         || matchMedia('(display-mode: fullscreen)').matches || matchMedia('(display-mode: minimal-ui)').matches)) return true;
    }catch(e){}
    return navigator.standalone === true;
  }
  function isIOS(){
    const ua = navigator.userAgent || '';
    return /iPhone|iPad|iPod/.test(ua) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  }
  // Safari proper: every iOS browser says "Safari" in its UA, the others add their own token.
  function iosSafari(){
    const ua = navigator.userAgent || '';
    return /Safari\//.test(ua) && !/CriOS|FxiOS|EdgiOS|OPiOS|OPT\/|GSA\/|YaBrowser|DuckDuckGo|Brave|FBAN|FBAV|Instagram|Line\/|MicroMessenger|Snapchat|Twitter/.test(ua);
  }
  function dismissed(){ try{ return localStorage.getItem(KEY) === '1'; }catch(e){ return false; } }
  function dismiss(){ try{ localStorage.setItem(KEY, '1'); }catch(e){} P.emit('install', state()); }

  /* 'prompt' | 'ios-safari' | 'ios-other' | null */
  function state(){
    if(standalone()) return null;
    if(deferred) return 'prompt';
    if(isIOS()) return iosSafari() ? 'ios-safari' : 'ios-other';
    return null;
  }

  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();            // our button, not the mini-infobar
    deferred = e;
    P.emit('install', state());
  });
  window.addEventListener('appinstalled', () => {
    deferred = null;
    P.installed = true;
    P.emit('install', null);
  });

  function install(btn){
    const ev = deferred;
    if(!ev) return;
    btn.disabled = true;
    Promise.resolve(ev.prompt()).then(() => ev.userChoice).then((choice) => {
      // A prompt can be used once; Chrome fires a new event if it may ask again.
      deferred = null;
      if(choice && choice.outcome === 'accepted') P.toast('Installing Porch…');
      P.emit('install', state());
    }).catch(() => { btn.disabled = false; });
  }

  function step(...parts){
    const li = el('li');
    parts.forEach((p) => li.append(typeof p === 'string' ? document.createTextNode(p) : p));
    return li;
  }
  function chip(name, text){
    const b = el('b', 'install-chip');
    b.append(icon(name), document.createTextNode(text));
    return b;
  }

  function body(st, where){
    const card = el('div', 'card card--accent install-card');
    card.dataset.install = st;
    const head = el('div', 'card-head');
    const title = el('div', 'card-title');
    title.append(icon('phone'), el('span', '', st === 'ios-other' ? 'Install from Safari' : 'Install Porch'));
    head.append(title);
    if(where === 'home'){
      const x = P.btn('', 'p-btn p-btn--quiet p-btn--sm install-x', () => dismiss(), {icon:'x', aria:'Hide this'});
      head.append(x);
    }
    card.append(head);
    if(st === 'prompt'){
      card.append(el('p', 'card-sub', 'Add Porch to your home screen: it opens like an app, in its own window, and shows up in the share sheet.'));
      const acts = el('div', 'actions');
      acts.append(P.btn('Install Porch', 'p-btn', (e, b) => install(b), {icon:'plus'}));
      card.append(acts);
    }else if(st === 'ios-safari'){
      card.append(el('p', 'card-sub', 'Put Porch on your home screen so it opens like an app (and can send you notifications).'));
      const ol = el('ol', 'ios-steps install-steps');
      ol.append(step('Tap ', chip('share', 'Share'), ' in Safari’s toolbar.'),
                step('Scroll down and tap ', chip('plus', 'Add to Home Screen'), '.'),
                step('Tap ', el('b', '', 'Add'), ', then open Porch from your home screen.'));
      card.append(ol);
    }else{
      card.append(el('p', 'card-sub', 'On iPhone and iPad only Safari can add Porch to the home screen. Open this page in Safari to install it.'));
      const acts = el('div', 'actions');
      const copy = P.btn('Copy link', 'p-btn p-btn--ghost p-btn--sm', () => {
        const url = location.origin + '/';
        const done = () => P.toast('Link copied. Paste it into Safari.');
        try{ navigator.clipboard.writeText(url).then(done, () => {}); }catch(e){}
      }, {icon:'copy'});
      acts.append(copy);
      card.append(acts);
    }
    return card;
  }

  /* A live slot: redraws on install events. where: 'home' (dismissible) | 'about'. */
  P.installCard = function(where){
    const slot = el('div', 'install-slot');
    const draw = () => {
      const st = state();
      const show = st && !(where === 'home' && dismissed());
      slot.hidden = !show;
      slot.replaceChildren(...(show ? [body(st, where)] : []));
    };
    draw();
    const off = P.on('install', draw);
    slot.cleanup = off;
    return slot;
  };
  P.installState = state;
})();

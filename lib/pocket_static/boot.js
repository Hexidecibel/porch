/* Start the app once every screen module has registered its section. */
'use strict';
(function(){
  const P = window.Porch;
  if(!location.hash) history.replaceState(null, '', location.pathname + location.search + '#/home');
  if('serviceWorker' in navigator){ navigator.serviceWorker.register('/sw.js').catch(() => {}); }
  P.render();
  P.loadApp().catch((err) => { if(err && err.code === 'offline') P.setOffline(true); }).then(() => P.render(true));
  P.homeInit();
  P.loadPush();
  // The badge and the door count need these even when another tab is open.
  P.store.requests.load().catch(() => {});
  P.store.doors.load().catch(() => {});
  P.events.connect();
})();

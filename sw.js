/* Nexo — Service Worker */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(
  caches.keys().then(keys => Promise.all(keys.map(k => caches.delete(k))))
    .then(() => self.clients.claim())
));
self.addEventListener('fetch', e => e.respondWith(fetch(e.request)));

/* ── Web Push ── */
self.addEventListener('push', e => {
  if (!e.data) return;
  let d = {};
  try { d = e.data.json(); } catch { d = { title: 'Nexo', body: e.data.text() }; }
  const opts = {
    body:    d.body  || 'Nova mensagem',
    icon:    '/icon-192.png',
    badge:   '/icon-192.png',
    tag:     d.tag   || 'nexo-msg',
    data:    d,
    vibrate: d.type === 'call' ? [200,100,200,100,400] : [200,100,200],
    requireInteraction: !!d.requireInteraction,
    silent: false
  };
  e.waitUntil(self.registration.showNotification(d.title || 'Nexo', opts));
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  const d = e.notification.data || {};
  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      const existing = list.find(c => c.url && c.visibilityState);
      if (existing) {
        existing.focus();
        existing.postMessage({ type: 'NOTIF_TAP', from: d.from, notifType: d.type });
      } else {
        clients.openWindow('/').then(w => {
          if (w) w.postMessage({ type: 'NOTIF_TAP', from: d.from, notifType: d.type });
        });
      }
    })
  );
});

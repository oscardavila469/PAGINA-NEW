self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('push', (event) => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch {}
  const title = data.title || 'Nuevo mensaje';
  const options = {
    body: data.body || '',
    tag: data.tag || 'notas-msg',
    renotify: true,
    icon: '/icon.svg',
    badge: '/icon.svg',
    data: { url: data.url || '/' },
  };
  event.waitUntil(
    (async () => {
      try {
        const list = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
        const visible = list.some((c) => c.visibilityState === 'visible' && (c.focused === undefined || c.focused));
        if (visible) return; // ya lo está viendo en pantalla, no hace falta duplicar el aviso
      } catch {}
      await self.registration.showNotification(title, options);
    })()
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      for (const c of list) if ('focus' in c) return c.focus();
      if (self.clients.openWindow) return self.clients.openWindow(url);
    })
  );
});

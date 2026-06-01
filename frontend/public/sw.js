/*
 * FreeSDN service worker, framework-free (no Workbox).
 *
 * Responsibilities:
 *   1. Make the SPA installable + usable offline: precache the app shell and
 *      serve a cached index.html for navigations when the network is down.
 *   2. Runtime-cache the hashed build assets (/assets/*) cache-first, they are
 *      content-hashed so they never go stale within a build.
 *   3. WebPush: render `push` notifications and route `notificationclick` to the
 *      right in-app URL (focusing an existing tab when possible).
 *
 * Deliberately NEVER touches /api/* (auth + live data must always hit network)
 * or cross-origin requests.
 *
 * Bump CACHE_VERSION to invalidate old caches on the next activate.
 */
const CACHE_VERSION = 'freesdn-v1';
const SHELL_CACHE = `${CACHE_VERSION}-shell`;
const ASSET_CACHE = `${CACHE_VERSION}-assets`;
const SHELL_URLS = ['/', '/index.html', '/favicon.svg', '/manifest.webmanifest'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(SHELL_CACHE)
      .then((cache) => cache.addAll(SHELL_URLS))
      .catch(() => {/* a missing shell URL must not block install */})
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((k) => k !== SHELL_CACHE && k !== ASSET_CACHE)
            .map((k) => caches.delete(k)),
        ),
      )
      .then(() => self.clients.claim()),
  );
});

// Allow the page to tell a waiting SW to take over immediately (update flow).
self.addEventListener('message', (event) => {
  if (event.data === 'SKIP_WAITING') self.skipWaiting();
});

function isAsset(url) {
  return url.origin === self.location.origin && url.pathname.startsWith('/assets/');
}

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  // Never intercept API / websocket / cross-origin traffic.
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/')) return;

  // SPA navigations: network-first, fall back to the cached shell when offline
  // (so a hard refresh / cold open still renders the app, which then hydrates
  // from cache or shows its own offline states).
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request).catch(() =>
        caches.match('/index.html').then((cached) => cached || caches.match('/')),
      ),
    );
    return;
  }

  // Hashed build assets: cache-first (immutable within a build), revalidate in
  // the background so a new deploy's assets get cached on next visit.
  if (isAsset(url)) {
    event.respondWith(
      caches.open(ASSET_CACHE).then(async (cache) => {
        const cached = await cache.match(request);
        const network = fetch(request)
          .then((resp) => {
            if (resp.ok) cache.put(request, resp.clone());
            return resp;
          })
          .catch(() => cached);
        return cached || network;
      }),
    );
  }
});

// ── WebPush ────────────────────────────────────────────────────────────────
self.addEventListener('push', (event) => {
  let payload = {};
  try {
    payload = event.data ? event.data.json() : {};
  } catch {
    payload = { title: 'FreeSDN', body: event.data ? event.data.text() : '' };
  }
  const title = payload.title || 'FreeSDN alert';
  const options = {
    body: payload.body || '',
    icon: payload.icon || '/icon.svg',
    badge: '/favicon.svg',
    tag: payload.tag || undefined,
    timestamp: payload.timestamp || undefined,
    renotify: Boolean(payload.tag),
    data: { url: payload.url || '/cameras/events' },
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const target = (event.notification.data && event.notification.data.url) || '/cameras/events';
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clients) => {
      // Focus an existing tab on the same origin (and navigate it) if present.
      for (const client of clients) {
        if (new URL(client.url).origin === self.location.origin && 'focus' in client) {
          client.navigate(target).catch(() => {});
          return client.focus();
        }
      }
      return self.clients.openWindow(target);
    }),
  );
});

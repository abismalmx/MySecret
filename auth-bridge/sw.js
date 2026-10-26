/**
 * MySecret WebAuthn Bridge - Offline Service Worker
 * Ensures the bridge page functions 100% offline once loaded.
 *
 * SECURITY
 * --------
 * The cache name embeds the PROTOCOL VERSION. When the protocol changes (and
 * with it the cryptographic guarantees), the old cache is dropped, so a device
 * can never keep serving a STALE, weaker build of the bridge.
 *
 * Only same-origin GET requests are ever cached: a cross-origin response
 * must never be stored in a cache the page controls.
 */

const CACHE_VERSION = 'v3';
const CACHE_NAME = `mysecret-auth-${CACHE_VERSION}`;
const ASSETS_TO_CACHE = [
  './',
  './index.html',
  './style.css',
  './auth.js',
  './manifest.json'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS_TO_CACHE);
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          // Delete every cache that does not belong to the current version.
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  // Only handle GET requests
  if (event.request.method !== 'GET') return;

  const requestUrl = new URL(event.request.url);

  // SECURITY: never cache a cross-origin response. Only the assets of this
  // origin are stored in the cache.
  if (requestUrl.origin !== self.location.origin) return;

  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      if (cachedResponse) {
        // Fetch fresh in background (stale-while-revalidate)
        fetch(event.request).then((networkResponse) => {
          if (networkResponse && networkResponse.status === 200) {
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, networkResponse));
          }
        }).catch(() => {/* Ignore offline fetch errors */});
        return cachedResponse;
      }

      return fetch(event.request).catch(() => {
        // Return the cached index.html for navigation if available
        if (event.request.mode === 'navigate') {
          return caches.match('./index.html');
        }
        return new Response('Recurso no disponible sin conexión.', {
          status: 503,
          headers: { 'Content-Type': 'text/plain; charset=utf-8' }
        });
      });
    })
  );
});

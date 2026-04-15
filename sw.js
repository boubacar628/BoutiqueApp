/* =============================================
   BoutiqueApp — Service Worker v2.0
   Cache-First · 100% Offline · Path-agnostic
   ============================================= */
'use strict';

const CACHE_NAME = 'bapp-v2.1';

/* Assets locaux à mettre en cache — chemins relatifs au SW */
const LOCAL_ASSETS = [
  './',
  './index.html',
  './style.css',
  './script.js',
  './sw.js',
];

/* CDN assets */
const CDN_ASSETS = [
  'https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=DM+Sans:wght@400;500&display=swap',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css',
];

/* ---- INSTALL ---- */
self.addEventListener('install', event => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    // Cache local assets strictly
    await cache.addAll(LOCAL_ASSETS);
    // Cache CDN assets best-effort
    await Promise.allSettled(CDN_ASSETS.map(url =>
      fetch(url, { mode: 'cors', credentials: 'omit' })
        .then(res => { if (res.ok) cache.put(url, res); })
        .catch(() => {})
    ));
    return self.skipWaiting();
  })());
});

/* ---- ACTIVATE ---- */
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

/* ---- FETCH ---- */
self.addEventListener('fetch', event => {
  const { request } = event;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  if (url.protocol === 'chrome-extension:') return;
  // data: URIs (inline manifest/icons) — let browser handle
  if (url.protocol === 'data:') return;

  event.respondWith(cacheFirst(request));
});

async function cacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) {
    // Background refresh
    fetch(request).then(res => {
      if (res && res.ok) caches.open(CACHE_NAME).then(c => c.put(request, res));
    }).catch(() => {});
    return cached;
  }
  try {
    const res = await fetch(request);
    if (res.ok) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, res.clone());
    }
    return res;
  } catch {
    // Offline fallback
    const fallback = await caches.match('./index.html');
    return fallback || new Response('Hors ligne', { status: 503 });
  }
}

/* ---- MESSAGE ---- */
self.addEventListener('message', event => {
  if (event.data?.type === 'SKIP_WAITING') self.skipWaiting();
});

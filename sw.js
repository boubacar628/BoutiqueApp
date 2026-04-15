/* =============================================
   BoutiqueApp — Service Worker v2.0
   Stratégie : Cache-First pour assets statiques
   Network-First avec fallback pour le reste
   ============================================= */

'use strict';

const CACHE_NAME    = 'bapp-v2.0.0';
const OFFLINE_URL   = './index.html';

/* Tous les assets à mettre en cache immédiatement */
const PRECACHE_ASSETS = [
  './index.html',
  './style.css',
  './script.js',
  './manifest.json',
  './icons/icon-72x72.png',
  './icons/icon-96x96.png',
  './icons/icon-128x128.png',
  './icons/icon-144x144.png',
  './icons/icon-152x152.png',
  './icons/icon-192x192.png',
  './icons/icon-384x384.png',
  './icons/icon-512x512.png',
  './icons/apple-touch-icon.png',
  './icons/icon-maskable-512x512.png',
  './icons/favicon-32x32.png',
  /* CDN Google Fonts */
  'https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=DM+Sans:wght@400;500&display=swap',
  /* FontAwesome */
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css',
];

/* ---- INSTALL : pré-cache de tous les assets ---- */
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(async cache => {
      /* On met en cache les assets locaux de façon stricte */
      const localAssets = PRECACHE_ASSETS.filter(url => url.startsWith('./'));
      await cache.addAll(localAssets);

      /* Pour les CDN, on tente mais on ne bloque pas l'install si réseau absent */
      const cdnAssets = PRECACHE_ASSETS.filter(url => !url.startsWith('./'));
      await Promise.allSettled(cdnAssets.map(url =>
        fetch(url, { mode: 'cors', credentials: 'omit' })
          .then(res => { if (res.ok) cache.put(url, res); })
          .catch(() => {/* CDN indisponible, pas grave */})
      ));
    }).then(() => self.skipWaiting())
  );
});

/* ---- ACTIVATE : suppression des anciens caches ---- */
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(key => key !== CACHE_NAME)
          .map(key => caches.delete(key))
      )
    ).then(() => self.clients.claim())
  );
});

/* ---- FETCH : stratégie intelligente ---- */
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  /* Ignorer les requêtes non-GET et chrome-extension */
  if (request.method !== 'GET') return;
  if (url.protocol === 'chrome-extension:') return;

  /* Stratégie 1 — Assets locaux (HTML, CSS, JS, images) : Cache-First */
  if (url.origin === self.location.origin || url.pathname.startsWith('./')) {
    event.respondWith(cacheFirst(request));
    return;
  }

  /* Stratégie 2 — Google Fonts & FontAwesome CDN : Cache-First avec fallback */
  if (
    url.hostname.includes('fonts.googleapis.com') ||
    url.hostname.includes('fonts.gstatic.com') ||
    url.hostname.includes('cdnjs.cloudflare.com')
  ) {
    event.respondWith(cacheFirst(request));
    return;
  }

  /* Stratégie 3 — Tout le reste : Network-First avec fallback cache */
  event.respondWith(networkFirst(request));
});

/* Cache-First : cache → réseau → mise à jour en arrière-plan */
async function cacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) {
    /* Revalidation en arrière-plan (stale-while-revalidate) */
    updateCache(request);
    return cached;
  }
  return networkFallback(request);
}

/* Network-First : réseau → cache → offline page */
async function networkFirst(request) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    const cached = await caches.match(request);
    return cached || caches.match(OFFLINE_URL);
  }
}

async function networkFallback(request) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    return caches.match(OFFLINE_URL);
  }
}

async function updateCache(request) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, response);
    }
  } catch {/* Silencieux */}
}

/* ---- MESSAGE : force update depuis l'app ---- */
self.addEventListener('message', event => {
  if (event.data?.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

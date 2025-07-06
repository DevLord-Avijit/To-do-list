const CACHE_NAME = 'task-scheduler-cache-v2';
const STATIC_ASSETS = [
  '/',
  '/summary',
  '/login',
  '/manifest.json',
  '/static/icon-192.png',
  '/static/icon-512.png',
  '/static/images.png'
  // Add more static assets (CSS, JS) if needed
];

// Install: cache static assets only (do not block install on navigation pages)
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(STATIC_ASSETS))
  );
  self.skipWaiting();
});

// Activate: clean up old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.filter(key => key !== CACHE_NAME)
            .map(key => caches.delete(key))
      )
    )
  );
  self.clients.claim();
});

// Fetch: network first for navigation (HTML), cache first for static assets
self.addEventListener('fetch', event => {
  const req = event.request;

  // Handle navigation requests (HTML pages)
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req)
        .then(response => {
          // Optionally, cache the page for offline use
          const resClone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(req, resClone));
          return response;
        })
        .catch(() => caches.match(req).then(res => res || caches.match('/')))
    );
    return;
  }

  // For static assets: cache first, then network
  event.respondWith(
    caches.match(req).then(res => res || fetch(req))
  );
});

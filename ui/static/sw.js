/*
 * Olympus Debug Console — Service Worker
 *
 * Provides offline caching so the PWA launches instantly on Android
 * even when the network is unavailable.
 */

const CACHE_NAME = "olympus-v1";

const PRE_CACHE = [
  "/",
  "/manifest.json",
  "/static/icon.svg",
  "/static/icon-192.png",
  "/static/icon-512.png",
];

/* --- Install: pre-cache shell assets --- */
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(PRE_CACHE))
  );
  self.skipWaiting();
});

/* --- Activate: purge old caches --- */
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))
      )
    )
  );
  self.clients.claim();
});

/* --- Fetch: network-first with cache fallback --- */
self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") return;

  event.respondWith(
    fetch(event.request)
      .then((response) => {
        const clone = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
        return response;
      })
      .catch(() =>
        caches.match(event.request).then((cached) =>
          cached || new Response("Offline", { status: 503, statusText: "Service Unavailable" })
        )
      )
  );
});

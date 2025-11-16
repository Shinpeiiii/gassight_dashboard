// static/service-worker.js

const CACHE_NAME = "gassight-cache-v7";

// We serve this built-in fallback page instead of your missing /offline route
const OFFLINE_FALLBACK = "/offline.html";

const OFFLINE_URLS = [
  "/",
  "/login",
  "/dashboard",
  OFFLINE_FALLBACK,
  "/static/manifest.json",
  "/static/icons/icon-192.png",
  "/static/icons/icon-512.png"
];

// INSTALL — PRE-CACHE CORE FILES
self.addEventListener("install", (event) => {
  console.log("[SW] Installing...");
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(OFFLINE_URLS))
  );
  self.skipWaiting();
});

// ACTIVATE — REMOVE OLD CACHES
self.addEventListener("activate", (event) => {
  console.log("[SW] Activating...");
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// FETCH HANDLER
self.addEventListener("fetch", (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Ignore extension requests
  if (url.protocol.startsWith("chrome-extension")) return;
  if (request.method !== "GET") return;

  // ---- API REPORTS CACHE ----
  if (url.pathname.startsWith("/api/reports")) {
    event.respondWith(
      fetch(request)
        .then((res) => {
          const clone = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
          return res;
        })
        .catch(() => caches.match(request))
    );
    return;
  }

  // ---- Don't cache write API routes ----
  if (url.pathname.startsWith("/api/")) {
    event.respondWith(fetch(request).catch(() => caches.match(OFFLINE_FALLBACK)));
    return;
  }

  // ---- Cache-first for static files ----
  event.respondWith(
    caches.match(request).then((cached) => {
      if (cached) {
        return cached;
      }

      return fetch(request)
        .then((res) => {
          if (res.status === 200) {
            const clone = res.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
          }
          return res;
        })
        .catch(() => {
          // If navigation fails → show offline page
          if (request.mode === "navigate") {
            return caches.match(OFFLINE_FALLBACK);
          }
        });
    })
  );
});

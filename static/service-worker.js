const CACHE_NAME = "gassight-cache-v1";
const OFFLINE_FALLBACK = "/offline.html";

const OFFLINE_URLS = [
  "/",
  "/login",
  OFFLINE_FALLBACK,
  "/static/manifest.json",
  "/static/images/snail-logo.png",
];

// INSTALL
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(OFFLINE_URLS))
  );
  self.skipWaiting();
});

// ACTIVATE
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// FETCH
self.addEventListener("fetch", (event) => {
  const req = event.request;
  const url = new URL(req.url);

  if (url.protocol.startsWith("chrome-extension")) return;
  if (req.method !== "GET") return;

  // cache + network for reports
  if (url.pathname.startsWith("/api/reports")) {
    event.respondWith(
      fetch(req)
        .then((res) => {
          caches.open(CACHE_NAME).then((cache) => cache.put(req, res.clone()));
          return res;
        })
        .catch(() => caches.match(req))
    );
    return;
  }

  if (url.pathname.startsWith("/api/")) {
    event.respondWith(
      fetch(req).catch(() => caches.match(OFFLINE_FALLBACK))
    );
    return;
  }

  event.respondWith(
    caches.match(req).then((cached) => {
      if (cached) return cached;

      return fetch(req)
        .then((res) => {
          if (res.status === 200) {
            caches.open(CACHE_NAME).then((cache) => cache.put(req, res.clone()));
          }
          return res;
        })
        .catch(() => {
          if (req.mode === "navigate") {
            return caches.match(OFFLINE_FALLBACK);
          }
        });
    })
  );
});

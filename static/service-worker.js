const CACHE_NAME = "gassight-cache-v4";
const OFFLINE_FALLBACK = "/offline";

// Only static assets should be pre-cached (not APIs)
const OFFLINE_URLS = [
  "/",
  "/dashboard",
  OFFLINE_FALLBACK,
  "/static/manifest.json",
  "/static/icons/icon-192.png",
  "/static/icons/icon-512.png",
  "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css",
  "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js",
  "https://cdn.jsdelivr.net/npm/chart.js@4.3.0/dist/chart.umd.min.js",
  "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css",
  "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js",
  "https://unpkg.com/leaflet.heat/dist/leaflet-heat.js",
  "https://cdn-icons-png.flaticon.com/512/616/616408.png"
];

self.addEventListener("install", (event) => {
  console.log("[Service Worker] Installing...");
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(OFFLINE_URLS)));
});

self.addEventListener("activate", (event) => {
  console.log("[Service Worker] Activating...");
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );

  // 🔄 Optional: auto-refresh open tabs when new SW version activates
  self.clients.matchAll({ includeUncontrolled: true }).then(clients => {
    clients.forEach(client => client.navigate(client.url));
  });
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  // 🚫 Never cache dynamic API data
  if (url.pathname.startsWith("/api/")) {
    event.respondWith(
      fetch(event.request)
        .then(response => response)
        .catch(() => caches.match(OFFLINE_FALLBACK))
    );
    return;
  }

  // ✅ For static assets, use cache-first strategy
  event.respondWith(
    caches.match(event.request).then(cached => {
      return (
        cached ||
        fetch(event.request)
          .then(response => {
            const clone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
            return response;
          })
          .catch(() => {
            if (event.request.mode === "navigate") {
              return caches.match(OFFLINE_FALLBACK);
            }
          })
      );
    })
  );
});

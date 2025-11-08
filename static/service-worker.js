const CACHE_NAME = "gassight-cache-v6";
const OFFLINE_FALLBACK = "/offline";

const OFFLINE_URLS = [
  "/",
  "/dashboard", // ✅ cache admin dashboard
  OFFLINE_FALLBACK,
  "/static/manifest.json",
  "/static/icons/icon-192.png",
  "/static/icons/icon-512.png",
  "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css",
  "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js",
  "https://cdn.jsdelivr.net/npm/chart.js@4.3.0/dist/chart.umd.min.js",
  "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css",
  "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js",
  "https://unpkg.com/leaflet.heat/dist/leaflet-heat.js"
];

self.addEventListener("install", (event) => {
  console.log("[Service Worker] Installing...");
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(OFFLINE_URLS)));
});

self.addEventListener("activate", (event) => {
  console.log("[Service Worker] Activating...");
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );

  // 🔄 Refresh open tabs when new SW activates
  self.clients.matchAll({ includeUncontrolled: true }).then((clients) => {
    clients.forEach((client) => client.navigate(client.url));
  });
});

self.addEventListener("fetch", (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Ignore Chrome extension / dev requests
  if (url.origin.includes("chrome-extension")) return;

  // 🚫 Don’t cache API calls
  if (url.pathname.startsWith("/api/")) {
    event.respondWith(
      fetch(request).catch(() => caches.match(OFFLINE_FALLBACK))
    );
    return;
  }

  // ✅ Cache-first for static and dashboard routes
  event.respondWith(
    caches.match(request).then((cached) => {
      return (
        cached ||
        fetch(request)
          .then((response) => {
            // only cache GET requests (avoid POST / PUT)
            if (request.method === "GET" && response.status === 200) {
              const clone = response.clone();
              caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
            }
            return response;
          })
          .catch(() => {
            if (request.mode === "navigate") {
              return caches.match(OFFLINE_FALLBACK);
            }
          })
      );
    })
  );
});

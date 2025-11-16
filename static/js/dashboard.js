/**************************************************
 * GASsight — Dashboard.js (Infestation-aware)
 * - Province → Municipality → Barangay filters
 * - Severity + Infestation type filters
 * - Leaflet map + heatmap with per-type icons
 **************************************************/

let map, markersLayer, heatLayer;
let allReports = [];

let severityChart, barangayChart, trendChart;

/* ============================
   FETCH HELPER
============================ */
async function fetchJSON(url) {
  try {
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) throw new Error("HTTP " + res.status);
    return await res.json();
  } catch (err) {
    console.error("Fetch error:", err);
    return null;
  }
}

/* ============================
   INITIAL LOAD
============================ */
window.addEventListener("load", () => {
  initMap();
  loadProvinceDropdown();
  loadReports(); // full load

  ["severityFilter", "startDate", "endDate"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.onchange = applyFilters;
  });

  const brgySel = document.getElementById("barangayFilter");
  if (brgySel) brgySel.onchange = applyFilters;

  const typeSel = document.getElementById("infestationFilter");
  if (typeSel) typeSel.onchange = applyFilters;

  const filterBtn = document.getElementById("filterBtn");
  if (filterBtn) filterBtn.onclick = applyFilters;

  const manualRefresh = document.getElementById("manualRefresh");
  if (manualRefresh) manualRefresh.onclick = () => loadReports();

  const refreshInterval = document.getElementById("refreshInterval");
  if (refreshInterval) {
    refreshInterval.onchange = function () {
      const val = this.value;
      if (window.refreshTimer) clearInterval(window.refreshTimer);
      if (val !== "off") window.refreshTimer = setInterval(loadReports, val * 1000);
    };
  }
});

/* ==========================================================================
   3-LEVEL CASCADING LOCATION FILTERS (Province → Municipality → Barangay)
========================================================================== */
async function loadProvinceDropdown() {
  const container = document.querySelector(".card-body.row");
  if (!container) return;

  // Province dropdown
  if (!document.getElementById("provinceFilter")) {
    container.insertAdjacentHTML(
      "afterbegin",
      `
      <div class="col-md-3">
        <label class="form-label fw-semibold">Province</label>
        <select id="provinceFilter" class="form-select">
          <option value="All">All</option>
        </select>
      </div>
    `
    );
  }

  // Municipality dropdown
  if (!document.getElementById("municipalityFilter")) {
    container.insertAdjacentHTML(
      "afterbegin",
      `
      <div class="col-md-3">
        <label class="form-label fw-semibold">Municipality</label>
        <select id="municipalityFilter" class="form-select">
          <option value="All">All</option>
        </select>
      </div>
    `
    );
  }

  const provinceSel = document.getElementById("provinceFilter");
  const municipalitySel = document.getElementById("municipalityFilter");
  const barangaySel = document.getElementById("barangayFilter");

  // load provinces (list of names)
  const provinces = await fetchJSON("/api/provinces");
  if (!provinces) return;

  provinceSel.innerHTML = `<option value="All">All</option>`;
  provinces.forEach((name) => {
    provinceSel.innerHTML += `<option value="${name}">${name}</option>`;
  });

  provinceSel.onchange = async () => {
    const p = provinceSel.value;
    barangaySel.innerHTML = `<option value="All">All</option>`;
    municipalitySel.innerHTML = `<option value="All">All</option>`;
    if (p === "All") return;
    await loadMunicipalities(p);
  };

  municipalitySel.onchange = async () => {
    const m = municipalitySel.value;
    barangaySel.innerHTML = `<option value="All">All</option>`;
    if (m === "All") return;
    await loadBarangays(m);
  };
}

async function loadMunicipalities(provinceName) {
  const municipalitySel = document.getElementById("municipalityFilter");
  const list = await fetchJSON(`/api/municipalities?province=${encodeURIComponent(provinceName)}`);
  if (!municipalitySel || !list) return;

  municipalitySel.innerHTML = `<option value="All">All</option>`;
  list.forEach((name) => {
    municipalitySel.innerHTML += `<option value="${name}">${name}</option>`;
  });
}

async function loadBarangays(municipalityName) {
  const barangaySel = document.getElementById("barangayFilter");
  const list = await fetchJSON(
    `/api/barangays?municipality=${encodeURIComponent(municipalityName)}`
  );
  if (!barangaySel || !list) return;

  barangaySel.innerHTML = `<option value="All">All</option>`;
  list.forEach((name) => {
    barangaySel.innerHTML += `<option value="${name}">${name}</option>`;
  });
}

/* ============================
   LOAD REPORTS
============================ */
async function loadReports(params = "") {
  let url = "/api/reports";
  if (params) url += "?" + params;

  const data = await fetchJSON(url);
  if (!data) return;

  window.allReports = data;

  renderKPIs(data);
  renderTable(data);
  renderMap(data);
  renderCharts(data);
  updateHighAlert(data);

  const lu = document.getElementById("lastUpdate");
  if (lu) lu.innerText = new Date().toLocaleTimeString();
}

/* ============================
   APPLY FILTERS
============================ */
function applyFilters() {
  const province = document.getElementById("provinceFilter")?.value || "All";
  const municipality = document.getElementById("municipalityFilter")?.value || "All";
  const barangay = document.getElementById("barangayFilter")?.value || "All";
  const severity = document.getElementById("severityFilter")?.value || "All";
  const infestation = document.getElementById("infestationFilter")?.value || "All";
  const start = document.getElementById("startDate")?.value || "";
  const end = document.getElementById("endDate")?.value || "";

  const params = new URLSearchParams();

  if (province !== "All") params.append("province", province);
  if (municipality !== "All") params.append("municipality", municipality);
  if (barangay !== "All") params.append("barangay", barangay);
  if (severity !== "All") params.append("severity", severity);
  if (infestation !== "All") params.append("infestation_type", infestation);
  if (start) params.append("start_date", start);
  if (end) params.append("end_date", end);

  loadReports(params.toString());
}

/* ============================
   KPIs
============================ */
function renderKPIs(data) {
  const totalSightings = document.getElementById("totalSightings");
  const activeHotspots = document.getElementById("activeHotspots");
  const activeReporters = document.getElementById("activeReporters");
  const avgResponse = document.getElementById("avgResponse");

  if (totalSightings) totalSightings.innerText = data.length;

  const hotspotBrgys = new Set(
    data.filter((r) => r.severity === "High" || r.severity === "Critical").map((r) => r.barangay)
  );
  if (activeHotspots) activeHotspots.innerText = hotspotBrgys.size;

  const reporters = new Set(data.map((r) => r.reporter));
  if (activeReporters) activeReporters.innerText = reporters.size;

  if (avgResponse) avgResponse.innerText = "0";
}

/* ============================
   TABLE
============================ */
function renderTable(data) {
  const tbody = document.querySelector("#reports-table tbody");
  if (!tbody) return;
  tbody.innerHTML = "";

  data.forEach((r) => {
    const tr = document.createElement("tr");
    if (r.severity === "High" || r.severity === "Critical") tr.classList.add("high-row");

    tr.innerHTML = `
      <td>${r.date}</td>
      <td>${r.reporter || ""}</td>
      <td>${r.barangay || ""}, ${r.municipality || ""}, ${r.province || ""}</td>
      <td>
        ${r.severity || ""}
        ${r.infestation_type ? `<br><small class="text-muted">${r.infestation_type}</small>` : ""}
      </td>
      <td>${
        r.photo
          ? `<img src="${r.photo}" style="width:60px;height:60px;border-radius:6px;object-fit:cover">`
          : `<span class="text-muted">No photo</span>`
      }</td>
      <td>${r.status || ""}</td>
      <td>${r.action_status || ""}</td>
    `;
    tbody.appendChild(tr);
  });
}

/* ============================
   MAP
============================ */
function initMap() {
  map = L.map("map").setView([16.63, 120.33], 12);

  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution: "&copy; OpenStreetMap contributors",
  }).addTo(map);

  markersLayer = L.layerGroup().addTo(map);
}

function renderMap(data) {
  markersLayer.clearLayers();
  if (heatLayer) {
    map.removeLayer(heatLayer);
    heatLayer = null;
  }

  const heatPoints = [];

  // icon set per infestation type
  const infestationIcons = {
    "Golden Apple Snail": "/static/icons/infestation_snail.png",
    "Rice Bug": "/static/icons/infestation_rice_bug.png",
    "Rice Black Bug": "/static/icons/infestation_rice_black_bug.png",
    Armyworm: "/static/icons/infestation_armyworm.png",
    "Rat / Rodent": "/static/icons/infestation_rodent.png",
    "Fungal infection": "/static/icons/infestation_fungal.png",
    "Bacterial infection": "/static/icons/infestation_bacterial.png",
    Other: "/static/icons/infestation_other.png",
    "Unknown Pest": "/static/icons/infestation_other.png",
  };

  const severityWeight = {
    Low: 0.3,
    Moderate: 0.6,
    High: 1.0,
    Critical: 1.2,
  };

  const typeBoost = {
    "Golden Apple Snail": 1.0,
    "Rice Bug": 0.9,
    "Rice Black Bug": 1.1,
    Armyworm: 1.0,
    "Rat / Rodent": 0.8,
    "Fungal infection": 0.7,
    "Bacterial infection": 0.7,
    Other: 0.6,
    "Unknown Pest": 0.6,
  };

  data.forEach((r) => {
    if (r.lat == null || r.lng == null) return;

    const type = r.infestation_type || "Other";
    const sev = r.severity || "Low";

    const sevW = severityWeight[sev] || 0.5;
    const tb = typeBoost[type] || 1.0;
    let weight = sevW * tb;
    if (weight > 1) weight = 1;

    heatPoints.push([r.lat, r.lng, weight]);

    const iconUrl = infestationIcons[type] || infestationIcons["Other"];

    const icon = L.icon({
      iconUrl,
      iconSize: [32, 32],
      iconAnchor: [16, 32],
      popupAnchor: [0, -28],
    });

    L.marker([r.lat, r.lng], { icon })
      .bindPopup(
        `<b>${r.barangay || "Unknown"}</b><br>
         ${r.municipality || ""}, ${r.province || ""}<br>
         <b>Severity:</b> ${sev}<br>
         <b>Type:</b> ${type}<br>
         <small>${r.date || ""}</small>`
      )
      .addTo(markersLayer);
  });

  if (heatPoints.length) {
    heatLayer = L.heatLayer(heatPoints, {
      radius: 28,
      blur: 18,
      gradient: { 0.2: "lime", 0.5: "yellow", 1: "red" },
    }).addTo(map);
  }
}

/* ============================
   CHARTS
============================ */
function renderCharts(data) {
  if (severityChart) severityChart.destroy();
  if (barangayChart) barangayChart.destroy();
  if (trendChart) trendChart.destroy();

  // Severity distribution
  const sevCounts = { Low: 0, Moderate: 0, High: 0, Critical: 0 };
  data.forEach((r) => {
    if (sevCounts[r.severity] != null) sevCounts[r.severity]++;
  });

  const sevCtx = document.getElementById("severityChart");
  if (sevCtx) {
    severityChart = new Chart(sevCtx, {
      type: "pie",
      data: {
        labels: Object.keys(sevCounts),
        datasets: [
          {
            data: Object.values(sevCounts),
            backgroundColor: ["#4caf50", "#ff9800", "#f44336", "#8e24aa"],
          },
        ],
      },
    });
  }

  // Barangay counts
  const brgyCounts = {};
  data.forEach((r) => {
    if (!r.barangay) return;
    brgyCounts[r.barangay] = (brgyCounts[r.barangay] || 0) + 1;
  });

  const brgyCtx = document.getElementById("barangayChart");
  if (brgyCtx) {
    barangayChart = new Chart(brgyCtx, {
      type: "bar",
      data: {
        labels: Object.keys(brgyCounts),
        datasets: [
          {
            label: "Reports",
            data: Object.values(brgyCounts),
            backgroundColor: "#42a5f5",
          },
        ],
      },
      options: {
        scales: {
          x: { ticks: { autoSkip: true, maxTicksLimit: 8 } },
        },
      },
    });
  }

  // Daily trend
  const dayCounts = {};
  data.forEach((r) => {
    const day = (r.date || "").split(" ")[0];
    if (!day) return;
    dayCounts[day] = (dayCounts[day] || 0) + 1;
  });

  const trendCtx = document.getElementById("trendChart");
  if (trendCtx) {
    trendChart = new Chart(trendCtx, {
      type: "line",
      data: {
        labels: Object.keys(dayCounts),
        datasets: [
          {
            label: "Sightings",
            data: Object.values(dayCounts),
            borderColor: "#d32f2f",
            tension: 0.3,
          },
        ],
      },
    });
  }
}

/* ============================
   HIGH ALERT
============================ */
function updateHighAlert(data) {
  const alert = document.getElementById("alertIndicator");
  if (!alert) return;
  const highs = data.filter((r) => r.severity === "High" || r.severity === "Critical");

  if (highs.length === 0) {
    alert.classList.add("d-none");
    alert.onclick = null;
    return;
  }

  alert.classList.remove("d-none");
  alert.onclick = () => {
    if (typeof showHighReports === "function") {
      showHighReports(highs);
    }
  };
}

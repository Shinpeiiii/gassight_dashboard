/**************************************************
 * GASsight — Dashboard.js (Fixed Final Version)
 * Compatible with dashboard.html + app.py
 * 3-level filters: Province → Municipality → Barangay
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
  initLocationFilters();
  loadReports(); // full report load

  // filter events
  ["severityFilter", "startDate", "endDate"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.onchange = applyFilters;
  });

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
   Uses:
   - /api/provinces          -> [{id, name}]
   - /api/municipalities     -> [{id, name}]  (requires ?province=ID)
   - /api/barangays          -> [{id, name}]  (requires ?municipality=ID)
   We store both name (value) and id (data-id) on each <option>.
=========================================================================== */
async function initLocationFilters() {
  const container = document.querySelector(".card-body.row.g-3.align-items-end");
  if (!container) return;

  // Province
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

  // Municipality
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

  if (!provinceSel || !municipalitySel || !barangaySel) return;

  // Load provinces from backend
  const provinces = await fetchJSON("/api/provinces");
  provinceSel.innerHTML = `<option value="All">All</option>`;

  if (Array.isArray(provinces)) {
    provinces.forEach((p) => {
      provinceSel.innerHTML += `
        <option value="${p.name}" data-id="${p.id}">${p.name}</option>
      `;
    });
  }

  // Province change → load municipalities
  provinceSel.onchange = async () => {
    const opt = provinceSel.selectedOptions[0];
    const provinceId = opt ? opt.dataset.id : null;

    // Reset lower levels
    municipalitySel.innerHTML = `<option value="All">All</option>`;
    barangaySel.innerHTML = `<option value="All">All</option>`;

    if (!provinceId || provinceSel.value === "All") {
      applyFilters();
      return;
    }

    await loadMunicipalities(provinceId);
    applyFilters();
  };

  // Municipality change → load barangays
  municipalitySel.onchange = async () => {
    const opt = municipalitySel.selectedOptions[0];
    const municipalityId = opt ? opt.dataset.id : null;

    barangaySel.innerHTML = `<option value="All">All</option>`;

    if (!municipalityId || municipalitySel.value === "All") {
      applyFilters();
      return;
    }

    await loadBarangays(municipalityId);
    applyFilters();
  };

  // Barangay change → just filter
  barangaySel.onchange = applyFilters;
}

async function loadMunicipalities(provinceId) {
  const municipalitySel = document.getElementById("municipalityFilter");
  if (!municipalitySel) return;

  const list = await fetchJSON(`/api/municipalities?province=${provinceId}`);
  municipalitySel.innerHTML = `<option value="All">All</option>`;

  if (Array.isArray(list)) {
    list.forEach((m) => {
      municipalitySel.innerHTML += `
        <option value="${m.name}" data-id="${m.id}">${m.name}</option>
      `;
    });
  }
}

async function loadBarangays(municipalityId) {
  const barangaySel = document.getElementById("barangayFilter");
  if (!barangaySel) return;

  const list = await fetchJSON(`/api/barangays?municipality=${municipalityId}`);
  barangaySel.innerHTML = `<option value="All">All</option>`;

  if (Array.isArray(list)) {
    list.forEach((b) => {
      barangaySel.innerHTML += `
        <option value="${b.name}" data-id="${b.id}">${b.name}</option>
      `;
    });
  }
}

/* ============================
   LOAD REPORTS
============================ */
async function loadReports(params = "") {
  let url = "/api/reports";
  if (params) url += "?" + params;

  const data = await fetchJSON(url);
  if (!data) return;

  allReports = data;

  renderKPIs(data);
  renderTable(data);
  renderMap(data);
  renderCharts(data);
  updateHighAlert(data);

  const lastUpdate = document.getElementById("lastUpdate");
  if (lastUpdate) {
    lastUpdate.innerText = new Date().toLocaleTimeString();
  }
}

/* ============================
   APPLY FILTERS
============================ */
function applyFilters() {
  const provinceSel = document.getElementById("provinceFilter");
  const municipalitySel = document.getElementById("municipalityFilter");
  const barangaySel = document.getElementById("barangayFilter");
  const severitySel = document.getElementById("severityFilter");
  const startDate = document.getElementById("startDate");
  const endDate = document.getElementById("endDate");

  const province = provinceSel ? provinceSel.value : "All";
  const municipality = municipalitySel ? municipalitySel.value : "All";
  const barangay = barangaySel ? barangaySel.value : "All";
  const severity = severitySel ? severitySel.value : "All";
  const start = startDate ? startDate.value : "";
  const end = endDate ? endDate.value : "";

  const params = new URLSearchParams();

  if (province !== "All") params.append("province", province);
  if (municipality !== "All") params.append("municipality", municipality);
  if (barangay !== "All") params.append("barangay", barangay);
  if (severity !== "All") params.append("severity", severity);
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
    data.filter((r) => r.severity === "High").map((r) => r.barangay)
  );
  if (activeHotspots) activeHotspots.innerText = hotspotBrgys.size;

  const reporters = new Set(data.map((r) => r.reporter));
  if (activeReporters) activeReporters.innerText = reporters.size;

  if (avgResponse) avgResponse.innerText = "0"; // TODO: calculate if you add response timestamps
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
    if (r.severity === "High") tr.classList.add("high-row");

    tr.innerHTML = `
      <td>${r.date}</td>
      <td>${r.reporter || ""}</td>
      <td>${r.barangay}, ${r.municipality}, ${r.province}</td>
      <td>${r.severity}</td>
      <td>
        ${
          r.photo
            ? `<img src="${r.photo}" style="width:60px;height:60px;border-radius:6px;object-fit:cover">`
            : `<span class="text-muted">No photo</span>`
        }
      </td>
      <td>${r.status}</td>
      <td>${r.action_status}</td>
    `;
    tbody.appendChild(tr);
  });
}

/* ============================
   MAP
============================ */
function initMap() {
  map = L.map("map").setView([16.63, 120.33], 12);

  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png").addTo(map);

  markersLayer = L.layerGroup().addTo(map);
}

function renderMap(data) {
  if (!map || !markersLayer) return;

  markersLayer.clearLayers();
  if (heatLayer) {
    map.removeLayer(heatLayer);
    heatLayer = null;
  }

  const heatPoints = [];

  data.forEach((r) => {
    if (!r.lat || !r.lng) return;

    const sevWeight =
      r.severity === "High" ? 1 : r.severity === "Moderate" ? 0.6 : 0.3;

    heatPoints.push([r.lat, r.lng, sevWeight]);

    const color =
      r.severity === "High"
        ? "red"
        : r.severity === "Moderate"
        ? "orange"
        : "green";

    L.circleMarker([r.lat, r.lng], {
      radius: 7,
      color,
      fillColor: color,
      fillOpacity: 0.7,
    })
      .bindPopup(`<b>${r.barangay}</b><br>${r.severity}<br>${r.date}`)
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

  const sevCounts = { Low: 0, Moderate: 0, High: 0 };
  data.forEach((r) => {
    if (sevCounts[r.severity] !== undefined) {
      sevCounts[r.severity]++;
    }
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
            backgroundColor: ["#4caf50", "#ff9800", "#f44336"],
          },
        ],
      },
    });
  }

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
        plugins: {
          legend: { display: false },
        },
        scales: {
          x: { ticks: { autoSkip: true, maxTicksLimit: 6 } },
        },
      },
    });
  }

  const dayCounts = {};
  data.forEach((r) => {
    const day = r.date.split(" ")[0];
    dayCounts[day] = (dayCounts[day] || 0) + 1;
  });

  const trendCtx = document.getElementById("trendChart");
  if (trendCtx) {
    const days = Object.keys(dayCounts).sort();
    const counts = days.map((d) => dayCounts[d]);

    trendChart = new Chart(trendCtx, {
      type: "line",
      data: {
        labels: days,
        datasets: [
          {
            label: "Sightings",
            data: counts,
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

  const highs = data.filter((r) => r.severity === "High");

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

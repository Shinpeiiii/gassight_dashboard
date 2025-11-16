/**************************************************
 * GASsight — Dashboard.js (Option 2 Version)
 * Uses DISTINCT province/municipality/barangay
 * directly from the reports table.
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

    // filter triggers
    ["severityFilter", "startDate", "endDate"].forEach(id => {
        document.getElementById(id).onchange = applyFilters;
    });

    document.getElementById("filterBtn").onclick = applyFilters;
    document.getElementById("manualRefresh").onclick = () => loadReports();

    document.getElementById("refreshInterval").onchange = function () {
        const val = this.value;
        if (window.refreshTimer) clearInterval(window.refreshTimer);
        if (val !== "off") window.refreshTimer = setInterval(loadReports, val * 1000);
    };
});

/* ======================================================
   3-LEVEL LOCATION FILTERS (PROVINCE → MUNICIPALITY → BARANGAY)
====================================================== */
async function initLocationFilters() {
    const barangaySel = document.getElementById("barangayFilter");

    // Inject province dropdown
    if (!document.getElementById("provinceFilter")) {
        document.querySelector(".card-body.row").insertAdjacentHTML("afterbegin", `
            <div class="col-md-3">
                <label class="form-label fw-semibold">Province</label>
                <select id="provinceFilter" class="form-select">
                    <option value="All">All</option>
                </select>
            </div>
        `);
    }

    // Inject municipality dropdown
    if (!document.getElementById("municipalityFilter")) {
        document.querySelector(".card-body.row").insertAdjacentHTML("afterbegin", `
            <div class="col-md-3">
                <label class="form-label fw-semibold">Municipality</label>
                <select id="municipalityFilter" class="form-select">
                    <option value="All">All</option>
                </select>
            </div>
        `);
    }

    const provinceSel = document.getElementById("provinceFilter");
    const municipalitySel = document.getElementById("municipalityFilter");

    // Load provinces
    const provinces = await fetchJSON("/api/provinces");
    provinceSel.innerHTML = `<option value="All">All</option>`;
    provinces.forEach(p => provinceSel.innerHTML += `<option value="${p}">${p}</option>`);

    // province change
    provinceSel.onchange = async () => {
        const province = provinceSel.value;
        municipalitySel.innerHTML = `<option value="All">All</option>`;
        barangaySel.innerHTML = `<option value="All">All</option>`;

        if (province !== "All") loadMunicipalities(province);
    };

    // municipality change
    municipalitySel.onchange = () => {
        const municipality = municipalitySel.value;
        barangaySel.innerHTML = `<option value="All">All</option>`;

        if (municipality !== "All") loadBarangays(municipality);
    };
}

async function loadMunicipalities(province) {
    const municipalitySel = document.getElementById("municipalityFilter");
    const list = await fetchJSON(`/api/municipalities?province=${province}`);
    municipalitySel.innerHTML = `<option value="All">All</option>`;
    list.forEach(m => municipalitySel.innerHTML += `<option value="${m}">${m}</option>`);
}

async function loadBarangays(municipality) {
    const barangaySel = document.getElementById("barangayFilter");
    const list = await fetchJSON(`/api/barangays?municipality=${municipality}`);
    barangaySel.innerHTML = `<option value="All">All</option>`;
    list.forEach(b => barangaySel.innerHTML += `<option value="${b}">${b}</option>`);
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

    document.getElementById("lastUpdate").innerText =
        new Date().toLocaleTimeString();
}

/* ============================
   APPLY FILTERS
============================ */
function applyFilters() {
    const province = document.getElementById("provinceFilter")?.value || "All";
    const municipality = document.getElementById("municipalityFilter")?.value || "All";
    const barangay = document.getElementElementById("barangayFilter").value;
    const severity = document.getElementById("severityFilter").value;
    const start = document.getElementById("startDate").value;
    const end = document.getElementById("endDate").value;

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
    document.getElementById("totalSightings").innerText = data.length;

    const hotspotBrgys = new Set(
        data.filter(r => r.severity === "High").map(r => r.barangay)
    );
    document.getElementById("activeHotspots").innerText = hotspotBrgys.size;

    const reporters = new Set(data.map(r => r.reporter));
    document.getElementById("activeReporters").innerText = reporters.size;

    document.getElementById("avgResponse").innerText = "0";
}

/* ============================
   TABLE
============================ */
function renderTable(data) {
    const tbody = document.querySelector("#reports-table tbody");
    tbody.innerHTML = "";

    data.forEach(r => {
        const tr = document.createElement("tr");
        if (r.severity === "High") tr.classList.add("high-row");

        tr.innerHTML = `
            <td>${r.date}</td>
            <td>${r.reporter || ""}</td>
            <td>${r.barangay}, ${r.municipality}, ${r.province}</td>
            <td>${r.severity}</td>
            <td>${r.photo ? `<img src="${r.photo}" style="width:60px;height:60px;border-radius:6px;object-fit:cover">` : `<span class="text-muted">No photo</span>`}</td>
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
    markersLayer.clearLayers();
    if (heatLayer) {
        map.removeLayer(heatLayer);
        heatLayer = null;
    }

    const heatPoints = [];

    data.forEach(r => {
        if (!r.lat || !r.lng) return;

        const sevWeight = r.severity === "High" ? 1 :
                          r.severity === "Moderate" ? 0.6 : 0.3;

        heatPoints.push([r.lat, r.lng, sevWeight]);

        const color =
            r.severity === "High" ? "red" :
            r.severity === "Moderate" ? "orange" : "green";

        L.circleMarker([r.lat, r.lng], {
            radius: 7,
            color,
            fillColor: color,
            fillOpacity: 0.7
        })
        .bindPopup(`<b>${r.barangay}</b><br>${r.severity}<br>${r.date}`)
        .addTo(markersLayer);
    });

    if (heatPoints.length) {
        heatLayer = L.heatLayer(heatPoints, {
            radius: 28,
            blur: 18,
            gradient: { 0.2: "lime", 0.5: "yellow", 1: "red" }
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
    data.forEach(r => sevCounts[r.severity]++);

    severityChart = new Chart(document.getElementById("severityChart"), {
        type: "pie",
        data: {
            labels: Object.keys(sevCounts),
            datasets: [{ data: Object.values(sevCounts), backgroundColor: ["#4caf50", "#ff9800", "#f44336"] }]
        }
    });

    const brgyCounts = {};
    data.forEach(r => {
        if (!r.barangay) return;
        brgyCounts[r.barangay] = (brgyCounts[r.barangay] || 0) + 1;
    });

    barangayChart = new Chart(document.getElementById("barangayChart"), {
        type: "bar",
        data: {
            labels: Object.keys(brgyCounts),
            datasets: [{ label: "Reports", data: Object.values(brgyCounts), backgroundColor: "#42a5f5" }]
        }
    });

    const dayCounts = {};
    data.forEach(r => {
        const d = r.date.split(" ")[0];
        dayCounts[d] = (dayCounts[d] || 0) + 1;
    });

    trendChart = new Chart(document.getElementById("trendChart"), {
        type: "line",
        data: {
            labels: Object.keys(dayCounts),
            datasets: [{ label: "Sightings", data: Object.values(dayCounts), borderColor: "#d32f2f", tension: 0.3 }]
        }
    });
}

/* ============================
   HIGH ALERT
============================ */
function updateHighAlert(data) {
    const alert = document.getElementById("alertIndicator");
    const highs = data.filter(r => r.severity === "High");

    if (highs.length === 0) {
        alert.classList.add("d-none");
        return;
    }

    alert.classList.remove("d-none");
    alert.onclick = () => showHighReports(highs);
}

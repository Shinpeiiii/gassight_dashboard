/**************************************************
 * GASsight — Dashboard.js (Final Stable Version)
 * Compatible with: dashboard.html + app.py
 **************************************************/

let map, markersLayer, heatLayer;
let allReports = [];

let severityChart, barangayChart, trendChart;

/* ============================
   FETCH HELPERS
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
   LOAD REPORTS
============================ */
async function loadReports(filters = "") {
    let url = "/api/reports";
    if (filters) url += "?" + filters;

    const data = await fetchJSON(url);
    if (!data) return;

    allReports = data;

    populateBarangayDropdown(data);
    renderKPIs(data);
    renderTable(data);
    renderMap(data);
    renderCharts(data);
    updateHighAlert(data);

    document.getElementById("lastUpdate").innerText =
        new Date().toLocaleTimeString();
}

/* ============================
   AUTO POPULATE BARANGAY FILTER
============================ */
function populateBarangayDropdown(data) {
    const sel = document.getElementById("barangayFilter");

    const barangays = [...new Set(data.map(r => r.barangay).filter(Boolean))];

    sel.innerHTML = `<option value="All">All</option>`;
    barangays.forEach(b => {
        sel.innerHTML += `<option value="${b}">${b}</option>`;
    });
}

/* ============================
   FILTER HANDLING
============================ */
function applyFilters() {
    const brgy = document.getElementById("barangayFilter").value;
    const sev = document.getElementById("severityFilter").value;
    const start = document.getElementById("startDate").value;
    const end = document.getElementById("endDate").value;

    const params = new URLSearchParams();

    if (brgy !== "All") params.append("barangay", brgy);
    if (sev !== "All") params.append("severity", sev);
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
   TABLE RENDERING
============================ */
function renderTable(data) {
    const tbody = document.querySelector("#reports-table tbody");
    tbody.innerHTML = "";

    data.forEach(r => {
        const tr = document.createElement("tr");
        if (r.severity === "High") tr.classList.add("high-row");

        tr.innerHTML = `
            <td>${r.date || ""}</td>
            <td>${r.reporter || ""}</td>
            <td>${r.barangay || ""}, ${r.municipality || ""}, ${r.province || ""}</td>
            <td>${r.severity}</td>
            <td>
                ${
                    r.photo
                        ? `<img src="${r.photo}" style="width:60px;height:60px;object-fit:cover;border-radius:6px;">`
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
   LEAFLET MAP
============================ */
function initMap() {
    map = L.map("map").setView([16.63, 120.33], 12);

    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png").addTo(map);

    markersLayer = L.layerGroup().addTo(map);
}

function renderMap(data) {
    if (!map) return;

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
            maxZoom: 18,
            gradient: {
                0.2: "lime",
                0.5: "yellow",
                0.8: "orange",
                1.0: "red"
            }
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

    /* --- Severity --- */
    const sevCounts = { Low: 0, Moderate: 0, High: 0 };
    data.forEach(r => sevCounts[r.severity] = (sevCounts[r.severity] || 0) + 1);

    severityChart = new Chart(document.getElementById("severityChart"), {
        type: "pie",
        data: {
            labels: Object.keys(sevCounts),
            datasets: [{
                data: Object.values(sevCounts),
                backgroundColor: ["#4caf50", "#ff9800", "#f44336"]
            }]
        }
    });

    /* --- Barangay --- */
    const brgyCounts = {};
    data.forEach(r => {
        if (!r.barangay) return;
        brgyCounts[r.barangay] = (brgyCounts[r.barangay] || 0) + 1;
    });

    barangayChart = new Chart(document.getElementById("barangayChart"), {
        type: "bar",
        data: {
            labels: Object.keys(brgyCounts),
            datasets: [{
                label: "Reports",
                data: Object.values(brgyCounts),
                backgroundColor: "#42a5f5"
            }]
        },
        options: { scales: { y: { beginAtZero: true } } }
    });

    /* --- Trend Chart --- */
    const dayCounts = {};
    data.forEach(r => {
        const day = r.date.split(" ")[0];
        dayCounts[day] = (dayCounts[day] || 0) + 1;
    });

    trendChart = new Chart(document.getElementById("trendChart"), {
        type: "line",
        data: {
            labels: Object.keys(dayCounts),
            datasets: [{
                label: "Sightings",
                data: Object.values(dayCounts),
                borderColor: "#d32f2f",
                tension: 0.3
            }]
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

/* ============================
   PAGE INIT
============================ */
window.addEventListener("load", () => {
    initMap();
    loadReports();

    document.getElementById("filterBtn").onclick = applyFilters;

    ["barangayFilter", "severityFilter", "startDate", "endDate"].forEach(id => {
        document.getElementById(id).onchange = applyFilters;
    });

    document.getElementById("manualRefresh").onclick = () => loadReports();

    document.getElementById("refreshInterval").onchange = function () {
        const val = this.value;

        if (window.refreshTimer) clearInterval(window.refreshTimer);

        if (val === "off") return;

        window.refreshTimer = setInterval(() => loadReports(), val * 1000);
    };
});

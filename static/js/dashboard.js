// -----------------------------------------------
// GLOBAL VARIABLES
// -----------------------------------------------
let map;
let heatLayer;
let markersLayer = L.layerGroup();
window.allReports = [];

let severityChart, barangayChart, trendChart;

let autoRefreshTimer = null;


// -----------------------------------------------
// INIT MAP
// -----------------------------------------------
function initMap() {
    map = L.map("map").setView([17.25, 120.45], 9);

    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
        maxZoom: 18,
        attribution: "&copy; OpenStreetMap contributors",
    }).addTo(map);

    markersLayer.addTo(map);
}


// -----------------------------------------------
// LOAD FILTER DROPDOWNS
// -----------------------------------------------
async function loadFilterDropdowns() {
    const provinceSelect = document.getElementById("provinceFilter");
    const municipalitySelect = document.getElementById("municipalityFilter");
    const barangaySelect = document.getElementById("barangayFilter");

    provinceSelect.innerHTML = `<option value="All">All</option>`;
    municipalitySelect.innerHTML = `<option value="All">All</option>`;
    barangaySelect.innerHTML = `<option value="All">All</option>`;

    try {
        const res = await fetch("/api/reports");
        const data = await res.json();

        const provinces = new Set();
        const municipalities = new Set();
        const barangays = new Set();

        data.forEach(r => {
            if (r.province) provinces.add(r.province);
            if (r.municipality) municipalities.add(r.municipality);
            if (r.barangay) barangays.add(r.barangay);
        });

        [...provinces].sort().forEach(p => {
            provinceSelect.innerHTML += `<option value="${p}">${p}</option>`;
        });

        [...municipalities].sort().forEach(m => {
            municipalitySelect.innerHTML += `<option value="${m}">${m}</option>`;
        });

        [...barangays].sort().forEach(b => {
            barangaySelect.innerHTML += `<option value="${b}">${b}</option>`;
        });

    } catch (err) {
        console.error("Failed loading dropdowns:", err);
    }
}


// -----------------------------------------------
// FETCH FILTERED REPORTS
// -----------------------------------------------
async function fetchReports() {
    const province = document.getElementById("provinceFilter").value;
    const municipality = document.getElementById("municipalityFilter").value;
    const barangay = document.getElementById("barangayFilter").value;
    const severity = document.getElementById("severityFilter").value;
    const infestationType = document.getElementById("infestationFilter").value;
    const start = document.getElementById("startDate").value;
    const end = document.getElementById("endDate").value;

    const params = new URLSearchParams();

    if (province !== "All") params.append("province", province);
    if (municipality !== "All") params.append("municipality", municipality);
    if (barangay !== "All") params.append("barangay", barangay);
    if (severity !== "All") params.append("severity", severity);
    if (infestationType !== "All") params.append("infestation_type", infestationType);
    if (start) params.append("start_date", start);
    if (end) params.append("end_date", end);

    const query = params.toString();
    const url = query ? `/api/reports?${query}` : `/api/reports`;
    console.log("Fetching:", url);

    const res = await fetch(url);
    return await res.json();
}


// -----------------------------------------------
// UPDATE EVERYTHING
// -----------------------------------------------
async function updateReports() {
    try {
        window.allReports = await fetchReports();

        updateHeatmap();
        updateMarkers();
        updateKPIs();
        updateCharts();
        updateRecentReportsTable();   // <--- NEW
        updateLastUpdated();

    } catch (err) {
        console.error("Failed to update reports:", err);
    }
}


// -----------------------------------------------
// HEATMAP
// -----------------------------------------------
function updateHeatmap() {
    if (heatLayer) heatLayer.remove();

    const points = window.allReports
        .filter(r => r.lat && r.lng)
        .map(r => [
            r.lat,
            r.lng,
            r.severity === "Critical" ? 1.0 :
            r.severity === "High" ? 0.9 :
            r.severity === "Moderate" ? 0.6 :
            0.3
        ]);

    heatLayer = L.heatLayer(points, {
        radius: 25,
        blur: 20,
        maxZoom: 17,
    }).addTo(map);
}


// -----------------------------------------------
// MARKERS
// -----------------------------------------------
function updateMarkers() {
    markersLayer.clearLayers();

    window.allReports.forEach(r => {
        if (!r.lat || !r.lng) return;

        let color =
            r.severity === "Critical" ? "#6a00ff" :
            r.severity === "High" ? "red" :
            r.severity === "Moderate" ? "orange" :
            "green";

        const marker = L.circleMarker([r.lat, r.lng], {
            radius: 9,
            color: color,
            fillColor: color,
            fillOpacity: 0.85,
        });

        marker.bindPopup(`
            <strong>${r.barangay}, ${r.municipality}</strong><br>
            <small>${r.infestation_type}</small><br>
            <b>Severity:</b> ${r.severity}<br>
            <b>Date:</b> ${r.date}<br>
            <img src="${r.photo || '/static/icons/icon-192.png'}" 
                 style="width:120px;border-radius:5px;margin-top:4px;">
        `);

        markersLayer.addLayer(marker);
    });
}


// -----------------------------------------------
// KPIs
// -----------------------------------------------
function updateKPIs() {
    document.getElementById("totalSightings").innerText = window.allReports.length;

    const activeHotspots = window.allReports.filter(r =>
        r.severity === "High" || r.severity === "Critical"
    ).length;
    document.getElementById("activeHotspots").innerText = activeHotspots;

    const reporters = new Set(window.allReports.map(r => r.reporter || "Unknown"));
    document.getElementById("activeReporters").innerText = reporters.size;

    document.getElementById("avgResponse").innerText = "0";
}


// -----------------------------------------------
// CHARTS
// -----------------------------------------------
function updateCharts() {
    const severityCount = { Low: 0, Moderate: 0, High: 0, Critical: 0 };
    const barangayCount = {};
    const weekly = {};

    window.allReports.forEach(r => {
        if (severityCount[r.severity] !== undefined)
            severityCount[r.severity]++;

        if (r.barangay) {
            barangayCount[r.barangay] = (barangayCount[r.barangay] || 0) + 1;
        }

        if (r.date) {
            const day = r.date.substring(0, 10);
            weekly[day] = (weekly[day] || 0) + 1;
        }
    });

    drawSeverityChart(severityCount);
    drawBarangayChart(barangayCount);
    drawTrendChart(weekly);
}


function drawSeverityChart(data) {
    if (severityChart) severityChart.destroy();

    severityChart = new Chart(document.getElementById("severityChart"), {
        type: "pie",
        data: {
            labels: ["Low", "Moderate", "High", "Critical"],
            datasets: [{ data: [data.Low, data.Moderate, data.High, data.Critical] }]
        }
    });
}


function drawBarangayChart(data) {
    if (barangayChart) barangayChart.destroy();

    barangayChart = new Chart(document.getElementById("barangayChart"), {
        type: "bar",
        data: {
            labels: Object.keys(data),
            datasets: [{ data: Object.values(data) }]
        }
    });
}


function drawTrendChart(data) {
    if (trendChart) trendChart.destroy();

    const labels = Object.keys(data).sort();

    trendChart = new Chart(document.getElementById("trendChart"), {
        type: "line",
        data: {
            labels: labels,
            datasets: [{ data: labels.map(d => data[d]) }]
        }
    });
}


// -----------------------------------------------
// NEW: RECENT REPORTS TABLE
// -----------------------------------------------
function updateRecentReportsTable() {
    const tbody = document.getElementById("recentReportsTable");
    tbody.innerHTML = "";

    if (!window.allReports.length) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">No reports found</td></tr>`;
        return;
    }

    const sorted = [...window.allReports].sort((a, b) => new Date(b.date) - new Date(a.date));

    const recent = sorted.slice(0, 10);

    recent.forEach(r => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td>${r.date || "-"}</td>
            <td>${r.province || "-"}</td>
            <td>${r.municipality || "-"}</td>
            <td>${r.barangay || "-"}</td>
            <td>
                <span class="badge bg-${
                    r.severity === "Critical" ? "danger" :
                    r.severity === "High" ? "warning" :
                    r.severity === "Moderate" ? "info" : "success"
                }">${r.severity}</span>
            </td>
            <td>${r.infestation_type || "-"}</td>
            <td>${r.reporter || "Unknown"}</td>
        `;
        tbody.appendChild(tr);
    });
}


// -----------------------------------------------
// AUTO REFRESH
// -----------------------------------------------
function updateLastUpdated() {
    document.getElementById("lastUpdate").innerText = new Date().toLocaleTimeString();
}

function startAutoRefresh(seconds) {
    if (autoRefreshTimer) clearInterval(autoRefreshTimer);
    if (seconds === "off") return;
    autoRefreshTimer = setInterval(updateReports, seconds * 1000);
}


// -----------------------------------------------
// INITIALIZE
// -----------------------------------------------
window.addEventListener("load", async () => {
    initMap();
    await loadFilterDropdowns();
    await updateReports();

    document.getElementById("filterBtn").onclick = updateReports;
    document.getElementById("refreshInterval").addEventListener("change", e => startAutoRefresh(e.target.value));
    document.getElementById("manualRefresh").onclick = updateReports;
});

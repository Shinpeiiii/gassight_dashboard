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
    map = L.map("map").setView([10.7, 122.56], 10);

    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
        maxZoom: 18,
        attribution: "&copy; OpenStreetMap contributors",
    }).addTo(map);

    markersLayer.addTo(map);
}


// -----------------------------------------------
// LOAD FILTER OPTIONS
// -----------------------------------------------
async function loadFilterDropdowns() {
    const barangaySelect = document.getElementById("barangayFilter");

    barangaySelect.innerHTML = `<option value="All">All</option>`;

    try {
        const res = await fetch("/api/barangays");
        const data = await res.json();

        data.forEach((b) => {
            const opt = document.createElement("option");
            opt.value = b;
            opt.textContent = b;
            barangaySelect.appendChild(opt);
        });
    } catch (err) {
        console.error("Failed loading barangays:", err);
    }
}


// -----------------------------------------------
// FETCH FILTERED REPORTS
// -----------------------------------------------
async function fetchReports() {
    const barangay = document.getElementById("barangayFilter").value;
    const severity = document.getElementById("severityFilter").value;
    const infestationType = document.getElementById("infestationFilter") 
        ? document.getElementById("infestationFilter").value 
        : "All";
    const start = document.getElementById("startDate").value;
    const end = document.getElementById("endDate").value;

    const params = new URLSearchParams();

    if (barangay !== "All") params.append("barangay", barangay);
    if (severity !== "All") params.append("severity", severity);
    if (infestationType !== "All") params.append("infestation_type", infestationType);
    if (start) params.append("start_date", start);
    if (end) params.append("end_date", end);

    const res = await fetch(`/api/reports?${params.toString()}`);
    return await res.json();
}


// -----------------------------------------------
// UPDATE EVERYTHING
// -----------------------------------------------
async function updateReports() {
    window.allReports = await fetchReports();
    updateHeatmap();
    updateMarkers();
    updateTable();
    updateKPIs();
    updateCharts();
    updateLastUpdated();
}


// -----------------------------------------------
// UPDATE HEATMAP
// -----------------------------------------------
function updateHeatmap() {
    if (heatLayer) heatLayer.remove();

    const points = window.allReports
        .filter(r => r.lat && r.lng)
        .map(r => [r.lat, r.lng, r.severity === "High" ? 1.0 : r.severity === "Moderate" ? 0.6 : 0.3]);

    heatLayer = L.heatLayer(points, {
        radius: 25,
        blur: 20,
        maxZoom: 17,
    }).addTo(map);
}


// -----------------------------------------------
// UPDATE MARKERS
// -----------------------------------------------
function updateMarkers() {
    markersLayer.clearLayers();

    window.allReports.forEach(r => {
        if (!r.lat || !r.lng) return;

        const color = r.severity === "High" ? "red" :
                      r.severity === "Moderate" ? "orange" : "green";

        const marker = L.circleMarker([r.lat, r.lng], {
            radius: 8,
            color: color,
            fillColor: color,
            fillOpacity: 0.8,
        });

        marker.bindPopup(`
            <strong>${r.barangay}, ${r.municipality}</strong><br>
            Severity: <b>${r.severity}</b><br>
            Type: ${r.infestation_type || "Unknown"}<br>
            <img src="${r.photo || '/static/icons/icon-192.png'}" 
                 style="width:100px;border-radius:5px;margin-top:4px;">
        `);

        markersLayer.addLayer(marker);
    });
}


// -----------------------------------------------
// UPDATE TABLE
// -----------------------------------------------
function updateTable() {
    const tbody = document.querySelector("#reports-table tbody");
    tbody.innerHTML = "";

    window.allReports.forEach(r => {
        const tr = document.createElement("tr");
        if (r.severity === "High") tr.classList.add("high-row");

        tr.innerHTML = `
            <td>${r.date}</td>
            <td>${r.reporter || "Unknown"}</td>
            <td>${r.barangay}, ${r.municipality}</td>
            <td><span class="badge bg-${r.severity === "High" ? "danger" : r.severity === "Moderate" ? "warning" : "success"}">${r.severity}</span></td>
            <td><img src="${r.photo || '/static/icons/icon-192.png'}" style="width:50px;height:50px;border-radius:6px;object-fit:cover"></td>
            <td>${r.status}</td>
            <td><button class="btn btn-sm btn-outline-primary" onclick="focusReport(${r.lat},${r.lng})">Locate</button></td>
        `;

        tbody.appendChild(tr);
    });
}

function focusReport(lat, lng) {
    if (!lat || !lng) return;
    map.setView([lat, lng], 15);
}


// -----------------------------------------------
// UPDATE KPIs
// -----------------------------------------------
function updateKPIs() {
    document.getElementById("totalSightings").innerText = window.allReports.length;

    const activeHotspots = window.allReports.filter(r => r.severity === "High").length;
    document.getElementById("activeHotspots").innerText = activeHotspots;

    const reporters = new Set(window.allReports.map(r => r.reporter));
    document.getElementById("activeReporters").innerText = reporters.size;

    document.getElementById("avgResponse").innerText = "0";
}


// -----------------------------------------------
// UPDATE CHARTS
// -----------------------------------------------
function updateCharts() {
    const severityCount = { Low: 0, Moderate: 0, High: 0 };
    const barangayCount = {};
    const weekly = {};

    window.allReports.forEach(r => {
        if (severityCount[r.severity] !== undefined) severityCount[r.severity]++;

        barangayCount[r.barangay] = (barangayCount[r.barangay] || 0) + 1;

        const week = r.date.substring(0, 10);
        weekly[week] = (weekly[week] || 0) + 1;
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
            labels: ["Low", "Moderate", "High"],
            datasets: [{
                data: [data.Low, data.Moderate, data.High],
            }]
        }
    });
}


function drawBarangayChart(data) {
    if (barangayChart) barangayChart.destroy();

    barangayChart = new Chart(document.getElementById("barangayChart"), {
        type: "bar",
        data: {
            labels: Object.keys(data),
            datasets: [{
                data: Object.values(data),
            }]
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
            datasets: [{
                data: labels.map(d => data[d]),
            }]
        }
    });
}


// -----------------------------------------------
// AUTO-REFRESH
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

    // Auto-refresh dropdown
    document.getElementById("refreshInterval").addEventListener("change", (e) => {
        startAutoRefresh(e.target.value);
    });

    // Manual refresh button
    document.getElementById("manualRefresh").onclick = updateReports;
});

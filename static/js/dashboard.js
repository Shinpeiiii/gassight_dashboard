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
// LOAD FILTER DROPDOWNS
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
    const infestationType = document.getElementById("infestationFilter").value;

    const start = document.getElementById("startDate").value;
    const end = document.getElementById("endDate").value;

    const params = new URLSearchParams();

    if (barangay !== "All") params.append("barangay", barangay);
    if (severity !== "All") params.append("severity", severity);
    if (infestationType !== "All") params.append("infestation_type", infestationType);
    if (start) params.append("start_date", start);
    if (end) params.append("end_date", end);

    const url = `/api/reports?${params.toString()}`;
    console.log("Fetching:", url);

    const res = await fetch(url);
    const data = await res.json();

    return data;
}



// -----------------------------------------------
// UPDATE EVERYTHING
// -----------------------------------------------
async function updateReports() {
    window.allReports = await fetchReports();
    updateHeatmap();
    updateMarkers();
    updateKPIs();
    updateCharts();
    updateLastUpdated();
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

            // heat intensity based on severity
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
    const severityCount = {
        Low: 0,
        Moderate: 0,
        High: 0,
        Critical: 0,
    };

    const barangayCount = {};
    const weekly = {};

    window.allReports.forEach(r => {
        if (severityCount[r.severity] !== undefined)
            severityCount[r.severity]++;

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
            labels: ["Low", "Moderate", "High", "Critical"],
            datasets: [{
                data: [data.Low, data.Moderate, data.High, data.Critical],
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

    document.getElementById("refreshInterval").addEventListener("change", (e) => {
        startAutoRefresh(e.target.value);
    });

    document.getElementById("manualRefresh").onclick = updateReports;
});

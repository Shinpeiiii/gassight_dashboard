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
    // Center roughly around Ilocos Sur
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
// FETCH REPORTS (WITH FILTERS)
// -----------------------------------------------
async function fetchReports() {
    const params = new URLSearchParams();

    const filters = {
        province: "provinceFilter",
        municipality: "municipalityFilter",
        barangay: "barangayFilter",
        severity: "severityFilter",
        infestation_type: "infestationFilter",
    };

    for (let key in filters) {
        const value = document.getElementById(filters[key]).value;
        if (value !== "All") {
            params.append(key, value);
        }
    }

    const start = document.getElementById("startDate").value;
    const end = document.getElementById("endDate").value;
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
        updateRecentReportsTable();
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
        .map(r => {
            const sev = r.severity || "Pending";
            let weight = null;

            if (sev === "Critical") weight = 1.0;
            else if (sev === "High") weight = 0.9;
            else if (sev === "Moderate") weight = 0.6;
            else if (sev === "Low") weight = 0.3;
            // Pending / unknown => no heat weight

            if (weight === null) return null;
            return [r.lat, r.lng, weight];
        })
        .filter(p => p !== null);

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

        const sev = r.severity || "Pending";
        let color;

        if (sev === "Critical") color = "#6a00ff";
        else if (sev === "High") color = "red";
        else if (sev === "Moderate") color = "orange";
        else if (sev === "Low") color = "green";
        else color = "#6c757d"; // Pending

        const marker = L.circleMarker([r.lat, r.lng], {
            radius: 9,
            color: color,
            fillColor: color,
            fillOpacity: 0.85,
        });

        marker.bindPopup(`
            <strong>${r.barangay || ""}, ${r.municipality || ""}</strong><br>
            <small>${r.infestation_type || ""}</small><br>
            <b>Severity:</b> ${sev}<br>
            <b>Date:</b> ${r.date || ""}<br>
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

    const hotspots = window.allReports.filter(r =>
        r.severity === "High" || r.severity === "Critical"
    ).length;
    document.getElementById("activeHotspots").innerText = hotspots;

    const reporters = new Set(window.allReports.map(r => r.reporter || "Unknown"));
    document.getElementById("activeReporters").innerText = reporters.size;

    // Placeholder for now
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
        if (severityCount[r.severity] !== undefined) {
            severityCount[r.severity]++;
        }

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
// RECENT REPORTS TABLE + PHOTO + EDIT
// -----------------------------------------------
function updateRecentReportsTable() {
    const tbody = document.getElementById("recentReportsTable");
    tbody.innerHTML = "";

    if (!window.allReports.length) {
        tbody.innerHTML = `<tr><td colspan="9" class="text-center text-muted">No reports found</td></tr>`;
        return;
    }

    const sorted = [...window.allReports].sort((a, b) => new Date(b.date) - new Date(a.date));
    const recent = sorted.slice(0, 10);

    recent.forEach(r => {
        const photo = r.photo || "/static/icons/icon-192.png";
        const sev = r.severity || "Pending";
        const sevClass =
            sev === "Critical" ? "danger" :
            sev === "High" ? "warning" :
            sev === "Moderate" ? "info" :
            sev === "Low" ? "success" :
            "secondary";

        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td class="text-center">
                <img src="${photo}"
                     class="img-thumbnail shadow-sm"
                     style="width:60px;height:60px;object-fit:cover;cursor:pointer;border-radius:6px;"
                     onclick="openPhotoModal('${photo}')">
            </td>
            <td>${r.date || "-"}</td>
            <td>${r.province || "-"}</td>
            <td>${r.municipality || "-"}</td>
            <td>${r.barangay || "-"}</td>
            <td>
                <span class="badge bg-${sevClass}">${sev}</span>
            </td>
            <td>${r.infestation_type || "-"}</td>
            <td>${r.reporter || "Unknown"}</td>
            <td class="text-center">
                <button 
                    class="btn btn-sm btn-outline-primary"
                    data-report-id="${r.id}"
                    data-current-severity="${sev}"
                    data-location="${(r.barangay || '')}, ${(r.municipality || '')}"
                    onclick="openSeverityModalFromButton(this)">
                    Set severity
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}


// -----------------------------------------------
// PHOTO MODAL
// -----------------------------------------------
function openPhotoModal(photoUrl) {
    document.getElementById("modalPhoto").src = photoUrl;
    new bootstrap.Modal(document.getElementById("photoModal")).show();
}


// -----------------------------------------------
// SEVERITY MODAL (ADMIN)
// -----------------------------------------------
function openSeverityModalFromButton(btn) {
    const id = btn.getAttribute("data-report-id");
    const severity = btn.getAttribute("data-current-severity") || "Pending";
    const locationText = btn.getAttribute("data-location") || "";

    openSeverityModal(id, severity, locationText);
}

function openSeverityModal(reportId, currentSeverity, locationText) {
    document.getElementById("severityReportId").value = reportId;
    document.getElementById("severitySelect").value = currentSeverity || "Pending";
    document.getElementById("severityLocation").innerText = locationText;

    const errorBox = document.getElementById("severityError");
    errorBox.classList.add("d-none");
    errorBox.textContent = "";

    const modal = new bootstrap.Modal(document.getElementById("severityModal"));
    modal.show();
}

async function saveSeverity() {
    const reportId = document.getElementById("severityReportId").value;
    const severity = document.getElementById("severitySelect").value;
    const errorBox = document.getElementById("severityError");

    errorBox.classList.add("d-none");
    errorBox.textContent = "";

    if (!reportId) {
        errorBox.textContent = "Missing report ID.";
        errorBox.classList.remove("d-none");
        return;
    }

    try {
        const res = await fetch("/api/update_severity", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ id: reportId, severity })
        });

        const data = await res.json();

        if (data.status !== "success") {
            throw new Error(data.error || "Failed to update severity");
        }

        const modalEl = document.getElementById("severityModal");
        const modal = bootstrap.Modal.getInstance(modalEl) || new bootstrap.Modal(modalEl);
        modal.hide();

        await updateReports();

    } catch (err) {
        console.error("Failed to update severity:", err);
        errorBox.textContent = "Failed to update severity. Please try again.";
        errorBox.classList.remove("d-none");
    }
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
// INIT
// -----------------------------------------------
window.addEventListener("load", async () => {
    initMap();
    await loadFilterDropdowns();
    await updateReports();

    document.getElementById("filterBtn").onclick = updateReports;
    document.getElementById("manualRefresh").onclick = updateReports;

    document.getElementById("refreshInterval").addEventListener("change", e =>
        startAutoRefresh(e.target.value)
    );
});

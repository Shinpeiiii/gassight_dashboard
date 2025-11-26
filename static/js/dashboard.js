// -----------------------------------------------
// GLOBAL VARIABLES
// -----------------------------------------------
let map;
let heatLayer;
let markersLayer = L.layerGroup();
window.allReports = [];
window.userProfile = null;

let severityChart, barangayChart, trendChart;
let autoRefreshTimer = null;


// -----------------------------------------------
// SEVERITY COLOR MAPPING
// -----------------------------------------------
const SEVERITY_COLORS = {
    'Pending': { badge: 'severity-pending', marker: '#6c757d' },
    'Low': { badge: 'severity-low', marker: '#28a745' },
    'Moderate': { badge: 'severity-moderate', marker: '#ffc107' },
    'High': { badge: 'severity-high', marker: '#fd7e14' },
    'Critical': { badge: 'severity-critical', marker: '#dc3545' }
};


// -----------------------------------------------
// LOAD USER PROFILE
// -----------------------------------------------
async function loadUserProfile() {
    try {
        const res = await fetch("/api/profile");
        if (!res.ok) {
            console.error("Failed to load profile");
            return;
        }

        window.userProfile = await res.json();
        
        // Update profile button
        const name = window.userProfile.full_name || window.userProfile.username || "User";
        const initials = getInitials(name);
        
        document.getElementById("profileAvatar").textContent = initials;
        document.getElementById("profileName").textContent = name.split(' ')[0]; // First name only
        
    } catch (err) {
        console.error("Error loading profile:", err);
    }
}


// -----------------------------------------------
// GET INITIALS FROM NAME
// -----------------------------------------------
function getInitials(name) {
    if (!name) return "?";
    const parts = name.trim().split(' ');
    if (parts.length === 1) return parts[0][0].toUpperCase();
    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}


// -----------------------------------------------
// SHOW PROFILE MODAL
// -----------------------------------------------
function showProfileModal() {
    if (!window.userProfile) {
        alert("Profile not loaded yet");
        return;
    }

    const profile = window.userProfile;
    const name = profile.full_name || profile.username || "Unknown";
    const initials = getInitials(name);

    document.getElementById("profileModalAvatar").textContent = initials;
    document.getElementById("profileModalName").textContent = name;
    document.getElementById("profileUsername").textContent = profile.username || "-";
    document.getElementById("profileEmail").textContent = profile.email || "-";
    document.getElementById("profilePhone").textContent = profile.phone || profile.contact || "-";
    document.getElementById("profileRole").textContent = profile.is_admin ? "Admin" : "User";
    document.getElementById("profileAddress").textContent = profile.address || "-";
    document.getElementById("profileProvince").textContent = profile.province || "-";
    document.getElementById("profileMunicipality").textContent = profile.municipality || "-";
    document.getElementById("profileBarangay").textContent = profile.barangay || "-";

    const modal = new bootstrap.Modal(document.getElementById("profileModal"));
    modal.show();
}


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
            else if (sev === "High") weight = 0.8;
            else if (sev === "Moderate") weight = 0.5;
            else if (sev === "Low") weight = 0.3;
            // Pending => no heat

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
        const color = SEVERITY_COLORS[sev]?.marker || '#6c757d';

        const marker = L.circleMarker([r.lat, r.lng], {
            radius: 9,
            color: color,
            fillColor: color,
            fillOpacity: 0.85,
        });

        // Fix photo URL - ensure it has proper path
        const photoUrl = getPhotoUrl(r.photo);

        marker.bindPopup(`
            <strong>${r.barangay || ""}, ${r.municipality || ""}</strong><br>
            <small>${r.infestation_type || ""}</small><br>
            <b>Severity:</b> ${sev}<br>
            <b>Date:</b> ${r.date || ""}<br>
            <img src="${photoUrl}" 
                 style="width:120px;border-radius:5px;margin-top:4px;"
                 onerror="this.src='/static/images/snail-logo.png'">
        `);

        markersLayer.addLayer(marker);
    });
}


// -----------------------------------------------
// GET PROPER PHOTO URL
// -----------------------------------------------
function getPhotoUrl(photo) {
    if (!photo) return '/static/images/snail-logo.png';
    
    // If it's already a full URL, return as-is
    if (photo.startsWith('http://') || photo.startsWith('https://')) {
        return photo;
    }
    
    // If it starts with /uploads/, return as-is
    if (photo.startsWith('/uploads/')) {
        return photo;
    }
    
    // If it's just a filename, prepend /uploads/
    if (!photo.startsWith('/')) {
        return '/uploads/' + photo;
    }
    
    return photo;
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
    const severityCount = { Low: 0, Moderate: 0, High: 0, Critical: 0, Pending: 0 };
    const barangayCount = {};
    const weekly = {};

    window.allReports.forEach(r => {
        const sev = r.severity || "Pending";
        if (severityCount[sev] !== undefined) {
            severityCount[sev]++;
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
            labels: ["Pending", "Low", "Moderate", "High", "Critical"],
            datasets: [{
                data: [data.Pending, data.Low, data.Moderate, data.High, data.Critical],
                backgroundColor: [
                    SEVERITY_COLORS.Pending.marker,
                    SEVERITY_COLORS.Low.marker,
                    SEVERITY_COLORS.Moderate.marker,
                    SEVERITY_COLORS.High.marker,
                    SEVERITY_COLORS.Critical.marker
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}


function drawBarangayChart(data) {
    if (barangayChart) barangayChart.destroy();

    // Sort and take top 10
    const sorted = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const labels = sorted.map(x => x[0]);
    const values = sorted.map(x => x[1]);

    barangayChart = new Chart(document.getElementById("barangayChart"), {
        type: "bar",
        data: {
            labels: labels,
            datasets: [{
                label: 'Reports',
                data: values,
                backgroundColor: '#0d6efd'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: { beginAtZero: true }
            }
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
                label: 'Daily Reports',
                data: labels.map(d => data[d]),
                borderColor: '#198754',
                backgroundColor: 'rgba(25, 135, 84, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: { beginAtZero: true }
            }
        }
    });
}


// -----------------------------------------------
// RECENT REPORTS TABLE + PHOTO + EDIT + DELETE
// -----------------------------------------------
function updateRecentReportsTable() {
    const tbody = document.getElementById("recentReportsTable");
    tbody.innerHTML = "";

    if (!window.allReports.length) {
        tbody.innerHTML = `<tr><td colspan="9" class="text-center text-muted">No reports found</td></tr>`;
        return;
    }

    const sorted = [...window.allReports].sort((a, b) => new Date(b.date) - new Date(a.date));
    const recent = sorted.slice(0, 20); // Show top 20

    recent.forEach(r => {
        const photoUrl = getPhotoUrl(r.photo);
        const sev = r.severity || "Pending";
        const sevClass = SEVERITY_COLORS[sev]?.badge || 'severity-pending';

        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td class="text-center">
                <img src="${photoUrl}"
                     class="img-thumbnail shadow-sm"
                     style="width:60px;height:60px;object-fit:cover;cursor:pointer;border-radius:6px;"
                     onerror="this.src='/static/images/snail-logo.png'"
                     onclick="openPhotoModal('${photoUrl}')">
            </td>
            <td>${r.date || "-"}</td>
            <td>${r.province || "-"}</td>
            <td>${r.municipality || "-"}</td>
            <td>${r.barangay || "-"}</td>
            <td>
                <span class="badge ${sevClass}">${sev}</span>
            </td>
            <td>${r.infestation_type || "-"}</td>
            <td>${r.reporter || "Unknown"}</td>
            <td>
                <div class="action-btn-group">
                    <button 
                        class="btn-severity"
                        data-report-id="${r.id}"
                        data-current-severity="${sev}"
                        data-location="${(r.barangay || '')}, ${(r.municipality || '')}"
                        onclick="openSeverityModalFromButton(this)">
                        Set
                    </button>
                    <button 
                        class="btn-delete"
                        data-report-id="${r.id}"
                        onclick="openDeleteModal(${r.id})">
                        Delete
                    </button>
                </div>
            </td>
        `;
        tbody.appendChild(tr);
    });
}


// -----------------------------------------------
// PHOTO MODAL
// -----------------------------------------------
function openPhotoModal(photoUrl) {
    const imgUrl = photoUrl || '/static/images/snail-logo.png';
    document.getElementById("modalPhoto").src = imgUrl;
    document.getElementById("modalPhoto").onerror = function() {
        this.src = '/static/images/snail-logo.png';
    };
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
        errorBox.textContent = err.message || "Failed to update severity. Please try again.";
        errorBox.classList.remove("d-none");
    }
}


// -----------------------------------------------
// DELETE MODAL & CONFIRMATION
// -----------------------------------------------
function openDeleteModal(reportId) {
    document.getElementById("deleteReportId").value = reportId;
    const modal = new bootstrap.Modal(document.getElementById("deleteModal"));
    modal.show();
}

async function confirmDelete() {
    const reportId = document.getElementById("deleteReportId").value;

    if (!reportId) {
        alert("No report ID found");
        return;
    }

    try {
        const res = await fetch(`/api/report/${reportId}`, {
            method: "DELETE"
        });

        const data = await res.json();

        if (data.status !== "success") {
            throw new Error(data.error || "Failed to delete report");
        }

        // Close modal
        const modalEl = document.getElementById("deleteModal");
        const modal = bootstrap.Modal.getInstance(modalEl) || new bootstrap.Modal(modalEl);
        modal.hide();

        // Refresh reports
        await updateReports();

        // Show success message
        alert("Report deleted successfully!");

    } catch (err) {
        console.error("Failed to delete report:", err);
        alert("Failed to delete report: " + err.message);
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
    await loadUserProfile();
    await loadFilterDropdowns();
    await updateReports();

    // Event listeners
    document.getElementById("filterBtn").onclick = updateReports;
    document.getElementById("manualRefresh").onclick = updateReports;
    document.getElementById("profileBtn").onclick = showProfileModal;

    document.getElementById("refreshInterval").addEventListener("change", e =>
        startAutoRefresh(e.target.value)
    );
});
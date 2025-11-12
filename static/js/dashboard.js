// static/js/dashboard.js

let leafletMap, heatLayer;
let allReports = [];
let severityChart, barangayChart, trendChart;

/* ---------------- Toast ---------------- */
function showToast(msg, type = 'info') {
  const c = document.getElementById('toastContainer');
  if (!c) return;
  const t = document.createElement('div');
  t.className = `toast align-items-center text-bg-${type} border-0`;
  t.innerHTML = `
    <div class="d-flex">
      <div class="toast-body">${msg}</div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
    </div>`;
  c.appendChild(t);
  const bsToast = new bootstrap.Toast(t, { delay: 2500 });
  bsToast.show();
  t.addEventListener('hidden.bs.toast', () => t.remove());
}

/* ---------------- Fetch helper ---------------- */
async function fetchJSON(endpoint, opts = {}) {
  try {
    const res = await fetch(endpoint, opts);
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return await res.json();
  } catch (e) {
    console.error('fetchJSON error:', endpoint, e);
    return null;
  }
}

/* ---------------- Reports ---------------- */
async function loadReports() {
  const data = await fetchJSON('/api/reports');
  if (!data) {
    showToast('Failed to load reports', 'danger');
    return;
  }

  allReports = data;

  updateKPIs(allReports);
  renderTable(allReports);
  renderMap();
  updateCharts();

  const highs = allReports.filter((r) => r.severity === 'High');
  showHighAlert(highs);
}

/* ---------------- KPI cards ---------------- */
function updateKPIs(reports) {
  document.getElementById('totalSightings').textContent = reports.length;

  const activeHotspots = new Set(
    reports.filter((r) => r.severity === 'High').map((r) => r.barangay)
  ).size;
  document.getElementById('activeHotspots').textContent = activeHotspots;

  const activeReporters = new Set(reports.map((r) => r.reporter)).size;
  document.getElementById('activeReporters').textContent = activeReporters;

  document.getElementById('avgResponse').textContent = 0;
}

/* ---------------- Table ---------------- */
function renderTable(reports) {
  const tbody = document.querySelector('#reports-table tbody');
  tbody.innerHTML = '';

  reports.forEach((r) => {
    const tr = document.createElement('tr');
    if (r.severity === 'High') tr.classList.add('table-danger');

    const hasPhoto = r.photo && r.photo.trim() !== '';
    const photoUrl = hasPhoto
      ? (r.photo.startsWith('/static/') ? r.photo : '/static/uploads/' + r.photo)
      : '';

    // Status pill
    const statusHtml = (() => {
      const s = r.status || 'Pending';
      const map = { Pending: 'secondary', Approved: 'success', Accepted: 'success', Rejected: 'danger' };
      return `<span class="badge rounded-pill text-bg-${map[s] || 'secondary'}">${s}</span>`;
    })();

    const actionState = r.action_status || 'Not Resolved';
    const actionColor = actionState === 'Resolved' ? 'primary' : 'secondary';

    tr.innerHTML = `
      <td>${r.date || ''}</td>
      <td>${r.reporter || ''}</td>
      <td>
        ${r.barangay && r.municipality ? `${r.barangay}, ${r.municipality}` : ''}
        <br>
        <small class="text-muted" style="cursor:pointer"
               onclick="focusOnMap(${Number(r.lat)}, ${Number(r.lng)})">
          📍 ${r.lat?.toFixed ? r.lat.toFixed(4) : r.lat}, ${r.lng?.toFixed ? r.lng.toFixed(4) : r.lng}
        </small>
      </td>
      <td>${r.severity || ''}</td>
      <td>
        ${
          photoUrl
            ? `<img src="${photoUrl}" alt="photo"
                 style="width:60px;height:60px;object-fit:cover;border-radius:6px;cursor:pointer"
                 onclick="openImage('${photoUrl}')">`
            : '<span class="text-muted">No photo</span>'
        }
      </td>

      <!-- Status -->
      <td>
        ${statusHtml}
        <div class="mt-2 d-flex gap-2">
          <button class="btn btn-sm btn-success" onclick="updateStatus(${r.id}, 'Approved')">✔ Approve</button>
          <button class="btn btn-sm btn-danger"  onclick="updateStatus(${r.id}, 'Rejected')">✖ Reject</button>
        </div>
      </td>

      <!-- Action -->
      <td>
        <span id="action-pill-${r.id}" class="badge rounded-pill text-bg-${actionColor}">${actionState}</span>
        <button class="btn btn-sm btn-outline-secondary ms-2" onclick="toggleAction(${r.id})">Change</button>
      </td>
    `;

    tbody.appendChild(tr);
  });
}

/* ---- Status & Action updaters ---- */
async function updateStatus(id, newStatus) {
  const ok = await fetch(`/api/report/${id}/status`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status: newStatus }),
  }).then((r) => r.ok).catch(() => false);

  if (ok) {
    showToast(`Status saved: ${newStatus}`, 'success');
    loadReports();
  } else {
    showToast('Failed to save status', 'danger');
  }
}

async function toggleAction(id) {
  const pill = document.getElementById(`action-pill-${id}`);
  if (!pill) return;
  const current = pill.textContent.trim();
  const next = current === 'Resolved' ? 'Not Resolved' : 'Resolved';

  const ok = await fetch(`/api/report/${id}/action_status`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action_status: next }),
  }).then((r) => r.ok).catch(() => false);

  if (ok) {
    pill.textContent = next;
    pill.className =
      'badge rounded-pill ' + (next === 'Resolved' ? 'text-bg-primary' : 'text-bg-secondary');
    showToast(`Action set to ${next}`, 'info');
  } else {
    showToast('Failed to update action', 'danger');
  }
}

/* ---------------- Map ---------------- */
function initMap() {
  leafletMap = L.map('map').setView([16.63, 120.33], 10);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(leafletMap);
}

function renderMap() {
  if (!leafletMap) return;

  // ✅ Show all reports (Approved + Pending + Accepted + Rejected)
  const visibleReports = allReports.filter((r) => r.lat && r.lng);

  // ✅ Prepare severity-weighted heat points
  const heatPoints = visibleReports.map((r) => {
    let weight = 0.3;
    if (r.severity === "Moderate") weight = 0.6;
    if (r.severity === "High") weight = 1.0;
    return [Number(r.lat), Number(r.lng), weight];
  });

  if (heatLayer) leafletMap.removeLayer(heatLayer);

  if (heatPoints.length) {
    heatLayer = L.heatLayer(heatPoints, {
      radius: 30,
      blur: 20,
      maxZoom: 17,
      gradient: {
        0.2: "limegreen",
        0.6: "orange",
        1.0: "red"
      },
    }).addTo(leafletMap);
  }

  // ✅ Add severity + status markers
  visibleReports.forEach((r) => {
    let color = "green";
    if (r.severity === "Moderate") color = "orange";
    if (r.severity === "High") color = "red";
    if (r.status === "Pending") color = "gray";

    const marker = L.circleMarker([r.lat, r.lng], {
      radius: 6,
      color: color,
      fillColor: color,
      fillOpacity: 0.7,
    }).addTo(leafletMap);

    marker.bindPopup(`
      <strong>${r.barangay || "Unknown"}</strong><br>
      Severity: <b>${r.severity}</b><br>
      Status: ${r.status}<br>
      <small>${r.date || ""}</small>
    `);
  });
}

function focusOnMap(lat, lng) {
  if (!leafletMap || isNaN(lat) || isNaN(lng)) return;
  leafletMap.flyTo([lat, lng], 16);
  L.marker([lat, lng]).addTo(leafletMap).bindPopup(`📍 ${lat}, ${lng}`).openPopup();
}

/* ---------------- Charts ---------------- */
async function updateCharts() {
  const sevData = await fetchJSON('/api/severity-distribution') || {};
  const brgData = await fetchJSON('/api/barangay-reports') || [];
  const trendData = await fetchJSON('/api/trend') || [];

  if (severityChart) severityChart.destroy();
  if (barangayChart) barangayChart.destroy();
  if (trendChart) trendChart.destroy();

  const sevCtx = document.getElementById('severityChart');
  if (sevCtx) {
    severityChart = new Chart(sevCtx, {
      type: 'pie',
      data: {
        labels: Object.keys(sevData),
        datasets: [{ data: Object.values(sevData), backgroundColor: ['#7cb342','#fbc02d','#e53935'] }],
      },
    });
  }

  const brgCtx = document.getElementById('barangayChart');
  if (brgCtx) {
    barangayChart = new Chart(brgCtx, {
      type: 'bar',
      data: {
        labels: brgData.map((x) => x.name),
        datasets: [{ label: 'Reports', data: brgData.map((x) => x.reports), backgroundColor: '#42a5f5' }],
      },
      options: { plugins: { legend: { display: false } } },
    });
  }

  const trnCtx = document.getElementById('trendChart');
  if (trnCtx) {
    trendChart = new Chart(trnCtx, {
      type: 'line',
      data: {
        labels: trendData.map((x) => x.week),
        datasets: [{ label: 'Sightings', data: trendData.map((x) => x.sightings), borderColor: '#d32f2f', tension: 0.3 }],
      },
      options: { plugins: { legend: { display: false } } },
    });
  }
}

/* ---------------- Image preview ---------------- */
function openImage(url) {
  const w = window.open('');
  w.document.write(`<img src="${url}" style="max-width:100%;height:auto;">`);
}

/* ---------------- Alert (High severity) ---------------- */
function showHighAlert(highReports) {
  const indicator = document.getElementById('alertIndicator');
  if (!indicator) return;
  if (!highReports.length) return indicator.classList.add('d-none');

  indicator.classList.remove('d-none');
  indicator.onclick = () => showHighReports(highReports);
}

function showHighReports(highReports) {
  const list = document.getElementById('highList');
  if (!list) return;
  list.innerHTML = '';

  highReports.forEach((r) => {
    const btn = document.createElement('button');
    btn.className = 'list-group-item list-group-item-action d-flex align-items-center gap-3';
    btn.innerHTML = `
      <img src="${r.photo || '/static/icons/icon-192.png'}" class="thumb"
           style="width:64px;height:64px;border-radius:8px;object-fit:cover;border:2px solid #eee;">
      <div><strong>${r.barangay || 'Unknown'}${r.municipality ? ', ' + r.municipality : ''}</strong><br>
      <small>${r.date || ''} — ${r.reporter || ''}</small></div>`;
    btn.addEventListener('click', () => {
      const modalEl = document.getElementById('highModal');
      const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
      modalEl.addEventListener('hidden.bs.modal', () => {
        setTimeout(() => {
          leafletMap.invalidateSize();
          document.getElementById('map')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
          focusOnMap(Number(r.lat), Number(r.lng));
        }, 350);
      }, { once: true });
      modal.hide();
    });
    list.appendChild(btn);
  });

  bootstrap.Modal.getOrCreateInstance(document.getElementById('highModal')).show();
}

/* ---------------- Init ---------------- */
window.addEventListener('load', () => {
  initMap();
  loadReports();
  setInterval(loadReports, 15000); // Auto-refresh every 15s
});

/* ---------------- Service Worker ---------------- */
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/service-worker.js')
    .then(() => console.log('✅ Service Worker registered'))
    .catch(err => console.error('SW registration failed:', err));
}

/* ---------------- User Location ---------------- */
if (navigator.geolocation) {
  navigator.geolocation.getCurrentPosition((pos) => {
    const { latitude, longitude } = pos.coords;
    const userMarker = L.circleMarker([latitude, longitude], {
      radius: 8,
      color: "blue",
      fillColor: "blue",
      fillOpacity: 0.8,
    }).addTo(leafletMap);
    userMarker.bindPopup("📍 You are here").openPopup();
  });
}

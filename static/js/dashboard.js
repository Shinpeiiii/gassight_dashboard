// static/js/dashboard.js

let map, heatLayer;
let allReports = [];
let severityChart, barangayChart, trendChart;

// Toast notification
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
  const bsToast = new bootstrap.Toast(t, { delay: 3000 });
  bsToast.show();
  t.addEventListener('hidden.bs.toast', () => t.remove());
}

// ============ LOAD REPORTS ============
async function loadReports() {
  try {
    const response = await fetch('/api/reports');
    const reports = await response.json();
    allReports = Array.isArray(reports) ? reports : [];

    // ===== Update KPIs =====
    updateKPIs(allReports);

    // ===== Update Table =====
    const tableBody = document.querySelector('#reports-table tbody');
    tableBody.innerHTML = '';

    allReports.forEach((r) => {
      const row = document.createElement('tr');
      if (r.severity === 'High') row.classList.add('table-danger');

      let photoUrl = '';
      if (r.photo && r.photo.trim() !== '') {
        photoUrl = r.photo.startsWith('/static/')
          ? r.photo
          : '/static/uploads/' + r.photo;
      }

      row.innerHTML = `
        <td>${r.date || ''}</td>
        <td>${r.reporter || ''}</td>
        <td>${r.barangay && r.municipality ? `${r.barangay}, ${r.municipality}` : ''}</td>
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
        <td>${r.status || 'Pending'}</td>
        <td>
          <select class="form-select form-select-sm action-select" data-id="${r.id}">
            <option value="">Select Status</option>
            <option value="Resolved">Resolved</option>
            <option value="Not Resolved">Not Resolved</option>
          </select>
        </td>`;
      tableBody.appendChild(row);
    });

    // Status update handling
    document.querySelectorAll('.action-select').forEach((select) => {
      select.addEventListener('change', async (e) => {
        const reportId = e.target.dataset.id;
        const newStatus = e.target.value;
        if (!newStatus) return;
        try {
          const res = await fetch(`/api/report/${reportId}/status`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: newStatus }),
          });
          if (res.ok) {
            showToast(`Report ${reportId} updated to ${newStatus}`, 'success');
            loadReports();
          } else showToast('Failed to update status', 'danger');
        } catch (err) {
          console.error('Error updating status:', err);
        }
      });
    });

    renderMap();
    updateCharts();
    showHighAlert(allReports.filter((r) => r.severity === 'High'));
  } catch (err) {
    console.error('Failed to load reports:', err);
    showToast('Failed to load reports', 'danger');
  }
}

// ============ UPDATE KPI CARDS ============
function updateKPIs(reports) {
  // Total reports
  document.getElementById('totalSightings').textContent = reports.length;

  // Active hotspots: unique barangays with high severity
  const activeHotspots = new Set(
    reports.filter((r) => r.severity === 'High').map((r) => r.barangay)
  ).size;
  document.getElementById('activeHotspots').textContent = activeHotspots;

  // Active reporters: unique names
  const activeReporters = new Set(reports.map((r) => r.reporter)).size;
  document.getElementById('activeReporters').textContent = activeReporters;

  // Average response time (if exists)
  const validReports = reports.filter((r) => r.response_time_hours);
  if (validReports.length > 0) {
    const avg =
      validReports.reduce((a, b) => a + b.response_time_hours, 0) /
      validReports.length;
    document.getElementById('avgResponse').textContent = Math.round(avg);
  } else {
    document.getElementById('avgResponse').textContent = 0;
  }
}

// ============ MAP ============
function initMap() {
  map = L.map('map').setView([16.63, 120.33], 10);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);
}

function renderMap() {
  if (!map) return;
  const pts = allReports
    .filter((r) => r.lat && r.lng)
    .map((r) => [
      r.lat,
      r.lng,
      r.severity === 'High' ? 1 : r.severity === 'Moderate' ? 0.6 : 0.3,
    ]);
  if (heatLayer) map.removeLayer(heatLayer);
  if (pts.length > 0)
    heatLayer = L.heatLayer(pts, { radius: 25, blur: 15 }).addTo(map);
}

// ============ CHARTS ============
async function updateCharts() {
  const sevData = await fetchJSON('/api/severity-distribution');
  const brgData = await fetchJSON('/api/barangay-reports');
  const trendData = await fetchJSON('/api/trend');

  if (severityChart) severityChart.destroy();
  if (barangayChart) barangayChart.destroy();
  if (trendChart) trendChart.destroy();

  const sevCtx = document.getElementById('severityChart');
  if (sevCtx) {
    severityChart = new Chart(sevCtx, {
      type: 'pie',
      data: {
        labels: Object.keys(sevData),
        datasets: [
          {
            data: Object.values(sevData),
            backgroundColor: ['#7cb342', '#fbc02d', '#e53935'],
          },
        ],
      },
    });
  }

  const brgCtx = document.getElementById('barangayChart');
  if (brgCtx) {
    barangayChart = new Chart(brgCtx, {
      type: 'bar',
      data: {
        labels: brgData.map((x) => x.name),
        datasets: [
          {
            label: 'Reports',
            data: brgData.map((x) => x.reports),
            backgroundColor: '#42a5f5',
          },
        ],
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
        datasets: [
          {
            label: 'Sightings',
            data: trendData.map((x) => x.sightings),
            borderColor: '#d32f2f',
            tension: 0.3,
          },
        ],
      },
      options: { plugins: { legend: { display: false } } },
    });
  }
}

async function fetchJSON(endpoint) {
  try {
    const res = await fetch(endpoint);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (e) {
    console.error(`Fetch error: ${endpoint}`, e);
    return [];
  }
}

// ============ IMAGE PREVIEW ============
function openImage(url) {
  const imgWindow = window.open('');
  imgWindow.document.write(`<img src="${url}" style="max-width:100%;height:auto;">`);
}

// ============ HIGH ALERT ============
function showHighAlert(highReports) {
  const alert = document.getElementById('alertIndicator');
  if (!alert) return;
  if (!highReports.length) {
    alert.classList.add('d-none');
    return;
  }
  alert.classList.remove('d-none');
  alert.onclick = () => showHighReports(highReports);
}

function showHighReports(highReports) {
  const list = document.getElementById('highList');
  if (!list) return;
  list.innerHTML = '';

  highReports.forEach((r) => {
    const item = document.createElement('button');
    item.className =
      'list-group-item list-group-item-action d-flex align-items-center gap-3';
    item.innerHTML = `
      <img src="${
        r.photo && r.photo.trim() !== '' ? r.photo : '/static/icons/icon-192.png'
      }"
        class="thumb"
        style="width:64px;height:64px;border-radius:8px;object-fit:cover;border:2px solid #eee;">
      <div>
        <strong>${r.barangay || 'Unknown'}${
      r.municipality ? ', ' + r.municipality : ''
    }</strong><br>
        <small>${r.date || ''} — ${r.reporter || ''}</small>
      </div>
    `;

    // 🔍 Click behavior for zooming into GPS location
    item.addEventListener('click', () => {
      const lat = Number(r.lat),
        lng = Number(r.lng);
      if (!map || Number.isNaN(lat) || Number.isNaN(lng)) return;

      const modalEl = document.getElementById('highModal');
      const modal = bootstrap.Modal.getOrCreateInstance(modalEl);

      // Wait until modal is fully closed before adjusting the map
      modalEl.addEventListener(
        'hidden.bs.modal',
        () => {
          // Recalculate map size and scroll it into view
          map.invalidateSize();
          document
            .getElementById('map')
            ?.scrollIntoView({ behavior: 'smooth', block: 'center' });

          // Smooth fly animation to the GPS coordinates
          map.flyTo([lat, lng], 16, {
            animate: true,
            duration: 1.5,
          });

          // Add a temporary pulsing marker for visibility
          const pulse = L.circleMarker([lat, lng], {
            radius: 10,
            color: 'red',
            fillColor: 'red',
            fillOpacity: 0.5,
            weight: 3,
          }).addTo(map);

          setTimeout(() => {
            map.removeLayer(pulse);
          }, 3000);
        },
        { once: true }
      );

      modal.hide(); // Close the modal and trigger the hidden event
    });

    list.appendChild(item);
  });

  // Show modal
  bootstrap.Modal.getOrCreateInstance(
    document.getElementById('highModal')
  ).show();
}

// ============ INIT ============
window.addEventListener('load', () => {
  initMap();
  loadReports();
  setInterval(loadReports, 15000);
});

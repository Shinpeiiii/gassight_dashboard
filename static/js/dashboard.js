// static/js/dashboard.js

async function loadReports() {
  try {
    const response = await fetch('/api/reports');
    const reports = await response.json();

    const tableBody = document.querySelector('#reports-table tbody');
    tableBody.innerHTML = '';

    reports.forEach((r) => {
      const row = document.createElement('tr');
      if (r.severity === 'High') row.classList.add('table-danger');

      // ✅ Fix photo path — must start with /static/uploads/
      let photoUrl = '';
      if (r.photo && r.photo.trim() !== '') {
        // if photo path doesn’t start with /static/, prepend it
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
        </td>
      `;
      tableBody.appendChild(row);
    });

    // ✅ Status update handling
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
            console.log(`✅ Report ${reportId} updated to ${newStatus}`);
            loadReports();
          } else {
            console.error('Failed to update status');
          }
        } catch (err) {
          console.error('Error updating status:', err);
        }
      });
    });

  } catch (err) {
    console.error('Failed to load reports:', err);
  }
}

// ✅ Enlarge image in new window
function openImage(url) {
  const imgWindow = window.open('');
  imgWindow.document.write(`<img src="${url}" style="max-width:100%;height:auto;">`);
}

loadReports();
setInterval(loadReports, 10000);

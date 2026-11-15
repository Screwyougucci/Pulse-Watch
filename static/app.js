const siteList = document.querySelector('#sites');
const notice = document.querySelector('#notice');
const dialog = document.querySelector('#add-dialog');
const form = document.querySelector('#add-form');
const formError = document.querySelector('#form-error');
const labels = {
  'content-security-policy': 'Content-Security-Policy',
  'strict-transport-security': 'Strict-Transport-Security',
  'x-content-type-options': 'X-Content-Type-Options',
  'x-frame-options': 'X-Frame-Options',
  'referrer-policy': 'Referrer-Policy',
};

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[char]));
}

function showNotice(message) {
  notice.textContent = message;
  notice.hidden = !message;
}

async function request(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
  });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || `Request failed (${response.status}).`);
  return value;
}

function statusOf(site) {
  if (site.paused) return ['Paused', 'paused'];
  if (!site.last_check) return ['Pending first check', 'pending'];
  return site.last_check.success ? ['Online', 'up'] : ['Check failed', 'down'];
}

function dateLabel(value) {
  if (!value) return 'Not checked yet';
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? 'Unknown' : date.toLocaleString();
}

function renderSite(site) {
  const check = site.last_check;
  const [status, statusClass] = statusOf(site);
  const responseTime = check?.response_time_ms == null ? '—' : `${check.response_time_ms} ms`;
  const httpStatus = check?.status_code == null ? '—' : `HTTP ${check.status_code}`;
  const certificate = check?.certificate?.expires_at
    ? `Expires ${new Date(check.certificate.expires_at).toLocaleDateString()}`
    : (new URL(site.url).protocol === 'https:' ? 'Not available' : 'Not applicable');
  const checks = Object.entries(labels).map(([key, label]) => {
    const state = check?.headers?.[key] || 'not checked';
    const className = state === 'present' ? 'present' : state === 'missing' ? 'missing' : '';
    return `<div class="header-chip"><b>${esc(label)}</b><span class="${className}">${esc(state.replaceAll('_', ' '))}</span></div>`;
  }).join('');
  const detail = check?.error
    ? `<div class="details"><h3>Latest check</h3><div class="data-value">${esc(check.error)} · ${esc(dateLabel(check.checked_at))}</div>${check.headers && Object.keys(check.headers).length ? `<div class="header-grid" style="margin-top:12px">${checks}</div>` : ''}</div>`
    : `<div class="details"><h3>Latest check · ${esc(dateLabel(check?.checked_at))}</h3><div class="header-grid">${checks}</div></div>`;

  return `<article class="site-card" data-id="${esc(site.id)}">
    <div class="site-main">
      <div class="site-address"><a href="${esc(site.url)}" target="_blank" rel="noopener noreferrer">${esc(site.url)}</a><small>Added ${esc(dateLabel(site.created_at))}</small></div>
      <div class="data-cell"><span class="data-label">Status</span><span class="status ${statusClass}">${esc(status)}</span></div>
      <div class="data-cell"><span class="data-label">Response</span><span class="data-value">${esc(responseTime)}</span></div>
      <div class="data-cell"><span class="data-label">HTTP / TLS</span><span class="data-value">${esc(httpStatus)} · ${esc(certificate)}</span></div>
      <div class="actions">
        <button class="text-button" data-action="check" type="button">Check now</button>
        <button class="text-button" data-action="pause" type="button">${site.paused ? 'Resume' : 'Pause'}</button>
        <button class="text-button" data-action="delete" type="button">Delete</button>
      </div>
    </div>${detail}
  </article>`;
}

function updateMetrics(sites) {
  const checked = sites.filter(site => site.last_check && !site.paused);
  const online = checked.filter(site => site.last_check.success);
  const failed = checked.filter(site => !site.last_check.success);
  const times = online.map(site => site.last_check.response_time_ms).filter(Number.isFinite);
  document.querySelector('#metric-total').textContent = sites.length;
  document.querySelector('#metric-online').textContent = online.length;
  document.querySelector('#metric-attention').textContent = failed.length;
  document.querySelector('#metric-response').textContent = times.length
    ? `${Math.round(times.reduce((sum, value) => sum + value, 0) / times.length)} ms`
    : '—';
}

async function loadSites() {
  showNotice('');
  try {
    const sites = await request('/api/sites');
    updateMetrics(sites);
    siteList.innerHTML = sites.length
      ? sites.map(renderSite).join('')
      : '<div class="empty-state"><strong>No websites yet</strong><p>Add a public website to start collecting real monitoring data.</p></div>';
  } catch (error) {
    siteList.innerHTML = '<div class="empty-state"><strong>Monitoring data unavailable</strong><p>PulseWatch could not retrieve the saved website list.</p></div>';
    showNotice(error.message);
  }
}

document.querySelector('#open-add').addEventListener('click', () => {
  formError.hidden = true;
  dialog.showModal();
  document.querySelector('#site-url').focus();
});
document.querySelector('#close-add').addEventListener('click', () => dialog.close());
document.querySelector('#cancel-add').addEventListener('click', () => dialog.close());
document.querySelector('#refresh').addEventListener('click', loadSites);

form.addEventListener('submit', async event => {
  event.preventDefault();
  formError.hidden = true;
  const button = form.querySelector('[type="submit"]');
  button.disabled = true;
  try {
    await request('/api/sites', {
      method: 'POST',
      body: JSON.stringify({ url: new FormData(form).get('url') }),
    });
    form.reset();
    dialog.close();
    await loadSites();
  } catch (error) {
    formError.textContent = error.message;
    formError.hidden = false;
  } finally {
    button.disabled = false;
  }
});

siteList.addEventListener('click', async event => {
  const button = event.target.closest('button[data-action]');
  if (!button) return;
  const card = button.closest('[data-id]');
  const id = card.dataset.id;
  button.disabled = true;
  try {
    if (button.dataset.action === 'check') {
      await request(`/api/sites/${encodeURIComponent(id)}/check`, {
        method: 'POST', body: '{}',
      });
      showNotice('A check was queued. Refresh in a few seconds to see its result.');
    } else if (button.dataset.action === 'pause') {
      const paused = button.textContent.trim() !== 'Resume';
      await request(`/api/sites/${encodeURIComponent(id)}`, {
        method: 'PATCH', body: JSON.stringify({ paused }),
      });
      await loadSites();
    } else if (button.dataset.action === 'delete') {
      if (!window.confirm('Delete this website and its monitoring history?')) return;
      await request(`/api/sites/${encodeURIComponent(id)}`, { method: 'DELETE' });
      await loadSites();
    }
  } catch (error) {
    showNotice(error.message);
  } finally {
    button.disabled = false;
  }
});

loadSites();
window.setInterval(loadSites, 15000);

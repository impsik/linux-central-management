(function () {
  'use strict';

  let catalog = [];
  let selectedMitigation = '';
  let hosts = [];
  const selectedHosts = new Set();

  const esc = (value) => String(value ?? '')
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;').replaceAll("'", '&#039;');

  function updateCount() {
    const el = document.getElementById('mitigation-hosts-count');
    if (el) el.textContent = String(selectedHosts.size);
  }

  function renderCatalog() {
    const wrap = document.getElementById('security-mitigations-list');
    if (!wrap) return;
    if (!catalog.length) {
      wrap.innerHTML = '<div class="status-muted">No mitigations are available.</div>';
      return;
    }
    if (!selectedMitigation) selectedMitigation = catalog[0].id;
    wrap.innerHTML = catalog.map((item) => `
      <label style="display:block;border:1px solid var(--border);border-radius:10px;padding:0.75rem;margin-bottom:0.5rem;">
        <span style="display:flex;gap:0.6rem;align-items:flex-start;">
          <input type="radio" name="security-mitigation" value="${esc(item.id)}" ${item.id === selectedMitigation ? 'checked' : ''} />
          <span><strong>${esc(item.name)}</strong> <code>v${esc(item.version)}</code>
          <span class="status-warn" style="margin-left:0.4rem;">${esc(item.severity)}</span><br>
          <span class="status-muted">${esc(item.summary)}</span><br>
          <span class="status-muted">Apply: ${item.apply_available ? 'available with approval' : 'not enabled yet'}</span></span>
        </span>
      </label>`).join('');
    wrap.querySelectorAll('input[name="security-mitigation"]').forEach((input) => {
      input.addEventListener('change', () => { selectedMitigation = input.value; });
    });
  }

  function renderHosts() {
    const wrap = document.getElementById('mitigation-hosts-list');
    if (!wrap) return;
    if (!hosts.length) {
      wrap.innerHTML = '<div class="status-muted">No visible hosts.</div>';
      return;
    }
    wrap.innerHTML = hosts.map((host) => {
      const id = String(host.agent_id || host.id || '');
      const label = host.hostname || host.fqdn || id;
      return `<label style="display:flex;gap:0.5rem;align-items:center;padding:0.3rem;">
        <input type="checkbox" data-agent-id="${esc(id)}" ${selectedHosts.has(id) ? 'checked' : ''} />
        <span>${esc(label)} <code>${esc(id)}</code></span>
      </label>`;
    }).join('');
    wrap.querySelectorAll('input[data-agent-id]').forEach((input) => {
      input.addEventListener('change', () => {
        if (input.checked) selectedHosts.add(input.dataset.agentId);
        else selectedHosts.delete(input.dataset.agentId);
        updateCount();
      });
    });
    updateCount();
  }

  function renderResults(job) {
    const wrap = document.getElementById('mitigation-results');
    if (!wrap) return;
    const rows = (job.runs || []).map((run) => {
      let result = {};
      try { result = JSON.parse(run.stdout_tail || run.stdout || '{}'); } catch (_) { result = {}; }
      const state = result.status || run.status;
      const cls = state === 'mitigated' || state === 'not_applicable' ? 'status-ok' : (state === 'vulnerable' ? 'status-error' : 'status-muted');
      return `<tr><td><code>${esc(run.agent_id)}</code></td><td class="${cls}">${esc(state)}</td><td>${esc(result.detail || run.error || '')}</td></tr>`;
    }).join('');
    wrap.innerHTML = `<table class="process-table"><thead><tr><th>Host</th><th>Assessment</th><th>Detail</th></tr></thead><tbody>${rows}</tbody></table>`;
  }

  async function pollJob(jobId) {
    const status = document.getElementById('mitigation-status');
    for (let attempt = 0; attempt < 60; attempt += 1) {
      const response = await fetch(`/jobs/${encodeURIComponent(jobId)}`, { credentials: 'include' });
      if (!response.ok) throw new Error(`job status failed (${response.status})`);
      const job = await response.json();
      renderResults(job);
      if (job.done) {
        if (status) status.textContent = 'Assessment complete.';
        return;
      }
      if (status) status.textContent = 'Assessment running…';
      await new Promise((resolve) => setTimeout(resolve, 1500));
    }
    if (status) status.textContent = 'Assessment is still running. Check Queue health for details.';
  }

  async function assess() {
    const status = document.getElementById('mitigation-status');
    if (!selectedMitigation) return window.showToast?.('Select a mitigation', 'error');
    if (!selectedHosts.size) return window.showToast?.('Select at least one host', 'error');
    const button = document.getElementById('mitigation-assess');
    if (button) button.disabled = true;
    try {
      if (status) status.textContent = 'Queueing assessment…';
      const response = await fetch(`/security/mitigations/${encodeURIComponent(selectedMitigation)}/assess`, {
        method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agent_ids: Array.from(selectedHosts) }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.detail || `assessment failed (${response.status})`);
      await pollJob(body.job_id);
    } catch (error) {
      if (status) status.textContent = error.message || String(error);
      window.showToast?.(`Assessment failed: ${error.message || error}`, 'error');
    } finally {
      if (button) button.disabled = false;
    }
  }

  async function load() {
    try {
      const [catalogResponse, hostsResponse] = await Promise.all([
        fetch('/security/mitigations', { credentials: 'include' }),
        fetch('/hosts?limit=500', { credentials: 'include' }),
      ]);
      if (!catalogResponse.ok) throw new Error(`mitigation catalog failed (${catalogResponse.status})`);
      if (!hostsResponse.ok) throw new Error(`hosts failed (${hostsResponse.status})`);
      catalog = (await catalogResponse.json()).items || [];
      const hostBody = await hostsResponse.json();
      hosts = Array.isArray(hostBody) ? hostBody : (hostBody.items || hostBody.hosts || []);
      renderCatalog();
      renderHosts();
    } catch (error) {
      const wrap = document.getElementById('security-mitigations-list');
      if (wrap) wrap.innerHTML = `<div class="status-error">${esc(error.message || error)}</div>`;
    }
  }

  document.getElementById('mitigation-hosts-select-all')?.addEventListener('click', () => {
    hosts.forEach((host) => selectedHosts.add(String(host.agent_id || host.id || '')));
    renderHosts();
  });
  document.getElementById('mitigation-hosts-select-none')?.addEventListener('click', () => {
    selectedHosts.clear(); renderHosts();
  });
  document.getElementById('mitigation-assess')?.addEventListener('click', assess);
  window.fleetSecurityMitigationsUi = { load };
})();

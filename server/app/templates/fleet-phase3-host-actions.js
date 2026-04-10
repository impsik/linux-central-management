(function (w) {
  function initHostActionControls(ctx) {
    const api = ctx || {};
    document.getElementById('app-title')?.addEventListener('click', function (e) {
      e.preventDefault();
      if (typeof api.showServerInfo === 'function') api.showServerInfo();
    });
    document.getElementById('host-action-terminal')?.addEventListener('click', function (e) {
      e.preventDefault();
      if (typeof api.showTerminal === 'function') api.showTerminal();
    });
    document.getElementById('host-action-users')?.addEventListener('click', function (e) {
      e.preventDefault();
      if (typeof api.showUsers === 'function') api.showUsers();
    });
    document.getElementById('host-action-services')?.addEventListener('click', function (e) {
      e.preventDefault();
      if (typeof api.showServices === 'function') api.showServices();
    });
    document.getElementById('host-action-packages')?.addEventListener('click', function (e) {
      e.preventDefault();
      if (typeof api.showPackages === 'function') api.showPackages();
    });
  }

  function collectEnvEntriesFromDom() {
    const out = {};
    document.querySelectorAll('[data-host-meta-env-row="1"]').forEach((row) => {
      const k = (row.querySelector('[data-host-meta-env-key="1"]')?.value || '').trim();
      const v = (row.querySelector('[data-host-meta-env-val="1"]')?.value || '').trim();
      if (!k) return;
      out[k] = v;
    });
    return out;
  }

  function appendEnvRow(key, val) {
    const list = document.getElementById('host-meta-env-list');
    if (!list) return;
    const row = document.createElement('div');
    row.setAttribute('data-host-meta-env-row', '1');
    row.style.display = 'grid';
    row.style.gridTemplateColumns = 'minmax(120px,1fr) minmax(180px,2fr) auto';
    row.style.gap = '0.35rem';
    row.innerHTML = `
      <input data-host-meta-env-key="1" class="host-search" type="text" placeholder="ENV_KEY" value="${w.escapeHtml(String(key || ''))}" />
      <input data-host-meta-env-val="1" class="host-search" type="text" placeholder="value" value="${w.escapeHtml(String(val || ''))}" />
      <button class="btn" data-host-meta-env-del="1" type="button">×</button>
    `;
    row.querySelector('[data-host-meta-env-del="1"]')?.addEventListener('click', (e) => {
      e.preventDefault();
      row.remove();
    });
    list.appendChild(row);
  }

  function ensureOwnerInput() {
    let ownerEl = document.getElementById('host-meta-owner');
    if (ownerEl) return ownerEl;
    const roleEl = document.getElementById('host-meta-role');
    if (!roleEl || !roleEl.parentElement) return null;
    ownerEl = document.createElement('input');
    ownerEl.id = 'host-meta-owner';
    ownerEl.className = 'host-search';
    ownerEl.type = 'text';
    ownerEl.placeholder = 'Owner (person responsible for this server)';
    roleEl.insertAdjacentElement('afterend', ownerEl);
    return ownerEl;
  }

  function populateHostMetadataEditor(host) {
    const nameEl = document.getElementById('host-meta-name');
    const roleEl = document.getElementById('host-meta-role');
    const ownerEl = ensureOwnerInput();
    const list = document.getElementById('host-meta-env-list');
    const statusEl = document.getElementById('host-meta-status');
    if (!nameEl || !roleEl || !ownerEl || !list) return;

    const labels = (host && typeof host.labels === 'object' && host.labels) ? host.labels : {};
    const envVars = (labels && typeof labels.env_vars === 'object' && labels.env_vars) ? labels.env_vars : {};

    nameEl.value = String(host?.hostname || host?.agent_id || '');
    roleEl.value = String(labels.role || '');
    ownerEl.value = String(labels.owner || '');
    list.innerHTML = '';
    const pairs = Object.entries(envVars);
    if (!pairs.length) appendEnvRow('', '');
    else pairs.forEach(([k, v]) => appendEnvRow(k, v));
    if (statusEl) statusEl.textContent = '';
  }

  function normalizeHostMetadataPayload(input) {
    const src = input || {};
    const envIn = (src.env && typeof src.env === 'object') ? src.env : {};
    const env = {};
    Object.keys(envIn).forEach((k) => {
      const key = String(k || '').trim();
      if (!key) return;
      env[key] = String(envIn[k] || '').trim();
    });
    return {
      hostname: String(src.hostname || '').trim(),
      role: String(src.role || '').trim(),
      owner: String(src.owner || '').trim(),
      env,
    };
  }

  function initHostMetadataEditor(ctx) {
    const api = ctx || {};
    ensureOwnerInput();
    const addBtn = document.getElementById('host-meta-env-add');
    const saveBtn = document.getElementById('host-meta-save');
    const statusEl = document.getElementById('host-meta-status');

    addBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      appendEnvRow('', '');
    });

    saveBtn?.addEventListener('click', async (e) => {
      e.preventDefault();
      const agentId = (typeof api.getCurrentAgentId === 'function') ? api.getCurrentAgentId() : null;
      if (!agentId) return;
      const payload = normalizeHostMetadataPayload({
        hostname: document.getElementById('host-meta-name')?.value || '',
        role: document.getElementById('host-meta-role')?.value || '',
        owner: document.getElementById('host-meta-owner')?.value || '',
        env: collectEnvEntriesFromDom(),
      });

      try {
        saveBtn.disabled = true;
        if (statusEl) statusEl.textContent = 'Saving…';
        const r = await fetch(`/hosts/${encodeURIComponent(agentId)}/metadata`, {
          method: 'PATCH',
          credentials: 'include',
          headers: {
            'content-type': 'application/json',
            'X-CSRF-Token': (typeof w.getCookie === 'function' ? (w.getCookie('fleet_csrf') || '') : ''),
          },
          body: JSON.stringify(payload),
        });
        const raw = await r.text();
        let d = null; try { d = raw ? JSON.parse(raw) : null; } catch {}
        if (!r.ok) throw new Error((d && (d.detail || d.error)) || raw || `Save failed (${r.status})`);

        if (typeof api.onMetadataSaved === 'function') api.onMetadataSaved(d?.host || null);
        if (statusEl) statusEl.textContent = 'Saved.';
        if (typeof w.showToast === 'function') w.showToast('Host metadata updated', 'success');
      } catch (err) {
        const msg = err?.message || String(err);
        if (statusEl) statusEl.textContent = msg;
        if (typeof w.showToast === 'function') w.showToast(msg, 'error');
      } finally {
        saveBtn.disabled = false;
      }
    });
  }

  function initCommonModalDismissHandlers(ctx) {
    const api = ctx || {};
    const getCurrentMetricsAgentId = typeof api.getCurrentMetricsAgentId === 'function' ? api.getCurrentMetricsAgentId : function () { return null; };

    document.getElementById('disk-card')?.addEventListener('click', function (e) {
      e.preventDefault();
      const aid = getCurrentMetricsAgentId();
      if (!aid) return;
      if (typeof api.openDiskModal === 'function') api.openDiskModal(aid);
    });
    document.getElementById('disk-modal-close')?.addEventListener('click', function (e) { e.preventDefault(); if (typeof api.closeDiskModal === 'function') api.closeDiskModal(); });
    document.getElementById('disk-modal')?.addEventListener('click', function (e) { if (e.target && e.target.id === 'disk-modal' && typeof api.closeDiskModal === 'function') api.closeDiskModal(); });

    document.getElementById('service-modal-close')?.addEventListener('click', function (e) { e.preventDefault(); if (typeof api.closeServiceModal === 'function') api.closeServiceModal(); });
    document.getElementById('service-modal')?.addEventListener('click', function (e) { if (e.target && e.target.id === 'service-modal' && typeof api.closeServiceModal === 'function') api.closeServiceModal(); });

    document.getElementById('user-modal-close')?.addEventListener('click', function (e) { e.preventDefault(); if (typeof api.closeUserModal === 'function') api.closeUserModal(); });
    document.getElementById('user-modal')?.addEventListener('click', function (e) { if (e.target && e.target.id === 'user-modal' && typeof api.closeUserModal === 'function') api.closeUserModal(); });
  }

  w.phase3HostActions = {
    initHostActionControls: initHostActionControls,
    normalizeHostMetadataPayload: normalizeHostMetadataPayload,
    initHostMetadataEditor: initHostMetadataEditor,
    populateHostMetadataEditor: populateHostMetadataEditor,
    initCommonModalDismissHandlers: initCommonModalDismissHandlers,
  };
})(window);

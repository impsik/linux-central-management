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
    document.getElementById('host-action-firewall')?.addEventListener('click', function (e) {
      e.preventDefault();
      if (typeof api.showFirewall === 'function') api.showFirewall();
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

  function populateHostMetadataEditor(host) {
    const nameEl = document.getElementById('host-meta-name');
    const roleEl = document.getElementById('host-meta-role');
    const teamEl = document.getElementById('host-meta-team');
    const ownerEl = document.getElementById('host-meta-owner');
    const list = document.getElementById('host-meta-env-list');
    const statusEl = document.getElementById('host-meta-status');
    if (!nameEl || !roleEl || !ownerEl || !list) return;

    const labels = (host && typeof host.labels === 'object' && host.labels) ? host.labels : {};
    const envVars = (labels && typeof labels.env_vars === 'object' && labels.env_vars) ? labels.env_vars : {};

    nameEl.value = String(host?.hostname || host?.agent_id || '');
    roleEl.value = String(labels.role || '');
    if (teamEl) teamEl.value = String(labels.team || '');
    ownerEl.value = String(labels.owner || '');
    list.innerHTML = '';
    const pairs = Object.entries(envVars);
    if (!pairs.length) appendEnvRow('', '');
    else pairs.forEach(([k, v]) => appendEnvRow(k, v));
    if (statusEl) statusEl.textContent = '';
  }

  function populateDiskCleanupPanel(host) {
    const statusEl = document.getElementById('disk-cleanup-status');
    const outputEl = document.getElementById('disk-cleanup-output');
    if (statusEl) {
      const online = host?.is_online ? 'Ready' : 'Agent offline';
      statusEl.textContent = online;
    }
    if (outputEl) {
      outputEl.style.display = 'none';
      outputEl.textContent = '';
    }
  }

  function formatDiskCleanupResult(data) {
    const lines = [];
    const dryRun = !!data?.dry_run;
    lines.push((dryRun ? 'Dry run' : 'Cleanup complete') + ': estimated reclaimable ' + (data?.total_reclaimable_human || '0B'));
    const actions = Array.isArray(data?.actions) ? data.actions : [];
    actions.forEach((item) => {
      const label = item?.label || item?.key || 'action';
      const status = item?.status || 'unknown';
      const reclaim = item?.reclaimable_human ? ' · ' + item.reclaimable_human : '';
      const detail = item?.detail ? ' · ' + item.detail : '';
      lines.push('- ' + label + ': ' + status + reclaim + detail);
    });
    if (data?.note) lines.push('', data.note);
    return lines.join('\n');
  }

  function initDiskCleanupControls(ctx) {
    const api = ctx || {};
    const dryBtn = document.getElementById('disk-cleanup-dry-run');
    const applyBtn = document.getElementById('disk-cleanup-apply');
    const statusEl = document.getElementById('disk-cleanup-status');
    const outputEl = document.getElementById('disk-cleanup-output');

    async function runCleanup(dryRun) {
      const agentId = (typeof api.getCurrentAgentId === 'function') ? api.getCurrentAgentId() : null;
      if (!agentId) return;
      if (!dryRun && !confirm('Run safe disk cleanup on this host now?')) return;

      const buttons = [dryBtn, applyBtn].filter(Boolean);
      try {
        buttons.forEach((btn) => { btn.disabled = true; });
        if (statusEl) statusEl.textContent = dryRun ? 'Checking cleanup…' : 'Running cleanup…';
        if (outputEl) {
          outputEl.style.display = 'block';
          outputEl.textContent = '';
        }
        const r = await fetch(`/hosts/${encodeURIComponent(agentId)}/disk-cleanup?wait=true`, {
          method: 'POST',
          credentials: 'include',
          headers: {
            'content-type': 'application/json',
            'X-CSRF-Token': (typeof w.getCookie === 'function' ? (w.getCookie('fleet_csrf') || '') : ''),
          },
          body: JSON.stringify({ dry_run: !!dryRun }),
        });
        const raw = await r.text();
        let data = null; try { data = raw ? JSON.parse(raw) : null; } catch {}
        if (!r.ok) throw new Error((data && (data.detail || data.error)) || raw || `Cleanup failed (${r.status})`);
        if (outputEl) outputEl.textContent = formatDiskCleanupResult(data || {});
        if (statusEl) statusEl.textContent = dryRun ? 'Dry run complete.' : 'Cleanup complete.';
        if (typeof w.showToast === 'function') w.showToast(dryRun ? 'Disk cleanup dry run complete' : 'Disk cleanup complete', 'success');
      } catch (err) {
        const msg = err?.message || String(err);
        if (statusEl) statusEl.textContent = msg;
        if (outputEl) {
          outputEl.style.display = 'block';
          outputEl.textContent = msg;
        }
        if (typeof w.showToast === 'function') w.showToast(msg, 'error');
      } finally {
        buttons.forEach((btn) => { btn.disabled = false; });
      }
    }

    dryBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      runCleanup(true);
    });
    applyBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      runCleanup(false);
    });
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
      team: String(src.team || '').trim(),
      owner: String(src.owner || '').trim(),
      env,
    };
  }

  function canManageHostAssignments(api) {
    const perms = (api && typeof api.getCurrentPermissions === 'function') ? (api.getCurrentPermissions() || {}) : {};
    return String(perms.role || '').toLowerCase() === 'admin' || !!perms.can_manage_users;
  }

  function updateHostMetadataPermissions(api) {
    const canManage = canManageHostAssignments(api);
    ['host-meta-name', 'host-meta-team', 'host-meta-owner'].forEach((id) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.disabled = !canManage;
      el.title = canManage ? '' : 'Admin privileges required';
    });
  }

  function initHostMetadataEditor(ctx) {
    const api = ctx || {};
    const addBtn = document.getElementById('host-meta-env-add');
    const saveBtn = document.getElementById('host-meta-save');
    const statusEl = document.getElementById('host-meta-status');

    addBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      appendEnvRow('', '');
    });

    updateHostMetadataPermissions(api);

    saveBtn?.addEventListener('click', async (e) => {
      e.preventDefault();
      const agentId = (typeof api.getCurrentAgentId === 'function') ? api.getCurrentAgentId() : null;
      if (!agentId) return;
      const payload = normalizeHostMetadataPayload({
        hostname: document.getElementById('host-meta-name')?.value || '',
        role: document.getElementById('host-meta-role')?.value || '',
        team: document.getElementById('host-meta-team')?.value || '',
        owner: document.getElementById('host-meta-owner')?.value || '',
        env: collectEnvEntriesFromDom(),
      });
      if (!canManageHostAssignments(api)) {
        delete payload.hostname;
        delete payload.team;
        delete payload.owner;
      }

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
    populateDiskCleanupPanel: populateDiskCleanupPanel,
    initDiskCleanupControls: initDiskCleanupControls,
    initCommonModalDismissHandlers: initCommonModalDismissHandlers,
  };
})(window);

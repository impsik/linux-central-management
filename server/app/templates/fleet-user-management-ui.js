(function () {
  'use strict';

  const esc = (value) => String(value == null ? '' : value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');

  async function waitForJobDone(jobId, timeoutMs = 70000) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const r = await fetch(`/jobs/${encodeURIComponent(jobId)}`);
      if (!r.ok) {
        const err = await r.json().catch(() => ({}));
        throw new Error(err.detail || `Job status failed: HTTP ${r.status}`);
      }
      const data = await r.json();
      const runs = Array.isArray(data.runs) ? data.runs : [];
      if (data.done) {
        const success = runs.filter((run) => run.status === 'success').map((run) => run.agent_id).filter(Boolean);
        const failed = runs.filter((run) => run.status === 'failed').map((run) => run.agent_id).filter(Boolean);
        return { done: true, success, failed, total: runs.length };
      }
      await new Promise((resolve) => setTimeout(resolve, 1500));
    }
    return { done: false, success: [], failed: [], total: 0 };
  }

  function initUserManagementControls(ctx) {
    const usernameEl = document.getElementById('user-management-username');
    const exactEl = document.getElementById('user-management-exact');
    const liveEl = document.getElementById('user-management-live');
    const searchBtn = document.getElementById('user-management-search');
    const selectOnlineBtn = document.getElementById('user-management-select-online');
    const selectAllEl = document.getElementById('user-management-select-all');
    const lockBtn = document.getElementById('user-management-lock');
    const unlockBtn = document.getElementById('user-management-unlock');
    const statusEl = document.getElementById('user-management-status');
    const bodyEl = document.getElementById('user-management-table-body');
    if (!usernameEl || !bodyEl) return;

    let currentItems = [];

    function selectedAgentIds() {
      return Array.from(bodyEl.querySelectorAll('input[data-user-agent-id]:checked'))
        .map((el) => el.getAttribute('data-user-agent-id') || '')
        .filter(Boolean);
    }

    function updateActionState() {
      const currentPermissions = ctx.getCurrentPermissions();
      const canLockUsers = !!currentPermissions?.can_lock_users;
      const selected = selectedAgentIds();
      const disabled = !canLockUsers || selected.length === 0;
      if (lockBtn) {
        lockBtn.disabled = disabled;
        lockBtn.title = canLockUsers ? '' : 'Admin access required';
      }
      if (unlockBtn) {
        unlockBtn.disabled = disabled;
        unlockBtn.title = canLockUsers ? '' : 'Admin access required';
      }
      if (statusEl && !canLockUsers) statusEl.textContent = 'Admin access required to lock or unlock users';
    }

    function renderItems(items) {
      currentItems = Array.isArray(items) ? items : [];
      if (selectAllEl) selectAllEl.checked = false;
      if (!currentItems.length) {
        bodyEl.innerHTML = '<tr><td colspan="8" class="status-muted" style="text-align:center;">No matching cached accounts found. Enable Refresh live and search again if inventory is stale.</td></tr>';
        updateActionState();
        return;
      }
      const currentPermissions = ctx.getCurrentPermissions();
      const canLockUsers = !!currentPermissions?.can_lock_users;
      bodyEl.innerHTML = currentItems.map((it) => {
        const agentId = String(it.agent_id || '');
        const isRoot = String(it.username || '') === 'root';
        const online = !!it.is_online;
        const disabled = (!canLockUsers || isRoot || !online) ? 'disabled' : '';
        const title = !canLockUsers ? 'Admin access required' : isRoot ? 'Cannot lock root account' : !online ? 'Host offline' : '';
        const osName = `${it.os_id || ''} ${it.os_version || ''}`.trim();
        return `<tr>
          <td><input type="checkbox" data-user-agent-id="${esc(agentId)}" ${disabled} title="${esc(title)}" /></td>
          <td><b>${esc(it.hostname || agentId)}</b><div class="status-muted">${esc(agentId)}${it.ip_address ? ` • ${esc(it.ip_address)}` : ''}${osName ? ` • ${esc(osName)}` : ''}</div></td>
          <td><code>${esc(it.username || '')}</code></td>
          <td><code>${esc(it.shell || '-')}</code><div class="status-muted">${esc(it.home || '-')}</div></td>
          <td><span class="${it.has_sudo ? 'status-warn' : 'status-muted'}">${it.has_sudo ? 'yes' : 'no'}</span></td>
          <td><span class="${it.is_locked ? 'status-error' : 'status-ok'}">${it.is_locked ? 'locked' : 'unlocked'}</span></td>
          <td><span class="${online ? 'status-ok' : 'status-error'}">${online ? 'online' : 'offline'}</span></td>
          <td class="status-muted">${esc(it.last_seen || '')}</td>
        </tr>`;
      }).join('');
      bodyEl.querySelectorAll('input[data-user-agent-id]').forEach((cb) => {
        cb.addEventListener('change', updateActionState);
      });
      updateActionState();
    }

    async function searchUsers(showToastOnManual = false, liveScan = false, scanAgentIds = []) {
      const username = String(usernameEl.value || '').trim();
      if (!username) {
        if (typeof ctx.showToast === 'function') ctx.showToast('Enter username', 'error');
        return;
      }
      bodyEl.innerHTML = `<tr><td colspan="8" class="status-muted" style="text-align:center;">${liveScan ? 'Refreshing live…' : 'Searching…'}</td></tr>`;
      if (statusEl) statusEl.textContent = liveScan ? 'Refreshing live…' : 'Searching…';
      try {
        const qs = new URLSearchParams({
          username,
          exact: String(!!exactEl?.checked),
          live_scan: String(!!liveScan),
          limit: '500',
          offset: '0',
        });
        (Array.isArray(scanAgentIds) ? scanAgentIds : []).forEach((aid) => {
          if (aid) qs.append('agent_ids', aid);
        });
        const r = await fetch(`/reports/user-presence?${qs}`);
        if (!r.ok) {
          const err = await r.json().catch(() => ({}));
          throw new Error(err.detail || `HTTP ${r.status}`);
        }
        const data = await r.json();
        renderItems(data.items || []);
        const liveNote = data.live?.scanned_hosts ? `; refreshed ${data.live.scanned_hosts} host(s)` : '';
        if (statusEl) statusEl.textContent = `${data.total || 0} matching account${Number(data.total || 0) === 1 ? '' : 's'}${liveNote}`;
        if (showToastOnManual && typeof ctx.showToast === 'function') ctx.showToast('User search complete', 'success');
      } catch (e) {
        console.error('[user management search failed]', e);
        bodyEl.innerHTML = '<tr><td colspan="8" class="status-error" style="text-align:center;">Search failed.</td></tr>';
        if (statusEl) statusEl.textContent = 'Search failed';
        if (typeof ctx.showToast === 'function') ctx.showToast(e.message || 'Search failed', 'error');
      }
    }

    async function runUserAction(action) {
      const username = String(usernameEl.value || '').trim();
      const agentIds = selectedAgentIds();
      if (!username) {
        if (typeof ctx.showToast === 'function') ctx.showToast('Enter username', 'error');
        return;
      }
      if (!agentIds.length) {
        if (typeof ctx.showToast === 'function') ctx.showToast('Select at least one online matching host', 'error');
        return;
      }
      if (username === 'root') {
        if (typeof ctx.showToast === 'function') ctx.showToast('Cannot lock root account', 'error');
        return;
      }
      const label = action === 'lock' ? 'Lock' : 'Unlock';
      if (!confirm(`${label} ${username} on ${agentIds.length} selected host(s)?`)) return;

      [lockBtn, unlockBtn, searchBtn].forEach((btn) => { if (btn) btn.disabled = true; });
      if (statusEl) statusEl.textContent = `${label} job queueing…`;
      try {
        const r = await fetch(`/reports/user-presence/${encodeURIComponent(action)}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ username, agent_ids: agentIds }),
        });
        if (!r.ok) {
          const err = await r.json().catch(() => ({}));
          throw new Error(err.detail || `HTTP ${r.status}`);
        }
        const data = await r.json();
        const skipped = Array.isArray(data.skipped_offline) && data.skipped_offline.length ? `; skipped offline: ${data.skipped_offline.join(', ')}` : '';
        if (statusEl) statusEl.textContent = `${label} job ${data.job_id} queued for ${data.targets?.length || 0} host(s)${skipped}`;
        if (typeof ctx.showToast === 'function') ctx.showToast(`${label} job queued`, 'success');
        const summary = await waitForJobDone(data.job_id);
        if (summary.done) {
          if (statusEl) statusEl.textContent = `${label} finished: ${summary.success.length} succeeded, ${summary.failed.length} failed. Refreshing status…`;
        } else if (statusEl) {
          statusEl.textContent = `${label} still running. Refreshing visible status…`;
        }
        await searchUsers(false, true, Array.isArray(data.targets) ? data.targets : agentIds);
      } catch (e) {
        console.error('[user management action failed]', e);
        if (statusEl) statusEl.textContent = `${label} failed`;
        if (typeof ctx.showToast === 'function') ctx.showToast(e.message || `${label} failed`, 'error');
      } finally {
        [searchBtn].forEach((btn) => { if (btn) btn.disabled = false; });
        updateActionState();
      }
    }

    searchBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      void searchUsers(true, !!liveEl?.checked);
    });
    usernameEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        void searchUsers(true, !!liveEl?.checked);
      }
    });
    selectOnlineBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      bodyEl.querySelectorAll('input[data-user-agent-id]').forEach((cb) => {
        if (!cb.disabled) cb.checked = true;
      });
      updateActionState();
    });
    selectAllEl?.addEventListener('change', () => {
      const checked = !!selectAllEl.checked;
      bodyEl.querySelectorAll('input[data-user-agent-id]').forEach((cb) => {
        if (!cb.disabled) cb.checked = checked;
      });
      updateActionState();
    });
    lockBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      void runUserAction('lock');
    });
    unlockBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      void runUserAction('unlock');
    });
    updateActionState();
  }

  window.fleetUserManagementUi = {
    initUserManagementControls,
    waitForJobDone,
  };
})();

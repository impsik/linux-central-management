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
        return {
          done: true,
          success: runs.filter((run) => run.status === 'success').map((run) => run.agent_id).filter(Boolean),
          failed: runs.filter((run) => run.status === 'failed').map((run) => run.agent_id).filter(Boolean),
          total: runs.length,
        };
      }
      await new Promise((resolve) => setTimeout(resolve, 1500));
    }
    return { done: false, success: [], failed: [], total: 0 };
  }

  function initServiceManagementControls(ctx) {
    const serviceEl = document.getElementById('service-management-name');
    const exactEl = document.getElementById('service-management-exact');
    const searchBtn = document.getElementById('service-management-search');
    const selectAllBtn = document.getElementById('service-management-select-all');
    const checkAllEl = document.getElementById('service-management-check-all');
    const startBtn = document.getElementById('service-management-start');
    const enableBtn = document.getElementById('service-management-enable');
    const stopBtn = document.getElementById('service-management-stop');
    const stopDisableBtn = document.getElementById('service-management-stop-disable');
    const statusEl = document.getElementById('service-management-status');
    const bodyEl = document.getElementById('service-management-table-body');
    if (!serviceEl || !bodyEl) return;

    function selectedServiceAgentIds() {
      return Array.from(bodyEl.querySelectorAll('input[data-service-agent-id]:checked'))
        .map((el) => el.getAttribute('data-service-agent-id') || '')
        .filter(Boolean);
    }

    function updateServiceActionState() {
      const currentPermissions = ctx.getCurrentPermissions();
      const canManageServices = !!currentPermissions?.can_manage_services;
      const selected = selectedServiceAgentIds();
      const disabled = !canManageServices || selected.length === 0;
      [startBtn, enableBtn, stopBtn, stopDisableBtn].forEach((btn) => {
        if (!btn) return;
        btn.disabled = disabled;
        btn.title = canManageServices ? '' : 'Service management permission required';
      });
      if (statusEl && !canManageServices) statusEl.textContent = 'Service management permission required';
    }

    function renderServiceItems(items) {
      const rows = Array.isArray(items) ? items : [];
      if (checkAllEl) checkAllEl.checked = false;
      if (!rows.length) {
        bodyEl.innerHTML = '<tr><td colspan="7" class="status-muted" style="text-align:center;">No matching services found on visible online hosts.</td></tr>';
        updateServiceActionState();
        return;
      }
      const currentPermissions = ctx.getCurrentPermissions();
      const canManageServices = !!currentPermissions?.can_manage_services;
      bodyEl.innerHTML = rows.map((it) => {
        const agentId = String(it.agent_id || '');
        const osName = `${it.os_id || ''} ${it.os_version || ''}`.trim();
        const status = String(it.status || '');
        const statusCls = status === 'active' ? 'status-ok' : status === 'failed' ? 'status-error' : 'status-muted';
        const disabled = canManageServices ? '' : 'disabled';
        return `<tr>
          <td><input type="checkbox" data-service-agent-id="${esc(agentId)}" ${disabled} /></td>
          <td><b>${esc(it.hostname || agentId)}</b><div class="status-muted">${esc(agentId)}${it.ip_address ? ` • ${esc(it.ip_address)}` : ''}${osName ? ` • ${esc(osName)}` : ''}</div></td>
          <td><code>${esc(it.service_name || '')}</code></td>
          <td><span class="${statusCls}">${esc(status || '-')}</span></td>
          <td><span class="${it.enabled ? 'status-warn' : 'status-muted'}">${it.enabled ? 'yes' : 'manual'}</span></td>
          <td>${esc(it.description || '-')}</td>
          <td class="status-muted">${esc(it.last_seen || '')}</td>
        </tr>`;
      }).join('');
      bodyEl.querySelectorAll('input[data-service-agent-id]').forEach((cb) => {
        cb.addEventListener('change', updateServiceActionState);
      });
      updateServiceActionState();
    }

    async function searchServices(showToastOnManual = false) {
      const serviceName = String(serviceEl.value || '').trim();
      if (!serviceName) {
        if (typeof ctx.showToast === 'function') ctx.showToast('Enter service name', 'error');
        return;
      }
      bodyEl.innerHTML = '<tr><td colspan="7" class="status-muted" style="text-align:center;">Scanning online hosts…</td></tr>';
      if (statusEl) statusEl.textContent = 'Scanning online hosts…';
      try {
        const qs = new URLSearchParams({
          service_name: serviceName,
          exact: String(!!exactEl?.checked),
          max_hosts: '300',
        }).toString();
        const r = await fetch(`/reports/service-presence?${qs}`);
        if (!r.ok) {
          const err = await r.json().catch(() => ({}));
          throw new Error(err.detail || `HTTP ${r.status}`);
        }
        const data = await r.json();
        renderServiceItems(data.items || []);
        const failed = Array.isArray(data.failed_hosts) && data.failed_hosts.length ? `; failed scan: ${data.failed_hosts.length}` : '';
        const skipped = Array.isArray(data.skipped_offline) && data.skipped_offline.length ? `; offline skipped: ${data.skipped_offline.length}` : '';
        if (statusEl) statusEl.textContent = `${data.total || 0} matching service${Number(data.total || 0) === 1 ? '' : 's'} on ${data.scanned_hosts || 0} online host(s)${failed}${skipped}`;
        if (showToastOnManual && typeof ctx.showToast === 'function') ctx.showToast('Service scan complete', 'success');
      } catch (e) {
        console.error('[service management search failed]', e);
        bodyEl.innerHTML = '<tr><td colspan="7" class="status-error" style="text-align:center;">Service scan failed.</td></tr>';
        if (statusEl) statusEl.textContent = 'Service scan failed';
        if (typeof ctx.showToast === 'function') ctx.showToast(e.message || 'Service scan failed', 'error');
      }
    }

    async function queueServiceAction(action, agentIds) {
      const serviceName = String(serviceEl.value || '').trim();
      const r = await fetch(`/reports/service-presence/${encodeURIComponent(action)}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ service_name: serviceName, agent_ids: agentIds }),
      });
      if (!r.ok) {
        const err = await r.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${r.status}`);
      }
      return r.json();
    }

    async function runServiceOperation(kind) {
      const serviceName = String(serviceEl.value || '').trim();
      const agentIds = selectedServiceAgentIds();
      if (!serviceName) {
        if (typeof ctx.showToast === 'function') ctx.showToast('Enter service name', 'error');
        return;
      }
      if (!agentIds.length) {
        if (typeof ctx.showToast === 'function') ctx.showToast('Select at least one matching host', 'error');
        return;
      }
      const label = kind === 'stop-disable' ? 'Stop and disable' : kind === 'enable' ? 'Enable' : kind === 'start' ? 'Start' : 'Stop';
      if (!confirm(`${label} ${serviceName} on ${agentIds.length} selected host(s)?`)) return;

      [startBtn, enableBtn, stopBtn, stopDisableBtn, searchBtn].forEach((btn) => { if (btn) btn.disabled = true; });
      try {
        if (kind === 'start') {
          if (statusEl) statusEl.textContent = 'Queueing start job…';
          const startData = await queueServiceAction('start', agentIds);
          if (statusEl) statusEl.textContent = `Start job ${startData.job_id} queued for ${startData.targets?.length || 0} host(s)…`;
          const startSummary = await waitForJobDone(startData.job_id);
          if (statusEl) statusEl.textContent = startSummary.done
            ? `Started: ${startSummary.success.length} succeeded, ${startSummary.failed.length} failed. Refreshing…`
            : 'Start still running. Refreshing visible status…';
          if (typeof ctx.showToast === 'function') ctx.showToast('Start job finished', 'success');
          await searchServices(false);
          return;
        }

        if (kind === 'enable') {
          if (statusEl) statusEl.textContent = 'Queueing enable job…';
          const enableData = await queueServiceAction('enable', agentIds);
          if (statusEl) statusEl.textContent = `Enable job ${enableData.job_id} queued for ${enableData.targets?.length || 0} host(s)…`;
          const enableSummary = await waitForJobDone(enableData.job_id);
          if (statusEl) statusEl.textContent = enableSummary.done
            ? `Enabled: ${enableSummary.success.length} succeeded, ${enableSummary.failed.length} failed. Refreshing…`
            : 'Enable still running. Refreshing visible status…';
          if (typeof ctx.showToast === 'function') ctx.showToast('Enable job finished', 'success');
          await searchServices(false);
          return;
        }

        if (statusEl) statusEl.textContent = 'Queueing stop job…';
        const stopData = await queueServiceAction('stop', agentIds);
        if (statusEl) statusEl.textContent = `Stop job ${stopData.job_id} queued for ${stopData.targets?.length || 0} host(s)…`;
        const stopSummary = await waitForJobDone(stopData.job_id);
        const stoppedTargets = stopSummary.done ? stopSummary.success : (Array.isArray(stopData.targets) ? stopData.targets : agentIds);
        if (kind === 'stop') {
          if (statusEl) statusEl.textContent = stopSummary.done
            ? `Stopped: ${stopSummary.success.length} succeeded, ${stopSummary.failed.length} failed. Refreshing…`
            : 'Stop still running. Refreshing visible status…';
          if (typeof ctx.showToast === 'function') ctx.showToast('Stop job finished', 'success');
        } else {
          if (!stopSummary.done) throw new Error('Stop did not finish before timeout; disable skipped');
          if (!stoppedTargets.length) throw new Error('No hosts stopped successfully; disable skipped');
          if (statusEl) statusEl.textContent = `Stopped ${stopSummary.success.length}/${stopSummary.total || agentIds.length}; queueing disable…`;
          const disableData = await queueServiceAction('disable', stoppedTargets);
          const disableSummary = await waitForJobDone(disableData.job_id);
          if (statusEl) statusEl.textContent = disableSummary.done
            ? `Stopped ${stopSummary.success.length}/${stopSummary.total || agentIds.length}; disabled ${disableSummary.success.length}/${disableSummary.total || stoppedTargets.length}. Refreshing…`
            : `Stopped ${stopSummary.success.length}/${stopSummary.total || agentIds.length}; disable still running. Refreshing…`;
          if (typeof ctx.showToast === 'function') ctx.showToast('Stop and disable jobs finished', 'success');
        }
        await searchServices(false);
      } catch (e) {
        console.error('[service management action failed]', e);
        if (statusEl) statusEl.textContent = `${label} failed`;
        if (typeof ctx.showToast === 'function') ctx.showToast(e.message || `${label} failed`, 'error');
      } finally {
        if (searchBtn) searchBtn.disabled = false;
        updateServiceActionState();
      }
    }

    searchBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      void searchServices(true);
    });
    serviceEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        void searchServices(true);
      }
    });
    selectAllBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      bodyEl.querySelectorAll('input[data-service-agent-id]').forEach((cb) => {
        if (!cb.disabled) cb.checked = true;
      });
      updateServiceActionState();
    });
    checkAllEl?.addEventListener('change', () => {
      const checked = !!checkAllEl.checked;
      bodyEl.querySelectorAll('input[data-service-agent-id]').forEach((cb) => {
        if (!cb.disabled) cb.checked = checked;
      });
      updateServiceActionState();
    });
    startBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      void runServiceOperation('start');
    });
    enableBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      void runServiceOperation('enable');
    });
    stopBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      void runServiceOperation('stop');
    });
    stopDisableBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      void runServiceOperation('stop-disable');
    });
    updateServiceActionState();
  }

  window.fleetServiceManagementUi = {
    initServiceManagementControls,
    waitForJobDone,
  };
})();

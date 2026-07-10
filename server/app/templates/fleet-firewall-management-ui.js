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

  function initFirewallManagementControls(ctx) {
    const refreshBtn = document.getElementById('firewall-management-refresh');
    const selectAllBtn = document.getElementById('firewall-management-select-all');
    const checkAllEl = document.getElementById('firewall-management-check-all');
    const allowBtn = document.getElementById('firewall-management-allow');
    const denyBtn = document.getElementById('firewall-management-deny');
    const deleteBtn = document.getElementById('firewall-management-delete');
    const statusEl = document.getElementById('firewall-management-status');
    const bodyEl = document.getElementById('firewall-management-table-body');
    const portEl = document.getElementById('firewall-management-port');
    const serviceEl = document.getElementById('firewall-management-service');
    const protoEl = document.getElementById('firewall-management-protocol');
    const sourceEl = document.getElementById('firewall-management-source');
    if (!bodyEl) return;

    function selectedFirewallAgentIds() {
      return Array.from(bodyEl.querySelectorAll('input[data-firewall-agent-id]:checked'))
        .map((el) => el.getAttribute('data-firewall-agent-id') || '')
        .filter(Boolean);
    }

    function updateFirewallActionState() {
      const currentPermissions = ctx.getCurrentPermissions();
      const canManage = !!currentPermissions?.can_manage_services;
      const selected = selectedFirewallAgentIds();
      const disabled = !canManage || selected.length === 0;
      [allowBtn, denyBtn, deleteBtn].forEach((btn) => {
        if (!btn) return;
        btn.disabled = disabled;
        btn.title = canManage ? '' : 'Service management permission required';
      });
      if (statusEl && !canManage) statusEl.textContent = 'Service management permission required';
    }

    function formatRule(rule) {
      const parts = [];
      if (rule.service) parts.push(`service ${rule.service}`);
      if (rule.port) parts.push(`${rule.port}${rule.protocol ? '/' + rule.protocol : ''}`);
      if (rule.action) parts.push(String(rule.action).toUpperCase());
      if (rule.source) parts.push(`from ${rule.source}`);
      return esc(parts.length ? parts.join(' ') : (rule.raw || '-'));
    }

    function renderFirewallItems(items) {
      const rows = Array.isArray(items) ? items : [];
      if (checkAllEl) checkAllEl.checked = false;
      if (!rows.length) {
        bodyEl.innerHTML = '<tr><td colspan="6" class="status-muted" style="text-align:center;">No firewall data from visible online hosts.</td></tr>';
        updateFirewallActionState();
        return;
      }
      const currentPermissions = ctx.getCurrentPermissions();
      const canManage = !!currentPermissions?.can_manage_services;
      bodyEl.innerHTML = rows.map((it) => {
        const agentId = String(it.agent_id || '');
        const osName = `${it.os_id || ''} ${it.os_version || ''}`.trim();
        const rules = Array.isArray(it.rules) ? it.rules : [];
        const ruleText = rules.length ? rules.map(formatRule).join('<br>') : '<span class="status-muted">No rules reported</span>';
        const disabled = canManage ? '' : 'disabled';
        return `<tr>
          <td><input type="checkbox" data-firewall-agent-id="${esc(agentId)}" ${disabled} /></td>
          <td><b>${esc(it.hostname || agentId)}</b><div class="status-muted">${esc(agentId)}${it.ip_address ? ` • ${esc(it.ip_address)}` : ''}${osName ? ` • ${esc(osName)}` : ''}</div></td>
          <td>${esc(it.backend || '-')}</td>
          <td>${esc(it.status || '-')}${it.zone ? `<div class="status-muted">zone ${esc(it.zone)}</div>` : ''}</td>
          <td>${ruleText}</td>
          <td class="status-muted">${esc(it.last_seen || '')}</td>
        </tr>`;
      }).join('');
      bodyEl.querySelectorAll('input[data-firewall-agent-id]').forEach((cb) => {
        cb.addEventListener('change', updateFirewallActionState);
      });
      updateFirewallActionState();
    }

    async function scanFirewalls(showToastOnManual = false) {
      bodyEl.innerHTML = '<tr><td colspan="6" class="status-muted" style="text-align:center;">Scanning online hosts…</td></tr>';
      if (statusEl) statusEl.textContent = 'Scanning online hosts…';
      try {
        const r = await fetch('/reports/firewall-rules?max_hosts=300');
        if (!r.ok) {
          const err = await r.json().catch(() => ({}));
          throw new Error(err.detail || `HTTP ${r.status}`);
        }
        const data = await r.json();
        renderFirewallItems(data.items || []);
        const failed = Array.isArray(data.failed_hosts) && data.failed_hosts.length ? `; failed scan: ${data.failed_hosts.length}` : '';
        const skipped = Array.isArray(data.skipped_offline) && data.skipped_offline.length ? `; offline skipped: ${data.skipped_offline.length}` : '';
        if (statusEl) statusEl.textContent = `${(data.items || []).length} host(s) scanned${failed}${skipped}`;
        if (showToastOnManual && typeof ctx.showToast === 'function') ctx.showToast('Firewall scan complete', 'success');
      } catch (e) {
        console.error('[firewall management scan failed]', e);
        bodyEl.innerHTML = '<tr><td colspan="6" class="status-error" style="text-align:center;">Firewall scan failed.</td></tr>';
        if (statusEl) statusEl.textContent = 'Firewall scan failed';
        if (typeof ctx.showToast === 'function') ctx.showToast(e.message || 'Firewall scan failed', 'error');
      }
    }

    async function runFirewallOperation(action) {
      const agentIds = selectedFirewallAgentIds();
      const port = Number(portEl?.value || '0');
      const service = String(serviceEl?.value || '').trim();
      const protocol = protoEl?.value || 'tcp';
      const source = String(sourceEl?.value || '').trim();
      if (!agentIds.length) {
        if (typeof ctx.showToast === 'function') ctx.showToast('Select at least one host', 'error');
        return;
      }
      if (!service && (!port || port < 1 || port > 65535)) {
        if (typeof ctx.showToast === 'function') ctx.showToast('Enter a valid port or service', 'error');
        return;
      }
      const label = action === 'delete' ? 'Remove allow' : action === 'allow' ? 'Allow' : 'Deny';
      const target = service ? `service ${service}` : `${port}/${protocol}`;
      if (!confirm(`${label} ${target} on ${agentIds.length} selected host(s)?`)) return;

      [allowBtn, denyBtn, deleteBtn, refreshBtn].forEach((btn) => { if (btn) btn.disabled = true; });
      try {
        if (statusEl) statusEl.textContent = `Queueing ${label.toLowerCase()} job…`;
        const r = await fetch(`/reports/firewall-rules/${encodeURIComponent(action)}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ agent_ids: agentIds, port, protocol, source, service }),
        });
        if (!r.ok) {
          const err = await r.json().catch(() => ({}));
          throw new Error(err.detail || `HTTP ${r.status}`);
        }
        const data = await r.json();
        if (statusEl) statusEl.textContent = `Job ${data.job_id} queued for ${data.targets?.length || 0} host(s)…`;
        const summary = await waitForJobDone(data.job_id);
        if (statusEl) statusEl.textContent = summary.done
          ? `${label}: ${summary.success.length} succeeded, ${summary.failed.length} failed. Refreshing…`
          : `${label} still running. Refreshing visible status…`;
        if (typeof ctx.showToast === 'function') ctx.showToast('Firewall job finished', 'success');
        await scanFirewalls(false);
      } catch (e) {
        console.error('[firewall management action failed]', e);
        if (statusEl) statusEl.textContent = `${label} failed`;
        if (typeof ctx.showToast === 'function') ctx.showToast(e.message || `${label} failed`, 'error');
      } finally {
        if (refreshBtn) refreshBtn.disabled = false;
        updateFirewallActionState();
      }
    }

    refreshBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      void scanFirewalls(true);
    });
    selectAllBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      bodyEl.querySelectorAll('input[data-firewall-agent-id]').forEach((cb) => {
        if (!cb.disabled) cb.checked = true;
      });
      updateFirewallActionState();
    });
    checkAllEl?.addEventListener('change', () => {
      const checked = !!checkAllEl.checked;
      bodyEl.querySelectorAll('input[data-firewall-agent-id]').forEach((cb) => {
        if (!cb.disabled) cb.checked = checked;
      });
      updateFirewallActionState();
    });
    allowBtn?.addEventListener('click', (e) => { e.preventDefault(); void runFirewallOperation('allow'); });
    denyBtn?.addEventListener('click', (e) => { e.preventDefault(); void runFirewallOperation('deny'); });
    deleteBtn?.addEventListener('click', (e) => { e.preventDefault(); void runFirewallOperation('delete'); });
    updateFirewallActionState();
  }

  window.fleetFirewallManagementUi = {
    initFirewallManagementControls,
    waitForJobDone,
  };
})();

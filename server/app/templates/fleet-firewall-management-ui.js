(function () {
  'use strict';

  const esc = (value) => String(value == null ? '' : value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');

  async function boundedJsonFetch(url, options = {}, timeoutMs = 15000) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, { ...options, signal: controller.signal });
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        const error = new Error(data.detail || `HTTP ${response.status}`);
        error.httpStatus = response.status;
        throw error;
      }
      return await response.json();
    } catch (error) {
      if (error.name === 'AbortError') throw new Error('Request timed out');
      throw error;
    } finally {
      clearTimeout(timeout);
    }
  }

  async function waitForJobDone(jobId, timeoutMs = 70000) {
    const start = Date.now();
    let runs = [];
    const summarize = (done) => ({
      done,
      success: runs.filter((run) => run.status === 'success').map((run) => run.agent_id).filter(Boolean),
      failed: runs.filter((run) => run.status === 'failed').map((run) => run.agent_id).filter(Boolean),
      successDetails: runs.filter((run) => run.status === 'success').map((run) => {
        const stdout = run.stdout_tail || run.stdout || '';
        try { return { agentId: run.agent_id, message: JSON.parse(stdout).message || '' }; }
        catch { return { agentId: run.agent_id, message: stdout.slice(0, 600) }; }
      }).filter((detail) => detail.message),
      failureDetails: runs.filter((run) => run.status === 'failed').map((run) => ({
        agentId: run.agent_id,
        message: [...new Set([run.error, run.stderr_tail || run.stderr || run.stdout_tail || run.stdout].filter(Boolean))]
          .join(': ').slice(0, 600) || 'Operation failed',
      })),
      total: runs.length,
    });
    while (Date.now() - start < timeoutMs) {
      const data = await boundedJsonFetch(`/jobs/${encodeURIComponent(jobId)}`, {}, Math.max(1, Math.min(15000, timeoutMs - (Date.now() - start))));
      runs = Array.isArray(data.runs) ? data.runs : [];
      if (data.done) {
        if (!runs.length) throw new Error('Job completed without host results');
        return summarize(true);
      }
      await new Promise((resolve) => setTimeout(resolve, 1500));
    }
    return summarize(false);
  }

  function initFirewallManagementControls(ctx) {
    const refreshBtn = document.getElementById('firewall-management-refresh');
    const selectAllBtn = document.getElementById('firewall-management-select-all');
    const checkAllEl = document.getElementById('firewall-management-check-all');
    const allowBtn = document.getElementById('firewall-management-allow');
    const denyBtn = document.getElementById('firewall-management-deny');
    const deleteBtn = document.getElementById('firewall-management-delete');
    const enableBtn = document.getElementById('firewall-management-enable');
    const disableBtn = document.getElementById('firewall-management-disable');
    const statusEl = document.getElementById('firewall-management-status');
    const resultEl = document.getElementById('firewall-management-result');
    const bodyEl = document.getElementById('firewall-management-table-body');
    const ruleTypeEl = document.getElementById('firewall-management-rule-type');
    const portEl = document.getElementById('firewall-management-port');
    const serviceEl = document.getElementById('firewall-management-service');
    const protoEl = document.getElementById('firewall-management-protocol');
    const sourceEl = document.getElementById('firewall-management-source');
    if (!bodyEl) return;
    const removeDialog = document.getElementById('firewall-remove-dialog');
    const removeRulesEl = document.getElementById('firewall-remove-rules');
    const removeConfirm = document.getElementById('firewall-remove-confirm');
    const removeCount = document.getElementById('firewall-remove-count');
    let removalChoices = [];
    let busy = false;
    let firewallItems = new Map();

    function updateRuleInputState() {
      const profileMode = ruleTypeEl?.value === 'service';
      if (portEl) portEl.disabled = profileMode;
      if (serviceEl) serviceEl.disabled = !profileMode;
      if (protoEl) protoEl.disabled = profileMode;
    }
    ruleTypeEl?.addEventListener('change', updateRuleInputState);
    updateRuleInputState();

    function selectedFirewallAgentIds() {
      return Array.from(bodyEl.querySelectorAll('input[data-firewall-agent-id]:checked'))
        .map((el) => el.getAttribute('data-firewall-agent-id') || '')
        .filter(Boolean);
    }

    function canEnable(agentId) {
      const item = firewallItems.get(agentId);
      return item && ['ufw', 'firewalld'].includes(String(item.backend).toLowerCase())
        && ['inactive', 'stopped', 'not running', 'disabled'].includes(String(item.status).toLowerCase());
    }

    function canDisable(agentId) {
      const item = firewallItems.get(agentId);
      return item && ['ufw', 'firewalld'].includes(String(item.backend).toLowerCase())
        && ['active', 'running', 'enabled'].includes(String(item.status).toLowerCase());
    }

    function updateFirewallActionState() {
      const currentPermissions = ctx.getCurrentPermissions();
      const canManage = !!currentPermissions?.can_manage_services;
      const selected = selectedFirewallAgentIds();
      const disabled = busy || !canManage || selected.length === 0;
      [allowBtn, denyBtn, deleteBtn].forEach((btn) => {
        if (!btn) return;
        btn.disabled = disabled;
        btn.title = canManage ? '' : 'Service management permission required';
      });
      if (enableBtn) {
        enableBtn.disabled = busy || !canManage || !selected.some(canEnable);
        enableBtn.title = !canManage ? 'Service management permission required' : 'Enable inactive firewalls on selected hosts';
      }
      if (disableBtn) {
        disableBtn.disabled = busy || !canManage || !selected.some(canDisable);
        disableBtn.title = !canManage ? 'Service management permission required' : 'Disable active firewalls on selected hosts; keep saved rules';
      }
      [refreshBtn, selectAllBtn, checkAllEl].forEach((el) => { if (el) el.disabled = busy; });
      bodyEl.querySelectorAll('input[data-firewall-agent-id]').forEach((cb) => { cb.disabled = busy || !canManage; });
      if (statusEl && !canManage) statusEl.textContent = 'Service management permission required';
    }

    function formatRule(rule) {
      if (rule.raw && !rule.service && !rule.port && !rule.source) return esc(rule.raw);
      const parts = [];
      if (rule.service) parts.push(`service ${rule.service}`);
      if (rule.port) parts.push(`${rule.port}${rule.protocol ? '/' + rule.protocol : ''}`);
      if (rule.action) parts.push(String(rule.action).toUpperCase());
      if (rule.source) parts.push(`from ${rule.source}`);
      return esc(parts.length ? parts.join(' ') : (rule.raw || '-'));
    }

    function renderFirewallItems(items, selected = []) {
      const rows = Array.isArray(items) ? items : [];
      firewallItems = new Map(rows.map((item) => [String(item.agent_id || ''), item]));
      if (checkAllEl) checkAllEl.checked = rows.length > 0 && rows.every((item) => selected.includes(String(item.agent_id)));
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
        const ruleText = rules.length ? rules.map((rule) => formatRule(rule) + (rule.scope ? ` [${esc(rule.scope)}]` : '')).join('<br>') : '<span class="status-muted">No user rules saved/reported</span>';
        const disabled = canManage ? '' : 'disabled';
        return `<tr>
          <td><input type="checkbox" data-firewall-agent-id="${esc(agentId)}" aria-label="Select firewall on ${esc(it.hostname || agentId)}" ${disabled} ${selected.includes(agentId) ? 'checked' : ''} /></td>
          <td><b>${esc(it.hostname || agentId)}</b><div class="status-muted">${esc(agentId)}${it.ip_address ? ` • ${esc(it.ip_address)}` : ''}${osName ? ` • ${esc(osName)}` : ''}</div></td>
          <td>${esc(it.backend || '-')}</td>
          <td>${esc(it.status || '-')}${it.zone ? `<div class="status-muted">zone ${esc(it.zone)}</div>` : ''}</td>
          <td>${ruleText}${it.notice ? `<div class="status-muted">${esc(it.notice)}</div>` : ''}</td>
          <td class="status-muted">${esc(it.last_seen || '')}</td>
        </tr>`;
      }).join('');
      bodyEl.querySelectorAll('input[data-firewall-agent-id]').forEach((cb) => {
        cb.addEventListener('change', updateFirewallActionState);
      });
      updateFirewallActionState();
    }

    async function loadFirewalls() {
      const selection = selectedFirewallAgentIds();
      bodyEl.innerHTML = '<tr><td colspan="6" class="status-muted" style="text-align:center;">Scanning online hosts…</td></tr>';
      updateFirewallActionState();
      if (statusEl) statusEl.textContent = 'Scanning online hosts…';
      const data = await boundedJsonFetch('/reports/firewall-rules?max_hosts=300', {}, 45000);
      renderFirewallItems(data.items || [], selection);
      const failed = Array.isArray(data.failed_hosts) && data.failed_hosts.length ? `; failed scan: ${data.failed_hosts.length}` : '';
      const skipped = Array.isArray(data.skipped_offline) && data.skipped_offline.length ? `; offline skipped: ${data.skipped_offline.length}` : '';
      if (statusEl) statusEl.textContent = `${(data.items || []).length} host(s) scanned${failed}${skipped}`;
      return data;
    }

    async function scanFirewalls(showToastOnManual = false) {
      if (busy) return;
      busy = true;
      updateFirewallActionState();
      try {
        const data = await loadFirewalls();
        if (showToastOnManual && typeof ctx.showToast === 'function') {
          ctx.showToast(data.failed_hosts?.length ? 'Some hosts could not be scanned' : 'Firewall scan complete', data.failed_hosts?.length ? 'error' : 'success');
        }
      } catch (e) {
        console.error('[firewall management scan failed]', e);
        bodyEl.innerHTML = '<tr><td colspan="6" class="status-error" style="text-align:center;">Firewall scan failed.</td></tr>';
        if (statusEl) statusEl.textContent = 'Firewall scan failed';
        if (typeof ctx.showToast === 'function') ctx.showToast(e.message || 'Firewall scan failed', 'error');
      } finally {
        busy = false;
        updateFirewallActionState();
      }
    }

    function selectedRemovalRules() {
      const rulesByAgent = Object.create(null);
      removeRulesEl.querySelectorAll('input[data-remove-rule]:checked').forEach((checkbox) => {
        const choice = removalChoices[Number(checkbox.getAttribute('data-remove-rule'))];
        if (choice) (rulesByAgent[choice.agentId] ||= []).push(choice.rule);
      });
      return rulesByAgent;
    }

    function updateRemovalCount() {
      const selected = selectedRemovalRules();
      const count = Object.values(selected).reduce((total, rules) => total + rules.length, 0);
      removeConfirm.disabled = !count;
      removeCount.textContent = `${count} rule(s) selected for removal on ${Object.keys(selected).length} host(s). All other rules will be kept.`;
    }

    function openRemovalDialog() {
      if (busy || !ctx.getCurrentPermissions()?.can_manage_services || !removeDialog) return;
      removalChoices = [];
      removeRulesEl.innerHTML = selectedFirewallAgentIds().map((agentId) => {
        const item = firewallItems.get(agentId);
        if (!item) return '';
        const rules = Array.isArray(item.rules) ? item.rules : [];
        return `<fieldset style="margin:12px 0;padding:12px;border:1px solid var(--border);">
          <legend>${esc(item.hostname || agentId)} · ${esc(item.ip_address || agentId)} · ${esc(item.backend)}${item.zone ? ` · zone ${esc(item.zone)}` : ''}</legend>
          ${rules.length ? rules.map((rule) => {
            const index = removalChoices.length;
            const selectable = !!rule.raw && ['ufw', 'firewalld'].includes(item.backend) && (item.backend !== 'ufw' || !!rule.id);
            removalChoices.push({ agentId, rule: { backend: item.backend, raw: rule.raw, id: rule.id || '', zone: item.zone || '' } });
            return `<label style="display:flex;gap:10px;align-items:baseline;margin:8px 0;overflow-wrap:anywhere;">
              <input type="checkbox" data-remove-rule="${index}" ${selectable ? '' : 'disabled'} />
              <span>${rule.raw ? esc(rule.raw) : formatRule(rule)}${selectable ? '' : ' (Scan with an updated agent to select this rule)'}</span></label>`;
          }).join('') : '<p class="status-muted">No rules reported. Nothing will be removed from this host.</p>'}
        </fieldset>`;
      }).join('');
      updateRemovalCount();
      removeDialog.showModal();
    }

    removeRulesEl?.addEventListener('change', updateRemovalCount);
    document.getElementById('firewall-remove-cancel')?.addEventListener('click', () => removeDialog.close());
    removeConfirm?.addEventListener('click', () => {
      const selections = selectedRemovalRules();
      if (!Object.keys(selections).length) return;
      removeDialog.close();
      void runFirewallOperation('delete-rules', selections);
    });

    async function runFirewallOperation(action, selections = null) {
      if (busy || !ctx.getCurrentPermissions()?.can_manage_services) return;
      const enabling = action === 'enable';
      const disabling = action === 'disable';
      const changingState = enabling || disabling;
      const agentIds = (selections ? Object.keys(selections) : selectedFirewallAgentIds()).filter((id) => enabling ? canEnable(id) : disabling ? canDisable(id) : true);
      const profileMode = ruleTypeEl?.value === 'service';
      const port = profileMode ? 0 : Number(portEl?.value || '0');
      const service = profileMode ? String(serviceEl?.value || '').trim() : '';
      const protocol = protoEl?.value || 'tcp';
      const source = String(sourceEl?.value || '').trim();
      if (!agentIds.length) {
        if (typeof ctx.showToast === 'function') ctx.showToast(enabling ? 'Select a host with an inactive firewall' : disabling ? 'Select a host with an active firewall' : 'Select at least one host', 'error');
        return;
      }
      if (!selections && !changingState && profileMode && !service) {
        ctx.showToast?.('Enter an existing firewall profile or service name', 'error');
        return;
      }
      if (!selections && !changingState && !service && (!Number.isInteger(port) || port < 1 || port > 65535)) {
        if (typeof ctx.showToast === 'function') ctx.showToast('Enter a valid port or service', 'error');
        return;
      }
      const label = selections ? 'Remove rules' : enabling ? 'Enable' : disabling ? 'Disable' : action === 'delete' ? 'Remove allow' : action === 'allow' ? 'Allow' : 'Deny';
      const target = service ? `service ${service}` : `${port}/${protocol}`;
      const confirmation = changingState
        ? `${label} firewalls on ${agentIds.length} selected host(s)?\n\n${agentIds.map((id) => firewallItems.get(id)?.hostname || id).join('\n')}\n\n${enabling ? 'Saved rules will take effect. Master SSH/Console access rules are prepared before activation.' : 'Host firewall protection will stop and automatic startup will be disabled. Saved rules will be kept. Runtime-only firewalld rules may be lost.'}`
        : `${label} ${target} on ${agentIds.length} selected host(s)?\n\nThis adds a rule without replacing conflicting rules. Existing rule order and policy still apply. Inactive firewalls save rules for later activation.`;
      if (!selections && !confirm(confirmation)) return;

      busy = true;
      updateFirewallActionState();
      if (resultEl) resultEl.textContent = '';
      let queuedJobId = null;
      try {
        if (statusEl) statusEl.textContent = `Queueing ${label.toLowerCase()} job…`;
        const data = await boundedJsonFetch(`/reports/firewall-rules/${encodeURIComponent(action)}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(selections ? { agent_ids: agentIds, rules_by_agent: selections } : changingState ? { agent_ids: agentIds } : { agent_ids: agentIds, port, protocol, source, service }),
        });
        if (!data.job_id) throw new Error('Server did not return a firewall job');
        queuedJobId = data.job_id;
        if (statusEl) statusEl.textContent = `Job ${data.job_id} queued for ${data.targets?.length || 0} host(s)…`;
        const summary = await waitForJobDone(data.job_id);
        const lines = [summary.done
          ? `${label}: ${summary.success.length} succeeded, ${summary.failed.length} failed.`
          : `${label} still running: ${summary.success.length} succeeded, ${summary.failed.length} failed so far. Job: ${data.job_id}`];
        summary.successDetails.forEach((detail) => lines.push(`${firewallItems.get(detail.agentId)?.hostname || detail.agentId}: ${detail.message}`));
        summary.failureDetails.forEach((failure) => {
          lines.push(`${firewallItems.get(failure.agentId)?.hostname || failure.agentId}: ${failure.message}`);
        });
        const skipped = [...(data.skipped_offline || []), ...(data.unknown_or_unavailable || [])];
        if (skipped.length) lines.push(`${skipped.length} selected host(s) were skipped because they are offline or unavailable.`);
        if (resultEl) resultEl.textContent = lines.join('\n');
        if (typeof ctx.showToast === 'function') {
          ctx.showToast(lines[0], summary.failed.length ? 'error' : summary.done ? 'success' : 'info');
        }
        try {
          await loadFirewalls();
        } catch (refreshError) {
          bodyEl.innerHTML = '<tr><td colspan="6" class="status-error" style="text-align:center;">Could not refresh firewall status. Scan hosts to try again.</td></tr>';
          if (statusEl) statusEl.textContent = 'Status refresh failed';
          if (resultEl) resultEl.textContent += `\nStatus refresh failed: ${refreshError.message}`;
          if (typeof ctx.showToast === 'function') ctx.showToast('Firewall operation results received, but status refresh failed', 'error');
        }
      } catch (e) {
        console.error('[firewall management action failed]', e);
        const requestRejected = e.httpStatus >= 400 && e.httpStatus < 500;
        const message = queuedJobId
          ? `Could not confirm job ${queuedJobId}; it may still be running. ${e.message}`
          : requestRejected ? `${label} request failed: ${e.message}`
            : `Could not confirm ${label.toLowerCase()} request. Scan hosts again before retrying. ${e.message}`;
        if (statusEl) statusEl.textContent = queuedJobId ? 'Job status unavailable'
          : requestRejected ? `${label} request failed` : 'Request status unavailable';
        if (resultEl) resultEl.textContent = [resultEl.textContent, message].filter(Boolean).join('\n');
        if (typeof ctx.showToast === 'function') ctx.showToast(message, 'error');
      } finally {
        busy = false;
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
    deleteBtn?.addEventListener('click', (e) => { e.preventDefault(); openRemovalDialog(); });
    enableBtn?.addEventListener('click', (e) => { e.preventDefault(); void runFirewallOperation('enable'); });
    disableBtn?.addEventListener('click', (e) => { e.preventDefault(); void runFirewallOperation('disable'); });
    updateFirewallActionState();
  }

  window.fleetFirewallManagementUi = {
    initFirewallManagementControls,
    waitForJobDone,
  };
})();

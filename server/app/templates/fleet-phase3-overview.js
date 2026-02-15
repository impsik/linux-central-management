(function (w) {
  async function loadFleetOverview(ctx, forceLive) {
    const onlineEl = document.getElementById('kpi-online');
    const onlineDetailsEl = document.getElementById('kpi-online-details');
    const secEl = document.getElementById('kpi-sec');
    const secDetailsEl = document.getElementById('kpi-sec-details');
    const updEl = document.getElementById('kpi-upd');
    const updDetailsEl = document.getElementById('kpi-upd-details');
    const failEl = document.getElementById('kpi-fail');
    const freshEl = document.getElementById('kpi-fresh');
    const attentionEl = document.getElementById('overview-attention');

    try {
      const r = await fetch('/dashboard/summary', { credentials: 'include' });
      if (!r.ok) {
        if (r.status === 403 && typeof w.loadAuthInfo === 'function') {
          try { await w.loadAuthInfo(); } catch (_) {}
          if (typeof w.showToast === 'function') {
            w.showToast('MFA required — complete setup/verification to continue.', 'info', 4000);
          }
        }
        throw new Error(`dashboard summary failed (${r.status})`);
      }
      const d = await r.json();

      const hostsTotal = d?.hosts?.total ?? 0;
      const hostsOnline = d?.hosts?.online ?? 0;
      const hostsOffline = d?.hosts?.offline ?? Math.max(0, hostsTotal - hostsOnline);
      const secHosts = d?.updates?.hosts_with_security_updates ?? 0;
      const secPkgs = d?.updates?.security_total ?? 0;
      const updHosts = d?.updates?.hosts_with_updates ?? 0;
      const updPkgs = d?.updates?.total ?? 0;
      const failed24h = d?.jobs?.failed_runs_last_24h ?? 0;
      const freshest = d?.updates?.freshest_checked_at;

      if (onlineEl) onlineEl.textContent = `${hostsOnline} / ${hostsTotal}`;
      if (onlineDetailsEl) onlineDetailsEl.textContent = `${hostsOffline} offline (grace ${d?.hosts?.online_grace_seconds ?? 0}s)`;
      if (secEl) secEl.textContent = `${secHosts} hosts`;
      if (secDetailsEl) secDetailsEl.textContent = `${secPkgs} packages`;
      if (updEl) updEl.textContent = `${updHosts} hosts`;
      if (updDetailsEl) updDetailsEl.textContent = `${updPkgs} packages`;
      if (failEl) failEl.textContent = `${failed24h}`;
      if (freshEl) freshEl.textContent = freshest ? new Date(freshest).toLocaleString() : '–';

      if (attentionEl) {
        attentionEl.innerHTML = '<div class="loading">Loading attention list…</div>';
        try {
          const r2 = await fetch(`/dashboard/attention?limit=200&include_live=true&force_live=${forceLive ? 'true' : 'false'}`, { credentials: 'include' });
          if (!r2.ok) throw new Error(`attention failed (${r2.status})`);
          const a = await r2.json();
          const rows = a?.items || [];
          if (!rows.length) {
            attentionEl.innerHTML = '<div style="color:#86efac;">All clear. No high-priority issues detected.</div>';
          } else {
            const html = [];
            html.push('<div style="overflow:auto;"><table class="process-table" style="min-width:800px;"><thead><tr><th>Host</th><th>Issues</th><th>Last seen</th></tr></thead><tbody>');
            for (const it of rows) {
              const agentId = String(it.agent_id || '');
              const hostName = String(it.hostname || it.agent_id || '');
              const host = w.escapeHtml(hostName);
              const last = it.last_seen ? w.escapeHtml(ctx.formatShortTime(it.last_seen)) : '–';
              const issuesHtml = (it.issues || []).map(x => {
                const kind = String(x.kind || '');
                const msg = String(x.message || '');
                return `<a href="#" class="attention-issue" data-agent-id="${w.escapeHtml(agentId)}" data-hostname="${w.escapeHtml(hostName)}" data-kind="${w.escapeHtml(kind)}" style="text-decoration:underline;">${w.escapeHtml(msg)}</a>`;
              }).join(', ');
              html.push(`<tr><td style="font-family:monospace;">${host}</td><td>${issuesHtml || ''}</td><td style="color:#94a3b8;">${last}</td></tr>`);
            }
            html.push('</tbody></table></div>');
            attentionEl.innerHTML = html.join('');

            attentionEl.querySelectorAll('a.attention-issue').forEach(a => {
              a.addEventListener('click', (e) => {
                e.preventDefault();
                const aid = a.getAttribute('data-agent-id') || '';
                const hostname = a.getAttribute('data-hostname') || aid;
                const kind = a.getAttribute('data-kind') || '';
                if (!aid) return;
                ctx.selectHost(aid, hostname);
                if (kind === 'disk') return ctx.openDiskModal(aid);
                if (kind === 'cpu') {
                  ctx.showServerInfo();
                  document.getElementById('top-processes-body')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                  return;
                }
                if (kind === 'security_updates' || kind === 'updates') {
                  ctx.showPackages();
                  const updatesOnlyEl = document.getElementById('packages-updates-only');
                  if (updatesOnlyEl) {
                    updatesOnlyEl.checked = true;
                    ctx.setPackagesUpdatesOnly(true);
                    ctx.loadPackages(aid);
                  }
                  return;
                }
                if (kind === 'reboot_required') {
                  w.showToast('Host reports reboot required', 'info');
                  return ctx.showServerInfo();
                }
                if (kind === 'offline') return w.showToast('Host appears offline', 'error');
                ctx.showServerInfo();
              });
            });
          }
        } catch (e2) {
          attentionEl.innerHTML = `<div class="error">Attention list error: ${w.escapeHtml(e2.message || String(e2))}</div>`;
        }
      }
    } catch (e) {
      if (attentionEl) attentionEl.textContent = `Overview error: ${e.message}`;
    }

    ctx.loadPendingUpdatesReport();
  }

  async function loadHostsTable(ctx) {
    const tbody = document.getElementById('hosts-table-body');
    if (!tbody) return;
    const sortSel = document.getElementById('hosts-sort');
    const orderSel = document.getElementById('hosts-order');
    const sort = sortSel?.value || 'hostname';
    const order = orderSel?.value || 'asc';

    try {
      w.setTableState(tbody, 9, 'loading', 'Loading…');
      const url = `/reports/hosts-updates?only_pending=false&online_only=false&sort=${encodeURIComponent(sort)}&order=${encodeURIComponent(order)}&limit=500`;
      const r = await fetch(url, { credentials: 'include' });
      if (!r.ok) throw new Error(`hosts report failed (${r.status})`);
      const d = await r.json();
      const items = d?.items || [];
      if (!items.length) return w.setTableState(tbody, 9, 'empty', 'No hosts');

      // Keep sidebar host metadata hydrated even if sidebar fetch path fails.
      if (ctx && typeof ctx.setAllHosts === 'function') {
        ctx.setAllHosts(items.map((it) => ({
          agent_id: it.agent_id,
          hostname: it.hostname || it.agent_id,
          ip_address: it.ip_address || '',
          os_id: it.os_id || '',
          os_version: it.os_version || '',
          labels: (it.labels && typeof it.labels === 'object') ? it.labels : {},
          is_online: !!it.is_online,
          last_seen: it.last_seen || null,
        })));
      }

      tbody.innerHTML = '';
      for (const it of items) {
        const hostName = it.hostname || it.agent_id;
        const os = `${it.os_id || ''} ${it.os_version || ''}`.trim() || '–';
        const kernel = it.kernel || '–';
        const sec = Number(it.security_updates || 0);
        const all = Number(it.updates || 0);
        const online = it.is_online ? '<span style="color:#86efac;">online</span>' : '<span style="color:#fca5a5;">offline</span>';
        const reboot = it.reboot_required ? '<span style="color:#fbbf24;">required</span>' : '<span style="color:#94a3b8;">no</span>';
        const lastSeen = ctx.formatShortTime(it.last_seen);

        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><input type="checkbox" class="hosts-row-select" data-agent-id="${w.escapeHtml(it.agent_id || '')}" /></td>
          <td><b>${w.escapeHtml(hostName)}</b><div style="color:#94a3b8;font-size:0.85rem;">${w.escapeHtml(it.agent_id || '')} ${it.ip_address ? '• ' + w.escapeHtml(it.ip_address) : ''}</div></td>
          <td>${w.escapeHtml(os)}</td>
          <td><code>${w.escapeHtml(kernel)}</code></td>
          <td style="text-align:right;"><b>${sec}</b></td>
          <td style="text-align:right;"><b>${all}</b></td>
          <td>${reboot}</td>
          <td>${online}</td>
          <td style="color:#94a3b8;">${w.escapeHtml(lastSeen)}</td>
        `;
        tbody.appendChild(tr);
      }

      // Sidebar fallback: if host list panel is still stuck in loading state, render from report rows.
      const hostsEl = document.getElementById('hosts');
      const hostText = (hostsEl?.textContent || '').toLowerCase();
      if (hostsEl && hostText.includes('loading hosts')) {
        hostsEl.innerHTML = items.map((it) => {
          const ip = it.ip_address || '';
          const lastSeen = ctx.formatShortTime(it.last_seen);
          const labels = (it.labels && typeof it.labels === 'object') ? it.labels : {};
          const env = labels.env || '';
          const role = labels.role || '';
          return `
          <div class="host-item" data-agent-id="${w.escapeHtml(it.agent_id || '')}">
            <div class="host-meta">
              <div class="host-row-top">
                <div class="host-name">${w.escapeHtml(it.hostname || it.agent_id || '')}</div>
                <span class="status-dot ${it.is_online ? 'online' : 'offline'}"></span>
              </div>
              <div class="host-subline">
                <span class="host-subitem">${w.escapeHtml(ip || it.agent_id || '')}</span>
                <span class="host-subsep">•</span>
                <span class="host-subitem">seen ${w.escapeHtml(lastSeen)}</span>
              </div>
              <div class="host-tags">
                ${env ? `<span class="tag">env: <code>${w.escapeHtml(env)}</code></span>` : ''}
                ${role ? `<span class="tag">role: <code>${w.escapeHtml(role)}</code></span>` : ''}
              </div>
            </div>
          </div>
        `;
        }).join('');
        hostsEl.querySelectorAll('.host-item').forEach((el) => {
          el.addEventListener('click', () => {
            const aid = el.getAttribute('data-agent-id') || '';
            if (!aid) return;
            const row = items.find((x) => (x.agent_id || '') === aid) || {};
            ctx.selectHost(aid, row.hostname || aid);
          });
        });
      }
    } catch (e) {
      w.setTableState(tbody, 9, 'error', `Hosts table error: ${e.message || String(e)}`);
    }
  }

  async function loadPendingUpdatesReport(ctx, showToastOnManual) {
    const tbody = document.getElementById('overview-updates-report');
    if (!tbody) return;

    const sortSel = document.getElementById('report-sort');
    const orderSel = document.getElementById('report-order');
    const sort = sortSel?.value || 'security_updates';
    const order = orderSel?.value || 'desc';
    w.updateReportSortIndicators(sort, order);
    w.setTableState(tbody, 7, 'loading', 'Loading…');

    try {
      const url = `/reports/hosts-updates?only_pending=true&online_only=false&sort=${encodeURIComponent(sort)}&order=${encodeURIComponent(order)}&limit=100`;
      const r = await fetch(url, { credentials: 'include' });
      if (!r.ok) throw new Error(`report failed (${r.status})`);
      const d = await r.json();
      const items = d?.items || [];
      if (showToastOnManual) w.showToast('Report refreshed', 'success');
      if (!items.length) return w.setTableState(tbody, 7, 'empty', 'No pending updates 🎯');

      tbody.innerHTML = '';
      for (const it of items) {
        const hostName = it.hostname || it.agent_id;
        const os = `${it.os_id || ''} ${it.os_version || ''}`.trim() || '–';
        const kernel = it.kernel || '–';
        const sec = Number(it.security_updates || 0);
        const all = Number(it.updates || 0);
        const online = it.is_online ? '<span style="color:#86efac;">online</span>' : '<span style="color:#fca5a5;">offline</span>';
        const lastSeen = ctx.formatShortTime(it.last_seen);

        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><b>${w.escapeHtml(hostName)}</b><div style="color:#94a3b8;font-size:0.85rem;">${w.escapeHtml(it.agent_id || '')} ${it.ip_address ? '• ' + w.escapeHtml(it.ip_address) : ''}</div></td>
          <td>${w.escapeHtml(os)}</td>
          <td><code>${w.escapeHtml(kernel)}</code></td>
          <td><b>${sec}</b></td>
          <td><b>${all}</b></td>
          <td>${online}</td>
          <td style="color:#94a3b8;">${w.escapeHtml(lastSeen)}</td>
        `;
        tbody.appendChild(tr);
      }
    } catch (e) {
      if (showToastOnManual) w.showToast(`Report refresh failed: ${e.message}`, 'error');
      w.setTableState(tbody, 7, 'error', `Report error: ${e.message}`);
    }
  }

  function initFleetOverviewControls(ctx) {
    const navOverview = document.getElementById('nav-overview');
    const navHosts = document.getElementById('nav-hosts');
    const navCronjobs = document.getElementById('nav-cronjobs');
    const navSshKeys = document.getElementById('nav-sshkeys');
    const containerEl = document.querySelector('.container');

    function showOverviewTab() {
      ctx.clearCurrentHostSelection();
      document.querySelectorAll('.tab-content-custom, .tab-content').forEach(c => c.classList.remove('active'));
      document.getElementById('server-info-tab')?.classList.add('active');
      if (containerEl) containerEl.classList.add('sidebar-collapsed');
      ctx.loadFleetOverview();
    }

    function showHostsTab() {
      ctx.stopMetricsPolling();
      ctx.clearCurrentHostSelection();
      document.querySelectorAll('.tab-content-custom, .tab-content').forEach(c => c.classList.remove('active'));
      document.getElementById('hosts-table-tab')?.classList.add('active');
      if (containerEl) containerEl.classList.remove('sidebar-collapsed');
      ctx.loadHostsTable();
    }

    function showCronjobsTab() {
      ctx.clearCurrentHostSelection();
      document.querySelectorAll('.tab-content-custom, .tab-content').forEach(c => c.classList.remove('active'));
      document.getElementById('cronjobs-tab')?.classList.add('active');
      if (containerEl) containerEl.classList.add('sidebar-collapsed');
      ctx.loadCronjobs();
    }

    function showSshKeysTab() {
      ctx.clearCurrentHostSelection();
      document.querySelectorAll('.tab-content-custom, .tab-content').forEach(c => c.classList.remove('active'));
      document.getElementById('sshkeys-tab')?.classList.add('active');
      if (containerEl) containerEl.classList.add('sidebar-collapsed');
      ctx.loadSshKeys();
      ctx.loadSshKeyRequests();
      ctx.maybeLoadSshKeyAdminQueue();
      ctx.loadAdminSshKeys();
    }

    navOverview?.addEventListener('click', (e) => { e.preventDefault(); showOverviewTab(); });
    navHosts?.addEventListener('click', (e) => { e.preventDefault(); showHostsTab(); });
    navCronjobs?.addEventListener('click', (e) => { e.preventDefault(); showCronjobsTab(); });
    navSshKeys?.addEventListener('click', (e) => { e.preventDefault(); showSshKeysTab(); });

    showOverviewTab();

    const refreshBtn = document.getElementById('overview-refresh');
    const invBtn = document.getElementById('overview-inventory-now');
    const secBtn = document.getElementById('overview-security-campaign');
    const distBtn = document.getElementById('overview-dist-upgrade');
    const failedRunsRefreshBtn = document.getElementById('failed-runs-refresh');

    w.wireBusyClick(failedRunsRefreshBtn, 'Refreshing…', async () => { await ctx.loadFailedRuns(24, true); });
    w.wireBusyClick(refreshBtn, 'Refreshing…', async () => { await Promise.allSettled([ctx.loadFleetOverview(true), ctx.loadPendingUpdatesReport(), ctx.loadHosts()]); });

    w.wireBusyClick(invBtn, 'Queueing…', async () => {
      const agentIds = (ctx.getLastRenderedAgentIds() || []).slice();
      if (!agentIds.length) return w.showToast('No visible hosts to inventory', 'error');
      const r = await fetch('/jobs/inventory-now', { method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ agent_ids: agentIds }) });
      if (!r.ok) return w.showToast('Inventory-now failed', 'error');
      w.showToast(`Triggered inventory for ${agentIds.length} hosts`, 'success');
      setTimeout(ctx.loadPendingUpdatesReport, 1500);
    });

    w.wireBusyClick(secBtn, 'Scheduling…', async () => {
      const agentIds = (ctx.getLastRenderedAgentIds() || []).slice();
      if (!agentIds.length) return w.showToast('No visible hosts selected', 'error');
      const now = new Date();
      const end = new Date(now.getTime() + 60 * 60 * 1000);
      const payload = { agent_ids: agentIds, window_start: now.toISOString(), window_end: end.toISOString(), concurrency: 5, reboot_if_needed: true, include_kernel: false };
      const r = await fetch('/patching/campaigns/security-updates', { method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
      if (!r.ok) return w.showToast('Campaign creation failed', 'error');
      const d = await r.json();
      w.showToast(`Security campaign scheduled: ${d.campaign_id}`, 'success');
    });

    w.wireBusyClick(distBtn, 'Queueing…', async () => {
      const agentIds = (ctx.getLastRenderedAgentIds() || []).slice();
      if (!agentIds.length) return w.showToast('No visible hosts selected', 'error');
      const r = await fetch('/jobs/dist-upgrade', { method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ agent_ids: agentIds }) });
      if (!r.ok) return w.showToast('dist-upgrade job creation failed', 'error');
      const d = await r.json();
      w.showToast(`dist-upgrade queued: ${d.job_id}`, 'success');
    });

    const reportRefresh = document.getElementById('report-refresh');
    w.wireBusyClick(reportRefresh, 'Refreshing…', async () => { await ctx.loadPendingUpdatesReport(true); });
    document.getElementById('report-sort')?.addEventListener('change', ctx.loadPendingUpdatesReport);
    document.getElementById('report-order')?.addEventListener('change', ctx.loadPendingUpdatesReport);

    w.setupReportSortHandlers(ctx.loadPendingUpdatesReport);
    w.setupKpiHandlers(showHostsTab, showOverviewTab, ctx.loadFailedRuns);
  }

  w.phase3Overview = { loadFleetOverview, loadHostsTable, loadPendingUpdatesReport, initFleetOverviewControls };
})(window);

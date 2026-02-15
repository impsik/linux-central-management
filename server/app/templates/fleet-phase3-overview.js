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
    const morningBriefEl = document.getElementById('overview-morning-brief');

    try {
      const r = await fetch('/dashboard/summary', { credentials: 'include' });
      if (!r.ok) {
        if (r.status === 403) {
          // Expected transient state during MFA gating; avoid flashing scary errors.
          if (typeof w.loadAuthInfo === 'function') {
            try { await w.loadAuthInfo(); } catch (_) {}
          }
          return;
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

      if (morningBriefEl) {
        morningBriefEl.innerHTML = '<div class="loading">Building brief…</div>';
        try {
          const reportUrl = `/reports/hosts-updates?only_pending=false&online_only=false&sort=hostname&order=asc&limit=500`;
          const rr = await fetch(reportUrl, { credentials: 'include' });
          if (!rr.ok) throw new Error(`hosts-updates failed (${rr.status})`);
          const report = await rr.json();
          const items = Array.isArray(report?.items) ? report.items : [];

          const rebootRequired = items.filter((it) => !!it.reboot_required).length;
          const heavySecurity = items.filter((it) => Number(it.security_updates || 0) >= 10).length;
          const staleHosts = items.filter((it) => {
            const last = it?.last_seen ? Date.parse(it.last_seen) : NaN;
            if (!Number.isFinite(last)) return true;
            return (Date.now() - last) > (24 * 60 * 60 * 1000);
          }).length;

          const thresholdsKey = 'fleet_brief_thresholds_v1';
          let th = { offline: 1, failed: 1, secPkgs: 20 };
          try {
            const raw = localStorage.getItem(thresholdsKey);
            const parsed = raw ? JSON.parse(raw) : null;
            if (parsed && typeof parsed === 'object') {
              th = {
                offline: Number(parsed.offline || 1),
                failed: Number(parsed.failed || 1),
                secPkgs: Number(parsed.secPkgs || 20),
              };
            }
          } catch (_) { }

          const alerts = [];
          if (hostsOffline >= th.offline) alerts.push(`offline hosts (${hostsOffline} ≥ ${th.offline})`);
          if (failed24h >= th.failed) alerts.push(`failed runs (${failed24h} ≥ ${th.failed})`);
          if (secPkgs >= th.secPkgs) alerts.push(`security backlog (${secPkgs} ≥ ${th.secPkgs})`);

          morningBriefEl.innerHTML = `
            <div style="display:flex;flex-direction:column;gap:0.35rem;">
              <div><span style="color:#94a3b8;">Offline hosts:</span> <b>${hostsOffline}</b> <button class="btn" data-brief-action="offline" type="button" style="margin-left:0.35rem;padding:0.2rem 0.45rem;">Show</button></div>
              <div><span style="color:#94a3b8;">Security backlog:</span> <b>${secPkgs}</b> packages on <b>${secHosts}</b> hosts</div>
              <div><span style="color:#94a3b8;">Reboot required:</span> <b>${rebootRequired}</b> hosts</div>
              <div><span style="color:#94a3b8;">Failed runs (24h):</span> <b>${failed24h}</b> <button class="btn" data-brief-action="failed" type="button" style="margin-left:0.35rem;padding:0.2rem 0.45rem;">Show</button></div>
              <div><span style="color:#94a3b8;">Hosts with 10+ security updates:</span> <b>${heavySecurity}</b> <button class="btn" data-brief-action="heavy-security" type="button" style="margin-left:0.35rem;padding:0.2rem 0.45rem;">Show</button></div>
              <div><span style="color:#94a3b8;">Stale inventory (&gt;24h):</span> <b>${staleHosts}</b></div>

              <div style="margin-top:0.4rem;padding-top:0.4rem;border-top:1px solid var(--border);display:flex;gap:0.35rem;flex-wrap:wrap;align-items:center;">
                <span style="color:#94a3b8;font-size:0.82rem;">Alerts:</span>
                <label style="font-size:0.8rem;color:#94a3b8;">Offline ≥ <input id="brief-th-offline" type="number" min="0" value="${th.offline}" style="width:58px;" /></label>
                <label style="font-size:0.8rem;color:#94a3b8;">Failed ≥ <input id="brief-th-failed" type="number" min="0" value="${th.failed}" style="width:58px;" /></label>
                <label style="font-size:0.8rem;color:#94a3b8;">Sec pkgs ≥ <input id="brief-th-sec" type="number" min="0" value="${th.secPkgs}" style="width:64px;" /></label>
                <button class="btn" id="brief-th-save" type="button" style="padding:0.2rem 0.45rem;">Save</button>
              </div>
              <div style="font-size:0.85rem;color:${alerts.length ? '#fca5a5' : '#86efac'};">${alerts.length ? ('Attention: ' + alerts.join(' • ')) : 'No alert thresholds exceeded.'}</div>
            </div>
          `;

          morningBriefEl.querySelectorAll('[data-brief-action]').forEach((btn) => {
            btn.addEventListener('click', (e) => {
              e.preventDefault();
              const action = btn.getAttribute('data-brief-action') || '';
              if (action === 'failed') {
                const el = document.getElementById('failed-runs-card');
                if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
                return;
              }

              document.getElementById('nav-hosts')?.click();
              const sortSel = document.getElementById('hosts-sort');
              const orderSel = document.getElementById('hosts-order');

              if (action === 'offline') {
                if (sortSel) sortSel.value = 'last_seen';
                if (orderSel) orderSel.value = 'asc';
              } else if (action === 'heavy-security') {
                if (sortSel) sortSel.value = 'security_updates';
                if (orderSel) orderSel.value = 'desc';
              }

              sortSel?.dispatchEvent(new Event('change'));
            });
          });

          document.getElementById('brief-th-save')?.addEventListener('click', () => {
            const offlineN = Number(document.getElementById('brief-th-offline')?.value || 0);
            const failedN = Number(document.getElementById('brief-th-failed')?.value || 0);
            const secN = Number(document.getElementById('brief-th-sec')?.value || 0);
            try {
              localStorage.setItem('fleet_brief_thresholds_v1', JSON.stringify({ offline: offlineN, failed: failedN, secPkgs: secN }));
              if (typeof w.showToast === 'function') w.showToast('Morning brief thresholds saved', 'success');
            } catch (_) {
              if (typeof w.showToast === 'function') w.showToast('Failed to save thresholds', 'error');
            }
          });
        } catch (briefErr) {
          morningBriefEl.innerHTML = `<div class="error">Brief unavailable: ${w.escapeHtml(briefErr.message || String(briefErr))}</div>`;
        }
      }

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

  async function loadNotifications(ctx, showToastOnManual) {
    const wrap = document.getElementById('overview-notifications');
    const badge = document.getElementById('notifications-badge');
    if (!wrap) return;
    try {
      wrap.innerHTML = '<div class="loading">Loading notifications…</div>';
      const r = await fetch('/dashboard/notifications?limit=30', { credentials: 'include' });
      if (!r.ok) {
        if (r.status === 403) return; // MFA transient
        throw new Error(`notifications failed (${r.status})`);
      }
      const d = await r.json();
      const items = Array.isArray(d?.items) ? d.items : [];

      let seen = [];
      try { seen = JSON.parse(localStorage.getItem('fleet_notifications_seen_v1') || '[]'); } catch (_) { seen = []; }
      const seenSet = new Set(Array.isArray(seen) ? seen : []);
      const unread = items.filter((it) => !seenSet.has(String(it.id || '')));

      if (badge) badge.style.display = unread.length ? 'inline' : 'none';

      if (!items.length) {
        wrap.innerHTML = '<div style="color:#86efac;">No active notifications 🎯</div>';
      } else {
        wrap.innerHTML = `
          <div style="display:flex;gap:0.5rem;justify-content:space-between;align-items:center;margin-bottom:0.5rem;">
            <div style="color:#94a3b8;">Unread: <b>${unread.length}</b> / ${items.length}</div>
            <button class="btn" id="notifications-mark-read" type="button">Mark all read</button>
          </div>
          <div style="display:flex;flex-direction:column;gap:0.45rem;">
            ${items.map((it) => `<div style="border:1px solid var(--border);border-radius:10px;padding:0.45rem 0.6rem;background:var(--panel-2);${seenSet.has(String(it.id||'')) ? 'opacity:0.75;' : ''}">
              <div style="display:flex;justify-content:space-between;gap:0.5rem;align-items:center;">
                <b>${w.escapeHtml(it.title || '')}</b>
                <span style="font-size:0.75rem;color:${it.severity==='high' ? '#fca5a5' : '#fbbf24'};">${w.escapeHtml(it.severity || 'info')}</span>
              </div>
              <div style="color:#94a3b8;font-size:0.88rem;">${w.escapeHtml(it.detail || '')}</div>
            </div>`).join('')}
          </div>
        `;

        document.getElementById('notifications-mark-read')?.addEventListener('click', () => {
          try {
            const ids = items.map((it) => String(it.id || '')).filter(Boolean);
            localStorage.setItem('fleet_notifications_seen_v1', JSON.stringify(ids));
          } catch (_) { }
          loadNotifications(ctx, false);
        });
      }
      if (showToastOnManual) w.showToast('Notifications refreshed', 'success');
    } catch (e) {
      wrap.innerHTML = `<div class="error">Notifications error: ${w.escapeHtml(e.message || String(e))}</div>`;
      if (showToastOnManual) w.showToast(`Notifications failed: ${e.message || String(e)}`, 'error');
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
      ctx.loadFailedRuns(24, false);
      loadNotifications(ctx, false);
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
    const notificationsRefreshBtn = document.getElementById('notifications-refresh');
    const teamsTestBtn = document.getElementById('teams-test-alert');
    const teamsBriefBtn = document.getElementById('teams-send-brief');

    w.wireBusyClick(failedRunsRefreshBtn, 'Refreshing…', async () => { await ctx.loadFailedRuns(24, true); });
    w.wireBusyClick(notificationsRefreshBtn, 'Refreshing…', async () => { await loadNotifications(ctx, true); });
    w.wireBusyClick(teamsTestBtn, 'Sending…', async () => {
      const r = await fetch('/dashboard/alerts/teams/test', { method: 'POST', credentials: 'include' });
      if (!r.ok) {
        const t = await r.text();
        throw new Error(`Teams test failed (${r.status}): ${t}`);
      }
      w.showToast('Teams test alert sent', 'success');
    });
    w.wireBusyClick(teamsBriefBtn, 'Sending…', async () => {
      const r = await fetch('/dashboard/alerts/teams/morning-brief', { method: 'POST', credentials: 'include' });
      if (!r.ok) {
        const t = await r.text();
        throw new Error(`Teams brief failed (${r.status}): ${t}`);
      }
      w.showToast('Teams morning brief sent', 'success');
    });
    w.wireBusyClick(refreshBtn, 'Refreshing…', async () => { await Promise.allSettled([ctx.loadFleetOverview(true), ctx.loadPendingUpdatesReport(), ctx.loadHosts(), ctx.loadFailedRuns(24, false)]); });

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

    try {
      if (window.__fleetNotifInterval) clearInterval(window.__fleetNotifInterval);
      window.__fleetNotifInterval = setInterval(() => {
        const isOverview = document.getElementById('server-info-tab')?.classList.contains('active');
        if (isOverview) loadNotifications(ctx, false);
      }, 60000);
    } catch (_) { }
  }

  w.phase3Overview = { loadFleetOverview, loadHostsTable, loadPendingUpdatesReport, initFleetOverviewControls };
})(window);

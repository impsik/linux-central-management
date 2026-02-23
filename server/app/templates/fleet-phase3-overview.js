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
    const maintenanceEl = document.getElementById('maintenance-window-status');

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

      if (maintenanceEl) {
        try {
          const mw = await fetch('/dashboard/maintenance-window', { credentials: 'include' });
          if (mw.ok) {
            const md = await mw.json();
            if (!md.enabled) {
              maintenanceEl.className = 'status-muted';
              maintenanceEl.textContent = 'Maintenance window: disabled';
            } else if (md.within_window_now) {
              maintenanceEl.className = 'status-ok';
              maintenanceEl.textContent = `Maintenance window: ACTIVE (${md.start}-${md.end} ${md.timezone})`;
            } else {
              maintenanceEl.className = 'status-warn';
              maintenanceEl.textContent = `Maintenance window: outside allowed hours (${md.start}-${md.end} ${md.timezone})`;
            }
          }
        } catch (_) { }
      }

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
              <div><span style="color:var(--muted-2);">Offline hosts:</span> <b>${hostsOffline}</b> <button class="btn" data-brief-action="offline" type="button" style="margin-left:0.35rem;padding:0.2rem 0.45rem;">Show</button></div>
              <div><span style="color:var(--muted-2);">Security backlog:</span> <b>${secPkgs}</b> packages on <b>${secHosts}</b> hosts</div>
              <div><span style="color:var(--muted-2);">Reboot required:</span> <b>${rebootRequired}</b> hosts</div>
              <div><span style="color:var(--muted-2);">Failed runs (24h):</span> <b>${failed24h}</b> <button class="btn" data-brief-action="failed" type="button" style="margin-left:0.35rem;padding:0.2rem 0.45rem;">Show</button></div>
              <div><span style="color:var(--muted-2);">Hosts with 10+ security updates:</span> <b>${heavySecurity}</b> <button class="btn" data-brief-action="heavy-security" type="button" style="margin-left:0.35rem;padding:0.2rem 0.45rem;">Show</button></div>
              <div><span style="color:var(--muted-2);">Stale inventory (&gt;24h):</span> <b>${staleHosts}</b></div>

              <div style="margin-top:0.4rem;padding-top:0.4rem;border-top:1px solid var(--border);display:flex;gap:0.35rem;flex-wrap:wrap;align-items:center;">
                <span style="color:var(--muted-2);font-size:0.82rem;">Alerts:</span>
                <label style="font-size:0.8rem;color:var(--muted-2);">Offline ≥ <input id="brief-th-offline" type="number" min="0" value="${th.offline}" style="width:58px;" /></label>
                <label style="font-size:0.8rem;color:var(--muted-2);">Failed ≥ <input id="brief-th-failed" type="number" min="0" value="${th.failed}" style="width:58px;" /></label>
                <label style="font-size:0.8rem;color:var(--muted-2);">Sec pkgs ≥ <input id="brief-th-sec" type="number" min="0" value="${th.secPkgs}" style="width:64px;" /></label>
                <button class="btn" id="brief-th-save" type="button" style="padding:0.2rem 0.45rem;">Save</button>
              </div>
              <div style="font-size:0.85rem;" class="${alerts.length ? 'status-error' : 'status-ok'}">${alerts.length ? ('Attention: ' + alerts.join(' • ')) : 'No alert thresholds exceeded.'}</div>
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
            attentionEl.innerHTML = '<div class="status-ok">All clear. No high-priority issues detected.</div>';
          } else {
            const html = [];
            html.push('<div style="overflow:auto;max-width:100%;"><table class="process-table" style="width:100%;table-layout:fixed;"><thead><tr><th style="width:24%;">Host</th><th style="width:46%;">Issues</th><th style="width:30%;">Last seen</th></tr></thead><tbody>');
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
              html.push(`<tr><td style="font-family:monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${host}</td><td style="white-space:normal;overflow-wrap:anywhere;word-break:break-word;line-height:1.35;">${issuesHtml || ''}</td><td style="color:var(--muted-2);white-space:normal;overflow-wrap:anywhere;">${last}</td></tr>`);
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

  let hostsTableItemsCache = [];

  function filterHostsTableItems(ctx, items) {
    let out = Array.isArray(items) ? items.slice() : [];
    const q = String((ctx && typeof ctx.getHostSearchQuery === 'function') ? (ctx.getHostSearchQuery() || '') : '').trim().toLowerCase();
    const labelEnv = String((ctx && typeof ctx.getLabelEnvFilter === 'function') ? (ctx.getLabelEnvFilter() || '') : '').trim();
    const labelRole = String((ctx && typeof ctx.getLabelRoleFilter === 'function') ? (ctx.getLabelRoleFilter() || '') : '').trim();
    const vulnSet = (ctx && typeof ctx.getVulnFilteredAgentIds === 'function') ? ctx.getVulnFilteredAgentIds() : null;

    if (vulnSet instanceof Set) {
      out = out.filter((it) => vulnSet.has(String(it.agent_id || '')));
    }

    if (labelEnv || labelRole) {
      out = out.filter((it) => {
        const labels = (it && it.labels && typeof it.labels === 'object') ? it.labels : {};
        if (labelEnv && String(labels.env || '') !== labelEnv) return false;
        if (labelRole && String(labels.role || '') !== labelRole) return false;
        return true;
      });
    }

    if (q) {
      out = out.filter((it) => {
        const hay = `${it.hostname || ''} ${it.agent_id || ''} ${it.ip_address || ''} ${it.fqdn || ''} ${it.os_id || ''} ${it.os_version || ''}`.toLowerCase();
        return hay.includes(q);
      });
    }

    return out;
  }

  function renderHostsTableRows(ctx, tbody, items) {
    if (!tbody) return;
    const counterEl = document.getElementById('hosts-visible-counter');
    const total = Array.isArray(hostsTableItemsCache) ? hostsTableItemsCache.length : 0;
    if (!items.length) {
      if (counterEl) counterEl.textContent = `0 / ${total} hosts shown`;
      w.setTableState(tbody, 9, 'empty', 'No hosts match current filters');
      if (ctx && typeof ctx.setLastRenderedAgentIds === 'function') ctx.setLastRenderedAgentIds([]);
      return;
    }

    if (counterEl) counterEl.textContent = `${items.length} / ${total} hosts shown`;

    if (ctx && typeof ctx.setLastRenderedAgentIds === 'function') {
      ctx.setLastRenderedAgentIds(items.map((it) => String(it.agent_id || '')).filter(Boolean));
    }

    tbody.innerHTML = '';
    for (const it of items) {
      const hostName = it.hostname || it.agent_id;
      const os = `${it.os_id || ''} ${it.os_version || ''}`.trim() || '–';
      const kernel = it.kernel || '–';
      const sec = Number(it.security_updates || 0);
      const all = Number(it.updates || 0);
      const online = it.is_online ? '<span class="status-ok">online</span>' : '<span class="status-error">offline</span>';
      const reboot = it.reboot_required ? '<span class="status-warn">required</span>' : '<span class="status-muted">no</span>';
      const lastSeen = ctx.formatShortTime(it.last_seen);

      const tr = document.createElement('tr');
      tr.style.cursor = 'pointer';
      const selectedAgentIds = (ctx.getSelectedAgentIds && ctx.getSelectedAgentIds()) || new Set();
      tr.innerHTML = `
        <td><input type="checkbox" class="hosts-row-select" data-agent-id="${w.escapeHtml(it.agent_id || '')}" ${selectedAgentIds.has(String(it.agent_id || '')) ? 'checked' : ''} /></td>
        <td>
          <div style="display:flex;align-items:center;justify-content:space-between;gap:0.5rem;">
            <b>${w.escapeHtml(hostName)}</b>
            <button type="button" class="btn btn-danger host-remove-btn" data-agent-id="${w.escapeHtml(it.agent_id || '')}" data-hostname="${w.escapeHtml(hostName)}" style="padding:0.2rem 0.45rem;font-size:0.8rem;">Remove</button>
          </div>
          <div style="color:var(--muted-2);font-size:0.85rem;">${w.escapeHtml(it.agent_id || '')} ${it.ip_address ? '• ' + w.escapeHtml(it.ip_address) : ''}</div>
        </td>
        <td>${w.escapeHtml(os)}</td>
        <td><code>${w.escapeHtml(kernel)}</code></td>
        <td style="text-align:right;"><b>${sec}</b></td>
        <td style="text-align:right;"><b>${all}</b></td>
        <td>${reboot}</td>
        <td>${online}</td>
        <td class="status-muted">${w.escapeHtml(lastSeen)}</td>
      `;

      tr.addEventListener('click', () => {
        const aid = String(it.agent_id || '');
        if (!aid) return;
        ctx.selectHost(aid, hostName);
      });

      const cb = tr.querySelector('.hosts-row-select');
      if (cb) {
        cb.addEventListener('click', (e) => e.stopPropagation());
        cb.addEventListener('change', (e) => {
          e.stopPropagation();
          const aid = String(cb.getAttribute('data-agent-id') || '').trim();
          if (!aid || !ctx.getSelectedAgentIds) return;
          const selected = ctx.getSelectedAgentIds();
          if (!(selected instanceof Set)) return;
          if (cb.checked) selected.add(aid);
          else selected.delete(aid);
          if (typeof ctx.updateUpgradeControls === 'function') ctx.updateUpgradeControls();
        });
      }

      const removeBtn = tr.querySelector('.host-remove-btn');
      if (removeBtn) {
        removeBtn.addEventListener('click', async (e) => {
          e.preventDefault();
          e.stopPropagation();
          const agentId = String(removeBtn.getAttribute('data-agent-id') || '').trim();
          const hostnameLabel = String(removeBtn.getAttribute('data-hostname') || '').trim() || agentId;
          if (!agentId) return;

          try {
            const previewResp = await fetch('/hosts/remove', {
              method: 'POST',
              credentials: 'include',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ agent_ids: [agentId], dry_run: true })
            });
            if (!previewResp.ok) throw new Error(`preview failed (${previewResp.status})`);
            const preview = await previewResp.json();
            const found = Array.isArray(preview?.found_agent_ids) ? preview.found_agent_ids : [];
            if (!found.length) {
              w.showToast('Host no longer exists', 'error');
              return;
            }

            if (!confirm(`Remove host "${hostnameLabel}" (${agentId}) from inventory?`)) return;

            const resp = await fetch('/hosts/remove', {
              method: 'POST',
              credentials: 'include',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ agent_ids: [agentId] })
            });
            if (!resp.ok) throw new Error(`remove failed (${resp.status})`);

            w.showToast(`Removed host ${hostnameLabel}`, 'success');
            if (ctx && typeof ctx.loadHostsTable === 'function') await ctx.loadHostsTable();
            else await loadHostsTable(ctx);
            if (ctx && typeof ctx.loadHosts === 'function') await ctx.loadHosts();
          } catch (err) {
            w.showToast(err?.message || String(err), 'error');
          }
        });
      }

      tbody.appendChild(tr);
    }
  }

  function applyHostsTableFilters(ctx) {
    const tbody = document.getElementById('hosts-table-body');
    if (!tbody) return;
    const filtered = filterHostsTableItems(ctx, hostsTableItemsCache);
    renderHostsTableRows(ctx, tbody, filtered);
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
      hostsTableItemsCache = Array.isArray(items) ? items : [];
      if (!hostsTableItemsCache.length) {
        if (ctx && typeof ctx.setLastRenderedAgentIds === 'function') ctx.setLastRenderedAgentIds([]);
        return w.setTableState(tbody, 9, 'empty', 'No hosts');
      }

      // Keep host metadata hydrated for filter options and host detail panel.
      if (ctx && typeof ctx.setAllHosts === 'function') {
        ctx.setAllHosts(hostsTableItemsCache.map((it) => ({
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

      applyHostsTableFilters(ctx);

      // Legacy hidden list fallback kept for compatibility.
      const hostsEl = document.getElementById('hosts');
      const hostText = (hostsEl?.textContent || '').toLowerCase();
      if (hostsEl && hostText.includes('loading hosts')) {
        hostsEl.innerHTML = hostsTableItemsCache.map((it) => {
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
            const row = hostsTableItemsCache.find((x) => (x.agent_id || '') === aid) || {};
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
        const online = it.is_online ? '<span class="status-ok">online</span>' : '<span class="status-error">offline</span>';
        const lastSeen = ctx.formatShortTime(it.last_seen);

        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><b>${w.escapeHtml(hostName)}</b><div style="color:var(--muted-2);font-size:0.85rem;">${w.escapeHtml(it.agent_id || '')} ${it.ip_address ? '• ' + w.escapeHtml(it.ip_address) : ''}</div></td>
          <td>${w.escapeHtml(os)}</td>
          <td><code>${w.escapeHtml(kernel)}</code></td>
          <td><b>${sec}</b></td>
          <td><b>${all}</b></td>
          <td>${online}</td>
          <td class="status-muted">${w.escapeHtml(lastSeen)}</td>
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
      const itemsRaw = Array.isArray(d?.items) ? d.items : [];
      const suppressedCount = Number(d?.suppressed || 0);

      let seen = [];
      try { seen = JSON.parse(localStorage.getItem('fleet_notifications_seen_v1') || '[]'); } catch (_) { seen = []; }
      const seenSet = new Set(Array.isArray(seen) ? seen : []);

      let snoozed = {};
      try { snoozed = JSON.parse(localStorage.getItem('fleet_notifications_snooze_v1') || '{}') || {}; } catch (_) { snoozed = {}; }
      const nowMs = Date.now();
      const isSnoozed = (kind) => {
        const until = Number((snoozed && snoozed[kind]) || 0);
        return Number.isFinite(until) && until > nowMs;
      };

      const kinds = Array.from(new Set(itemsRaw.map((it) => String(it.kind || '')).filter(Boolean)));
      const items = itemsRaw.filter((it) => !isSnoozed(String(it.kind || '')));
      const unread = items.filter((it) => !seenSet.has(String(it.id || '')));

      if (badge) badge.style.display = unread.length ? 'inline' : 'none';

      if (!items.length) {
        wrap.innerHTML = '<div class="status-ok">No active notifications 🎯</div>';
      } else {
        wrap.innerHTML = `
          <div style="display:flex;gap:0.5rem;justify-content:space-between;align-items:center;margin-bottom:0.5rem;flex-wrap:wrap;">
            <div style="color:var(--muted-2);display:flex;gap:0.6rem;flex-wrap:wrap;align-items:center;">
              <span>Unread: <b>${unread.length}</b> / ${items.length}</span>
              ${suppressedCount > 0 ? `<span title="Suppressed by server cooldown" class="status-warn">Suppressed: ${suppressedCount}</span>` : ''}
            </div>
            <div style="display:flex;gap:0.35rem;flex-wrap:wrap;">
              <button class="btn" id="notifications-mark-read" type="button">Mark all read</button>
              <button class="btn" id="notifications-unsnooze-all" type="button">Unsnooze all</button>
            </div>
          </div>
          <div id="notifications-snooze-summary" style="color:var(--muted-2);font-size:0.85rem;margin-bottom:0.4rem;"></div>
          <div style="display:flex;flex-direction:column;gap:0.45rem;">
            ${items.map((it) => `<div style="border:1px solid var(--border);border-radius:10px;padding:0.45rem 0.6rem;background:var(--panel-2);${seenSet.has(String(it.id||'')) ? 'opacity:0.75;' : ''}">
              <div style="display:flex;justify-content:space-between;gap:0.5rem;align-items:center;">
                <b>${w.escapeHtml(it.title || '')}</b>
                <span style="font-size:0.75rem;" class="${it.severity==='high' ? 'status-error' : 'status-warn'}">${w.escapeHtml(it.severity || 'info')}</span>
              </div>
              <div class="status-muted" style="font-size:0.88rem;">${w.escapeHtml(it.detail || '')}</div>
              <div style="display:flex;gap:0.35rem;flex-wrap:wrap;margin-top:0.45rem;">
                <button class="btn" data-notif-action="open" data-notif-kind="${w.escapeHtml(it.kind || '')}" type="button" style="padding:0.18rem 0.45rem;">Open</button>
                <button class="btn" data-notif-action="snooze" data-notif-kind="${w.escapeHtml(it.kind || '')}" data-snooze-ms="3600000" type="button" style="padding:0.18rem 0.45rem;">Snooze 1h</button>
                <button class="btn" data-notif-action="snooze" data-notif-kind="${w.escapeHtml(it.kind || '')}" data-snooze-ms="28800000" type="button" style="padding:0.18rem 0.45rem;">Snooze 8h</button>
                <button class="btn" data-notif-action="snooze" data-notif-kind="${w.escapeHtml(it.kind || '')}" data-snooze-ms="86400000" type="button" style="padding:0.18rem 0.45rem;">Snooze 24h</button>
              </div>
            </div>`).join('')}
          </div>
        `;

        function fmtRemain(ms) {
          const total = Math.max(0, Math.floor(ms / 1000));
          const h = Math.floor(total / 3600);
          const m = Math.floor((total % 3600) / 60);
          if (h > 0) return `${h}h ${m}m`;
          return `${m}m`;
        }

        const snoozeSummaryEl = document.getElementById('notifications-snooze-summary');
        if (snoozeSummaryEl) {
          const activeKinds = kinds
            .map((k) => ({ kind: k, until: Number((snoozed && snoozed[k]) || 0) }))
            .filter((x) => Number.isFinite(x.until) && x.until > nowMs)
            .sort((a, b) => a.until - b.until);
          if (!activeKinds.length) {
            snoozeSummaryEl.textContent = 'No active snoozes.';
          } else {
            snoozeSummaryEl.textContent = 'Snoozed: ' + activeKinds.map((x) => `${x.kind} (${fmtRemain(x.until - nowMs)})`).join(' • ');
          }
        }

        document.getElementById('notifications-mark-read')?.addEventListener('click', () => {
          try {
            const ids = items.map((it) => String(it.id || '')).filter(Boolean);
            localStorage.setItem('fleet_notifications_seen_v1', JSON.stringify(ids));
          } catch (_) { }
          loadNotifications(ctx, false);
        });

        document.getElementById('notifications-unsnooze-all')?.addEventListener('click', () => {
          try {
            localStorage.setItem('fleet_notifications_snooze_v1', JSON.stringify({}));
          } catch (_) { }
          loadNotifications(ctx, false);
        });

        wrap.querySelectorAll('[data-notif-action]').forEach((btn) => {
          btn.addEventListener('click', (e) => {
            e.preventDefault();
            const action = btn.getAttribute('data-notif-action') || '';
            const kind = btn.getAttribute('data-notif-kind') || '';
            if (!kind) return;

            if (action === 'snooze') {
              const ms = Number(btn.getAttribute('data-snooze-ms') || 0);
              if (ms > 0) {
                try {
                  snoozed[kind] = Date.now() + ms;
                  localStorage.setItem('fleet_notifications_snooze_v1', JSON.stringify(snoozed));
                } catch (_) { }
                loadNotifications(ctx, false);
              }
              return;
            }

            // Open action by notification kind
            if (kind === 'failed_run') {
              const el = document.getElementById('failed-runs-card');
              if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
              return;
            }

            document.getElementById('nav-hosts')?.click();
            const sortSel = document.getElementById('hosts-sort');
            const orderSel = document.getElementById('hosts-order');
            if (kind === 'offline') {
              if (sortSel) sortSel.value = 'last_seen';
              if (orderSel) orderSel.value = 'asc';
            } else if (kind === 'security_backlog') {
              if (sortSel) sortSel.value = 'security_updates';
              if (orderSel) orderSel.value = 'desc';
            }
            sortSel?.dispatchEvent(new Event('change'));
          });
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

    function setGuardedButtonState(btn, blocked, message) {
      if (!btn) return;
      const original = btn.dataset.originalLabel || btn.textContent || '';
      if (!btn.dataset.originalLabel) btn.dataset.originalLabel = original;
      if (blocked) {
        btn.disabled = true;
        btn.textContent = original.startsWith('🔒 ') ? original : `🔒 ${original}`;
        btn.title = message || 'Blocked by maintenance window';
      } else {
        btn.disabled = false;
        btn.textContent = original;
        btn.title = '';
      }
    }

    async function refreshMaintenanceGuardButtons() {
      try {
        const r = await fetch('/dashboard/maintenance-window', { credentials: 'include' });
        if (!r.ok) return;
        const m = await r.json();
        const blocked = !!m.enabled && !m.within_window_now;
        const msg = blocked ? `Blocked outside maintenance window (${m.start}-${m.end} ${m.timezone})` : '';

        // Overview risky actions
        setGuardedButtonState(document.getElementById('overview-security-campaign'), blocked, msg);
        setGuardedButtonState(document.getElementById('overview-dist-upgrade'), blocked, msg);

        // Sidebar runbooks (risky ones)
        setGuardedButtonState(document.getElementById('runbook-security-now'), blocked, msg);
        setGuardedButtonState(document.getElementById('runbook-dist-now'), blocked, msg);
      } catch (_) { }
    }

    function showOverviewTab() {
      ctx.clearCurrentHostSelection();
      document.querySelectorAll('.tab-content-custom, .tab-content').forEach(c => c.classList.remove('active'));
      document.getElementById('server-info-tab')?.classList.add('active');
      if (containerEl) containerEl.classList.add('sidebar-collapsed');
      ctx.loadFleetOverview();
      ctx.loadFailedRuns(24, false);
      loadNotifications(ctx, false);
      refreshMaintenanceGuardButtons();
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
    refreshMaintenanceGuardButtons();

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
      if (!r.ok) {
        const t = await r.text();
        let msg = 'Campaign creation failed';
        try { const j = t ? JSON.parse(t) : null; msg = j?.detail || j?.error || msg; } catch (_) { }
        return w.showToast(msg, 'error');
      }
      const d = await r.json();
      if (d && d.approval_required) {
        return w.showToast(`Approval required (security-campaign): ${d.request_id}`, 'info', 5000);
      }
      w.showToast(`Security campaign scheduled: ${d.campaign_id}`, 'success');
    });

    w.wireBusyClick(distBtn, 'Queueing…', async () => {
      const agentIds = (ctx.getLastRenderedAgentIds() || []).slice();
      if (!agentIds.length) return w.showToast('No visible hosts selected', 'error');
      const r = await fetch('/jobs/dist-upgrade', { method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ agent_ids: agentIds }) });
      if (!r.ok) {
        const t = await r.text();
        let msg = 'dist-upgrade job creation failed';
        try { const j = t ? JSON.parse(t) : null; msg = j?.detail || j?.error || msg; } catch (_) { }
        return w.showToast(msg, 'error');
      }
      const d = await r.json();
      if (d && d.approval_required) {
        return w.showToast(`Approval required (dist-upgrade): ${d.request_id}`, 'info', 5000);
      }
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
        if (isOverview) {
          loadNotifications(ctx, false);
          refreshMaintenanceGuardButtons();
        }
      }, 60000);
    } catch (_) { }
  }

  w.phase3Overview = { loadFleetOverview, loadHostsTable, applyHostsTableFilters, loadPendingUpdatesReport, initFleetOverviewControls };
})(window);

(function (w) {
  function formatDateSafe(value) {
    if (!value) return '–';
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString();
  }

  async function buildHttpError(resp, label) {
    let detail = '';
    try {
      const data = await resp.clone().json();
      detail = data?.detail || data?.error || '';
    } catch (_) {
      try {
        detail = (await resp.text() || '').slice(0, 180);
      } catch (_) { }
    }
    return new Error(`${label} (${resp.status}${detail ? `: ${detail}` : ''})`);
  }

  function cssVar(name, fallback) {
    const raw = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return raw || fallback;
  }

  async function loadFleetOverview(ctx, forceLive) {
    const onlineEl = document.getElementById('kpi-online');
    const onlineDetailsEl = document.getElementById('kpi-online-details');
    const secEl = document.getElementById('kpi-sec');
    const secDetailsEl = document.getElementById('kpi-sec-details');
    const failEl = document.getElementById('kpi-fail');
    const freshEl = document.getElementById('kpi-fresh');
    const attentionEl = document.getElementById('overview-attention');
    const operationalQualityEl = document.getElementById('overview-operational-quality');
    const nextCronEl = document.getElementById('overview-next-cronjobs');
    const maintenanceEl = document.getElementById('maintenance-window-status');

    try {
      // First hydrate update KPIs from hosts report (more resilient than summary-only path).
      try {
        const rr0 = await fetch('/reports/hosts-updates?only_pending=false&online_only=false&sort=hostname&order=asc&limit=500', { credentials: 'include' });
        if (rr0.ok) {
          const report0 = await rr0.json();
          const items0 = Array.isArray(report0?.items) ? report0.items : [];
          const secHosts0 = items0.filter((it) => Number(it.security_updates || 0) > 0).length;
          const secPkgs0 = items0.reduce((n, it) => n + Number(it.security_updates || 0), 0);
          if (secEl) secEl.textContent = `${secHosts0} hosts`;
          if (secDetailsEl) secDetailsEl.textContent = `${secPkgs0} packages`;
        }
      } catch (_) { }

      const r = await fetch('/dashboard/summary', { credentials: 'include' });
      if (!r.ok) {
        if (r.status === 403) {
          // Expected transient state during MFA gating.
          // MFA/login transient; refresh auth state but continue with report-based fallbacks.
          if (typeof w.loadAuthInfo === 'function') {
            try { await w.loadAuthInfo(); } catch (_) {}
          }
        }
        throw await buildHttpError(r, 'dashboard summary failed');
      }
      const d = await r.json();

      const hostsTotal = d?.hosts?.total ?? 0;
      const hostsOnline = d?.hosts?.online ?? 0;
      const hostsOffline = d?.hosts?.offline ?? Math.max(0, hostsTotal - hostsOnline);
      const lastUpdatedEl = document.getElementById('guardian-last-updated');
      if (lastUpdatedEl) lastUpdatedEl.textContent = formatDateSafe(d?.ts);
      const secHosts = d?.updates?.hosts_with_security_updates ?? 0;
      const secPkgs = d?.updates?.security_total ?? 0;
      const failed24h = d?.jobs?.failed_runs_last_24h ?? 0;
      const freshest = d?.updates?.freshest_checked_at;

      const tfEl = document.getElementById('kpi-timeframe');
      const kpiHours = parseInt((tfEl?.value || '24').trim(), 10) || 24;
      const sr = await fetch(`/dashboard/slo?hours=${encodeURIComponent(kpiHours)}`, { credentials: 'include' });
      if (!sr.ok) throw await buildHttpError(sr, 'dashboard slo failed');
      const slo = await sr.json();
      const k = slo?.kpis || {};

      const fmtNum = (v, digits = 1, suffix = '') => (v == null || Number.isNaN(Number(v))) ? '–' : `${Number(v).toFixed(digits)}${suffix}`;
      const trend = (v, p, invert = false) => {
        if (v == null || p == null || Number.isNaN(Number(v)) || Number.isNaN(Number(p))) return 'n/a';
        const delta = Number(v) - Number(p);
        const good = invert ? delta < 0 : delta >= 0;
        const arrow = delta === 0 ? '→' : (good ? '↑' : '↓');
        return `${arrow} ${delta >= 0 ? '+' : ''}${delta.toFixed(1)}`;
      };

      const offline = k.offline_host_ratio || {};
      const succ = k.job_success_rate || {};
      const auth = k.auth_error_rate || {};

      if (onlineEl) onlineEl.textContent = `${hostsOffline}/${hostsTotal}`;
      if (onlineDetailsEl) onlineDetailsEl.textContent = `${fmtNum(offline.value, 1, '%')} offline • ${trend(offline.value, offline.previous, true)} • n=${offline.sample_count ?? 0}`;
      if (secEl) secEl.textContent = fmtNum(succ.value, 1, '%');
      if (secDetailsEl) secDetailsEl.textContent = `Using SLO window ${kpiHours}h`;
      if (failEl) failEl.textContent = fmtNum(succ.value, 1, '%');
      const slaDetail = !succ.sample_count ? 'no data in window' : `${trend(succ.value, succ.previous)} • n=${succ.sample_count ?? 0}`;
      const failDetailsEl = document.getElementById('kpi-fail-details');
      if (failDetailsEl) failDetailsEl.textContent = slaDetail;
      if (freshEl) freshEl.textContent = formatDateSafe(freshest);

      if (maintenanceEl) {
        try {
          const mw = await fetch('/dashboard/maintenance-window', { credentials: 'include' });
          if (mw.ok) {
            const md = await mw.json();
            if (!md.enabled) {
              maintenanceEl.className = 'status-muted';
              maintenanceEl.textContent = 'Maintenance window: disabled';
              if (secEl) secEl.textContent = 'Disabled';
              if (secDetailsEl) secDetailsEl.textContent = 'No active maintenance policy';
            } else if (md.within_window_now) {
              maintenanceEl.className = 'status-ok';
              maintenanceEl.textContent = `Maintenance window: ACTIVE (${md.start}-${md.end} ${md.timezone})`;
              if (secEl) secEl.textContent = `${md.start}-${md.end}`;
              if (secDetailsEl) secDetailsEl.textContent = `${md.timezone} · currently active`;
            } else {
              maintenanceEl.className = 'status-warn';
              maintenanceEl.textContent = `Maintenance window: outside allowed hours (${md.start}-${md.end} ${md.timezone})`;
              if (secEl) secEl.textContent = `${md.start}-${md.end}`;
              if (secDetailsEl) secDetailsEl.textContent = `${md.timezone} · outside window`;
            }
          }
        } catch (_) { }
      }

      if (operationalQualityEl) {
        const onlineRatio = hostsTotal > 0 ? (hostsOnline / hostsTotal) * 100 : 0;
        const patchHygiene = hostsTotal > 0 ? ((hostsTotal - secHosts) / hostsTotal) * 100 : 0;
        const successRate = Number(succ.value || 0);

        const qualityRow = (label, score, detail) => {
          const s = Math.max(0, Math.min(100, Number(score || 0)));
          const cls = s >= 95 ? 'status-ok' : s >= 85 ? 'status-warn' : 'status-error';
          return `<div style="display:flex;flex-direction:column;gap:.2rem;">
            <div style="display:flex;justify-content:space-between;gap:.6rem;"><span>${label}</span><b class="${cls}">${s.toFixed(1)}%</b></div>
            <div style="height:6px;border-radius:6px;background:var(--panel-2);overflow:hidden;"><div style="height:100%;width:${s}%;background:linear-gradient(90deg,${cssVar('--quality-bar-start', 'var(--primary)')},${cssVar('--quality-bar-end', 'var(--success)')});"></div></div>
            <div class="status-muted" style="font-size:.78rem;">${detail}</div>
          </div>`;
        };

        operationalQualityEl.innerHTML = `<div style="display:flex;flex-direction:column;gap:.55rem;">
          ${qualityRow('Online host ratio', onlineRatio, `${hostsOnline}/${hostsTotal} hosts online`) }
          ${qualityRow('Patch hygiene', patchHygiene, `${secHosts} hosts with security updates`) }
          ${qualityRow('Job success rate', successRate, `SLO window ${kpiHours}h`) }
        </div>`;
      }

      if (nextCronEl) {
        nextCronEl.innerHTML = '<div class="loading">Loading cronjobs…</div>';
        try {
          const rc = await fetch('/cronjobs', { credentials: 'include' });
          if (!rc.ok) throw await buildHttpError(rc, 'cronjobs failed');
          const cron = await rc.json();
          const items = Array.isArray(cron?.items) ? cron.items : [];
          const upcoming = items
            .filter((it) => (it?.status || '') === 'scheduled' && !!it?.run_at)
            .sort((a, b) => {
              const ta = Date.parse(a.run_at || '') || 0;
              const tb = Date.parse(b.run_at || '') || 0;
              return ta - tb;
            })
            .slice(0, 5);

          if (!upcoming.length) {
            nextCronEl.innerHTML = '<div class="status-muted">No scheduled cronjobs.</div>';
          } else {
            nextCronEl.innerHTML = `<div style="display:flex;flex-direction:column;gap:0.3rem;">${upcoming.map((it, idx) => {
              const when = formatDateSafe(it?.run_at);
              const action = w.escapeHtml(String(it?.action || 'job'));
              const name = w.escapeHtml(String(it?.name || action));
              return `<div><b>${idx + 1}.</b> ${name} <span style="color:var(--muted-2);">(${action})</span><br/><span style="color:var(--muted-2);font-size:0.9rem;">${w.escapeHtml(when)}</span></div>`;
            }).join('')}</div>`;
          }
        } catch (ec) {
          nextCronEl.innerHTML = `<div class="error">Cronjobs unavailable: ${w.escapeHtml(ec.message || String(ec))}</div>`;
        }
      }

      if (attentionEl) {
        attentionEl.innerHTML = '<div class="loading">Loading attention list…</div>';
        try {
          const r2 = await fetch(`/dashboard/attention?limit=200&include_live=true&force_live=${forceLive ? 'true' : 'false'}`, { credentials: 'include' });
          if (!r2.ok) throw await buildHttpError(r2, 'attention failed');
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
      // Fallback: keep KPI cards populated even if summary endpoint fails.
      try {
        const rf = await fetch('/reports/hosts-updates?only_pending=false&online_only=false&sort=hostname&order=asc&limit=500', { credentials: 'include' });
        if (rf.ok) {
          const dd = await rf.json();
          const items = Array.isArray(dd?.items) ? dd.items : [];
          const hostsTotal = items.length;
          const hostsOnline = items.filter((it) => !!it.is_online).length;
          const hostsOffline = Math.max(0, hostsTotal - hostsOnline);
          const secHosts = items.filter((it) => Number(it.security_updates || 0) > 0).length;
          const secPkgs = items.reduce((n, it) => n + Number(it.security_updates || 0), 0);
          const updHosts = items.filter((it) => Number(it.updates || 0) > 0).length;
          const updPkgs = items.reduce((n, it) => n + Number(it.updates || 0), 0);

          if (onlineEl) onlineEl.textContent = `${hostsOnline} / ${hostsTotal}`;
          if (onlineDetailsEl) onlineDetailsEl.textContent = `${hostsOffline} offline`;
          if (secEl) secEl.textContent = `${secHosts} hosts`;
          if (secDetailsEl) secDetailsEl.textContent = `${secPkgs} packages`;
          if (updEl) updEl.textContent = `${updHosts} hosts`;
          if (updDetailsEl) updDetailsEl.textContent = `${updPkgs} packages`;
        }
      } catch (_) { }

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
    const labelOwner = String((ctx && typeof ctx.getLabelOwnerFilter === 'function') ? (ctx.getLabelOwnerFilter() || '') : (document.getElementById('label-owner')?.value || '')).trim();
    const vulnSet = (ctx && typeof ctx.getVulnFilteredAgentIds === 'function') ? ctx.getVulnFilteredAgentIds() : null;

    if (vulnSet instanceof Set) {
      out = out.filter((it) => vulnSet.has(String(it.agent_id || '')));
    }

    if (labelEnv || labelRole || labelOwner) {
      out = out.filter((it) => {
        const labels = (it && it.labels && typeof it.labels === 'object') ? it.labels : {};
        if (labelEnv && String(labels.env || '') !== labelEnv) return false;
        if (labelRole && String(labels.role || '') !== labelRole) return false;
        if (labelOwner && String(labels.owner || '') !== labelOwner) return false;
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
      if (counterEl) counterEl.textContent = `0 / ${total} hosts shown · online 0 · offline 0`;
      w.setTableState(tbody, 10, 'empty', 'No hosts match current filters');
      if (ctx && typeof ctx.setLastRenderedAgentIds === 'function') ctx.setLastRenderedAgentIds([]);
      return;
    }

    if (counterEl) {
      const onlineCount = items.filter((it) => !!it.is_online).length;
      const offlineCount = Math.max(0, items.length - onlineCount);
      const withUpdates = items.filter((it) => Number(it.security_updates || 0) > 0 || Number(it.updates || 0) > 0).length;
      counterEl.textContent = `${items.length} / ${total} hosts shown · online ${onlineCount} · offline ${offlineCount} · pending updates ${withUpdates}`;
    }

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
      const rebootAction = it.reboot_required
        ? ('<button type="button" class="btn host-reboot-btn" data-agent-id="' + w.escapeHtml(it.agent_id || '') + '" data-hostname="' + w.escapeHtml(hostName) + '" style="padding:0.15rem 0.4rem;font-size:0.78rem;">Reboot</button>')
        : '<span class="status-muted">—</span>';
      const lastSeen = ctx.formatShortTime(it.last_seen);

      const tr = document.createElement('tr');
      tr.style.cursor = 'pointer';
      const activeAgentId = (ctx.getCurrentAgentId && ctx.getCurrentAgentId()) || '';
      if (activeAgentId && String(it.agent_id || '') === String(activeAgentId)) {
        tr.classList.add('host-row-active');
      }
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
        <td style="text-align:right;">${rebootAction}</td>
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
            const blockedLocal = Array.isArray(preview?.blocked_local_agent_ids) ? preview.blocked_local_agent_ids : [];
            if (!found.length) {
              if (blockedLocal.includes(agentId)) {
                const force = confirm('Host is protected (srv-001 local agent).\n\nForce remove it from inventory?');
                if (!force) return;
                const forceResp = await fetch('/hosts/remove', {
                  method: 'POST',
                  credentials: 'include',
                  headers: { 'content-type': 'application/json' },
                  body: JSON.stringify({ agent_ids: [agentId], include_local: true })
                });
                if (!forceResp.ok) throw new Error(`force remove failed (${forceResp.status})`);
                w.showToast(`Removed host ${hostnameLabel}`, 'success');
                if (ctx && typeof ctx.loadHostsTable === 'function') await ctx.loadHostsTable();
                else await loadHostsTable(ctx);
                if (ctx && typeof ctx.loadHosts === 'function') await ctx.loadHosts();
                return;
              }
              else w.showToast('Host no longer exists', 'error');
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

      const rebootBtn = tr.querySelector('.host-reboot-btn');
      if (rebootBtn) {
        rebootBtn.addEventListener('click', async (e) => {
          e.preventDefault();
          e.stopPropagation();
          const agentId = String(rebootBtn.getAttribute('data-agent-id') || '').trim();
          const hostnameLabel = String(rebootBtn.getAttribute('data-hostname') || '').trim() || agentId;
          if (!agentId) return;
          if (!confirm(`Reboot host "${hostnameLabel}" (${agentId})?`)) return;
          try {
            const resp = await fetch(`/hosts/${encodeURIComponent(agentId)}/reboot`, {
              method: 'POST',
              credentials: 'include',
            });
            let data = null;
            try { data = await resp.json(); } catch (_) { data = null; }
            if (!resp.ok) {
              throw new Error((data && (data.detail || data.error)) || `reboot failed (${resp.status})`);
            }
            w.showToast(`Reboot queued for ${hostnameLabel}`, 'success');
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

  async function updateHostsUpdatesHint() {
    const hintEl = document.getElementById('hosts-updates-hint');
    if (!hintEl) return;

    const fmt = (iso) => formatDateSafe(iso);

    try {
      const [summaryRes, jobsRes] = await Promise.all([
        fetch('/dashboard/summary', { credentials: 'include' }),
        fetch('/jobs?type=dist-upgrade&status=success&limit=1', { credentials: 'include' }),
      ]);

      let lastCheck = null;
      if (summaryRes.ok) {
        const s = await summaryRes.json();
        lastCheck = s?.updates?.freshest_checked_at || null;
      }

      let lastUpgrade = null;
      if (jobsRes.ok) {
        const j = await jobsRes.json();
        const first = Array.isArray(j?.items) ? j.items[0] : null;
        lastUpgrade = first?.created_at || null;
      }

      hintEl.textContent = `Last updates check: ${fmt(lastCheck)} • Last successful dist-upgrade: ${fmt(lastUpgrade)} • 0 means fully patched.`;
    } catch (_) {
      hintEl.textContent = '0 in Security/All updates usually means fully patched (possibly recently upgraded).';
    }
  }

  async function loadHostsTable(ctx) {
    const tbody = document.getElementById('hosts-table-body');
    if (!tbody) return;
    const sortSel = document.getElementById('hosts-sort');
    const orderSel = document.getElementById('hosts-order');
    const sort = sortSel?.value || 'hostname';
    const order = orderSel?.value || 'asc';

    try {
      w.setTableState(tbody, 10, 'loading', 'Loading…');
      const effectiveSort = sort === 'owner' ? 'hostname' : sort;
      const url = `/reports/hosts-updates?only_pending=false&online_only=false&sort=${encodeURIComponent(effectiveSort)}&order=${encodeURIComponent(order)}&limit=500`;
      const r = await fetch(url, { credentials: 'include' });
      if (!r.ok) throw await buildHttpError(r, 'hosts report failed');
      const d = await r.json();
      const items = d?.items || [];
      hostsTableItemsCache = Array.isArray(items) ? items : [];
      if (sort === 'owner') {
        const dir = order === 'desc' ? -1 : 1;
        hostsTableItemsCache.sort((a, b) => {
          const ao = String(a?.labels?.owner || '').trim();
          const bo = String(b?.labels?.owner || '').trim();
          const ownerCmp = ao.localeCompare(bo, undefined, { sensitivity: 'base' });
          if (ownerCmp !== 0) return ownerCmp * dir;
          return String(a?.hostname || a?.agent_id || '').localeCompare(String(b?.hostname || b?.agent_id || ''), undefined, { sensitivity: 'base' }) * dir;
        });
      }
      if (!hostsTableItemsCache.length) {
        if (ctx && typeof ctx.setLastRenderedAgentIds === 'function') ctx.setLastRenderedAgentIds([]);
        updateHostsUpdatesHint();
        return w.setTableState(tbody, 10, 'empty', 'No hosts');
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
      updateHostsUpdatesHint();

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
      w.setTableState(tbody, 10, 'error', `Hosts table error: ${e.message || String(e)}`);
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
      if (!r.ok) throw await buildHttpError(r, 'report failed');
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
    const wrap = document.getElementById('overview-active-alerts') || document.getElementById('overview-notifications');
    const card = document.getElementById('notifications-card');
    const badge = document.getElementById('notifications-badge');
    if (!wrap) return;
    try {
      const compactMode = wrap.id === 'overview-active-alerts';
      wrap.innerHTML = '<div class="loading">Loading alerts…</div>';
      const r = await fetch(`/dashboard/notifications?limit=${compactMode ? 8 : 30}`, { credentials: 'include' });
      if (!r.ok) {
        if (r.status === 403) return; // MFA transient
        throw await buildHttpError(r, 'notifications failed');
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
        if (card) card.style.display = 'none';
        wrap.innerHTML = '<div class="status-ok">No active alerts.</div>';
      } else {
        if (card && !compactMode) card.style.display = '';
        wrap.innerHTML = compactMode
          ? `<div style="display:flex;flex-direction:column;gap:0.4rem;">${items.map((it) => `<div style="border:1px solid var(--border);border-radius:8px;padding:0.38rem 0.5rem;background:var(--panel-2);">
              <div style="display:flex;justify-content:space-between;gap:0.45rem;align-items:center;">
                <b>${w.escapeHtml(it.title || '')}</b>
                <span style="font-size:0.72rem;" class="${it.severity==='high' ? 'status-error' : 'status-warn'}">${w.escapeHtml(it.severity || 'info')}</span>
              </div>
              <div class="status-muted" style="font-size:0.8rem;">${w.escapeHtml(it.detail || '')}</div>
            </div>`).join('')}</div>`
          : `
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
      if (card) card.style.display = '';
      wrap.innerHTML = `<div class="error">Notifications error: ${w.escapeHtml(e.message || String(e))}</div>`;
      if (showToastOnManual) w.showToast(`Notifications failed: ${e.message || String(e)}`, 'error');
    }
  }

  function initFleetOverviewControls(ctx) {
    const navOverview = document.getElementById('nav-overview');
    const navHosts = document.getElementById('nav-hosts');
    const navCronjobs = document.getElementById('nav-cronjobs');
    const navSshKeys = document.getElementById('nav-sshkeys');
    const navReports = document.getElementById('nav-reports');
    const nextCronjobsOpenBtn = document.getElementById('overview-next-cronjobs-open');
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

    function showReportsTab() {
      ctx.clearCurrentHostSelection();
      document.querySelectorAll('.tab-content-custom, .tab-content').forEach(c => c.classList.remove('active'));
      document.getElementById('reports-tab')?.classList.add('active');
      if (containerEl) containerEl.classList.add('sidebar-collapsed');
    }

    navOverview?.addEventListener('click', (e) => { e.preventDefault(); showOverviewTab(); });
    navHosts?.addEventListener('click', (e) => { e.preventDefault(); showHostsTab(); });
    navCronjobs?.addEventListener('click', (e) => { e.preventDefault(); showCronjobsTab(); });
    navSshKeys?.addEventListener('click', (e) => { e.preventDefault(); showSshKeysTab(); });
    navReports?.addEventListener('click', (e) => { e.preventDefault(); showReportsTab(); });
    nextCronjobsOpenBtn?.addEventListener('click', (e) => { e.preventDefault(); showCronjobsTab(); });

    showOverviewTab();
    refreshMaintenanceGuardButtons();

    const refreshBtn = document.getElementById('overview-refresh');
    const kpiTimeframeEl = document.getElementById('kpi-timeframe');
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
    kpiTimeframeEl?.addEventListener('change', () => {
      ctx.loadFleetOverview(true);
    });

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

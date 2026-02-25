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
    const backupVerificationEl = document.getElementById('overview-backup-verification');
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
          const updHosts0 = items0.filter((it) => Number(it.updates || 0) > 0).length;
          const updPkgs0 = items0.reduce((n, it) => n + Number(it.updates || 0), 0);
          if (secEl) secEl.textContent = `${secHosts0} hosts`;
          if (secDetailsEl) secDetailsEl.textContent = `${secPkgs0} packages`;
          if (updEl) updEl.textContent = `${updHosts0} hosts`;
          if (updDetailsEl) updDetailsEl.textContent = `${updPkgs0} packages`;
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

      const tfEl = document.getElementById('kpi-timeframe');
      const kpiHours = parseInt((tfEl?.value || '24').trim(), 10) || 24;
      const sr = await fetch(`/dashboard/slo?hours=${encodeURIComponent(kpiHours)}`, { credentials: 'include' });
      if (!sr.ok) throw new Error(`dashboard slo failed (${sr.status})`);
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
      const patch = k.median_patch_duration || {};
      const auth = k.auth_error_rate || {};

      if (onlineEl) onlineEl.textContent = fmtNum(offline.value, 1, '%');
      if (onlineDetailsEl) onlineDetailsEl.textContent = `${trend(offline.value, offline.previous, true)} • n=${offline.sample_count ?? 0}`;
      if (secEl) secEl.textContent = fmtNum(succ.value, 1, '%');
      if (secDetailsEl) secDetailsEl.textContent = `${trend(succ.value, succ.previous)} • n=${succ.sample_count ?? 0}`;
      if (updEl) updEl.textContent = fmtNum(patch.value, 1, 's');
      if (updDetailsEl) updDetailsEl.textContent = `${trend(patch.value, patch.previous, true)} • n=${patch.sample_count ?? 0}`;
      if (failEl) failEl.textContent = fmtNum(auth.value, 1, '%');
      const authNoData = !auth.sample_count ? 'no data in window' : `${trend(auth.value, auth.previous, true)} • n=${auth.sample_count ?? 0}`;
      const failDetailsEl = document.getElementById('kpi-fail-details');
      if (failDetailsEl) failDetailsEl.textContent = authNoData;
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

      if (backupVerificationEl) {
        backupVerificationEl.innerHTML = '<div class="loading">Loading backup verification status…</div>';
        try {
          const thresholdKey = 'fleet_backup_verification_stale_hours_v1';
          let staleHours = 24;
          try {
            const raw = localStorage.getItem(thresholdKey);
            const parsed = Number(raw);
            if (Number.isFinite(parsed) && parsed > 0) staleHours = parsed;
          } catch (_) {}

          const getCsrf = () => {
            try {
              const m = document.cookie.match(/(?:^|; )fleet_csrf=([^;]+)/);
              return m ? decodeURIComponent(m[1]) : '';
            } catch (_) { return ''; }
          };

          const renderBackupCard = (latest, policy = {}) => {
            let statusLine = '<div class="status-warn">No backup verification runs yet.</div>';
            let detailsBtn = '';

            if (latest) {
              const finishedAt = latest?.finished_at ? Date.parse(latest.finished_at) : NaN;
              const ageMs = Number.isFinite(finishedAt) ? (Date.now() - finishedAt) : NaN;
              const staleMs = staleHours * 60 * 60 * 1000;

              let badge = 'Verified';
              let cls = 'status-ok';
              if (String(latest?.status || '').toLowerCase() !== 'verified') {
                badge = 'Failed';
                cls = 'status-error';
              } else if (!Number.isFinite(ageMs) || ageMs > staleMs) {
                badge = 'Stale';
                cls = 'status-warn';
              }

              const whenText = latest?.finished_at ? new Date(latest.finished_at).toLocaleString() : 'Unknown';
              const ageHours = Number.isFinite(ageMs) ? Math.floor(ageMs / (60 * 60 * 1000)) : null;
              statusLine = `
                <div>
                  <span class="${cls}" style="display:inline-block;padding:0.1rem 0.45rem;border-radius:999px;font-weight:600;">${w.escapeHtml(badge)}</span>
                  <span style="color:var(--muted-2);margin-left:0.5rem;">Updated: ${w.escapeHtml(whenText)}</span>
                </div>
                <div style="color:var(--muted-2);font-size:0.9rem;">${ageHours == null ? 'Age unavailable' : `Age: ${ageHours}h • Stale after ${staleHours}h`}</div>
              `;
              const detailsUrl = `/backup-verification/runs/${encodeURIComponent(String(latest?.id || ''))}`;
              detailsBtn = `<a class="btn" href="${detailsUrl}" target="_blank" rel="noopener">Open details</a>`;
            }

            backupVerificationEl.innerHTML = `
              <div style="display:flex;flex-direction:column;gap:0.45rem;">
                ${statusLine}
                <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;">
                  ${detailsBtn}
                  <label style="color:var(--muted-2);font-size:0.85rem;">Stale after (h)
                    <input id="backup-verification-stale-hours" class="host-search" type="number" min="1" value="${staleHours}" style="width:64px;margin-left:0.25rem;padding:0.25rem 0.4rem;" />
                  </label>
                  <button class="btn" id="backup-verification-stale-save" type="button" style="padding:0.2rem 0.45rem;">Save</button>
                </div>
                <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;">
                  <input id="backup-verification-policy-path" class="host-search" type="text" placeholder="/path/to/backup.file" value="${w.escapeHtml(String(policy.backup_path || ''))}" style="min-width:260px;flex:1;" />
                  <input id="backup-verification-policy-schema" class="host-search" type="number" min="0" placeholder="schema (optional)" value="${policy.expected_schema_version == null ? '' : Number(policy.expected_schema_version)}" style="width:130px;" />
                  <button class="btn" id="backup-verification-policy-save" type="button">Configure policy</button>
                  <button class="btn" id="backup-verification-policy-run-now" type="button">Run now</button>
                </div>
              </div>
            `;

            document.getElementById('backup-verification-stale-save')?.addEventListener('click', () => {
              const n = Number(document.getElementById('backup-verification-stale-hours')?.value || 24);
              const next = Number.isFinite(n) && n > 0 ? n : 24;
              try {
                localStorage.setItem(thresholdKey, String(next));
                if (typeof w.showToast === 'function') w.showToast('Backup verification threshold saved', 'success');
                if (typeof ctx.loadFleetOverview === 'function') ctx.loadFleetOverview(false);
              } catch (_) {
                if (typeof w.showToast === 'function') w.showToast('Failed to save threshold', 'error');
              }
            });

            document.getElementById('backup-verification-policy-save')?.addEventListener('click', async () => {
              const path = String(document.getElementById('backup-verification-policy-path')?.value || '').trim();
              const schemaRaw = String(document.getElementById('backup-verification-policy-schema')?.value || '').trim();
              if (!path) {
                if (typeof w.showToast === 'function') w.showToast('Backup path is required', 'error');
                return;
              }
              const body = {
                enabled: true,
                backup_path: path,
                schedule_kind: String(policy?.schedule_kind || 'daily'),
                timezone: String(policy?.timezone || 'UTC'),
                time_hhmm: String(policy?.time_hhmm || '03:00'),
                weekday: Number.isFinite(Number(policy?.weekday)) ? Number(policy.weekday) : 0,
                stale_after_hours: Number.isFinite(Number(policy?.stale_after_hours)) ? Number(policy.stale_after_hours) : 36,
                alert_on_failure: policy?.alert_on_failure !== false,
                alert_on_stale: policy?.alert_on_stale !== false,
              };
              if (schemaRaw !== '') body.expected_schema_version = Number(schemaRaw);
              const rp = await fetch('/backup-verification/policy', {
                method: 'PUT',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrf() },
                body: JSON.stringify(body),
              });
              if (!rp.ok) {
                const txt = await rp.text();
                if (typeof w.showToast === 'function') w.showToast(`Policy save failed (${rp.status}) ${txt || ''}`.trim(), 'error');
                return;
              }
              if (typeof w.showToast === 'function') w.showToast('Backup verification policy saved', 'success');
            });

            document.getElementById('backup-verification-policy-run-now')?.addEventListener('click', async () => {
              const rr = await fetch('/backup-verification/policy/run-now', {
                method: 'POST',
                credentials: 'include',
                headers: { 'X-CSRF-Token': getCsrf() },
              });
              if (!rr.ok) {
                const txt = await rr.text();
                if (typeof w.showToast === 'function') w.showToast(`Run failed (${rr.status}) ${txt || ''}`.trim(), 'error');
                return;
              }
              if (typeof w.showToast === 'function') w.showToast('Backup verification run started', 'success');
              if (typeof ctx.loadFleetOverview === 'function') ctx.loadFleetOverview(false);
            });
          };

          let policy = {};
          try {
            const rp = await fetch('/backup-verification/policy', { credentials: 'include' });
            if (rp.ok) policy = await rp.json();
          } catch (_) {}

          const rv = await fetch('/backup-verification/latest', { credentials: 'include' });
          if (rv.status === 404) {
            renderBackupCard(null, policy);
          } else if (!rv.ok) {
            throw new Error(`backup verification failed (${rv.status})`);
          } else {
            const latest = await rv.json();
            renderBackupCard(latest, policy);
          }
        } catch (ev) {
          backupVerificationEl.innerHTML = `<div class="error">Backup verification unavailable: ${w.escapeHtml(ev.message || String(ev))}</div>`;
        }
      }

      if (nextCronEl) {
        nextCronEl.innerHTML = '<div class="loading">Loading cronjobs…</div>';
        try {
          const rc = await fetch('/cronjobs', { credentials: 'include' });
          if (!rc.ok) throw new Error(`cronjobs failed (${rc.status})`);
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
              const when = it?.run_at ? new Date(it.run_at).toLocaleString() : '–';
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
      w.setTableState(tbody, 10, 'empty', 'No hosts match current filters');
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
      const rebootAction = it.reboot_required
        ? ('<button type="button" class="btn host-reboot-btn" data-agent-id="' + w.escapeHtml(it.agent_id || '') + '" data-hostname="' + w.escapeHtml(hostName) + '" style="padding:0.15rem 0.4rem;font-size:0.78rem;">Reboot</button>')
        : '<span class="status-muted">—</span>';
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

    const fmt = (iso) => {
      if (!iso) return '–';
      try { return new Date(iso).toLocaleString(); } catch (_) { return String(iso); }
    };

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
      const url = `/reports/hosts-updates?only_pending=false&online_only=false&sort=${encodeURIComponent(sort)}&order=${encodeURIComponent(order)}&limit=500`;
      const r = await fetch(url, { credentials: 'include' });
      if (!r.ok) throw new Error(`hosts report failed (${r.status})`);
      const d = await r.json();
      const items = d?.items || [];
      hostsTableItemsCache = Array.isArray(items) ? items : [];
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
    const card = document.getElementById('notifications-card');
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
        if (card) card.style.display = 'none';
        wrap.innerHTML = '<div class="status-ok">No active notifications 🎯</div>';
      } else {
        if (card) card.style.display = '';
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

    navOverview?.addEventListener('click', (e) => { e.preventDefault(); showOverviewTab(); });
    navHosts?.addEventListener('click', (e) => { e.preventDefault(); showHostsTab(); });
    navCronjobs?.addEventListener('click', (e) => { e.preventDefault(); showCronjobsTab(); });
    navSshKeys?.addEventListener('click', (e) => { e.preventDefault(); showSshKeysTab(); });
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
    const rolloutCampaignIdEl = document.getElementById('rollout-campaign-id');
    const rolloutLoadBtn = document.getElementById('rollout-load');
    const rolloutPauseBtn = document.getElementById('rollout-pause');
    const rolloutResumeBtn = document.getElementById('rollout-resume');
    const rolloutApproveNextBtn = document.getElementById('rollout-approve-next');
    const rolloutSummaryEl = document.getElementById('rollout-summary');
    const rolloutStatusEl = document.getElementById('rollout-status');

    function renderRolloutSummary(data) {
      if (!rolloutSummaryEl) return;
      if (!data) {
        rolloutSummaryEl.textContent = 'No rollout data.';
        return;
      }
      const waves = Array.isArray(data?.waves) ? data.waves : [];
      const status = String(data?.status || 'unknown');
      const paused = !!data?.rollout?.paused;
      const approved = Number(data?.rollout?.approved_through_ring || 0);
      const done = Number(data?.hosts_done || 0);
      const total = Number(data?.hosts_total || 0);
      const failed = Number(data?.hosts_failed || 0);
      const pauseReason = data?.rollout?.pause_reason ? ` • reason: ${w.escapeHtml(String(data.rollout.pause_reason))}` : '';
      rolloutSummaryEl.innerHTML = `
        <div><b>${w.escapeHtml(String(data?.campaign_id || ''))}</b> • status: <b>${w.escapeHtml(status)}</b> • paused: <b>${paused ? 'yes' : 'no'}</b>${pauseReason}</div>
        <div class="status-muted" style="margin-top:0.3rem;">Progress: ${done}/${total} done • failed: ${failed} • approved ring: ${approved}</div>
        <div style="margin-top:0.45rem;overflow:auto;">
          <table class="process-table" style="min-width:520px;">
            <thead><tr><th>Wave</th><th style="text-align:right;">Hosts</th><th style="text-align:right;">Failed</th></tr></thead>
            <tbody>
              ${waves.length ? waves.map((wv) => `<tr><td>${w.escapeHtml(String(wv?.name || `ring-${wv?.index || 0}`))}</td><td style="text-align:right;">${Number(wv?.size || 0)}</td><td style="text-align:right;">${Number(wv?.failed || 0)}</td></tr>`).join('') : '<tr><td colspan="3" class="status-muted" style="text-align:center;">No wave data</td></tr>'}
            </tbody>
          </table>
        </div>
      `;
    }

    async function loadRolloutSummary(showToastOnError) {
      const campaignId = (rolloutCampaignIdEl?.value || '').trim();
      if (!campaignId) {
        if (rolloutStatusEl) rolloutStatusEl.textContent = 'Campaign id is required.';
        return null;
      }
      if (rolloutStatusEl) rolloutStatusEl.textContent = 'Loading rollout…';
      const r = await fetch(`/patching/campaigns/${encodeURIComponent(campaignId)}/rollout`, { credentials: 'include' });
      const raw = await r.text();
      let d = null;
      try { d = raw ? JSON.parse(raw) : null; } catch (_) { d = null; }
      if (!r.ok) {
        const msg = (d && (d.detail || d.error)) || raw || `rollout load failed (${r.status})`;
        if (rolloutStatusEl) rolloutStatusEl.textContent = msg;
        if (showToastOnError) w.showToast(msg, 'error');
        return null;
      }
      renderRolloutSummary(d);
      if (rolloutStatusEl) rolloutStatusEl.textContent = `Last refresh: ${new Date().toLocaleTimeString()}`;
      return d;
    }

    async function rolloutAction(action) {
      const campaignId = (rolloutCampaignIdEl?.value || '').trim();
      if (!campaignId) return w.showToast('Campaign id is required', 'error');
      const endpoint = action === 'approve-next' ? 'approve-next' : action;
      const r = await fetch(`/patching/campaigns/${encodeURIComponent(campaignId)}/${endpoint}`, {
        method: 'POST',
        credentials: 'include',
      });
      const raw = await r.text();
      let d = null;
      try { d = raw ? JSON.parse(raw) : null; } catch (_) { d = null; }
      if (!r.ok) {
        const msg = (d && (d.detail || d.error)) || raw || `${action} failed (${r.status})`;
        if (rolloutStatusEl) rolloutStatusEl.textContent = msg;
        return w.showToast(msg, 'error');
      }
      renderRolloutSummary(d);
      if (rolloutStatusEl) rolloutStatusEl.textContent = `${action} ok • ${new Date().toLocaleTimeString()}`;
      w.showToast(`Rollout ${action} OK`, 'success');
    }

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

    w.wireBusyClick(rolloutLoadBtn, 'Loading…', async () => {
      await loadRolloutSummary(true);
    });
    w.wireBusyClick(rolloutPauseBtn, 'Pausing…', async () => { await rolloutAction('pause'); });
    w.wireBusyClick(rolloutResumeBtn, 'Resuming…', async () => { await rolloutAction('resume'); });
    w.wireBusyClick(rolloutApproveNextBtn, 'Approving…', async () => { await rolloutAction('approve-next'); });
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
      if (rolloutCampaignIdEl && d?.campaign_id) rolloutCampaignIdEl.value = String(d.campaign_id);
      w.showToast(`Security campaign scheduled: ${d.campaign_id}`, 'success');
      if (d?.campaign_id) {
        try { await loadRolloutSummary(false); } catch (_) { }
      }
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

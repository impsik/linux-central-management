(function () {
  'use strict';

  async function loadCronjobs(ctx, showToastOnManual = false) {
    const tbody = document.getElementById('cronjobs-table');
    if (!tbody) return;
    try {
      ctx.setTableState(tbody, 7, 'loading', 'Loading…');
      const r = await fetch('/cronjobs', { credentials: 'include' });
      if (!r.ok) throw new Error(`cronjobs failed (${r.status})`);
      const d = await r.json();
      const items = d?.items || [];
      if (!items.length) {
        ctx.setTableState(tbody, 7, 'empty', 'No cronjobs yet');
        return;
      }
      tbody.innerHTML = '';
      for (const it of items) {
        const tr = document.createElement('tr');
        const when = ctx.formatShortTime(it.run_at);
        const owner = String(it.owner_username || '').trim();
        const targets = Array.isArray(it.selector?.agent_ids) ? it.selector.agent_ids.length : '–';
        const status = it.status || '–';
        tr.innerHTML = `
          <td class="status-muted">${ctx.escapeHtml(when)}</td>
          <td>${ctx.escapeHtml(it.name || '')}</td>
          <td>${owner ? `<code>${ctx.escapeHtml(owner)}</code>` : '<span class="status-muted">—</span>'}</td>
          <td><code>${ctx.escapeHtml(it.action || '')}</code></td>
          <td>${ctx.escapeHtml(String(targets))}</td>
          <td>${ctx.escapeHtml(status)}</td>
          <td style="text-align:right;">
            ${(() => {
              const jk = it.latest_run?.job_key || '';
              if (jk && !jk.startsWith('patch-campaign:')) {
                return `<a class="btn" href="/jobs/${encodeURIComponent(jk)}/logs.zip" target="_blank" rel="noopener">Download logs</a>`;
              }
              return '';
            })()}
            ${status === 'scheduled' ? ` <button class="btn" data-cancel-id="${ctx.escapeHtml(it.id)}">Cancel</button>` : ''}
          </td>
        `;
        tbody.appendChild(tr);
      }
      tbody.querySelectorAll('button[data-cancel-id]').forEach(btn => {
        btn.addEventListener('click', async (e) => {
          e.preventDefault();
          const id = btn.getAttribute('data-cancel-id');
          if (!id) return;
          const r2 = await fetch(`/cronjobs/${encodeURIComponent(id)}/cancel`, { method: 'POST', credentials: 'include' });
          if (!r2.ok) return ctx.showToast('Cancel failed', 'error');
          ctx.showToast('Cronjob canceled', 'success');
          loadCronjobs(ctx);
        });
      });
      if (showToastOnManual) ctx.showToast('Cronjobs refreshed', 'success');
    } catch (e) {
      ctx.setTableState(tbody, 7, 'error', e.message || String(e));
      if (showToastOnManual) ctx.showToast(e.message, 'error');
    }
  }

  function setCronHostsPanelVisible(visible) {
    const panel = document.getElementById('cron-hosts-panel');
    if (!panel) return;
    panel.style.display = visible ? 'block' : 'none';
  }

  function renderCronHostsList(ctx) {
    const listEl = document.getElementById('cron-hosts-list');
    const countEl = document.getElementById('cron-hosts-count');
    if (!listEl) return;

    const selectedAgentIds = ctx.getCronSelectedAgentIds();
    const q = (document.getElementById('cron-hosts-search')?.value || '').trim().toLowerCase();
    const hosts = (ctx.getAllHosts() || []).slice();

    listEl.innerHTML = '';
    if (!hosts.length) {
      listEl.innerHTML = '<div class="empty-state" style="padding:0.75rem;">No hosts loaded yet.</div>';
      if (countEl) countEl.textContent = String(selectedAgentIds.size);
      return;
    }

    for (const h of hosts) {
      const aid = h.agent_id || '';
      const name = h.hostname || aid;
      const ip = h.ip_address || '';
      const os = `${h.os_id || ''} ${h.os_version || ''}`.trim();
      const hay = `${name} ${aid} ${ip} ${os}`.toLowerCase();
      if (q && !hay.includes(q)) continue;

      const row = document.createElement('label');
      row.style.display = 'flex';
      row.style.alignItems = 'center';
      row.style.justifyContent = 'space-between';
      row.style.gap = '0.75rem';
      row.style.padding = '0.5rem 0.6rem';
      row.style.borderRadius = '8px';
      row.style.cursor = 'pointer';
      row.style.background = 'transparent';

      const left = document.createElement('div');
      left.style.display = 'flex';
      left.style.flexDirection = 'column';
      left.style.gap = '0.1rem';

      const title = document.createElement('div');
      title.innerHTML = `<b>${ctx.escapeHtml(name)}</b> <span class="status-muted" style="font-size:0.85rem;">${ctx.escapeHtml(aid)}</span>`;
      const sub = document.createElement('div');
      sub.style.color = 'var(--muted-2)';
      sub.style.fontSize = '0.85rem';
      sub.textContent = ip ? ip : '';

      left.appendChild(title);
      if (ip) left.appendChild(sub);

      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.checked = selectedAgentIds.has(aid);
      cb.addEventListener('change', () => {
        if (cb.checked) selectedAgentIds.add(aid);
        else selectedAgentIds.delete(aid);
        if (countEl) countEl.textContent = String(selectedAgentIds.size);
      });

      row.appendChild(left);
      row.appendChild(cb);
      row.addEventListener('mouseenter', () => { row.style.background = 'color-mix(in srgb, var(--panel) 55%, transparent)'; });
      row.addEventListener('mouseleave', () => { row.style.background = 'transparent'; });

      listEl.appendChild(row);
    }

    if (countEl) countEl.textContent = String(selectedAgentIds.size);
  }

  function getVisibleOrAllHostIds(ctx) {
    const visibleIds = Array.from(ctx.getLastRenderedAgentIds() || []);
    return visibleIds.length ? visibleIds : (ctx.getAllHosts() || []).map(h => h.agent_id).filter(Boolean);
  }

  async function runImmediateForVisible(ctx, action) {
    const statusEl = document.getElementById('cron-from-filter-status');
    const ids = getVisibleOrAllHostIds(ctx);
    if (!ids.length) {
      if (statusEl) statusEl.textContent = 'No hosts available. Load hosts first.';
      return;
    }

    try {
      if (statusEl) statusEl.textContent = `Running ${action} for ${ids.length} hosts…`;
      let r = null;
      if (action === 'inventory-now') {
        r = await fetch('/jobs/inventory-now', { method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ agent_ids: ids }) });
      } else if (action === 'security-campaign') {
        const now = new Date();
        const end = new Date(now.getTime() + 60 * 60 * 1000);
        r = await fetch('/patching/campaigns/security-updates', {
          method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ agent_ids: ids, window_start: now.toISOString(), window_end: end.toISOString(), concurrency: 5, reboot_if_needed: true, include_kernel: false })
        });
      } else {
        const check = await ctx.confirmBlastRadius(ids, 'dist-upgrade preflight');
        if (!check.ok) {
          if (statusEl) statusEl.textContent = 'Cancelled.';
          return;
        }
        r = await fetch('/jobs/dist-upgrade', { method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ agent_ids: ids }) });
      }

      if (!r || !r.ok) {
        const raw = r ? await r.text() : '';
        let detail = '';
        try { const j = raw ? JSON.parse(raw) : null; detail = j?.detail || j?.error || ''; } catch (_) { detail = ''; }
        throw new Error(detail || `request failed (${r ? r.status : 'n/a'})`);
      }

      let data = null;
      try { data = await r.json(); } catch (_) { data = null; }
      if (data && data.approval_required) {
        if (statusEl) statusEl.textContent = `Approval required: request ${data.request_id}`;
        ctx.showToast(`Approval required (${action}). Request: ${data.request_id}`, 'info', 5000);
        return;
      }

      if (statusEl) statusEl.textContent = `Triggered ${action} for ${ids.length} hosts.`;
      ctx.showToast(`Triggered ${action} for ${ids.length} hosts`, 'success');
    } catch (err) {
      const msg = (err && err.message) ? err.message : String(err);
      if (statusEl) statusEl.textContent = msg;
      ctx.showToast(msg, 'error');
    }
  }

  function initCronjobsControls(ctx) {
    setupCronScheduleUi();

    setupCronHostPickerControls({
      setPanelVisible: setCronHostsPanelVisible,
      renderList: () => renderCronHostsList(ctx),
      selectAll: () => {
        const selectedAgentIds = ctx.getCronSelectedAgentIds();
        (ctx.getAllHosts() || []).forEach(h => { if (h.agent_id) selectedAgentIds.add(h.agent_id); });
      },
      clearSelection: () => {
        ctx.setCronSelectedAgentIds(new Set());
      },
    });

    const cronRefreshBtn = document.getElementById('cron-refresh');
    ctx.wireBusyClick(cronRefreshBtn, 'Refreshing…', async () => {
      await loadCronjobs(ctx, true);
    });

    const cronCreateBtn = document.getElementById('cron-create');
    cronCreateBtn?.addEventListener('click', async (e) => {
      e.preventDefault();
      await handleCronCreate({
        createBtn: cronCreateBtn,
        statusEl: document.getElementById('cron-create-status'),
        getSelectedAgentIds: () => Array.from(ctx.getCronSelectedAgentIds() || []),
        setPanelVisible: setCronHostsPanelVisible,
        renderList: () => renderCronHostsList(ctx),
        loadCronjobs: () => loadCronjobs(ctx),
        withBusyButton: ctx.withBusyButton,
      });
    });

    const fromFilterBtn = document.getElementById('cron-from-filter-open');
    const fromFilterRunNowBtn = document.getElementById('cron-from-filter-run-now');
    const runbookInventoryBtn = document.getElementById('runbook-inventory-now');
    const runbookSecurityBtn = document.getElementById('runbook-security-now');
    const runbookDistBtn = document.getElementById('runbook-dist-now');

    fromFilterBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      const statusEl = document.getElementById('cron-from-filter-status');
      const action = document.getElementById('cron-from-filter-action')?.value || 'security-campaign';
      const schedule = document.getElementById('cron-from-filter-schedule')?.value || 'weekly-sun-0200';

      const ids = getVisibleOrAllHostIds(ctx);
      if (!ids.length) {
        if (statusEl) statusEl.textContent = 'No hosts available. Load hosts first.';
        return;
      }

      document.getElementById('nav-cronjobs')?.click();

      ctx.setCronSelectedAgentIds(new Set(ids));
      setCronHostsPanelVisible(true);
      renderCronHostsList(ctx);

      const actionEl = document.getElementById('cron-action');
      if (actionEl) actionEl.value = action;

      const nameEl = document.getElementById('cron-name');
      const env = (document.getElementById('label-env')?.value || '').trim();
      const role = (document.getElementById('label-role')?.value || '').trim();
      const search = (document.getElementById('host-search')?.value || '').trim();
      const scopeBits = [env ? `env:${env}` : '', role ? `role:${role}` : '', search ? `q:${search}` : ''].filter(Boolean).join(' ');
      if (nameEl) nameEl.value = `${action} (${scopeBits || 'visible hosts'})`;

      const kindEl = document.getElementById('cron-schedule-kind');
      const runAtEl = document.getElementById('cron-run-at');
      const timeEl = document.getElementById('cron-time');
      const weekdayEl = document.getElementById('cron-weekday');

      if (schedule === 'once-30m') {
        if (kindEl) kindEl.value = 'once';
        const dt = new Date(Date.now() + 30 * 60 * 1000);
        const yyyy = dt.getFullYear();
        const mm = String(dt.getMonth() + 1).padStart(2, '0');
        const dd = String(dt.getDate()).padStart(2, '0');
        const hh = String(dt.getHours()).padStart(2, '0');
        const mi = String(dt.getMinutes()).padStart(2, '0');
        if (runAtEl) runAtEl.value = `${yyyy}-${mm}-${dd}T${hh}:${mi}`;
      } else if (schedule === 'daily-0600') {
        if (kindEl) kindEl.value = 'daily';
        if (timeEl) timeEl.value = '06:00';
      } else {
        if (kindEl) kindEl.value = 'weekly';
        if (weekdayEl) weekdayEl.value = '0'; // Sunday
        if (timeEl) timeEl.value = '02:00';
      }

      kindEl?.dispatchEvent(new Event('change'));
      if (statusEl) statusEl.textContent = `Prefilled cron with ${ids.length} hosts.`;
    });

    fromFilterRunNowBtn?.addEventListener('click', async (e) => {
      e.preventDefault();
      const action = document.getElementById('cron-from-filter-action')?.value || 'security-campaign';
      await runImmediateForVisible(ctx, action);
    });

    runbookInventoryBtn?.addEventListener('click', async (e) => { e.preventDefault(); await runImmediateForVisible(ctx, 'inventory-now'); });
    runbookSecurityBtn?.addEventListener('click', async (e) => { e.preventDefault(); await runImmediateForVisible(ctx, 'security-campaign'); });
    runbookDistBtn?.addEventListener('click', async (e) => { e.preventDefault(); await runImmediateForVisible(ctx, 'dist-upgrade'); });
  }

  window.fleetCronjobsUi = {
    loadCronjobs,
    renderCronHostsList,
    initCronjobsControls,
  };
})();

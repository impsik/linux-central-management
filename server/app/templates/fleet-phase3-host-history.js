(function (w) {
  function timelineJobCategory(ctx, it) {
    const api = ctx || {};
    const jtRaw = String(it?.job_type || '').toLowerCase();
    const jt = jtRaw.replace(/[_\s]+/g, '-');
    if (jt === 'dist-upgrade' || jt === 'security-campaign') return 'security';
    if (jt.startsWith('pkg-') || jt.includes('package') || jt.includes('inventory')) return 'package';
    if (jt.startsWith('service-') || jt.includes('service')) return 'service';
    return 'all';
  }

  function timelineFilterMatch(ctx, it) {
    const api = ctx || {};
    const filter = api.getTimelineFilter?.() || 'all';
    if (filter === 'all') return true;
    const st = String(it?.status || '').toLowerCase();
    if (filter === 'failed') return st === 'failed';
    return timelineJobCategory(api, it) === filter;
  }

  function timelineJobEffect(ctx, it) {
    const jtRaw = String(it?.job_type || '').toLowerCase();
    const jt = jtRaw.replace(/[_\s]+/g, '-');
    if (jt === 'query-pkg-updates' || jt === 'query-pkg-version' || jt === 'query-pkg-info' || jt === 'inventory-now') {
      return { kind: 'info', label: 'Read-only check', detail: 'Collects inventory/update status. Does not install packages.' };
    }
    if (jt === 'pkg-upgrade' || jt === 'dist-upgrade' || jt === 'security-campaign') {
      return { kind: 'warn', label: 'Installs/changes packages', detail: 'This action can modify installed packages on the host.' };
    }
    return null;
  }

  function hostTimelineFilteredItems(ctx) {
    const api = ctx || {};
    return (api.getTimelineItems?.() || []).filter((it) => timelineFilterMatch(api, it));
  }

  function renderHostTimeline(ctx) {
    const api = ctx || {};
    const el = document.getElementById('host-timeline-list');
    const countEl = document.getElementById('host-timeline-count');
    if (!el) return;

    ['all', 'failed', 'security', 'package', 'service'].forEach((k) => {
      const btn = document.getElementById(`timeline-filter-${k}`);
      if (!btn) return;
      btn.classList.toggle('btn-primary', (api.getTimelineFilter?.() || 'all') === k);
      if (btn.dataset.boundTimelineFilterRender !== '1') {
        btn.addEventListener('click', (e) => {
          e.preventDefault();
          api.setTimelineFilter?.(k);
          renderHostTimeline(api);
        });
        btn.dataset.boundTimelineFilterRender = '1';
      }
    });

    const allItems = api.getTimelineItems?.() || [];
    const items = hostTimelineFilteredItems(api);
    if (countEl) countEl.textContent = `(${items.length}/${allItems.length})`;
    if (!items.length) {
      el.innerHTML = '<div class="status-muted">No events for selected filter.</div>';
      return;
    }

    el.innerHTML = items.map((it) => {
      const t = it?.time ? new Date(it.time).toLocaleString() : 'n/a';
      const st = String(it?.status || 'unknown');
      const stClass = st === 'success' ? 'status-ok' : (st === 'failed' ? 'status-error' : 'status-muted');
      const jobType = w.escapeHtml(String(it?.job_type || 'job'));
      const jobId = w.escapeHtml(String(it?.job_id || ''));
      const stdout = it?.stdout ? `<a class="status-link" href="${w.escapeHtml(String(it.stdout))}" target="_blank" rel="noopener">stdout</a>` : '';
      const stderr = it?.stderr ? `<a class="status-link" href="${w.escapeHtml(String(it.stderr))}" target="_blank" rel="noopener">stderr</a>` : '';
      const links = [stdout, stderr].filter(Boolean).join(' • ');
      const effect = timelineJobEffect(api, it);
      const effectTone = effect?.kind === 'warn' ? 'var(--warn)' : 'var(--muted-2)';
      return `<div style="border:1px solid var(--border);border-radius:10px;padding:0.45rem 0.55rem;background:var(--panel-2);">
        <div style="display:flex;justify-content:space-between;gap:0.5rem;align-items:center;">
          <b>${jobType}</b>
          <span class="${stClass}" style="font-size:0.8rem;">${w.escapeHtml(st)}</span>
        </div>
        ${effect ? `<div style="font-size:0.78rem;margin-top:0.18rem;color:${effectTone};">${w.escapeHtml(effect.label)} — ${w.escapeHtml(effect.detail)}</div>` : ''}
        <div class="status-muted" style="font-size:0.82rem;margin-top:0.2rem;display:flex;justify-content:space-between;gap:0.5rem;align-items:center;flex-wrap:wrap;">
          <span>${w.escapeHtml(t)} • <code>${jobId}</code></span>
          <button class="btn" data-copy-job-id="${jobId}" type="button" style="padding:0.16rem 0.45rem;">Copy job id</button>
        </div>
        ${links ? `<div style="font-size:0.8rem;margin-top:0.2rem;">${links}</div>` : ''}
      </div>`;
    }).join('');

    el.querySelectorAll('button[data-copy-job-id]').forEach((btn) => {
      if (btn.dataset.boundCopyJobId === '1') return;
      btn.addEventListener('click', async (e) => {
        e.preventDefault();
        const id = btn.getAttribute('data-copy-job-id') || '';
        if (!id) return;
        try {
          if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(id);
          } else {
            const ta = document.createElement('textarea');
            ta.value = id;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
          }
          api.showToast?.('Job ID copied', 'success', 1800);
        } catch (_) {
          api.showToast?.('Failed to copy job ID', 'error', 2200);
        }
      });
      btn.dataset.boundCopyJobId = '1';
    });
  }

  function downloadHostTimeline(ctx, kind) {
    const api = ctx || {};
    const items = hostTimelineFilteredItems(api);
    if (!items.length) {
      api.showToast?.('No timeline entries to export', 'error', 2200);
      return;
    }
    const now = new Date();
    const stamp = `${now.getFullYear()}${String(now.getMonth()+1).padStart(2,'0')}${String(now.getDate()).padStart(2,'0')}-${String(now.getHours()).padStart(2,'0')}${String(now.getMinutes()).padStart(2,'0')}`;
    const base = `host-timeline-${api.getTimelineFilter?.() || 'all'}-${stamp}`;
    let blob;
    let filename;
    if (kind === 'csv') {
      const esc = (v) => {
        const s = String(v == null ? '' : v);
        return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
      };
      const headers = ['time','job_id','job_type','status','exit_code','started_at','finished_at','created_by'];
      const rows = [headers.join(',')].concat(items.map((it) => headers.map((h) => esc(it?.[h] ?? '')).join(',')));
      blob = new Blob([rows.join('\n')], { type: 'text/csv;charset=utf-8' });
      filename = `${base}.csv`;
    } else {
      blob = new Blob([JSON.stringify(items, null, 2)], { type: 'application/json;charset=utf-8' });
      filename = `${base}.json`;
    }
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    api.showToast?.(`Exported ${items.length} timeline entr${items.length === 1 ? 'y' : 'ies'}`, 'success', 2000);
  }

  function renderHostDriftChecks(ctx) {
    const api = ctx || {};
    const listEl = document.getElementById('host-drift-list');
    const toggleBtn = document.getElementById('host-drift-critical-only');
    if (!listEl) return;
    if (toggleBtn) toggleBtn.classList.toggle('btn-primary', !!api.getDriftCriticalOnly?.());

    const checks = (api.getDriftChecks?.() || []).filter((c) => {
      if (!api.getDriftCriticalOnly?.()) return true;
      const sev = String(c?.severity || (String(c?.status || '') === 'pass' ? 'ok' : 'warn'));
      return sev === 'critical';
    });

    if (!checks.length) {
      listEl.innerHTML = '<div class="status-muted">No checks for selected filter.</div>';
      return;
    }

    listEl.innerHTML = checks.map((c) => {
      const sev = String(c?.severity || (String(c?.status || '') === 'pass' ? 'ok' : 'warn'));
      const sevClass = sev === 'critical' ? 'status-error' : (sev === 'warn' ? 'status-warn' : 'status-ok');
      return `<div style="display:flex;justify-content:space-between;gap:0.6rem;align-items:flex-start;">
        <div><b>${w.escapeHtml(String(c?.title || 'check'))}</b><div class="status-muted" style="font-size:0.82rem;">${w.escapeHtml(String(c?.detail || ''))}</div></div>
        <span class="${sevClass}" style="font-size:0.75rem;">${w.escapeHtml(sev)}</span>
      </div>`;
    }).join('');
  }

  function initTimelineFilters(ctx) {
    const api = ctx || {};
    ['all', 'failed', 'security', 'package', 'service'].forEach((k) => {
      const btn = document.getElementById(`timeline-filter-${k}`);
      if (!btn || btn.dataset.boundTimelineFilter === '1') return;
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        api.setTimelineFilter?.(k);
        renderHostTimeline(api);
      });
      btn.dataset.boundTimelineFilter = '1';
    });
  }

  w.phase3HostHistory = {
    timelineJobCategory,
    timelineFilterMatch,
    timelineJobEffect,
    renderHostTimeline,
    hostTimelineFilteredItems,
    downloadHostTimeline,
    renderHostDriftChecks,
    initTimelineFilters,
  };
})(window);

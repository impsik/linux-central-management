(function () {
  'use strict';

  const esc = (value) => String(value == null ? '' : value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');

  async function loadHighSeverityCveReport(ctx, showToastOnManual = false) {
    const bodyEl = document.getElementById('reports-cve-table-body');
    const statusEl = document.getElementById('reports-cve-status');
    const minSeverity = String(document.getElementById('reports-cve-min-severity')?.value || '7.0').trim() || '7.0';
    if (!bodyEl) return;
    bodyEl.innerHTML = '<tr><td colspan="10" class="status-muted" style="text-align:center;">Loading…</td></tr>';
    if (statusEl) statusEl.textContent = 'Loading…';
    try {
      const qs = new URLSearchParams({ min_severity: minSeverity, sort: 'severity', order: 'desc', limit: '200' }).toString();
      const r = await fetch(`/reports/cve-high-severity?${qs}`, { credentials: 'include' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const data = await r.json();
      const items = Array.isArray(data?.items) ? data.items : [];
      if (!items.length) {
        bodyEl.innerHTML = '<tr><td colspan="10" class="status-ok" style="text-align:center;">No high severity CVEs found on online hosts.</td></tr>';
      } else {
        bodyEl.innerHTML = items.map((it) => {
          const sev = Number(it?.severity || 0);
          const sevCls = sev >= 9 ? 'status-error' : 'status-warn';
          const remediation = it.candidate_fixes === true ? 'Upgrade fixes' : (it.candidate_fixes === false ? 'No fixed candidate' : 'Candidate unknown');
          const remediationCls = it.candidate_fixes === true ? 'status-ok' : (it.candidate_fixes === false ? 'status-error' : 'status-warn');
          return `<tr>
            <td><b>${esc(it.hostname || it.agent_id || '')}</b><div class="status-muted">${esc(it.agent_id || '')}</div></td>
            <td><code>${esc(it.package_name || '')}</code></td>
            <td>${(Array.isArray(it.cve_ids) ? it.cve_ids : []).map((cve) => `<a href="https://ubuntu.com/security/${encodeURIComponent(cve)}" target="_blank" rel="noopener noreferrer"><code>${esc(cve)}</code></a>`).join('<br>') || '-'}</td>
            <td style="text-align:right;"><span class="${sevCls}">${esc(sev.toFixed ? sev.toFixed(1) : sev)}</span></td>
            <td style="text-align:right;">${esc(it.cve_count || 0)}</td>
            <td><code>${esc(it.installed_version || '')}</code></td>
            <td><code>${esc(it.candidate_version || '-')}</code></td>
            <td><span class="${remediationCls}">${esc(remediation)}</span></td>
            <td><code>${esc(it.fixed_version || '')}</code></td>
            <td>${esc(it.release || '')}</td>
          </tr>`;
        }).join('');
      }
      if (statusEl) statusEl.textContent = `${items.length} finding${items.length === 1 ? '' : 's'} shown`;
      if (showToastOnManual && typeof ctx.showToast === 'function') ctx.showToast('CVE report refreshed', 'success');
    } catch (e) {
      console.error('[loadHighSeverityCveReport failed]', e);
      bodyEl.innerHTML = '<tr><td colspan="10" class="status-error" style="text-align:center;">Failed to load CVE report.</td></tr>';
      if (statusEl) statusEl.textContent = 'Load failed';
      if (showToastOnManual && typeof ctx.showToast === 'function') ctx.showToast('Failed to load CVE report', 'error');
    }
  }

  function initReportsControls(ctx) {
    document.getElementById('reports-cve-refresh')?.addEventListener('click', (e) => {
      e.preventDefault();
      void loadHighSeverityCveReport(ctx, true);
    });

    document.getElementById('reports-cve-html')?.addEventListener('click', (e) => {
      e.preventDefault();
      const minSeverity = String(document.getElementById('reports-cve-min-severity')?.value || '7.0').trim() || '7.0';
      const qs = new URLSearchParams({ min_severity: minSeverity, sort: 'severity', order: 'desc' }).toString();
      window.open(`/reports/cve-high-severity.html?${qs}`, '_blank', 'noopener');
    });

    const btn = document.getElementById('reports-user-presence-open');
    if (btn) {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const u = String(document.getElementById('reports-user-presence-username')?.value || '').trim();
        const exact = !!document.getElementById('reports-user-presence-exact')?.checked;
        const liveScan = !!document.getElementById('reports-user-presence-live')?.checked;
        if (!u) {
          if (typeof ctx.showToast === 'function') ctx.showToast('Enter username', 'error');
          return;
        }
        const qs = new URLSearchParams({ username: u, exact: String(exact), live_scan: String(liveScan) }).toString();
        window.open(`/reports/user-presence.html?${qs}`, '_blank', 'noopener');
      });
    }

    document.getElementById('nav-reports')?.addEventListener('click', () => {
      void loadHighSeverityCveReport(ctx, false);
    });
  }

  window.fleetReportsUi = {
    initReportsControls,
    loadHighSeverityCveReport,
  };
})();

(function () {
  'use strict';

  async function loadFailedRuns(ctx, hours = 24, showToastOnManual = false) {
    const tbody = document.getElementById('overview-failed-runs');
    const card = document.getElementById('failed-runs-card');
    if (!tbody) return;
    try {
      ctx.setTableState(tbody, 5, 'loading', 'Loading…');
      const r = await fetch(`/dashboard/failed-runs?hours=${encodeURIComponent(hours)}&limit=200`, { credentials: 'include' });
      if (!r.ok) throw new Error(`failed-runs fetch failed (${r.status})`);
      const d = await r.json();
      const items = d?.items || [];
      if (!items.length) {
        if (card) card.style.display = 'none';
        ctx.setTableState(tbody, 5, 'empty', 'No failed runs 🎯');
        return;
      }
      if (card) card.style.display = '';
      tbody.innerHTML = '';
      const detailsByRunId = {};
      for (const it of items) {
        const when = ctx.formatShortTime(it.finished_at);
        const host = it.agent_id || '–';
        const job = `${it.job_type || 'job'}${it.job_key ? ' • ' + it.job_key : ''}`.trim();
        const exit = (it.exit_code === null || it.exit_code === undefined) ? '–' : String(it.exit_code);
        const err = (it.error || (it.stderr || '').split('\n').slice(-1)[0] || '').trim();
        const runId = String(it.run_id || it.id || `${host}|${job}|${it.finished_at || ''}`);
        const retryCount = Number(it.retry_count || 0);
        const retryNote = retryCount > 0 ? `retried ${retryCount}x` : '';
        const staleNote = it.is_stale ? 'stale running before failure' : '';
        const cancelledNote = it.is_cancelled ? 'cancelled before agent claim' : '';
        const queueNotes = [retryNote, staleNote, cancelledNote].filter(Boolean).join(' • ');
        const errClass = it.is_cancelled ? 'status-muted' : 'status-error';

        const detail = [
          `Host: ${host}`,
          `Job: ${job}`,
          it.finished_at ? `When: ${new Date(it.finished_at).toLocaleString()}` : '',
          (it.exit_code === null || it.exit_code === undefined) ? '' : `Exit: ${it.exit_code}`,
          it.is_cancelled ? 'Cancelled: yes' : '',
          retryCount > 0 ? `Retries: ${retryCount}` : '',
          it.stale_after_seconds ? `Stale threshold: ${it.stale_after_seconds}s` : '',
          '',
          '--- error ---',
          (it.error || ''),
          '',
          '--- stderr ---',
          (it.stderr || ''),
          '',
          '--- stdout ---',
          (it.stdout || ''),
        ].filter(Boolean).join('\n');
        detailsByRunId[runId] = detail;

        const tr = document.createElement('tr');
        tr.style.cursor = 'pointer';
        tr.setAttribute('data-failed-run-id', runId);
        tr.setAttribute('data-failed-run-detail', detail);
        tr.innerHTML = `
          <td class="status-muted">${ctx.escapeHtml(when)}</td>
          <td><b>${ctx.escapeHtml(host)}</b></td>
          <td>${ctx.escapeHtml(job)}${queueNotes ? `<div class="status-muted" style="font-size:0.78rem;margin-top:0.15rem;">${ctx.escapeHtml(queueNotes)}</div>` : ''}</td>
          <td style="text-align:right;">${ctx.escapeHtml(exit)}</td>
          <td class="${errClass}">${ctx.escapeHtml(err || (it.is_cancelled ? 'cancelled' : 'failed'))} <button class="btn" data-copy-failed-run="${ctx.escapeHtml(runId)}" type="button" style="margin-left:0.4rem;padding:0.12rem 0.4rem;">Copy</button></td>
        `;

        tr.addEventListener('click', () => {
          if (typeof window.openFailedRunDetailModal === 'function') {
            window.openFailedRunDetailModal(detail, `${host} • ${job}`);
          }
        });

        const copyBtn = tr.querySelector('button[data-copy-failed-run]');
        copyBtn?.addEventListener('click', async (e) => {
          e.preventDefault();
          e.stopPropagation();
          try {
            await navigator.clipboard.writeText(detail);
            ctx.showToast('Failed run detail copied', 'success');
          } catch {
            if (typeof window.openFailedRunDetailModal === 'function') {
              window.openFailedRunDetailModal(detail, `${host} • ${job}`);
            }
            ctx.showToast('Clipboard blocked. Opened detail view for manual copy.', 'error', 3800);
          }
        });

        tbody.appendChild(tr);
      }

      const copyVisibleBtn = document.getElementById('failed-runs-copy-visible');
      copyVisibleBtn?.replaceWith(copyVisibleBtn.cloneNode(true));
      const copyVisibleBtn2 = document.getElementById('failed-runs-copy-visible');
      copyVisibleBtn2?.addEventListener('click', async (e) => {
        e.preventDefault();
        const rows = Array.from(tbody.querySelectorAll('tr[data-failed-run-id]'));
        const chunks = rows.map((row, idx) => {
          const detail = row.getAttribute('data-failed-run-detail') || '';
          return `#${idx + 1}\n${detail}`;
        }).filter(Boolean);
        const text = chunks.join('\n\n');
        if (!text) return;
        try {
          await navigator.clipboard.writeText(text);
          ctx.showToast('Visible failed runs copied', 'success');
        } catch {
          if (typeof window.openFailedRunDetailModal === 'function') {
            window.openFailedRunDetailModal(text, `Visible failed runs (${rows.length})`);
          }
          ctx.showToast('Clipboard blocked. Opened detail view for manual copy.', 'error', 3800);
        }
      });

      if (showToastOnManual) ctx.showToast('Failed runs refreshed', 'success');
    } catch (e) {
      if (card) card.style.display = '';
      ctx.setTableState(tbody, 5, 'error', e.message || String(e));
      if (showToastOnManual) ctx.showToast(e.message, 'error');
    }
  }

  window.fleetFailedRunsUi = {
    loadFailedRuns,
  };
})();

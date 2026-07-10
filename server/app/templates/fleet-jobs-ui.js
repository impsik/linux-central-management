(function () {
  'use strict';

  function formatSecondsShort(seconds) {
    if (seconds === null || seconds === undefined || seconds === '') return '';
    const total = Math.max(0, Number(seconds) || 0);
    if (total < 60) return `${Math.round(total)}s`;
    const minutes = Math.floor(total / 60);
    if (minutes < 60) return `${minutes}m`;
    const hours = Math.floor(minutes / 60);
    const remMinutes = minutes % 60;
    if (hours < 48) return remMinutes ? `${hours}h ${remMinutes}m` : `${hours}h`;
    const days = Math.floor(hours / 24);
    const remHours = hours % 24;
    return remHours ? `${days}d ${remHours}h` : `${days}d`;
  }

  async function loadQueueHealth(ctx, showToastOnManual = false) {
    const tbody = document.getElementById('overview-queue-health');
    const summaryEl = document.getElementById('queue-health-summary');
    const statusEl = document.getElementById('queue-health-status');
    const typeEl = document.getElementById('queue-health-type');
    const agentEl = document.getElementById('queue-health-agent');
    const ownerEl = document.getElementById('queue-health-owner');
    const limitEl = document.getElementById('queue-health-limit');
    const pageEl = document.getElementById('queue-health-page');
    const prevBtn = document.getElementById('queue-health-prev');
    const nextBtn = document.getElementById('queue-health-next');
    if (!tbody) return;
    const status = String(statusEl?.value || '').trim();
    const type = String(typeEl?.value || '').trim();
    const agentId = String(agentEl?.value || '').trim();
    const owner = String(ownerEl?.value || '').trim();
    const limit = Math.max(1, Math.min(200, Number(limitEl?.value || 50) || 50));
    const offset = Math.max(0, Number(ctx.getOffset?.() || 0));
    const qs = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    if (status) qs.set('status', status);
    if (type) qs.set('type', type);
    if (agentId) qs.set('agent_id', agentId);
    if (owner) qs.set('created_by', owner);

    try {
      ctx.setTableState(tbody, 6, 'loading', 'Loading…');
      if (summaryEl) summaryEl.textContent = 'Loading…';
      const r = await fetch(`/jobs?${qs.toString()}`, { credentials: 'include' });
      if (!r.ok) throw new Error(`queue health fetch failed (${r.status})`);
      const d = await r.json();
      const items = d?.items || [];
      const total = Number(d?.total || 0);
      const shownStart = items.length ? offset + 1 : 0;
      const shownEnd = offset + items.length;
      const counts = { queued: 0, running: 0, failed: 0, success: 0 };
      let staleRunning = 0;
      let retried = 0;
      let oldQueued = 0;
      for (const it of items) {
        const st = String(it.status || '').toLowerCase();
        if (Object.prototype.hasOwnProperty.call(counts, st)) counts[st] += 1;
        const runs = it.runs || {};
        if (Number(runs.stale_running || 0) > 0) staleRunning += 1;
        if (Number(runs.retry_count_max || 0) > 0) retried += 1;
        if (it?.observability?.is_old_queued) oldQueued += 1;
      }
      if (summaryEl) {
        summaryEl.textContent = `${shownStart}-${shownEnd} of ${total} jobs · queued ${counts.queued} · running ${counts.running} · failed ${counts.failed} · success ${counts.success} · old queued ${oldQueued} · stale ${staleRunning} · retried ${retried}`;
      }
      if (pageEl) pageEl.textContent = `Page ${Math.floor(offset / limit) + 1}`;
      if (prevBtn) prevBtn.disabled = offset <= 0;
      if (nextBtn) nextBtn.disabled = shownEnd >= total;
      if (!items.length) {
        ctx.setTableState(tbody, 6, 'empty', 'No jobs in selected view');
        return;
      }

      tbody.innerHTML = '';
      for (const it of items) {
        const jobId = it.job_id || it.id;
        const type = String(it.type || 'job');
        const statusText = String(it.status || 'unknown');
        const runs = it.runs || {};
        const runCount = Number(runs.total || runs.count || 0);
        const retryMax = Number(runs.retry_count_max || 0);
        const staleCount = Number(runs.stale_running || 0);
        const failedCount = Number(runs.failed || 0);
        const cancelledCount = Number(runs.cancelled || 0);
        const isCancelledJob = statusText === 'failed' && cancelledCount > 0 && failedCount > 0 && cancelledCount >= failedCount;
        const displayStatus = isCancelledJob ? 'cancelled' : statusText;
        const obs = it.observability || {};
        const ageText = formatSecondsShort(obs.age_seconds);
        const queueNotes = [
          it.created_by ? `by ${it.created_by}` : '',
          ageText ? `age ${ageText}` : '',
          obs.is_old_queued ? `old queued > ${formatSecondsShort(obs.queued_warn_after_seconds)}` : '',
          runs.running ? `${runs.running} running` : '',
          failedCount && !isCancelledJob ? `${failedCount} failed` : '',
          cancelledCount ? `${cancelledCount} cancelled` : '',
          retryMax > 0 ? `retry max ${retryMax}` : '',
          staleCount > 0 ? `${staleCount} stale running` : '',
        ].filter(Boolean);
        const statusClass = displayStatus === 'success' ? 'status-ok' : (displayStatus === 'failed' ? 'status-error' : (displayStatus === 'running' ? 'status-warn' : 'status-muted'));

        const tr = document.createElement('tr');
        if (statusText === 'queued' && obs.is_old_queued && jobId) {
          tr.setAttribute('data-old-queued-job-id', String(jobId));
        }
        const cancelAction = jobId && statusText === 'queued'
          ? `<button class="btn" data-job-cancel="${ctx.escapeHtml(String(jobId))}" type="button" style="padding:0.12rem 0.4rem;margin-right:0.35rem;">Cancel</button>`
          : '';
        tr.innerHTML = `
          <td class="status-muted">${ctx.escapeHtml(ctx.formatShortTime(it.created_at))}${ageText ? `<div class="${obs.is_old_queued ? 'status-warn' : 'status-muted'}" style="font-size:0.78rem;margin-top:0.15rem;">age ${ctx.escapeHtml(ageText)}</div>` : ''}</td>
          <td><b>${ctx.escapeHtml(type)}</b><div class="status-muted" style="font-size:0.78rem;">${ctx.escapeHtml(String(jobId || ''))}</div></td>
          <td><span class="${statusClass}">${ctx.escapeHtml(displayStatus)}</span></td>
          <td style="text-align:right;">${ctx.escapeHtml(String(runCount))}</td>
          <td>${ctx.escapeHtml(queueNotes.join(' • ') || 'waiting for agent')}</td>
          <td>${jobId ? `<button class="btn" data-job-detail="${ctx.escapeHtml(String(jobId))}" type="button" style="padding:0.12rem 0.4rem;margin-right:0.35rem;">Details</button>${cancelAction}<a href="/jobs/${encodeURIComponent(jobId)}/logs.zip" target="_blank" rel="noopener">logs.zip</a>` : '<span class="status-muted">–</span>'}</td>
        `;
        const detailBtn = tr.querySelector('button[data-job-detail]');
        detailBtn?.addEventListener('click', (e) => {
          e.preventDefault();
          const id = detailBtn.getAttribute('data-job-detail') || '';
          if (id) void openJobDetailModal(ctx, id);
        });
        const cancelBtn = tr.querySelector('button[data-job-cancel]');
        cancelBtn?.addEventListener('click', (e) => {
          e.preventDefault();
          const id = cancelBtn.getAttribute('data-job-cancel') || '';
          if (id) void cancelQueuedJob(ctx, id);
        });
        tbody.appendChild(tr);
      }
      if (showToastOnManual) ctx.showToast('Queue health refreshed', 'success');
    } catch (e) {
      ctx.setTableState(tbody, 6, 'error', e.message || String(e));
      if (summaryEl) summaryEl.textContent = 'Queue health unavailable';
      if (showToastOnManual) ctx.showToast(e.message || String(e), 'error');
    }
  }

  function resetQueueHealthPagination(ctx) {
    ctx.setOffset?.(0);
  }

  function moveQueueHealthPage(ctx, direction) {
    const limitEl = document.getElementById('queue-health-limit');
    const limit = Math.max(1, Math.min(200, Number(limitEl?.value || 50) || 50));
    const offset = Math.max(0, Number(ctx.getOffset?.() || 0) + (direction * limit));
    ctx.setOffset?.(offset);
    return loadQueueHealth(ctx, false);
  }

  function formatJobDetailText(d) {
    const lines = [];
    const runs = Array.isArray(d?.runs) ? d.runs : [];
    const obs = d?.observability || {};
    lines.push(`Job: ${d?.job_id || 'unknown'}`);
    lines.push(`Type: ${d?.type || 'job'}`);
    lines.push(`Created: ${d?.created_at ? new Date(d.created_at).toLocaleString() : 'n/a'}`);
    lines.push(`Done: ${d?.done ? 'yes' : 'no'}`);
    if (obs.age_seconds !== null && obs.age_seconds !== undefined) lines.push(`Age: ${formatSecondsShort(obs.age_seconds)} (${obs.age_seconds}s)`);
    if (obs.queued_warn_after_seconds !== null && obs.queued_warn_after_seconds !== undefined) lines.push(`Queued warning threshold: ${obs.queued_warn_after_seconds}s`);
    lines.push(`Old queued: ${obs.is_old_queued ? 'yes' : 'no'}`);
    lines.push('');
    lines.push('--- selector ---');
    lines.push(JSON.stringify(d?.selector || {}, null, 2));
    lines.push('');
    lines.push('--- payload ---');
    lines.push(JSON.stringify(d?.payload || {}, null, 2));
    if (d?.result) {
      lines.push('');
      lines.push('--- result ---');
      lines.push(JSON.stringify(d.result, null, 2));
    }
    lines.push('');
    lines.push(`--- runs (${runs.length}) ---`);
    for (const r of runs) {
      lines.push('');
      lines.push(`Host: ${r.agent_id || 'unknown'}`);
      lines.push(`Status: ${r.status || 'unknown'}`);
      lines.push(`Started: ${r.started_at ? new Date(r.started_at).toLocaleString() : 'n/a'}`);
      lines.push(`Finished: ${r.finished_at ? new Date(r.finished_at).toLocaleString() : 'n/a'}`);
      if (r.running_seconds !== null && r.running_seconds !== undefined) lines.push(`Running seconds: ${r.running_seconds}`);
      if (r.stale_after_seconds !== null && r.stale_after_seconds !== undefined) lines.push(`Stale threshold: ${r.stale_after_seconds}s`);
      lines.push(`Stale: ${r.is_stale ? 'yes' : 'no'}`);
      lines.push(`Retries: ${Number(r.retry_count || 0)}`);
      if (r.exit_code !== null && r.exit_code !== undefined) lines.push(`Exit: ${r.exit_code}`);
      if (r.error) lines.push(`Error: ${r.error}`);
      const stdoutText = r.stdout || r.stdout_tail;
      if (stdoutText) {
        lines.push('');
        lines.push(r.stdout_tail_truncated ? 'stdout tail (truncated):' : 'stdout:');
        lines.push(String(stdoutText));
      }
      if (r.stderr_tail) {
        lines.push('');
        lines.push(r.stderr_tail_truncated ? 'stderr tail (truncated):' : 'stderr:');
        lines.push(String(r.stderr_tail));
      }
    }
    return lines.join('\n');
  }

  async function openJobDetailModal(ctx, jobId) {
    const modal = document.getElementById('job-detail-modal');
    const titleEl = document.getElementById('job-detail-modal-title');
    const metaEl = document.getElementById('job-detail-modal-meta');
    const outEl = document.getElementById('job-detail-modal-output');
    if (!modal || !outEl || !jobId) return;
    if (titleEl) titleEl.textContent = 'Job details';
    if (metaEl) metaEl.textContent = jobId;
    outEl.value = 'Loading…';
    modal.hidden = false;
    modal.setAttribute('aria-hidden', 'false');
    modal.classList.add('open');
    try {
      const r = await fetch(`/jobs/${encodeURIComponent(jobId)}`, { credentials: 'include' });
      if (!r.ok) throw new Error(`job detail fetch failed (${r.status})`);
      const d = await r.json();
      if (titleEl) titleEl.textContent = `${d?.type || 'Job'} details`;
      if (metaEl) metaEl.textContent = d?.job_id || jobId;
      outEl.value = formatJobDetailText(d);
      setTimeout(() => { try { outEl.focus(); } catch { } }, 0);
    } catch (e) {
      outEl.value = e.message || String(e);
      ctx.showToast(e.message || String(e), 'error');
    }
  }

  async function cancelQueuedJob(ctx, jobId) {
    if (!jobId) return;
    const ok = window.confirm(`Cancel queued job ${jobId}? Running hosts will not be stopped.`);
    if (!ok) return;
    try {
      const r = await fetch(`/jobs/${encodeURIComponent(jobId)}/cancel`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'X-CSRF-Token': (ctx.getCookie('fleet_csrf') || '') },
      });
      if (!r.ok) throw new Error(`cancel failed (${r.status})`);
      const d = await r.json();
      ctx.showToast(`Cancelled ${d?.cancelled_runs || 0} queued run(s)`, 'success');
      await loadQueueHealth(ctx, false);
    } catch (e) {
      ctx.showToast(e.message || String(e), 'error');
    }
  }

  async function cancelVisibleOldQueuedJobs(ctx) {
    const ids = Array.from(document.querySelectorAll('#overview-queue-health tr[data-old-queued-job-id]'))
      .map((row) => row.getAttribute('data-old-queued-job-id') || '')
      .filter(Boolean);
    const uniqueIds = Array.from(new Set(ids));
    if (!uniqueIds.length) {
      ctx.showToast('No old queued jobs visible on this page', 'info');
      return;
    }
    const ok = window.confirm(`Cancel ${uniqueIds.length} visible old queued job(s)? Running hosts will not be stopped.`);
    if (!ok) return;

    let cancelled = 0;
    let failed = 0;
    for (const id of uniqueIds) {
      try {
        const r = await fetch(`/jobs/${encodeURIComponent(id)}/cancel`, {
          method: 'POST',
          credentials: 'include',
          headers: { 'X-CSRF-Token': (ctx.getCookie('fleet_csrf') || '') },
        });
        if (!r.ok) throw new Error(`cancel failed (${r.status})`);
        const d = await r.json();
        cancelled += Number(d?.cancelled_runs || 0);
      } catch {
        failed += 1;
      }
    }
    ctx.showToast(`Cancelled ${cancelled} queued run(s)${failed ? `, ${failed} job(s) failed` : ''}`, failed ? 'error' : 'success');
    await loadQueueHealth(ctx, false);
  }

  function initJobDetailModalControls(ctx) {
    const modal = document.getElementById('job-detail-modal');
    const closeBtn = document.getElementById('job-detail-modal-close');
    const copyBtn = document.getElementById('job-detail-modal-copy');
    const outEl = document.getElementById('job-detail-modal-output');
    if (!modal || !outEl) return;

    const close = () => {
      modal.classList.remove('open');
      modal.setAttribute('aria-hidden', 'true');
      modal.hidden = true;
    };

    closeBtn?.addEventListener('click', (e) => { e.preventDefault(); close(); });
    modal.addEventListener('click', (e) => { if (e.target && e.target.id === 'job-detail-modal') close(); });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && modal.classList.contains('open')) close(); });

    copyBtn?.addEventListener('click', async (e) => {
      e.preventDefault();
      const ok = await ctx.copyTextWithFallback(outEl.value || '', outEl);
      if (ok) {
        ctx.showToast('Copied', 'success');
      } else {
        ctx.showToast('Copy failed (clipboard blocked). Text selected—press Ctrl/Cmd+C.', 'error', 5000);
      }
    });

    window.openJobDetailModal = (jobId) => openJobDetailModal(ctx, jobId);
  }

  window.fleetJobsUi = {
    loadQueueHealth,
    resetQueueHealthPagination,
    moveQueueHealthPage,
    formatSecondsShort,
    formatJobDetailText,
    openJobDetailModal,
    cancelQueuedJob,
    cancelVisibleOldQueuedJobs,
    initJobDetailModalControls,
  };
})();

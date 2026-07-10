import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('failed runs copyability UI', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const appPath = path.join(root, 'server/app/templates/fleet-app.js');
  const jobsPath = path.join(root, 'server/app/templates/fleet-jobs-ui.js');
  const html = fs.readFileSync(indexPath, 'utf8');
  const app = fs.readFileSync(appPath, 'utf8');
  const jobs = fs.readFileSync(jobsPath, 'utf8');
  const src = `${html}\n${app}\n${jobs}`;

  it('includes failed runs copy affordances and detail modal', () => {
    expect(src).toContain('id="failed-runs-copy-visible"');
    expect(src).toContain('data-copy-failed-run');
    expect(src).toContain('id="failed-run-detail-modal"');
    expect(src).toContain('id="failed-run-detail-modal-copy"');
    expect(src).toContain('retried ${retryCount}x');
    expect(src).toContain('cancelled before agent claim');
    expect(src).toContain('Cancelled: yes');
  });

  it('uses failed run detail modal instead of alert for row details', () => {
    expect(src).toContain('window.openFailedRunDetailModal');
    expect(src).not.toContain('alert(detail);');
  });

  it('includes queue health dashboard controls backed by jobs API metadata', () => {
    expect(src).toContain('id="queue-health-card"');
    expect(src).toContain('id="overview-queue-health"');
    expect(src).toContain('id="queue-health-refresh"');
    expect(src).toContain('id="queue-health-type"');
    expect(src).toContain('id="queue-health-agent"');
    expect(src).toContain('id="queue-health-owner"');
    expect(src).toContain('id="queue-health-limit"');
    expect(src).toContain('id="queue-health-prev"');
    expect(src).toContain('id="queue-health-next"');
    expect(src).toContain('id="queue-health-cancel-old"');
    expect(src).toContain('id="job-detail-modal"');
    expect(src).toContain('data-job-detail');
    expect(src).toContain('data-job-cancel');
    expect(src).toContain('data-old-queued-job-id');
    expect(src).toContain('async function cancelQueuedJob');
    expect(src).toContain('async function cancelVisibleOldQueuedJobs');
    expect(src).toContain('/cancel`');
    expect(src).toContain("'X-CSRF-Token': (ctx.getCookie('fleet_csrf') || '')");
    expect(src).toContain('async function loadQueueHealth');
    expect(src).toContain('resetQueueHealthPagination');
    expect(src).toContain('moveQueueHealthPage');
    expect(src).toContain('async function openJobDetailModal');
    expect(src).toContain('formatJobDetailText');
    expect(src).toContain('formatSecondsShort');
    expect(src).toContain("new URLSearchParams({ limit: String(limit), offset: String(offset) })");
    expect(src).toContain("qs.set('agent_id', agentId)");
    expect(src).toContain("qs.set('created_by', owner)");
    expect(src).toContain('fetch(`/jobs/${encodeURIComponent(jobId)}`');
    expect(src).toContain('old queued');
    expect(src).toContain('is_old_queued');
    expect(src).toContain('queued_warn_after_seconds');
    expect(src).toContain('stdout_tail');
    expect(src).toContain('stderr_tail');
    expect(src).toContain('stderr tail (truncated)');
    expect(src).toContain('isCancelledJob');
    expect(src).toContain('displayStatus');
    expect(src).toContain('cancelledCount');
    expect(src).toContain('retry_count_max');
    expect(src).toContain('stale_running');
  });
});

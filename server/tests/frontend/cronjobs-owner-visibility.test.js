import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('automation cronjobs owner visibility UI', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const htmlPath = path.join(root, 'server/app/templates/index.html');
  const appPath = path.join(root, 'server/app/templates/fleet-cronjobs-ui.js');
  const fleetAppPath = path.join(root, 'server/app/templates/fleet-app.js');
  const html = fs.readFileSync(htmlPath, 'utf8');
  const app = fs.readFileSync(appPath, 'utf8');
  const fleetApp = fs.readFileSync(fleetAppPath, 'utf8');

  it('shows an Owner column in the cronjobs table', () => {
    expect(html).toContain('<th>Owner</th>');
    expect(app).toContain('const owner = String(it.owner_username || \'\').trim();');
    expect(app).toContain('<td>${owner ? `<code>${ctx.escapeHtml(owner)}</code>` : \'<span class="status-muted">—</span>\'}</td>');
  });

  it('shows explicit schedule timezone, creation time, and lifecycle history', () => {
    expect(html).toContain('<th>Created</th>');
    expect(html).toContain('id="cron-timezone-hint"');
    expect(app).toContain('function scheduleLabel(item)');
    expect(app).toContain('data-history-id=');
    expect(app).toContain('/audit`');
  });

  it('loads cronjobs during module initialization instead of relying only on tab navigation', () => {
    expect(app).toContain('void loadCronjobs(ctx);');
    expect(html).toContain('<tbody id="cronjobs-table">\n                  <tr><td colspan="8"');
  });

  it('owns host picker wiring instead of depending on a different UI bundle', () => {
    expect(app).toContain('function setupCronHostPickerControlsLocal(ctx)');
    expect(app).toContain("document.getElementById('cron-hosts-open')?.addEventListener('click'");
    expect(app).not.toContain('setupCronHostPickerControls({');
  });

  it('provides blast-radius preflight in the scope used by cronjobs context', () => {
    const helperIndex = fleetApp.indexOf('async function confirmBlastRadius(');
    const contextIndex = fleetApp.indexOf('function getCronjobsCtx()');
    expect(helperIndex).toBeGreaterThan(-1);
    expect(contextIndex).toBeGreaterThan(helperIndex);
  });
});

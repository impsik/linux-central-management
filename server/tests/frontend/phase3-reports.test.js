import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('phase3 reports controls wiring', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const reportsModulePath = path.join(root, 'server/app/templates/fleet-phase3-reports.js');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const reportsSrc = fs.readFileSync(reportsModulePath, 'utf8');
  const indexSrc = fs.readFileSync(indexPath, 'utf8');

  it('loads reports controls from a dedicated module instead of inline shell helper', () => {
    expect(indexSrc).toContain('/assets/fleet-phase3-reports.js');
    expect(indexSrc).not.toContain('function initReportsControls()');
  });

  it('binds the user-presence report opener in the reports module', () => {
    expect(reportsSrc).toContain("document.getElementById('reports-user-presence-open')");
    expect(reportsSrc).toContain("btn.dataset.boundReportsControls === '1'");
    expect(reportsSrc).toContain("window.open(`/reports/user-presence.html?${qs}`, '_blank', 'noopener')");
  });
});

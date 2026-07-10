import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('reports split', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const appPath = path.join(root, 'server/app/templates/fleet-app.js');
  const reportsPath = path.join(root, 'server/app/templates/fleet-reports-ui.js');
  const app = fs.readFileSync(appPath, 'utf8');
  const reports = fs.readFileSync(reportsPath, 'utf8');

  it('keeps reports UI behavior in its own asset', () => {
    expect(app).toContain('window.fleetReportsUi');
    expect(reports).toContain('function initReportsControls(ctx)');
    expect(reports).toContain('/reports/cve-high-severity');
    expect(reports).toContain('/reports/user-presence.html');
    expect(reports).toContain('loadHighSeverityCveReport');
  });
});

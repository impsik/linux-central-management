import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('service management split', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const appPath = path.join(root, 'server/app/templates/fleet-app.js');
  const serviceManagementPath = path.join(root, 'server/app/templates/fleet-service-management-ui.js');
  const app = fs.readFileSync(appPath, 'utf8');
  const serviceManagement = fs.readFileSync(serviceManagementPath, 'utf8');

  it('keeps service-management workflow behavior in its own asset', () => {
    expect(app).toContain('window.fleetServiceManagementUi');
    expect(serviceManagement).toContain('function initServiceManagementControls(ctx)');
    expect(serviceManagement).toContain('/reports/service-presence');
    expect(serviceManagement).toContain("ctx.getCurrentPermissions()");
    expect(serviceManagement).toContain("void runServiceOperation('start')");
    expect(serviceManagement).toContain("void runServiceOperation('enable')");
  });
});

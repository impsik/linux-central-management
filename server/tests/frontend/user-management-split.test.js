import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('user management split', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const appPath = path.join(root, 'server/app/templates/fleet-app.js');
  const userManagementPath = path.join(root, 'server/app/templates/fleet-user-management-ui.js');
  const app = fs.readFileSync(appPath, 'utf8');
  const userManagement = fs.readFileSync(userManagementPath, 'utf8');

  it('keeps user-management workflow behavior in its own asset', () => {
    expect(app).toContain('window.fleetUserManagementUi');
    expect(userManagement).toContain('function initUserManagementControls(ctx)');
    expect(userManagement).toContain('/reports/user-presence');
    expect(userManagement).toContain("ctx.getCurrentPermissions()");
    expect(userManagement).toContain("void runUserAction('lock')");
    expect(userManagement).toContain("void runUserAction('unlock')");
  });
});

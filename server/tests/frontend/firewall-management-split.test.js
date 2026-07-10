import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('firewall management split', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const appPath = path.join(root, 'server/app/templates/fleet-app.js');
  const firewallManagementPath = path.join(root, 'server/app/templates/fleet-firewall-management-ui.js');
  const app = fs.readFileSync(appPath, 'utf8');
  const firewallManagement = fs.readFileSync(firewallManagementPath, 'utf8');

  it('keeps firewall-management workflow behavior in its own asset', () => {
    expect(app).toContain('window.fleetFirewallManagementUi');
    expect(firewallManagement).toContain('function initFirewallManagementControls(ctx)');
    expect(firewallManagement).toContain('/reports/firewall-rules');
    expect(firewallManagement).toContain("ctx.getCurrentPermissions()");
    expect(firewallManagement).toContain("void runFirewallOperation('allow')");
    expect(firewallManagement).toContain("void runFirewallOperation('delete')");
  });
});

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('index shell split', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const appPath = path.join(root, 'server/app/templates/fleet-app.js');
  const terminalPath = path.join(root, 'server/app/templates/fleet-terminal-ui.js');
  const jobsPath = path.join(root, 'server/app/templates/fleet-jobs-ui.js');
  const cronjobsPath = path.join(root, 'server/app/templates/fleet-cronjobs-ui.js');
  const userManagementPath = path.join(root, 'server/app/templates/fleet-user-management-ui.js');
  const serviceManagementPath = path.join(root, 'server/app/templates/fleet-service-management-ui.js');
  const firewallManagementPath = path.join(root, 'server/app/templates/fleet-firewall-management-ui.js');
  const reportsPath = path.join(root, 'server/app/templates/fleet-reports-ui.js');
  const adminPath = path.join(root, 'server/app/templates/fleet-admin-ui.js');
  const failedRunsPath = path.join(root, 'server/app/templates/fleet-failed-runs-ui.js');
  const html = fs.readFileSync(indexPath, 'utf8');
  const app = fs.readFileSync(appPath, 'utf8');
  const terminal = fs.readFileSync(terminalPath, 'utf8');
  const jobs = fs.readFileSync(jobsPath, 'utf8');
  const cronjobs = fs.readFileSync(cronjobsPath, 'utf8');
  const userManagement = fs.readFileSync(userManagementPath, 'utf8');
  const serviceManagement = fs.readFileSync(serviceManagementPath, 'utf8');
  const firewallManagement = fs.readFileSync(firewallManagementPath, 'utf8');
  const reports = fs.readFileSync(reportsPath, 'utf8');
  const admin = fs.readFileSync(adminPath, 'utf8');
  const failedRuns = fs.readFileSync(failedRunsPath, 'utf8');

  it('loads the main dashboard behavior from a separate cacheable asset', () => {
    expect(html).toContain('<script src="/assets/fleet-app.js?v=__ASSET_VERSION__"></script>');
    expect(html).toContain('<script src="/assets/fleet-terminal-ui.js?v=__ASSET_VERSION__"></script>');
    expect(html).toContain('<script src="/assets/fleet-jobs-ui.js?v=__ASSET_VERSION__"></script>');
    expect(html).toContain('<script src="/assets/fleet-cronjobs-ui.js?v=__ASSET_VERSION__"></script>');
    expect(html).toContain('<script src="/assets/fleet-user-management-ui.js?v=__ASSET_VERSION__"></script>');
    expect(html).toContain('<script src="/assets/fleet-service-management-ui.js?v=__ASSET_VERSION__"></script>');
    expect(html).toContain('<script src="/assets/fleet-firewall-management-ui.js?v=__ASSET_VERSION__"></script>');
    expect(html).toContain('<script src="/assets/fleet-reports-ui.js?v=__ASSET_VERSION__"></script>');
    expect(html).toContain('<script src="/assets/fleet-admin-ui.js?v=__ASSET_VERSION__"></script>');
    expect(html).toContain('<script src="/assets/fleet-failed-runs-ui.js?v=__ASSET_VERSION__"></script>');
    expect(app).toContain('bootUi().catch');
    expect(terminal).toContain('window.fleetTerminalUi');
    expect(jobs).toContain('window.fleetJobsUi');
    expect(cronjobs).toContain('window.fleetCronjobsUi');
    expect(userManagement).toContain('window.fleetUserManagementUi');
    expect(serviceManagement).toContain('window.fleetServiceManagementUi');
    expect(firewallManagement).toContain('window.fleetFirewallManagementUi');
    expect(reports).toContain('window.fleetReportsUi');
    expect(admin).toContain('window.fleetAdminUi');
    expect(failedRuns).toContain('window.fleetFailedRunsUi');
  });

  it('keeps index.html as a lighter shell instead of a large inline script bundle', () => {
    expect(Buffer.byteLength(html, 'utf8')).toBeLessThan(140_000);
    expect(html).not.toContain('<script nonce="__CSP_NONCE__">');
  });
});

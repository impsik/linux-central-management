import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('index shell integrity', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const src = fs.readFileSync(path.join(root, 'server/app/templates/index.html'), 'utf8');
  const headerPartial = fs.readFileSync(path.join(root, 'server/app/templates/partials/header-shell.html'), 'utf8');
  const adminPartial = fs.readFileSync(path.join(root, 'server/app/templates/partials/admin-panel.html'), 'utf8');
  const hostInventoryPartial = fs.readFileSync(path.join(root, 'server/app/templates/partials/host-inventory.html'), 'utf8');
  const reportsPartial = fs.readFileSync(path.join(root, 'server/app/templates/partials/reports-panel.html'), 'utf8');
  const cronjobsPartial = fs.readFileSync(path.join(root, 'server/app/templates/partials/cronjobs-panel.html'), 'utf8');
  const sshkeysPartial = fs.readFileSync(path.join(root, 'server/app/templates/partials/sshkeys-panel.html'), 'utf8');
  const modalsPartial = fs.readFileSync(path.join(root, 'server/app/templates/partials/modals.html'), 'utf8');
  const packagesPartial = fs.readFileSync(path.join(root, 'server/app/templates/partials/packages-tab.html'), 'utf8');
  const servicesPartial = fs.readFileSync(path.join(root, 'server/app/templates/partials/services-tab.html'), 'utf8');
  const usersPartial = fs.readFileSync(path.join(root, 'server/app/templates/partials/users-tab.html'), 'utf8');
  const terminalPartial = fs.readFileSync(path.join(root, 'server/app/templates/partials/terminal-tab.html'), 'utf8');

  it('ends with expected closing tags', () => {
    const trimmed = src.trim();
    expect(trimmed.endsWith('</html>')).toBe(true);
    expect(trimmed.includes('</body>')).toBe(true);
    expect(trimmed.includes('</script>')).toBe(true);
  });

  it('contains boot-critical markers and extracted partials', () => {
    expect(src).toContain('__PARTIAL_HEADER_SHELL__');
    expect(src).toContain('__PARTIAL_ADMIN_PANEL__');
    expect(src).toContain('__PARTIAL_HOST_INVENTORY__');
    expect(src).toContain('__PARTIAL_REPORTS_PANEL__');
    expect(src).toContain('__PARTIAL_CRONJOBS_PANEL__');
    expect(src).toContain('__PARTIAL_SSHKEYS_PANEL__');
    expect(src).toContain('__PARTIAL_MODALS__');
    expect(src).toContain('__PARTIAL_PACKAGES_TAB__');
    expect(src).toContain('__PARTIAL_SERVICES_TAB__');
    expect(src).toContain('__PARTIAL_USERS_TAB__');
    expect(src).toContain('__PARTIAL_TERMINAL_TAB__');
    expect(src).toContain('id="nav-overview"');
    expect(src).toContain('safeInit(');
    expect(src).toContain('bootPhase3AppShell()');
    expect(src).toContain('/assets/fleet-phase3-contexts.js');
    expect(src).toContain('/assets/fleet-phase3-reports.js');

    expect(headerPartial).toContain('id="settings-btn"');
    expect(headerPartial).toContain('id="current-user"');
    expect(headerPartial).toContain('id="change-password-menu-item"');
    expect(adminPartial).toContain('id="admin-tab"');
    expect(adminPartial).toContain('id="admin-users-table"');
    expect(adminPartial).toContain('id="admin-audit-table"');
    expect(hostInventoryPartial).toContain('id="hosts-table-tab"');
    expect(hostInventoryPartial).toContain('id="host-search"');
    expect(hostInventoryPartial).toContain('id="hosts-table-body"');
    expect(reportsPartial).toContain('id="reports-tab"');
    expect(reportsPartial).toContain('id="reports-user-presence-open"');
    expect(cronjobsPartial).toContain('id="cronjobs-tab"');
    expect(cronjobsPartial).toContain('id="cron-create"');
    expect(cronjobsPartial).toContain('id="cronjobs-table"');
    expect(sshkeysPartial).toContain('id="sshkeys-tab"');
    expect(sshkeysPartial).toContain('id="sshkey-refresh"');
    expect(sshkeysPartial).toContain('id="sshkey-admin-table"');
    expect(modalsPartial).toContain('id="ansible-modal"');
    expect(modalsPartial).toContain('id="audit-detail-modal"');
    expect(modalsPartial).toContain('id="toast-container"');
    expect(packagesPartial).toContain('id="packages-tab"');
    expect(packagesPartial).toContain('id="packages-search"');
    expect(packagesPartial).toContain('id="packages-list"');
    expect(servicesPartial).toContain('id="services-tab"');
    expect(servicesPartial).toContain('id="services-list"');
    expect(usersPartial).toContain('id="users-tab"');
    expect(usersPartial).toContain('id="users-list"');
    expect(terminalPartial).toContain('id="terminal-tab"');
    expect(terminalPartial).toContain('id="terminal-run-pending-cmd"');
    expect(terminalPartial).toContain('id="terminal"');
  });
});

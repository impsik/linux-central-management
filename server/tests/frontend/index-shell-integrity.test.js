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
    expect(src).toContain('id="nav-overview"');
    expect(src).toContain('safeInit(');
    expect(src).toContain('bootPhase3AppShell()');

    expect(headerPartial).toContain('id="settings-btn"');
    expect(headerPartial).toContain('id="current-user"');
    expect(adminPartial).toContain('id="admin-tab"');
    expect(adminPartial).toContain('id="admin-users-table"');
    expect(adminPartial).toContain('id="admin-audit-table"');
    expect(hostInventoryPartial).toContain('id="hosts-table-tab"');
    expect(hostInventoryPartial).toContain('id="host-search"');
    expect(hostInventoryPartial).toContain('id="hosts-table-body"');
    expect(reportsPartial).toContain('id="reports-tab"');
    expect(reportsPartial).toContain('id="reports-user-presence-open"');
  });
});

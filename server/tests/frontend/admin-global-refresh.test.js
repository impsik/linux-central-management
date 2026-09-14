import { it, expect, vi } from 'vitest';
import fs from 'node:fs';
import vm from 'node:vm';

it('refreshes Admin users and audit through browser-global hooks without recursion', async () => {
  const app = fs.readFileSync(new URL('../../app/templates/fleet-app.js', import.meta.url), 'utf8');
  const admin = fs.readFileSync(new URL('../../app/templates/fleet-admin-ui.js', import.meta.url), 'utf8');
  const tables = { 'admin-users-table': {}, 'admin-audit-table': {} };
  const fetch = vi.fn(async () => ({ ok: true, text: async () => '{"items":[]}' }));
  const setTableState = vi.fn();
  const browser = {
    document: { getElementById: id => tables[id] || null },
    fetch, setTableState, URLSearchParams,
    formatShortTime: String, safeJsonPreview: JSON.stringify, escapeHtml: String,
    showToast: vi.fn(), getCookie: () => '', currentPermissions: { role: 'admin' },
    currentUsername: 'admin', adminUsername: 'admin', approvalActionFeedback: {},
  };
  // Classic-script globals and window properties must be the SAME binding.
  browser.window = browser;
  vm.createContext(browser);
  vm.runInContext(admin, browser);
  vm.runInContext(app.slice(app.indexOf('    function getAdminCtx()'), app.indexOf('    function showAdminPage()')), browser);
  await browser.loadAdminUsers();
  await browser.loadAdminAudit();
  expect(fetch.mock.calls.map(([url]) => url)).toEqual(['/auth/admin/users', '/audit?limit=200']);
  expect(setTableState).toHaveBeenCalledWith(tables['admin-users-table'], 8, 'empty', 'No users');
  expect(setTableState).toHaveBeenCalledWith(tables['admin-audit-table'], 6, 'empty', 'No events');
});

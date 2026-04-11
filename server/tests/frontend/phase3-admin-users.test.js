import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('phase3 admin users remove action wiring', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const adminUsersPath = path.join(root, 'server/app/templates/fleet-phase3-admin-users.js');
  const ownerScopeUiPath = path.join(root, 'server/app/templates/fleet-phase3-owner-scope-ui.js');
  const adminUsersSrc = fs.readFileSync(adminUsersPath, 'utf8');
  const ownerScopeUiSrc = fs.readFileSync(ownerScopeUiPath, 'utf8');

  it('renders a base remove button in the admin users table', () => {
    expect(adminUsersSrc).toContain('data-user-remove-enhanced');
    expect(adminUsersSrc).toContain("Permanently remove this user");
    expect(adminUsersSrc).toContain('>Remove</button>');
  });

  it('binds remove handling in the base admin users module and keeps owner-scope enhancement compatible', () => {
    expect(adminUsersSrc).toContain("tbody.querySelectorAll('button[data-user-remove-enhanced]')");
    expect(adminUsersSrc).toContain("fetch(`/auth/users/${encodeURIComponent(uname)}/remove`");
    expect(ownerScopeUiSrc).toContain('function wireRemoveButton(btn, username, tr)');
    expect(ownerScopeUiSrc).toContain('if (existingRemoveBtn) wireRemoveButton(existingRemoveBtn, username, tr);');
  });
});

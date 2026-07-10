import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('admin split', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const appPath = path.join(root, 'server/app/templates/fleet-app.js');
  const adminPath = path.join(root, 'server/app/templates/fleet-admin-ui.js');
  const app = fs.readFileSync(appPath, 'utf8');
  const admin = fs.readFileSync(adminPath, 'utf8');

  it('keeps admin workflows in their own asset while preserving global refresh hooks', () => {
    expect(app).toContain('window.fleetAdminUi');
    expect(app).toContain('window.loadAdminUsers');
    expect(app).toContain('window.loadAdminAudit');
    expect(admin).toContain('function bind(ctx)');
    expect(admin).toContain('async function loadAdminUsers');
    expect(admin).toContain('async function loadAdminApprovals');
    expect(admin).toContain('/auth/admin/users');
    expect(admin).toContain('/approvals/admin/pending');
  });
});

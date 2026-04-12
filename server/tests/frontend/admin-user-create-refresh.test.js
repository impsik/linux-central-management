import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('admin create-user refresh behavior', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const authUiPath = path.join(root, 'server/app/templates/fleet-phase3-auth-ui.js');
  const src = fs.readFileSync(authUiPath, 'utf8');

  it('reloads admin users and audit after successful user creation', () => {
    expect(src).toContain("if (typeof loadAdminUsers === 'function') loadAdminUsers();");
    expect(src).toContain("if (typeof loadAdminAudit === 'function') loadAdminAudit();");
  });
});

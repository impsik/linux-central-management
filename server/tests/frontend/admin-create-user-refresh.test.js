import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('admin create-user refresh behavior', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const filePath = path.join(root, 'server/app/templates/fleet-phase3-auth-ui.js');
  const src = fs.readFileSync(filePath, 'utf8');

  it('refreshes admin users and audit after successful user creation', () => {
    expect(src).toContain("if (typeof window.loadAdminUsers === 'function')");
    expect(src).toContain('await window.loadAdminUsers()');
    expect(src).toContain("if (typeof window.loadAdminAudit === 'function')");
    expect(src).toContain('await window.loadAdminAudit()');
  });
});

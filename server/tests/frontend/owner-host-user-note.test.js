import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('owner host user access note gating', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const authStatePath = path.join(root, 'server/app/templates/fleet-phase3-auth-state.js');
  const src = fs.readFileSync(authStatePath, 'utf8');

  it('hides the users access note when the current user owns the current host', () => {
    expect(src).toContain("const currentHostOwner = String(labels.owner || '').trim();");
    expect(src).toContain("const currentUser = String(window.currentUsername || '').trim();");
    expect(src).toContain('currentUser === currentHostOwner');
    expect(src).toContain('usersAccessNote.style.display = canManageHostUsers ? \'none\' : \'block\';');
  });
});

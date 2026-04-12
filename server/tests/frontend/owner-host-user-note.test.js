import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('owner host user access note gating', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const workflowsPath = path.join(root, 'server/app/templates/fleet-phase3-host-workflows.js');
  const authStatePath = path.join(root, 'server/app/templates/fleet-phase3-auth-state.js');
  const workflowsSrc = fs.readFileSync(workflowsPath, 'utf8');
  const authStateSrc = fs.readFileSync(authStatePath, 'utf8');

  it('controls the users access note from the host workflow after ownership is known', () => {
    expect(workflowsSrc).toContain("const usersAccessNote = document.getElementById('users-access-note');");
    expect(workflowsSrc).toContain("if (usersAccessNote) usersAccessNote.style.display = 'none';");
    expect(workflowsSrc).toContain("if (usersAccessNote) usersAccessNote.style.display = canLockUsers ? 'none' : 'block';");
  });

  it('does not toggle the users access note from auth state anymore', () => {
    expect(authStateSrc).not.toContain("document.getElementById('users-access-note')");
  });
});

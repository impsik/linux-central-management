import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('owner host user controls ui gating', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const workflowsPath = path.join(root, 'server/app/templates/fleet-phase3-host-workflows.js');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const workflowsSrc = fs.readFileSync(workflowsPath, 'utf8');
  const indexSrc = fs.readFileSync(indexPath, 'utf8');

  it('passes current username and current host owner into host workflows ctx', () => {
    expect(indexSrc).toContain('getCurrentUsername: () => currentUsername');
    expect(indexSrc).toContain('getCurrentHostOwner: hostOwnerForCurrentAgent');
  });

  it('allows user lock controls when the current user owns the current host', () => {
    expect(workflowsSrc).toContain('const currentUsername = String(ctx.getCurrentUsername?.() || \'\').trim();');
    expect(workflowsSrc).toContain('const currentHostOwner = String(ctx.getCurrentHostOwner?.() || \'\').trim();');
    expect(workflowsSrc).toContain('currentUsername === currentHostOwner');
  });
});

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('owner host workflow context plumbing', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const contextsPath = path.join(root, 'server/app/templates/fleet-phase3-contexts.js');
  const authStatePath = path.join(root, 'server/app/templates/fleet-phase3-auth-state.js');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const contextsSrc = fs.readFileSync(contextsPath, 'utf8');
  const authStateSrc = fs.readFileSync(authStatePath, 'utf8');
  const indexSrc = fs.readFileSync(indexPath, 'utf8');

  it('preserves username/owner getters in host workflow contexts', () => {
    expect(contextsSrc).toContain('getCurrentUsername: d.getCurrentUsername || (() => \'\')');
    expect(contextsSrc).toContain('getCurrentHostOwner: d.getCurrentHostOwner || (() => \'\')');
  });

  it('syncs window globals used by owner-aware auth/ui notes', () => {
    expect(authStateSrc).toContain('window.currentUsername = currentUsername;');
    expect(indexSrc).toContain('window.allHosts = allHosts;');
    expect(indexSrc).toContain('window.currentAgentId = currentAgentId;');
  });
});

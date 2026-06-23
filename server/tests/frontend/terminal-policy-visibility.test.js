import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('terminal policy visibility', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');

  it('shows terminal access policy next to the Console action', () => {
    const src = fs.readFileSync(path.join(root, 'server/app/templates/index.html'), 'utf8');

    expect(src).toContain('id="host-terminal-policy"');
    expect(src).toContain('updateTerminalAccessIndicator(hostObj');
    expect(src).toContain('updateTerminalAccessIndicator(updatedHost');
  });

  it('maps terminal_access labels into operator-visible policy states', () => {
    const src = fs.readFileSync(path.join(root, 'server/app/templates/fleet-phase3-host-actions.js'), 'utf8');

    expect(src).toContain('function terminalAccessPolicy(host)');
    expect(src).toContain("labels.terminal_access || 'all'");
    expect(src).toContain('Terminal: operators allowed');
    expect(src).toContain('Terminal: admins only');
    expect(src).toContain('Terminal: restricted');
    expect(src).toContain("role === 'operator' && policy.operatorBlocked");
  });
});

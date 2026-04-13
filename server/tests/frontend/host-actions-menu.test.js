import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('hosts row actions menu', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const overviewPath = path.join(root, 'server/app/templates/fleet-phase3-overview.js');
  const src = fs.readFileSync(overviewPath, 'utf8');

  it('renders a real host actions menu trigger in the hosts table actions cell', () => {
    expect(src).toContain('host-actions-toggle');
    expect(src).toContain('host-actions-menu');
    expect(src).toContain('Actions ▾');
  });

  it('includes reboot and install-updates-reboot-if-required actions in the host menu', () => {
    expect(src).toContain('host-reboot-action');
    expect(src).toContain('host-upgrade-reboot-action');
    expect(src).toContain('Install updates + reboot if required');
  });
});

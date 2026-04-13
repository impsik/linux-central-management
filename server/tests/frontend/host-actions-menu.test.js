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
    expect(src).toContain('aria-haspopup="menu" aria-expanded="false"');
  });

  it('includes reboot, security-install, update, check-updates, refresh-inventory, and remove actions in the host menu', () => {
    expect(src).toContain('host-reboot-action');
    expect(src).toContain('host-actions-section-label');
    expect(src).toContain('Observe');
    expect(src).toContain('Remediate');
    expect(src).toContain('Destructive');
    expect(src).toContain('host-security-updates-action');
    expect(src).toContain('host-upgrade-reboot-action');
    expect(src).toContain('host-check-updates-action');
    expect(src).toContain('host-refresh-inventory-action');
    expect(src).toContain('host-remove-action');
    expect(src).toContain('Install security updates');
    expect(src).toContain('Install updates + reboot if required');
    expect(src).toContain('Check updates');
    expect(src).toContain('Refresh inventory');
    expect(src).toContain('Remove host');
  });

  it('does not defeat hidden menu state with inline display grid and explicitly toggles display in JS', () => {
    expect(src).not.toContain('class="host-actions-menu" hidden style="position:absolute;right:0;top:calc(100% + 4px);min-width:260px;background:var(--panel);border:1px solid var(--border);border-radius:10px;box-shadow:0 10px 30px rgba(0,0,0,.25);padding:0.35rem;z-index:30;display:grid;gap:0.25rem;"');
    expect(src).toContain("actionsMenu.style.display = 'grid';");
    expect(src).toContain("actionsMenu.style.display = 'none';");
  });
});

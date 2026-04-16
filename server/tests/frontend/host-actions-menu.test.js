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

  it('includes only full-upgrade, reboot, and remove actions in the host menu', () => {
    expect(src).toContain('host-reboot-action');
    expect(src).toContain('host-upgrade-reboot-action');
    expect(src).toContain('host-remove-action');
    expect(src).toContain('Install all updates and reboot');
    expect(src).toContain('Reboot');
    expect(src).toContain('Remove host');

    expect(src).not.toContain('host-security-updates-action');
    expect(src).not.toContain('host-check-updates-action');
    expect(src).not.toContain('host-refresh-inventory-action');
    expect(src).not.toContain('Install security updates');
    expect(src).not.toContain('Check updates');
    expect(src).not.toContain('Refresh inventory');
  });

  it('routes the host full-upgrade action through dist-upgrade and separately queues reboot', () => {
    const marker = "const upgradeRebootBtn = tr.querySelector('.host-upgrade-reboot-action');";
    const start = src.indexOf(marker);
    expect(start).toBeGreaterThanOrEqual(0);
    const section = src.slice(start, start + 4200);

    expect(section).toContain("body: JSON.stringify({ action: 'dist-upgrade', agent_ids: [agentId] })");
    expect(section).toContain("await fetch('/jobs/dist-upgrade'");
    expect(section).toContain("await fetch(`/hosts/${encodeURIComponent(agentId)}/reboot`");
    expect(section).not.toContain("await fetch('/patching/campaigns/security-updates'");
  });

  it('opens the actions menu with explicit JS positioning instead of relying on clipped in-row absolute layout', () => {
    expect(src).not.toContain('class="host-actions-menu" hidden style="position:absolute;right:0;top:calc(100% + 4px);min-width:260px;background:var(--panel);border:1px solid var(--border);border-radius:10px;box-shadow:0 10px 30px rgba(0,0,0,.25);padding:0.35rem;z-index:30;display:grid;gap:0.25rem;"');
    expect(src).toContain("actionsMenu.style.display = 'grid';");
    expect(src).toContain("actionsMenu.style.display = 'none';");
    expect(src).toContain("actionsMenu.style.position = 'fixed';");
    expect(src).toContain("actionsMenu.style.left = `${left}px`;");
    expect(src).toContain("actionsMenu.style.top = `${Math.min(rect.bottom + 4, viewportHeight - 40)}px`;");
  });
});

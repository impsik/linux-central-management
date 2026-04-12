import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('maintenance window preview ui', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const overviewPath = path.join(root, 'server/app/templates/fleet-phase3-overview.js');
  const src = fs.readFileSync(overviewPath, 'utf8');

  it('refreshes risky action buttons from scoped maintenance-window evaluation', () => {
    expect(src).toContain("fetch('/maintenance-windows/evaluate'");
    expect(src).toContain("action: 'security-campaign'");
    expect(src).toContain("action: 'dist-upgrade'");
    expect(src).toContain("body: JSON.stringify({ action: entry.action, agent_ids: agentIds })");
  });

  it('falls back to the global dashboard maintenance status if scoped preview is unavailable', () => {
    expect(src).toContain("fetch('/dashboard/maintenance-window', { credentials: 'include' })");
    expect(src).toContain("Blocked outside maintenance window");
  });
});

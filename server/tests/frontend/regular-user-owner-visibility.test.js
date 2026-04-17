import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('regular-user owner visibility guards', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const hostListPath = path.join(root, 'server/app/templates/fleet-phase3-host-list.js');
  const overviewPath = path.join(root, 'server/app/templates/fleet-phase3-overview.js');
  const hostListSrc = fs.readFileSync(hostListPath, 'utf8');
  const overviewSrc = fs.readFileSync(overviewPath, 'utf8');

  it('clears stale current host selection when the sidebar host list no longer contains it', () => {
    expect(hostListSrc).toContain("if (currentAgentId && !list.some((h) => String(h?.agent_id || '') === String(currentAgentId))) {");
    expect(hostListSrc).toContain("if (typeof ctx.clearCurrentHostSelection === 'function') ctx.clearCurrentHostSelection();");
  });

  it('clears stale current host selection when the hosts table result set no longer contains it', () => {
    expect(overviewSrc).toContain("if (currentAgentId && !hostsTableItemsCache.some((it) => String(it?.agent_id || '') === String(currentAgentId))) {");
    expect(overviewSrc).toContain("if (ctx && typeof ctx.clearCurrentHostSelection === 'function') ctx.clearCurrentHostSelection();");
  });
});

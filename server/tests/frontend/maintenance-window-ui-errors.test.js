import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('maintenance window ui error surfacing', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const overviewPath = path.join(root, 'server/app/templates/fleet-phase3-overview.js');
  const src = fs.readFileSync(overviewPath, 'utf8');

  it('formats structured maintenance-window blocks with matched window names', () => {
    expect(src).toContain('function formatMaintenanceWindowBlockMessage(payload, fallback)');
    expect(src).toContain('data.matched_windows');
    expect(src).toContain('return `${detail} [${preview}${suffix}]`;');
  });

  it('uses the maintenance-window formatter for security campaign and dist-upgrade failures', () => {
    expect(src).toContain("let msg = 'Campaign creation failed';");
    expect(src).toContain("let msg = 'dist-upgrade job creation failed';");
    expect(src.match(/formatMaintenanceWindowBlockMessage\(j, msg\)/g)?.length || 0).toBeGreaterThanOrEqual(2);
  });
});

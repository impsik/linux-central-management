import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('phase3 overview bridge extraction', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const modulePath = path.join(root, 'server/app/templates/fleet-phase3-overview-bridges.js');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const moduleSrc = fs.readFileSync(modulePath, 'utf8');
  const indexSrc = fs.readFileSync(indexPath, 'utf8');

  it('loads overview bridge helpers from a dedicated module', () => {
    expect(indexSrc).toContain('/assets/fleet-phase3-overview-bridges.js');
    expect(indexSrc).toContain('function getOverviewBridgeCtx()');
    expect(indexSrc).toContain('window.phase3OverviewBridges');
  });

  it('defines overview ctx/load bridge helpers in the module', () => {
    expect(moduleSrc).toContain('function getOverviewCtx(ctx)');
    expect(moduleSrc).toContain('function loadFleetOverview(ctx, forceLive = false)');
    expect(moduleSrc).toContain('function loadPendingUpdatesReport(ctx, showToastOnManual = false)');
    expect(moduleSrc).toContain('w.phase3OverviewBridges = {');
  });
});

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('phase3 host history extraction', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const modulePath = path.join(root, 'server/app/templates/fleet-phase3-host-history.js');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const moduleSrc = fs.readFileSync(modulePath, 'utf8');
  const indexSrc = fs.readFileSync(indexPath, 'utf8');

  it('loads host history helpers from a dedicated module', () => {
    expect(indexSrc).toContain('/assets/fleet-phase3-host-history.js');
    expect(indexSrc).toContain('function getHostHistoryCtx()');
    expect(indexSrc).toContain('window.phase3HostHistory');
  });

  it('defines timeline and drift helpers in the extracted module', () => {
    expect(moduleSrc).toContain('function timelineJobCategory(ctx, it)');
    expect(moduleSrc).toContain('function timelineFilterMatch(ctx, it)');
    expect(moduleSrc).toContain('function timelineJobEffect(ctx, it)');
    expect(moduleSrc).toContain('function renderHostTimeline(ctx)');
    expect(moduleSrc).toContain('function hostTimelineFilteredItems(ctx)');
    expect(moduleSrc).toContain('function downloadHostTimeline(ctx, kind)');
    expect(moduleSrc).toContain('function renderHostDriftChecks(ctx)');
    expect(moduleSrc).toContain('function initTimelineFilters(ctx)');
    expect(moduleSrc).toContain('w.phase3HostHistory = {');
  });
});

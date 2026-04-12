import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('phase3 host list bridge extraction', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const modulePath = path.join(root, 'server/app/templates/fleet-phase3-host-list-bridges.js');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const moduleSrc = fs.readFileSync(modulePath, 'utf8');
  const indexSrc = fs.readFileSync(indexPath, 'utf8');

  it('loads host list bridge helpers from a dedicated module', () => {
    expect(indexSrc).toContain('/assets/fleet-phase3-host-list-bridges.js');
    expect(indexSrc).toContain('function getHostListBridgeCtx()');
    expect(indexSrc).toContain('window.phase3HostListBridges');
  });

  it('defines host list ctx/load/filter bridge helpers in the module', () => {
    expect(moduleSrc).toContain('function getHostListCtx(ctx)');
    expect(moduleSrc).toContain('function rebuildLabelFilterOptions(ctx, hosts)');
    expect(moduleSrc).toContain('function applyHostFilters(ctx)');
    expect(moduleSrc).toContain('async function loadHosts(ctx)');
    expect(moduleSrc).toContain('w.phase3HostListBridges = {');
  });
});

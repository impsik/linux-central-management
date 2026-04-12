import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('phase3 host view switching extraction', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const modulePath = path.join(root, 'server/app/templates/fleet-phase3-host-view-switching.js');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const moduleSrc = fs.readFileSync(modulePath, 'utf8');
  const indexSrc = fs.readFileSync(indexPath, 'utf8');

  it('loads host view switching helpers from a dedicated module', () => {
    expect(indexSrc).toContain('/assets/fleet-phase3-host-view-switching.js');
    expect(indexSrc).toContain('function getHostViewSwitchingCtx()');
    expect(indexSrc).toContain("window.phase3HostViewSwitching");
  });

  it('keeps show* implementations in the extracted module', () => {
    expect(moduleSrc).toContain('function showTerminal(ctx)');
    expect(moduleSrc).toContain('function showUsers(ctx)');
    expect(moduleSrc).toContain('function showServices(ctx)');
    expect(moduleSrc).toContain('function showPackages(ctx)');
    expect(moduleSrc).toContain('function showServerInfo(ctx)');
    expect(moduleSrc).toContain("w.phase3HostViewSwitching = {");
  });
});

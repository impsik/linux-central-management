import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('phase3 admin bridges extraction', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const modulePath = path.join(root, 'server/app/templates/fleet-phase3-admin-bridges.js');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const moduleSrc = fs.readFileSync(modulePath, 'utf8');
  const indexSrc = fs.readFileSync(indexPath, 'utf8');

  it('loads admin bridge helpers from a dedicated module', () => {
    expect(indexSrc).toContain('/assets/fleet-phase3-admin-bridges.js');
    expect(indexSrc).toContain('function getAdminBridgeCtx()');
    expect(indexSrc).toContain('window.phase3AdminBridges');
  });

  it('defines host-action, ssh, and ansible bridge helpers in the module', () => {
    expect(moduleSrc).toContain('function initHostActionControls(ctx)');
    expect(moduleSrc).toContain('function initHostMetadataEditor(ctx)');
    expect(moduleSrc).toContain('function getSshUiCtx(ctx)');
    expect(moduleSrc).toContain('function initSshKeysControls(ctx)');
    expect(moduleSrc).toContain('function getAnsibleCtx(ctx)');
    expect(moduleSrc).toContain('function initAnsibleSection(ctx)');
    expect(moduleSrc).toContain('w.phase3AdminBridges = {');
  });
});

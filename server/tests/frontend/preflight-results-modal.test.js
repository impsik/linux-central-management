import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('preflight results modal', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const modalsPath = path.join(root, 'server/app/templates/fleet-phase3-modals.js');
  const shellPath = path.join(root, 'server/app/templates/fleet-phase3-app-shell.js');
  const partialsPath = path.join(root, 'server/app/templates/partials/modals.html');
  const overviewPath = path.join(root, 'server/app/templates/fleet-phase3-overview.js');
  const packagesPath = path.join(root, 'server/app/templates/fleet-phase3-packages.js');
  const modalsSrc = fs.readFileSync(modalsPath, 'utf8');
  const shellSrc = fs.readFileSync(shellPath, 'utf8');
  const partialsSrc = fs.readFileSync(partialsPath, 'utf8');
  const overviewSrc = fs.readFileSync(overviewPath, 'utf8');
  const packagesSrc = fs.readFileSync(packagesPath, 'utf8');

  it('defines reusable preflight modal markup and control wiring', () => {
    expect(partialsSrc).toContain('id="preflight-results-modal"');
    expect(modalsSrc).toContain('function initPreflightResultsModalControls()');
    expect(modalsSrc).toContain('window.openPreflightResultsModal = (preflight, meta) =>');
    expect(shellSrc).toContain("safeInit('initPreflightResultsModalControls', initPreflightResultsModalControls);");
  });

  it('opens the reusable preflight modal from overview and package upgrade flows', () => {
    expect(overviewSrc).toContain('w.openPreflightResultsModal(d.preflight');
    expect(packagesSrc).toContain('w.openPreflightResultsModal(dryRunData.preflight');
  });
});

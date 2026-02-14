import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

function runScriptInContext(filePath, contextObj) {
  const code = fs.readFileSync(filePath, 'utf8');
  vm.runInContext(code, contextObj, { filename: filePath });
}

describe('phase3 host-filters orchestrator', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const orchestratorPath = path.join(root, 'server/app/templates/fleet-phase3-host-filters.js');

  it('fails fast when required modules are missing', () => {
    const win = {
      window: null,
      console,
      document: {},
    };
    win.window = win;
    const ctx = vm.createContext(win);
    runScriptInContext(orchestratorPath, ctx);

    expect(() => ctx.phase3HostFilters.initHostFilters({})).toThrow(/phase3HostFiltersUi\.initHostFiltersUi is required/);
  });

  it('composes ui + vuln modules and returns contract', () => {
    let uiCalled = false;
    let vulnCalled = false;

    const win = {
      window: null,
      console,
      document: {},
      phase3HostFiltersUi: {
        initHostFiltersUi: (ctx) => {
          uiCalled = true;
          return {
            updateSelectionSummary: () => ctx.selectionSummaryUpdated = true,
            renderCvePackagesPanel: () => ctx.renderedPanel = true,
          };
        },
      },
      phase3HostFiltersVuln: {
        initHostFiltersVuln: (ctx) => {
          vulnCalled = true;
          return {
            updateUpgradeControls: () => {
              ctx.upgradeControlsUpdated = true;
            },
          };
        },
      },
    };
    win.window = win;
    const ctx = vm.createContext(win);
    runScriptInContext(orchestratorPath, ctx);

    const out = ctx.phase3HostFilters.initHostFilters({});
    expect(uiCalled).toBe(true);
    expect(vulnCalled).toBe(true);
    expect(out).toHaveProperty('updateUpgradeControls');
    expect(typeof out.updateUpgradeControls).toBe('function');
  });
});

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

function loadBrowserScript(filePath, baseWindow = {}) {
  const code = fs.readFileSync(filePath, 'utf8');
  const windowObj = {
    ...baseWindow,
    window: null,
    document: baseWindow.document || {},
    console,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
  };
  windowObj.window = windowObj;
  const context = vm.createContext(windowObj);
  vm.runInContext(code, context, { filename: filePath });
  return context;
}

describe('phase3 shared state helpers', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const phase3Path = path.join(root, 'server/app/templates/fleet-phase3.js');

  it('createUiStateAccess reads/writes values consistently', () => {
    const ctx = loadBrowserScript(phase3Path);
    const access = ctx.createUiStateAccess('testScope', { count: 1 });

    expect(access.get('count')).toBe(1);
    access.set('count', 2);
    expect(access.get('count')).toBe(2);

    access.update('count', (v) => (v || 0) + 1);
    expect(access.get('count')).toBe(3);

    access.set('flag', true);
    expect(access.get('flag')).toBe(true);
  });

  it('stopMetricsPollingLifecycle clears active intervals and flags', () => {
    const ctx = loadBrowserScript(phase3Path);
    const access = ctx.createUiStateAccess('metrics', {
      metricsUpdateInterval: 11,
      topProcessesUpdateInterval: 22,
      topProcessesInFlight: true,
      currentMetricsAgentId: 'agent-1',
    });

    const cleared = [];
    ctx.clearInterval = (id) => cleared.push(id);

    ctx.stopMetricsPollingLifecycle(access);

    expect(cleared).toEqual([11, 22]);
    expect(access.get('metricsUpdateInterval')).toBeNull();
    expect(access.get('topProcessesUpdateInterval')).toBeNull();
    // This helper only manages interval lifecycle; other fields are left intact.
    expect(access.get('topProcessesInFlight')).toBe(true);
    expect(access.get('currentMetricsAgentId')).toBe('agent-1');
  });
});

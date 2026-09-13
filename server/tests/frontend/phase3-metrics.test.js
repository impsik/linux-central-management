import { describe, it, expect, vi } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

function loadBrowserScript(filePath, baseWindow = {}) {
  const code = fs.readFileSync(filePath, 'utf8');
  const windowObj = {
    ...baseWindow,
    window: null,
    document: baseWindow.document || {},
    console: baseWindow.console || console,
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

function makeEl(extra = {}) {
  return {
    textContent: '-',
    innerHTML: '',
    style: {},
    ...extra,
  };
}

describe('phase3 metrics rendering', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const metricsPath = path.join(root, 'server/app/templates/fleet-phase3-metrics.js');

  it('shows the nearest measured load on a scaled canvas and clears it on leave', () => {
    const listeners = {};
    const draw = {
      clearRect() {}, beginPath() {}, moveTo() {}, lineTo() {}, stroke() {},
      arc() {}, fill() {}, fillRect() {},
      fillText: vi.fn(), measureText: () => ({ width: 150 }),
    };
    const canvas = {
      width: 600, height: 200,
      getContext: () => draw,
      getBoundingClientRect: () => ({ left: 100, width: 300 }),
      addEventListener: vi.fn((name, callback) => { listeners[name] = callback; }),
    };
    const now = Date.now();
    let data = [
      { time: new Date(now - 60000), load: 0.25 },
      { time: new Date(now - 45000), load: 2.75 },
      { time: new Date(now), load: 0.1 },
    ];
    const win = loadBrowserScript(metricsPath, {
      document: { documentElement: {}, getElementById: () => canvas },
      getComputedStyle: () => ({ getPropertyValue: () => '' }),
      formatTimeLabel: date => date.toISOString(),
    });
    const state = { getLoadGraphData: () => data, getLoadTimeframeSeconds: () => 3600 };
    win.phase3Metrics.redrawLoadGraph(state);
    listeners.pointermove({ clientX: 176.5 });
    expect(draw.fillText).toHaveBeenLastCalledWith(`Load: 2.75 @ ${data[1].time.toISOString()}`, expect.any(Number), expect.any(Number));
    data = data.map(point => ({ ...point, load: 0.5 }));
    win.phase3Metrics.redrawLoadGraph(state);
    expect(draw.fillText.mock.calls.at(-1)[0]).toContain('Load: 0.50');
    expect(canvas.addEventListener).toHaveBeenCalledTimes(3);
    listeners.pointerleave();
    expect(draw.fillText).toHaveBeenLastCalledWith(`Load: 0.50 @ ${data[2].time.toISOString()}`, 10, 20);
  });

  it('coerces numeric strings and avoids sticky Error values on transient failures', async () => {
    const elements = {
      'disk-usage': makeEl(),
      'disk-details': makeEl(),
      'disk-bar': makeEl(),
      'memory-usage': makeEl(),
      'memory-details': makeEl(),
      'memory-bar': makeEl(),
      vcpus: makeEl(),
      'ip-addresses': makeEl(),
      'ip-list': makeEl(),
      'top-processes-body': makeEl(),
      'load-graph': makeEl({
        offsetWidth: 300,
        offsetHeight: 120,
        width: 300,
        height: 120,
        getContext: () => ({ clearRect() {}, beginPath() {}, moveTo() {}, lineTo() {}, stroke() {}, fillText() {} }),
      }),
    };

    const state = { currentMetricsAgentId: 'a-1', topProcessesInFlight: false };
    const testConsole = { error: vi.fn(), log: vi.fn(), warn: vi.fn(), info: vi.fn() };
    const ctxObj = {
      console: testConsole,
      document: {
        getElementById: (id) => elements[id] || null,
      },
      fetch: async () => ({
        ok: true,
        json: async () => ({
          disk_usage: { used_gb: '3.0', total_gb: '19.0' },
          memory: { used_gb: '0.55', total_gb: '15.62' },
          cpu: { cores: '4', load_1min: '0.12' },
          ip_addresses: ['192.168.100.241'],
          top_processes: [],
        }),
      }),
      getLoadHistoryLimitForRange: () => 300,
      formatTimeLabel: () => 'now',
      escapeHtml: (s) => String(s),
      renderTopProcessesTable: () => {},
    };

    const win = loadBrowserScript(metricsPath, ctxObj);

    const metricsCtx = {
      getMetricsLifecycleState: () => ({
        get: (k) => state[k],
        set: (k, v) => { state[k] = v; },
      }),
      getLoadGraphData: () => [],
      setLoadGraphData: () => {},
      getLoadTimeframeSeconds: () => 3600,
    };

    await win.phase3Metrics.loadMetrics(metricsCtx, 'a-1', false);

    expect(elements['disk-usage'].textContent).toBe('15.8%');
    expect(elements['memory-usage'].textContent).toBe('3.5%');
    expect(elements.vcpus.textContent).toBe('4');
    expect(elements['ip-addresses'].textContent).toBe(1);

    win.fetch = async () => {
      throw new Error('temporary network issue');
    };

    await win.phase3Metrics.loadMetrics(metricsCtx, 'a-1', true);

    expect(elements['disk-usage'].textContent).toBe('15.8%');
    expect(elements['memory-usage'].textContent).toBe('3.5%');
    expect(elements.vcpus.textContent).toBe('4');
    expect(testConsole.error).toHaveBeenCalled();
  });
});

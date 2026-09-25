import { afterEach, it, expect, vi } from 'vitest';
import fs from 'node:fs';
import vm from 'node:vm';

const app = fs.readFileSync(new URL('../../app/templates/fleet-app.js', import.meta.url), 'utf8');
const overview = fs.readFileSync(new URL('../../app/templates/fleet-phase3-overview.js', import.meta.url), 'utf8');
function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}
afterEach(() => vi.useRealTimers());

it('coalesces timed Dashboard refreshes until the slow CVE request finishes', async () => {
  vi.useFakeTimers();
  const cve = deferred();
  let active = true;
  let agentId = null;
  const document = {
    hidden: false, addEventListener() {},
    getElementById(id) {
      if (id === 'server-info-tab') return { classList: { contains: () => active } };
      if (id === 'overview-urgent-updates') return {};
      return null;
    },
  };
  const fetch = vi.fn(async (url) => {
    if (url.startsWith('/dashboard/urgent-updates')) await cve.promise;
    return { ok: true, json: async () => ({ items: [], kpis: {} }) };
  });
  const api = { getCurrentAgentId: () => agentId, loadPendingUpdatesReport: vi.fn(async () => {}) };
  const browser = { document, fetch, console, setTableState: vi.fn(), setInterval, clearInterval };
  browser.window = browser;
  vm.createContext(browser);
  vm.runInContext(overview, browser);
  browser.loadFleetOverview = (force, background) => browser.phase3Overview.loadFleetOverview(api, force, background);
  vm.runInContext(app.split('\n').find(line => line.includes('setInterval(() => { void loadFleetOverview(false, true)')), browser);
  const initial = browser.loadFleetOverview(false, false);
  await vi.advanceTimersByTimeAsync(45000);
  expect(fetch.mock.calls.filter(([url]) => url.startsWith('/dashboard/urgent-updates'))).toHaveLength(1);
  expect(fetch.mock.calls.filter(([url]) => url === '/dashboard/summary')).toHaveLength(1);
  cve.resolve();
  await initial;
  document.hidden = true;
  await vi.advanceTimersByTimeAsync(15000);
  document.hidden = false;
  active = false;
  await vi.advanceTimersByTimeAsync(15000);
  active = true;
  agentId = 'selected-host';
  await vi.advanceTimersByTimeAsync(15000);
  expect(fetch.mock.calls.filter(([url]) => url === '/dashboard/summary')).toHaveLength(1);
  agentId = null;
  await vi.advanceTimersByTimeAsync(15000);
  expect(fetch.mock.calls.filter(([url]) => url === '/dashboard/summary')).toHaveLength(2);
});

it('coalesces host inventory refreshes, skips hidden polling, and preserves explicit refreshes', async () => {
  vi.useFakeTimers();
  const pending = deferred();
  const load = vi.fn(() => pending.promise);
  const browser = { document: { hidden: false }, console, getHostListCtx: () => ({}), phase3HostList: { loadHosts: load }, setInterval };
  browser.window = browser;
  vm.createContext(browser);
  vm.runInContext(app.slice(app.indexOf('    let hostsLoadPromise = null;'), app.indexOf('    function initHostFilters()')), browser);
  vm.runInContext(app.slice(app.indexOf('    const HOSTS_REFRESH_MS ='), app.indexOf('    void loadHosts(true).catch')), browser);
  browser.startHostRefresh();
  const initial = browser.loadHosts(true);
  await vi.advanceTimersByTimeAsync(15000);
  expect(load).toHaveBeenCalledOnce();
  pending.resolve();
  await initial;
  browser.document.hidden = true;
  await vi.advanceTimersByTimeAsync(15000);
  expect(load).toHaveBeenCalledOnce();
  await browser.loadHosts();
  expect(load).toHaveBeenCalledTimes(2);
  browser.document.hidden = false;
  await vi.advanceTimersByTimeAsync(5000);
  expect(load).toHaveBeenCalledTimes(3);
});

it('loads the initial Dashboard through navigation initialization only', () => {
  const startup = app.slice(app.indexOf('    bootUi().catch'));
  expect(startup).not.toContain('void loadFleetOverview();');
  expect(overview).toContain('    showOverviewTab();');
  expect(app).toContain("safeInit('initFleetOverviewControls', initFleetOverviewControls)");
});

it('keeps alert badges refreshed outside Dashboard while skipping hidden-page polling', async () => {
  vi.useFakeTimers();
  const loadNotifications = vi.fn();
  const refreshMaintenanceGuardButtons = vi.fn();
  const ctx = { getCurrentAgentId: () => null };
  const browser = {
    document: { hidden: false, getElementById: () => ({ classList: { contains: () => false } }) },
    ctx, loadNotifications, refreshMaintenanceGuardButtons, setInterval, clearInterval,
  };
  browser.window = browser;
  vm.createContext(browser);
  const start = overview.indexOf('    try {\n      if (window.__fleetNotifInterval)');
  const end = overview.indexOf('    } catch (_) { }', start) + '    } catch (_) { }'.length;
  vm.runInContext(overview.slice(start, end), browser);
  await vi.advanceTimersByTimeAsync(60000);
  expect(loadNotifications).toHaveBeenCalledOnce();
  expect(refreshMaintenanceGuardButtons).not.toHaveBeenCalled();
  browser.document.hidden = true;
  await vi.advanceTimersByTimeAsync(60000);
  expect(loadNotifications).toHaveBeenCalledOnce();
});

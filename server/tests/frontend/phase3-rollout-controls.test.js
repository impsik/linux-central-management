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
  const handlers = {};
  return {
    textContent: '',
    innerHTML: '',
    value: '',
    style: {},
    dataset: {},
    disabled: false,
    classList: { add() {}, remove() {}, contains() { return false; } },
    addEventListener(type, cb) { handlers[type] = cb; },
    dispatch(type, evt = {}) { if (handlers[type]) handlers[type](evt); },
    ...extra,
  };
}

describe('phase3 rollout controls wiring', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const overviewPath = path.join(root, 'server/app/templates/fleet-phase3-overview.js');

  it('loads rollout summary from campaign id input', async () => {
    const els = {
      'nav-overview': makeEl(),
      'nav-hosts': makeEl(),
      'nav-cronjobs': makeEl(),
      'nav-sshkeys': makeEl(),
      'overview-next-cronjobs-open': makeEl(),
      'overview-refresh': makeEl(),
      'kpi-timeframe': makeEl({ value: '24' }),
      'overview-inventory-now': makeEl(),
      'overview-security-campaign': makeEl(),
      'overview-dist-upgrade': makeEl(),
      'failed-runs-refresh': makeEl(),
      'notifications-refresh': makeEl(),
      'teams-test-alert': makeEl(),
      'teams-send-brief': makeEl(),
      'report-refresh': makeEl(),
      'report-sort': makeEl(),
      'report-order': makeEl(),
      'rollout-campaign-id': makeEl({ value: 'pc-123' }),
      'rollout-load': makeEl(),
      'rollout-pause': makeEl(),
      'rollout-resume': makeEl(),
      'rollout-approve-next': makeEl(),
      'rollout-summary': makeEl(),
      'rollout-status': makeEl(),
      'server-info-tab': makeEl({ classList: { add() {}, remove() {}, contains() { return true; } } }),
      'hosts-table-tab': makeEl({ classList: { add() {}, remove() {}, contains() { return false; } } }),
      'cronjobs-tab': makeEl({ classList: { add() {}, remove() {}, contains() { return false; } } }),
      'sshkeys-tab': makeEl({ classList: { add() {}, remove() {}, contains() { return false; } } }),
    };

    const fetchMock = vi.fn(async (url) => {
      if (String(url).includes('/patching/campaigns/pc-123/rollout')) {
        return {
          ok: true,
          text: async () => JSON.stringify({
            campaign_id: 'pc-123',
            status: 'running',
            hosts_done: 2,
            hosts_total: 4,
            hosts_failed: 1,
            rollout: { paused: false, approved_through_ring: 0 },
            waves: [{ name: 'canary', size: 1, failed: 0 }],
          }),
        };
      }
      return { ok: true, json: async () => ({ items: [] }), text: async () => '{}' };
    });

    const win = loadBrowserScript(overviewPath, {
      document: {
        getElementById: (id) => els[id] || null,
        querySelectorAll: () => [],
        querySelector: () => ({ classList: { add() {}, remove() {} } }),
      },
      fetch: fetchMock,
      escapeHtml: (s) => String(s),
      setTableState: () => {},
      updateReportSortIndicators: () => {},
      updateHostsSortIndicators: () => {},
      bindSortableHeader: () => {},
      setupReportSortHandlers: () => {},
      setupKpiHandlers: () => {},
      wireBusyClick: (el, _label, fn) => { if (el) el.addEventListener('click', (e) => fn(e)); },
      showToast: () => {},
      loadNotifications: () => {},
      refreshMaintenanceGuardButtons: () => {},
    });

    const ctx = {
      clearCurrentHostSelection: () => {},
      loadFleetOverview: async () => {},
      loadPendingUpdatesReport: async () => {},
      loadHosts: async () => {},
      loadFailedRuns: async () => {},
      loadHostsTable: async () => {},
      loadCronjobs: async () => {},
      loadSshKeys: async () => {},
      loadSshKeyRequests: async () => {},
      maybeLoadSshKeyAdminQueue: async () => {},
      loadAdminSshKeys: async () => {},
      getLastRenderedAgentIds: () => [],
      formatShortTime: () => 'now',
    };

    win.phase3Overview.initFleetOverviewControls(ctx);

    await els['rollout-load'].dispatch('click', { preventDefault() {} });

    expect(fetchMock).toHaveBeenCalledWith('/patching/campaigns/pc-123/rollout', { credentials: 'include' });
  });
});

import { describe, it, expect, vi } from 'vitest';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../../app/templates/fleet-phase3-host-list.js', import.meta.url), 'utf8');

function setup(hosts = []) {
  const state = { hosts, visibleIds: ['stale'], currentAgentId: '' };
  const fetch = vi.fn(async () => ({ ok: true, json: async () => state.hosts }));
  const controls = vi.fn();
  const clearSelection = vi.fn();
  const browser = {
    window: null,
    // The current page no longer has a hidden #hosts sidebar.
    document: { getElementById: () => null },
    fetch,
    console,
    setTimeout,
    clearTimeout,
    normalize: (value) => String(value || '').toLowerCase(),
    hostLabel: (host, key) => host.labels?.[key] || '',
  };
  browser.window = browser;
  vm.runInNewContext(source, browser);
  const ctx = {
    getAllHosts: () => state.hosts,
    setAllHosts: (value) => { state.hosts = value; },
    getCurrentAgentId: () => state.currentAgentId,
    clearCurrentHostSelection: clearSelection,
    getHostSearchQuery: () => '',
    getVulnFilteredAgentIds: () => null,
    getLabelEnvFilter: () => '',
    getLabelRoleFilter: () => '',
    getLabelOwnerFilter: () => '',
    setLastRenderedAgentIds: (value) => { state.visibleIds = Array.from(value); },
    updateUpgradeControls: controls,
  };
  return { api: browser.phase3HostList, ctx, state, fetch, controls, clearSelection };
}

describe('host inventory without the retired sidebar', () => {
  it('refreshes inventory and bulk-action IDs without creating hidden host cards', async () => {
    const test = setup([{ agent_id: 'node-1', hostname: 'web-1' }]);
    await test.api.loadHosts(test.ctx);
    expect(test.fetch).toHaveBeenCalledWith('/hosts?online_only=true', expect.objectContaining({ credentials: 'include' }));
    expect(test.state.visibleIds).toEqual(['node-1']);
    expect(test.controls).toHaveBeenCalledOnce();
  });

  it('combines search, label, and vulnerability filters for bulk actions', () => {
    const test = setup([
      { agent_id: 'node-1', hostname: 'web-1', labels: { env: 'prod', owner: 'imre' } },
      { agent_id: 'node-2', hostname: 'db-1', labels: { env: 'prod', owner: 'imre' } },
      { agent_id: 'node-3', hostname: 'web-2', labels: { env: 'test', owner: 'imre' } },
      { agent_id: 'node-4', hostname: 'web-3', labels: { env: 'prod', owner: 'other' } },
      { agent_id: 'node-5', hostname: 'web-4', labels: { env: 'prod', owner: 'imre' } },
    ]);
    test.api.applyHostFilters({
      ...test.ctx,
      getHostSearchQuery: () => 'WEB',
      getLabelEnvFilter: () => 'prod',
      getLabelOwnerFilter: () => 'imre',
      getVulnFilteredAgentIds: () => new Set(['node-1', 'node-2', 'node-3', 'node-4']),
    });
    expect(test.state.visibleIds).toEqual(['node-1']);
    expect(test.controls).toHaveBeenCalledOnce();
  });

  it('clears stale host selection and bulk-action IDs when inventory becomes empty', async () => {
    const test = setup();
    test.state.currentAgentId = 'removed-host';
    await test.api.loadHosts(test.ctx);
    expect(test.clearSelection).toHaveBeenCalledOnce();
    expect(test.state.visibleIds).toEqual([]);
    expect(test.controls).toHaveBeenCalledOnce();
  });
});

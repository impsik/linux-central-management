import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

class FakeElement {
  constructor(id) {
    this.id = id;
    this.value = '';
    this.checked = false;
    this.disabled = false;
    this.textContent = '';
    this.innerHTML = '';
    this.style = {};
    this.listeners = {};
    this.classList = {
      set: new Set(),
      toggle: (name, force) => {
        if (typeof force === 'boolean') {
          if (force) this.classList.set.add(name); else this.classList.set.delete(name);
          return;
        }
        if (this.classList.set.has(name)) this.classList.set.delete(name);
        else this.classList.set.add(name);
      },
      contains: (name) => this.classList.set.has(name),
    };
  }
  addEventListener(type, cb) {
    this.listeners[type] = this.listeners[type] || [];
    this.listeners[type].push(cb);
  }
  dispatch(type) {
    for (const cb of this.listeners[type] || []) cb({ preventDefault() {}, target: this });
  }
  setAttribute() {}
  querySelectorAll() { return []; }
}

function createDocument(ids) {
  const byId = new Map(ids.map((id) => [id, new FakeElement(id)]));
  return {
    getElementById(id) { return byId.get(id) || null; },
    _byId: byId,
  };
}

function run(filePath, win) {
  const code = fs.readFileSync(filePath, 'utf8');
  const ctx = vm.createContext(win);
  vm.runInContext(code, ctx, { filename: filePath });
  return ctx;
}

describe('phase3 host-filter behavior flows', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const uiPath = path.join(root, 'server/app/templates/fleet-phase3-host-filters-ui.js');
  const vulnPath = path.join(root, 'server/app/templates/fleet-phase3-host-filters-vuln.js');

  it('updates CVE upgrade status and button state across transitions', () => {
    const doc = createDocument([
      'vuln-cve', 'vuln-package', 'vuln-version', 'vuln-apply', 'vuln-clear', 'vuln-status',
      'select-visible-hosts', 'upgrade-selected', 'upgrade-status', 'cve-packages-panel', 'cve-packages-list', 'cve-plan-summary',
    ]);
    const win = { window: null, document: doc, console };
    win.window = win;
    run(vulnPath, win);

    const state = {
      selectedAgentIds: new Set(['a1']),
      lastRenderedAgentIds: ['a1'],
      lastCveCheck: null,
      lastCveUnionPackages: [],
      selectedCvePackages: new Set(),
    };
    const api = win.phase3HostFiltersVuln.initHostFiltersVuln({
      getState: () => state,
      setState: (patch) => Object.assign(state, patch),
    });

    doc.getElementById('vuln-cve').value = 'CVE-2025-1234';
    api.updateUpgradeControls();
    expect(doc.getElementById('upgrade-selected').disabled).toBe(true);
    expect(doc.getElementById('upgrade-status').textContent).toContain('Run CVE check');

    state.lastCveCheck = {
      cve: 'CVE-2025-1234',
      resultsByAgentId: { a1: { packages: ['openssl'] } },
    };
    state.lastCveUnionPackages = ['openssl'];
    state.selectedCvePackages = new Set(['openssl']);
    api.updateUpgradeControls();

    expect(doc.getElementById('upgrade-selected').disabled).toBe(false);
    expect(doc.getElementById('upgrade-status').textContent).toContain('Packages selected: 1');
    expect(doc.getElementById('upgrade-status').textContent).toContain('CVE: CVE-2025-1234');
  });

  it('select all visible hosts propagates selection + refresh callbacks', () => {
    const doc = createDocument([
      'host-search', 'label-env', 'label-role', 'labels-clear', 'labels-filter-section', 'labels-filter-toggle', 'labels-toggle-btn',
      'select-visible-hosts', 'vuln-filter-section', 'vuln-filter-toggle', 'vuln-toggle-btn', 'ansible-filter-section', 'ansible-filter-toggle', 'ansible-toggle-btn',
    ]);
    const win = { window: null, document: doc, console };
    win.window = win;
    run(uiPath, win);

    const state = { lastRenderedAgentIds: ['a1', 'a2'], selectedAgentIds: new Set() };
    let applyCount = 0;
    let upgradeCount = 0;

    win.phase3HostFiltersUi.initHostFiltersUi({
      getState: () => state,
      setState: (patch) => Object.assign(state, patch),
      syncSelectionState: (_, value) => value,
      applyHostFilters: () => { applyCount += 1; },
      updateUpgradeControls: () => { upgradeCount += 1; },
    });

    const cb = doc.getElementById('select-visible-hosts');
    cb.checked = true;
    cb.dispatch('change');

    expect(Array.from(state.selectedAgentIds)).toEqual(['a1', 'a2']);
    expect(applyCount).toBe(1);
    expect(upgradeCount).toBe(1);
  });

  it('label clear resets env/role filters and reapplies filtering', () => {
    const doc = createDocument([
      'host-search', 'label-env', 'label-role', 'labels-clear', 'labels-filter-section', 'labels-filter-toggle', 'labels-toggle-btn',
      'select-visible-hosts', 'vuln-filter-section', 'vuln-filter-toggle', 'vuln-toggle-btn', 'ansible-filter-section', 'ansible-filter-toggle', 'ansible-toggle-btn',
    ]);
    const win = { window: null, document: doc, console };
    win.window = win;
    run(uiPath, win);

    const state = { labelEnvFilter: 'prod', labelRoleFilter: 'db' };
    let applyCount = 0;

    win.phase3HostFiltersUi.initHostFiltersUi({
      getState: () => state,
      setState: (patch) => Object.assign(state, patch),
      syncSelectionState: (_, value) => value,
      applyHostFilters: () => { applyCount += 1; },
    });

    doc.getElementById('label-env').value = 'prod';
    doc.getElementById('label-role').value = 'db';
    doc.getElementById('labels-clear').dispatch('click');

    expect(state.labelEnvFilter).toBe('');
    expect(state.labelRoleFilter).toBe('');
    expect(applyCount).toBe(1);
  });
});

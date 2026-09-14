import { describe, it, expect, vi } from 'vitest';
import fs from 'node:fs';
import vm from 'node:vm';

const read = name => fs.readFileSync(new URL(`../../app/templates/${name}`, import.meta.url), 'utf8');
function load(extra = {}) {
  const browser = { console, ...extra };
  browser.window = browser;
  vm.createContext(browser);
  vm.runInContext(read('fleet-phase3.js'), browser);
  return browser;
}

describe('service autostart state', () => {
  it.each(['static', 'indirect', 'generated', 'transient'])('describes %s without offering an ineffective direct toggle', state => {
    const browser = load();
    const actual = browser.describeServiceAutostart({ unit_file_state: state, enabled: false, can_enable: false, can_disable: false });
    expect(actual.label.toLowerCase()).toBe(state);
    expect(actual.reason).not.toBe('');
    expect(actual.canEnable).toBe(false);
    expect(actual.canDisable).toBe(false);
  });

  it('keeps service and socket activation distinct and honors agent capabilities', () => {
    const browser = load();
    const actual = browser.describeServiceAutostart({ unit_file_state: 'static', socket_unit_file_state: 'enabled', enabled: true, can_enable: false, can_disable: true });
    expect(actual.label).toBe('Via socket · service static');
    expect(actual.reason).toContain('Service state: static. Matching socket state: enabled.');
    expect(actual.enabled).toBe(true);
    expect(actual.canDisable).toBe(true);
    expect(actual.canEnable).toBe(false);
  });

  it('labels disabled services started by enabled sockets without suggesting autostart is off', () => {
    const browser = load();
    const state = { unit_file_state: 'disabled', socket_unit_file_state: 'enabled', enabled: true };
    expect(browser.describeServiceAutostart(state).label).toBe('Via socket · service disabled');
    expect(browser.describeServiceAutostart({ ...state, socket_unit_file_state: 'enabled-runtime' }).label).toBe('Via socket (until reboot) · service disabled');
    expect(browser.describeServiceAutostart({ ...state, unit_file_state: 'enabled' }).label).toBe('Enabled · socket enabled');
  });

  it('supports older agents without state/capability fields', () => {
    const browser = load();
    expect(browser.describeServiceAutostart({ enabled: true, can_enable: null }).label).toBe('Enabled');
    expect(browser.describeServiceAutostart({ enabled: true, can_disable: null }).canDisable).toBe(true);
    expect(browser.describeServiceAutostart({ enabled: false }).canEnable).toBe(true);
  });

  it('renders a static service with disabled enable action but leaves runtime Start available', async () => {
    const list = { innerHTML: '', querySelectorAll: () => [] };
    const browser = load({ document: { getElementById: () => list }, fetch: async () => ({ ok: true, json: async () => ({ services: [{ name: 'systemd-fsckd.service', status: 'inactive', unit_file_state: 'static', enabled: false, can_enable: false, can_disable: false }] }) }) });
    vm.runInContext(read('fleet-phase3-host-workflows.js'), browser);
    await browser.phase3HostWorkflows.loadServices({}, 'node-1');
    expect(list.innerHTML).toContain('Autostart: Static');
    expect(list.innerHTML).toMatch(/data-service-action="enable"[^>]*disabled/);
    expect(list.innerHTML).not.toMatch(/data-service-action="start"[^>]*disabled/);
  });

  it('blocks bulk autostart changes for static units without blocking runtime actions', async () => {
    const node = (value = '') => ({ value, disabled: false, checked: false, events: {}, addEventListener(type, fn) { this.events[type] = fn; } });
    const elements = Object.fromEntries(['name', 'exact', 'search', 'start', 'enable', 'stop', 'stop-disable', 'status', 'table-body'].map(id => [`service-management-${id}`, node()]));
    elements['service-management-name'].value = 'systemd-fsckd.service';
    const check = node();
    check.checked = true;
    check.getAttribute = key => ({ 'data-service-agent-id': 'node-1', 'data-service-can-enable': 'false', 'data-service-can-disable': 'false' })[key];
    const body = elements['service-management-table-body'];
    body.querySelectorAll = () => [check];
    const fetch = vi.fn(async () => ({ ok: true, json: async () => ({ total: 1, scanned_hosts: 1, items: [{ agent_id: 'node-1', service_name: 'systemd-fsckd.service', status: 'inactive', unit_file_state: 'static', can_enable: false, can_disable: false }] }) }));
    const showToast = vi.fn();
    const browser = load({ document: { getElementById: id => elements[id] || null }, fetch, URLSearchParams, confirm: vi.fn(() => true) });
    vm.runInContext(read('fleet-service-management-ui.js'), browser);
    browser.fleetServiceManagementUi.initServiceManagementControls({ getCurrentPermissions: () => ({ can_manage_services: true }), showToast });
    elements['service-management-search'].events.click({ preventDefault() {} });
    await vi.waitFor(() => expect(body.innerHTML).toContain('Static'));
    expect(elements['service-management-enable'].disabled).toBe(true);
    expect(elements['service-management-stop-disable'].disabled).toBe(true);
    expect(elements['service-management-start'].disabled).toBe(false);
    expect(elements['service-management-stop'].disabled).toBe(false);
    elements['service-management-enable'].events.click({ preventDefault() {} });
    expect(fetch).toHaveBeenCalledOnce();
    expect(showToast).toHaveBeenLastCalledWith(expect.stringContaining('do not support'), 'error');
  });
});

import { describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import vm from 'node:vm';
const read = name => fs.readFileSync(new URL(`../../app/templates/${name}`, import.meta.url), 'utf8');
const response = data => ({ ok: true, json: async () => data });
function setup() {
  const buttons = [];
  const list = { innerHTML: '', querySelectorAll: () => buttons };
  const elements = { 'firewall-list': list, 'users-list': list, 'host-firewall-status': { textContent: '' } };
  const browser = { console: { error: vi.fn() }, document: { getElementById: id => elements[id] },
    showToast: vi.fn(), confirm: vi.fn(() => true),
    fetch: vi.fn(async url => response(url.startsWith('/reports/') ? { job_id: 'j1' } : { backend: 'ufw', rules: [] })),
    fleetFirewallManagementUi: { waitForJobDone: vi.fn(async () => ({ done: true, success: ['node'], failed: [], successDetails: [{ agentId: 'node', message: 'Firewall is OFF; saved rules are not enforced.' }] })) },
  };
  browser.window = browser;
  vm.createContext(browser);
  vm.runInContext(read('fleet-phase3.js'), browser);
  vm.runInContext(read('fleet-phase3-host-workflows.js'), browser);
  const ctx = { getCurrentPermissions: () => ({ can_manage_services: true }) };
  return { browser, ctx, list, buttons, elements, api: browser.phase3HostWorkflows };
}

describe('host firewall and error handling', () => {
  it('removes the exact displayed deny/source rule through the durable fleet job', async () => {
    const s = setup();
    const rule = { id: '2', raw: '[ 2] 22/tcp DENY IN 192.0.2.8', backend: 'ufw' };
    const button = { getAttribute: () => '0', addEventListener: (event, fn) => { button.click = fn; } };
    s.buttons.push(button);
    s.browser.fetch.mockResolvedValueOnce(response({ backend: 'ufw', rules: [rule] }));
    await s.api.loadFirewall(s.ctx, 'node');
    button.click({ preventDefault() {} });
    await vi.waitFor(() => expect(s.browser.showToast).toHaveBeenCalledWith(expect.stringContaining('Firewall is OFF'), 'success'));
    const post = s.browser.fetch.mock.calls.find(([url]) => url === '/reports/firewall-rules/delete-rules');
    expect(JSON.parse(post[1].body)).toEqual({ agent_ids: ['node'], rules_by_agent: { node: [{ ...rule, zone: '' }] } });
    expect(s.browser.fleetFirewallManagementUi.waitForJobDone).toHaveBeenCalledWith('j1');
  });
  it.each([
    { done: false, success: [], failed: [], failureDetails: [] },
    { done: true, success: [], failed: ['node'], failureDetails: [{ message: 'Backend failed' }] },
    { done: true, success: [], failed: [], failureDetails: [] },
  ])('does not report unconfirmed/failed work as successful: %j', async summary => {
    const s = setup();
    s.browser.fleetFirewallManagementUi.waitForJobDone.mockResolvedValue(summary);
    await s.api.controlFirewall(s.ctx, 'node', { action: 'allow', port: 1122, protocol: 'tcp' });
    expect(s.browser.showToast).toHaveBeenCalledWith(expect.any(String), 'error');
    expect(s.browser.showToast).not.toHaveBeenCalledWith(expect.any(String), 'success');
  });
  it('blocks duplicate submission while a host firewall job is pending', async () => {
    const s = setup();
    let resolve;
    s.browser.fleetFirewallManagementUi.waitForJobDone.mockReturnValue(new Promise(done => { resolve = done; }));
    const first = s.api.controlFirewall(s.ctx, 'node', { action: 'allow', port: 1122 });
    await s.api.controlFirewall(s.ctx, 'node', { action: 'allow', port: 1122 });
    expect(s.browser.fetch).toHaveBeenCalledTimes(1);
    resolve({ done: true, success: ['node'], failed: [] });
    await first;
  });
  it('escapes agent/API errors instead of rendering HTML in user management', async () => {
    const s = setup();
    s.browser.fetch.mockResolvedValue({ ok: false, json: async () => ({ detail: '<img src=x onerror=alert(1)>' }) });
    await s.api.loadUsers(s.ctx, 'node');
    expect(s.list.innerHTML).toContain('&lt;img');
    expect(s.list.innerHTML).not.toContain('<img');
  });
});

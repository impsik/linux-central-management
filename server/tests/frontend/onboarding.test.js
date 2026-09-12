import { describe, it, expect, vi } from 'vitest';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../../app/templates/fleet-onboarding.js', import.meta.url), 'utf8');
const html = fs.readFileSync(new URL('../../app/templates/index.html', import.meta.url), 'utf8');

function setup(data = { host_count: 0, host: null }, status = 200) {
  const elements = new Map();
  for (const [, id] of html.matchAll(/id="([^"]+)"/g)) {
    const classes = new Set();
    const span = { textContent: '' };
    elements.set(id, { hidden: true, dataset: {}, value: '', textContent: '', listeners: {},
      classList: { toggle: (key, value) => value ? classes.add(key) : classes.delete(key), contains: key => classes.has(key) },
      addEventListener(event, cb) { this.listeners[event] = cb; },
      querySelector: () => span, focus() {},
    });
  }
  const w = { document: { hidden: false, getElementById: id => elements.get(id) },
    fetch: vi.fn().mockResolvedValue({ ok: status === 200, status, json: async () => data }),
    navigator: { clipboard: { writeText: vi.fn().mockResolvedValue() } },
    setInterval: vi.fn(), console };
  w.window = w;
  vm.runInNewContext(source, w);
  const ctx = { selectHost: vi.fn(), showPackages: vi.fn() };
  const el = id => elements.get(id);
  const tick = async () => { await new Promise(resolve => setTimeout(resolve, 0)); };
  return { w, el, ctx, tick };
}

describe('first-host setup', () => {
  it('builds a command without accepting shell or Ansible patterns', () => {
    const { w } = setup();
    expect(w.fleetOnboarding.attachmentCommand('192.0.2.21', 'fleet-admin').command)
      .toBe("ATTACH_HOSTS='192.0.2.21' ANSIBLE_USER='fleet-admin' ./add-host.sh");
    for (const host of ['$(id)', 'host;id', 'host:22', '*', 'all', 'ungrouped', '999.2.3.4', 'a b', '-option']) {
      expect(() => w.fleetOnboarding.attachmentCommand(host, 'ubuntu')).toThrow();
    }
    expect(() => w.fleetOnboarding.attachmentCommand('host', "a' ;id")).toThrow();
  });

  it('does not call registration complete without current connection and inventory', () => {
    const { w } = setup();
    expect(w.fleetOnboarding.progress(null).ready).toBe(false);
    expect(w.fleetOnboarding.progress({ online: true, os_id: 'ubuntu', os_version: '24.04' }).ready).toBe(false);
    expect(w.fleetOnboarding.progress({ online: false, os_id: 'ubuntu', os_version: '24.04', inventory_received: true }).ready).toBe(false);
  });

  it('shows setup for an empty fleet, then transitions through inventory to packages', async () => {
    const { w, el, ctx, tick } = setup();
    w.fleetOnboarding.init(ctx);
    await tick();
    expect(el('fleet-onboarding').hidden).toBe(false);
    expect(el('server-info-placeholder').classList.contains('onboarding-active')).toBe(true);
    el('onboarding-host').value = 'server.example.test';
    el('onboarding-username').value = 'ubuntu';
    el('onboarding-form').listeners.submit({ preventDefault() {} });
    await tick();
    expect(el('onboarding-command').textContent).toContain("ATTACH_HOSTS='server.example.test'");
    expect(w.fetch.mock.calls.at(-1)[0]).toContain('target=server.example.test');
    const host = { agent_id: 'a', hostname: '<host>', online: true, os_id: 'ubuntu', os_version: '24.04', package_count: 12,
      inventory_received: true, updates_count: 2 };
    w.fetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({ host_count: 1, host }) });
    el('onboarding-refresh').listeners.click();
    await tick();
    expect(el('onboarding-view').hidden).toBe(false);
    expect(el('onboarding-host-summary').textContent).toContain('<host>');
    el('onboarding-view').listeners.click();
    expect(ctx.selectHost).toHaveBeenCalledWith('a', '<host>');
    expect(ctx.showPackages).toHaveBeenCalledOnce();
    expect(el('fleet-onboarding').hidden).toBe(true);
  });

  it('leaves existing fleets on the dashboard and supports reopening', async () => {
    const { w, el, ctx, tick } = setup({ host_count: 3, host: { hostname: 'old' } });
    w.fleetOnboarding.init(ctx);
    await tick();
    expect(el('fleet-onboarding').hidden).toBe(true);
    expect(el('onboarding-open').hidden).toBe(false);
    el('onboarding-open').listeners.click();
    await tick();
    expect(el('fleet-onboarding').hidden).toBe(false);
    expect(el('onboarding-progress').hidden).toBe(true);
    el('onboarding-skip').listeners.click();
    expect(el('fleet-onboarding').hidden).toBe(true);
  });

  it('does not expose setup on forbidden responses and retries after MFA', async () => {
    const { w, el, ctx, tick } = setup({}, 403);
    w.fleetOnboarding.init(ctx);
    await tick();
    expect(el('fleet-onboarding').hidden).toBe(true);
    expect(el('onboarding-open').hidden).toBe(true);
    w.fetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({ host_count: 0, host: null }) });
    w.setInterval.mock.calls[0][0]();
    await tick();
    expect(el('fleet-onboarding').hidden).toBe(false);
  });

  it('keeps API errors distinct from an unregistered host', async () => {
    const { w, el, ctx, tick } = setup();
    w.fleetOnboarding.init(ctx);
    await tick();
    w.fetch.mockResolvedValue({ ok: false, status: 500 });
    el('onboarding-refresh').listeners.click();
    await tick();
    expect(el('onboarding-status').textContent).toContain('unavailable (500)');
  });
});

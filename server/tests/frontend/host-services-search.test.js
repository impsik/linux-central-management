import { afterEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import vm from 'node:vm';

const read = name => fs.readFileSync(new URL(`../../app/templates/${name}`, import.meta.url), 'utf8');
const services = [
  { name: 'ufw.service', description: 'Uncomplicated firewall', status: 'active', enabled: true },
  { name: 'ssh.service', description: 'OpenBSD Secure Shell server', status: 'active', enabled: true },
  { name: 'backup.service', description: 'Nightly filesystem backup', status: 'inactive', enabled: false },
];
const response = items => ({ ok: true, json: async () => ({ services: items }) });
const decode = text => text.replace(/&(amp|quot|#39|lt|gt);/g, (_, key) => ({ amp: '&', quot: '"', '#39': "'", lt: '<', gt: '>' })[key]);
const attributes = text => Object.fromEntries([...text.matchAll(/([\w-]+)="([^"]*)"/g)].map(([, name, value]) => [name, decode(value)]));

function element(attrs = {}) {
  const listeners = new Map();
  return {
    attrs, listeners, value: '', textContent: '', disabled: false, hidden: false, style: {}, dataset: {},
    getAttribute(name) { return this.attrs[name] ?? null; },
    addEventListener(type, callback) { listeners.set(type, [...(listeners.get(type) || []), callback]); },
    dispatch(type) { for (const callback of listeners.get(type) || []) callback({ type, preventDefault() {} }); },
    click() { if (!this.disabled) this.dispatch('click'); },
    focus: vi.fn(),
  };
}

function setup(fetch = vi.fn(async () => response(services))) {
  const search = element();
  const clear = element();
  const status = element();
  const sort = element();
  sort.value = 'name-asc';
  // Parse just the rendered service-card nodes needed by this view, keeping its
  // real input/link/button listeners and refresh logic under test.
  const list = {
    cards: [], markup: '',
    get innerHTML() { return this.markup; },
    set innerHTML(markup) {
      this.markup = markup;
      this.cards = [...markup.matchAll(/<div class="service-card"([^>]*)>([\s\S]*?)(?=<div class="service-card"|$)/g)].map(([, attrText, body]) => {
        const card = element(attributes(attrText));
        card.links = [...body.matchAll(/<a ([^>]*class="service-name-link"[^>]*)>/g)].map(([, attr]) => element(attributes(attr)));
        card.buttons = [...body.matchAll(/<button ([\s\S]*?)>/g)].map(([, attr]) => {
          const button = element(attributes(attr));
          button.disabled = /\bdisabled\b/.test(attr);
          return button;
        });
        card.status = element();
        card.querySelectorAll = selector => selector === '.btn' ? card.buttons : [];
        card.querySelector = selector => selector === '.service-status' ? card.status : null;
        return card;
      });
    },
    querySelectorAll(selector) {
      if (selector === '.service-card[data-service-search]') return this.cards;
      if (selector === 'a.service-name-link') return this.cards.flatMap(card => card.links);
      if (selector === 'button[data-service-action][data-service-name]') return this.cards.flatMap(card => card.buttons);
      return [];
    },
    appendChild(card) {
      this.cards = this.cards.filter(item => item !== card);
      this.cards.push(card);
    },
  };
  const elements = { 'services-list': list, 'services-search': search, 'services-search-clear': clear, 'services-search-status': status, 'services-sort': sort };
  let currentHost = 'node-a';
  const ctx = { getCurrentAgentId: () => currentHost };
  const browser = {
    console: { error: vi.fn() }, fetch, setTimeout, clearTimeout, AbortController,
    openServiceModal: vi.fn(), showToast: vi.fn(),
    document: {
      getElementById: id => elements[id] || null,
      querySelector: selector => list.cards.find(card => selector === `.service-card[data-service-name="${card.getAttribute('data-service-name')}"]`) || null,
    },
  };
  browser.window = browser;
  vm.createContext(browser);
  vm.runInContext(read('fleet-phase3.js'), browser);
  vm.runInContext(read('fleet-phase3-host-workflows.js'), browser);
  return {
    browser, ctx, list, search, clear, status, sort, fetch,
    setHost(value) { currentHost = value; },
    load(host = currentHost) { return browser.phase3HostWorkflows.loadServices(ctx, host); },
    type(value) { search.value = value; search.dispatch('input'); },
    sortBy(value) { sort.value = value; sort.dispatch('change'); },
    visible() { return list.cards.filter(card => !card.hidden && card.style.display !== 'none').map(card => card.getAttribute('data-service-name')); },
  };
}

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

afterEach(() => vi.useRealTimers());

describe('individual host service search', () => {
  it('sorts names both ways and groups autostart states alphabetically without refetching', async () => {
    const ui = setup();
    await ui.load();
    expect(ui.visible()).toEqual(['backup.service', 'ssh.service', 'ufw.service']);
    ui.sortBy('name-desc');
    expect(ui.visible()).toEqual(['ufw.service', 'ssh.service', 'backup.service']);
    ui.sortBy('enabled-first');
    expect(ui.visible()).toEqual(['ssh.service', 'ufw.service', 'backup.service']);
    ui.sortBy('disabled-first');
    expect(ui.visible()).toEqual(['backup.service', 'ssh.service', 'ufw.service']);
    expect(ui.fetch).toHaveBeenCalledOnce();
  });

  it('uses autostart rather than running status and keeps special states separate', async () => {
    const ui = setup(vi.fn(async () => response([
      { name: 'z-disabled', enabled: false, status: 'active', unit_file_state: 'disabled' },
      { name: 'a-static', enabled: false, unit_file_state: 'static' },
      { name: 'c-masked', enabled: false, unit_file_state: 'masked' },
      { name: 'd-enabled', enabled: true, status: 'inactive', unit_file_state: 'enabled-runtime' },
      { name: 'b-socket', enabled: true, unit_file_state: 'static', socket_unit_file_state: 'enabled' },
    ])));
    await ui.load();
    ui.sortBy('enabled-first');
    expect(ui.visible()).toEqual(['b-socket', 'd-enabled', 'z-disabled', 'a-static', 'c-masked']);
    ui.sortBy('disabled-first');
    expect(ui.visible()).toEqual(['z-disabled', 'b-socket', 'd-enabled', 'a-static', 'c-masked']);
  });

  it('keeps sorting with search, refreshes and host changes, preserving existing card listeners', async () => {
    const ui = setup();
    await ui.load();
    const originalCard = ui.list.cards.find(card => card.getAttribute('data-service-name') === 'ufw.service');
    ui.type('service');
    ui.sortBy('name-desc');
    expect(ui.visible()).toEqual(['ufw.service', 'ssh.service', 'backup.service']);
    expect(ui.list.cards[0]).toBe(originalCard);
    ui.list.cards[0].links[0].click();
    expect(ui.browser.openServiceModal).toHaveBeenCalledWith('node-a', 'ufw.service');
    ui.type('ufw');
    ui.sortBy('disabled-first');
    expect(ui.visible()).toEqual(['ufw.service']);
    await ui.load();
    expect(ui.sort.value).toBe('disabled-first');
    expect(ui.visible()).toEqual(['ufw.service']);
    ui.clear.click();
    expect(ui.visible()).toEqual(['backup.service', 'ssh.service', 'ufw.service']);
    ui.setHost('node-b');
    await ui.load();
    expect(ui.sort.value).toBe('disabled-first');
    expect(ui.sort.listeners.get('change')).toHaveLength(1);
  });
  it('filters case-insensitive partial names and descriptions on input without fetching again', async () => {
    const ui = setup();
    await ui.load();
    expect(ui.status.textContent).toBe('Showing 3 of 3 services.');
    ui.type('  UfW  ');
    expect(ui.visible()).toEqual(['ufw.service']);
    expect(ui.status.textContent).toBe('Showing 1 of 3 services.');
    expect(ui.list.cards.find(card => card.getAttribute('data-service-name') === 'ssh.service').style.display).toBe('none');
    ui.type('secure SHELL');
    expect(ui.visible()).toEqual(['ssh.service']);
    ui.type('backup');
    expect(ui.visible()).toEqual(['backup.service']);
    expect(ui.fetch).toHaveBeenCalledOnce();
  });

  it('reports no matches and restores all cards when typing is cleared or Clear is clicked', async () => {
    const ui = setup();
    await ui.load();
    ui.type('no such service');
    expect(ui.visible()).toEqual([]);
    expect(ui.status.textContent).toBe('No services match your search. Showing 0 of 3 services.');
    ui.clear.click();
    expect(ui.search.value).toBe('');
    expect(ui.visible()).toHaveLength(3);
    expect(ui.clear.disabled).toBe(true);
    expect(ui.search.focus).toHaveBeenCalledOnce();
    ui.type('ufw');
    ui.type('');
    expect(ui.visible()).toHaveLength(3);
    expect(ui.fetch).toHaveBeenCalledOnce();
  });

  it('preserves search through action refresh and keeps details/actions wired to the host', async () => {
    vi.useFakeTimers();
    const ui = setup();
    await ui.load();
    ui.type('ufw');
    const card = ui.list.cards.find(item => item.getAttribute('data-service-name') === 'ufw.service');
    card.links[0].click();
    expect(ui.browser.openServiceModal).toHaveBeenCalledWith('node-a', 'ufw.service');
    card.buttons.find(button => button.getAttribute('data-service-action') === 'restart').click();
    await vi.advanceTimersByTimeAsync(1000);
    expect(ui.fetch.mock.calls.map(call => call[0])).toEqual([
      '/hosts/node-a/services', '/hosts/node-a/services/ufw.service/restart', '/hosts/node-a/services',
    ]);
    expect(ui.fetch.mock.calls[1][1].method).toBe('POST');
    expect(ui.search.value).toBe('ufw');
    expect(ui.visible()).toEqual(['ufw.service']);
    expect(ui.search.listeners.get('input')).toHaveLength(1);
    expect(ui.clear.listeners.get('click')).toHaveLength(1);
  });

  it('resets search for another host and rejects an older response arriving afterward', async () => {
    const pending = deferred();
    const fetch = vi.fn().mockImplementationOnce(() => pending.promise).mockResolvedValueOnce(response([services[1]]));
    const ui = setup(fetch);
    const oldLoad = ui.load();
    ui.type('ufw');
    ui.setHost('node-b');
    await ui.load();
    expect(ui.search.value).toBe('');
    expect(ui.visible()).toEqual(['ssh.service']);
    pending.resolve(response([services[0]]));
    await oldLoad;
    expect(ui.visible()).toEqual(['ssh.service']);
    expect(ui.status.textContent).toBe('Showing 1 of 1 services.');
    await ui.load('node-a'); // A delayed action completion must not reload the previous host.
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('ignores a superseded same-host request while applying text entered during loading', async () => {
    const pending = deferred();
    const ui = setup(vi.fn().mockImplementationOnce(() => pending.promise).mockResolvedValueOnce(response(services)));
    const oldLoad = ui.load();
    const newLoad = ui.load();
    ui.type('shell');
    await newLoad;
    expect(ui.visible()).toEqual(['ssh.service']);
    pending.resolve(response([services[0]]));
    await oldLoad;
    expect(ui.visible()).toEqual(['ssh.service']);
  });

  it('clears previous results and count on an empty or failed refresh', async () => {
    const ui = setup(vi.fn().mockResolvedValueOnce(response(services)).mockResolvedValueOnce(response([]))
      .mockRejectedValueOnce(new Error('Service query <failed>')));
    await ui.load();
    ui.type('ufw');
    await ui.load();
    expect(ui.visible()).toEqual([]);
    expect(ui.status.textContent).toBe('Showing 0 of 0 services.');
    await ui.load();
    expect(ui.status.textContent).toBe('Services could not be loaded.');
    expect(ui.list.innerHTML).toContain('Service query &lt;failed&gt;');
    expect(ui.search.value).toBe('ufw');
  });

  it('provides a labelled search field with accessible live feedback in the real services tab', () => {
    const html = read('index.html');
    const tab = html.slice(html.indexOf('id="services-tab"'), html.indexOf('id="firewall-tab"'));
    expect(tab).toContain('for="services-search"');
    expect(tab).toMatch(/id="services-search"[\s\S]*?type="search"[\s\S]*?aria-controls="services-list"/);
    expect(tab).toMatch(/id="services-search-status"[^>]*role="status"[^>]*aria-live="polite"/);
    expect(tab).toContain('aria-describedby="services-search-status"');
    expect(tab).toContain('for="services-sort"');
    expect(tab).toMatch(/id="services-sort"[^>]*aria-controls="services-list"/);
  });
});

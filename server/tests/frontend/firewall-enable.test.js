import { afterEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('../../app/templates/fleet-firewall-management-ui.js', import.meta.url), 'utf8');
const html = fs.readFileSync(new URL('../../app/templates/index.html', import.meta.url), 'utf8');
const inactive = { agent_id: 'node-1', hostname: 'slave1', backend: 'ufw', status: 'inactive', rules: [] };
const active = { agent_id: 'node-2', hostname: 'slave2', backend: 'firewalld', status: 'running', rules: [] };
const response = (data, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => data });

function setup({ canManage = true, items = [inactive, active] } = {}) {
  const node = () => ({ value: '', textContent: '', disabled: false, checked: false, events: {},
    addEventListener(type, listener) { this.events[type] = listener; },
  });
  const elements = Object.fromEntries(['refresh', 'select-all', 'check-all', 'enable', 'disable', 'allow', 'deny', 'delete',
    'status', 'result', 'table-body', 'port', 'service', 'protocol', 'source'].map(name => [name, node()]));
  let markup = '';
  let checks = [];
  Object.defineProperty(elements['table-body'], 'innerHTML', {
    get: () => markup,
    set(value) {
      markup = value;
      checks = Array.from(value.matchAll(/<input[^>]*data-firewall-agent-id="([^"]+)"[^>]*>/g), match => {
        const check = node();
        check.disabled = match[0].includes('disabled');
        check.getAttribute = key => key === 'data-firewall-agent-id' ? match[1] : null;
        return check;
      });
    },
  });
  elements['table-body'].querySelectorAll = selector => checks.filter(check => !selector.endsWith(':checked') || check.checked);
  const fetch = vi.fn(async url => {
    if (url.startsWith('/reports/firewall-rules?')) return response({ items });
    if (url === '/reports/firewall-rules/enable') return response({ job_id: 'job-1', targets: ['node-1'] });
    if (url === '/reports/firewall-rules/disable') return response({ job_id: 'job-2', targets: ['node-2'] });
    if (url === '/jobs/job-1') return response({ done: true, runs: [{ agent_id: 'node-1', status: 'success' }] });
    if (url === '/jobs/job-2') return response({ done: true, runs: [{ agent_id: 'node-2', status: 'success' }] });
    throw new Error(`Unexpected URL: ${url}`);
  });
  const browser = { document: { getElementById: id => elements[id.replace('firewall-management-', '')] || null },
    fetch, confirm: vi.fn(() => true), console: { error: vi.fn() }, setTimeout, clearTimeout, AbortController, Date };
  browser.window = browser;
  vm.runInNewContext(source, browser);
  const showToast = vi.fn();
  browser.fleetFirewallManagementUi.initFirewallManagementControls({ getCurrentPermissions: () => ({ can_manage_services: canManage }), showToast });
  const click = name => elements[name].events.click({ preventDefault() {} });
  const select = id => {
    const check = checks.find(check => check.getAttribute('data-firewall-agent-id') === id);
    check.checked = true;
    check.events.change();
  };
  const scan = async () => {
    click('refresh');
    await vi.waitFor(() => {
      expect(elements.refresh.disabled).toBe(false);
      expect(elements['table-body'].innerHTML).toContain('data-firewall-agent-id');
    });
    showToast.mockClear();
  };
  return { browser, elements, fetch, showToast, click, select, scan };
}

afterEach(() => vi.useRealTimers());

describe('fleet firewall state changes', () => {
  it('provides enable/disable actions and a durable result area in the real template', () => {
    expect(html).toMatch(/id="firewall-management-enable"[^>]*disabled>Enable selected/);
    expect(html).toMatch(/id="firewall-management-disable"[^>]*disabled>Disable selected/);
    expect(html).toMatch(/id="firewall-management-result"[^>]*role="status"[^>]*aria-live="polite"/);
  });

  it('shows the full firewalld management rule instead of only its allow action', async () => {
    const s = setup({ items: [{ ...active, rules: [{ action: 'allow', raw: 'rule source address="192.0.2.10" port port="2222" protocol="tcp" accept' }] }] });
    await s.scan();
    expect(s.elements['table-body'].innerHTML).toContain('source address=&quot;192.0.2.10&quot;');
    expect(s.elements['table-body'].innerHTML).toContain('port=&quot;2222&quot;');
  });

  it('enables only selected inactive firewalls without requiring or sending rule fields', async () => {
    const s = setup();
    expect(s.elements.enable.disabled).toBe(true);
    await s.scan();
    s.select('node-2');
    expect(s.elements.enable.disabled).toBe(true);
    s.select('node-1');
    expect(s.elements.enable.disabled).toBe(false);
    s.elements.port.value = 'invalid';
    s.elements.service.value = 'unrelated rule';
    s.click('enable');
    await vi.waitFor(() => expect(s.elements.result.textContent).toContain('Enable: 1 succeeded, 0 failed.'));
    expect(s.browser.confirm).toHaveBeenCalledWith(expect.stringContaining('slave1'));
    const post = s.fetch.mock.calls.find(([url]) => url === '/reports/firewall-rules/enable');
    expect(JSON.parse(post[1].body)).toEqual({ agent_ids: ['node-1'] });
    expect(s.fetch.mock.calls.filter(([url]) => url.startsWith('/reports/firewall-rules?'))).toHaveLength(2);
    expect(s.elements.result.textContent).toContain('Enable: 1 succeeded');
    expect(s.showToast).toHaveBeenCalledWith('Enable: 1 succeeded, 0 failed.', 'success');
  });

  it.each([['enable', 'node-1'], ['disable', 'node-2']])('blocks readonly users and cancelled %s confirmations', async (action, agentId) => {
    const readonly = setup({ canManage: false });
    await readonly.scan();
    readonly.select(agentId);
    readonly.click(action);
    expect(readonly.elements[action].disabled).toBe(true);
    expect(readonly.fetch).toHaveBeenCalledTimes(1);
    const cancelled = setup();
    await cancelled.scan();
    cancelled.select(agentId);
    cancelled.browser.confirm.mockReturnValue(false);
    cancelled.click(action);
    expect(cancelled.fetch).toHaveBeenCalledTimes(1);
  });

  it('keeps controls disabled during a pending action and prevents duplicate requests', async () => {
    const s = setup();
    await s.scan();
    s.select('node-1');
    let finish;
    const original = s.fetch.getMockImplementation();
    s.fetch.mockImplementation((url, options) => url.endsWith('/enable') ? new Promise(resolve => { finish = resolve; }) : original(url, options));
    s.click('enable');
    s.select('node-2');
    for (const name of ['enable', 'disable', 'allow', 'deny', 'delete', 'refresh', 'select-all', 'check-all']) expect(s.elements[name].disabled).toBe(true);
    s.click('enable');
    s.click('disable');
    s.click('refresh');
    expect(s.fetch.mock.calls.filter(([url]) => url.endsWith('/enable'))).toHaveLength(1);
    expect(s.fetch.mock.calls.some(([url]) => url.endsWith('/disable'))).toBe(false);
    finish(response({ job_id: 'job-1', targets: ['node-1'] }));
    await vi.waitFor(() => expect(s.elements.refresh.disabled).toBe(false));
  });

  it('disables only selected active hosts without rule fields and refreshes their state', async () => {
    const s = setup();
    expect(s.elements.disable.disabled).toBe(true);
    await s.scan();
    s.select('node-1');
    expect(s.elements.disable.disabled).toBe(true);
    s.select('node-2');
    expect(s.elements.disable.disabled).toBe(false);
    const original = s.fetch.getMockImplementation();
    s.fetch.mockImplementation((url, options) => url.startsWith('/reports/firewall-rules?')
      ? response({ items: [inactive, { ...active, status: 'inactive' }] }) : original(url, options));
    s.elements.port.value = 'invalid';
    s.elements.service.value = 'irrelevant';
    s.click('disable');
    await vi.waitFor(() => expect(s.elements.result.textContent).toContain('Disable: 1 succeeded, 0 failed.'));
    const confirmation = s.browser.confirm.mock.calls[0][0];
    expect(confirmation).toContain('slave2');
    expect(confirmation).not.toContain('slave1');
    expect(confirmation).toContain('Host firewall protection will stop');
    expect(confirmation).toContain('Saved rules will be kept.');
    const post = s.fetch.mock.calls.find(([url]) => url === '/reports/firewall-rules/disable');
    expect(JSON.parse(post[1].body)).toEqual({ agent_ids: ['node-2'] });
    expect(s.showToast).toHaveBeenCalledWith('Disable: 1 succeeded, 0 failed.', 'success');
    s.select('node-2');
    expect(s.elements.disable.disabled).toBe(true);
    expect(s.elements.enable.disabled).toBe(false);
  });

  it('keeps a disable failure visible after the rescan', async () => {
    const s = setup();
    await s.scan();
    s.select('node-2');
    const original = s.fetch.getMockImplementation();
    s.fetch.mockImplementation((url, options) => url === '/jobs/job-2'
      ? response({ done: true, runs: [{ agent_id: 'node-2', status: 'failed', error: 'firewalld remains active', stderr_tail: 'stop failed' }] }) : original(url, options));
    s.click('disable');
    await vi.waitFor(() => expect(s.elements.result.textContent).toContain('slave2: firewalld remains active: stop failed'));
    expect(s.showToast).toHaveBeenCalledWith('Disable: 0 succeeded, 1 failed.', 'error');
    expect(s.elements.refresh.disabled).toBe(false);
  });

  it('retains host-specific failures after the status rescan and never toasts them as success', async () => {
    const s = setup();
    const original = s.fetch.getMockImplementation();
    s.fetch.mockImplementation((url, options) => url === '/jobs/job-1'
      ? response({ done: true, runs: [{ agent_id: 'node-1', status: 'failed', error: 'Cannot preserve SSH <access>', stdout: null, stderr_tail: 'Permission denied by sudo policy' }] }) : original(url, options));
    await s.scan();
    s.select('node-1');
    s.click('enable');
    await vi.waitFor(() => expect(s.elements.result.textContent).toContain('slave1: Cannot preserve SSH <access>'));
    expect(s.elements.result.textContent).toContain('0 succeeded, 1 failed');
    expect(s.elements.result.textContent).toContain('Permission denied by sudo policy');
    expect(s.showToast).toHaveBeenCalledWith('Enable: 0 succeeded, 1 failed.', 'error');
    expect(s.showToast.mock.calls.some(([, kind]) => kind === 'success')).toBe(false);
  });

  it('does not report activation as failed when only its rescan fails', async () => {
    const s = setup();
    await s.scan();
    const original = s.fetch.getMockImplementation();
    s.fetch.mockImplementation((url, options) => url.startsWith('/reports/firewall-rules?') ? response({ detail: 'Scan unavailable' }, 503) : original(url, options));
    s.select('node-1');
    s.click('enable');
    await vi.waitFor(() => expect(s.elements.result.textContent).toContain('Status refresh failed: Scan unavailable'));
    expect(s.elements.result.textContent).toContain('Enable: 1 succeeded');
    expect(s.elements.status.textContent).toBe('Status refresh failed');
  });

  it('reports an unknown job outcome when polling fails after queueing', async () => {
    const s = setup();
    const original = s.fetch.getMockImplementation();
    s.fetch.mockImplementation((url, options) => url === '/jobs/job-1' ? response({ detail: 'Temporarily unavailable' }, 503) : original(url, options));
    await s.scan();
    s.select('node-1');
    s.click('enable');
    await vi.waitFor(() => expect(s.elements.result.textContent).toContain('Could not confirm job job-1; it may still be running.'));
    expect(s.elements.status.textContent).toBe('Job status unavailable');
    expect(s.showToast.mock.calls.some(([, kind]) => kind === 'success')).toBe(false);
  });

  it.each([[403, 'Enable request failed'], [503, 'Could not confirm enable request']])('handles an activation HTTP %i without encouraging duplicate jobs', async (status, message) => {
    const s = setup();
    await s.scan();
    s.select('node-1');
    s.fetch.mockResolvedValue(response({ detail: 'Request unavailable' }, status));
    s.click('enable');
    await vi.waitFor(() => expect(s.elements.result.textContent).toContain(message));
    expect(s.elements.refresh.disabled).toBe(false);
  });

  it('keeps partial results on polling timeout instead of treating unfinished work as successful', async () => {
    vi.useFakeTimers();
    const s = setup();
    s.fetch.mockResolvedValue(response({ done: false, runs: [
      { agent_id: 'node-1', status: 'success' }, { agent_id: 'node-2', status: 'running' },
    ] }));
    const pending = s.browser.fleetFirewallManagementUi.waitForJobDone('job-1', 50);
    await vi.advanceTimersByTimeAsync(1500);
    const result = await pending;
    expect(result.done).toBe(false);
    expect(result.success).toEqual(['node-1']);
    expect(result.total).toBe(2);
  });

  it.each(['headers', 'body'])('aborts a stalled job-status %s at the polling deadline', async (phase) => {
    vi.useFakeTimers();
    const s = setup();
    s.fetch.mockImplementation((url, options) => {
      const waitUntilAborted = () => new Promise((resolve, reject) => {
        options.signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
      });
      return phase === 'headers' ? waitUntilAborted() : { ok: true, json: waitUntilAborted };
    });
    const pending = expect(s.browser.fleetFirewallManagementUi.waitForJobDone('job-1', 50)).rejects.toThrow('Request timed out');
    await vi.advanceTimersByTimeAsync(50);
    await pending;
    expect(s.fetch.mock.calls[0][1].signal.aborted).toBe(true);
  });

  it('restores controls when an activation request stalls and warns that its outcome is unknown', async () => {
    vi.useFakeTimers();
    const s = setup();
    await s.scan();
    s.select('node-1');
    s.fetch.mockImplementation((url, options) => new Promise((resolve, reject) => {
      options.signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
    }));
    s.click('enable');
    await vi.advanceTimersByTimeAsync(15000);
    expect(s.elements.result.textContent).toContain('Scan hosts again before retrying. Request timed out');
    expect(s.elements.refresh.disabled).toBe(false);
    expect(s.elements.enable.disabled).toBe(false);
  });
});

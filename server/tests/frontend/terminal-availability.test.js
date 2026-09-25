import { it, expect, vi } from 'vitest';
import fs from 'node:fs';
import vm from 'node:vm';

const read = name => fs.readFileSync(new URL(`../../app/templates/${name}`, import.meta.url), 'utf8');
function setup() {
  const badge = {};
  const button = { setAttribute: vi.fn() };
  const browser = { document: { getElementById: id => id === 'host-terminal-policy' ? badge : button } };
  browser.window = browser;
  vm.createContext(browser);
  vm.runInContext(read('fleet-phase3-host-actions.js'), browser);
  return { browser, badge, button, api: browser.phase3HostActions };
}

it('disables Console with a Master configuration explanation even for an admin', () => {
  const { api, badge, button } = setup();
  const result = api.updateTerminalAccessIndicator({}, { role: 'admin', can_use_terminal: true, terminal_configured: false });
  expect(result.blocked).toBe(true);
  expect(button.disabled).toBe(true);
  expect(button.setAttribute).toHaveBeenCalledWith('aria-disabled', 'true');
  expect(badge.textContent).toBe('Terminal: unavailable on Master');
  expect(badge.title).toContain('install.sh --advanced');
});

it('distinguishes account permission and host policy from Master availability', () => {
  const { api } = setup();
  const viewer = api.terminalAccessState({}, { role: 'viewer', can_use_terminal: false, terminal_configured: true });
  expect(viewer.reason).toBe('Your account does not have Console permission.');
  const operator = api.terminalAccessState({ labels: { terminal_access: 'admin' } }, { role: 'operator', can_use_terminal: true, terminal_configured: true });
  expect(operator.label).toBe('Terminal: admins only');
  expect(operator.blocked).toBe(true);
  expect(api.terminalAccessState({}, { role: 'operator', can_use_terminal: true, terminal_configured: true }).blocked).toBe(false);
});

it('does not construct xterm or a WebSocket when Console is unavailable', () => {
  const { browser } = setup();
  vm.runInContext(read('fleet-terminal-ui.js'), browser);
  const getTerm = vi.fn();
  const showToast = vi.fn();
  browser.fleetTerminalUi.connect({ getTerminalAccess: () => ({ blocked: true, reason: 'Console is not configured on the Master.' }), getTerm, showToast }, 'node-1');
  expect(getTerm).not.toHaveBeenCalled();
  expect(showToast).toHaveBeenCalledWith('Console is not configured on the Master.', 'error');
});

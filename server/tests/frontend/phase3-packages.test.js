import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

function loadBrowserScript(filePath, baseWindow = {}) {
  const code = fs.readFileSync(filePath, 'utf8');
  const windowObj = {
    ...baseWindow,
    window: null,
    document: baseWindow.document || {},
    console,
    setTimeout,
    clearTimeout,
  };
  windowObj.window = windowObj;
  const context = vm.createContext(windowObj);
  vm.runInContext(code, context, { filename: filePath });
  return context;
}

describe('phase3 packages UI', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const pkgPath = path.join(root, 'server/app/templates/fleet-phase3-packages.js');

  it('renders CVE chip and applies cve-only filter', async () => {
    const elements = {
      'packages-list': { innerHTML: '' },
      'packages-meta': { textContent: '' },
      'package-info': { innerHTML: '' },
    };

    const ctx = loadBrowserScript(pkgPath, {
      document: {
        getElementById: (id) => elements[id] || null,
        querySelectorAll: () => [],
      },
      fetch: async () => ({
        ok: true,
        json: async () => ({
          total: 2,
          packages: [
            { name: 'openssl', version: '1.0', cves: ['CVE-2024-0001', 'CVE-2024-0002'] },
            { name: 'curl', version: '1.0', cves: [] },
          ],
        }),
      }),
      escapeHtml: (s) => String(s),
      URLSearchParams,
    });

    await ctx.phase3Packages.loadPackages({ getState: () => ({ packagesCvesOnly: true, packagesUpdatesOnly: false, selectedPackages: new Set() }) }, 'agent-1');

    expect(elements['packages-list'].innerHTML).toContain('openssl');
    expect(elements['packages-list'].innerHTML).toContain('CVE 2');
    expect(elements['packages-list'].innerHTML).not.toContain('curl');
  });
});

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

    await ctx.phase3Packages.loadPackages({ getState: () => ({ packagesCvesOnly: true, packagesUpdatesOnly: false, packagesSortBy: 'name', selectedPackages: new Set() }) }, 'agent-1');

    expect(elements['packages-list'].innerHTML).toContain('openssl');
    expect(elements['packages-list'].innerHTML).toContain('CVE 2');
    expect(elements['packages-list'].innerHTML).not.toContain('curl');
  });

  it('sorts by cve count desc and asc', async () => {
    const elements = {
      'packages-list': { innerHTML: '' },
      'packages-meta': { textContent: '' },
      'package-info': { innerHTML: '' },
    };

    const baseWindow = {
      document: {
        getElementById: (id) => elements[id] || null,
        querySelectorAll: () => [],
      },
      fetch: async () => ({
        ok: true,
        json: async () => ({
          total: 3,
          packages: [
            { name: 'b', version: '1.0', cves: ['CVE-1'] },
            { name: 'a', version: '1.0', cves: ['CVE-1', 'CVE-2'] },
            { name: 'c', version: '1.0', cves: [] },
          ],
        }),
      }),
      escapeHtml: (s) => String(s),
      URLSearchParams,
    };

    const ctx = loadBrowserScript(pkgPath, baseWindow);

    await ctx.phase3Packages.loadPackages({ getState: () => ({ packagesCvesOnly: false, packagesUpdatesOnly: false, packagesSortBy: 'cve-desc', selectedPackages: new Set() }) }, 'agent-1');
    const descHtml = elements['packages-list'].innerHTML;
    const descOrder = Array.from(new Set(Array.from(descHtml.matchAll(/data-pkg="([^"]+)"/g)).map((m) => m[1])));
    expect(descOrder).toEqual(['a', 'b', 'c']);

    await ctx.phase3Packages.loadPackages({ getState: () => ({ packagesCvesOnly: false, packagesUpdatesOnly: false, packagesSortBy: 'cve-asc', selectedPackages: new Set() }) }, 'agent-1');
    const ascHtml = elements['packages-list'].innerHTML;
    const ascOrder = Array.from(new Set(Array.from(ascHtml.matchAll(/data-pkg="([^"]+)"/g)).map((m) => m[1])));
    expect(ascOrder).toEqual(['c', 'b', 'a']);
  });

  it('shows full CVE IDs in package details for selected package', async () => {
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
      fetch: async (url) => {
        if (String(url).includes('/info')) {
          return {
            ok: true,
            json: async () => ({ name: 'openssl', installed_version: '1.0', candidate_version: '1.1', summary: 'sum', description: 'desc' }),
          };
        }
        return {
          ok: true,
          json: async () => ({
            total: 1,
            packages: [
              { name: 'openssl', version: '1.0', cves: ['CVE-2024-0001', 'CVE-2024-0002'] },
            ],
          }),
        };
      },
      escapeHtml: (s) => String(s),
      URLSearchParams,
    });

    await ctx.phase3Packages.loadPackages({ getState: () => ({ packagesCvesOnly: false, packagesUpdatesOnly: false, packagesSortBy: 'name', selectedPackages: new Set(), currentPackageName: null }) }, 'agent-1');
    await ctx.phase3Packages.loadPackageInfo({ getState: () => ({}) }, 'agent-1', 'openssl');

    expect(elements['package-info'].innerHTML).toContain('CVE-2024-0001');
    expect(elements['package-info'].innerHTML).toContain('CVE-2024-0002');
  });
});

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

function loadScript(filePath) {
  const code = fs.readFileSync(filePath, 'utf8');
  const windowObj = {
    window: null,
    document: {},
    console,
  };
  windowObj.window = windowObj;
  const context = vm.createContext(windowObj);
  vm.runInContext(code, context, { filename: filePath });
  return context;
}

describe('phase3 host metadata payload normalization', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const scriptPath = path.join(root, 'server/app/templates/fleet-phase3-host-actions.js');
  const indexPath = path.join(root, 'server/app/templates/index.html');

  it('trims hostname/role/owner and drops blank env keys', () => {
    const ctx = loadScript(scriptPath);
    const fn = ctx.phase3HostActions.normalizeHostMetadataPayload;

    const got = fn({
      hostname: '  web-01  ',
      role: '  app  ',
      owner: '  imre  ',
      env: {
        ' FOO ': '  bar ',
        '': 'x',
        '   ': 'y',
      },
    });

    expect(got).toEqual({
      hostname: 'web-01',
      role: 'app',
      owner: 'imre',
      env: { FOO: 'bar' },
    });
  });

  it('preserves explicit blank owner so metadata save can clear host owner access', () => {
    const ctx = loadScript(scriptPath);
    const fn = ctx.phase3HostActions.normalizeHostMetadataPayload;

    const got = fn({
      hostname: 'srv-1',
      role: 'db',
      owner: '   ',
      env: {},
    });

    expect(got.owner).toBe('');
  });

  it('renders a host owner field in the metadata editor', () => {
    const html = fs.readFileSync(indexPath, 'utf8');
    expect(html).toContain('id="host-meta-owner"');
    expect(html).toContain('Owner username (blank to clear)');
  });
});

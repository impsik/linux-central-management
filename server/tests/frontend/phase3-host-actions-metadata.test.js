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

  it('trims hostname/role/owner and drops blank env keys', () => {
    const ctx = loadScript(scriptPath);
    const fn = ctx.phase3HostActions.normalizeHostMetadataPayload;

    const got = fn({
      hostname: '  web-01  ',
      role: '  app  ',
      owner: '  alice  ',
      env: {
        ' FOO ': '  bar ',
        '': 'x',
        '   ': 'y',
      },
    });

    expect(got).toEqual({
      hostname: 'web-01',
      role: 'app',
      owner: 'alice',
      env: { FOO: 'bar' },
    });
  });
});

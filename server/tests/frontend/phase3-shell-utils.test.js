import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('phase3 shell utils extraction', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const shellUtilsPath = path.join(root, 'server/app/templates/fleet-phase3-shell-utils.js');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const shellUtilsSrc = fs.readFileSync(shellUtilsPath, 'utf8');
  const indexSrc = fs.readFileSync(indexPath, 'utf8');

  it('loads shell helpers from a dedicated module instead of inline shell code', () => {
    expect(indexSrc).toContain('/assets/fleet-phase3-shell-utils.js');
    expect(indexSrc).not.toContain('function safeInit(name, fn)');
    expect(indexSrc).not.toContain('function initGlobalSearch()');
  });

  it('provides safeInit and initGlobalSearch in the extracted module', () => {
    expect(shellUtilsSrc).toContain('function safeInit(name, fn)');
    expect(shellUtilsSrc).toContain('function initGlobalSearch()');
    expect(shellUtilsSrc).toContain("console.error('[init failed]', name, e)");
    expect(shellUtilsSrc).toContain("document.getElementById('global-search')");
    expect(shellUtilsSrc).toContain('safeInit(name, fn)'.split('(')[0]);
  });
});

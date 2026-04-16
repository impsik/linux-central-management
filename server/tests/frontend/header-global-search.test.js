import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('header global search removal', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const src = fs.readFileSync(indexPath, 'utf8');

  it('does not render the removed global search input or init hook', () => {
    expect(src).not.toContain('id="global-search"');
    expect(src).not.toContain('Search hosts, jobs, packages');
    expect(src).not.toContain('function initGlobalSearch()');
    expect(src).not.toContain("safeInit('initGlobalSearch', initGlobalSearch);");
  });
});

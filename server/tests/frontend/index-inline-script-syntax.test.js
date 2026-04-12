import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('index inline script syntax', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const indexSrc = fs.readFileSync(indexPath, 'utf8');

  it('has a parseable final inline script block', () => {
    const matches = [...indexSrc.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)];
    expect(matches.length).toBeGreaterThan(0);
    const inlineScript = matches[matches.length - 1]?.[1] || '';
    expect(inlineScript).toContain('bootPhase3AppShell()');
    expect(() => new Function(inlineScript)).not.toThrow();
  });
});

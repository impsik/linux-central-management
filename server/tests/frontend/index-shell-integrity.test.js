import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('index shell integrity', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const src = fs.readFileSync(path.join(root, 'server/app/templates/index.html'), 'utf8');

  it('ends with expected closing tags', () => {
    const trimmed = src.trim();
    expect(trimmed.endsWith('</html>')).toBe(true);
    expect(trimmed.includes('</body>')).toBe(true);
    expect(trimmed.includes('</script>')).toBe(true);
  });

  it('contains boot-critical markers', () => {
    expect(src).toContain('id="settings-btn"');
    expect(src).toContain('id="nav-overview"');
    expect(src).toContain('safeInit(');
    expect(src).toContain('bootPhase3AppShell()');
  });
});

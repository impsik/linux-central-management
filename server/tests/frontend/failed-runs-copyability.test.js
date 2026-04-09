import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('failed runs copyability UI', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const src = fs.readFileSync(indexPath, 'utf8');

  it('includes failed run detail modal copy affordances', () => {
    expect(src).toContain('id="failed-run-detail-modal"');
    expect(src).toContain('id="failed-run-detail-modal-title"');
    expect(src).toContain('id="failed-run-detail-modal-output"');
    expect(src).toContain('id="failed-run-detail-modal-copy"');
  });

  it('does not use legacy alert-based failed run details', () => {
    expect(src).not.toContain('alert(detail);');
  });
});

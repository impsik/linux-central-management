import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('failed runs copyability UI', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const src = fs.readFileSync(indexPath, 'utf8');

  it('includes failed runs copy affordances and detail modal', () => {
    expect(src).toContain('id="failed-runs-copy-visible"');
    expect(src).toContain('data-copy-failed-run');
    expect(src).toContain('id="failed-run-detail-modal"');
    expect(src).toContain('id="failed-run-detail-modal-copy"');
  });

  it('uses failed run detail modal instead of alert for row details', () => {
    expect(src).toContain('window.openFailedRunDetailModal');
    expect(src).not.toContain('alert(detail);');
  });
});

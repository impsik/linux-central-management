import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('failed runs copyability UI', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const modalsPath = path.join(root, 'server/app/templates/partials/modals.html');
  const src = fs.readFileSync(indexPath, 'utf8');
  const modalsSrc = fs.readFileSync(modalsPath, 'utf8');

  it('includes failed run detail modal copy affordances', () => {
    expect(src).toContain('__PARTIAL_MODALS__');
    expect(modalsSrc).toContain('id="failed-run-detail-modal"');
    expect(modalsSrc).toContain('id="failed-run-detail-modal-title"');
    expect(modalsSrc).toContain('id="failed-run-detail-modal-output"');
    expect(modalsSrc).toContain('id="failed-run-detail-modal-copy"');
  });

  it('does not use legacy alert-based failed run details', () => {
    expect(src).not.toContain('alert(detail);');
    expect(modalsSrc).not.toContain('alert(detail);');
  });
});

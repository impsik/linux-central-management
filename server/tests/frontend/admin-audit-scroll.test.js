import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('admin audit scroll wrapper', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const adminPartialPath = path.join(root, 'server/app/templates/partials/admin-panel.html');
  const cssPath = path.join(root, 'server/app/templates/fleet-ui.css');
  const adminPartial = fs.readFileSync(adminPartialPath, 'utf8');
  const css = fs.readFileSync(cssPath, 'utf8');

  it('wraps the audit table in a dedicated scroll container', () => {
    expect(adminPartial).toContain('class="admin-audit-table-wrap"');
  });

  it('caps audit table height and enables scrolling', () => {
    expect(css).toContain('.admin-audit-table-wrap');
    expect(css).toContain('max-height: 29rem;');
    expect(css).toContain('overflow: auto;');
  });
});

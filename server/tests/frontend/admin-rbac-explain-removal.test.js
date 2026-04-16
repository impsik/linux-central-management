import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('admin RBAC access explain removal', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const src = fs.readFileSync(indexPath, 'utf8');

  it('does not render the RBAC access explain admin box or related controls', () => {
    expect(src).not.toContain('RBAC access explain');
    expect(src).not.toContain('admin-rbac-explain-card');
    expect(src).not.toContain('admin-rbac-explain-run');
    expect(src).not.toContain('admin-rbac-user');
    expect(src).not.toContain('admin-rbac-host');
    expect(src).not.toContain('data-user-rbac-explain');
    expect(src).not.toContain('initRbacExplain');
  });
});

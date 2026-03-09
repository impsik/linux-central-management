import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('overview cards cleanup', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const overviewPath = path.join(root, 'server/app/templates/fleet-phase3-overview.js');
  const indexSrc = fs.readFileSync(indexPath, 'utf8');
  const overviewSrc = fs.readFileSync(overviewPath, 'utf8');

  it('does not render backup verification card in overview', () => {
    expect(indexSrc).not.toContain('id="overview-backup-verification"');
    expect(indexSrc).not.toContain('Backup verification');
  });

  it('does not include backup verification API wiring', () => {
    expect(overviewSrc).not.toContain('/backup-verification/latest');
    expect(overviewSrc).not.toContain('/backup-verification/policy');
  });
});

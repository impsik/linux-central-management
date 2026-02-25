import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('backup verification overview card', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const overviewPath = path.join(root, 'server/app/templates/fleet-phase3-overview.js');
  const indexSrc = fs.readFileSync(indexPath, 'utf8');
  const overviewSrc = fs.readFileSync(overviewPath, 'utf8');

  it('renders backup verification card in overview', () => {
    expect(indexSrc).toContain('id="overview-backup-verification"');
    expect(indexSrc).toContain('Backup verification');
  });

  it('loads latest backup verification API and links run details', () => {
    expect(overviewSrc).toContain('/backup-verification/latest');
    expect(overviewSrc).toContain('/backup-verification/runs/');
    expect(overviewSrc).toContain('fleet_backup_verification_stale_hours_v1');
  });

  it('includes policy configure + run-now controls', () => {
    expect(overviewSrc).toContain('/backup-verification/policy');
    expect(overviewSrc).toContain('/backup-verification/policy/run-now');
    expect(overviewSrc).toContain('backup-verification-policy-save');
    expect(overviewSrc).toContain('backup-verification-policy-run-now');
  });
});

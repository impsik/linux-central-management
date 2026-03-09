import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('overview rollout controls cleanup', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const overviewPath = path.join(root, 'server/app/templates/fleet-phase3-overview.js');
  const indexSrc = fs.readFileSync(indexPath, 'utf8');
  const overviewSrc = fs.readFileSync(overviewPath, 'utf8');

  it('does not render rollout controls card in overview', () => {
    expect(indexSrc).not.toContain('id="rollout-controls-card"');
    expect(indexSrc).not.toContain('Rollout controls');
  });

  it('does not wire rollout controls handlers', () => {
    expect(overviewSrc).not.toContain('rollout-campaign-id');
    expect(overviewSrc).not.toContain('/patching/campaigns/${encodeURIComponent(campaignId)}/rollout');
    expect(overviewSrc).not.toContain('Rollout ${action} OK');
  });
});

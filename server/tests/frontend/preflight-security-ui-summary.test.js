import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('security campaign preflight ui surfacing', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const overviewPath = path.join(root, 'server/app/templates/fleet-phase3-overview.js');
  const src = fs.readFileSync(overviewPath, 'utf8');

  it('runs security-campaign preflight before campaign creation', () => {
    expect(src).toContain("fetch('/jobs/preflight'");
    expect(src).toContain("body: JSON.stringify({ action: 'security-campaign', agent_ids: agentIds })");
  });

  it('surfaces the reusable preflight modal for security campaigns', () => {
    expect(src).toContain('const preflightMsg = summarizePreflight(preflightData);');
    expect(src).toContain("w.openPreflightResultsModal(preflightData, `security-campaign dry run · ${agentIds.length} host(s)`);");
  });
});

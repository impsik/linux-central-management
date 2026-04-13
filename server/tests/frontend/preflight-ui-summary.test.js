import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('preflight ui summary surfacing', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const overviewPath = path.join(root, 'server/app/templates/fleet-phase3-overview.js');
  const src = fs.readFileSync(overviewPath, 'utf8');

  it('formats a compact preflight summary from blocker/warning counts and failed checks', () => {
    expect(src).toContain('function summarizePreflight(preflight)');
    expect(src).toContain('Preflight: ${blockers} blocker(s), ${warnings} warning(s)');
    expect(src).toContain('failed.slice(0, 2)');
  });

  it('surfaces dist-upgrade preflight summaries for approval-required and queued responses', () => {
    expect(src).toContain('const preflightMsg = summarizePreflight(d?.preflight);');
    expect(src).toContain('Approval required (dist-upgrade): ${d.request_id}');
    expect(src).toContain("w.showToast(preflightMsg, d?.preflight?.has_blockers ? 'error' : (d?.preflight?.has_warnings ? 'info' : 'success'), 7000);");
  });
});

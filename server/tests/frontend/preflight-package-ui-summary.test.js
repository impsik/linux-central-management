import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('package preflight ui summary surfacing', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const packagesPath = path.join(root, 'server/app/templates/fleet-phase3-packages.js');
  const src = fs.readFileSync(packagesPath, 'utf8');

  it('formats a compact preflight summary in the packages module', () => {
    expect(src).toContain('function summarizePreflight(preflight)');
    expect(src).toContain('Preflight: ${blockers} blocker(s), ${warnings} warning(s)');
  });

  it('runs pkg-upgrade dry-run preflight before direct package upgrade execution and surfaces the summary toast', () => {
    expect(src).toContain("fetch('/jobs/pkg-upgrade'");
    expect(src).toContain("body: JSON.stringify({ agent_ids: [st.currentAgentId], packages: selected, dry_run: true })");
    expect(src).toContain("const preflightMsg = summarizePreflight(dryRunData.preflight);");
    expect(src).toContain("w.showToast(preflightMsg, dryRunData.preflight?.has_blockers ? 'error' : (dryRunData.preflight?.has_warnings ? 'info' : 'success'), 7000);");
  });
});

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('owner host control surface stays ungated in UI', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const workflowsPath = path.join(root, 'server/app/templates/fleet-phase3-host-workflows.js');
  const hostActionsPath = path.join(root, 'server/app/templates/fleet-phase3-host-actions.js');
  const overviewPath = path.join(root, 'server/app/templates/fleet-phase3-overview.js');
  const workflowsSrc = fs.readFileSync(workflowsPath, 'utf8');
  const hostActionsSrc = fs.readFileSync(hostActionsPath, 'utf8');
  const overviewSrc = fs.readFileSync(overviewPath, 'utf8');

  it('does not gate service action buttons behind a coarse role flag in the UI', () => {
    expect(workflowsSrc).not.toContain('can_manage_services');
    expect(workflowsSrc).toContain('data-service-action="start"');
    expect(workflowsSrc).toContain('data-service-action="restart"');
    expect(workflowsSrc).toContain('data-service-action="stop"');
  });

  it('does not gate host metadata save behind admin-only UI logic', () => {
    expect(hostActionsSrc).toContain("const r = await fetch(`/hosts/${encodeURIComponent(agentId)}/metadata`, {");
    expect(hostActionsSrc).not.toContain('can_manage_users');
  });

  it('keeps reboot action rendered from host state rather than coarse role gating', () => {
    expect(overviewSrc).toContain('host-reboot-btn');
    expect(overviewSrc).not.toContain('can_manage_packages');
  });
});

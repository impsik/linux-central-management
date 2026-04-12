import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('phase3 cron ui extraction', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const modulePath = path.join(root, 'server/app/templates/fleet-phase3-cron-ui.js');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const moduleSrc = fs.readFileSync(modulePath, 'utf8');
  const indexSrc = fs.readFileSync(indexPath, 'utf8');

  it('loads cron helpers from a dedicated module and keeps only thin wrappers inline', () => {
    expect(indexSrc).toContain('/assets/fleet-phase3-cron-ui.js');
    expect(indexSrc).toContain('function getCronUiCtx()');
    expect(indexSrc).toContain('window.phase3CronUi');
  });

  it('defines cron state and host-picker helpers in the extracted module', () => {
    expect(moduleSrc).toContain('function getCronSelectedAgentIds(ctx)');
    expect(moduleSrc).toContain('function setCronSelectedAgentIds(ctx, next)');
    expect(moduleSrc).toContain('function setCronHostsPanelVisible(ctx, visible)');
    expect(moduleSrc).toContain('function renderCronHostsList(ctx)');
    expect(moduleSrc).toContain('w.phase3CronUi = {');
  });
});

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('phase3 ssh ui state extraction', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const modulePath = path.join(root, 'server/app/templates/fleet-phase3-ssh-ui-state.js');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const moduleSrc = fs.readFileSync(modulePath, 'utf8');
  const indexSrc = fs.readFileSync(indexPath, 'utf8');

  it('loads ssh ui state helpers from a dedicated module', () => {
    expect(indexSrc).toContain('/assets/fleet-phase3-ssh-ui-state.js');
    expect(indexSrc).toContain('function getSshUiStateCtx()');
    expect(indexSrc).toContain('window.phase3SshUiState');
  });

  it('defines ssh ui state and host-picker helpers in the extracted module', () => {
    expect(moduleSrc).toContain('function getSshSelectedAgentIds(ctx)');
    expect(moduleSrc).toContain('function setSshSelectedAgentIds(ctx, next)');
    expect(moduleSrc).toContain('function getSshSelectedKeyId(ctx)');
    expect(moduleSrc).toContain('function setSshSelectedKeyId(ctx, next)');
    expect(moduleSrc).toContain('function getSshKeysCache(ctx)');
    expect(moduleSrc).toContain('function setSshKeysCache(ctx, next)');
    expect(moduleSrc).toContain('function setSshHostsPanelVisible(ctx, visible)');
    expect(moduleSrc).toContain('function renderSshHostsList(ctx)');
    expect(moduleSrc).toContain('w.phase3SshUiState = {');
  });
});

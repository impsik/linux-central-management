import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('phase3 terminal runtime extraction', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const modulePath = path.join(root, 'server/app/templates/fleet-phase3-terminal-runtime.js');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const moduleSrc = fs.readFileSync(modulePath, 'utf8');
  const indexSrc = fs.readFileSync(indexPath, 'utf8');

  it('loads terminal runtime helpers from a dedicated module', () => {
    expect(indexSrc).toContain('/assets/fleet-phase3-terminal-runtime.js');
    expect(indexSrc).toContain('function getTerminalRuntimeCtx()');
    expect(indexSrc).toContain('window.phase3TerminalRuntime');
  });

  it('defines isolated terminal runtime helpers in the extracted module', () => {
    expect(moduleSrc).toContain('function fitTerminalViewport(ctx)');
    expect(moduleSrc).toContain('function initTerminalOnce(ctx)');
    expect(moduleSrc).toContain('function attachTerminalInputHandlerOnce(ctx)');
    expect(moduleSrc).toContain('function updateTerminalPendingCmdButton(ctx)');
    expect(moduleSrc).toContain('function runPendingInteractivePackageCommand(ctx)');
    expect(moduleSrc).toContain('function initTerminalPendingCmdButton(ctx)');
    expect(moduleSrc).toContain('w.phase3TerminalRuntime = {');
  });
});

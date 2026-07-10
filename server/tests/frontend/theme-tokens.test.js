import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('central theme tokens', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const tokensPath = path.join(root, 'server/app/templates/fleet-theme-tokens.css');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const terminalPath = path.join(root, 'server/app/templates/terminal_popup.html');
  const bootstrapPath = path.join(root, 'server/app/templates/fleet-theme-bootstrap.js');
  const v2Path = path.join(root, 'server/app/templates/fleet-ui-v2.css');
  const reportsPath = path.join(root, 'server/app/routers/reports_html.py');

  const tokens = fs.readFileSync(tokensPath, 'utf8');
  const index = fs.readFileSync(indexPath, 'utf8');
  const terminal = fs.readFileSync(terminalPath, 'utf8');
  const bootstrap = fs.readFileSync(bootstrapPath, 'utf8');
  const v2 = fs.readFileSync(v2Path, 'utf8');
  const reports = fs.readFileSync(reportsPath, 'utf8');

  it('defines light and dark palettes in one token stylesheet', () => {
    expect(tokens).toContain(':root {');
    expect(tokens).toContain(':root[data-theme="dark"]');
    for (const token of ['--bg', '--panel', '--panel-2', '--border', '--text', '--muted', '--primary', '--status-ok-text', '--report-th-bg']) {
      expect(tokens).toContain(`${token}:`);
    }
  });

  it('loads the token stylesheet in app, terminal, report, and v2 surfaces', () => {
    expect(index).toContain('/assets/fleet-theme-tokens.css');
    expect(terminal).toContain('/assets/fleet-theme-tokens.css');
    expect(reports).toContain('/assets/fleet-theme-tokens.css');
    expect(v2).toContain("@import url('/assets/fleet-theme-tokens.css");
  });

  it('does not keep duplicate v2 root palette definitions or terminal-local palettes', () => {
    expect(v2).not.toMatch(/:root\s*\{\s*--app-surface:/);
    expect(v2).not.toMatch(/:root\[data-theme="dark"\]\s*\{\s*--app-surface:/);
    expect(terminal).not.toContain('--btn-bg:');
    expect(terminal).not.toContain('--border-soft:');
  });

  it('keeps v2 component colors token-based instead of reintroducing raw palettes', () => {
    expect(v2).not.toMatch(/#[0-9a-fA-F]{3,8}/);
    expect(v2).not.toMatch(/rgba\(/);
    expect(v2).not.toMatch(/linear-gradient/);
    expect(v2).not.toMatch(/color-mix\(in srgb, #[0-9a-fA-F]/);
  });

  it('keeps terminal popup on shared tokens without attaching the full v2 layout stylesheet', () => {
    expect(terminal).toContain('name="fleet-skip-ui-v2"');
    expect(bootstrap).toContain('fleet-skip-ui-v2');
    expect(bootstrap).toContain('const isV2 = !skipV2 && uiParam !==');
  });
});

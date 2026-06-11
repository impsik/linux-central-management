import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('terminal input transport', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');

  it('sends xterm input as websocket text frames in the main console', () => {
    const src = fs.readFileSync(path.join(root, 'server/app/templates/index.html'), 'utf8');
    const marker = 'term.onData(data => {';
    const start = src.indexOf(marker);
    expect(start).toBeGreaterThanOrEqual(0);
    const section = src.slice(start, start + 180);

    expect(section).toContain('ws.send(data);');
    expect(section).not.toContain('new TextEncoder().encode(data)');
  });

  it('sends popup terminal input as websocket text frames', () => {
    const src = fs.readFileSync(path.join(root, 'server/app/templates/terminal_popup.html'), 'utf8');
    const marker = 'term.onData(data => {';
    const start = src.indexOf(marker);
    expect(start).toBeGreaterThanOrEqual(0);
    const section = src.slice(start, start + 180);

    expect(section).toContain('ws.send(data);');
    expect(section).not.toContain('new TextEncoder().encode(data)');
  });

  it('submits queued commands with carriage return for interactive shells', () => {
    const main = fs.readFileSync(path.join(root, 'server/app/templates/index.html'), 'utf8');
    const popup = fs.readFileSync(path.join(root, 'server/app/templates/terminal_popup.html'), 'utf8');

    expect(main).toContain("ws.send(pendingInteractivePackageCmd + '\\r');");
    expect(popup).toContain('ws.send(cmd + "\\r");');
  });

  it('resets xterm state before starting a new main console session', () => {
    const main = fs.readFileSync(path.join(root, 'server/app/templates/index.html'), 'utf8');
    const phase3 = fs.readFileSync(path.join(root, 'server/app/templates/fleet-phase3.js'), 'utf8');

    expect(main).toContain("if (typeof term.reset === 'function') term.reset();");
    expect(phase3).toContain("if (typeof term.reset === 'function') term.reset();");
  });
});

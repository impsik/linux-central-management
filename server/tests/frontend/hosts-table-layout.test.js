import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('hosts table layout CSS', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const cssPath = path.join(root, 'server/app/templates/fleet-ui.css');
  const src = fs.readFileSync(cssPath, 'utf8');

  it('uses auto table layout for the hosts table so columns can size naturally', () => {
    expect(src).toContain('.hosts-table {\n  width: 100%;\n  table-layout: auto;\n}');
    expect(src).not.toContain('.hosts-table {\n  width: 100%;\n  table-layout: fixed;');
  });

  it('does not reserve a fixed 20 percent width for the Kernel column', () => {
    const marker = '.hosts-table th:nth-child(4),\n.hosts-table td:nth-child(4) {';
    const start = src.indexOf(marker);
    expect(start).toBeGreaterThanOrEqual(0);
    const section = src.slice(start, start + 220);

    expect(section).toContain('width: 1%;');
    expect(section).toContain('min-width: 0;');
    expect(section).not.toContain('width: 20%;');
    expect(section).not.toContain('min-width: 140px;');
  });
});

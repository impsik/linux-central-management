import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('dashboard attention pagination UI', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const htmlPath = path.join(root, 'server/app/templates/index.html');
  const overviewPath = path.join(root, 'server/app/templates/fleet-phase3-overview.js');
  const html = fs.readFileSync(htmlPath, 'utf8');
  const overview = fs.readFileSync(overviewPath, 'utf8');

  it('defaults Dashboard Host Inventory issues to 10 rows with 50 and All options', () => {
    expect(html).toContain('id="overview-attention-page-size"');
    expect(html).toContain('<option value="10" selected>10</option>');
    expect(html).toContain('<option value="50">50</option>');
    expect(html).toContain('<option value="all">All</option>');
    expect(html).toContain('id="overview-attention-page-prev"');
    expect(html).toContain('id="overview-attention-page-next"');
  });

  it('renders only the current Dashboard attention page', () => {
    expect(overview).toContain("const raw = String(document.getElementById('overview-attention-page-size')?.value || '10')");
    expect(overview).toContain('return n === 50 ? 50 : 10;');
    expect(overview).toContain('rows.slice((attentionPage - 1) * pageSize, attentionPage * pageSize)');
    expect(overview).toContain('for (const it of pageRows)');
    expect(overview).toContain("document.getElementById('overview-attention-page-next')?.addEventListener('click'");
  });
});

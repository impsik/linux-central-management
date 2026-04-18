import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('hosts owner sorting UI', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const htmlPath = path.join(root, 'server/app/templates/index.html');
  const overviewPath = path.join(root, 'server/app/templates/fleet-phase3-overview.js');
  const html = fs.readFileSync(htmlPath, 'utf8');
  const overview = fs.readFileSync(overviewPath, 'utf8');

  it('offers owner in the Hosts sort dropdown and exposes an Owner sortable header', () => {
    expect(html).toContain('<option value="owner">Owner</option>');
    expect(html).toContain('id="hosts-th-owner"');
    expect(html).toContain('title="Sort by owner"');
    expect(html).toContain("bindSortableHeader('hosts-th-owner', () => setSort('owner'));");
  });

  it('renders the owner value as its own Hosts table column', () => {
    expect(overview).toContain("const owner = String(it?.labels?.owner || '').trim();");
    expect(overview).toContain("<td>${owner ? `<code>${w.escapeHtml(owner)}</code>` : '<span class=\"status-muted\">—</span>'}</td>");
  });

  it('keeps owner sorting implemented in the hosts table loader', () => {
    expect(overview).toContain("const effectiveSort = sort === 'owner' ? 'hostname' : sort;");
    expect(overview).toContain("if (sort === 'owner') {");
    expect(overview).toContain("const ownerCmp = ao.localeCompare(bo, undefined, { sensitivity: 'base' });");
  });
});

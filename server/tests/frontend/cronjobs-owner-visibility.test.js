import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('automation cronjobs owner visibility UI', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const htmlPath = path.join(root, 'server/app/templates/index.html');
  const html = fs.readFileSync(htmlPath, 'utf8');

  it('shows an Owner column in the cronjobs table', () => {
    expect(html).toContain('<th>Owner</th>');
    expect(html).toContain('const owner = String(it.owner_username || \'\').trim();');
    expect(html).toContain('<td>${owner ? `<code>${escapeHtml(owner)}</code>` : \'<span class="status-muted">—</span>\'}</td>');
  });
});

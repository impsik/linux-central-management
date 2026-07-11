import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const root = process.cwd();

describe('security mitigations UI', () => {
  const html = fs.readFileSync(path.join(root, 'server/app/templates/index.html'), 'utf8');
  const src = fs.readFileSync(path.join(root, 'server/app/templates/fleet-security-mitigations-ui.js'), 'utf8');

  it('offers assessment and approval-protected apply workflows in Security', () => {
    expect(html).toContain('id="security-mitigations-list"');
    expect(html).toContain('id="mitigation-hosts-list"');
    expect(html).toContain('id="mitigation-assess"');
    expect(html).toContain('/assets/fleet-security-mitigations-ui.js');
    expect(src).toContain('/security/mitigations');
    expect(src).toContain('/assess');
    expect(html).toContain('id="mitigation-apply"');
    expect(src).toContain('/apply');
    expect(src).toContain('vulnerableHosts');
  });
});

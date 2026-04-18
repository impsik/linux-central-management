import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';


describe('hosts owner filter UI', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const htmlPath = path.join(root, 'server/app/templates/index.html');
  const hostListPath = path.join(root, 'server/app/templates/fleet-phase3-host-list.js');
  const filtersUiPath = path.join(root, 'server/app/templates/fleet-phase3-host-filters-ui.js');
  const html = fs.readFileSync(htmlPath, 'utf8');
  const hostList = fs.readFileSync(hostListPath, 'utf8');
  const filtersUi = fs.readFileSync(filtersUiPath, 'utf8');

  it('renders an Owner filter control in the Hosts filters', () => {
    expect(html).toContain('id="label-owner"');
    expect(html).toContain('Owner: Any');
  });

  it('populates and applies owner filter values in host list filtering', () => {
    expect(hostList).toContain("const ownerSel = document.getElementById('label-owner');");
    expect(hostList).toContain('const ownerVals = new Set();');
    expect(hostList).toContain('ctx.setLabelOwnerFilter(ownerSel.value || \'\');');
    expect(hostList).toContain('const labelOwnerFilter = ctx.getLabelOwnerFilter();');
    expect(hostList).toContain("if (labelOwnerFilter) filtered = filtered.filter(h => (w.hostLabel(h, 'owner') || '') === labelOwnerFilter);");
  });

  it('persists owner filter in filter UI state and saved views', () => {
    expect(filtersUi).toContain("const ownerSel = document.getElementById('label-owner');");
    expect(filtersUi).toContain('labelOwnerFilter: ownerSel?.value || \'\'');
    expect(filtersUi).toContain('const labelOwner = String(view.labelOwnerFilter || \'\');');
    expect(filtersUi).toContain("syncSelectionState('labelOwnerFilter', labelOwner);");
    expect(filtersUi).toContain("ownerSel?.addEventListener('change', onLabelsChanged);");
  });
});

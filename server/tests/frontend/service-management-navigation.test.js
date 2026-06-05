import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('service management navigation', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const overviewPath = path.join(root, 'server/app/templates/fleet-phase3-overview.js');
  const hostWorkflowsPath = path.join(root, 'server/app/templates/fleet-phase3-host-workflows.js');
  const indexSrc = fs.readFileSync(indexPath, 'utf8');
  const overviewSrc = fs.readFileSync(overviewPath, 'utf8');
  const hostWorkflowsSrc = fs.readFileSync(hostWorkflowsPath, 'utf8');

  it('renders service management as a top-level sidebar destination', () => {
    expect(indexSrc).toContain('id="nav-service-management"');
    expect(indexSrc).toContain('id="service-management-tab"');
    expect(overviewSrc).toContain("const navServiceManagement = document.getElementById('nav-service-management')");
    expect(overviewSrc).toContain("document.getElementById('service-management-tab')?.classList.add('active')");
    expect(overviewSrc).toContain('navServiceManagement?.addEventListener');
  });

  it('does not render service management inside user management', () => {
    const userTabStart = indexSrc.indexOf('id="user-management-tab"');
    const serviceTabStart = indexSrc.indexOf('id="service-management-tab"');
    expect(userTabStart).toBeGreaterThanOrEqual(0);
    expect(serviceTabStart).toBeGreaterThan(userTabStart);

    const userTabMarkup = indexSrc.slice(userTabStart, serviceTabStart);
    expect(userTabMarkup).toContain('<div class="section-title">User management</div>');
    expect(userTabMarkup).not.toContain('Service management');
    expect(userTabMarkup).not.toContain('service-management-name');
  });

  it('labels service enablement as autostart instead of current access', () => {
    expect(indexSrc).toContain('<th>Autostart</th>');
    expect(indexSrc).not.toContain('<th>Enabled</th>');
    expect(indexSrc).toContain("${it.enabled ? 'yes' : 'manual'}");
    expect(hostWorkflowsSrc).toContain('✓ Autostart');
    expect(hostWorkflowsSrc).toContain('✗ Manual start');
  });
});

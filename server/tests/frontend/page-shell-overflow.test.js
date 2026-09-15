import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('page shell release details', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const css = fs.readFileSync(path.join(root, 'server/app/templates/fleet-ui-v2.css'), 'utf8');
  const version = fs.readFileSync(path.join(root, 'server/app/version.py'), 'utf8');
  const release = fs.readFileSync(path.join(root, 'VERSION'), 'utf8').trim();

  it('clips accidental document-level horizontal overflow', () => {
    expect(css).toMatch(/html,\s*\nbody\s*\{[^}]*overflow-x:\s*hidden;/s);
  });

  it('uses the shared release version in the application', () => {
    expect(version).toContain(`APP_VERSION = "${release}"`);
  });
});

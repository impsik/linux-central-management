import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('phase3 modal detail controls extraction', () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../..');
  const modalsPath = path.join(root, 'server/app/templates/fleet-phase3-modals.js');
  const indexPath = path.join(root, 'server/app/templates/index.html');
  const modalsSrc = fs.readFileSync(modalsPath, 'utf8');
  const indexSrc = fs.readFileSync(indexPath, 'utf8');

  it('keeps detail modal control helpers out of index.html', () => {
    expect(indexSrc).not.toContain('function initAuditDetailModalControls()');
    expect(indexSrc).not.toContain('function initApprovalDetailModalControls()');
    expect(indexSrc).not.toContain('function initFailedRunDetailModalControls()');
    expect(indexSrc).not.toContain('function initApprovalsFilterControls()');
    expect(indexSrc).not.toContain('async function copyTextWithFallback(');
  });

  it('defines detail modal helpers in fleet-phase3-modals.js', () => {
    expect(modalsSrc).toContain('async function copyTextWithFallback(text, selectableEl)');
    expect(modalsSrc).toContain('function initAuditDetailModalControls()');
    expect(modalsSrc).toContain('function initApprovalDetailModalControls()');
    expect(modalsSrc).toContain('function initFailedRunDetailModalControls()');
    expect(modalsSrc).toContain('function initApprovalsFilterControls()');
    expect(modalsSrc).toContain('window.openFailedRunDetailModal = (text, meta) =>');
  });
});

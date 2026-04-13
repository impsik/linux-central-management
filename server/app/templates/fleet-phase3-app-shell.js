function bootPhase3AppShell() {
  const HOSTS_REFRESH_MS = 5000;
  let hostsRefreshTimer = null;

  function startHostRefresh() {
    if (hostsRefreshTimer) return;
    hostsRefreshTimer = setInterval(loadHosts, HOSTS_REFRESH_MS);
  }

  loadAuthInfo().catch((e) => console.error('[loadAuthInfo failed]', e));

  safeInit('initHostFilters', initHostFilters);
  safeInit('initGlobalSearch', initGlobalSearch);
  safeInit('initReportsControls', initReportsControls);
  safeInit('initFleetOverviewControls', initFleetOverviewControls);
  safeInit('initHostsTableControls', initHostsTableControls);
  safeInit('initCronjobsControls', initCronjobsControls);
  safeInit('initSshKeysControls', initSshKeysControls);
  safeInit('initLoadTimeframeControls', initLoadTimeframeControls);
  safeInit('initPackagesSearch', initPackagesSearch);
  safeInit('initAdminPanel', initAdminPanel);
  safeInit('initRbacExplain', initRbacExplain);
  safeInit('initOidcMapPreview', initOidcMapPreview);
  safeInit('initThemeToggle', initThemeToggle);
  safeInit('initSettingsMenu', initSettingsMenu);
  safeInit('initHostActionControls', initHostActionControls);
  safeInit('initHostMetadataEditor', initHostMetadataEditor);
  safeInit('initAuditDetailModalControls', initAuditDetailModalControls);
  safeInit('initApprovalDetailModalControls', initApprovalDetailModalControls);
  safeInit('initFailedRunDetailModalControls', initFailedRunDetailModalControls);
  safeInit('initPreflightResultsModalControls', initPreflightResultsModalControls);
  safeInit('initApprovalsFilterControls', initApprovalsFilterControls);
  safeInit('bindDiskCardClick', () => {
    const diskCard = document.getElementById('disk-card');
    if (!diskCard) return;
    diskCard.addEventListener('click', (e) => {
      e.preventDefault();
      if (!currentAgentId) return;
      openDiskModal(currentAgentId);
    });
  });
  safeInit('bindDiskModalClose', () => {
    document.getElementById('disk-modal-close')?.addEventListener('click', (e) => {
      e.preventDefault();
      if (typeof closeDiskModal === 'function') closeDiskModal();
    });
    document.getElementById('disk-modal')?.addEventListener('click', (e) => {
      if (e.target && e.target.id === 'disk-modal' && typeof closeDiskModal === 'function') closeDiskModal();
    });
  });
  safeInit('initTerminalOnce', initTerminalOnce);
  safeInit('attachTerminalInputHandlerOnce', attachTerminalInputHandlerOnce);
  safeInit('initTerminalPendingCmdButton', () => {
    const btn = document.getElementById('terminal-run-pending-cmd');
    if (btn) btn.addEventListener('click', (e) => { e.preventDefault(); runPendingInteractivePackageCommand(); });
    updateTerminalPendingCmdButton();
  });
  safeInit('initAnsibleSection', initAnsibleSection);
  safeInit('bindAnsibleOpenFallback', () => {
    const btn = document.getElementById('ansible-open');
    const sel = document.getElementById('ansible-playbook');
    const status = document.getElementById('ansible-status');
    if (!btn || btn.dataset.boundAnsibleOpenFallback === '1') return;
    btn.addEventListener('click', (e) => {
      const mod = window.phase3Ansible;
      if (!mod || typeof mod.openAnsibleModal !== 'function') return;
      e.preventDefault();
      const pb = sel ? (sel.value || '') : '';
      if (!pb) {
        if (status) status.textContent = 'Select playbook first.';
        return;
      }
      mod.openAnsibleModal(getAnsibleCtx(), pb);
    });
    btn.dataset.boundAnsibleOpenFallback = '1';
  });
  safeInit('initTimelineFilters', initTimelineFilters);
  safeInit('initCommonModalDismissHandlers', () => {
    const hostActionsMod = window.phase3HostActions;
    if (hostActionsMod && typeof hostActionsMod.initCommonModalDismissHandlers === 'function') {
      hostActionsMod.initCommonModalDismissHandlers({
        getCurrentMetricsAgentId: () => metricsLifecycleState.get('currentMetricsAgentId'),
        openDiskModal,
        closeDiskModal,
        closeServiceModal,
        closeUserModal,
      });
    }
  });

  void loadHosts().catch((e) => {
    console.error('[loadHosts failed]', e);
    const hostsEl = document.getElementById('hosts');
    if (hostsEl) hostsEl.innerHTML = `<div class="error">Error loading hosts: ${escapeHtml(e?.message || String(e))}</div>`;
  });

  setTimeout(() => {
    const hostsEl = document.getElementById('hosts');
    if (!hostsEl) return;
    const txt = (hostsEl.textContent || '').trim().toLowerCase();
    if (txt.includes('loading hosts')) {
      console.warn('[hosts-watchdog] still loading after 10s; forcing inline fallback');
      hostsEl.innerHTML = '<div class="error">Hosts view was stuck loading. Retrying…</div>';
      void loadHosts().catch((e) => {
        hostsEl.innerHTML = `<div class="error">Error loading hosts: ${escapeHtml(e?.message || String(e))}</div>`;
      });
    }
  }, 10000);

  void loadFleetOverview();
  void refreshApprovalsIndicator();
  startHostRefresh();
  setInterval(() => { void loadFleetOverview(); }, 15000);
  setInterval(() => { void refreshApprovalsIndicator(); }, 60000);
}

(function (w) {
  function createHostListCtx(deps) {
    const d = deps || {};
    return {
      getAllHosts: d.getAllHosts || (() => []),
      setAllHosts: d.setAllHosts || ((v) => v),
      getHostSearchQuery: d.getHostSearchQuery || (() => ''),
      getLabelEnvFilter: d.getLabelEnvFilter || (() => ''),
      setLabelEnvFilter: d.setLabelEnvFilter || ((v) => v),
      getLabelRoleFilter: d.getLabelRoleFilter || (() => ''),
      setLabelRoleFilter: d.setLabelRoleFilter || ((v) => v),
      getLabelOwnerFilter: d.getLabelOwnerFilter || (() => ''),
      setLabelOwnerFilter: d.setLabelOwnerFilter || ((v) => v),
      getVulnFilteredAgentIds: d.getVulnFilteredAgentIds || (() => null),
      getSelectedAgentIds: d.getSelectedAgentIds || (() => new Set()),
      setLastRenderedAgentIds: d.setLastRenderedAgentIds || ((v) => v),
      getCurrentAgentId: d.getCurrentAgentId || (() => null),
      getLastPkgVerification: d.getLastPkgVerification || (() => null),
      selectHost: d.selectHost || (() => {}),
      updateUpgradeControls: d.updateUpgradeControls || (() => {}),
      renderHosts: d.renderHosts || (() => {}),
    };
  }

  function createHostWorkflowsCtx(deps) {
    const d = deps || {};
    return {
      getCurrentPermissions: d.getCurrentPermissions || (() => ({})),
      getCurrentAgentId: d.getCurrentAgentId || (() => null),
      getCurrentUsername: d.getCurrentUsername || (() => ''),
      getCurrentHostOwner: d.getCurrentHostOwner || (() => ''),
    };
  }

  function createOverviewCtx(deps) {
    const d = deps || {};
    return {
      formatShortTime: d.formatShortTime || w.formatShortTime,
      selectHost: d.selectHost || (() => {}),
      openDiskModal: d.openDiskModal || (() => {}),
      showServerInfo: d.showServerInfo || (() => {}),
      showPackages: d.showPackages || (() => {}),
      loadPackages: d.loadPackages || (() => Promise.resolve()),
      setPackagesUpdatesOnly: d.setPackagesUpdatesOnly || (() => {}),
      loadPendingUpdatesReport: d.loadPendingUpdatesReport || (() => Promise.resolve()),
      clearCurrentHostSelection: d.clearCurrentHostSelection || (() => {}),
      stopMetricsPolling: d.stopMetricsPolling || (() => {}),
      loadHostsTable: d.loadHostsTable || (() => Promise.resolve()),
      loadCronjobs: d.loadCronjobs || (() => Promise.resolve()),
      loadSshKeys: d.loadSshKeys || (() => Promise.resolve()),
      loadSshKeyRequests: d.loadSshKeyRequests || (() => Promise.resolve()),
      maybeLoadSshKeyAdminQueue: d.maybeLoadSshKeyAdminQueue || (() => Promise.resolve()),
      loadAdminSshKeys: d.loadAdminSshKeys || (() => Promise.resolve()),
      loadFleetOverview: d.loadFleetOverview || (() => Promise.resolve()),
      loadFailedRuns: d.loadFailedRuns || (() => Promise.resolve()),
      loadHosts: d.loadHosts || (() => Promise.resolve()),
      getLastRenderedAgentIds: d.getLastRenderedAgentIds || (() => []),
      setLastRenderedAgentIds: d.setLastRenderedAgentIds || ((v) => v),
      getHostSearchQuery: d.getHostSearchQuery || (() => ''),
      getCurrentAgentId: d.getCurrentAgentId || (() => null),
      getLabelEnvFilter: d.getLabelEnvFilter || (() => ''),
      getLabelRoleFilter: d.getLabelRoleFilter || (() => ''),
      getVulnFilteredAgentIds: d.getVulnFilteredAgentIds || (() => null),
      setAllHosts: d.setAllHosts || ((hosts) => hosts),
    };
  }

  function createMetricsCtx(deps) {
    const d = deps || {};
    return {
      getMetricsLifecycleState: d.getMetricsLifecycleState || (() => null),
      getLoadGraphData: d.getLoadGraphData || (() => []),
      setLoadGraphData: d.setLoadGraphData || ((v) => v),
      getLoadTimeframeSeconds: d.getLoadTimeframeSeconds || (() => 3600),
      stopMetricsPolling: d.stopMetricsPolling || (() => {}),
    };
  }

  function createPackagesCtx(deps) {
    const d = deps || {};
    return {
      getState: d.getState || (() => ({})),
      setState: d.setState || (() => {}),
      runInteractivePackageCommand: d.runInteractivePackageCommand || (() => false),
    };
  }

  function createSshUiCtx(deps) {
    const d = deps || {};
    return {
      loadSshKeys: d.loadSshKeys || (() => Promise.resolve()),
      maybeLoadSshKeyAdminQueue: d.maybeLoadSshKeyAdminQueue || (() => Promise.resolve()),
      loadAdminSshKeys: d.loadAdminSshKeys || (() => Promise.resolve()),
      loadAdminUsers: d.loadAdminUsers || (() => Promise.resolve()),
      loadAdminOidcEvents: d.loadAdminOidcEvents || (() => Promise.resolve()),
      loadAdminApprovals: d.loadAdminApprovals || (() => Promise.resolve()),
      loadAdminNotificationDedupe: d.loadAdminNotificationDedupe || (() => Promise.resolve()),
      loadAdminAudit: d.loadAdminAudit || (() => Promise.resolve()),
      setSshHostsPanelVisible: d.setSshHostsPanelVisible || (() => {}),
      renderSshHostsList: d.renderSshHostsList || (() => {}),
      getSshSelectedAgentIds: d.getSshSelectedAgentIds || (() => []),
      setSshSelectedAgentIds: d.setSshSelectedAgentIds || (() => {}),
      getSshSelectedKeyId: d.getSshSelectedKeyId || (() => null),
      loadSshKeyRequests: d.loadSshKeyRequests || (() => Promise.resolve()),
      getAllHosts: d.getAllHosts || (() => []),
    };
  }

  function createAnsibleCtx(deps) {
    const d = deps || {};
    return {
      getAnsiblePlaybooks: d.getAnsiblePlaybooks || (() => []),
      setAnsiblePlaybooks: d.setAnsiblePlaybooks || ((v) => v),
      getSelectedAgentIds: d.getSelectedAgentIds || (() => new Set()),
      getLastRenderedAgentIds: d.getLastRenderedAgentIds || (() => []),
      getCurrentAgentId: d.getCurrentAgentId || (() => null),
    };
  }

  function createHostActionControlsCtx(deps) {
    const d = deps || {};
    return {
      showServerInfo: d.showServerInfo || (() => {}),
      showTerminal: d.showTerminal || (() => {}),
      showUsers: d.showUsers || (() => {}),
      showServices: d.showServices || (() => {}),
      showPackages: d.showPackages || (() => {}),
    };
  }

  function createHostMetadataEditorCtx(deps) {
    const d = deps || {};
    return {
      getCurrentAgentId: d.getCurrentAgentId || (() => null),
      onMetadataSaved: d.onMetadataSaved || (() => {}),
    };
  }

  w.phase3Contexts = {
    createHostListCtx,
    createHostWorkflowsCtx,
    createOverviewCtx,
    createMetricsCtx,
    createPackagesCtx,
    createSshUiCtx,
    createAnsibleCtx,
    createHostActionControlsCtx,
    createHostMetadataEditorCtx,
  };
})(window);

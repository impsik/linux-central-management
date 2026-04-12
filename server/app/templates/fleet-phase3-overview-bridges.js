(function (w) {
  function getOverviewCtx(ctx) {
    const api = ctx || {};
    const deps = {
      formatShortTime: api.formatShortTime,
      selectHost: api.selectHost,
      openDiskModal: api.openDiskModal,
      showServerInfo: api.showServerInfo,
      showPackages: api.showPackages,
      loadPackages: api.loadPackages,
      setPackagesUpdatesOnly: api.setPackagesUpdatesOnly,
      loadPendingUpdatesReport: api.loadPendingUpdatesReport,
      clearCurrentHostSelection: api.clearCurrentHostSelection,
      stopMetricsPolling: api.stopMetricsPolling,
      loadHostsTable: api.loadHostsTable,
      loadCronjobs: api.loadCronjobs,
      loadSshKeys: api.loadSshKeys,
      loadSshKeyRequests: api.loadSshKeyRequests,
      maybeLoadSshKeyAdminQueue: api.maybeLoadSshKeyAdminQueue,
      loadAdminSshKeys: api.loadAdminSshKeys,
      loadFleetOverview: api.loadFleetOverview,
      loadFailedRuns: api.loadFailedRuns,
      loadHosts: api.loadHosts,
      getLastRenderedAgentIds: api.getLastRenderedAgentIds,
      setLastRenderedAgentIds: api.setLastRenderedAgentIds,
      getHostSearchQuery: api.getHostSearchQuery,
      getCurrentAgentId: api.getCurrentAgentId,
      getLabelEnvFilter: api.getLabelEnvFilter,
      getLabelRoleFilter: api.getLabelRoleFilter,
      getVulnFilteredAgentIds: api.getVulnFilteredAgentIds,
      setAllHosts: api.setAllHosts,
    };
    const mod = w.phase3Contexts;
    if (mod && typeof mod.createOverviewCtx === 'function') return mod.createOverviewCtx(deps);
    return deps;
  }

  function loadFleetOverview(ctx, forceLive = false) {
    const mod = w.phase3Overview;
    if (mod && typeof mod.loadFleetOverview === 'function') {
      return mod.loadFleetOverview(getOverviewCtx(ctx), forceLive);
    }
  }

  function loadPendingUpdatesReport(ctx, showToastOnManual = false) {
    const mod = w.phase3Overview;
    if (mod && typeof mod.loadPendingUpdatesReport === 'function') {
      return mod.loadPendingUpdatesReport(getOverviewCtx(ctx), showToastOnManual);
    }
  }

  function loadHostsTable(ctx) {
    const mod = w.phase3Overview;
    if (mod && typeof mod.loadHostsTable === 'function') {
      return mod.loadHostsTable(getOverviewCtx(ctx));
    }
  }

  w.phase3OverviewBridges = {
    getOverviewCtx,
    loadFleetOverview,
    loadPendingUpdatesReport,
    loadHostsTable,
  };
})(window);

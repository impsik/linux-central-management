(function (w) {
  function initHostFilters(ctx) {
    const api = ctx || {};

    const vulnModule = w.phase3HostFiltersVuln;
    const uiModule = w.phase3HostFiltersUi;

    if (!uiModule || typeof uiModule.initHostFiltersUi !== 'function') {
      throw new Error('phase3HostFiltersUi.initHostFiltersUi is required');
    }
    if (!vulnModule || typeof vulnModule.initHostFiltersVuln !== 'function') {
      throw new Error('phase3HostFiltersVuln.initHostFiltersVuln is required');
    }

    let updateUpgradeControls = function () { };

    const uiOut = uiModule.initHostFiltersUi({
      getState: api.getState,
      setState: api.setState,
      syncSelectionState: api.syncSelectionState,
      applyHostFilters: api.applyHostFilters,
      updateUpgradeControls: function () { updateUpgradeControls(); },
    }) || {};

    const vulnOut = vulnModule.initHostFiltersVuln({
      getState: api.getState,
      setState: api.setState,
      syncSelectionState: api.syncSelectionState,
      applyHostFilters: api.applyHostFilters,
      pollJob: api.pollJob,
      escapeHtml: api.escapeHtml,
      matchesGlob: api.matchesGlob,
      setVulnOpen: uiOut.setVulnOpen,
    }) || {};

    if (typeof vulnOut.updateUpgradeControls === 'function') {
      updateUpgradeControls = vulnOut.updateUpgradeControls;
    }

    return {
      updateUpgradeControls: updateUpgradeControls,
    };
  }

  w.phase3HostFilters = {
    initHostFilters: initHostFilters,
  };
})(window);

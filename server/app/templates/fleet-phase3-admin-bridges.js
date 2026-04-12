(function (w) {
  function initHostActionControls(ctx) {
    const api = ctx || {};
    const mod = w.phase3HostActions;
    if (!mod || typeof mod.initHostActionControls !== 'function') return;
    const ctxMod = w.phase3Contexts;
    const bridgeCtx = (ctxMod && typeof ctxMod.createHostActionControlsCtx === 'function')
      ? ctxMod.createHostActionControlsCtx({
          showServerInfo: api.showServerInfo,
          showTerminal: api.showTerminal,
          showUsers: api.showUsers,
          showServices: api.showServices,
          showPackages: api.showPackages,
        })
      : {
          showServerInfo: api.showServerInfo,
          showTerminal: api.showTerminal,
          showUsers: api.showUsers,
          showServices: api.showServices,
          showPackages: api.showPackages,
        };
    return mod.initHostActionControls(bridgeCtx);
  }

  function initHostMetadataEditor(ctx) {
    const api = ctx || {};
    const mod = w.phase3HostActions;
    if (!mod || typeof mod.initHostMetadataEditor !== 'function') return;
    const deps = {
      getCurrentAgentId: api.getCurrentAgentId,
      onMetadataSaved: api.onMetadataSaved,
    };
    const ctxMod = w.phase3Contexts;
    const bridgeCtx = (ctxMod && typeof ctxMod.createHostMetadataEditorCtx === 'function')
      ? ctxMod.createHostMetadataEditorCtx(deps)
      : deps;
    return mod.initHostMetadataEditor(bridgeCtx);
  }

  function getSshUiCtx(ctx) {
    const api = ctx || {};
    const deps = {
      loadSshKeys: api.loadSshKeys,
      maybeLoadSshKeyAdminQueue: api.maybeLoadSshKeyAdminQueue,
      loadAdminSshKeys: api.loadAdminSshKeys,
      loadAdminUsers: api.loadAdminUsers,
      loadAdminOidcEvents: api.loadAdminOidcEvents,
      loadAdminApprovals: api.loadAdminApprovals,
      loadAdminNotificationDedupe: api.loadAdminNotificationDedupe,
      loadAdminAudit: api.loadAdminAudit,
      setSshHostsPanelVisible: api.setSshHostsPanelVisible,
      renderSshHostsList: api.renderSshHostsList,
      getSshSelectedAgentIds: api.getSshSelectedAgentIds,
      setSshSelectedAgentIds: api.setSshSelectedAgentIds,
      getSshSelectedKeyId: api.getSshSelectedKeyId,
      loadSshKeyRequests: api.loadSshKeyRequests,
      getAllHosts: api.getAllHosts,
    };
    const ctxMod = w.phase3Contexts;
    if (ctxMod && typeof ctxMod.createSshUiCtx === 'function') return ctxMod.createSshUiCtx(deps);
    return deps;
  }

  function initSshKeysControls(ctx) {
    const mod = w.phase3SshUi;
    if (mod && typeof mod.initSshKeysControls === 'function') {
      return mod.initSshKeysControls(getSshUiCtx(ctx));
    }
  }

  function getAnsibleCtx(ctx) {
    const api = ctx || {};
    const deps = {
      getAnsiblePlaybooks: api.getAnsiblePlaybooks,
      setAnsiblePlaybooks: api.setAnsiblePlaybooks,
      getSelectedAgentIds: api.getSelectedAgentIds,
      getLastRenderedAgentIds: api.getLastRenderedAgentIds,
      getCurrentAgentId: api.getCurrentAgentId,
    };
    const ctxMod = w.phase3Contexts;
    if (ctxMod && typeof ctxMod.createAnsibleCtx === 'function') return ctxMod.createAnsibleCtx(deps);
    return deps;
  }

  function initAnsibleSection(ctx) {
    const mod = w.phase3Ansible;
    if (mod && typeof mod.initAnsibleSection === 'function') {
      return mod.initAnsibleSection(getAnsibleCtx(ctx));
    }
  }

  w.phase3AdminBridges = {
    initHostActionControls,
    initHostMetadataEditor,
    getSshUiCtx,
    initSshKeysControls,
    getAnsibleCtx,
    initAnsibleSection,
  };
})(window);

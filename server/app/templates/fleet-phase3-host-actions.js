(function (w) {
  function initHostActionControls(ctx) {
    const api = ctx || {};
    document.getElementById('app-title')?.addEventListener('click', function (e) {
      e.preventDefault();
      if (typeof api.showServerInfo === 'function') api.showServerInfo();
    });
    document.getElementById('host-action-terminal')?.addEventListener('click', function (e) {
      e.preventDefault();
      if (typeof api.showTerminal === 'function') api.showTerminal();
    });
    document.getElementById('host-action-users')?.addEventListener('click', function (e) {
      e.preventDefault();
      if (typeof api.showUsers === 'function') api.showUsers();
    });
    document.getElementById('host-action-services')?.addEventListener('click', function (e) {
      e.preventDefault();
      if (typeof api.showServices === 'function') api.showServices();
    });
    document.getElementById('host-action-packages')?.addEventListener('click', function (e) {
      e.preventDefault();
      if (typeof api.showPackages === 'function') api.showPackages();
    });
  }

  function initCommonModalDismissHandlers(ctx) {
    const api = ctx || {};
    const getCurrentMetricsAgentId = typeof api.getCurrentMetricsAgentId === 'function' ? api.getCurrentMetricsAgentId : function () { return null; };

    document.getElementById('disk-card')?.addEventListener('click', function (e) {
      e.preventDefault();
      const aid = getCurrentMetricsAgentId();
      if (!aid) return;
      if (typeof api.openDiskModal === 'function') api.openDiskModal(aid);
    });
    document.getElementById('disk-modal-close')?.addEventListener('click', function (e) { e.preventDefault(); if (typeof api.closeDiskModal === 'function') api.closeDiskModal(); });
    document.getElementById('disk-modal')?.addEventListener('click', function (e) { if (e.target && e.target.id === 'disk-modal' && typeof api.closeDiskModal === 'function') api.closeDiskModal(); });

    document.getElementById('service-modal-close')?.addEventListener('click', function (e) { e.preventDefault(); if (typeof api.closeServiceModal === 'function') api.closeServiceModal(); });
    document.getElementById('service-modal')?.addEventListener('click', function (e) { if (e.target && e.target.id === 'service-modal' && typeof api.closeServiceModal === 'function') api.closeServiceModal(); });

    document.getElementById('user-modal-close')?.addEventListener('click', function (e) { e.preventDefault(); if (typeof api.closeUserModal === 'function') api.closeUserModal(); });
    document.getElementById('user-modal')?.addEventListener('click', function (e) { if (e.target && e.target.id === 'user-modal' && typeof api.closeUserModal === 'function') api.closeUserModal(); });
  }

  w.phase3HostActions = {
    initHostActionControls: initHostActionControls,
    initCommonModalDismissHandlers: initCommonModalDismissHandlers,
  };
})(window);

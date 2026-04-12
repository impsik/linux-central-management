(function (w) {
  function clearActiveTabs() {
    document.querySelectorAll('.tab-content-custom, .tab-content').forEach((c) => c.classList.remove('active'));
  }

  function showTerminal(ctx) {
    const api = ctx || {};
    const agentId = typeof api.getCurrentAgentId === 'function' ? api.getCurrentAgentId() : null;
    if (!agentId) return;
    api.setHostActionActive?.('terminal');
    api.stopMetricsPolling?.();
    api.connect?.(agentId);
    clearActiveTabs();
    document.getElementById('terminal-tab')?.classList.add('active');
    w.requestAnimationFrame(() => {
      api.fitTerminalViewport?.();
      setTimeout(() => api.fitTerminalViewport?.(), 60);
    });
  }

  function showUsers(ctx) {
    const api = ctx || {};
    const agentId = typeof api.getCurrentAgentId === 'function' ? api.getCurrentAgentId() : null;
    if (!agentId) return;
    api.setHostActionActive?.('users');
    api.stopMetricsPolling?.();
    clearActiveTabs();
    document.getElementById('users-tab')?.classList.add('active');
    api.loadUsers?.(agentId);
  }

  function showServices(ctx) {
    const api = ctx || {};
    const agentId = typeof api.getCurrentAgentId === 'function' ? api.getCurrentAgentId() : null;
    if (!agentId) return;
    api.setHostActionActive?.('services');
    api.stopMetricsPolling?.();
    clearActiveTabs();
    document.getElementById('services-tab')?.classList.add('active');
    api.loadServices?.(agentId);
  }

  function showPackages(ctx) {
    const api = ctx || {};
    const agentId = typeof api.getCurrentAgentId === 'function' ? api.getCurrentAgentId() : null;
    if (!agentId) return;
    api.setHostActionActive?.('packages');
    api.stopMetricsPolling?.();
    clearActiveTabs();
    document.getElementById('packages-tab')?.classList.add('active');
    api.loadPackages?.(agentId);
    api.refreshPackagesNow?.(agentId);
  }

  function showServerInfo(ctx) {
    const api = ctx || {};
    const agentId = typeof api.getCurrentAgentId === 'function' ? api.getCurrentAgentId() : null;
    if (!agentId) return;
    const hostObj = typeof api.findCurrentHost === 'function' ? api.findCurrentHost(agentId) : null;
    const hostname = hostObj?.hostname || agentId;
    api.selectHost?.(agentId, hostname);
  }

  w.phase3HostViewSwitching = {
    showTerminal,
    showUsers,
    showServices,
    showPackages,
    showServerInfo,
  };
})(window);

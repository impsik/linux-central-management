(function (w) {
  function getHostListCtx(ctx) {
    const api = ctx || {};
    const deps = {
      getAllHosts: api.getAllHosts,
      setAllHosts: api.setAllHosts,
      getHostSearchQuery: api.getHostSearchQuery,
      getLabelEnvFilter: api.getLabelEnvFilter,
      setLabelEnvFilter: api.setLabelEnvFilter,
      getLabelRoleFilter: api.getLabelRoleFilter,
      setLabelRoleFilter: api.setLabelRoleFilter,
      getLabelOwnerFilter: api.getLabelOwnerFilter,
      setLabelOwnerFilter: api.setLabelOwnerFilter,
      getVulnFilteredAgentIds: api.getVulnFilteredAgentIds,
      getSelectedAgentIds: api.getSelectedAgentIds,
      setLastRenderedAgentIds: api.setLastRenderedAgentIds,
      getCurrentAgentId: api.getCurrentAgentId,
      getLastPkgVerification: api.getLastPkgVerification,
      selectHost: api.selectHost,
      updateUpgradeControls: api.updateUpgradeControls,
      renderHosts: api.renderHosts,
      applyHostsTableFilters: api.applyHostsTableFilters,
    };
    const mod = w.phase3Contexts;
    if (mod && typeof mod.createHostListCtx === 'function') return mod.createHostListCtx(deps);
    return deps;
  }

  function rebuildLabelFilterOptions(ctx, hosts) {
    const mod = w.phase3HostList;
    if (mod && typeof mod.rebuildLabelFilterOptions === 'function') {
      if (Array.isArray(hosts)) getHostListCtx(ctx).setAllHosts(hosts);
      return mod.rebuildLabelFilterOptions(getHostListCtx(ctx));
    }
  }

  function applyHostFilters(ctx) {
    const listMod = w.phase3HostList;
    if (listMod && typeof listMod.applyHostFilters === 'function') {
      listMod.applyHostFilters(getHostListCtx(ctx));
    }
    if (typeof ctx.applyHostsTableFilters === 'function') {
      ctx.applyHostsTableFilters();
    }
  }

  async function loadHosts(ctx) {
    const hostsEl = document.getElementById('hosts');
    const mod = w.phase3HostList;
    try {
      if (mod && typeof mod.loadHosts === 'function') {
        await mod.loadHosts(getHostListCtx(ctx));
        return;
      }

      console.error('[loadHosts] phase3HostList module missing; using inline fallback');
      const r = await fetch('/hosts?online_only=true', { credentials: 'include' });
      if (!r.ok) throw new Error(`hosts failed (${r.status})`);
      const items = await r.json();
      const hosts = Array.isArray(items) ? items : [];
      if (!hostsEl) return;
      if (!hosts.length) {
        hostsEl.innerHTML = '<div class="empty-state">No hosts found</div>';
        if (typeof ctx.setAllHosts === 'function') ctx.setAllHosts([]);
        return;
      }
      if (typeof ctx.setAllHosts === 'function') ctx.setAllHosts(hosts);
      rebuildLabelFilterOptions(ctx);
      applyHostFilters(ctx);
    } catch (e) {
      if (hostsEl) hostsEl.innerHTML = `<div class="error">Error loading hosts: ${w.escapeHtml(e?.message || String(e))}</div>`;
      throw e;
    }
  }

  w.phase3HostListBridges = {
    getHostListCtx,
    rebuildLabelFilterOptions,
    applyHostFilters,
    loadHosts,
  };
})(window);

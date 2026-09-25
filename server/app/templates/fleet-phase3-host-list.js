(function (w) {
  function rebuildLabelFilterOptions(ctx) {
    const envSel = document.getElementById('label-env');
    const roleSel = document.getElementById('label-role');
    const ownerSel = document.getElementById('label-owner');
    if (!envSel || !roleSel || !ownerSel) return;

    const hosts = ctx.getAllHosts();
    const envVals = new Set();
    const roleVals = new Set();
    const ownerVals = new Set();
    (hosts || []).forEach(h => {
      const env = (w.hostLabel(h, 'env') || '').trim();
      const role = (w.hostLabel(h, 'role') || '').trim();
      const owner = (w.hostLabel(h, 'owner') || '').trim();
      if (env) envVals.add(env);
      if (role) roleVals.add(role);
      if (owner) ownerVals.add(owner);
    });

    const envList = Array.from(envVals).sort((a, b) => a.localeCompare(b));
    const roleList = Array.from(roleVals).sort((a, b) => a.localeCompare(b));
    const ownerList = Array.from(ownerVals).sort((a, b) => a.localeCompare(b));

    const prevEnv = envSel.value || '';
    const prevRole = roleSel.value || '';
    const prevOwner = ownerSel.value || '';

    envSel.innerHTML = `<option value="">Env: Any</option>` + envList.map(v => `<option value="${w.escapeHtml(v)}">${w.escapeHtml(v)}</option>`).join('');
    roleSel.innerHTML = `<option value="">Role: Any</option>` + roleList.map(v => `<option value="${w.escapeHtml(v)}">${w.escapeHtml(v)}</option>`).join('');
    ownerSel.innerHTML = `<option value="">Owner: Any</option>` + ownerList.map(v => `<option value="${w.escapeHtml(v)}">${w.escapeHtml(v)}</option>`).join('');

    envSel.value = (prevEnv && envList.includes(prevEnv)) ? prevEnv : '';
    roleSel.value = (prevRole && roleList.includes(prevRole)) ? prevRole : '';
    ownerSel.value = (prevOwner && ownerList.includes(prevOwner)) ? prevOwner : '';

    ctx.setLabelEnvFilter(envSel.value || '');
    ctx.setLabelRoleFilter(roleSel.value || '');
    ctx.setLabelOwnerFilter(ownerSel.value || '');
  }

  function applyHostFilters(ctx) {
    const q = w.normalize(ctx.getHostSearchQuery()).trim();
    let filtered = (ctx.getAllHosts() || []).slice();

    const vulnFilteredAgentIds = ctx.getVulnFilteredAgentIds();
    if (vulnFilteredAgentIds) filtered = filtered.filter(h => vulnFilteredAgentIds.has(h.agent_id));

    const labelEnvFilter = ctx.getLabelEnvFilter();
    const labelRoleFilter = ctx.getLabelRoleFilter();
    const labelOwnerFilter = ctx.getLabelOwnerFilter();
    if (labelEnvFilter) filtered = filtered.filter(h => (w.hostLabel(h, 'env') || '') === labelEnvFilter);
    if (labelRoleFilter) filtered = filtered.filter(h => (w.hostLabel(h, 'role') || '') === labelRoleFilter);
    if (labelOwnerFilter) filtered = filtered.filter(h => (w.hostLabel(h, 'owner') || '') === labelOwnerFilter);

    if (q) {
      filtered = filtered.filter(h => {
        const hay = `${h.hostname || ''} ${h.agent_id || ''} ${h.ip_address || ''} ${h.fqdn || ''} ${h.os_id || ''} ${h.os_version || ''}`.toLowerCase();
        return hay.includes(q);
      });
    }

    ctx.setLastRenderedAgentIds(filtered.map(h => h.agent_id));
    ctx.updateUpgradeControls();
  }

  async function loadHosts(ctx) {
    let controller = null;
    let timeout = null;
    try {
      if (typeof AbortController !== 'undefined') {
        controller = new AbortController();
        timeout = setTimeout(() => controller.abort(), 8000);
      }
      const response = await fetch('/hosts?online_only=true', { credentials: 'include', cache: 'no-store', ...(controller ? { signal: controller.signal } : {}) });
      if (!response.ok) {
        if (response.status === 403 && typeof w.loadAuthInfo === 'function') {
          try { await w.loadAuthInfo(); } catch (_) {}
        }
        throw new Error(`hosts failed (${response.status})`);
      }
      const hosts = await response.json();
      const list = Array.isArray(hosts) ? hosts : [];
      ctx.setAllHosts(list);
      const currentAgentId = (typeof ctx.getCurrentAgentId === 'function') ? (ctx.getCurrentAgentId() || '') : '';
      if (currentAgentId && !list.some((h) => String(h?.agent_id || '') === String(currentAgentId))) {
        if (typeof ctx.clearCurrentHostSelection === 'function') ctx.clearCurrentHostSelection();
      }
      rebuildLabelFilterOptions(ctx);

      applyHostFilters(ctx);
    } catch (error) {
      const msg = (error && error.name === 'AbortError') ? 'hosts request timed out' : (error?.message || String(error));
      console.error('[loadHosts failed]', msg);
    } finally {
      if (timeout) clearTimeout(timeout);
    }
  }

  w.phase3HostList = {
    rebuildLabelFilterOptions,
    applyHostFilters,
    loadHosts,
  };
})(window);

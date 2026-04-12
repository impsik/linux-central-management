(function (w) {
  function getSshSelectedAgentIds(ctx) {
    const api = ctx || {};
    return api.getSelectedAgentIds?.() || new Set();
  }

  function setSshSelectedAgentIds(ctx, next) {
    const api = ctx || {};
    return api.setSelectedAgentIds?.((next instanceof Set) ? next : new Set());
  }

  function getSshSelectedKeyId(ctx) {
    const api = ctx || {};
    return api.getSelectedKeyId?.() || null;
  }

  function setSshSelectedKeyId(ctx, next) {
    const api = ctx || {};
    return api.setSelectedKeyId?.(next || null);
  }

  function getSshKeysCache(ctx) {
    const api = ctx || {};
    return api.getKeysCache?.() || [];
  }

  function setSshKeysCache(ctx, next) {
    const api = ctx || {};
    return api.setKeysCache?.(Array.isArray(next) ? next : []);
  }

  function setSshHostsPanelVisible(ctx, visible) {
    const panel = document.getElementById('sshkey-hosts-panel');
    if (!panel) return;
    panel.style.display = visible ? 'block' : 'none';
  }

  function renderSshHostsList(ctx) {
    const api = ctx || {};
    const selectedAgentIds = getSshSelectedAgentIds(api);
    const nextSelected = w.renderSshHostsListView({
      hosts: Array.isArray(api.getAllHosts?.()) ? api.getAllHosts() : [],
      selectedAgentIds,
      listId: 'sshkey-hosts-list',
      countId: 'sshkey-hosts-count',
      searchId: 'sshkey-hosts-search',
    }) || selectedAgentIds;
    setSshSelectedAgentIds(api, nextSelected);
  }

  w.phase3SshUiState = {
    getSshSelectedAgentIds,
    setSshSelectedAgentIds,
    getSshSelectedKeyId,
    setSshSelectedKeyId,
    getSshKeysCache,
    setSshKeysCache,
    setSshHostsPanelVisible,
    renderSshHostsList,
  };
})(window);

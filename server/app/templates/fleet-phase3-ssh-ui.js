(function (w) {
  function initSshKeysControls(ctx) {
    w.setupSshRefreshHandlers({
      loadSshKeys: ctx.loadSshKeys,
      maybeLoadSshKeyAdminQueue: ctx.maybeLoadSshKeyAdminQueue,
      loadAdminSshKeys: ctx.loadAdminSshKeys,
      loadAdminUsers: ctx.loadAdminUsers,
      loadAdminAudit: ctx.loadAdminAudit,
    });

    document.getElementById('sshkey-approval-modal-close')?.addEventListener('click', (e) => { e.preventDefault(); w.closeSshKeyDeployApprovalModal(); });
    document.getElementById('sshkey-approval-modal')?.addEventListener('click', (e) => { if (e.target && e.target.id === 'sshkey-approval-modal') w.closeSshKeyDeployApprovalModal(); });

    document.getElementById('sshkey-add')?.addEventListener('click', async (e) => {
      e.preventDefault();
      await w.handleSshKeyAdd({
        statusEl: document.getElementById('sshkey-add-status'),
        loadSshKeys: ctx.loadSshKeys,
      });
    });

    w.setupSshHostPickerControls({
      setPanelVisible: ctx.setSshHostsPanelVisible,
      renderList: ctx.renderSshHostsList,
      selectAll: () => {
        const selectedAgentIds = ctx.getSshSelectedAgentIds();
        (ctx.getAllHosts() || []).forEach(h => { if (h.agent_id) selectedAgentIds.add(h.agent_id); });
      },
      clearSelection: () => {
        ctx.setSshSelectedAgentIds(new Set());
      },
    });

    document.getElementById('sshkey-request-deploy')?.addEventListener('click', async (e) => {
      e.preventDefault();
      await w.handleSshRequestDeploy({
        statusEl: document.getElementById('sshkey-request-status'),
        selectedKeyId: ctx.getSshSelectedKeyId(),
        getSelectedAgentIds: () => Array.from(ctx.getSshSelectedAgentIds() || []),
        setPanelVisible: ctx.setSshHostsPanelVisible,
        renderList: ctx.renderSshHostsList,
        loadSshKeyRequests: ctx.loadSshKeyRequests,
        maybeLoadSshKeyAdminQueue: ctx.maybeLoadSshKeyAdminQueue,
        loadAdminSshKeys: ctx.loadAdminSshKeys,
      });
    });
  }

  w.phase3SshUi = {
    initSshKeysControls,
  };
})(window);

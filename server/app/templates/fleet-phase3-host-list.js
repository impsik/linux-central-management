(function (w) {
  function rebuildLabelFilterOptions(ctx) {
    const envSel = document.getElementById('label-env');
    const roleSel = document.getElementById('label-role');
    if (!envSel || !roleSel) return;

    const hosts = ctx.getAllHosts();
    const envVals = new Set();
    const roleVals = new Set();
    (hosts || []).forEach(h => {
      const env = (w.hostLabel(h, 'env') || '').trim();
      const role = (w.hostLabel(h, 'role') || '').trim();
      if (env) envVals.add(env);
      if (role) roleVals.add(role);
    });

    const envList = Array.from(envVals).sort((a, b) => a.localeCompare(b));
    const roleList = Array.from(roleVals).sort((a, b) => a.localeCompare(b));

    const prevEnv = envSel.value || '';
    const prevRole = roleSel.value || '';

    envSel.innerHTML = `<option value="">Env: Any</option>` + envList.map(v => `<option value="${w.escapeHtml(v)}">${w.escapeHtml(v)}</option>`).join('');
    roleSel.innerHTML = `<option value="">Role: Any</option>` + roleList.map(v => `<option value="${w.escapeHtml(v)}">${w.escapeHtml(v)}</option>`).join('');

    envSel.value = (prevEnv && envList.includes(prevEnv)) ? prevEnv : '';
    roleSel.value = (prevRole && roleList.includes(prevRole)) ? prevRole : '';

    ctx.setLabelEnvFilter(envSel.value || '');
    ctx.setLabelRoleFilter(roleSel.value || '');
  }

  function applyHostFilters(ctx) {
    const q = w.normalize(ctx.getHostSearchQuery()).trim();
    let filtered = (ctx.getAllHosts() || []).slice();

    const vulnFilteredAgentIds = ctx.getVulnFilteredAgentIds();
    if (vulnFilteredAgentIds) filtered = filtered.filter(h => vulnFilteredAgentIds.has(h.agent_id));

    const labelEnvFilter = ctx.getLabelEnvFilter();
    const labelRoleFilter = ctx.getLabelRoleFilter();
    if (labelEnvFilter) filtered = filtered.filter(h => (w.hostLabel(h, 'env') || '') === labelEnvFilter);
    if (labelRoleFilter) filtered = filtered.filter(h => (w.hostLabel(h, 'role') || '') === labelRoleFilter);

    if (q) {
      filtered = filtered.filter(h => {
        const hay = `${h.hostname || ''} ${h.agent_id || ''} ${h.ip_address || ''} ${h.fqdn || ''} ${h.os_id || ''} ${h.os_version || ''}`.toLowerCase();
        return hay.includes(q);
      });
    }

    ctx.renderHosts(filtered);
  }

  function renderHosts(ctx, hosts) {
    const hostsDiv = document.getElementById('hosts');
    hostsDiv.innerHTML = '';
    ctx.setLastRenderedAgentIds((hosts || []).map(h => h.agent_id));

    if (!hosts || hosts.length === 0) {
      hostsDiv.innerHTML = '<div class="empty-state">No hosts match your filters</div>';
      ctx.updateUpgradeControls();
      return;
    }

    hosts.forEach(host => {
      const div = document.createElement('div');
      div.className = 'host-item';
      div.dataset.agentId = host.agent_id;
      div.onclick = () => { ctx.selectHost(host.agent_id, host.hostname); };

      let pkgLine = '';
      const pkgNameInput = (document.getElementById('vuln-package')?.value || '').trim();
      const vulnVersionInput = (document.getElementById('vuln-version')?.value || '').trim();
      const lastPkgVerification = ctx.getLastPkgVerification();
      if (pkgNameInput && lastPkgVerification && lastPkgVerification.packageName === pkgNameInput) {
        const r = (lastPkgVerification.resultsByAgentId || {})[host.agent_id];
        if (r) {
          const v = r.version ? `<code>${w.escapeHtml(r.version)}</code>` : '<code>n/a</code>';
          if (r.status === 'upgraded') pkgLine = `<div class="pkg-status-line"><span class="pkg-badge good">Upgraded</span> ${v}</div>`;
          else if (r.status === 'vulnerable') {
            const vv = vulnVersionInput ? `<code>${w.escapeHtml(vulnVersionInput)}</code>` : '';
            pkgLine = `<div class="pkg-status-line"><span class="pkg-badge bad">Still vulnerable</span> ${v} ${vv ? `<span style="color:#a0aec0;">(vuln = ${vv})</span>` : ''}</div>`;
          } else if (r.status === 'installed') pkgLine = `<div class="pkg-status-line"><span class="pkg-badge neutral">Installed</span> ${v}</div>`;
          else if (r.status === 'not-installed') pkgLine = `<div class="pkg-status-line"><span class="pkg-badge neutral">Not installed</span></div>`;
          else pkgLine = `<div class="pkg-status-line"><span class="pkg-badge neutral">Unknown</span></div>`;
        }
      }

      const isOnline = !!host.is_online;
      const lastSeen = host.last_seen ? new Date(host.last_seen) : null;
      const lastSeenText = lastSeen ? w.formatRelativeTime(lastSeen) : 'never';
      const ip = host.ip_address || '';
      const fqdn = host.fqdn || '';
      const env = w.hostLabel(host, 'env') || '';
      const role = w.hostLabel(host, 'role') || '';
      const selectedAgentIds = ctx.getSelectedAgentIds();

      div.innerHTML = `
        <div class="host-select-wrap">
          <input class="host-select" type="checkbox" data-agent-id="${host.agent_id}" ${selectedAgentIds.has(host.agent_id) ? 'checked' : ''} />
        </div>
        <div class="host-meta">
          <div class="host-row-top">
            <div class="host-name">${w.escapeHtml(host.hostname || host.agent_id)}</div>
            <span class="status-dot ${isOnline ? 'online' : 'offline'}" title="${isOnline ? 'online' : 'offline'}"></span>
          </div>
          <div class="host-subline">
            <span class="host-subitem">${ip ? w.escapeHtml(ip) : (fqdn ? w.escapeHtml(fqdn) : '')}</span>
            <span class="host-subsep">•</span>
            <span class="host-subitem">seen ${w.escapeHtml(lastSeenText)}</span>
          </div>
          <div class="host-tags">
            ${env ? `<span class="tag">env: <code>${w.escapeHtml(env)}</code></span>` : ''}
            ${role ? `<span class="tag">role: <code>${w.escapeHtml(role)}</code></span>` : ''}
          </div>
          ${pkgLine}
        </div>
      `;
      hostsDiv.appendChild(div);

      const cb = div.querySelector('.host-select');
      if (cb) {
        cb.addEventListener('click', (e) => e.stopPropagation());
        cb.addEventListener('change', (e) => {
          e.stopPropagation();
          const aid = cb.getAttribute('data-agent-id');
          if (!aid) return;
          const selected = ctx.getSelectedAgentIds();
          if (cb.checked) selected.add(aid);
          else selected.delete(aid);
          ctx.updateUpgradeControls();
        });
      }
    });

    const currentAgentId = ctx.getCurrentAgentId();
    if (currentAgentId) {
      document.querySelectorAll('.host-item').forEach(item => {
        if (item.dataset.agentId === currentAgentId) item.classList.add('active');
      });
    }

    ctx.updateUpgradeControls();
  }

  async function loadHosts(ctx) {
    try {
      const response = await fetch('/hosts?online_only=true');
      const hosts = await response.json();
      ctx.setAllHosts(hosts || []);
      rebuildLabelFilterOptions(ctx);

      if ((ctx.getAllHosts() || []).length === 0) {
        document.getElementById('hosts').innerHTML = '<div class="empty-state">No hosts found</div>';
        return;
      }

      applyHostFilters(ctx);
    } catch (error) {
      document.getElementById('hosts').innerHTML = `<div class="error">Error loading hosts: ${error.message}</div>`;
    }
  }

  w.phase3HostList = {
    rebuildLabelFilterOptions,
    applyHostFilters,
    renderHosts,
    loadHosts,
  };
})(window);

(function (w) {
  function ensureOwnerFilterControl() {
    let ownerSel = document.getElementById('label-owner');
    if (ownerSel) return ownerSel;
    const roleSel = document.getElementById('label-role');
    const roleRow = roleSel ? roleSel.closest('.vuln-row') : null;
    const parent = roleRow ? roleRow.parentElement : null;
    if (!roleSel || !roleRow || !parent) return null;
    const row = document.createElement('div');
    row.className = 'vuln-row';
    row.innerHTML = '<select id="label-owner" class="host-search"><option value="">Owner: Any</option></select>';
    roleRow.insertAdjacentElement('afterend', row);
    return row.querySelector('#label-owner');
  }

  function rebuildLabelFilterOptions(ctx) {
    const envSel = document.getElementById('label-env');
    const roleSel = document.getElementById('label-role');
    const ownerSel = ensureOwnerFilterControl();
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

    if (typeof ctx.setLabelEnvFilter === 'function') ctx.setLabelEnvFilter(envSel.value || '');
    if (typeof ctx.setLabelRoleFilter === 'function') ctx.setLabelRoleFilter(roleSel.value || '');
    if (typeof ctx.setLabelOwnerFilter === 'function') ctx.setLabelOwnerFilter(ownerSel.value || '');
  }

  function applyHostFilters(ctx) {
    const q = w.normalize(ctx.getHostSearchQuery()).trim();
    let filtered = (ctx.getAllHosts() || []).slice();

    const vulnFilteredAgentIds = ctx.getVulnFilteredAgentIds();
    if (vulnFilteredAgentIds) filtered = filtered.filter(h => vulnFilteredAgentIds.has(h.agent_id));

    const labelEnvFilter = (typeof ctx.getLabelEnvFilter === 'function') ? ctx.getLabelEnvFilter() : '';
    const labelRoleFilter = (typeof ctx.getLabelRoleFilter === 'function') ? ctx.getLabelRoleFilter() : '';
    const labelOwnerFilter = (typeof ctx.getLabelOwnerFilter === 'function') ? ctx.getLabelOwnerFilter() : '';
    if (labelEnvFilter) filtered = filtered.filter(h => (w.hostLabel(h, 'env') || '') === labelEnvFilter);
    if (labelRoleFilter) filtered = filtered.filter(h => (w.hostLabel(h, 'role') || '') === labelRoleFilter);
    if (labelOwnerFilter) filtered = filtered.filter(h => (w.hostLabel(h, 'owner') || '') === labelOwnerFilter);

    if (q) {
      filtered = filtered.filter(h => {
        const hay = `${h.hostname || ''} ${h.agent_id || ''} ${h.ip_address || ''} ${h.fqdn || ''} ${h.os_id || ''} ${h.os_version || ''}`.toLowerCase();
        return hay.includes(q);
      });
    }

    const sortSel = document.getElementById('hosts-sort');
    const orderSel = document.getElementById('hosts-order');
    const sort = String(sortSel?.value || 'hostname');
    const order = String(orderSel?.value || 'asc');
    const dir = order === 'desc' ? -1 : 1;
    const cmpText = (a, b) => String(a || '').localeCompare(String(b || ''), undefined, { sensitivity: 'base' });
    const cmpNum = (a, b) => Number(a || 0) - Number(b || 0);
    filtered.sort((a, b) => {
      if (sort === 'owner') {
        const ownerCmp = cmpText(w.hostLabel(a, 'owner') || '', w.hostLabel(b, 'owner') || '');
        if (ownerCmp !== 0) return ownerCmp * dir;
        return cmpText(a.hostname || a.agent_id || '', b.hostname || b.agent_id || '') * dir;
      }
      if (sort === 'os_version') return cmpText(a.os_version || '', b.os_version || '') * dir;
      if (sort === 'updates') return cmpNum(a.updates, b.updates) * dir;
      if (sort === 'security_updates') return cmpNum(a.security_updates, b.security_updates) * dir;
      if (sort === 'last_seen') return cmpNum(new Date(a.last_seen || 0).getTime(), new Date(b.last_seen || 0).getTime()) * dir;
      return cmpText(a.hostname || a.agent_id || '', b.hostname || b.agent_id || '') * dir;
    });

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
            pkgLine = `<div class="pkg-status-line"><span class="pkg-badge bad">Still vulnerable</span> ${v} ${vv ? `<span class="status-muted">(vuln = ${vv})</span>` : ''}</div>`;
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
      const owner = w.hostLabel(host, 'owner') || '';
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
            ${owner ? `<span class="tag">owner: <code>${w.escapeHtml(owner)}</code></span>` : ''}
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
    let controller = null;
    let timeout = null;
    try {
      if (typeof AbortController !== 'undefined') {
        controller = new AbortController();
        timeout = setTimeout(() => controller.abort(), 8000);
      }
      const fetchHosts = async (onlineOnly) => {
        const r = await fetch(`/hosts?online_only=${onlineOnly ? 'true' : 'false'}`, { credentials: 'include', ...(controller ? { signal: controller.signal } : {}) });
        if (!r.ok) {
          if (r.status === 403 && typeof w.loadAuthInfo === 'function') {
            try { await w.loadAuthInfo(); } catch (_) {}
          }
          throw new Error(`hosts failed (${r.status})`);
        }
        const data = await r.json();
        return Array.isArray(data) ? data : [];
      };

      let list = await fetchHosts(true);
      if (list.length === 0) {
        list = await fetchHosts(false);
      }
      ctx.setAllHosts(list);
      rebuildLabelFilterOptions(ctx);

      if (list.length === 0) {
        document.getElementById('hosts').innerHTML = '<div class="empty-state">No hosts found</div>';
        return;
      }

      applyHostFilters(ctx);
    } catch (error) {
      const msg = (error && error.name === 'AbortError') ? 'hosts request timed out' : (error?.message || String(error));
      document.getElementById('hosts').innerHTML = `<div class="error">Error loading hosts: ${msg}</div>`;
    } finally {
      if (timeout) clearTimeout(timeout);
    }
  }

  w.phase3HostList = {
    ensureOwnerFilterControl,
    rebuildLabelFilterOptions,
    applyHostFilters,
    renderHosts,
    loadHosts,
  };
})(window);

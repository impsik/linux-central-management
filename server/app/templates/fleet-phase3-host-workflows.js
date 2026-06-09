(function (w) {
  async function loadUsers(ctx, agentId) {
    const usersList = document.getElementById('users-list');
    usersList.innerHTML = '<div class="loading">Loading users...</div>';

    try {
      const response = await fetch(`/hosts/${agentId}/users`);
      if (!response.ok) {
        let errorMsg = response.statusText;
        try {
          const errorData = await response.json();
          errorMsg = errorData.detail || errorData.message || response.statusText;
        } catch {
          errorMsg = response.statusText;
        }
        throw new Error(`Failed to load users: ${errorMsg}`);
      }
      const data = await response.json();

      if (!data.users || data.users.length === 0) {
        usersList.innerHTML = '<div class="empty-state">No users found</div>';
        return;
      }

      usersList.innerHTML = data.users.map(user => {
        const isNew = !!user.is_new;
        const canLockUsers = !!ctx.getCurrentPermissions()?.can_lock_users;
        const isRoot = user.username === 'root';
        const disabledReason = !canLockUsers
          ? 'Admin access required'
          : isRoot
            ? 'Cannot lock root account'
            : '';
        return `
          <div class="user-card ${isNew ? 'new-user' : ''}" data-username="${w.escapeHtml(user.username)}">
            <div class="user-info">
              <div class="user-name"><a href="#" class="user-name-link" data-username="${w.escapeHtml(user.username)}">${w.escapeHtml(user.username)}</a>${isNew ? '<span class="new-user-badge">NEW</span>' : ''}</div>
              <div class="user-details">
                UID: ${w.escapeHtml(user.uid)} | GID: ${w.escapeHtml(user.gid)} | Shell: ${w.escapeHtml(user.shell || 'N/A')}${user.home ? ` | Home: ${w.escapeHtml(user.home)}` : ''}
              </div>
              <div class="user-badges">
                <span class="sudo-badge ${user.has_sudo ? 'yes' : 'no'}">
                  ${user.has_sudo ? '✓ Has Sudo' : '✗ No Sudo'}
                </span>
                ${user.is_locked ? '<span class="sudo-badge no">Locked</span>' : ''}
              </div>
            </div>
            <div class="service-actions">
              <button class="btn ${user.is_locked ? 'btn-success' : 'btn-warning'}"
                data-user-action="${user.is_locked ? 'unlock' : 'lock'}"
                data-username="${w.escapeHtml(user.username)}"
                ${(isRoot || !canLockUsers) ? `disabled title="${disabledReason}"` : ''}>
                ${user.is_locked ? 'Unlock' : 'Lock'}
              </button>
            </div>
          </div>
        `;
      }).join('');

      usersList.querySelectorAll('a.user-name-link').forEach(a => {
        a.addEventListener('click', (e) => {
          e.preventDefault();
          const username = a.getAttribute('data-username') || '';
          if (!username) return;
          w.openUserModal(agentId, username);
        });
      });

      usersList.querySelectorAll('button[data-user-action][data-username]').forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.preventDefault();
          const action = btn.getAttribute('data-user-action') || '';
          const username = btn.getAttribute('data-username') || '';
          if (!action || !username) return;
          controlUser(ctx, ctx.getCurrentAgentId(), username, action);
        });
      });
    } catch (error) {
      console.error('Error loading users:', error);
      usersList.innerHTML = `<div class="error">Error loading users: ${error.message}</div>`;
    }
  }

  async function loadServices(ctx, agentId) {
    const servicesList = document.getElementById('services-list');
    servicesList.innerHTML = '<div class="loading">Loading services...</div>';

    try {
      const response = await fetch(`/hosts/${agentId}/services`);
      if (!response.ok) {
        let errorMsg = response.statusText;
        try {
          const errorData = await response.json();
          errorMsg = errorData.detail || errorData.message || response.statusText;
        } catch {
          errorMsg = response.statusText;
        }
        throw new Error(`Failed to load services: ${errorMsg}`);
      }
      const data = await response.json();

      if (!data.services || data.services.length === 0) {
        servicesList.innerHTML = '<div class="empty-state">No services found</div>';
        return;
      }

      servicesList.innerHTML = data.services.map(service => {
        const statusClass = service.status === 'active' ? 'active' : service.status === 'failed' ? 'failed' : 'inactive';
        const enabledBadge = service.enabled ? '<span class="sudo-badge yes" style="margin-left: 0.5rem;">✓ Autostart</span>' : '<span class="sudo-badge no" style="margin-left: 0.5rem;">✗ Manual start</span>';
        return `
            <div class="service-card" data-service-name="${w.escapeHtml(service.name)}">
              <div class="service-info">
                <div class="service-name"><a href="#" class="service-name-link" data-service="${w.escapeHtml(service.name)}" style="text-decoration:underline;">${w.escapeHtml(service.name)}</a></div>
                <div class="service-details">
                  <span class="service-status ${statusClass}">${w.escapeHtml(service.status)}</span>
                  ${enabledBadge}
                  ${w.escapeHtml(service.description || '')}
                </div>
              </div>
              <div class="service-actions">
                <button class="btn btn-success" data-service-action="start" data-service-name="${w.escapeHtml(service.name)}"
                  ${service.status === 'active' ? 'disabled' : ''}>Start</button>
                <button class="btn btn-warning" data-service-action="restart" data-service-name="${w.escapeHtml(service.name)}">Restart</button>
                <button class="btn btn-danger" data-service-action="stop" data-service-name="${w.escapeHtml(service.name)}"
                  ${service.status !== 'active' ? 'disabled' : ''}>Stop</button>
                <button class="btn ${service.enabled ? 'btn-danger' : 'btn-success'}" data-service-action="${service.enabled ? 'disable' : 'enable'}" data-service-name="${w.escapeHtml(service.name)}">
                  ${service.enabled ? 'Disable' : 'Enable'}
                </button>
              </div>
            </div>
          `;
      }).join('');

      servicesList.querySelectorAll('a.service-name-link').forEach(a => {
        a.addEventListener('click', (e) => {
          e.preventDefault();
          const name = a.getAttribute('data-service') || '';
          if (!name) return;
          w.openServiceModal(agentId, name);
        });
      });

      servicesList.querySelectorAll('button[data-service-action][data-service-name]').forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.preventDefault();
          const action = btn.getAttribute('data-service-action') || '';
          const serviceName = btn.getAttribute('data-service-name') || '';
          if (!action || !serviceName) return;
          controlService(ctx, agentId, serviceName, action);
        });
      });
    } catch (error) {
      console.error('Error loading services:', error);
      servicesList.innerHTML = `<div class="error">Error loading services: ${error.message}</div>`;
    }
  }

  function formatFirewallRule(rule) {
    const parts = [];
    if (rule.service) parts.push(`service ${rule.service}`);
    if (rule.port) parts.push(`${rule.port}${rule.protocol ? '/' + rule.protocol : ''}`);
    if (rule.action) parts.push(String(rule.action).toUpperCase());
    if (rule.source) parts.push(`from ${rule.source}`);
    return parts.length ? parts.join(' ') : (rule.raw || '-');
  }

  async function loadFirewall(ctx, agentId) {
    const list = document.getElementById('firewall-list');
    if (!list) return;
    list.innerHTML = '<div class="loading">Loading firewall rules...</div>';

    try {
      const response = await fetch(`/hosts/${agentId}/firewall`);
      if (!response.ok) {
        let errorMsg = response.statusText;
        try {
          const errorData = await response.json();
          errorMsg = errorData.detail || errorData.message || response.statusText;
        } catch {
          errorMsg = response.statusText;
        }
        throw new Error(`Failed to load firewall rules: ${errorMsg}`);
      }
      const data = await response.json();
      const rules = Array.isArray(data.rules) ? data.rules : [];
      const backend = data.backend || 'unknown';
      const status = data.status || 'unknown';
      const zone = data.zone ? ` • zone ${w.escapeHtml(data.zone)}` : '';
      const canManage = !!ctx.getCurrentPermissions()?.can_manage_services;
      const summary = `<div class="admin-note" style="margin-bottom:0.75rem;">Backend: <b>${w.escapeHtml(backend)}</b> • Status: <b>${w.escapeHtml(status)}</b>${zone}</div>`;
      if (!rules.length) {
        list.innerHTML = summary + '<div class="empty-state">No firewall rules reported</div>';
        return;
      }

      list.innerHTML = summary + rules.map((rule) => {
        const text = formatFirewallRule(rule);
        const port = rule.port || '';
        const protocol = rule.protocol || 'tcp';
        const service = rule.service || '';
        return `
          <div class="service-card">
            <div class="service-info">
              <div class="service-name">${w.escapeHtml(text)}</div>
              <div class="service-details">${w.escapeHtml(rule.raw || '')}</div>
            </div>
            <div class="service-actions">
              <button class="btn btn-danger" data-firewall-delete="1" data-port="${w.escapeHtml(port)}" data-protocol="${w.escapeHtml(protocol)}" data-service="${w.escapeHtml(service)}" ${((!port && !service) || !canManage) ? 'disabled' : ''}>Remove allow</button>
            </div>
          </div>
        `;
      }).join('');

      list.querySelectorAll('button[data-firewall-delete]').forEach((btn) => {
        btn.addEventListener('click', (e) => {
          e.preventDefault();
          const port = Number(btn.getAttribute('data-port') || '0');
          const protocol = btn.getAttribute('data-protocol') || 'tcp';
          const service = btn.getAttribute('data-service') || '';
          if (!port && !service) return;
          controlFirewall(ctx, agentId, { action: 'delete', port, protocol, service });
        });
      });
    } catch (error) {
      console.error('Error loading firewall:', error);
      list.innerHTML = `<div class="error">Error loading firewall rules: ${w.escapeHtml(error.message)}</div>`;
    }
  }

  function readHostFirewallPayload(action) {
    const port = Number(document.getElementById('host-firewall-port')?.value || '0');
    const protocol = document.getElementById('host-firewall-protocol')?.value || 'tcp';
    const source = (document.getElementById('host-firewall-source')?.value || '').trim();
    const service = (document.getElementById('host-firewall-service')?.value || '').trim();
    return { action, port, protocol, source, service };
  }

  async function controlFirewall(ctx, agentId, payload) {
    if (!ctx.getCurrentPermissions()?.can_manage_services) {
      w.showToast('Service management permission required to manage firewall rules.', 'error');
      return;
    }
    const statusEl = document.getElementById('host-firewall-status');
    if (!payload.service && (!payload.port || payload.port < 1 || payload.port > 65535)) {
      w.showToast('Enter a valid port or service', 'error');
      return;
    }
    try {
      if (statusEl) statusEl.textContent = `${payload.action} rule queued…`;
      const response = await fetch(`/hosts/${agentId}/firewall/rules`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        let errorMsg = `Failed to ${payload.action} firewall rule`;
        try {
          const error = await response.json();
          errorMsg = error.detail || error.message || errorMsg;
        } catch {
          errorMsg = response.statusText || errorMsg;
        }
        throw new Error(errorMsg);
      }
      await response.json();
      if (statusEl) statusEl.textContent = 'Firewall updated. Refreshing…';
      w.showToast('Firewall rule updated', 'success');
      await loadFirewall(ctx, agentId);
      if (statusEl) statusEl.textContent = '';
    } catch (error) {
      console.error('Error controlling firewall:', error);
      if (statusEl) statusEl.textContent = error.message || 'Firewall action failed';
      w.showToast(error.message || 'Firewall action failed', 'error');
    }
  }

  function initHostFirewallControls(ctx) {
    document.getElementById('host-firewall-refresh')?.addEventListener('click', (e) => {
      e.preventDefault();
      const aid = ctx.getCurrentAgentId ? ctx.getCurrentAgentId() : null;
      if (aid) void loadFirewall(ctx, aid);
    });
    ['allow', 'deny', 'delete'].forEach((action) => {
      document.getElementById(`host-firewall-${action}`)?.addEventListener('click', (e) => {
        e.preventDefault();
        const aid = ctx.getCurrentAgentId ? ctx.getCurrentAgentId() : null;
        if (!aid) return;
        void controlFirewall(ctx, aid, readHostFirewallPayload(action));
      });
    });
  }

  async function waitForServicesToStabilize(ctx, agentId, targetServiceName = null) {
    const maxWaitTime = 120000;
    const pollInterval = 3000;
    const startTime = Date.now();
    let pollCount = 0;
    let lastStatus = null;

    while (Date.now() - startTime < maxWaitTime) {
      pollCount++;
      try {
        const response = await fetch(`/hosts/${agentId}/services`);
        if (!response.ok) throw new Error(`Failed to fetch services: ${response.statusText}`);

        const data = await response.json();
        const services = data.services || [];

        if (targetServiceName) {
          const targetService = services.find(s => s.name === targetServiceName);
          if (targetService) {
            const currentStatus = targetService.status;
            lastStatus = currentStatus;
            if (currentStatus === 'active' || currentStatus === 'failed') {
              await loadServices(ctx, agentId);
              return;
            }
            if (currentStatus === 'activating' || currentStatus === 'deactivating' || currentStatus === 'inactive') {
              await new Promise(resolve => setTimeout(resolve, pollInterval));
              continue;
            }
          }
        }

        const hasActivating = services.some(s => s.status === 'activating' || s.status === 'deactivating');
        if (!hasActivating) {
          await loadServices(ctx, agentId);
          return;
        }
      } catch (error) {
        console.error('Error checking services status during polling:', error);
      }
      await new Promise(resolve => setTimeout(resolve, pollInterval));
    }

    await loadServices(ctx, agentId);
  }

  async function controlService(ctx, agentId, serviceName, action) {
    const targetCard = document.querySelector(`.service-card[data-service-name="${serviceName}"]`);
    if (targetCard) {
      const buttons = targetCard.querySelectorAll('.btn');
      buttons.forEach(btn => {
        btn.disabled = true;
        btn.style.opacity = '0.6';
        btn.style.cursor = 'wait';
      });
      const statusBadge = targetCard.querySelector('.service-status');
      if (statusBadge) {
        const actionText = action === 'start' ? 'Starting' : action === 'stop' ? 'Stopping' : action === 'restart' ? 'Restarting' : action === 'enable' ? 'Enabling' : action === 'disable' ? 'Disabling' : action;
        statusBadge.textContent = actionText + '...';
        statusBadge.className = 'service-status';
      }
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 40000);

      const response = await fetch(`/hosts/${agentId}/services/${encodeURIComponent(serviceName)}/${action}`, {
        method: 'POST',
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        let errorMsg = `Failed to ${action} service`;
        try {
          const error = await response.json();
          errorMsg = error.detail || error.message || errorMsg;
        } catch {
          errorMsg = response.statusText || errorMsg;
        }
        throw new Error(errorMsg);
      }

      await response.json();
      const actionLabel = action === 'start' ? 'Started' : action === 'stop' ? 'Stopped' : action === 'restart' ? 'Restarted' : action === 'enable' ? 'Enabled' : action === 'disable' ? 'Disabled' : action;
      w.showToast(`${actionLabel} ${serviceName}`, 'success');
      await new Promise(resolve => setTimeout(resolve, 1000));
      await loadServices(ctx, agentId);
    } catch (error) {
      console.error('Error controlling service:', error);
      if (targetCard) {
        const buttons = targetCard.querySelectorAll('.btn');
        buttons.forEach(btn => {
          btn.disabled = false;
          btn.style.opacity = '1';
          btn.style.cursor = 'pointer';
        });
      }
      let errorMsg = error.message;
      if (error.name === 'AbortError') {
        errorMsg = 'Operation timed out. The service may still be processing. Refreshing status...';
      }
      w.showToast(errorMsg, 'error');
      await waitForServicesToStabilize(ctx, agentId, serviceName);
    }
  }

  async function controlUser(ctx, agentId, username, action) {
    if (!ctx.getCurrentPermissions()?.can_lock_users) {
      w.showToast('Admin access required to lock or unlock users.', 'error');
      return;
    }
    const targetCard = document.querySelector(`.user-card[data-username="${username}"]`);
    if (targetCard) {
      const button = targetCard.querySelector('.btn');
      if (button) {
        button.disabled = true;
        button.style.opacity = '0.6';
        button.style.cursor = 'wait';
        button.textContent = action === 'lock' ? 'Locking...' : 'Unlocking...';
      }
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 20000);

      const response = await fetch(`/hosts/${agentId}/users/${encodeURIComponent(username)}/${action}`, {
        method: 'POST',
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        let errorMsg = `Failed to ${action} user`;
        try {
          const error = await response.json();
          errorMsg = error.detail || error.message || errorMsg;
        } catch {
          errorMsg = response.statusText || errorMsg;
        }
        throw new Error(errorMsg);
      }

      await response.json();
      w.showToast(`${action === 'lock' ? 'Locked' : 'Unlocked'} ${username}`, 'success');
      await new Promise(resolve => setTimeout(resolve, 500));
      await loadUsers(ctx, agentId);
    } catch (error) {
      console.error('Error controlling user:', error);
      if (targetCard) {
        const button = targetCard.querySelector('.btn');
        if (button) {
          button.disabled = false;
          button.style.opacity = '1';
          button.style.cursor = 'pointer';
          button.textContent = 'Loading...';
        }
      }
      let errorMsg = error.message;
      if (error.name === 'AbortError') {
        errorMsg = 'Operation timed out. The user status may still be updating. Refreshing...';
      }
      w.showToast(errorMsg, 'error');
      await loadUsers(ctx, agentId);
    }
  }

  w.phase3HostWorkflows = {
    loadUsers,
    loadServices,
    loadFirewall,
    initHostFirewallControls,
    waitForServicesToStabilize,
    controlService,
    controlFirewall,
    controlUser,
  };
})(window);

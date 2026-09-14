(function (w) {
  function attachmentCommand(host, username) {
    host = String(host || '').trim();
    username = String(username || '').trim();
    const labels = host.split('.');
    if (!host || host.length > 253 || !labels.every(label => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label)) || ['all', 'ungrouped'].includes(host.toLowerCase())) {
      throw new Error('Enter one IPv4 address or DNS hostname, without a URL, port or spaces.');
    }
    if (/^[0-9.]+$/.test(host) && (labels.length !== 4 || labels.some(n => Number(n) > 255))) {
      throw new Error('Enter a valid IPv4 address.');
    }
    if (!/^[a-zA-Z_][a-zA-Z0-9_-]{0,63}$/.test(username)) {
      throw new Error('Enter the SSH account name, for example ubuntu or fleet-admin.');
    }
    return { host, command: `ATTACH_HOSTS='${host}' ANSIBLE_USER='${username}' ./add-host.sh` };
  }

  function progress(host) {
    if (!host) return { registered: false, online: false, system: false, inventory: false, ready: false };
    const system = !!(host.os_id && host.os_version);
    return { registered: true, online: !!host.online, system, inventory: !!host.inventory_received,
      ready: !!host.online && system && !!host.inventory_received };
  }

  function init(ctx) {
    const panel = document.getElementById('fleet-onboarding');
    if (!panel || panel.dataset.initialized) return;
    panel.dataset.initialized = 'true';
    const el = id => document.getElementById(`onboarding-${id}`);
    const dashboard = document.getElementById('server-info-placeholder');
    const openButton = document.getElementById('onboarding-open');
    let active = false;
    let initialized = false;
    let target = '';
    let selectedHost = null;
    let pending = false;
    let tracking = false;
    let enrollmentId = null;
    let runLocation = 'the admin node';
    let joining = false;
    const csrfHeaders = () => ({ 'X-CSRF-Token': w.getCookie?.('fleet_csrf') || '' });

    function show(value) {
      active = value;
      panel.hidden = !value;
      dashboard.classList.toggle('onboarding-active', value);
    }

    function render(host) {
      selectedHost = host;
      const state = progress(host);
      for (const key of ['registered', 'online', 'system', 'inventory']) {
        const item = el(key);
        item.dataset.state = state[key] ? 'done' : 'waiting';
        item.querySelector('span').textContent = state[key] ? '✓' : '…';
      }
      el('progress').hidden = !tracking;
      el('view').hidden = !state.ready;
      el('host-summary').textContent = host
        ? `${host.hostname} · ${host.os_id || 'OS pending'} ${host.os_version || ''} · ${host.package_count} installed packages · ${host.updates_count} cached updates`
        : tracking ? `Waiting for the agent. Run the command on ${runLocation} to begin.`
        : 'Connection checks will appear after you prepare the command.';
      el('last-seen').textContent = host?.last_seen ? `Last contact: ${new Date(host.last_seen).toLocaleString()}` : '';
      el('connection-help').hidden = !tracking || state.ready;
      el('status').textContent = !tracking ? 'Create a join command to get started.' : state.ready
        ? 'Your host is connected and its package inventory is available.'
        : host && !state.online ? 'The agent registered, but is not currently connected. Check its service and network access.'
        : host && !state.inventory ? 'Connected. Waiting for package inventory; this may take a few minutes.'
        : 'Waiting for registration. No changes are made until you run the command.';
    }

    async function refresh() {
      if (pending || (initialized && !active) || document.hidden) return;
      pending = true;
      const requestedTarget = target;
      try {
        const response = await fetch(`/onboarding/status?target=${encodeURIComponent(target)}`, { credentials: 'include', cache: 'no-store' });
        if (response.status === 401 || response.status === 403) {
          // MFA may still be required. Keep retrying without exposing admin setup.
          openButton.hidden = true;
          if (active) show(false);
          initialized = false;
          return;
        }
        if (!response.ok) throw new Error(`Setup status is unavailable (${response.status}). Use Refresh to retry.`);
        const data = await response.json();
        if (requestedTarget !== target) return;
        openButton.hidden = false;
        if (!initialized) {
          initialized = true;
          if (data.host_count === 0) {
            tracking = true;
            show(true);
          }
        }
        if (active) render(tracking ? data.host : null);
      } catch (error) {
        if (active) el('status').textContent = `${error.message} Check your connection; registration has not been confirmed.`;
      } finally {
        pending = false;
      }
    }

    openButton.addEventListener('click', () => {
      target = '';
      el('title').textContent = 'Connect a Linux host';
      tracking = false;
      el('command-box').hidden = true;
      render(null);
      show(true);
      el('join').focus();
      void refresh();
    });
    el('skip').addEventListener('click', () => show(false));
    el('refresh').addEventListener('click', () => { void refresh(); });
    el('join').addEventListener('click', async () => {
      if (joining) return;
      joining = true;
      el('join').disabled = true;
      try {
        if (enrollmentId) {
          const revoke = await fetch(`/onboarding/enrollments/${enrollmentId}`, { method: 'DELETE', headers: csrfHeaders(), credentials: 'include' });
          if (!revoke.ok) throw new Error('Could not revoke the previous command. Retry.');
        }
        const response = await fetch('/onboarding/enrollments', { method: 'POST', headers: csrfHeaders(), credentials: 'include' });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Could not create join command.');
        enrollmentId = data.id;
        target = data.agent_id;
        runLocation = 'the managed Linux host';
        tracking = true;
        el('command').textContent = data.command;
        el('command-box').hidden = false;
        el('run-title').textContent = '2. Run on the managed Linux host';
        el('run-help').textContent = 'Open a shell on the new host and paste this command. It asks for sudo when needed. The command is single-use; keep it private.';
        el('join-status').textContent = `Command expires at ${new Date(data.expires_at).toLocaleString()}.`;
        el('revoke').hidden = false;
        render(null);
        void refresh();
      } catch (error) {
        el('join-status').textContent = error.message;
      } finally {
        joining = false;
        el('join').disabled = false;
      }
    });
    el('revoke').addEventListener('click', async () => {
      if (!enrollmentId || joining) return;
      try {
        const response = await fetch(`/onboarding/enrollments/${enrollmentId}`, { method: 'DELETE', headers: csrfHeaders(), credentials: 'include' });
        if (!response.ok) throw new Error('Could not revoke command. Retry.');
        enrollmentId = null;
        el('command').textContent = '';
        el('command-box').hidden = true;
        el('revoke').hidden = true;
        el('join-status').textContent = 'Unused command revoked. An already enrolled host remains connected.';
      } catch (error) {
        el('join-status').textContent = error.message;
      }
    });
    el('form').addEventListener('submit', event => {
      event.preventDefault();
      try {
        const result = attachmentCommand(el('host').value, el('username').value);
        target = result.host;
        runLocation = 'the admin node';
        el('run-title').textContent = '2. Run on the admin node';
        el('run-help').textContent = 'Open a shell on the Master, change to ~/linux-central-management, then run:';
        tracking = true;
        el('command').textContent = result.command;
        el('command-box').hidden = false;
        el('form-error').textContent = '';
        render(null);
        void refresh();
      } catch (error) {
        el('form-error').textContent = error.message;
      }
    });
    el('copy').addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(el('command').textContent);
        el('copy-status').textContent = 'Command copied.';
      } catch (_) {
        el('copy-status').textContent = 'Select and copy the command manually.';
      }
    });
    el('view').addEventListener('click', () => {
      if (!selectedHost || !progress(selectedHost).ready) return;
      show(false);
      ctx.selectHost(selectedHost.agent_id, selectedHost.hostname);
      ctx.showPackages();
    });
    void refresh();
    w.setInterval(() => { void refresh(); }, 5000);
  }
  w.fleetOnboarding = { init, attachmentCommand, progress };
})(window);

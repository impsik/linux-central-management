(function (w) {
  function getCronSelectedAgentIds(ctx) {
    const api = ctx || {};
    return api.getState?.() || new Set();
  }

  function setCronSelectedAgentIds(ctx, next) {
    const api = ctx || {};
    return api.setState?.((next instanceof Set) ? next : new Set());
  }

  function setCronHostsPanelVisible(ctx, visible) {
    const api = ctx || {};
    const panel = document.getElementById('cron-hosts-panel');
    if (!panel) return;
    panel.style.display = visible ? 'block' : 'none';
    if (typeof api.onPanelVisibleChanged === 'function') api.onPanelVisibleChanged(visible);
  }

  function renderCronHostsList(ctx) {
    const api = ctx || {};
    const listEl = document.getElementById('cron-hosts-list');
    const countEl = document.getElementById('cron-hosts-count');
    if (!listEl) return;

    const selectedAgentIds = getCronSelectedAgentIds(api);
    const q = (document.getElementById('cron-hosts-search')?.value || '').trim().toLowerCase();
    const hosts = Array.isArray(api.getAllHosts?.()) ? api.getAllHosts().slice() : [];

    listEl.innerHTML = '';
    if (!hosts.length) {
      listEl.innerHTML = '<div class="empty-state" style="padding:0.75rem;">No hosts loaded yet.</div>';
      if (countEl) countEl.textContent = String(selectedAgentIds.size);
      return;
    }

    for (const h of hosts) {
      const aid = h.agent_id || '';
      const name = h.hostname || aid;
      const ip = h.ip_address || '';
      const os = `${h.os_id || ''} ${h.os_version || ''}`.trim();
      const hay = `${name} ${aid} ${ip} ${os}`.toLowerCase();
      if (q && !hay.includes(q)) continue;

      const row = document.createElement('label');
      row.style.display = 'flex';
      row.style.alignItems = 'center';
      row.style.justifyContent = 'space-between';
      row.style.gap = '0.75rem';
      row.style.padding = '0.5rem 0.6rem';
      row.style.borderRadius = '8px';
      row.style.cursor = 'pointer';
      row.style.background = 'transparent';

      const left = document.createElement('div');
      left.style.display = 'flex';
      left.style.flexDirection = 'column';
      left.style.gap = '0.1rem';

      const title = document.createElement('div');
      title.innerHTML = `<b>${w.escapeHtml(name)}</b> <span class="status-muted" style="font-size:0.85rem;">${w.escapeHtml(aid)}</span>`;
      const sub = document.createElement('div');
      sub.style.color = 'var(--muted-2)';
      sub.style.fontSize = '0.85rem';
      sub.textContent = ip ? ip : '';

      left.appendChild(title);
      if (ip) left.appendChild(sub);

      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.checked = selectedAgentIds.has(aid);
      cb.addEventListener('change', () => {
        if (cb.checked) selectedAgentIds.add(aid);
        else selectedAgentIds.delete(aid);
        if (countEl) countEl.textContent = String(selectedAgentIds.size);
      });

      row.appendChild(left);
      row.appendChild(cb);
      row.addEventListener('mouseenter', () => { row.style.background = 'color-mix(in srgb, var(--panel) 55%, transparent)'; });
      row.addEventListener('mouseleave', () => { row.style.background = 'transparent'; });

      listEl.appendChild(row);
    }

    if (countEl) countEl.textContent = String(selectedAgentIds.size);
  }

  w.phase3CronUi = {
    getCronSelectedAgentIds,
    setCronSelectedAgentIds,
    setCronHostsPanelVisible,
    renderCronHostsList,
  };
})(window);

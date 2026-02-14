(function (w) {
  function escapeHtml(s) {
    return String(s)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }

  function formatRelativeTime(d) {
    if (!(d instanceof Date) || isNaN(d.getTime())) return 'unknown';
    const sec = Math.floor((Date.now() - d.getTime()) / 1000);
    if (sec < 5) return 'just now';
    if (sec < 60) return sec + 's ago';
    const min = Math.floor(sec / 60);
    if (min < 60) return min + 'm ago';
    const hr = Math.floor(min / 60);
    if (hr < 48) return hr + 'h ago';
    const day = Math.floor(hr / 24);
    return day + 'd ago';
  }

  function safeJsonPreview(obj, max) {
    const limit = Number.isFinite(max) ? max : 140;
    try {
      const s = JSON.stringify(obj || {});
      if (s.length > limit) return s.slice(0, limit - 3) + '...';
      return s;
    } catch (_) {
      return '';
    }
  }

  function normalize(s) {
    return (s || '').toString().toLowerCase();
  }

  function matchesGlob(text, glob) {
    if (!glob) return false;
    if (!glob.includes('*') && !glob.includes('?')) return text === glob;
    const esc = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    const reStr = '^' + esc.replaceAll('\\*', '.*').replaceAll('\\?', '.') + '$';
    try {
      return new RegExp(reStr).test(text);
    } catch (_) {
      return false;
    }
  }

  function hostLabel(host, key) {
    try {
      return (host && host.labels && typeof host.labels === 'object') ? (host.labels[key] || '') : '';
    } catch (_) {
      return '';
    }
  }

  function getLoadHistoryLimitForRange(seconds) {
    // Keep UI responsive; server returns at most this many points
    if (seconds <= 3600) return 1200;
    if (seconds <= 6 * 3600) return 1500;
    if (seconds <= 24 * 3600) return 2000;
    return 3000;
  }

  function formatTimeLabel(d, rangeSeconds) {
    if (!(d instanceof Date) || isNaN(d.getTime())) return '';
    const opts = rangeSeconds <= 3600
      ? { hour: '2-digit', minute: '2-digit', second: '2-digit' }
      : { hour: '2-digit', minute: '2-digit' };
    return d.toLocaleTimeString([], opts);
  }

  function setButtonBusy(button, busy, busyText) {
    if (!button) return;
    const nextText = busyText || 'Working…';
    if (busy) {
      if (!button.dataset.prevText) button.dataset.prevText = button.textContent || '';
      button.disabled = true;
      button.classList.add('is-loading');
      button.setAttribute('aria-busy', 'true');
      button.textContent = nextText;
      return;
    }

    button.disabled = false;
    button.classList.remove('is-loading');
    button.removeAttribute('aria-busy');
    if (button.dataset.prevText) {
      button.textContent = button.dataset.prevText;
      delete button.dataset.prevText;
    }
  }

  function setTableState(tbody, colspan, kind, message) {
    if (!tbody) return;
    const esc = typeof w.escapeHtml === 'function'
      ? w.escapeHtml
      : function (s) { return String(s == null ? '' : s); };
    const color = kind === 'error' ? '#fca5a5' : '#a0aec0';
    tbody.innerHTML = '<tr><td colspan="' + String(colspan) + '" style="text-align:center;color:' + color + ';">' + esc(message) + '</td></tr>';
  }

  function bindSortableHeader(id, handler) {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('click', handler);
    el.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        handler(e);
      }
    });
  }

  function updateSortIndicators(defs, sort, order) {
    for (const pair of defs) {
      const id = pair[0];
      const key = pair[1];
      const el = document.getElementById(id);
      if (!el) continue;
      const active = key === sort;
      el.setAttribute('aria-sort', active ? (order === 'asc' ? 'ascending' : 'descending') : 'none');
      const icon = el.querySelector('.sort-indicator');
      if (icon) icon.textContent = active ? (order === 'asc' ? '↑' : '↓') : '↕';
    }
  }

  function updateReportSortIndicators(sort, order) {
    updateSortIndicators([
      ['th-host', 'hostname'],
      ['th-os', 'os_version'],
      ['th-updates', 'updates'],
    ], sort, order);
  }

  function updateHostsSortIndicators(sort, order) {
    updateSortIndicators([
      ['hosts-th-host', 'hostname'],
      ['hosts-th-os', 'os_version'],
      ['hosts-th-upd', 'updates'],
      ['hosts-th-sec', 'security_updates'],
      ['hosts-th-last', 'last_seen'],
    ], sort, order);
  }

  async function withBusyButton(button, busyText, action) {
    if (typeof action !== 'function') return;
    setButtonBusy(button, true, busyText || 'Working…');
    try {
      return await action();
    } finally {
      setButtonBusy(button, false);
    }
  }

  function wireBusyClick(button, busyText, handler) {
    if (!button || typeof handler !== 'function') return;
    button.addEventListener('click', function (e) {
      e.preventDefault();
      void withBusyButton(button, busyText, function () { return handler(e); });
    });
  }

  function setReportSort(sortKey, loadPendingUpdatesReport) {
    const sortSel = document.getElementById('report-sort');
    const orderSel = document.getElementById('report-order');
    if (!sortSel || !orderSel) return;

    const currentSort = sortSel.value;
    const currentOrder = orderSel.value;

    if (currentSort === sortKey) {
      orderSel.value = (currentOrder === 'asc') ? 'desc' : 'asc';
    } else {
      sortSel.value = sortKey;
      orderSel.value = 'desc';
    }

    updateReportSortIndicators(sortSel.value, orderSel.value);
    if (typeof loadPendingUpdatesReport === 'function') {
      void loadPendingUpdatesReport(true);
    }
  }

  function setupReportSortHandlers(loadPendingUpdatesReport) {
    w.__setReportSort = function (sortKey) {
      setReportSort(sortKey, loadPendingUpdatesReport);
    };

    bindSortableHeader('th-host', function () { setReportSort('hostname', loadPendingUpdatesReport); });
    bindSortableHeader('th-os', function () { setReportSort('os_version', loadPendingUpdatesReport); });
    bindSortableHeader('th-updates', function () { setReportSort('updates', loadPendingUpdatesReport); });
  }

  function setupKpiHandlers(showHostsTab, showOverviewTab, loadFailedRuns) {
    function jumpToHostsSorted(sortKey, order) {
      const sortSel = document.getElementById('hosts-sort');
      const orderSel = document.getElementById('hosts-order');
      if (sortSel) sortSel.value = sortKey;
      if (orderSel) orderSel.value = order || 'desc';
      if (typeof showHostsTab === 'function') showHostsTab();
      setTimeout(function () {
        const el = document.getElementById('hosts-table-tab');
        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 50);
    }

    const online = document.getElementById('kpi-hosts-online');
    if (online) online.addEventListener('click', function (e) { e.preventDefault(); jumpToHostsSorted('last_seen', 'desc'); });

    const security = document.getElementById('kpi-security');
    if (security) security.addEventListener('click', function (e) { e.preventDefault(); jumpToHostsSorted('security_updates', 'desc'); });

    const updates = document.getElementById('kpi-updates');
    if (updates) updates.addEventListener('click', function (e) { e.preventDefault(); jumpToHostsSorted('updates', 'desc'); });

    const failures = document.getElementById('kpi-failures');
    if (failures) {
      failures.addEventListener('click', function (e) {
        e.preventDefault();
        if (typeof showOverviewTab === 'function') showOverviewTab();
        setTimeout(async function () {
          const card = document.getElementById('failed-runs-card');
          if (card) card.scrollIntoView({ behavior: 'smooth', block: 'start' });
          if (typeof loadFailedRuns === 'function') await loadFailedRuns(24, true);
        }, 50);
      });
    }
  }

  function setupCronScheduleUi() {
    const kindEl = document.getElementById('cron-schedule-kind');
    const wrapWeekday = document.getElementById('cron-weekday-wrap');
    const wrapDom = document.getElementById('cron-dom-wrap');
    const wrapTime = document.getElementById('cron-time-wrap');
    const runAtWrap = document.getElementById('cron-run-at')?.parentElement;

    function apply() {
      const kind = kindEl?.value || 'once';
      if (wrapWeekday) wrapWeekday.style.display = (kind === 'weekly') ? 'block' : 'none';
      if (wrapDom) wrapDom.style.display = (kind === 'monthly') ? 'block' : 'none';
      if (wrapTime) wrapTime.style.display = (kind === 'daily' || kind === 'weekly' || kind === 'monthly') ? 'block' : 'none';
      if (runAtWrap) runAtWrap.style.display = (kind === 'once') ? 'block' : 'none';
    }

    if (kindEl) kindEl.addEventListener('change', apply);
    apply();
  }

  function setupCronHostPickerControls(opts) {
    const api = opts || {};
    const setPanelVisible = api.setPanelVisible;
    const renderList = api.renderList;
    const selectAll = api.selectAll;
    const clearSelection = api.clearSelection;

    const openBtn = document.getElementById('cron-hosts-open');
    if (openBtn) {
      openBtn.addEventListener('click', function (e) {
        e.preventDefault();
        if (typeof setPanelVisible === 'function') setPanelVisible(true);
        if (typeof renderList === 'function') renderList();
      });
    }

    const closeBtn = document.getElementById('cron-hosts-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', function (e) {
        e.preventDefault();
        if (typeof setPanelVisible === 'function') setPanelVisible(false);
      });
    }

    const searchInput = document.getElementById('cron-hosts-search');
    if (searchInput && typeof renderList === 'function') {
      searchInput.addEventListener('input', function () { renderList(); });
    }

    const clearBtn = document.getElementById('cron-hosts-search-clear');
    if (clearBtn) {
      clearBtn.addEventListener('click', function (e) {
        e.preventDefault();
        const el = document.getElementById('cron-hosts-search');
        if (el) el.value = '';
        if (typeof renderList === 'function') renderList();
      });
    }

    const selectAllBtn = document.getElementById('cron-hosts-select-all');
    if (selectAllBtn) {
      selectAllBtn.addEventListener('click', function (e) {
        e.preventDefault();
        if (typeof selectAll === 'function') selectAll();
        if (typeof renderList === 'function') renderList();
      });
    }

    const selectNoneBtn = document.getElementById('cron-hosts-select-none');
    if (selectNoneBtn) {
      selectNoneBtn.addEventListener('click', function (e) {
        e.preventDefault();
        if (typeof clearSelection === 'function') clearSelection();
        if (typeof renderList === 'function') renderList();
      });
    }
  }

  async function handleCronCreate(opts) {
    const api = opts || {};
    const getSelectedAgentIds = api.getSelectedAgentIds;
    const setPanelVisible = api.setPanelVisible;
    const renderList = api.renderList;
    const withBusy = api.withBusyButton || withBusyButton;
    const createBtn = api.createBtn || document.getElementById('cron-create');
    const statusEl = api.statusEl || document.getElementById('cron-create-status');

    const name = document.getElementById('cron-name')?.value || '';
    const action = document.getElementById('cron-action')?.value || 'dist-upgrade';
    const schedule_kind = document.getElementById('cron-schedule-kind')?.value || 'once';

    let run_at = null;
    if (schedule_kind === 'once') {
      const runAtLocal = document.getElementById('cron-run-at')?.value;
      if (!runAtLocal) {
        if (typeof w.showToast === 'function') w.showToast('Select a date/time', 'error');
        return;
      }
      const dt = new Date(runAtLocal);
      if (Number.isNaN(dt.getTime())) {
        if (typeof w.showToast === 'function') w.showToast('Invalid date/time', 'error');
        return;
      }
      run_at = dt.toISOString();
    }

    const agent_ids = Array.from((typeof getSelectedAgentIds === 'function' ? getSelectedAgentIds() : []) || []);
    if (!agent_ids.length) {
      if (typeof w.showToast === 'function') w.showToast('Select hosts first', 'error');
      if (typeof setPanelVisible === 'function') setPanelVisible(true);
      if (typeof renderList === 'function') renderList();
      return;
    }

    try {
      if (statusEl) statusEl.textContent = 'Creating…';
      await withBusy(createBtn, 'Creating…', async function () {
        const timezone = (Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC');
        const time_hhmm = document.getElementById('cron-time')?.value || null;
        const weekdayRaw = document.getElementById('cron-weekday')?.value;
        const dayRaw = document.getElementById('cron-day-of-month')?.value;
        const weekday = (weekdayRaw !== undefined && weekdayRaw !== '') ? Number(weekdayRaw) : null;
        const day_of_month = dayRaw ? Number(dayRaw) : null;

        const r = await fetch('/cronjobs', {
          method: 'POST',
          credentials: 'include',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ name, run_at, action, agent_ids, schedule_kind, timezone, time_hhmm, weekday, day_of_month }),
        });
        if (!r.ok) {
          const t = await r.text();
          throw new Error('create failed (' + String(r.status) + '): ' + t);
        }
        if (typeof w.showToast === 'function') w.showToast('Cronjob scheduled for ' + String(agent_ids.length) + ' hosts', 'success');
        if (statusEl) statusEl.textContent = '';
        if (typeof api.loadCronjobs === 'function') await api.loadCronjobs();
      });
    } catch (err) {
      if (typeof w.showToast === 'function') w.showToast((err && err.message) ? err.message : String(err), 'error');
      if (statusEl) statusEl.textContent = '';
    }
  }

  function setPanelVisibleById(panelId, visible) {
    const panel = document.getElementById(panelId);
    if (panel) panel.style.display = visible ? 'block' : 'none';
  }

  function renderSshHostsListView(opts) {
    const api = opts || {};
    const listEl = document.getElementById(api.listId || 'sshkey-hosts-list');
    const countEl = document.getElementById(api.countId || 'sshkey-hosts-count');
    const searchEl = document.getElementById(api.searchId || 'sshkey-hosts-search');
    const hosts = api.hosts || [];
    const selected = api.selectedAgentIds || new Set();
    const esc = typeof w.escapeHtml === 'function' ? w.escapeHtml : function (s) { return String(s ?? ''); };

    if (!listEl) return selected;

    const q = ((searchEl && searchEl.value) ? searchEl.value : '').trim().toLowerCase();
    listEl.innerHTML = '';

    for (const h of hosts) {
      const aid = h.agent_id || '';
      const name = h.hostname || aid;
      const ip = h.ip_address || '';
      const os = ((h.os_id || '') + ' ' + (h.os_version || '')).trim();
      const hay = (name + ' ' + aid + ' ' + ip + ' ' + os).toLowerCase();
      if (q && !hay.includes(q)) continue;

      const row = document.createElement('label');
      row.style.display = 'flex';
      row.style.alignItems = 'center';
      row.style.justifyContent = 'space-between';
      row.style.gap = '0.75rem';
      row.style.padding = '0.5rem 0.6rem';
      row.style.borderRadius = '8px';
      row.style.cursor = 'pointer';

      const left = document.createElement('div');
      left.style.display = 'flex';
      left.style.flexDirection = 'column';
      left.innerHTML = '<b>' + esc(name) + '</b><span style="color:#94a3b8;font-size:0.85rem;">' + esc(aid) + (os ? ' • ' + esc(os) : '') + '</span>';

      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.checked = selected.has(aid);
      cb.addEventListener('change', function () {
        if (cb.checked) selected.add(aid);
        else selected.delete(aid);
        if (countEl) countEl.textContent = String(selected.size);
      });

      row.appendChild(left);
      row.appendChild(cb);
      listEl.appendChild(row);
    }

    if (countEl) countEl.textContent = String(selected.size);
    return selected;
  }

  function setupSshHostPickerControls(opts) {
    const api = opts || {};
    const setPanelVisible = api.setPanelVisible;
    const renderList = api.renderList;
    const selectAll = api.selectAll;
    const clearSelection = api.clearSelection;

    const openBtn = document.getElementById('sshkey-hosts-open');
    if (openBtn) {
      openBtn.addEventListener('click', function (e) {
        e.preventDefault();
        if (typeof setPanelVisible === 'function') setPanelVisible(true);
        if (typeof renderList === 'function') renderList();
      });
    }

    const closeBtn = document.getElementById('sshkey-hosts-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', function (e) {
        e.preventDefault();
        if (typeof setPanelVisible === 'function') setPanelVisible(false);
      });
    }

    const searchInput = document.getElementById('sshkey-hosts-search');
    if (searchInput && typeof renderList === 'function') {
      searchInput.addEventListener('input', function () { renderList(); });
    }

    const clearBtn = document.getElementById('sshkey-hosts-search-clear');
    if (clearBtn) {
      clearBtn.addEventListener('click', function (e) {
        e.preventDefault();
        const el = document.getElementById('sshkey-hosts-search');
        if (el) el.value = '';
        if (typeof renderList === 'function') renderList();
      });
    }

    const selectAllBtn = document.getElementById('sshkey-hosts-select-all');
    if (selectAllBtn) {
      selectAllBtn.addEventListener('click', function (e) {
        e.preventDefault();
        if (typeof selectAll === 'function') selectAll();
        if (typeof renderList === 'function') renderList();
      });
    }

    const selectNoneBtn = document.getElementById('sshkey-hosts-select-none');
    if (selectNoneBtn) {
      selectNoneBtn.addEventListener('click', function (e) {
        e.preventDefault();
        if (typeof clearSelection === 'function') clearSelection();
        if (typeof renderList === 'function') renderList();
      });
    }
  }

  async function handleSshKeyAdd(opts) {
    const api = opts || {};
    const statusEl = api.statusEl || document.getElementById('sshkey-add-status');
    const loadSshKeys = api.loadSshKeys;

    const name = document.getElementById('sshkey-name')?.value || '';
    const public_key = document.getElementById('sshkey-pub')?.value || '';

    try {
      if (statusEl) statusEl.textContent = 'Adding…';
      const r = await fetch('/sshkeys', {
        method: 'POST',
        credentials: 'include',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name, public_key }),
      });
      if (!r.ok) throw new Error(await r.text());
      let resp = null;
      try { resp = await r.json(); } catch (_) { resp = null; }
      if (resp && resp.existing) {
        const nameInfo = resp.existing_name ? ' (existing name: ' + resp.existing_name + ')' : '';
        if (typeof w.showToast === 'function') w.showToast('Key already exists' + nameInfo, 'info');
      } else {
        if (typeof w.showToast === 'function') w.showToast('Key added', 'success');
      }
      if (statusEl) statusEl.textContent = '';
      const pubEl = document.getElementById('sshkey-pub');
      if (pubEl) pubEl.value = '';
      if (typeof loadSshKeys === 'function') await loadSshKeys();
    } catch (err) {
      if (typeof w.showToast === 'function') w.showToast((err && err.message) ? err.message : String(err), 'error');
      if (statusEl) statusEl.textContent = '';
    }
  }

  async function handleSshRequestDeploy(opts) {
    const api = opts || {};
    const statusEl = api.statusEl || document.getElementById('sshkey-request-status');
    const selectedKeyId = api.selectedKeyId;
    const getSelectedAgentIds = api.getSelectedAgentIds;

    if (!selectedKeyId) {
      if (typeof w.showToast === 'function') w.showToast('Select a key (click a row)', 'error');
      return;
    }
    const agent_ids = Array.from((typeof getSelectedAgentIds === 'function' ? getSelectedAgentIds() : []) || []);
    if (!agent_ids.length) {
      if (typeof w.showToast === 'function') w.showToast('Select hosts first', 'error');
      if (typeof api.setPanelVisible === 'function') api.setPanelVisible(true);
      if (typeof api.renderList === 'function') api.renderList();
      return;
    }

    try {
      if (statusEl) statusEl.textContent = 'Requesting…';
      const r = await fetch('/sshkeys/deploy-requests', {
        method: 'POST',
        credentials: 'include',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ key_id: selectedKeyId, agent_ids }),
      });
      if (!r.ok) throw new Error(await r.text());
      if (typeof w.showToast === 'function') w.showToast('Deployment requested (awaiting admin approval)', 'success');
      if (statusEl) statusEl.textContent = '';
      if (typeof api.loadSshKeyRequests === 'function') await api.loadSshKeyRequests();
      if (typeof api.maybeLoadSshKeyAdminQueue === 'function') await api.maybeLoadSshKeyAdminQueue();
      if (typeof api.loadAdminSshKeys === 'function') await api.loadAdminSshKeys();
    } catch (err) {
      if (typeof w.showToast === 'function') w.showToast((err && err.message) ? err.message : String(err), 'error');
      if (statusEl) statusEl.textContent = '';
    }
  }

  function setupSshRefreshHandlers(opts) {
    const api = opts || {};
    const refresh = document.getElementById('sshkey-refresh');
    if (refresh) refresh.addEventListener('click', function (e) { e.preventDefault(); if (typeof api.loadSshKeys === 'function') api.loadSshKeys(true); });
    const adminRefresh = document.getElementById('sshkey-admin-refresh');
    if (adminRefresh) adminRefresh.addEventListener('click', function (e) { e.preventDefault(); if (typeof api.maybeLoadSshKeyAdminQueue === 'function') api.maybeLoadSshKeyAdminQueue(); });
    const adminKeysRefresh = document.getElementById('sshkey-admin-keys-refresh');
    if (adminKeysRefresh) adminKeysRefresh.addEventListener('click', function (e) { e.preventDefault(); if (typeof api.loadAdminSshKeys === 'function') api.loadAdminSshKeys(); });
    const usersRefresh = document.getElementById('admin-users-refresh');
    if (usersRefresh) usersRefresh.addEventListener('click', function (e) { e.preventDefault(); if (typeof api.loadAdminUsers === 'function') api.loadAdminUsers(true); });
    const auditRefresh = document.getElementById('admin-audit-refresh');
    if (auditRefresh) auditRefresh.addEventListener('click', function (e) { e.preventDefault(); if (typeof api.loadAdminAudit === 'function') api.loadAdminAudit(true); });
  }

  w.escapeHtml = w.escapeHtml || escapeHtml;
  w.formatRelativeTime = w.formatRelativeTime || formatRelativeTime;
  w.safeJsonPreview = w.safeJsonPreview || safeJsonPreview;
  w.normalize = w.normalize || normalize;
  w.matchesGlob = w.matchesGlob || matchesGlob;
  w.hostLabel = w.hostLabel || hostLabel;
  w.getLoadHistoryLimitForRange = w.getLoadHistoryLimitForRange || getLoadHistoryLimitForRange;
  w.formatTimeLabel = w.formatTimeLabel || formatTimeLabel;
  w.setButtonBusy = setButtonBusy;
  w.setTableState = setTableState;
  w.bindSortableHeader = bindSortableHeader;
  w.updateReportSortIndicators = updateReportSortIndicators;
  w.updateHostsSortIndicators = updateHostsSortIndicators;
  w.withBusyButton = withBusyButton;
  w.wireBusyClick = wireBusyClick;
  w.setupReportSortHandlers = setupReportSortHandlers;
  w.setupKpiHandlers = setupKpiHandlers;
  w.setupCronScheduleUi = setupCronScheduleUi;
  w.setupCronHostPickerControls = setupCronHostPickerControls;
  w.handleCronCreate = handleCronCreate;
  w.setupSshHostPickerControls = setupSshHostPickerControls;
  w.setupSshRefreshHandlers = setupSshRefreshHandlers;
  w.handleSshKeyAdd = handleSshKeyAdd;
  w.handleSshRequestDeploy = handleSshRequestDeploy;
  w.setPanelVisibleById = setPanelVisibleById;
  w.renderSshHostsListView = renderSshHostsListView;
})(window);

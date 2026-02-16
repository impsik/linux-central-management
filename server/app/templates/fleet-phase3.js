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

  async function pollJob(jobId, statusEl, maxMs) {
    const timeoutMs = Number.isFinite(maxMs) ? maxMs : 120000;
    const started = Date.now();
    let interval = 600;
    while (Date.now() - started < timeoutMs) {
      const resp = await fetch('/jobs/' + encodeURIComponent(jobId));
      if (!resp.ok) throw new Error(resp.statusText);
      const data = await resp.json();
      const done = (data && data.done === true) || (Array.isArray(data && data.runs) && data.runs.length > 0 && data.runs.every(function (r) {
        return r.status === 'success' || r.status === 'failed';
      }));
      if (done) return data;
      await new Promise(function (r) { setTimeout(r, interval); });
      if (interval < 1500) interval += 150;
    }
    throw new Error('Timed out waiting for job completion');
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
    const approvalsRefresh = document.getElementById('admin-approvals-refresh');
    if (approvalsRefresh) approvalsRefresh.addEventListener('click', function (e) { e.preventDefault(); if (typeof api.loadAdminApprovals === 'function') api.loadAdminApprovals(true); });
    const dedupeRefresh = document.getElementById('admin-dedupe-refresh');
    if (dedupeRefresh) dedupeRefresh.addEventListener('click', function (e) { e.preventDefault(); if (typeof api.loadAdminNotificationDedupe === 'function') api.loadAdminNotificationDedupe(true); });
    const auditRefresh = document.getElementById('admin-audit-refresh');
    if (auditRefresh) auditRefresh.addEventListener('click', function (e) { e.preventDefault(); if (typeof api.loadAdminAudit === 'function') api.loadAdminAudit(true); });
  }

  function renderTopProcessesTable(tbody, processes, escaper) {
    const esc = (typeof escaper === 'function') ? escaper : (typeof w.escapeHtml === 'function' ? w.escapeHtml : function (s) { return String(s ?? ''); });
    if (!tbody) return;

    if (!processes || processes.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#a0aec0;">No process data</td></tr>';
      return;
    }

    tbody.innerHTML = processes.slice(0, 10).map(function (p) {
      const pid = p.pid ?? '';
      const user = esc(p.user ?? '');
      const cpu = (p.cpu_percent ?? p.cpu ?? 0);
      const mem = (p.mem_percent ?? p.mem ?? 0);
      const cmd = esc(p.command ?? '');
      return '\n          <tr>\n            <td>' + pid + '</td>\n            <td>' + user + '</td>\n            <td>' + Number(cpu).toFixed(1) + '</td>\n            <td>' + Number(mem).toFixed(1) + '</td>\n            <td>' + cmd + '</td>\n          </tr>\n        ';
    }).join('');
  }

  function setHostActionActive(action) {
    document.querySelectorAll('.host-action-btn').forEach(function (btn) { btn.classList.remove('active'); });
    const map = {
      terminal: 'host-action-terminal',
      users: 'host-action-users',
      services: 'host-action-services',
      packages: 'host-action-packages'
    };
    const id = map[action];
    const target = id ? document.getElementById(id) : null;
    if (target) target.classList.add('active');
  }

  function updateActiveHostSidebar(agentId) {
    document.querySelectorAll('.host-item').forEach(function (item) {
      item.classList.remove('active');
      if (item.dataset.agentId === agentId) item.classList.add('active');
    });
  }

  function connectTerminalSession(opts) {
    const api = opts || {};
    const agentId = api.agentId;
    const term = api.term;
    const getWs = (typeof api.getWs === 'function') ? api.getWs : function () { return null; };
    const setWs = (typeof api.setWs === 'function') ? api.setWs : function () { };
    const setCurrentAgentId = (typeof api.setCurrentAgentId === 'function') ? api.setCurrentAgentId : function () { };

    if (!agentId || !term) return;

    setCurrentAgentId(agentId);
    updateActiveHostSidebar(agentId);

    const existing = getWs();
    if (existing) {
      try { existing.close(); } catch (_) { }
    }

    term.clear();
    term.write('Connecting to ' + agentId + '...\r\n');

    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const thisWs = new WebSocket(protocol + '//' + location.host + '/ws/terminal/' + agentId);
    thisWs.binaryType = 'arraybuffer';
    setWs(thisWs);

    thisWs.onopen = function () {
      if (getWs() !== thisWs) return;
      term.write('\r\nConnected to ' + agentId + '\r\n');
      try { term.focus(); } catch (_) { }
    };

    thisWs.onmessage = function (e) {
      if (getWs() !== thisWs) return;
      if (e.data instanceof ArrayBuffer) term.write(new TextDecoder().decode(e.data));
      else term.write(e.data);
    };

    thisWs.onerror = function () {
      if (getWs() !== thisWs) return;
      term.write('\r\nWebSocket error occurred\r\n');
    };

    thisWs.onclose = function (e) {
      if (getWs() !== thisWs) return;

      if (e.code === 4403) {
        term.write('\r\n[ERROR] Terminal access denied for this host.\r\n');
        term.write('\r\nThis environment allows operator terminal by default, but this host is restricted via label:\r\n');
        term.write('  - terminal_access=admin  (admins only)\r\n');
        term.write('  - terminal_access=none   (disabled)\r\n');
        term.write('\r\nAsk an admin to adjust host labels if you need access.\r\n');
        setWs(null);
        return;
      }

      if (e.code === 1006) {
        term.write('\r\n[ERROR] Connection closed abnormally. Possible causes:\r\n');
        term.write('  - Agent terminal server not running on port 18080\r\n');
        term.write('  - Network connectivity issue\r\n');
        term.write('  - Firewall blocking connection\r\n');
        term.write('  - Hostname not resolvable from server\r\n');
      } else {
        term.write('\r\nConnection closed (code: ' + e.code + ', reason: ' + (e.reason || 'unknown') + ')\r\n');
      }
      setWs(null);
    };
  }

  function createUiStateAccess(namespace, initialState, adapter) {
    const scope = namespace || 'default';
    const defaults = (initialState && typeof initialState === 'object') ? initialState : {};
    const io = (adapter && typeof adapter === 'object') ? adapter : {};
    const rootKey = '__fleetPhase3UiState';

    function ensureRoot() {
      if (typeof io.readRoot === 'function' && typeof io.writeRoot === 'function') {
        const existing = io.readRoot();
        if (existing && typeof existing === 'object') return existing;
        const created = {};
        io.writeRoot(created);
        return created;
      }
      if (!w[rootKey] || typeof w[rootKey] !== 'object') w[rootKey] = {};
      return w[rootKey];
    }

    function ensureScope() {
      const root = ensureRoot();
      if (!root[scope] || typeof root[scope] !== 'object') {
        root[scope] = Object.assign({}, defaults);
      }
      return root[scope];
    }

    function get(key, fallback) {
      const scoped = ensureScope();
      if (Object.prototype.hasOwnProperty.call(scoped, key)) return scoped[key];
      if (Object.prototype.hasOwnProperty.call(defaults, key)) return defaults[key];
      return fallback;
    }

    function set(key, value) {
      const scoped = ensureScope();
      scoped[key] = value;
      return value;
    }

    function update(key, mapper) {
      const current = get(key);
      if (typeof mapper !== 'function') return current;
      return set(key, mapper(current));
    }

    return { get: get, set: set, update: update };
  }

  function stopMetricsPollingLifecycle(stateAccess) {
    if (!stateAccess || typeof stateAccess.get !== 'function' || typeof stateAccess.set !== 'function') return;
    const metricsTimer = stateAccess.get('metricsUpdateInterval');
    const topProcessesTimer = stateAccess.get('topProcessesUpdateInterval');

    if (metricsTimer) {
      try { clearInterval(metricsTimer); } catch (_) { }
      stateAccess.set('metricsUpdateInterval', null);
    }
    if (topProcessesTimer) {
      try { clearInterval(topProcessesTimer); } catch (_) { }
      stateAccess.set('topProcessesUpdateInterval', null);
    }
  }

  function initMetricsLifecycleState(stateAccess) {
    if (!stateAccess || typeof stateAccess.get !== 'function' || typeof stateAccess.set !== 'function') {
      return {
        metricsUpdateInterval: null,
        topProcessesUpdateInterval: null,
        topProcessesInFlight: false,
        currentMetricsAgentId: null
      };
    }

    const normalized = {
      metricsUpdateInterval: stateAccess.get('metricsUpdateInterval', null) || null,
      topProcessesUpdateInterval: stateAccess.get('topProcessesUpdateInterval', null) || null,
      topProcessesInFlight: stateAccess.get('topProcessesInFlight', false) === true,
      currentMetricsAgentId: stateAccess.get('currentMetricsAgentId', null) || null
    };

    Object.keys(normalized).forEach(function (key) {
      stateAccess.set(key, normalized[key]);
    });

    return normalized;
  }

  function initHostFilterSelectionState(stateAccess) {
    if (!stateAccess || typeof stateAccess.get !== 'function' || typeof stateAccess.set !== 'function') {
      return {
        allHosts: [],
        hostSearchQuery: '',
        labelEnvFilter: '',
        labelRoleFilter: '',
        vulnFilteredAgentIds: null,
        selectedAgentIds: new Set(),
        lastRenderedAgentIds: []
      };
    }

    const normalized = {
      allHosts: Array.isArray(stateAccess.get('allHosts')) ? stateAccess.get('allHosts') : [],
      hostSearchQuery: stateAccess.get('hostSearchQuery', '') || '',
      labelEnvFilter: stateAccess.get('labelEnvFilter', '') || '',
      labelRoleFilter: stateAccess.get('labelRoleFilter', '') || '',
      vulnFilteredAgentIds: (stateAccess.get('vulnFilteredAgentIds') instanceof Set) ? stateAccess.get('vulnFilteredAgentIds') : null,
      selectedAgentIds: (stateAccess.get('selectedAgentIds') instanceof Set) ? stateAccess.get('selectedAgentIds') : new Set(),
      lastRenderedAgentIds: Array.isArray(stateAccess.get('lastRenderedAgentIds')) ? stateAccess.get('lastRenderedAgentIds') : []
    };

    Object.keys(normalized).forEach(function (key) {
      stateAccess.set(key, normalized[key]);
    });

    return normalized;
  }

  function initCronHostPickerState(stateAccess) {
    if (!stateAccess || typeof stateAccess.get !== 'function' || typeof stateAccess.set !== 'function') {
      return { selectedAgentIds: new Set() };
    }

    const selectedAgentIds = (stateAccess.get('selectedAgentIds') instanceof Set)
      ? stateAccess.get('selectedAgentIds')
      : new Set();
    stateAccess.set('selectedAgentIds', selectedAgentIds);
    return { selectedAgentIds: selectedAgentIds };
  }

  function initSshKeysUiState(stateAccess) {
    if (!stateAccess || typeof stateAccess.get !== 'function' || typeof stateAccess.set !== 'function') {
      return {
        keysCache: [],
        selectedKeyId: null,
        selectedAgentIds: new Set()
      };
    }

    const normalized = {
      keysCache: Array.isArray(stateAccess.get('keysCache')) ? stateAccess.get('keysCache') : [],
      selectedKeyId: stateAccess.get('selectedKeyId', null) || null,
      selectedAgentIds: (stateAccess.get('selectedAgentIds') instanceof Set) ? stateAccess.get('selectedAgentIds') : new Set()
    };

    Object.keys(normalized).forEach(function (key) {
      stateAccess.set(key, normalized[key]);
    });

    return normalized;
  }

  w.escapeHtml = w.escapeHtml || escapeHtml;
  w.formatRelativeTime = w.formatRelativeTime || formatRelativeTime;
  w.safeJsonPreview = w.safeJsonPreview || safeJsonPreview;
  w.normalize = w.normalize || normalize;
  w.matchesGlob = w.matchesGlob || matchesGlob;
  w.hostLabel = w.hostLabel || hostLabel;
  w.pollJob = w.pollJob || pollJob;
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
  w.renderTopProcessesTable = renderTopProcessesTable;
  w.setHostActionActive = setHostActionActive;
  w.updateActiveHostSidebar = updateActiveHostSidebar;
  w.connectTerminalSession = connectTerminalSession;
  w.createUiStateAccess = createUiStateAccess;
  w.stopMetricsPollingLifecycle = stopMetricsPollingLifecycle;
  w.initMetricsLifecycleState = initMetricsLifecycleState;
  w.initHostFilterSelectionState = initHostFilterSelectionState;
  w.initCronHostPickerState = initCronHostPickerState;
  w.initSshKeysUiState = initSshKeysUiState;
})(window);

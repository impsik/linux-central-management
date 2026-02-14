(function (w) {
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

  w.setButtonBusy = setButtonBusy;
  w.setTableState = setTableState;
  w.bindSortableHeader = bindSortableHeader;
  w.updateReportSortIndicators = updateReportSortIndicators;
  w.updateHostsSortIndicators = updateHostsSortIndicators;
  w.withBusyButton = withBusyButton;
  w.wireBusyClick = wireBusyClick;
  w.setupReportSortHandlers = setupReportSortHandlers;
  w.setupKpiHandlers = setupKpiHandlers;
})(window);

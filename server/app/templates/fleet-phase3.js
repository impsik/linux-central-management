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

  w.setButtonBusy = setButtonBusy;
  w.setTableState = setTableState;
  w.bindSortableHeader = bindSortableHeader;
  w.updateReportSortIndicators = updateReportSortIndicators;
  w.updateHostsSortIndicators = updateHostsSortIndicators;
  w.withBusyButton = withBusyButton;
  w.wireBusyClick = wireBusyClick;
})(window);

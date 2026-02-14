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

  w.setButtonBusy = setButtonBusy;
  w.setTableState = setTableState;
})(window);

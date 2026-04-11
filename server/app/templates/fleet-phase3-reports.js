function initReportsControls() {
  const btn = document.getElementById('reports-user-presence-open');
  if (!btn || btn.dataset.boundReportsControls === '1') return;
  btn.dataset.boundReportsControls = '1';
  btn.addEventListener('click', (e) => {
    e.preventDefault();
    const u = String(document.getElementById('reports-user-presence-username')?.value || '').trim();
    const exact = !!document.getElementById('reports-user-presence-exact')?.checked;
    const liveScan = !!document.getElementById('reports-user-presence-live')?.checked;
    if (!u) {
      if (typeof showToast === 'function') showToast('Enter username', 'error');
      return;
    }
    const qs = new URLSearchParams({ username: u, exact: String(exact), live_scan: String(liveScan) }).toString();
    window.open(`/reports/user-presence.html?${qs}`, '_blank', 'noopener');
  });
}

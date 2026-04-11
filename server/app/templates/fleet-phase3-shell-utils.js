function safeInit(name, fn) {
  try {
    if (typeof fn === 'function') fn();
  } catch (e) {
    console.error('[init failed]', name, e);
  }
}

function initGlobalSearch() {
  const globalSearchEl = document.getElementById('global-search');
  if (!globalSearchEl) return;

  let timer = null;
  const runSearch = () => {
    const query = String(globalSearchEl.value || '').trim();
    const navHosts = document.getElementById('nav-hosts');
    const hostSearchEl = document.getElementById('host-search');
    if (!hostSearchEl) return;

    if (navHosts) navHosts.click();
    hostSearchEl.value = query;
    hostSearchEl.dispatchEvent(new Event('input', { bubbles: true }));
    hostSearchEl.dispatchEvent(new Event('change', { bubbles: true }));
  };

  globalSearchEl.addEventListener('input', () => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(runSearch, 180);
  });

  globalSearchEl.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    e.preventDefault();
    runSearch();
  });
}

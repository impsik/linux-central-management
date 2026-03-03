(function () {
  try {
    const saved = localStorage.getItem('fleet_theme');
    const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    const theme = saved || (prefersDark ? 'dark' : 'light');
    document.documentElement.dataset.theme = theme;
  } catch (e) {
    document.documentElement.dataset.theme = 'dark';
  }

  try {
    const params = new URLSearchParams(window.location.search || '');
    const uiParam = (params.get('ui') || '').trim().toLowerCase();
    const isV2 = uiParam === 'v2';
    document.documentElement.dataset.uiVersion = isV2 ? 'v2' : 'v1';

    if (isV2) {
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = '/assets/fleet-ui-v2.css?v=__ASSET_VERSION__';
      link.setAttribute('data-ui-v2-style', '1');
      document.head.appendChild(link);
    }
  } catch (_) {
    document.documentElement.dataset.uiVersion = 'v1';
  }
})();

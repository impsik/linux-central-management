(function () {
  try {
    const saved = localStorage.getItem('fleet_theme');
    // Default to dark for the v2 prototype look; keep user override if saved.
    document.documentElement.dataset.theme = saved || 'dark';
  } catch (e) {
    document.documentElement.dataset.theme = 'dark';
  }

  try {
    const params = new URLSearchParams(window.location.search || '');
    const uiParam = (params.get('ui') || '').trim().toLowerCase();
    // v2 is default; allow temporary fallback with ?ui=v1
    const isV2 = uiParam !== 'v1';
    document.documentElement.dataset.uiVersion = isV2 ? 'v2' : 'v1';

    if (isV2) {
      const attachV2Styles = () => {
        if (document.querySelector('link[data-ui-v2-style="1"]')) return;
        const link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = '/assets/fleet-ui-v2.css?v=__ASSET_VERSION__';
        link.setAttribute('data-ui-v2-style', '1');
        document.head.appendChild(link);
      };

      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', attachV2Styles, { once: true });
      } else {
        attachV2Styles();
      }
    }
  } catch (_) {
    document.documentElement.dataset.uiVersion = 'v2';
  }
})();

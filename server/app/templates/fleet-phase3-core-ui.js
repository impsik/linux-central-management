// Global fetch wrapper:
    // - always send cookies (credentials: 'include')
    // - add CSRF header for state-changing requests
    (function(){
      function getCookie(name) {
        const v = `; ${document.cookie}`;
        const parts = v.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return '';
      }

      const origFetch = window.fetch ? window.fetch.bind(window) : null;
      if (!origFetch) return;

      window.fetch = function(input, init) {
        const opts = init ? { ...init } : {};
        const method = String(opts.method || 'GET').toUpperCase();
        const headers = new Headers(opts.headers || {});

        if (!('credentials' in opts)) opts.credentials = 'include';

        if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
          const csrf = getCookie('fleet_csrf');
          if (csrf && !headers.has('X-CSRF-Token')) headers.set('X-CSRF-Token', csrf);
        }

        opts.headers = headers;
        return origFetch(input, opts);
      };
    })();

    function getTheme() {
      return document.documentElement.dataset.theme || 'dark';
    }

    function setTheme(theme) {
      document.documentElement.dataset.theme = theme;
      try { localStorage.setItem('fleet_theme', theme); } catch { }
    }

    function toggleTheme() {
      const next = getTheme() === 'dark' ? 'light' : 'dark';
      setTheme(next);
    }

    function initThemeToggle() {
      const btn = document.getElementById('theme-toggle');
      if (!btn) return;
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        toggleTheme();
      });
    }


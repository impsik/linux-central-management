(function (w) {
  function initHostFiltersUi(ctx) {
    const api = ctx || {};
    const getState = typeof api.getState === 'function' ? api.getState : function () { return {}; };
    const setState = typeof api.setState === 'function' ? api.setState : function () { };
    const syncSelectionState = typeof api.syncSelectionState === 'function' ? api.syncSelectionState : function (_, v) { return v; };
    const applyHostFilters = typeof api.applyHostFilters === 'function' ? api.applyHostFilters : function () { };
    const updateUpgradeControls = typeof api.updateUpgradeControls === 'function' ? api.updateUpgradeControls : function () { };

    const searchEl = document.getElementById('host-search');
    const envSel = document.getElementById('label-env');
    const roleSel = document.getElementById('label-role');
    const labelsClearBtn = document.getElementById('labels-clear');
    const labelsSection = document.getElementById('labels-filter-section');
    const labelsToggle = document.getElementById('labels-filter-toggle');
    const labelsToggleBtn = document.getElementById('labels-toggle-btn');
    const selectVisibleEl = document.getElementById('select-visible-hosts');
    const vulnSection = document.getElementById('vuln-filter-section');
    const vulnToggle = document.getElementById('vuln-filter-toggle');
    const vulnToggleBtn = document.getElementById('vuln-toggle-btn');
    const ansibleSection = document.getElementById('ansible-filter-section');
    const ansibleToggle = document.getElementById('ansible-filter-toggle');
    const ansibleToggleBtn = document.getElementById('ansible-toggle-btn');

    const savedViewNameEl = document.getElementById('saved-view-name');
    const savedViewSelectEl = document.getElementById('saved-view-select');
    const savedViewSaveBtn = document.getElementById('saved-view-save');
    const savedViewApplyBtn = document.getElementById('saved-view-apply');
    const savedViewDeleteBtn = document.getElementById('saved-view-delete');
    const savedViewStatusEl = document.getElementById('saved-view-status');

    function st() { return getState() || {}; }
    function setPatch(patch) { setState(patch || {}); }

    function setLabelsOpen(open) {
      if (!labelsSection || !labelsToggleBtn) return;
      labelsSection.classList.toggle('open', open);
      labelsToggleBtn.textContent = open ? '−' : '+';
      labelsToggleBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
    }

    function setAnsibleOpen(open) {
      if (!ansibleSection || !ansibleToggleBtn) return;
      ansibleSection.classList.toggle('open', open);
      ansibleToggleBtn.textContent = open ? '−' : '+';
      ansibleToggleBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
    }

    function setVulnOpen(open) {
      if (!vulnSection || !vulnToggleBtn) return;
      vulnSection.classList.toggle('open', open);
      vulnToggleBtn.textContent = open ? '−' : '+';
      vulnToggleBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
    }

    const SAVED_VIEWS_KEY = 'fleet_saved_host_views_v1';

    function setSavedViewStatus(msg, kind) {
      if (!savedViewStatusEl) return;
      savedViewStatusEl.textContent = msg || '';
      savedViewStatusEl.style.color = (kind === 'error') ? '#fca5a5' : (kind === 'success' ? '#86efac' : 'var(--muted-2)');
    }

    function loadSavedViews() {
      try {
        const raw = localStorage.getItem(SAVED_VIEWS_KEY);
        if (!raw) return [];
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed : [];
      } catch (_) {
        return [];
      }
    }

    function storeSavedViews(items) {
      try {
        localStorage.setItem(SAVED_VIEWS_KEY, JSON.stringify(Array.isArray(items) ? items : []));
      } catch (_) { }
    }

    function refreshSavedViewsUi() {
      if (!savedViewSelectEl) return;
      const items = loadSavedViews();
      const prev = savedViewSelectEl.value || '';
      savedViewSelectEl.innerHTML = '<option value="">Select saved view</option>' + items.map((it) => {
        const name = String((it && it.name) || '').trim();
        if (!name) return '';
        return `<option value="${w.escapeHtml(name)}">${w.escapeHtml(name)}</option>`;
      }).join('');
      if (prev && items.some((x) => x && x.name === prev)) savedViewSelectEl.value = prev;
    }

    function captureCurrentView() {
      return {
        hostSearchQuery: searchEl?.value || '',
        labelEnvFilter: envSel?.value || '',
        labelRoleFilter: roleSel?.value || '',
      };
    }

    function applySavedView(view) {
      if (!view || typeof view !== 'object') return;
      const hostSearchQuery = String(view.hostSearchQuery || '');
      const labelEnv = String(view.labelEnvFilter || '');
      const labelRole = String(view.labelRoleFilter || '');

      if (searchEl) searchEl.value = hostSearchQuery;
      if (envSel) envSel.value = labelEnv;
      if (roleSel) roleSel.value = labelRole;

      syncSelectionState('hostSearchQuery', hostSearchQuery);
      syncSelectionState('labelEnvFilter', labelEnv);
      syncSelectionState('labelRoleFilter', labelRole);
      setPatch({ hostSearchQuery, labelEnvFilter: labelEnv, labelRoleFilter: labelRole });
      applyHostFilters();
    }

    if (searchEl) {
      searchEl.addEventListener('input', function () {
        const val = searchEl.value || '';
        syncSelectionState('hostSearchQuery', val);
        setPatch({ hostSearchQuery: val });
        applyHostFilters();
      });
    }

    setLabelsOpen(false);
    setAnsibleOpen(false);
    setVulnOpen(false);

    labelsToggle?.addEventListener('click', function (e) {
      if (e.target && (e.target.id === 'label-env' || e.target.id === 'label-role')) return;
      e.preventDefault();
      const isOpen = labelsSection?.classList.contains('open');
      setLabelsOpen(!isOpen);
    });
    ansibleToggle?.addEventListener('click', function (e) {
      e.preventDefault();
      const isOpen = ansibleSection?.classList.contains('open');
      setAnsibleOpen(!isOpen);
    });
    vulnToggle?.addEventListener('click', function (e) {
      if (e.target && (e.target.id === 'vuln-cve' || e.target.id === 'vuln-package' || e.target.id === 'vuln-version')) return;
      e.preventDefault();
      const isOpen = vulnSection?.classList.contains('open');
      setVulnOpen(!isOpen);
    });

    function onLabelsChanged() {
      const env = envSel?.value || '';
      const role = roleSel?.value || '';
      syncSelectionState('labelEnvFilter', env);
      syncSelectionState('labelRoleFilter', role);
      setPatch({ labelEnvFilter: env, labelRoleFilter: role });
      applyHostFilters();
    }
    envSel?.addEventListener('change', onLabelsChanged);
    roleSel?.addEventListener('change', onLabelsChanged);
    labelsClearBtn?.addEventListener('click', function (e) {
      e.preventDefault();
      if (envSel) envSel.value = '';
      if (roleSel) roleSel.value = '';
      syncSelectionState('labelEnvFilter', '');
      syncSelectionState('labelRoleFilter', '');
      setPatch({ labelEnvFilter: '', labelRoleFilter: '' });
      applyHostFilters();
    });

    savedViewSaveBtn?.addEventListener('click', function (e) {
      e.preventDefault();
      const name = String(savedViewNameEl?.value || '').trim();
      if (!name) {
        setSavedViewStatus('Enter a name first.', 'error');
        return;
      }
      const current = captureCurrentView();
      const items = loadSavedViews().filter((it) => it && it.name !== name);
      items.push({ name, ...current, saved_at: new Date().toISOString() });
      storeSavedViews(items);
      refreshSavedViewsUi();
      if (savedViewSelectEl) savedViewSelectEl.value = name;
      setSavedViewStatus(`Saved view "${name}".`, 'success');
    });

    savedViewApplyBtn?.addEventListener('click', function (e) {
      e.preventDefault();
      const name = String(savedViewSelectEl?.value || '').trim();
      if (!name) {
        setSavedViewStatus('Select a saved view first.', 'error');
        return;
      }
      const view = loadSavedViews().find((it) => it && it.name === name);
      if (!view) {
        setSavedViewStatus('Saved view not found.', 'error');
        refreshSavedViewsUi();
        return;
      }
      applySavedView(view);
      if (savedViewNameEl) savedViewNameEl.value = name;
      setSavedViewStatus(`Applied view "${name}".`, 'success');
    });

    savedViewDeleteBtn?.addEventListener('click', function (e) {
      e.preventDefault();
      const name = String(savedViewSelectEl?.value || '').trim();
      if (!name) {
        setSavedViewStatus('Select a saved view to delete.', 'error');
        return;
      }
      const next = loadSavedViews().filter((it) => it && it.name !== name);
      storeSavedViews(next);
      refreshSavedViewsUi();
      setSavedViewStatus(`Deleted view "${name}".`, 'success');
    });

    savedViewSelectEl?.addEventListener('change', function () {
      const name = String(savedViewSelectEl?.value || '').trim();
      if (savedViewNameEl) savedViewNameEl.value = name;
      if (!name) return;
      setSavedViewStatus('Click Apply to use selected view.', null);
    });

    refreshSavedViewsUi();

    selectVisibleEl?.addEventListener('change', function () {
      const nextSet = selectVisibleEl.checked ? new Set(st().lastRenderedAgentIds || []) : new Set();
      syncSelectionState('selectedAgentIds', nextSet);
      setPatch({ selectedAgentIds: nextSet });
      applyHostFilters();
      updateUpgradeControls();
    });

    return {
      setVulnOpen: setVulnOpen,
      setLabelsOpen: setLabelsOpen,
      setAnsibleOpen: setAnsibleOpen,
    };
  }

  w.phase3HostFiltersUi = {
    initHostFiltersUi: initHostFiltersUi,
  };
})(window);

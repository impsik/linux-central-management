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

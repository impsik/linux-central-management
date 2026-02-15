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
    const savedViewSharedEl = document.getElementById('saved-view-shared');
    const savedViewDefaultEl = document.getElementById('saved-view-default');
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

    let savedViewsCache = [];

    function setSavedViewStatus(msg, kind) {
      if (!savedViewStatusEl) return;
      savedViewStatusEl.textContent = msg || '';
      savedViewStatusEl.style.color = (kind === 'error') ? '#fca5a5' : (kind === 'success' ? '#86efac' : 'var(--muted-2)');
    }

    async function fetchSavedViews() {
      const r = await fetch('/auth/views?scope=hosts', { credentials: 'include' });
      if (!r.ok) throw new Error(`saved views fetch failed (${r.status})`);
      const d = await r.json();
      savedViewsCache = Array.isArray(d?.items) ? d.items : [];
      return savedViewsCache;
    }

    function viewKey(it) {
      const name = String((it && it.name) || '').trim();
      const owner = String((it && it.owner_username) || '').trim();
      const shared = !!(it && it.is_shared);
      return `${name}@@${owner}@@${shared ? '1' : '0'}`;
    }

    function refreshSavedViewsUi() {
      if (!savedViewSelectEl) return;
      const items = Array.isArray(savedViewsCache) ? savedViewsCache : [];
      const prev = savedViewSelectEl.value || '';
      savedViewSelectEl.innerHTML = '<option value="">Select saved view</option>' + items.map((it) => {
        const name = String((it && it.name) || '').trim();
        if (!name) return '';
        const shared = !!(it && it.is_shared);
        const owner = String((it && it.owner_username) || '').trim();
        const suffix = shared ? ` (shared${owner ? ` by ${owner}` : ''})` : '';
        return `<option value="${w.escapeHtml(viewKey(it))}">${w.escapeHtml(name + suffix)}</option>`;
      }).join('');
      if (prev && items.some((x) => x && viewKey(x) === prev)) savedViewSelectEl.value = prev;
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

    savedViewSaveBtn?.addEventListener('click', async function (e) {
      e.preventDefault();
      const name = String(savedViewNameEl?.value || '').trim();
      if (!name) {
        setSavedViewStatus('Enter a name first.', 'error');
        return;
      }
      const current = captureCurrentView();
      try {
        const r = await fetch('/auth/views', {
          method: 'POST',
          credentials: 'include',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            scope: 'hosts',
            name,
            payload: current,
            is_shared: !!savedViewSharedEl?.checked,
            is_default_startup: !!savedViewDefaultEl?.checked,
          }),
        });
        if (!r.ok) throw new Error(`save failed (${r.status})`);
        await fetchSavedViews();
        refreshSavedViewsUi();
        const saved = (savedViewsCache || []).find((it) => it && it.name === name && !!it.can_edit);
        if (savedViewSelectEl && saved) savedViewSelectEl.value = viewKey(saved);
        setSavedViewStatus(`Saved view "${name}".`, 'success');
      } catch (err) {
        setSavedViewStatus((err && err.message) ? err.message : 'Failed to save view', 'error');
      }
    });

    savedViewApplyBtn?.addEventListener('click', function (e) {
      e.preventDefault();
      const key = String(savedViewSelectEl?.value || '').trim();
      if (!key) {
        setSavedViewStatus('Select a saved view first.', 'error');
        return;
      }
      const view = (savedViewsCache || []).find((it) => viewKey(it) === key);
      if (!view) {
        setSavedViewStatus('Saved view not found.', 'error');
        refreshSavedViewsUi();
        return;
      }
      applySavedView(view.payload || {});
      if (savedViewNameEl) savedViewNameEl.value = String(view.name || '');
      if (savedViewSharedEl) savedViewSharedEl.checked = !!view.is_shared;
      if (savedViewDefaultEl) savedViewDefaultEl.checked = !!view.is_default_startup;
      setSavedViewStatus(`Applied view "${String(view.name || '')}".`, 'success');
    });

    savedViewDeleteBtn?.addEventListener('click', async function (e) {
      e.preventDefault();
      const key = String(savedViewSelectEl?.value || '').trim();
      if (!key) {
        setSavedViewStatus('Select a saved view to delete.', 'error');
        return;
      }
      const view = (savedViewsCache || []).find((it) => viewKey(it) === key);
      if (!view) {
        setSavedViewStatus('Saved view not found.', 'error');
        return;
      }
      try {
        const r = await fetch('/auth/views', {
          method: 'DELETE',
          credentials: 'include',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ scope: 'hosts', name: String(view.name || ''), owner_username: String(view.owner_username || '') }),
        });
        if (!r.ok) throw new Error(`delete failed (${r.status})`);
        await fetchSavedViews();
        refreshSavedViewsUi();
        setSavedViewStatus(`Deleted view "${String(view.name || '')}".`, 'success');
      } catch (err) {
        setSavedViewStatus((err && err.message) ? err.message : 'Failed to delete view', 'error');
      }
    });

    savedViewSelectEl?.addEventListener('change', function () {
      const key = String(savedViewSelectEl?.value || '').trim();
      const view = (savedViewsCache || []).find((it) => viewKey(it) === key);
      if (!view) return;
      if (savedViewNameEl) savedViewNameEl.value = String(view.name || '');
      if (savedViewSharedEl) {
        savedViewSharedEl.checked = !!view.is_shared;
        savedViewSharedEl.disabled = !view.can_edit;
      }
      if (savedViewDefaultEl) {
        savedViewDefaultEl.checked = !!view.is_default_startup;
        savedViewDefaultEl.disabled = !view.can_edit;
      }
      if (savedViewDeleteBtn) savedViewDeleteBtn.disabled = !view.can_edit;
      setSavedViewStatus('Click Apply to use selected view.', null);
    });

    (async () => {
      try {
        await fetchSavedViews();
        refreshSavedViewsUi();
        const def = (savedViewsCache || []).find((it) => !!it?.can_edit && !!it?.is_default_startup);
        if (def) {
          applySavedView(def.payload || {});
          if (savedViewSelectEl) savedViewSelectEl.value = viewKey(def);
          if (savedViewNameEl) savedViewNameEl.value = String(def.name || '');
          if (savedViewSharedEl) savedViewSharedEl.checked = !!def.is_shared;
          if (savedViewDefaultEl) savedViewDefaultEl.checked = !!def.is_default_startup;
          setSavedViewStatus(`Applied default view "${String(def.name || '')}".`, 'success');
        }
      } catch (_) {
        setSavedViewStatus('Saved views unavailable.', 'error');
      }
    })();

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

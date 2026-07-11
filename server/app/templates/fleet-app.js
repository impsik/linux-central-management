    // Terminal state is owned here; behavior lives in fleet-terminal-ui.js.
    let term = null;
    let termFitAddon = null;
    let ws = null;
    let currentAgentId = null;
    let pendingInteractivePackageCmd = null;
    var currentUsername = null;
    var adminUsername = null;
    var currentPermissions = {};
    var approvalActionFeedback = {}; // request_id -> short result text
    let terminalInputHandlerAttached = false;

    function getTerminalCtx() {
      return {
        getTerm: () => term,
        setTerm: (next) => { term = next; return term; },
        getTermFitAddon: () => termFitAddon,
        setTermFitAddon: (next) => { termFitAddon = next; return termFitAddon; },
        getWs: () => ws,
        setWs: (next) => { ws = next; return ws; },
        setCurrentAgentId: (next) => { currentAgentId = next; return currentAgentId; },
        getPendingInteractivePackageCmd: () => pendingInteractivePackageCmd,
        setPendingInteractivePackageCmd: (next) => { pendingInteractivePackageCmd = next; return pendingInteractivePackageCmd; },
        getTerminalInputHandlerAttached: () => terminalInputHandlerAttached,
        setTerminalInputHandlerAttached: (next) => { terminalInputHandlerAttached = !!next; return terminalInputHandlerAttached; },
        showToast,
      };
    }

    function fitTerminalViewport() {
      const mod = window.fleetTerminalUi;
      if (mod && typeof mod.fitTerminalViewport === 'function') {
        return mod.fitTerminalViewport(getTerminalCtx());
      }
    }

    function initTerminalOnce() {
      const mod = window.fleetTerminalUi;
      if (mod && typeof mod.initTerminalOnce === 'function') {
        return mod.initTerminalOnce(getTerminalCtx());
      }
    }

    function attachTerminalInputHandlerOnce() {
      const mod = window.fleetTerminalUi;
      if (mod && typeof mod.attachTerminalInputHandlerOnce === 'function') {
        return mod.attachTerminalInputHandlerOnce(getTerminalCtx());
      }
    }

    function updateTerminalPendingCmdButton() {
      const mod = window.fleetTerminalUi;
      if (mod && typeof mod.updateTerminalPendingCmdButton === 'function') {
        return mod.updateTerminalPendingCmdButton(getTerminalCtx());
      }
    }

    function runPendingInteractivePackageCommand() {
      const mod = window.fleetTerminalUi;
      if (mod && typeof mod.runPendingInteractivePackageCommand === 'function') {
        return mod.runPendingInteractivePackageCommand(getTerminalCtx());
      }
    }

    // Tab switching removed - tabs are now accessed via server info buttons only

    let loadGraphChart = null;
    let loadGraphData = [];
    const metricsLifecycleState = createUiStateAccess('hostMetricsLifecycle', {
      metricsUpdateInterval: null,
      topProcessesUpdateInterval: null,
      topProcessesInFlight: false,
      currentMetricsAgentId: null,
    });
    if (typeof window.initMetricsLifecycleState === 'function') {
      window.initMetricsLifecycleState(metricsLifecycleState);
    }
    const stopMetricsPolling = window.stopMetricsPollingLifecycle || function (stateAccess) {
      if (!stateAccess || typeof stateAccess.get !== 'function' || typeof stateAccess.set !== 'function') return;
      const metricsTimer = stateAccess.get('metricsUpdateInterval');
      const topTimer = stateAccess.get('topProcessesUpdateInterval');
      if (metricsTimer) { clearInterval(metricsTimer); stateAccess.set('metricsUpdateInterval', null); }
      if (topTimer) { clearInterval(topTimer); stateAccess.set('topProcessesUpdateInterval', null); }
    };
    let loadTimeframeSeconds = 3600;
    const METRICS_POLL_MS = 60_000; // 1 minute is enough for disk/mem/ips/top-procs/loadavg
    const TOP_PROCS_POLL_MS = 1_000; // top processes can change quickly

    function getMetricsCtx() {
      return {
        getMetricsLifecycleState: () => metricsLifecycleState,
        getLoadGraphData: () => loadGraphData,
        setLoadGraphData: (v) => { loadGraphData = v; return loadGraphData; },
        getLoadTimeframeSeconds: () => loadTimeframeSeconds,
        stopMetricsPolling: () => stopMetricsPolling(metricsLifecycleState),
      };
    }

    function initLoadTimeframeControls() {
      const sel = document.getElementById('load-timeframe');
      if (!sel) return;
      sel.addEventListener('change', async () => {
        const v = parseInt(sel.value, 10);
        if (!isNaN(v)) loadTimeframeSeconds = v;
        if (metricsLifecycleState.get('currentMetricsAgentId')) {
          loadGraphData = [];
          await loadHistoricalLoadData(metricsLifecycleState.get('currentMetricsAgentId'));
        }
      });
      // Ensure it matches initial value
      const v = parseInt(sel.value, 10);
      if (!isNaN(v)) loadTimeframeSeconds = v;
    }

    // Hosts + filtering state
    const hostFilterSelectionState = createUiStateAccess('hostFilterSelection', {
      allHosts: [],
      hostSearchQuery: '',
      labelEnvFilter: '',
      labelRoleFilter: '',
      labelOwnerFilter: '',
      vulnFilteredAgentIds: null,
      selectedAgentIds: new Set(),
      lastRenderedAgentIds: [],
    });
    const hostFilterSelectionDefaults = (typeof window.initHostFilterSelectionState === 'function')
      ? window.initHostFilterSelectionState(hostFilterSelectionState)
      : {
        allHosts: [],
        hostSearchQuery: '',
        labelEnvFilter: '',
        labelRoleFilter: '',
        labelOwnerFilter: '',
        vulnFilteredAgentIds: null,
        selectedAgentIds: new Set(),
        lastRenderedAgentIds: [],
      };
    let allHosts = hostFilterSelectionDefaults.allHosts;
    let hostSearchQuery = hostFilterSelectionDefaults.hostSearchQuery;
    let labelEnvFilter = hostFilterSelectionDefaults.labelEnvFilter;
    let labelRoleFilter = hostFilterSelectionDefaults.labelRoleFilter;
    let labelOwnerFilter = hostFilterSelectionDefaults.labelOwnerFilter;
    let vulnFilteredAgentIds = hostFilterSelectionDefaults.vulnFilteredAgentIds; // Set<string> or null
    let selectedAgentIds = hostFilterSelectionDefaults.selectedAgentIds;
    let lastRenderedAgentIds = hostFilterSelectionDefaults.lastRenderedAgentIds; // string[]

    function syncHostFilterSelectionState(key, value) {
      hostFilterSelectionState.set(key, value);
      return value;
    }
    // Will be initialized in initHostFilters(); renderHosts() calls this.
    let updateUpgradeControlsFn = () => { };
    let lastPkgVerification = null; // { packageName, vulnVersion, resultsByAgentId: { [aid]: { ok, found, version, status } } }
    let lastCveCheck = null; // { cve, resultsByAgentId: { [aid]: { affected, packages?: string[] } } }
    let lastCveAffectedAgentIds = []; // string[] for last CVE run (online hosts only)
    let lastCveUnionPackages = []; // string[] union of affected packages across affected hosts
    let selectedCvePackages = new Set(); // Set<string> selected in CVE package list
    let ansiblePlaybooks = [];

    // Packages workflow state
    let packagesSearchQuery = '';
    let packagesSearchTimer = null;
    let packagesUpdatesOnly = false;
    let packagesCvesOnly = false;
    let packagesSortBy = 'name';
    let pkgInteractiveTerminal = false;
    let selectedPackages = new Set();
    let currentPackageName = null;
    let queueHealthOffset = 0;

    function getHostListCtx() {
      return {
        getAllHosts: () => allHosts,
        setAllHosts: (v) => { allHosts = syncHostFilterSelectionState('allHosts', v); return allHosts; },
        getHostSearchQuery: () => hostSearchQuery,
        getLabelEnvFilter: () => labelEnvFilter,
        setLabelEnvFilter: (v) => { labelEnvFilter = syncHostFilterSelectionState('labelEnvFilter', v); return labelEnvFilter; },
        getLabelRoleFilter: () => labelRoleFilter,
        setLabelRoleFilter: (v) => { labelRoleFilter = syncHostFilterSelectionState('labelRoleFilter', v); return labelRoleFilter; },
        getLabelOwnerFilter: () => labelOwnerFilter,
        setLabelOwnerFilter: (v) => { labelOwnerFilter = syncHostFilterSelectionState('labelOwnerFilter', v); return labelOwnerFilter; },
        getVulnFilteredAgentIds: () => vulnFilteredAgentIds,
        getSelectedAgentIds: () => selectedAgentIds,
        setLastRenderedAgentIds: (v) => { lastRenderedAgentIds = syncHostFilterSelectionState('lastRenderedAgentIds', v); return lastRenderedAgentIds; },
        getCurrentAgentId: () => currentAgentId,
        getLastPkgVerification: () => lastPkgVerification,
        selectHost,
        updateUpgradeControls: () => updateUpgradeControlsFn(),
        renderHosts: (hosts) => renderHosts(hosts),
      };
    }

    function rebuildLabelFilterOptions(hosts) {
      const mod = window.phase3HostList;
      if (mod && typeof mod.rebuildLabelFilterOptions === 'function') {
        if (Array.isArray(hosts)) getHostListCtx().setAllHosts(hosts);
        return mod.rebuildLabelFilterOptions(getHostListCtx());
      }
    }

    function applyHostFilters() {
      const listMod = window.phase3HostList;
      if (listMod && typeof listMod.applyHostFilters === 'function') {
        listMod.applyHostFilters(getHostListCtx());
      }
      const overviewMod = window.phase3Overview;
      if (overviewMod && typeof overviewMod.applyHostsTableFilters === 'function') {
        overviewMod.applyHostsTableFilters(getOverviewCtx());
      }
    }

    function renderHosts(hosts) {
      const mod = window.phase3HostList;
      if (mod && typeof mod.renderHosts === 'function') {
        return mod.renderHosts(getHostListCtx(), hosts);
      }
    }

    function clearCurrentHostSelection() {
      currentAgentId = null;
      metricsLifecycleState.set('currentMetricsAgentId', null);

      // Stop any existing metrics updates
      stopMetricsPolling(metricsLifecycleState);
      

      // Clear sidebar highlight
      document.querySelectorAll('.host-item').forEach(item => item.classList.remove('active'));

      // Hide host action buttons
      const hostActions = document.getElementById('host-actions');
      if (hostActions) hostActions.style.display = 'none';
      setHostActionActive(null);

      document.querySelectorAll('.host-context-name').forEach((el) => { el.textContent = '—'; });
      document.querySelectorAll('.host-context-ip').forEach((el) => { el.textContent = '—'; });

      // Reset the overview panel to fleet overview placeholder
      const placeholder = document.getElementById('server-info-placeholder');
      const header = document.getElementById('server-info-header');
      if (placeholder) placeholder.style.display = 'block';
      if (header) header.style.display = 'none';
      const driftSummary = document.getElementById('host-drift-summary');
      const driftList = document.getElementById('host-drift-list');
      const timelineList = document.getElementById('host-timeline-list');
      const timelineCount = document.getElementById('host-timeline-count');
      if (driftSummary) driftSummary.textContent = 'Select a host';
      if (driftList) driftList.innerHTML = '';
      hostDriftChecksCache = [];
      hostDriftCriticalOnly = false;
      hostTimelineItemsCache = [];
      if (timelineList) timelineList.innerHTML = '';
      if (timelineCount) timelineCount.textContent = '';
    }

    function selectHost(agentId, hostname) {
      const prevActiveTabId = document.querySelector('.tab-content-custom.active')?.id || 'server-info-tab';

      currentAgentId = agentId;

      // Reset per-host package filters so they don't leak across hosts
      packagesUpdatesOnly = false;
      packagesCvesOnly = false;
      packagesSortBy = 'name';
      const updatesOnlyEl = document.getElementById('packages-updates-only');
      if (updatesOnlyEl) updatesOnlyEl.checked = false;
      const cvesOnlyEl = document.getElementById('packages-cves-only');
      if (cvesOnlyEl) cvesOnlyEl.checked = false;
      const sortEl = document.getElementById('packages-sort');
      if (sortEl) sortEl.value = 'name';

      // Reset package selection when switching hosts (prevents stale selections and enables CVE pre-select)
      selectedPackages = new Set();
      const selPkgsEl = document.getElementById('select-visible-packages');
      if (selPkgsEl) selPkgsEl.checked = false;
      currentPackageName = null;
      const infoEl = document.getElementById('package-info');
      if (infoEl) infoEl.innerHTML = '';

      const hostActions = document.getElementById('host-actions');
      if (hostActions) hostActions.style.display = 'flex';

      // Stop any existing metrics updates
      stopMetricsPolling(metricsLifecycleState);

      // Clear load graph data when switching hosts
      loadGraphData = [];

      // Update active host in sidebar
      document.querySelectorAll('.host-item').forEach(item => {
        item.classList.remove('active');
        if (item.dataset.agentId === agentId) {
          item.classList.add('active');
        }
      });

      // Update header content for the host overview panel
      document.getElementById('server-info-placeholder').style.display = 'none';
      document.getElementById('server-info-header').style.display = 'block';
      document.getElementById('server-info-hostname').textContent = hostname;

      const hostObj = (allHosts || []).find(h => h.agent_id === agentId);
      void loadHostDrift(agentId);
      void loadHostTimeline(agentId);
      const hostDisplayName = (hostObj?.hostname || hostname || agentId || '—');
      const hostIp = (hostObj?.ip_address || hostObj?.fqdn || 'n/a');
      document.querySelectorAll('.host-context-name').forEach((el) => { el.textContent = hostDisplayName; });
      document.querySelectorAll('.host-context-ip').forEach((el) => { el.textContent = hostIp; });

      const detailsEl = document.getElementById('server-info-details');
      if (detailsEl) {
        const agentText = hostObj?.agent_id ? escapeHtml(hostObj.agent_id) : 'n/a';
        const osParts = [];
        if (hostObj?.os_id) osParts.push(String(hostObj.os_id));
        if (hostObj?.os_version) osParts.push(String(hostObj.os_version));
        const osText = osParts.length ? escapeHtml(osParts.join(' ')) : 'n/a';
        detailsEl.innerHTML = `
          <span class="detail-pill">Agent ID: <code>${agentText}</code></span>
          <span class="detail-pill">Agent: <code>${escapeHtml(hostObj?.agent_version || 'unknown')}</code></span>
          <span class="detail-pill">Health: <code>${hostObj?.is_online ? 'online' : 'offline'}</code></span>
          <span class="detail-pill">OS: <code>${osText}</code></span>
        `;
      }

      const labelsEl = document.getElementById('server-info-labels');
      if (labelsEl) {
        const labels = (hostObj && hostObj.labels && typeof hostObj.labels === 'object') ? hostObj.labels : {};
        const envVars = (labels.env_vars && typeof labels.env_vars === 'object') ? labels.env_vars : {};
        const env = labels.env ? String(labels.env) : (envVars.env ? String(envVars.env) : '');
        const role = labels.role ? String(labels.role) : '';
        const team = labels.team ? String(labels.team) : '';
        const parts = [];
        if (env) parts.push(`<span class="label-badge">env: <code>${escapeHtml(env)}</code></span>`);
        if (role) parts.push(`<span class="label-badge">role: <code>${escapeHtml(role)}</code></span>`);
        if (team) parts.push(`<span class="label-badge">team: <code>${escapeHtml(team)}</code></span>`);
        labelsEl.innerHTML = parts.length ? parts.join('') : `<span class="label-badge">env: <code>n/a</code></span><span class="label-badge">role: <code>n/a</code></span>`;
      }
      try {
        const hostActionsMod = window.phase3HostActions;
        if (hostActionsMod && typeof hostActionsMod.populateHostMetadataEditor === 'function') {
          hostActionsMod.populateHostMetadataEditor(hostObj || { agent_id: agentId, hostname });
        }
        if (hostActionsMod && typeof hostActionsMod.populateDiskCleanupPanel === 'function') {
          hostActionsMod.populateDiskCleanupPanel(hostObj || { agent_id: agentId, hostname });
        }
        if (hostActionsMod && typeof hostActionsMod.updateTerminalAccessIndicator === 'function') {
          hostActionsMod.updateTerminalAccessIndicator(hostObj || { agent_id: agentId, hostname }, currentPermissions);
        }
      } catch (_) { }

      // Switch to the appropriate tab:
      // - If user is in Terminal/Users/Services/Firewall/Packages, keep that tab when switching hosts.
      // - Otherwise default to the host overview (server-info-tab).
      const hostActionTabs = new Set(['terminal-tab', 'users-tab', 'services-tab', 'firewall-tab', 'packages-tab']);
      const keepTabId = hostActionTabs.has(prevActiveTabId) ? prevActiveTabId : 'server-info-tab';

      document.querySelectorAll('.tab-content-custom, .tab-content').forEach(c => c.classList.remove('active'));
      document.getElementById(keepTabId)?.classList.add('active');

      // Keep the host-action button highlight consistent
      if (keepTabId === 'terminal-tab') setHostActionActive('terminal');
      else if (keepTabId === 'users-tab') setHostActionActive('users');
      else if (keepTabId === 'services-tab') setHostActionActive('services');
      else if (keepTabId === 'firewall-tab') setHostActionActive('firewall');
      else if (keepTabId === 'packages-tab') setHostActionActive('packages');
      else setHostActionActive(null);

      // Refresh tab-specific content
      if (keepTabId === 'terminal-tab') {
        connect(currentAgentId);
        window.requestAnimationFrame(() => {
          fitTerminalViewport();
          setTimeout(fitTerminalViewport, 60);
        });
      } else if (keepTabId === 'users-tab') {
        loadUsers(currentAgentId);
      } else if (keepTabId === 'services-tab') {
        loadServices(currentAgentId);
      } else if (keepTabId === 'firewall-tab') {
        loadFirewall(currentAgentId);
      } else if (keepTabId === 'packages-tab') {
        loadPackages(currentAgentId);
        refreshPackagesNow(currentAgentId);
      } else {
        // Host overview: start metrics polling
        metricsLifecycleState.set('currentMetricsAgentId', agentId);
        loadHistoricalLoadData(agentId);
        loadMetrics(agentId);
        loadTopProcesses(agentId, true);

        metricsLifecycleState.set('metricsUpdateInterval', setInterval(() => {
          if (metricsLifecycleState.get('currentMetricsAgentId') === agentId &&
            document.getElementById('server-info-tab').classList.contains('active')) {
            loadMetrics(agentId, true);
          } else {
            stopMetricsPolling(metricsLifecycleState);
          }
        }, METRICS_POLL_MS));

        metricsLifecycleState.set('topProcessesUpdateInterval', setInterval(() => {
          if (metricsLifecycleState.get('currentMetricsAgentId') === agentId &&
            document.getElementById('server-info-tab').classList.contains('active')) {
            loadTopProcesses(agentId, true);
          } else {
            stopMetricsPolling(metricsLifecycleState);
          }
        }, TOP_PROCS_POLL_MS));
      }
    }

    async function loadTopProcesses(agentId, silent = true) {
      const mod = window.phase3Metrics;
      if (mod && typeof mod.loadTopProcesses === 'function') {
        return mod.loadTopProcesses(getMetricsCtx(), agentId, silent);
      }
    }

    async function loadMetrics(agentId, silent = false) {
      const mod = window.phase3Metrics;
      if (mod && typeof mod.loadMetrics === 'function') {
        return mod.loadMetrics(getMetricsCtx(), agentId, silent);
      }
    }

    function updateTopProcessesTable(processes) {
      const mod = window.phase3Metrics;
      if (mod && typeof mod.updateTopProcessesTable === 'function') {
        return mod.updateTopProcessesTable(processes);
      }
    }

    async function loadHistoricalLoadData(agentId) {
      const mod = window.phase3Metrics;
      if (mod && typeof mod.loadHistoricalLoadData === 'function') {
        return mod.loadHistoricalLoadData(getMetricsCtx(), agentId);
      }
    }

    function redrawLoadGraph() {
      const mod = window.phase3Metrics;
      if (mod && typeof mod.redrawLoadGraph === 'function') {
        return mod.redrawLoadGraph(getMetricsCtx());
      }
    }

    function updateLoadGraph(loadValue) {
      const mod = window.phase3Metrics;
      if (mod && typeof mod.updateLoadGraph === 'function') {
        return mod.updateLoadGraph(getMetricsCtx(), loadValue);
      }
    }

    let hostTimelineFilter = 'all';
    let hostTimelineItemsCache = [];
    let hostDriftCriticalOnly = false;
    let hostDriftChecksCache = [];

    function timelineJobCategory(it) {
      const jtRaw = String(it?.job_type || '').toLowerCase();
      const jt = jtRaw.replace(/[_\s]+/g, '-');

      const securityJobTypes = new Set([
        'cve-check',
        'security-campaign',
        'security-updates',
        'patch-security',
      ]);
      if (securityJobTypes.has(jt) || /(^|-)security(-|$)|(^|-)cve(-|$)/.test(jt)) return 'security';

      const serviceJobTypes = new Set([
        'query-services',
        'query-service-details',
        'service-restart',
        'service-start',
        'service-stop',
      ]);
      if (serviceJobTypes.has(jt) || /(^|-)service(s)?(-|$)/.test(jt)) return 'service';

      const packageJobTypes = new Set([
        'query-pkg-info',
        'query-pkg-updates',
        'query-pkg-version',
        'inventory-now',
        'pkg-upgrade',
        'dist-upgrade',
      ]);
      if (packageJobTypes.has(jt) || /(^|-)pkg(-|$)|(^|-)package(s)?(-|$)|(^|-)upgrade(-|$)|(^|-)inventory(-|$)/.test(jt)) return 'package';

      return 'other';
    }

    function timelineFilterMatch(it) {
      if (hostTimelineFilter === 'all') return true;
      const st = String(it?.status || '').toLowerCase();
      if (hostTimelineFilter === 'failed') return st === 'failed';
      return timelineJobCategory(it) === hostTimelineFilter;
    }

    function timelineJobEffect(it) {
      const jtRaw = String(it?.job_type || '').toLowerCase();
      const jt = jtRaw.replace(/[_\s]+/g, '-');
      if (jt === 'query-pkg-updates' || jt === 'query-pkg-version' || jt === 'query-pkg-info' || jt === 'inventory-now') {
        return {
          kind: 'info',
          label: 'Read-only check',
          detail: 'Collects inventory/update status. Does not install packages.',
        };
      }
      if (jt === 'pkg-upgrade' || jt === 'dist-upgrade' || jt === 'security-campaign') {
        return {
          kind: 'warn',
          label: 'Installs/changes packages',
          detail: 'This action can modify installed packages on the host.',
        };
      }
      return null;
    }

    function renderHostTimeline() {
      const el = document.getElementById('host-timeline-list');
      const countEl = document.getElementById('host-timeline-count');
      if (!el) return;

      ['all', 'failed', 'security', 'package', 'service'].forEach((k) => {
        const btn = document.getElementById(`timeline-filter-${k}`);
        if (!btn) return;
        btn.classList.toggle('btn-primary', hostTimelineFilter === k);
        if (btn.dataset.boundTimelineFilterRender !== '1') {
          btn.addEventListener('click', (e) => {
            e.preventDefault();
            hostTimelineFilter = k;
            renderHostTimeline();
          });
          btn.dataset.boundTimelineFilterRender = '1';
        }
      });

      const allItems = (hostTimelineItemsCache || []);
      const items = allItems.filter(timelineFilterMatch);
      if (countEl) countEl.textContent = `(${items.length}/${allItems.length})`;
      if (!items.length) {
        el.innerHTML = '<div class="status-muted">No events for selected filter.</div>';
        return;
      }

      el.innerHTML = items.map((it) => {
        const t = it?.time ? new Date(it.time).toLocaleString() : 'n/a';
        const st = String(it?.status || 'unknown');
        const stClass = st === 'success' ? 'status-ok' : (st === 'failed' ? 'status-error' : 'status-muted');
        const jobType = escapeHtml(String(it?.job_type || 'job'));
        const jobId = escapeHtml(String(it?.job_id || ''));
        const stdout = it?.stdout ? `<a class="status-link" href="${escapeHtml(String(it.stdout))}" target="_blank" rel="noopener">stdout</a>` : '';
        const stderr = it?.stderr ? `<a class="status-link" href="${escapeHtml(String(it.stderr))}" target="_blank" rel="noopener">stderr</a>` : '';
        const links = [stdout, stderr].filter(Boolean).join(' • ');
        const effect = timelineJobEffect(it);
        const effectTone = effect?.kind === 'warn' ? 'var(--warn)' : 'var(--muted-2)';
        return `<div style="border:1px solid var(--border);border-radius:10px;padding:0.45rem 0.55rem;background:var(--panel-2);">
          <div style="display:flex;justify-content:space-between;gap:0.5rem;align-items:center;">
            <b>${jobType}</b>
            <span class="${stClass}" style="font-size:0.8rem;">${escapeHtml(st)}</span>
          </div>
          ${effect ? `<div style="font-size:0.78rem;margin-top:0.18rem;color:${effectTone};">${escapeHtml(effect.label)} — ${escapeHtml(effect.detail)}</div>` : ''}
          <div class="status-muted" style="font-size:0.82rem;margin-top:0.2rem;display:flex;justify-content:space-between;gap:0.5rem;align-items:center;flex-wrap:wrap;">
            <span>${escapeHtml(t)} • <code>${jobId}</code></span>
            <button class="btn" data-copy-job-id="${jobId}" type="button" style="padding:0.16rem 0.45rem;">Copy job id</button>
          </div>
          ${links ? `<div style="font-size:0.8rem;margin-top:0.2rem;">${links}</div>` : ''}
        </div>`;
      }).join('');

      el.querySelectorAll('button[data-copy-job-id]').forEach((btn) => {
        if (btn.dataset.boundCopyJobId === '1') return;
        btn.addEventListener('click', async (e) => {
          e.preventDefault();
          const id = btn.getAttribute('data-copy-job-id') || '';
          if (!id) return;
          try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
              await navigator.clipboard.writeText(id);
            } else {
              const ta = document.createElement('textarea');
              ta.value = id;
              document.body.appendChild(ta);
              ta.select();
              document.execCommand('copy');
              document.body.removeChild(ta);
            }
            showToast('Job ID copied', 'success', 1800);
          } catch (_) {
            showToast('Failed to copy job ID', 'error', 2200);
          }
        });
        btn.dataset.boundCopyJobId = '1';
      });
    }

    function hostTimelineFilteredItems() {
      return (hostTimelineItemsCache || []).filter(timelineFilterMatch);
    }

    function downloadHostTimeline(kind) {
      const items = hostTimelineFilteredItems();
      if (!items.length) {
        showToast('No timeline entries to export', 'error', 2200);
        return;
      }
      const now = new Date();
      const stamp = `${now.getFullYear()}${String(now.getMonth()+1).padStart(2,'0')}${String(now.getDate()).padStart(2,'0')}-${String(now.getHours()).padStart(2,'0')}${String(now.getMinutes()).padStart(2,'0')}`;
      const base = `host-timeline-${hostTimelineFilter}-${stamp}`;
      let blob;
      let filename;
      if (kind === 'csv') {
        const esc = (v) => {
          const s = String(v == null ? '' : v);
          return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
        };
        const headers = ['time','job_id','job_type','status','exit_code','started_at','finished_at','created_by'];
        const rows = [headers.join(',')].concat(items.map((it) => headers.map((h) => esc(it?.[h] ?? '')).join(',')));
        blob = new Blob([rows.join('\n')], { type: 'text/csv;charset=utf-8' });
        filename = `${base}.csv`;
      } else {
        blob = new Blob([JSON.stringify(items, null, 2)], { type: 'application/json;charset=utf-8' });
        filename = `${base}.json`;
      }
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      showToast(`Exported ${items.length} timeline entr${items.length === 1 ? 'y' : 'ies'}`, 'success', 2000);
    }

    async function loadHostTimeline(agentId) {
      const el = document.getElementById('host-timeline-list');
      if (!el || !agentId) return;
      const jsonBtn = document.getElementById('timeline-export-json');
      const csvBtn = document.getElementById('timeline-export-csv');
      if (jsonBtn && jsonBtn.dataset.boundTimelineExport !== '1') {
        jsonBtn.addEventListener('click', (e) => { e.preventDefault(); downloadHostTimeline('json'); });
        jsonBtn.dataset.boundTimelineExport = '1';
      }
      if (csvBtn && csvBtn.dataset.boundTimelineExport !== '1') {
        csvBtn.addEventListener('click', (e) => { e.preventDefault(); downloadHostTimeline('csv'); });
        csvBtn.dataset.boundTimelineExport = '1';
      }

      el.innerHTML = '<div class="loading" style="padding:0.5rem;">Loading timeline…</div>';
      try {
        const r = await fetch(`/hosts/${encodeURIComponent(agentId)}/timeline?limit=50`, { credentials: 'include' });
        if (!r.ok) throw new Error(`timeline failed (${r.status})`);
        const d = await r.json();
        hostTimelineItemsCache = Array.isArray(d?.items) ? d.items : [];
        renderHostTimeline();
      } catch (e) {
        el.innerHTML = `<div class="error" style="margin:0;">${escapeHtml(e?.message || String(e))}</div>`;
      }
    }

    function renderHostDriftChecks() {
      const listEl = document.getElementById('host-drift-list');
      const toggleBtn = document.getElementById('host-drift-critical-only');
      if (!listEl) return;
      if (toggleBtn) toggleBtn.classList.toggle('btn-primary', hostDriftCriticalOnly);

      const checks = (hostDriftChecksCache || []).filter((c) => {
        if (!hostDriftCriticalOnly) return true;
        const sev = String(c?.severity || (String(c?.status || '') === 'pass' ? 'ok' : 'warn'));
        return sev === 'critical';
      });

      if (!checks.length) {
        listEl.innerHTML = '<div class="status-muted">No checks for selected filter.</div>';
        return;
      }

      listEl.innerHTML = checks.map((c) => {
        const sev = String(c?.severity || (String(c?.status || '') === 'pass' ? 'ok' : 'warn'));
        const sevClass = sev === 'critical' ? 'status-error' : (sev === 'warn' ? 'status-warn' : 'status-ok');
        return `<div style="display:flex;justify-content:space-between;gap:0.6rem;align-items:flex-start;">
          <div><b>${escapeHtml(String(c?.title || 'check'))}</b><div class="status-muted" style="font-size:0.82rem;">${escapeHtml(String(c?.detail || ''))}</div></div>
          <span class="${sevClass}" style="font-size:0.75rem;">${escapeHtml(sev)}</span>
        </div>`;
      }).join('');
    }

    async function loadHostDrift(agentId) {
      const sumEl = document.getElementById('host-drift-summary');
      const listEl = document.getElementById('host-drift-list');
      if (!sumEl || !listEl || !agentId) return;
      sumEl.textContent = 'Loading…';
      listEl.innerHTML = '';
      try {
        const r = await fetch(`/hosts/${encodeURIComponent(agentId)}/drift`, { credentials: 'include' });
        if (!r.ok) throw new Error(`drift failed (${r.status})`);
        const d = await r.json();
        const s = d?.summary || {};
        const lastRemAt = s.last_remediated_at ? new Date(s.last_remediated_at).toLocaleString() : null;
        const lastRemVia = s.last_remediated_via ? String(s.last_remediated_via).replace('-', ' ') : '';
        sumEl.innerHTML = `
          <div>Checks: <b>${s.checks_pass || 0}</b>/<b>${s.checks_total || 0}</b> pass • <b>${s.checks_warn || 0}</b> warnings</div>
          <div class="status-muted" style="font-size:0.82rem;margin-top:0.25rem;">Security updates: ${s.security_updates || 0} • All updates: ${s.all_updates || 0} • Failed runs 24h: ${s.failed_runs_24h || 0}</div>
          <div class="status-muted" style="font-size:0.82rem;margin-top:0.2rem;">Last remediated: ${lastRemAt ? `${escapeHtml(lastRemAt)}${lastRemVia ? ` via ${escapeHtml(lastRemVia)}` : ''}` : 'n/a'}</div>
          <div style="display:flex;gap:0.4rem;flex-wrap:wrap;margin-top:0.45rem;">
            <button class="btn" id="host-drift-refresh" type="button">Re-check</button>
            <button class="btn" id="host-drift-inventory" type="button">Inventory now</button>
            <button class="btn btn-primary" id="host-drift-security" type="button">Install security updates</button>
            <button class="btn" id="host-drift-critical-only" type="button">Critical only</button>
          </div>
        `;

        document.getElementById('host-drift-refresh')?.addEventListener('click', (e) => {
          e.preventDefault();
          void loadHostDrift(agentId);
        });

        document.getElementById('host-drift-inventory')?.addEventListener('click', async (e) => {
          e.preventDefault();
          try {
            const rr = await fetch('/jobs/inventory-now', {
              method: 'POST',
              credentials: 'include',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ agent_ids: [agentId] }),
            });
            if (!rr.ok) throw new Error(`inventory-now failed (${rr.status})`);
            showToast('Inventory queued', 'success');
            setTimeout(() => { void loadHostDrift(agentId); }, 1500);
          } catch (err) {
            showToast(err.message || String(err), 'error');
          }
        });

        document.getElementById('host-drift-security')?.addEventListener('click', async (e) => {
          e.preventDefault();
          try {
            const now = new Date();
            const end = new Date(now.getTime() + 60 * 60 * 1000);
            const payload = {
              agent_ids: [agentId],
              window_start: now.toISOString(),
              window_end: end.toISOString(),
              concurrency: 1,
              reboot_if_needed: true,
              include_kernel: false,
            };
            const rr = await fetch('/patching/campaigns/security-updates', {
              method: 'POST',
              credentials: 'include',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify(payload),
            });
            if (!rr.ok) throw new Error(`security campaign failed (${rr.status})`);
            showToast('Security campaign queued for host', 'success');
            setTimeout(() => { void loadHostDrift(agentId); }, 1500);
          } catch (err) {
            showToast(err.message || String(err), 'error');
          }
        });

        document.getElementById('host-drift-critical-only')?.addEventListener('click', (e) => {
          e.preventDefault();
          hostDriftCriticalOnly = !hostDriftCriticalOnly;
          renderHostDriftChecks();
        });

        hostDriftChecksCache = Array.isArray(d?.checks) ? d.checks : [];
        renderHostDriftChecks();
      } catch (e) {
        sumEl.textContent = 'Drift unavailable';
        listEl.innerHTML = `<div class="error" style="margin:0;">${escapeHtml(e?.message || String(e))}</div>`;
      }
    }

    function initTimelineFilters() {
      ['all', 'failed', 'security', 'package', 'service'].forEach((k) => {
        const btn = document.getElementById(`timeline-filter-${k}`);
        if (!btn || btn.dataset.boundTimelineFilter === '1') return;
        btn.addEventListener('click', (e) => {
          e.preventDefault();
          hostTimelineFilter = k;
          renderHostTimeline();
        });
        btn.dataset.boundTimelineFilter = '1';
      });
    }

    function showTerminal() {
      if (!currentAgentId) return;
      setHostActionActive('terminal');
      // Stop metrics updates when leaving server info view
      stopMetricsPolling(metricsLifecycleState);
      document.querySelectorAll('.tab-content-custom, .tab-content').forEach(c => c.classList.remove('active'));
      document.getElementById('terminal-tab').classList.add('active');
      connect(currentAgentId);
      window.requestAnimationFrame(() => {
        fitTerminalViewport();
        setTimeout(fitTerminalViewport, 60);
      });
    }

    function showUsers() {
      if (!currentAgentId) return;
      setHostActionActive('users');
      // Stop metrics updates when leaving server info view
      stopMetricsPolling(metricsLifecycleState);
      document.querySelectorAll('.tab-content-custom, .tab-content').forEach(c => c.classList.remove('active'));
      document.getElementById('users-tab').classList.add('active');
      loadUsers(currentAgentId);
    }

    function showServices() {
      if (!currentAgentId) return;
      setHostActionActive('services');
      // Stop metrics updates when leaving server info view
      stopMetricsPolling(metricsLifecycleState);
      document.querySelectorAll('.tab-content-custom, .tab-content').forEach(c => c.classList.remove('active'));
      document.getElementById('services-tab').classList.add('active');
      loadServices(currentAgentId);
    }

    function showFirewall() {
      if (!currentAgentId) return;
      setHostActionActive('firewall');
      // Stop metrics updates when leaving server info view
      stopMetricsPolling(metricsLifecycleState);
      document.querySelectorAll('.tab-content-custom, .tab-content').forEach(c => c.classList.remove('active'));
      document.getElementById('firewall-tab').classList.add('active');
      loadFirewall(currentAgentId);
    }

    function showPackages() {
      if (!currentAgentId) return;
      setHostActionActive('packages');
      // Stop metrics updates when leaving server info view
      stopMetricsPolling(metricsLifecycleState);
      document.querySelectorAll('.tab-content-custom, .tab-content').forEach(c => c.classList.remove('active'));
      document.getElementById('packages-tab').classList.add('active');
      // Load what's in DB immediately, then trigger an on-demand inventory refresh and reload.
      loadPackages(currentAgentId);
      refreshPackagesNow(currentAgentId);
    }

    function showServerInfo() {
      if (!currentAgentId) return;
      const hostObj = (allHosts || []).find(h => h.agent_id === currentAgentId);
      const hostname = hostObj?.hostname || currentAgentId;
      selectHost(currentAgentId, hostname);
    }

    function getAdminCtx() {
      return {
        setTableState,
        formatShortTime,
        safeJsonPreview,
        escapeHtml,
        showToast,
        getCookie,
        getCurrentPermissions: () => currentPermissions || {},
        getCurrentUsername: () => currentUsername,
        getAdminUsername: () => adminUsername,
        getApprovalActionFeedback: () => approvalActionFeedback,
      };
    }

    async function loadAdminAudit(showToastOnManual = false) {
      const mod = window.fleetAdminUi;
      if (mod && typeof mod.loadAdminAudit === 'function') {
        return mod.loadAdminAudit(getAdminCtx(), showToastOnManual);
      }
    }

    async function loadAdminUsers(showToastOnManual = false) {
      const mod = window.fleetAdminUi;
      if (mod && typeof mod.loadAdminUsers === 'function') {
        return mod.loadAdminUsers(getAdminCtx(), showToastOnManual);
      }
    }

    async function loadAdminAdSettings(showToastOnManual = false) {
      const mod = window.fleetAdminUi;
      if (mod && typeof mod.loadAdminAdSettings === 'function') {
        return mod.loadAdminAdSettings(getAdminCtx(), showToastOnManual);
      }
    }

    async function saveAdminAdSettings() {
      const mod = window.fleetAdminUi;
      if (mod && typeof mod.saveAdminAdSettings === 'function') {
        return mod.saveAdminAdSettings(getAdminCtx());
      }
    }

    function initOidcMapPreview() {
      const mod = window.fleetAdminUi;
      if (mod && typeof mod.initOidcMapPreview === 'function') {
        return mod.initOidcMapPreview(getAdminCtx());
      }
    }

    async function loadAdminOidcEvents(showToastOnManual = false) {
      const mod = window.fleetAdminUi;
      if (mod && typeof mod.loadAdminOidcEvents === 'function') {
        return mod.loadAdminOidcEvents(getAdminCtx(), showToastOnManual);
      }
    }

    async function loadAdminNotificationDedupe(showToastOnManual = false) {
      const mod = window.fleetAdminUi;
      if (mod && typeof mod.loadAdminNotificationDedupe === 'function') {
        return mod.loadAdminNotificationDedupe(getAdminCtx(), showToastOnManual);
      }
    }

    async function refreshApprovalsIndicator() {
      const mod = window.fleetAdminUi;
      if (mod && typeof mod.refreshApprovalsIndicator === 'function') {
        return mod.refreshApprovalsIndicator(getAdminCtx());
      }
    }

    async function loadAdminApprovals(showToastOnManual = false) {
      const mod = window.fleetAdminUi;
      if (mod && typeof mod.loadAdminApprovals === 'function') {
        return mod.loadAdminApprovals(getAdminCtx(), showToastOnManual);
      }
    }

    window.loadAdminUsers = (...args) => loadAdminUsers(...args);
    window.loadAdminAudit = (...args) => loadAdminAudit(...args);

    function showAdminPage() {
      // Stop metrics updates when leaving server info view
      stopMetricsPolling(metricsLifecycleState);
      document.querySelectorAll('.tab-content-custom, .tab-content').forEach(c => c.classList.remove('active'));
      document.getElementById('admin-tab').classList.add('active');
      loadAdminUsers();
      loadAdminAdSettings();
      loadAdminAudit();
    }

    const setHostActionActive = window.setHostActionActive || function(action) {
      document.querySelectorAll('.host-action-btn').forEach(btn => btn.classList.remove('active'));
      const map = {
        terminal: 'host-action-terminal',
        users: 'host-action-users',
        services: 'host-action-services',
        packages: 'host-action-packages'
      };
      const id = map[action];
      const target = id ? document.getElementById(id) : null;
      if (target) target.classList.add('active');
    };

    function connect(agentId) {
      const mod = window.fleetTerminalUi;
      if (mod && typeof mod.connect === 'function') {
        return mod.connect(getTerminalCtx(), agentId);
      }
    }

    async function loadHosts() {
      const hostsEl = document.getElementById('hosts');
      const mod = window.phase3HostList;
      try {
        if (mod && typeof mod.loadHosts === 'function') {
          await mod.loadHosts(getHostListCtx());
          return;
        }

        // Fallback path so UI doesn't stay stuck when module fails to load.
        console.error('[loadHosts] phase3HostList module missing; using inline fallback');
        const r = await fetch('/hosts?online_only=true', { credentials: 'include', cache: 'no-store' });
        if (!r.ok) throw new Error(`hosts failed (${r.status})`);
        const items = await r.json();
        const hosts = Array.isArray(items) ? items : [];
        if (!hostsEl) return;
        if (!hosts.length) {
          hostsEl.innerHTML = '<div class="empty-state">No hosts found</div>';
          return;
        }
        hostsEl.innerHTML = hosts.map(h => `
          <div class="host-item">
            <div class="host-meta">
              <div class="host-row-top"><div class="host-name">${escapeHtml(h.hostname || h.agent_id || '')}</div></div>
              <div class="host-subline"><span class="host-subitem">${escapeHtml(h.agent_id || '')}</span></div>
            </div>
          </div>
        `).join('');
      } catch (e) {
        console.error('[loadHosts failed]', e);
        if (hostsEl) hostsEl.innerHTML = `<div class="error">Error loading hosts: ${escapeHtml(e?.message || String(e))}</div>`;
      }
    }

    function initHostFilters() {
      const mod = window.phase3HostFilters;
      if (!mod || typeof mod.initHostFilters !== 'function') return;

      const out = mod.initHostFilters({
        getState: () => ({
          allHosts,
          hostSearchQuery,
          labelEnvFilter,
          labelRoleFilter,
          labelOwnerFilter,
          vulnFilteredAgentIds,
          selectedAgentIds,
          lastRenderedAgentIds,
          lastPkgVerification,
          lastCveCheck,
          lastCveAffectedAgentIds,
          lastCveUnionPackages,
          selectedCvePackages,
        }),
        setState: (patch) => {
          if (!patch || typeof patch !== 'object') return;
          if (Object.prototype.hasOwnProperty.call(patch, 'allHosts')) allHosts = syncHostFilterSelectionState('allHosts', patch.allHosts || []);
          if (Object.prototype.hasOwnProperty.call(patch, 'hostSearchQuery')) hostSearchQuery = syncHostFilterSelectionState('hostSearchQuery', patch.hostSearchQuery || '');
          if (Object.prototype.hasOwnProperty.call(patch, 'labelEnvFilter')) labelEnvFilter = syncHostFilterSelectionState('labelEnvFilter', patch.labelEnvFilter || '');
          if (Object.prototype.hasOwnProperty.call(patch, 'labelRoleFilter')) labelRoleFilter = syncHostFilterSelectionState('labelRoleFilter', patch.labelRoleFilter || '');
          if (Object.prototype.hasOwnProperty.call(patch, 'labelOwnerFilter')) labelOwnerFilter = syncHostFilterSelectionState('labelOwnerFilter', patch.labelOwnerFilter || '');
          if (Object.prototype.hasOwnProperty.call(patch, 'vulnFilteredAgentIds')) vulnFilteredAgentIds = syncHostFilterSelectionState('vulnFilteredAgentIds', patch.vulnFilteredAgentIds);
          if (Object.prototype.hasOwnProperty.call(patch, 'selectedAgentIds')) selectedAgentIds = syncHostFilterSelectionState('selectedAgentIds', (patch.selectedAgentIds instanceof Set) ? patch.selectedAgentIds : new Set());
          if (Object.prototype.hasOwnProperty.call(patch, 'lastRenderedAgentIds')) lastRenderedAgentIds = syncHostFilterSelectionState('lastRenderedAgentIds', Array.isArray(patch.lastRenderedAgentIds) ? patch.lastRenderedAgentIds : []);
          if (Object.prototype.hasOwnProperty.call(patch, 'lastPkgVerification')) lastPkgVerification = patch.lastPkgVerification;
          if (Object.prototype.hasOwnProperty.call(patch, 'lastCveCheck')) lastCveCheck = patch.lastCveCheck;
          if (Object.prototype.hasOwnProperty.call(patch, 'lastCveAffectedAgentIds')) lastCveAffectedAgentIds = Array.isArray(patch.lastCveAffectedAgentIds) ? patch.lastCveAffectedAgentIds : [];
          if (Object.prototype.hasOwnProperty.call(patch, 'lastCveUnionPackages')) lastCveUnionPackages = Array.isArray(patch.lastCveUnionPackages) ? patch.lastCveUnionPackages : [];
          if (Object.prototype.hasOwnProperty.call(patch, 'selectedCvePackages')) selectedCvePackages = (patch.selectedCvePackages instanceof Set) ? patch.selectedCvePackages : new Set();
        },
        syncSelectionState: syncHostFilterSelectionState,
        applyHostFilters,
        pollJob: window.pollJob,
        escapeHtml,
        matchesGlob,
        getCurrentPermissions: () => currentPermissions,
      });

      updateUpgradeControlsFn = (out && typeof out.updateUpgradeControls === 'function')
        ? out.updateUpgradeControls
        : (() => {});
    }

    function getHostWorkflowsCtx() {
      return {
        getCurrentPermissions: () => currentPermissions,
        getCurrentAgentId: () => currentAgentId,
      };
    }

    async function loadUsers(agentId) {
      const mod = window.phase3HostWorkflows;
      if (mod && typeof mod.loadUsers === 'function') {
        return mod.loadUsers(getHostWorkflowsCtx(), agentId);
      }
    }

    async function loadServices(agentId) {
      const mod = window.phase3HostWorkflows;
      if (mod && typeof mod.loadServices === 'function') {
        return mod.loadServices(getHostWorkflowsCtx(), agentId);
      }
    }

    async function loadFirewall(agentId) {
      const mod = window.phase3HostWorkflows;
      if (mod && typeof mod.loadFirewall === 'function') {
        return mod.loadFirewall(getHostWorkflowsCtx(), agentId);
      }
    }

    async function waitForServicesToStabilize(agentId, targetServiceName = null) {
      const mod = window.phase3HostWorkflows;
      if (mod && typeof mod.waitForServicesToStabilize === 'function') {
        return mod.waitForServicesToStabilize(getHostWorkflowsCtx(), agentId, targetServiceName);
      }
    }

    async function controlService(agentId, serviceName, action) {
      const mod = window.phase3HostWorkflows;
      if (mod && typeof mod.controlService === 'function') {
        return mod.controlService(getHostWorkflowsCtx(), agentId, serviceName, action);
      }
    }

    window.controlService = controlService;

    async function controlFirewall(agentId, payload) {
      const mod = window.phase3HostWorkflows;
      if (mod && typeof mod.controlFirewall === 'function') {
        return mod.controlFirewall(getHostWorkflowsCtx(), agentId, payload);
      }
    }

    window.controlFirewall = controlFirewall;

    async function controlUser(agentId, username, action) {
      const mod = window.phase3HostWorkflows;
      if (mod && typeof mod.controlUser === 'function') {
        return mod.controlUser(getHostWorkflowsCtx(), agentId, username, action);
      }
    }

    window.controlUser = controlUser;


    function getPackagesCtx() {
      return {
        getState: () => ({
          currentAgentId,
          packagesSearchQuery,
          packagesSearchTimer,
          packagesUpdatesOnly,
          packagesCvesOnly,
          packagesSortBy,
          pkgInteractiveTerminal,
          selectedPackages,
          currentPackageName,
        }),
        setState: (patch) => {
          if (!patch || typeof patch !== 'object') return;
          if (Object.prototype.hasOwnProperty.call(patch, 'packagesSearchQuery')) packagesSearchQuery = patch.packagesSearchQuery || '';
          if (Object.prototype.hasOwnProperty.call(patch, 'packagesSearchTimer')) packagesSearchTimer = patch.packagesSearchTimer || null;
          if (Object.prototype.hasOwnProperty.call(patch, 'packagesUpdatesOnly')) packagesUpdatesOnly = !!patch.packagesUpdatesOnly;
          if (Object.prototype.hasOwnProperty.call(patch, 'packagesCvesOnly')) packagesCvesOnly = !!patch.packagesCvesOnly;
          if (Object.prototype.hasOwnProperty.call(patch, 'packagesSortBy')) packagesSortBy = String(patch.packagesSortBy || 'name');
          if (Object.prototype.hasOwnProperty.call(patch, 'pkgInteractiveTerminal')) pkgInteractiveTerminal = !!patch.pkgInteractiveTerminal;
          if (Object.prototype.hasOwnProperty.call(patch, 'selectedPackages')) selectedPackages = (patch.selectedPackages instanceof Set) ? patch.selectedPackages : new Set();
          if (Object.prototype.hasOwnProperty.call(patch, 'currentPackageName')) currentPackageName = patch.currentPackageName || null;
        },
        runInteractivePackageCommand: (action, packages) => {
          if (!currentAgentId || !Array.isArray(packages) || !packages.length) return false;
          const esc = (s) => `'${String(s).replace(/'/g, `'"'"'`)}'`;
          const pkgArgs = packages.map(esc).join(' ');
          let cmd = '';
          if (action === 'upgrade') cmd = `sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade ${pkgArgs}`;
          else if (action === 'reinstall') cmd = `sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall ${pkgArgs}`;
          else if (action === 'remove') cmd = `sudo DEBIAN_FRONTEND=noninteractive apt-get remove -y ${pkgArgs}`;
          if (!cmd) return false;

          // Security: never collect terminal credentials in browser prompts.
          // Queue command, switch to terminal, and let user run it after login.
          pendingInteractivePackageCmd = cmd;
          updateTerminalPendingCmdButton();
          showTerminal();
          showToast('Terminal opened. Log in and click "Run pending package command".', 'info', 5000);
          return true;
        },
      };
    }

    function initPackagesSearch() {
      const mod = window.phase3Packages;
      if (mod && typeof mod.initPackagesSearch === 'function') {
        return mod.initPackagesSearch(getPackagesCtx());
      }
    }

    async function loadPackages(agentId) {
      const mod = window.phase3Packages;
      if (mod && typeof mod.loadPackages === 'function') {
        return mod.loadPackages(getPackagesCtx(), agentId);
      }
    }

    async function refreshPackagesNow(agentId) {
      const mod = window.phase3Packages;
      if (mod && typeof mod.refreshPackagesNow === 'function') {
        return mod.refreshPackagesNow(getPackagesCtx(), agentId);
      }
    }

    function getOverviewCtx() {
      return {
        formatShortTime,
        selectHost,
        openDiskModal,
        showServerInfo,
        showPackages,
        loadPackages,
        setPackagesUpdatesOnly: (v) => { packagesUpdatesOnly = !!v; },
        loadPendingUpdatesReport: (showToastOnManual = false, backgroundRefresh = false) => loadPendingUpdatesReport(showToastOnManual, backgroundRefresh),
        clearCurrentHostSelection,
        stopMetricsPolling: () => stopMetricsPolling(metricsLifecycleState),
        loadHostsTable,
        loadCronjobs,
        loadSshKeys,
        loadSshKeyRequests,
        maybeLoadSshKeyAdminQueue,
        loadAdminSshKeys,
        loadFleetOverview: (forceLive = false, backgroundRefresh = false) => loadFleetOverview(forceLive, backgroundRefresh),
        loadFailedRuns,
        loadQueueHealth,
        resetQueueHealthPagination,
        moveQueueHealthPage,
        cancelVisibleOldQueuedJobs,
        requeueVisibleFailedJobs,
        loadHosts,
        getLastRenderedAgentIds: () => lastRenderedAgentIds,
        setLastRenderedAgentIds: (v) => { lastRenderedAgentIds = syncHostFilterSelectionState('lastRenderedAgentIds', Array.isArray(v) ? v : []); return lastRenderedAgentIds; },
        getHostSearchQuery: () => hostSearchQuery,
        getCurrentAgentId: () => currentAgentId,
        getLabelEnvFilter: () => labelEnvFilter,
        getLabelRoleFilter: () => labelRoleFilter,
        getLabelOwnerFilter: () => labelOwnerFilter,
        getVulnFilteredAgentIds: () => vulnFilteredAgentIds,
        setAllHosts: (hosts) => {
          allHosts = syncHostFilterSelectionState('allHosts', Array.isArray(hosts) ? hosts : []);
          try {
            const hostListMod = window.phase3HostList;
            if (hostListMod && typeof hostListMod.rebuildLabelFilterOptions === 'function') {
              hostListMod.rebuildLabelFilterOptions(getHostListCtx());
            }
          } catch (_) { }
          return allHosts;
        },
      };
    }

    async function loadFleetOverview(forceLive = false, backgroundRefresh = false) {
      const mod = window.phase3Overview;
      if (mod && typeof mod.loadFleetOverview === 'function') {
        return mod.loadFleetOverview(getOverviewCtx(), forceLive, backgroundRefresh);
      }
    }

    function getFailedRunsCtx() {
      return {
        setTableState,
        escapeHtml,
        formatShortTime,
        showToast,
      };
    }

    async function loadFailedRuns(hours = 24, showToastOnManual = false) {
      const mod = window.fleetFailedRunsUi;
      if (mod && typeof mod.loadFailedRuns === 'function') {
        return mod.loadFailedRuns(getFailedRunsCtx(), hours, showToastOnManual);
      }
    }

    function getQueueHealthCtx() {
      return {
        getOffset: () => queueHealthOffset,
        setOffset: (v) => { queueHealthOffset = Math.max(0, Number(v) || 0); return queueHealthOffset; },
        setTableState,
        escapeHtml,
        formatShortTime,
        showToast,
        getCookie,
        copyTextWithFallback,
      };
    }

    async function loadQueueHealth(showToastOnManual = false) {
      const mod = window.fleetJobsUi;
      if (mod && typeof mod.loadQueueHealth === 'function') {
        return mod.loadQueueHealth(getQueueHealthCtx(), showToastOnManual);
      }
    }

    function resetQueueHealthPagination() {
      const mod = window.fleetJobsUi;
      if (mod && typeof mod.resetQueueHealthPagination === 'function') {
        return mod.resetQueueHealthPagination(getQueueHealthCtx());
      }
    }

    function moveQueueHealthPage(direction) {
      const mod = window.fleetJobsUi;
      if (mod && typeof mod.moveQueueHealthPage === 'function') {
        return mod.moveQueueHealthPage(getQueueHealthCtx(), direction);
      }
    }

    function formatSecondsShort(seconds) {
      const mod = window.fleetJobsUi;
      if (mod && typeof mod.formatSecondsShort === 'function') {
        return mod.formatSecondsShort(seconds);
      }
      return '';
    }

    function formatJobDetailText(d) {
      const mod = window.fleetJobsUi;
      if (mod && typeof mod.formatJobDetailText === 'function') {
        return mod.formatJobDetailText(d);
      }
      return '';
    }

    async function openJobDetailModal(jobId) {
      const mod = window.fleetJobsUi;
      if (mod && typeof mod.openJobDetailModal === 'function') {
        return mod.openJobDetailModal(getQueueHealthCtx(), jobId);
      }
    }

    async function cancelQueuedJob(jobId) {
      const mod = window.fleetJobsUi;
      if (mod && typeof mod.cancelQueuedJob === 'function') {
        return mod.cancelQueuedJob(getQueueHealthCtx(), jobId);
      }
    }

    async function cancelVisibleOldQueuedJobs() {
      const mod = window.fleetJobsUi;
      if (mod && typeof mod.cancelVisibleOldQueuedJobs === 'function') {
        return mod.cancelVisibleOldQueuedJobs(getQueueHealthCtx());
      }
    }

    async function requeueVisibleFailedJobs() {
      const mod = window.fleetJobsUi;
      if (mod && typeof mod.requeueVisibleFailedJobs === 'function') {
        return mod.requeueVisibleFailedJobs(getQueueHealthCtx());
      }
    }

    function formatShortTime(iso) {
      if (!iso) return '–';
      try {
        return new Date(iso).toLocaleString();
      } catch {
        return String(iso);
      }
    }

    async function loadHostsTable() {
      const mod = window.phase3Overview;
      if (mod && typeof mod.loadHostsTable === 'function') {
        return mod.loadHostsTable(getOverviewCtx());
      }
    }

    // Shared by the Hosts bulk action and the extracted Cronjobs UI. Keep this
    // in fleet-app scope; a copy nested inside initHostsTableControls is not
    // visible while getCronjobsCtx is being constructed.
    async function confirmBlastRadius(agentIds, actionLabel, threshold = 5) {
      try {
        const r = await fetch('/jobs/preflight', {
          method: 'POST',
          credentials: 'include',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ agent_ids: agentIds }),
        });
        if (!r.ok) throw new Error(`preflight failed (${r.status})`);
        const pre = await r.json();
        const targeted = Array.isArray(pre?.targeted_hosts) ? pre.targeted_hosts : [];
        const excluded = Array.isArray(pre?.excluded_by_scope) ? pre.excluded_by_scope : [];
        const offline = Array.isArray(pre?.offline_or_unreachable) ? pre.offline_or_unreachable : [];
        const summary = `${actionLabel}\n\nTargeted: ${targeted.length}\nExcluded by scope: ${excluded.length}\nOffline/unreachable: ${offline.length}`;
        if (!targeted.length) {
          showToast('No targeted hosts after preflight', 'error');
          return { ok: false, preflight: pre };
        }
        if (targeted.length > threshold) {
          const typed = prompt(`${summary}\n\nType APPLY to continue:`);
          if ((typed || '').trim().toUpperCase() !== 'APPLY') return { ok: false, preflight: pre };
        } else if (!confirm(`${summary}\n\nProceed?`)) {
          return { ok: false, preflight: pre };
        }
        return { ok: true, preflight: pre };
      } catch (e) {
        showToast(e.message || String(e), 'error');
        return { ok: false, preflight: null };
      }
    }

    function getSelectedHostAgentIds() {
      const ids = [];
      document.querySelectorAll('.hosts-row-select:checked').forEach(cb => {
        const aid = cb.getAttribute('data-agent-id') || '';
        if (aid) ids.push(aid);
      });
      return ids;
    }

    function initHostsTableControls() {
      document.getElementById('hosts-reload')?.addEventListener('click', (e) => {
        e.preventDefault();
        loadHostsTable();
      });
      document.getElementById('hosts-sort')?.addEventListener('change', loadHostsTable);
      document.getElementById('hosts-order')?.addEventListener('change', loadHostsTable);
      document.getElementById('hosts-page-size')?.addEventListener('change', () => {
        const mod = window.phase3Overview;
        if (mod && typeof mod.setHostsTablePage === 'function') mod.setHostsTablePage(1);
        if (mod && typeof mod.applyHostsTableFilters === 'function') mod.applyHostsTableFilters(getOverviewCtx());
      });
      document.getElementById('hosts-page-prev')?.addEventListener('click', (e) => {
        e.preventDefault();
        const mod = window.phase3Overview;
        if (mod && typeof mod.moveHostsTablePage === 'function') mod.moveHostsTablePage(getOverviewCtx(), -1);
      });
      document.getElementById('hosts-page-next')?.addEventListener('click', (e) => {
        e.preventDefault();
        const mod = window.phase3Overview;
        if (mod && typeof mod.moveHostsTablePage === 'function') mod.moveHostsTablePage(getOverviewCtx(), 1);
      });

      document.getElementById('hosts-select-all')?.addEventListener('change', (e) => {
        const checked = !!e.target.checked;
        const selected = selectedAgentIds instanceof Set ? selectedAgentIds : new Set();
        document.querySelectorAll('.hosts-row-select').forEach(cb => {
          cb.checked = checked;
          const aid = String(cb.getAttribute('data-agent-id') || '').trim();
          if (!aid) return;
          if (checked) selected.add(aid);
          else selected.delete(aid);
        });
        selectedAgentIds = selected;
        updateUpgradeControlsFn();
      });

      async function bulkPost(url, payload, okMsg) {
        const statusEl = document.getElementById('hosts-bulk-status');
        if (statusEl) statusEl.textContent = 'Working…';
        try {
          const r = await fetch(url, {
            method: 'POST',
            credentials: 'include',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(payload),
          });
          if (!r.ok) throw new Error(`${url} failed (${r.status})`);
          const d = await r.json();
          showToast(okMsg, 'success');
          if (statusEl) statusEl.textContent = '';
          return d;
        } catch (e) {
          showToast(e.message, 'error');
          if (statusEl) statusEl.textContent = '';
        }
      }

      document.getElementById('hosts-bulk-inventory')?.addEventListener('click', async (e) => {
        e.preventDefault();
        const ids = getSelectedHostAgentIds();
        if (!ids.length) return showToast('Select hosts first', 'error');
        await bulkPost('/jobs/inventory-now', { agent_ids: ids }, `Triggered inventory for ${ids.length} hosts`);
      });

      document.getElementById('hosts-bulk-security')?.addEventListener('click', async (e) => {
        e.preventDefault();
        const ids = getSelectedHostAgentIds();
        if (!ids.length) return showToast('Select hosts first', 'error');
        const now = new Date();
        const end = new Date(now.getTime() + 60 * 60 * 1000);
        const payload = {
          agent_ids: ids,
          window_start: now.toISOString(),
          window_end: end.toISOString(),
          concurrency: 5,
          reboot_if_needed: true,
          include_kernel: false,
        };
        await bulkPost('/patching/campaigns/security-updates', payload, `Security campaign scheduled for ${ids.length} hosts`);
      });

      document.getElementById('hosts-bulk-dist')?.addEventListener('click', async (e) => {
        e.preventDefault();
        const ids = getSelectedHostAgentIds();
        if (!ids.length) return showToast('Select hosts first', 'error');
        const check = await confirmBlastRadius(ids, 'dist-upgrade preflight');
        if (!check.ok) return;
        await bulkPost('/jobs/dist-upgrade', { agent_ids: ids }, `dist-upgrade queued for ${ids.length} hosts`);
      });

      // Remove selected hosts
      document.getElementById('hosts-remove-selected')?.addEventListener('click', async (e) => {
        e.preventDefault();
        const ids = getSelectedHostAgentIds();
        if (!ids.length) return showToast('Select hosts first', 'error');

        const previewResp = await fetch('/hosts/remove', {
          method: 'POST',
          credentials: 'include',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ agent_ids: ids, dry_run: true })
        });
        if (!previewResp.ok) {
          showToast(`preview failed (${previewResp.status})`, 'error');
          return;
        }
        const preview = await previewResp.json();
        const found = Array.isArray(preview?.found_agent_ids) ? preview.found_agent_ids : [];
        const missing = Array.isArray(preview?.missing_agent_ids) ? preview.missing_agent_ids : [];
        const blockedLocal = Array.isArray(preview?.blocked_local_agent_ids) ? preview.blocked_local_agent_ids : [];
        if (!found.length) {
          if (blockedLocal.length) {
            const force = confirm('Selected host is protected (srv-001 local agent).\n\nForce remove it from inventory?');
            if (!force) return;
            const forceResp = await fetch('/hosts/remove', {
              method: 'POST',
              credentials: 'include',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ agent_ids: ids, include_local: true })
            });
            if (!forceResp.ok) {
              showToast(`force remove failed (${forceResp.status})`, 'error');
              return;
            }
            const forceOut = await forceResp.json();
            showToast(`Removed ${forceOut?.deleted?.length || 0} host(s)`, 'success');
            await loadHosts();
            await loadHostsTable();
            return;
          } else {
            const sample = missing.slice(0, 3).join(', ');
            showToast(sample ? `Selected host(s) not found: ${sample}` : 'None of the selected hosts exist anymore', 'error');
          }
          return;
        }

        const list = found.slice(0, 12).join('\n');
        const more = found.length > 12 ? `\n… and ${found.length - 12} more` : '';
        const missingMsg = missing.length ? `\n\nMissing: ${missing.slice(0, 6).join(', ')}${missing.length > 6 ? '…' : ''}` : '';
        const blockedMsg = blockedLocal.length ? `\n\nProtected local: ${blockedLocal.join(', ')} (not removable by default)` : '';
        const ok = confirm(`This will REMOVE ${found.length} host(s) from inventory:\n\n${list}${more}${missingMsg}${blockedMsg}\n\nProceed?`);
        if (!ok) return;

        const resp = await fetch('/hosts/remove', {
          method: 'POST',
          credentials: 'include',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ agent_ids: ids })
        });
        if (!resp.ok) {
          showToast(`remove failed (${resp.status})`, 'error');
          return;
        }
        const out = await resp.json();
        showToast(`Removed ${out?.deleted?.length || 0} host(s)`, 'success');

        await loadHosts();
        await loadHostsTable();
      });

      // Cleanup offline hosts
      document.getElementById('hosts-cleanup-offline')?.addEventListener('click', async (e) => {
        e.preventDefault();
        const minsStr = prompt('Delete hosts that have been offline for how many minutes?', '60');
        if (minsStr === null) return;
        const mins = parseInt((minsStr || '').trim(), 10);
        if (!Number.isFinite(mins) || mins < 1) {
          showToast('Enter a valid number of minutes (>= 1)', 'error');
          return;
        }

        // Dry run preview
        try {
          const previewResp = await fetch(`/hosts/cleanup-offline?older_than_minutes=${encodeURIComponent(mins)}&dry_run=true`, {
            method: 'POST',
            credentials: 'include'
          });
          if (!previewResp.ok) throw new Error(`preview failed (${previewResp.status})`);
          const preview = await previewResp.json();
          const n = preview?.count || 0;
          const agentIds = (preview?.agent_ids || []).slice(0, 12);
          const more = (preview?.agent_ids || []).length > 12 ? `\n… and ${(preview.agent_ids.length - 12)} more` : '';

          const msg = n
            ? `This will DELETE ${n} host(s) last seen before ${preview.cutoff}.\n\n${agentIds.join('\n')}${more}\n\nProceed?`
            : `No hosts are older than ${mins} minutes. (cutoff: ${preview.cutoff})`;

          if (!n) {
            showToast('No offline hosts to delete', 'success');
            return;
          }

          if (!confirm(msg)) return;

          const resp = await fetch(`/hosts/cleanup-offline?older_than_minutes=${encodeURIComponent(mins)}`, {
            method: 'POST',
            credentials: 'include'
          });
          if (!resp.ok) throw new Error(`cleanup failed (${resp.status})`);
          const out = await resp.json();
          showToast(`Deleted ${out?.deleted?.length || 0} host(s)`, 'success');

          // Reload lists
          await loadHosts();
          await loadHostsTable();
        } catch (err) {
          showToast(err.message || String(err), 'error');
        }
      });

      // Click-sort headers
      function setSort(key) {
        const sortSel = document.getElementById('hosts-sort');
        const orderSel = document.getElementById('hosts-order');
        if (!sortSel || !orderSel) return;
        const cur = sortSel.value;
        const curOrd = orderSel.value;
        if (cur === key) orderSel.value = (curOrd === 'asc') ? 'desc' : 'asc';
        else { sortSel.value = key; orderSel.value = 'asc'; }
        updateHostsSortIndicators(sortSel.value, orderSel.value);
        loadHostsTable();
      }
      const hostsSortSel = document.getElementById('hosts-sort');
      const hostsOrderSel = document.getElementById('hosts-order');
      updateHostsSortIndicators(hostsSortSel?.value || 'hostname', hostsOrderSel?.value || 'asc');
      bindSortableHeader('hosts-th-host', () => setSort('hostname'));
      bindSortableHeader('hosts-th-owner', () => setSort('owner'));
      bindSortableHeader('hosts-th-os', () => setSort('os_version'));
      bindSortableHeader('hosts-th-upd', () => setSort('updates'));
      bindSortableHeader('hosts-th-sec', () => setSort('security_updates'));
      bindSortableHeader('hosts-th-last', () => setSort('last_seen'));
    }

    async function loadPendingUpdatesReport(showToastOnManual = false, backgroundRefresh = false) {
      const mod = window.phase3Overview;
      if (mod && typeof mod.loadPendingUpdatesReport === 'function') {
        return mod.loadPendingUpdatesReport(getOverviewCtx(), showToastOnManual, backgroundRefresh);
      }
    }

    function initFleetOverviewControls() {
      const mod = window.phase3Overview;
      if (mod && typeof mod.initFleetOverviewControls === 'function') {
        return mod.initFleetOverviewControls(getOverviewCtx());
      }
    }

    

    // Cronjobs host picker state is owned here; behavior lives in fleet-cronjobs-ui.js.
    const cronUiState = createUiStateAccess('cronHostPicker', { selectedAgentIds: new Set() });
    const cronUiDefaults = (typeof window.initCronHostPickerState === 'function')
      ? window.initCronHostPickerState(cronUiState)
      : { selectedAgentIds: (cronUiState.get('selectedAgentIds') instanceof Set) ? cronUiState.get('selectedAgentIds') : new Set() };

    function getCronSelectedAgentIds() {
      return cronUiState.get('selectedAgentIds', cronUiDefaults.selectedAgentIds);
    }

    function setCronSelectedAgentIds(next) {
      return cronUiState.set('selectedAgentIds', (next instanceof Set) ? next : new Set());
    }

    function getCronjobsCtx() {
      return {
        setTableState,
        escapeHtml,
        formatShortTime,
        showToast,
        wireBusyClick,
        withBusyButton,
        confirmBlastRadius,
        getAllHosts: () => allHosts,
        getLastRenderedAgentIds: () => lastRenderedAgentIds,
        getCronSelectedAgentIds,
        setCronSelectedAgentIds,
      };
    }

    async function loadCronjobs(showToastOnManual = false) {
      const mod = window.fleetCronjobsUi;
      if (mod && typeof mod.loadCronjobs === 'function') {
        return mod.loadCronjobs(getCronjobsCtx(), showToastOnManual);
      }
    }

    function initCronjobsControls() {
      const mod = window.fleetCronjobsUi;
      if (mod && typeof mod.initCronjobsControls === 'function') {
        return mod.initCronjobsControls(getCronjobsCtx());
      }
    }

    // SSH Keys UI
    const sshUiState = createUiStateAccess('sshKeys', {
      keysCache: [],
      selectedKeyId: null,
      selectedAgentIds: new Set(),
    });
    const sshUiDefaults = (typeof window.initSshKeysUiState === 'function')
      ? window.initSshKeysUiState(sshUiState)
      : {
        keysCache: Array.isArray(sshUiState.get('keysCache')) ? sshUiState.get('keysCache') : [],
        selectedKeyId: sshUiState.get('selectedKeyId', null) || null,
        selectedAgentIds: (sshUiState.get('selectedAgentIds') instanceof Set) ? sshUiState.get('selectedAgentIds') : new Set(),
      };

    function getSshSelectedAgentIds() {
      return sshUiState.get('selectedAgentIds', sshUiDefaults.selectedAgentIds);
    }

    function setSshSelectedAgentIds(next) {
      return sshUiState.set('selectedAgentIds', (next instanceof Set) ? next : new Set());
    }

    function getSshSelectedKeyId() {
      return sshUiState.get('selectedKeyId', sshUiDefaults.selectedKeyId);
    }

    function setSshSelectedKeyId(next) {
      return sshUiState.set('selectedKeyId', next || null);
    }

    function getSshKeysCache() {
      return sshUiState.get('keysCache', sshUiDefaults.keysCache);
    }

    function setSshKeysCache(next) {
      return sshUiState.set('keysCache', Array.isArray(next) ? next : []);
    }

    function setSshHostsPanelVisible(v) {
      setPanelVisibleById('sshkey-hosts-panel', v);
    }

    function renderSshHostsList() {
      const selectedAgentIds = getSshSelectedAgentIds();
      const nextSelected = renderSshHostsListView({
        hosts: (allHosts || []),
        selectedAgentIds: selectedAgentIds,
        listId: 'sshkey-hosts-list',
        countId: 'sshkey-hosts-count',
        searchId: 'sshkey-hosts-search',
      }) || selectedAgentIds;
      setSshSelectedAgentIds(nextSelected);
    }

    async function loadSshKeys(showToastOnManual = false) {
      const tbody = document.getElementById('sshkeys-table');
      if (!tbody) return;
      try {
        setTableState(tbody, 4, 'loading', 'Loading…');
        const r = await fetch('/sshkeys', { credentials: 'include' });
        if (!r.ok) throw new Error(`sshkeys failed (${r.status})`);
        const d = await r.json();
        setSshKeysCache(d?.items || []);
        if (!getSshKeysCache().length) {
          setTableState(tbody, 4, 'empty', 'No keys yet');
          return;
        }
        tbody.innerHTML = '';
        for (const k of getSshKeysCache()) {
          const tr = document.createElement('tr');
          tr.style.cursor = 'pointer';
          const selectedKeyId = getSshSelectedKeyId();
          const isSel = (selectedKeyId && selectedKeyId === k.id);
          tr.innerHTML = `
            <td>${escapeHtml(k.name || '')}</td>
            <td><code>${escapeHtml(k.fingerprint || '')}</code></td>
            <td style="max-width:520px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><code>${escapeHtml(k.public_key || '')}</code></td>
            <td style="text-align:right;"><button class="btn" data-revoke-id="${escapeHtml(k.id)}">Delete</button></td>
          `;
          if (isSel) tr.style.background = 'color-mix(in srgb, var(--primary) 12%, var(--panel))';
          tr.setAttribute('data-key-id', k.id);
          tr.addEventListener('click', (e) => {
            if ((e.target && e.target.tagName || '').toLowerCase() === 'button') return;
            setSshSelectedKeyId(k.id);
            // Highlight immediately.
            Array.from(tbody.querySelectorAll('tr[data-key-id]')).forEach(row => {
              const rowId = row.getAttribute('data-key-id');
              if (rowId && rowId === getSshSelectedKeyId()) {
                row.style.background = 'color-mix(in srgb, var(--primary) 12%, var(--panel))';
              } else {
                row.style.background = '';
              }
            });
          });
          tbody.appendChild(tr);
        }
        tbody.querySelectorAll('button[data-revoke-id]').forEach(btn => {
          btn.addEventListener('click', async (e) => {
            e.preventDefault();
            const id = btn.getAttribute('data-revoke-id');
            if (!id) return;
            const r2 = await fetch(`/sshkeys/${encodeURIComponent(id)}`, { method: 'DELETE', credentials: 'include' });
            if (!r2.ok) return showToast('Delete failed', 'error');
            if (getSshSelectedKeyId() === id) setSshSelectedKeyId(null);
            showToast('Key deleted', 'success');
            loadSshKeys();
          });
        });
        if (showToastOnManual) showToast('SSH keys refreshed', 'success');
      } catch (e) {
        setTableState(tbody, 4, 'error', e.message || String(e));
        if (showToastOnManual) showToast(e.message, 'error');
      }
    }

    async function loadSshKeyRequests() {
      const tbody = document.getElementById('sshkey-requests-table');
      if (!tbody) return;
      try {
        setTableState(tbody, 7, 'loading', 'Loading…');
        const r = await fetch('/sshkeys/deploy-requests', { credentials: 'include' });
        if (!r.ok) throw new Error(`requests failed (${r.status})`);
        const d = await r.json();
        const items = d?.items || [];
        if (!items.length) {
          setTableState(tbody, 7, 'empty', 'No requests');
          return;
        }
        tbody.innerHTML = '';
        for (const it of items) {
          const tr = document.createElement('tr');
          const sudoMode = String(it.sudo_mode || (it.grant_sudo ? 'restricted' : 'none'));
          tr.innerHTML = `
            <td class="status-muted">${escapeHtml(formatShortTime(it.created_at))}</td>
            <td><code>${escapeHtml(String(it.key_id || '')).slice(0,8)}</code></td>
            <td>${escapeHtml(String((it.agent_ids||[]).length))}</td>
            <td>${escapeHtml(sudoMode)}</td>
            <td>${escapeHtml(it.status || '')}</td>
            <td>${escapeHtml(it.approved_by || '')}</td>
            <td class="status-error">${escapeHtml(it.error || '')}</td>
          `;
          tbody.appendChild(tr);
        }
      } catch (e) {
        setTableState(tbody, 7, 'error', e.message || String(e));
      }
    }

    async function loadAdminSshKeys() {
      const panel = document.getElementById('sshkey-admin-keys');
      const tbody = document.getElementById('sshkey-admin-keys-table');
      if (!panel || !tbody) return;

      const isAdmin = (currentPermissions && String(currentPermissions.role||'').toLowerCase() === 'admin') || !!currentPermissions.can_manage_users;
      if (!isAdmin) {
        panel.style.display = 'none';
        return;
      }
      panel.style.display = 'block';

      try {
        setTableState(tbody, 5, 'loading', 'Loading…');
        const r = await fetch('/sshkeys/admin/keys', { credentials: 'include' });
        if (!r.ok) throw new Error(`admin keys failed (${r.status})`);
        const d = await r.json();
        const items = d?.items || [];
        if (!items.length) {
          setTableState(tbody, 5, 'empty', 'No keys');
          return;
        }
        tbody.innerHTML = '';
        for (const k of items) {
          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td class="status-muted">${escapeHtml(formatShortTime(k.created_at))}</td>
            <td>${escapeHtml(k.user_name || String(k.user_id||'').slice(0,8))}</td>
            <td>${escapeHtml(k.name || '')}</td>
            <td><code>${escapeHtml(k.fingerprint || '')}</code></td>
            <td style="max-width:520px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><code>${escapeHtml(k.public_key || '')}</code></td>
          `;
          tbody.appendChild(tr);
        }
      } catch (e) {
        setTableState(tbody, 5, 'error', e.message || String(e));
      }
    }

    async function maybeLoadSshKeyAdminQueue() {
      const panel = document.getElementById('sshkey-admin-approvals');
      const tbody = document.getElementById('sshkey-admin-table');
      if (!panel || !tbody) return;
      // Only show for admin users
      const isAdmin = (currentPermissions && String(currentPermissions.role||'').toLowerCase() === 'admin') || !!currentPermissions.can_manage_users;
      if (!isAdmin) {
        panel.style.display = 'none';
        const indicator = document.getElementById('sshkeys-approval-indicator');
        if (indicator) indicator.style.display = 'none';
        return;
      }
      panel.style.display = 'block';
      try {
        const r = await fetch('/sshkeys/admin/deploy-requests', { credentials: 'include' });
        if (!r.ok) throw new Error(`admin queue failed (${r.status})`);
        const d = await r.json();
        const items = d?.items || [];

        const indicator = document.getElementById('sshkeys-approval-indicator');
        if (indicator) indicator.style.display = items.length ? 'inline' : 'none';

        if (!items.length) {
          tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;" class="status-muted">No pending approvals</td></tr>';
          return;
        }
        tbody.innerHTML = '';

        const itemsById = new Map();
        for (const it of items) itemsById.set(String(it.id), it);

        const targetsLabel = (it) => {
          const targets = it.targets || (it.agent_ids || []).map(aid => ({ agent_id: String(aid), hostname: String(aid) }));
          const names = targets.map(t => t.hostname || t.agent_id).filter(Boolean);
          const preview = names.slice(0, 3).join(', ');
          const more = names.length > 3 ? ` (+${names.length - 3} more)` : '';
          return { text: preview + more, title: names.join('\n') };
        };

        for (const it of items) {
          const tr = document.createElement('tr');
          const t = targetsLabel(it);
          const sudoMode = String(it.sudo_mode || (it.grant_sudo ? 'restricted' : 'none'));
          tr.innerHTML = `
            <td class="status-muted">${escapeHtml(formatShortTime(it.created_at))}</td>
            <td>${escapeHtml(it.user_name || String(it.user_id||'').slice(0,8))}</td>
            <td><code>${escapeHtml(String(it.key_name||'') || String(it.key_id||'').slice(0,8))}</code></td>
            <td title="${escapeHtml(t.title)}">${escapeHtml(t.text || String((it.agent_ids||[]).length))}</td>
            <td>${escapeHtml(sudoMode)}</td>
            <td style="text-align:right;white-space:nowrap;">
              <button class="btn" data-view-id="${escapeHtml(it.id)}">Details</button>
              <button class="btn btn-primary" data-approve-id="${escapeHtml(it.id)}">Approve</button>
              <button class="btn" data-reject-id="${escapeHtml(it.id)}">Reject</button>
            </td>
          `;
          tbody.appendChild(tr);
        }

        tbody.querySelectorAll('button[data-view-id]').forEach(btn => {
          btn.addEventListener('click', (e) => {
            e.preventDefault();
            const id = btn.getAttribute('data-view-id');
            const it = itemsById.get(String(id));
            if (!it) return;
            openSshKeyDeployApprovalModal(it);
          });
        });

        tbody.querySelectorAll('button[data-approve-id]').forEach(btn => {
          btn.addEventListener('click', async (e) => {
            e.preventDefault();
            const id = btn.getAttribute('data-approve-id');
            if (!id) return;

            const it = itemsById.get(String(id));
            if (it) {
              const t = targetsLabel(it);
              const keyShort = (String(it.key_id||'')).slice(0,8);
              const keyLabel = (String(it.key_name||'').trim()) ? `${it.key_name} (${keyShort})` : keyShort;
              const sudoMode = it.sudo_mode || (it.grant_sudo ? 'restricted' : 'none');
              const revokeWarning = (String(sudoMode).toLowerCase() === 'none')
                ? '\n\n⚠ No sudo will remove existing Fleet sudoers entry and sudo/wheel group access for this user on target hosts.'
                : '';
              const ok = confirm(`Approve deployment request?\n\nRequested by: ${it.user_name || it.user_id}\nKey: ${keyLabel}\nSudo mode: ${sudoMode}\nTargets:\n${t.title}${revokeWarning}`);
              if (!ok) return;
            }

            const r2 = await fetch(`/sshkeys/admin/deploy-requests/${encodeURIComponent(id)}/approve`, { method: 'POST', credentials: 'include' });
            const raw = await r2.text();
            let data = null;
            try { data = raw ? JSON.parse(raw) : null; } catch { }
            if (!r2.ok) {
              const msg = (data && (data.detail || data.error)) ? (data.detail || data.error) : (raw || 'Approve failed');
              return showToast(msg, 'error');
            }
            if (data && String(data.status||'') === 'failed') {
              showToast(data.error || 'Request marked failed', 'error');
              maybeLoadSshKeyAdminQueue();
              return;
            }

            // If backend returned a job_id, poll and show outcome so admins get immediate feedback.
            const jobId = data && (data.job_id || data.jobId);
            if (jobId) {
              showToast('Approved (waiting for agent result)…', 'info', 4500);
              try {
                const waitFn = (window.phase3Ansible && typeof window.phase3Ansible.waitForJobDone === 'function')
                  ? window.phase3Ansible.waitForJobDone
                  : (window.pollJob ? window.pollJob : null);
                if (!waitFn) throw new Error('Job wait helper is not available');
                const res = await waitFn(String(jobId), 60000);
                const runSummary = (res.runs || []).map(r => `${r.agent_id}: ${r.status}${r.exit_code != null ? ` (exit ${r.exit_code})` : ''}${r.error ? ` — ${r.error}` : ''}`).join('\n');
                if (res.done && (res.runs || []).every(r => r.status === 'success')) {
                  showToast('Deployment completed successfully', 'success', 5000);
                } else if (res.done) {
                  showToast('Deployment finished with errors (open Details)', 'error', 6000);
                } else {
                  showToast('Deployment still running (check Jobs/logs)', 'info', 6000);
                }

                // Also open the details modal with targets + job outcome.
                const it2 = itemsById.get(String(id)) || it;
                if (it2) {
                  openSshKeyDeployApprovalModal({ ...it2, job: res, job_id: jobId, job_summary: runSummary });
                }
              } catch (err) {
                showToast(err.message || String(err), 'error', 6000);
              }
            } else {
              showToast('Approved', 'success');
            }

            maybeLoadSshKeyAdminQueue();
            loadAdminSshKeys();
          });
        });
        tbody.querySelectorAll('button[data-reject-id]').forEach(btn => {
          btn.addEventListener('click', async (e) => {
            e.preventDefault();
            const id = btn.getAttribute('data-reject-id');
            if (!id) return;
            const r2 = await fetch(`/sshkeys/admin/deploy-requests/${encodeURIComponent(id)}/reject`, { method: 'POST', credentials: 'include' });
            const raw = await r2.text();
            let data = null;
            try { data = raw ? JSON.parse(raw) : null; } catch { }
            if (!r2.ok) {
              const msg = (data && (data.detail || data.error)) ? (data.detail || data.error) : (raw || 'Reject failed');
              return showToast(msg, 'error');
            }
            showToast('Rejected', 'success');
            maybeLoadSshKeyAdminQueue();
            loadAdminSshKeys();
          });
        });
      } catch (e) {
        const indicator = document.getElementById('sshkeys-approval-indicator');
        if (indicator) indicator.style.display = 'none';
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;" class="status-error">${escapeHtml(e.message)}</td></tr>`;
      }
    }

    async function copyTextWithFallback(text, selectableEl) {
      const value = String(text || '');
      if (!value) return false;

      // Modern async clipboard API (requires secure context/permissions)
      try {
        if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
          await navigator.clipboard.writeText(value);
          return true;
        }
      } catch {}

      // Legacy fallback for locked-down environments
      try {
        const ta = document.createElement('textarea');
        ta.value = value;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.top = '-9999px';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        const ok = document.execCommand && document.execCommand('copy');
        ta.remove();
        if (ok) return true;
      } catch {}

      if (selectableEl && typeof selectableEl.focus === 'function') {
        selectableEl.focus();
        if (typeof selectableEl.select === 'function') selectableEl.select();
      }
      return false;
    }

    function initAuditDetailModalControls() {
      const modal = document.getElementById('audit-detail-modal');
      const closeBtn = document.getElementById('audit-detail-modal-close');
      const copyBtn = document.getElementById('audit-detail-modal-copy');
      const outEl = document.getElementById('audit-detail-modal-output');
      if (!modal) return;

      const close = () => {
        modal.classList.remove('open');
        modal.setAttribute('aria-hidden', 'true');
        modal.hidden = true;
      };

      closeBtn?.addEventListener('click', (e) => { e.preventDefault(); close(); });
      modal.addEventListener('click', (e) => { if (e.target && e.target.id === 'audit-detail-modal') close(); });
      document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && modal.classList.contains('open')) close(); });

      copyBtn?.addEventListener('click', async (e) => {
        e.preventDefault();
        const text = outEl ? (outEl.value || '') : '';
        const ok = await copyTextWithFallback(text, outEl);
        if (ok) {
          showToast('Copied', 'success');
        } else {
          showToast('Copy failed (clipboard blocked). Text selected—press Ctrl/Cmd+C.', 'error', 5000);
        }
      });
    }

    function initApprovalDetailModalControls() {
      const modal = document.getElementById('approval-detail-modal');
      const closeBtn = document.getElementById('approval-detail-modal-close');
      const copyBtn = document.getElementById('approval-detail-modal-copy');
      const outEl = document.getElementById('approval-detail-modal-output');
      if (!modal) return;

      const close = () => {
        modal.classList.remove('open');
        modal.setAttribute('aria-hidden', 'true');
        modal.hidden = true;
      };

      closeBtn?.addEventListener('click', (e) => { e.preventDefault(); close(); });
      modal.addEventListener('click', (e) => { if (e.target && e.target.id === 'approval-detail-modal') close(); });
      document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && modal.classList.contains('open')) close(); });

      copyBtn?.addEventListener('click', async (e) => {
        e.preventDefault();
        const text = outEl ? (outEl.value || '') : '';
        const ok = await copyTextWithFallback(text, outEl);
        if (ok) {
          showToast('Copied', 'success');
        } else {
          showToast('Copy failed (clipboard blocked). Text selected—press Ctrl/Cmd+C.', 'error', 5000);
        }
      });
    }

    function initFailedRunDetailModalControls() {
      const modal = document.getElementById('failed-run-detail-modal');
      const closeBtn = document.getElementById('failed-run-detail-modal-close');
      const copyBtn = document.getElementById('failed-run-detail-modal-copy');
      const outEl = document.getElementById('failed-run-detail-modal-output');
      const metaEl = document.getElementById('failed-run-detail-modal-meta');
      if (!modal || !outEl) return;

      const close = () => {
        modal.classList.remove('open');
        modal.setAttribute('aria-hidden', 'true');
        modal.hidden = true;
      };

      closeBtn?.addEventListener('click', (e) => { e.preventDefault(); close(); });
      modal.addEventListener('click', (e) => { if (e.target && e.target.id === 'failed-run-detail-modal') close(); });
      document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && modal.classList.contains('open')) close(); });

      copyBtn?.addEventListener('click', async (e) => {
        e.preventDefault();
        const text = outEl.value || '';
        const ok = await copyTextWithFallback(text, outEl);
        if (ok) {
          showToast('Copied', 'success');
        } else {
          showToast('Copy failed (clipboard blocked). Text selected—press Ctrl/Cmd+C.', 'error', 5000);
        }
      });

      window.openFailedRunDetailModal = (text, meta) => {
        outEl.value = text || '';
        if (metaEl) metaEl.textContent = meta || '';
        modal.hidden = false;
        modal.setAttribute('aria-hidden', 'false');
        modal.classList.add('open');
        setTimeout(() => { try { outEl.focus(); } catch { } }, 0);
      };
    }

    function initJobDetailModalControls() {
      const mod = window.fleetJobsUi;
      if (mod && typeof mod.initJobDetailModalControls === 'function') {
        return mod.initJobDetailModalControls(getQueueHealthCtx());
      }
    }

    function initApprovalsFilterControls() {
      const ids = ['approvals-filter-action', 'approvals-filter-requester', 'approvals-filter-age', 'approvals-filter-mode', 'approvals-filter-sort'];
      ids.forEach((id) => {
        const el = document.getElementById(id);
        if (!el) return;
        const evt = (id === 'approvals-filter-action' || id === 'approvals-filter-requester') ? 'input' : 'change';
        el.addEventListener(evt, () => { loadAdminApprovals(false); });
      });

      const dedupeKind = document.getElementById('dedupe-filter-kind');
      const dedupeMinutes = document.getElementById('dedupe-filter-minutes');
      dedupeKind?.addEventListener('input', () => { loadAdminNotificationDedupe(false); });
      dedupeMinutes?.addEventListener('change', () => { loadAdminNotificationDedupe(false); });
    }

    function initHostActionControls() {
      const mod = window.phase3HostActions;
      if (mod && typeof mod.initHostActionControls === 'function') {
        return mod.initHostActionControls({ showServerInfo, showTerminal, showUsers, showServices, showFirewall, showPackages });
      }
    }

    function initHostFirewallControls() {
      const mod = window.phase3HostWorkflows;
      if (mod && typeof mod.initHostFirewallControls === 'function') {
        return mod.initHostFirewallControls(getHostWorkflowsCtx());
      }
    }

    function initHostMetadataEditor() {
      const mod = window.phase3HostActions;
      if (mod && typeof mod.initHostMetadataEditor === 'function') {
        return mod.initHostMetadataEditor({
          getCurrentAgentId: () => currentAgentId,
          getCurrentPermissions: () => currentPermissions,
          onMetadataSaved: (updatedHost) => {
            if (!updatedHost || !updatedHost.agent_id) return;
            const idx = (allHosts || []).findIndex(h => h.agent_id === updatedHost.agent_id);
            if (idx >= 0) {
              const prev = allHosts[idx] || {};
              allHosts[idx] = { ...prev, hostname: updatedHost.hostname || prev.hostname, labels: updatedHost.labels || prev.labels || {} };
            }

            if (String(currentAgentId || '') === String(updatedHost.agent_id || '')) {
              const labelsEl = document.getElementById('server-info-labels');
              if (labelsEl) {
                const labels = (updatedHost.labels && typeof updatedHost.labels === 'object') ? updatedHost.labels : {};
                const envVars = (labels.env_vars && typeof labels.env_vars === 'object') ? labels.env_vars : {};
                const env = labels.env ? String(labels.env) : (envVars.env ? String(envVars.env) : '');
                const role = labels.role ? String(labels.role) : '';
                const team = labels.team ? String(labels.team) : '';
                const parts = [];
                if (env) parts.push(`<span class="label-badge">env: <code>${escapeHtml(env)}</code></span>`);
                if (role) parts.push(`<span class="label-badge">role: <code>${escapeHtml(role)}</code></span>`);
                if (team) parts.push(`<span class="label-badge">team: <code>${escapeHtml(team)}</code></span>`);
                labelsEl.innerHTML = parts.length ? parts.join('') : `<span class="label-badge">env: <code>n/a</code></span><span class="label-badge">role: <code>n/a</code></span>`;
              }

              const headerNameEl = document.getElementById('server-info-hostname');
              if (headerNameEl && updatedHost.hostname) headerNameEl.textContent = String(updatedHost.hostname);
              const hostActionsMod = window.phase3HostActions;
              if (hostActionsMod && typeof hostActionsMod.updateTerminalAccessIndicator === 'function') {
                hostActionsMod.updateTerminalAccessIndicator(updatedHost, currentPermissions);
              }
            }

            rebuildLabelFilterOptions(allHosts);
            applyHostFilters();
            void Promise.allSettled([
              loadHostsTable(),
              loadHosts(),
            ]);
          }
        });
      }
    }

    function initDiskCleanupControls() {
      const mod = window.phase3HostActions;
      if (mod && typeof mod.initDiskCleanupControls === 'function') {
        return mod.initDiskCleanupControls({
          getCurrentAgentId: () => currentAgentId,
        });
      }
    }

    function getSshUiCtx() {
      return {
        loadSshKeys,
        maybeLoadSshKeyAdminQueue,
        loadAdminSshKeys,
        loadAdminUsers,
        loadAdminAdSettings,
        saveAdminAdSettings,
        loadAdminOidcEvents,
        loadAdminApprovals,
        loadAdminNotificationDedupe,
        loadAdminAudit,
        setSshHostsPanelVisible,
        renderSshHostsList,
        getSshSelectedAgentIds,
        setSshSelectedAgentIds,
        getSshSelectedKeyId,
        loadSshKeyRequests,
        getAllHosts: () => allHosts,
      };
    }

    function initSshKeysControls() {
      const mod = window.phase3SshUi;
      if (mod && typeof mod.initSshKeysControls === 'function') {
        return mod.initSshKeysControls(getSshUiCtx());
      }
    }

    function getAnsibleCtx() {
      return {
        getAnsiblePlaybooks: () => ansiblePlaybooks,
        setAnsiblePlaybooks: (v) => { ansiblePlaybooks = Array.isArray(v) ? v : []; return ansiblePlaybooks; },
        getSelectedAgentIds: () => selectedAgentIds,
        getLastRenderedAgentIds: () => lastRenderedAgentIds,
        getCurrentAgentId: () => currentAgentId,
      };
    }

    function initAnsibleSection() {
      const mod = window.phase3Ansible;
      if (mod && typeof mod.initAnsibleSection === 'function') {
        return mod.initAnsibleSection(getAnsibleCtx());
      }
    }

    function getReportsCtx() {
      return { showToast };
    }

    function initReportsControls() {
      const mod = window.fleetReportsUi;
      if (mod && typeof mod.initReportsControls === 'function') {
        return mod.initReportsControls(getReportsCtx());
      }
    }

    function getUserManagementCtx() {
      return {
        getCurrentPermissions: () => currentPermissions || {},
        showToast,
      };
    }

    function initUserManagementControls() {
      const mod = window.fleetUserManagementUi;
      if (mod && typeof mod.initUserManagementControls === 'function') {
        return mod.initUserManagementControls(getUserManagementCtx());
      }
    }

    function getServiceManagementCtx() {
      return {
        getCurrentPermissions: () => currentPermissions || {},
        showToast,
      };
    }

    function initServiceManagementControls() {
      const mod = window.fleetServiceManagementUi;
      if (mod && typeof mod.initServiceManagementControls === 'function') {
        return mod.initServiceManagementControls(getServiceManagementCtx());
      }
    }

    function getFirewallManagementCtx() {
      return {
        getCurrentPermissions: () => currentPermissions || {},
        showToast,
      };
    }

    function initFirewallManagementControls() {
      const mod = window.fleetFirewallManagementUi;
      if (mod && typeof mod.initFirewallManagementControls === 'function') {
        return mod.initFirewallManagementControls(getFirewallManagementCtx());
      }
    }

// Load hosts on page load
    function safeInit(name, fn) {
      try { if (typeof fn === 'function') fn(); }
      catch (e) { console.error('[init failed]', name, e); }
    }

    async function bootUi() {
      // Load auth state first so header + MFA flow are not blocked by later init errors.
      await loadAuthInfo();

      const mfa = window.__mfa || null;
      const mfaPending = !!(mfa && (mfa.setup_required || mfa.verify_required));
      if (mfaPending) return;

      safeInit('initHostFilters', initHostFilters);
      safeInit('initReportsControls', initReportsControls);
      safeInit('initUserManagementControls', initUserManagementControls);
      safeInit('initServiceManagementControls', initServiceManagementControls);
      safeInit('initFirewallManagementControls', initFirewallManagementControls);
      safeInit('initFleetOverviewControls', initFleetOverviewControls);
      safeInit('initHostsTableControls', initHostsTableControls);
      safeInit('initCronjobsControls', initCronjobsControls);
      safeInit('initSshKeysControls', initSshKeysControls);
      safeInit('initLoadTimeframeControls', initLoadTimeframeControls);
      safeInit('initPackagesSearch', initPackagesSearch);
      safeInit('initAdminPanel', initAdminPanel);
      safeInit('initOidcMapPreview', initOidcMapPreview);
      safeInit('initThemeToggle', initThemeToggle);
      safeInit('initSettingsMenu', initSettingsMenu);
      safeInit('initHostActionControls', initHostActionControls);
      safeInit('initHostFirewallControls', initHostFirewallControls);
      safeInit('initHostMetadataEditor', initHostMetadataEditor);
      safeInit('initDiskCleanupControls', initDiskCleanupControls);
      safeInit('initAuditDetailModalControls', initAuditDetailModalControls);
      safeInit('initApprovalDetailModalControls', initApprovalDetailModalControls);
      safeInit('initFailedRunDetailModalControls', initFailedRunDetailModalControls);
      safeInit('initJobDetailModalControls', initJobDetailModalControls);
      safeInit('initApprovalsFilterControls', initApprovalsFilterControls);
    }

    bootUi().catch((e) => console.error('[bootUi failed]', e));
    safeInit('bindDiskCardClick', () => {
      const diskCard = document.getElementById('disk-card');
      if (!diskCard) return;
      diskCard.addEventListener('click', (e) => {
        e.preventDefault();
        if (!currentAgentId) return;
        openDiskModal(currentAgentId);
      });
    });
    safeInit('bindDiskModalClose', () => {
      document.getElementById('disk-modal-close')?.addEventListener('click', (e) => {
        e.preventDefault();
        if (typeof closeDiskModal === 'function') closeDiskModal();
      });
      document.getElementById('disk-modal')?.addEventListener('click', (e) => {
        if (e.target && e.target.id === 'disk-modal' && typeof closeDiskModal === 'function') closeDiskModal();
      });
    });
    safeInit('initTerminalOnce', initTerminalOnce);
    safeInit('attachTerminalInputHandlerOnce', attachTerminalInputHandlerOnce);
    safeInit('initTerminalPendingCmdButton', () => {
      const mod = window.fleetTerminalUi;
      if (mod && typeof mod.initTerminalPendingCmdButton === 'function') {
        return mod.initTerminalPendingCmdButton(getTerminalCtx());
      }
    });
    safeInit('initAnsibleSection', initAnsibleSection);
    safeInit('bindAnsibleOpenFallback', () => {
      const btn = document.getElementById('ansible-open');
      const sel = document.getElementById('ansible-playbook');
      const status = document.getElementById('ansible-status');
      if (!btn || btn.dataset.boundAnsibleOpenFallback === '1') return;
      btn.addEventListener('click', (e) => {
        const mod = window.phase3Ansible;
        if (!mod || typeof mod.openAnsibleModal !== 'function') return;
        e.preventDefault();
        const pb = sel ? (sel.value || '') : '';
        if (!pb) {
          if (status) status.textContent = 'Select playbook first.';
          return;
        }
        mod.openAnsibleModal(getAnsibleCtx(), pb);
      });
      btn.dataset.boundAnsibleOpenFallback = '1';
    });
    safeInit('initTimelineFilters', initTimelineFilters);

    safeInit('initCommonModalDismissHandlers', () => {
      const hostActionsMod = window.phase3HostActions;
      if (hostActionsMod && typeof hostActionsMod.initCommonModalDismissHandlers === 'function') {
        hostActionsMod.initCommonModalDismissHandlers({
          getCurrentMetricsAgentId: () => metricsLifecycleState.get('currentMetricsAgentId'),
          openDiskModal,
          closeDiskModal,
          closeServiceModal,
          closeUserModal,
        });
      }
    });
    const HOSTS_REFRESH_MS = 5000;
    let hostsRefreshTimer = null;

    function startHostRefresh() {
      if (hostsRefreshTimer) return;
      hostsRefreshTimer = setInterval(loadHosts, HOSTS_REFRESH_MS);
    }

    void loadHosts().catch((e) => {
      console.error('[loadHosts failed]', e);
      const hostsEl = document.getElementById('hosts');
      if (hostsEl) hostsEl.innerHTML = `<div class="error">Error loading hosts: ${escapeHtml(e?.message || String(e))}</div>`;
    });

    // Watchdog: never let hosts panel stay in perpetual loading state.
    setTimeout(() => {
      const hostsEl = document.getElementById('hosts');
      if (!hostsEl) return;
      const txt = (hostsEl.textContent || '').trim().toLowerCase();
      if (txt.includes('loading hosts')) {
        console.warn('[hosts-watchdog] still loading after 10s; forcing inline fallback');
        hostsEl.innerHTML = '<div class="error">Hosts view was stuck loading. Retrying…</div>';
        void loadHosts().catch((e) => {
          hostsEl.innerHTML = `<div class="error">Error loading hosts: ${escapeHtml(e?.message || String(e))}</div>`;
        });
      }
    }, 10000);

    void loadFleetOverview();
    void refreshApprovalsIndicator();
    startHostRefresh();
    setInterval(() => { void loadFleetOverview(false, true); }, 15000);
    setInterval(() => { void refreshApprovalsIndicator(); }, 60000);

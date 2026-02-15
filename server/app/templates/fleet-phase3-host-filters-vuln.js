(function (w) {
  function initHostFiltersVuln(ctx) {
    const api = ctx || {};
    const getState = typeof api.getState === 'function' ? api.getState : function () { return {}; };
    const setState = typeof api.setState === 'function' ? api.setState : function () { };
    const syncSelectionState = typeof api.syncSelectionState === 'function' ? api.syncSelectionState : function (_, v) { return v; };
    const applyHostFilters = typeof api.applyHostFilters === 'function' ? api.applyHostFilters : function () { };
    const pollJob = typeof api.pollJob === 'function' ? api.pollJob : async function () { return null; };
    const escapeHtml = typeof api.escapeHtml === 'function' ? api.escapeHtml : function (v) { return String(v || ''); };
    const matchesGlob = typeof api.matchesGlob === 'function' ? api.matchesGlob : function () { return false; };
    const setVulnOpen = typeof api.setVulnOpen === 'function' ? api.setVulnOpen : function () { };

    const cveEl = document.getElementById('vuln-cve');
    const pkgEl = document.getElementById('vuln-package');
    const verEl = document.getElementById('vuln-version');
    const applyBtn = document.getElementById('vuln-apply');
    const clearBtn = document.getElementById('vuln-clear');
    const statusEl = document.getElementById('vuln-status');
    const selectVisibleEl = document.getElementById('select-visible-hosts');
    const upgradeBtn = document.getElementById('upgrade-selected');
    const upgradeStatusEl = document.getElementById('upgrade-status');
    const cvePackagesPanel = document.getElementById('cve-packages-panel');
    const cvePackagesList = document.getElementById('cve-packages-list');
    const cvePlanSummaryEl = document.getElementById('cve-plan-summary');

    function st() { return getState() || {}; }
    function setPatch(patch) { setState(patch || {}); }

    function renderCvePackagesPanel(cve) {
      const state = st();
      if (!cvePackagesPanel || !cvePackagesList) return;
      if (!cve || !state.lastCveCheck || state.lastCveCheck.cve !== cve || !Array.isArray(state.lastCveUnionPackages) || state.lastCveUnionPackages.length === 0) {
        cvePackagesPanel.style.display = 'none';
        cvePackagesList.innerHTML = '';
        if (cvePlanSummaryEl) cvePlanSummaryEl.innerHTML = '';
        setPatch({ selectedCvePackages: new Set() });
        return;
      }

      cvePackagesPanel.style.display = 'block';
      const selected = (state.selectedCvePackages && state.selectedCvePackages.size)
        ? new Set(state.selectedCvePackages)
        : new Set(state.lastCveUnionPackages);
      setPatch({ selectedCvePackages: selected });

      cvePackagesList.innerHTML = state.lastCveUnionPackages.map(function (p) {
        const checked = selected.has(p);
        return '<label style="display:flex;gap:0.5rem;align-items:center;">' +
          '<input type="checkbox" class="cve-pkg-cb" data-pkg="' + escapeHtml(p) + '" ' + (checked ? 'checked' : '') + ' />' +
          '<span style="font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;font-size:0.9rem;">' + escapeHtml(p) + '</span>' +
          '</label>';
      }).join('');

      cvePackagesList.querySelectorAll('input.cve-pkg-cb[data-pkg]').forEach(function (cb) {
        cb.addEventListener('change', function () {
          const p = cb.getAttribute('data-pkg');
          if (!p) return;
          const cur = new Set((st().selectedCvePackages || new Set()));
          if (cb.checked) cur.add(p); else cur.delete(p);
          setPatch({ selectedCvePackages: cur });
          updateUpgradeControls();
        });
      });
    }

    function updateUpgradeControls() {
      const state = st();
      const pkgName = (pkgEl?.value || '').trim();
      const cve = (cveEl?.value || '').trim().toUpperCase();
      const totalSelected = (state.selectedAgentIds || new Set()).size;
      const lastRendered = Array.isArray(state.lastRenderedAgentIds) ? state.lastRenderedAgentIds : [];
      const selectedIds = state.selectedAgentIds || new Set();
      const visibleSelected = lastRendered.filter(function (aid) { return selectedIds.has(aid); }).length;

      const isCveMode = !!cve && state.lastCveCheck && state.lastCveCheck.cve === cve && Array.isArray(state.lastCveUnionPackages) && state.lastCveUnionPackages.length > 0;
      renderCvePackagesPanel(isCveMode ? cve : '');

      let effectiveTotalPkgs = 0;
      let effectiveHostsWithPkgs = 0;
      if (isCveMode && state.selectedCvePackages && state.selectedCvePackages.size > 0) {
        Array.from(selectedIds).forEach(function (aid) {
          const r = state.lastCveCheck?.resultsByAgentId?.[aid];
          const pk = Array.isArray(r?.packages) ? r.packages : [];
          const eff = pk.filter(function (p) { return state.selectedCvePackages.has(p); });
          if (eff.length > 0) {
            effectiveHostsWithPkgs += 1;
            effectiveTotalPkgs += eff.length;
          }
        });
      }

      const canRun = isCveMode
        ? (totalSelected > 0 && state.selectedCvePackages && state.selectedCvePackages.size > 0 && effectiveTotalPkgs > 0)
        : (totalSelected > 0 && !!pkgName);
      if (upgradeBtn) upgradeBtn.disabled = !canRun;

      if (cvePlanSummaryEl) {
        if (isCveMode) {
          const selectedPkgs = Array.from(state.selectedCvePackages || []).sort();
          const selectedHosts = Array.from(selectedIds || []);
          const rows = selectedHosts.map(function (aid) {
            const r = state.lastCveCheck?.resultsByAgentId?.[aid];
            const pk = Array.isArray(r?.packages) ? r.packages : [];
            const eff = pk.filter(function (p) { return state.selectedCvePackages.has(p); });
            return '<div style="display:flex;justify-content:space-between;gap:8px;"><span><code>' + escapeHtml(aid) + '</code></span><span>' + eff.length + ' pkg(s)</span></div>';
          }).join('');
          let html = '<div><b>Plan:</b> ' + selectedHosts.length + ' host(s), ' + selectedPkgs.length + ' package(s) selected.</div>' +
            '<div><b>Effective upgrades:</b> ' + effectiveHostsWithPkgs + '/' + selectedHosts.length + ' host(s), ' + effectiveTotalPkgs + ' package upgrade(s) total.</div>';
          if (selectedHosts.length > 0) html += '<details style="margin-top:4px"><summary>Per-host package counts</summary><div style="margin-top:4px">' + rows + '</div></details>';
          if (effectiveTotalPkgs === 0) html += '<div style="margin-top:4px;color:#fbbf24">No selected packages apply to the selected host(s).</div>';
          cvePlanSummaryEl.innerHTML = html;
        } else cvePlanSummaryEl.innerHTML = '';
      }

      if (upgradeStatusEl) {
        if (isCveMode) {
          upgradeStatusEl.textContent = 'Selected: ' + visibleSelected + ' visible / ' + totalSelected + ' total host(s). CVE: ' + cve + '. Packages selected: ' + ((state.selectedCvePackages && state.selectedCvePackages.size) ? state.selectedCvePackages.size : 0) + '.';
        } else if (pkgName) {
          upgradeStatusEl.textContent = 'Selected: ' + visibleSelected + ' visible / ' + totalSelected + ' total host(s). Package: ' + pkgName;
        } else if (cve) {
          upgradeStatusEl.textContent = 'Selected: ' + visibleSelected + ' visible / ' + totalSelected + ' total host(s). CVE: ' + cve + '. (Run CVE check to see affected packages.)';
        } else {
          upgradeStatusEl.textContent = 'Selected: ' + visibleSelected + ' visible / ' + totalSelected + ' total host(s). Enter a CVE or package name.';
        }
      }
    }

    async function applyVulnFilter() {
      const cve = (cveEl?.value || '').trim().toUpperCase();
      const name = (pkgEl?.value || '').trim();
      const version = (verEl?.value || '').trim();
      if (!cve && !name) {
        if (statusEl) statusEl.textContent = 'Enter a CVE or a package name.';
        setVulnOpen(true);
        return;
      }

      if (statusEl) statusEl.textContent = cve ? 'Running CVE check…' : 'Searching…';
      if (applyBtn) applyBtn.disabled = true;
      if (clearBtn) clearBtn.disabled = true;

      try {
        if (cve) {
          if (!/^CVE-\d{4}-\d{4,}$/i.test(cve)) throw new Error('Invalid CVE format. Example: CVE-2021-45105');
          const targets = (st().allHosts || []).map(function (h) { return h.agent_id; }).filter(Boolean);
          if (!targets.length) throw new Error('No hosts loaded');

          const resp0 = await fetch('/jobs/cve-check', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ agent_ids: targets, cve: cve }) });
          if (!resp0.ok) {
            let msg = resp0.statusText;
            try { const err = await resp0.json(); msg = err.detail || err.message || msg; } catch (_) { }
            throw new Error(msg);
          }
          const out = await resp0.json();
          const jobId = out.job_id;
          if (statusEl) statusEl.textContent = 'CVE check started (job_id: ' + jobId + '). Waiting…';

          const data = await pollJob(jobId, statusEl, 180000);
          const affectedIds = [];
          const resultsByAgentId = {};
          for (const r of (data?.runs || [])) {
            if (r.status !== 'success' || !r.stdout) continue;
            try {
              const j = JSON.parse(r.stdout);
              const affected = !!(j && j.affected === true);
              const pkgs = Array.isArray(j?.packages) ? j.packages.filter(Boolean) : [];
              resultsByAgentId[r.agent_id] = { affected: affected, packages: pkgs };
              if (affected) affectedIds.push(r.agent_id);
            } catch (_) { }
          }
          const union = new Set();
          affectedIds.forEach(function (aid) {
            const pk = Array.isArray(resultsByAgentId?.[aid]?.packages) ? resultsByAgentId[aid].packages : [];
            pk.forEach(function (p) { if (p) union.add(p); });
          });

          const unionPkgs = Array.from(union).sort();
          syncSelectionState('vulnFilteredAgentIds', affectedIds.length ? new Set(affectedIds) : null);
          setPatch({
            vulnFilteredAgentIds: affectedIds.length ? new Set(affectedIds) : null,
            lastCveCheck: { cve: cve, resultsByAgentId: resultsByAgentId },
            lastCveAffectedAgentIds: affectedIds,
            lastCveUnionPackages: unionPkgs,
            selectedCvePackages: new Set(unionPkgs),
          });
          if (statusEl) statusEl.textContent = 'CVE ' + cve + ': ' + affectedIds.length + '/' + targets.length + ' host(s) affected (online). Affected packages: ' + unionPkgs.length + '. ' + (affectedIds.length ? ('Showing ' + affectedIds.length + ' affected host(s) in the list.') : 'Showing all hosts (none affected).');
        } else {
          const params = new URLSearchParams({ name: name });
          if (version) params.set('version', version);
          const resp = await fetch('/search/packages?' + params.toString());
          if (!resp.ok) throw new Error(resp.statusText);
          const rows = await resp.json();
          const vulnSet = new Set((rows || []).map(function (r) { return r.agent_id; }));
          syncSelectionState('vulnFilteredAgentIds', vulnSet);
          setPatch({ vulnFilteredAgentIds: vulnSet, lastCveCheck: null });
          if (statusEl) statusEl.textContent = 'Package ' + name + ': ' + vulnSet.size + ' host(s) matched.';
        }

        if (clearBtn) clearBtn.disabled = false;
        const emptySel = new Set();
        syncSelectionState('selectedAgentIds', emptySel);
        setPatch({ selectedAgentIds: emptySel, lastPkgVerification: null });
        if (selectVisibleEl) selectVisibleEl.checked = false;
        applyHostFilters();
        setVulnOpen(true);
        updateUpgradeControls();
      } catch (e) {
        syncSelectionState('vulnFilteredAgentIds', null);
        setPatch({ vulnFilteredAgentIds: null });
        if (statusEl) statusEl.textContent = 'Error searching: ' + (e.message || e);
        applyHostFilters();
        setVulnOpen(true);
      } finally {
        if (applyBtn) applyBtn.disabled = false;
      }
    }

    function clearVulnFilter() {
      syncSelectionState('vulnFilteredAgentIds', null);
      if (statusEl) statusEl.textContent = '';
      if (clearBtn) clearBtn.disabled = true;
      if (cveEl) cveEl.value = '';
      if (pkgEl) pkgEl.value = '';
      if (verEl) verEl.value = '';
      const emptySel = new Set();
      syncSelectionState('selectedAgentIds', emptySel);
      setPatch({ selectedAgentIds: emptySel, lastPkgVerification: null, lastCveCheck: null, lastCveAffectedAgentIds: [], lastCveUnionPackages: [], selectedCvePackages: new Set() });
      if (selectVisibleEl) selectVisibleEl.checked = false;
      applyHostFilters();
      updateUpgradeControls();
    }

    let activeUpgradePoll = { cancelled: false, jobId: null };

    function summarizeRuns(runs, targets) {
      const byAgent = new Map();
      (runs || []).forEach(function (r) { byAgent.set(r.agent_id, r.status); });
      const statuses = targets.map(function (aid) { return byAgent.get(aid) || 'queued'; });
      const counts = statuses.reduce(function (acc, s) { acc[s] = (acc[s] || 0) + 1; return acc; }, {});
      const done = (counts.success || 0) + (counts.failed || 0);
      const total = targets.length;
      return { counts: counts, done: done, total: total, allDone: done === total };
    }

    async function pollUpgradeJob(jobId, targets, pkgName, statusNode) {
      if (activeUpgradePoll && activeUpgradePoll.jobId && activeUpgradePoll.jobId !== jobId) activeUpgradePoll.cancelled = true;
      activeUpgradePoll = { cancelled: false, jobId: jobId };
      const startedAt = Date.now();
      const timeoutMs = 10 * 60 * 1000;
      let intervalMs = 1000;

      while (Date.now() - startedAt < timeoutMs) {
        if (activeUpgradePoll.cancelled) return;
        try {
          const resp = await fetch('/jobs/' + encodeURIComponent(jobId));
          if (!resp.ok) throw new Error(resp.statusText);
          const data = await resp.json();
          const runs = data.runs || [];
          const summary = summarizeRuns(runs, targets);
          const c = summary.counts;
          const parts = [];
          if (c.queued) parts.push('queued: ' + c.queued);
          if (c.running) parts.push('running: ' + c.running);
          if (c.success) parts.push('success: ' + c.success);
          if (c.failed) parts.push('failed: ' + c.failed);
          const logsUrl = '/jobs/' + encodeURIComponent(jobId) + '/logs.zip';
          if (statusNode) statusNode.innerHTML = 'Upgrading ' + escapeHtml(String(pkgName)) + ' — ' + summary.done + '/' + summary.total + ' finished (' + escapeHtml(parts.join(', ')) + ') (job_id: <code>' + escapeHtml(jobId) + '</code>) <a href="' + logsUrl + '" target="_blank" rel="noopener noreferrer">logs.zip</a>';
          if (summary.allDone) {
            if (statusNode) {
              const byAgent = new Map();
              runs.forEach(function (r) { byAgent.set(r.agent_id, r); });
              const rowsHtml = targets.map(function (aid) {
                const r = byAgent.get(aid) || { status: 'queued' };
                const st = r.status || 'queued';
                const stdoutUrl = '/jobs/' + encodeURIComponent(jobId) + '/runs/' + encodeURIComponent(aid) + '/stdout.txt';
                const stderrUrl = '/jobs/' + encodeURIComponent(jobId) + '/runs/' + encodeURIComponent(aid) + '/stderr.txt';
                return '<tr><td><code>' + escapeHtml(aid) + '</code></td><td>' + escapeHtml(st) + '</td><td><a href="' + stdoutUrl + '" target="_blank" rel="noopener noreferrer">stdout</a></td><td><a href="' + stderrUrl + '" target="_blank" rel="noopener noreferrer">stderr</a></td></tr>';
              }).join('');
              statusNode.innerHTML = 'Upgrade finished for ' + escapeHtml(String(pkgName)) + '. success: ' + (c.success || 0) + ', failed: ' + (c.failed || 0) + '. (job_id: <code>' + escapeHtml(jobId) + '</code>) <a href="' + logsUrl + '" target="_blank" rel="noopener noreferrer">logs.zip</a>' +
                '<details style="margin-top:6px"><summary>Per-host logs</summary><div style="overflow:auto; max-height:220px; border:1px solid #333; padding:6px; margin-top:6px"><table style="width:100%; border-collapse:collapse"><thead><tr><th align="left">Host</th><th align="left">Status</th><th align="left">stdout</th><th align="left">stderr</th></tr></thead><tbody>' + rowsHtml + '</tbody></table></div></details>';
            }
            return;
          }
          if (Date.now() - startedAt > 15000) intervalMs = 2000;
        } catch (e) {
          if (statusNode) statusNode.textContent = 'Checking job status failed: ' + (e.message || e) + ' (job_id: ' + jobId + ')';
        }
        await new Promise(function (r) { setTimeout(r, intervalMs); });
      }
      if (statusNode) statusNode.textContent = 'Timed out waiting for upgrade to finish (job_id: ' + jobId + ').';
    }

    async function verifyPackageVersions(targets, pkgName, vulnVersion, statusNode) {
      try {
        const resp = await fetch('/jobs/pkg-query', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ agent_ids: targets, packages: [pkgName] }) });
        if (!resp.ok) throw new Error(resp.statusText);
        const out = await resp.json();
        const jobId = out.job_id;
        const queryTargets = out.targets || targets;
        const startedAt = Date.now();
        const timeoutMs = 2 * 60 * 1000;
        let intervalMs = 500;

        while (Date.now() - startedAt < timeoutMs) {
          const s = await fetch('/jobs/' + encodeURIComponent(jobId));
          if (!s.ok) throw new Error(s.statusText);
          const data = await s.json();
          const runs = data.runs || [];
          const byAgent = new Map();
          runs.forEach(function (r) { byAgent.set(r.agent_id, r); });
          const done = queryTargets.filter(function (aid) {
            const r = byAgent.get(aid);
            return r && (r.status === 'success' || r.status === 'failed');
          }).length;
          if (statusNode) statusNode.textContent = 'Verifying ' + pkgName + ' version — ' + done + '/' + queryTargets.length + ' hosts checked…';

          if (done === queryTargets.length) {
            const rows = queryTargets.map(function (aid) {
              const r = byAgent.get(aid);
              if (!r || r.status !== 'success' || !r.stdout) return { aid: aid, ok: false, version: null };
              try {
                const parsed = JSON.parse(r.stdout);
                const pkg = (parsed.packages || [])[0];
                return { aid: aid, ok: true, version: (pkg && pkg.found) ? pkg.version : null };
              } catch (_) { return { aid: aid, ok: false, version: null }; }
            });

            const resultsByAgentId = {};
            rows.forEach(function (x) {
              const found = !!(x.ok && x.version);
              let status = 'unknown';
              if (!x.ok) status = 'unknown';
              else if (!found) status = 'not-installed';
              else if (vulnVersion && matchesGlob(x.version, vulnVersion)) status = 'vulnerable';
              else if (vulnVersion && !matchesGlob(x.version, vulnVersion)) status = 'upgraded';
              else status = 'installed';
              resultsByAgentId[x.aid] = { ok: x.ok, found: found, version: x.version, status: status };
            });
            setPatch({ lastPkgVerification: { packageName: pkgName, vulnVersion: vulnVersion || '', resultsByAgentId: resultsByAgentId } });
            applyHostFilters();
            const stillVuln = vulnVersion
              ? rows.filter(function (x) { return x.ok && x.version && matchesGlob(x.version, vulnVersion); }).map(function (x) { return x.aid; })
              : [];
            const upgraded = vulnVersion
              ? rows.filter(function (x) { return x.ok && x.version && !matchesGlob(x.version, vulnVersion); }).map(function (x) { return x.aid; })
              : rows.filter(function (x) { return x.ok; }).map(function (x) { return x.aid; });
            if (statusNode) {
              if (vulnVersion) statusNode.textContent = 'Verified ' + pkgName + '. Upgraded: ' + upgraded.length + '/' + rows.length + '. Still vulnerable (= ' + vulnVersion + '): ' + stillVuln.length + '.';
              else statusNode.textContent = 'Verified ' + pkgName + ' installed versions for ' + rows.length + ' host(s). (Provide vulnerable version to auto-classify).';
            }
            return;
          }

          await new Promise(function (r) { setTimeout(r, intervalMs); });
          if (Date.now() - startedAt > 10000) intervalMs = 1000;
        }
        if (statusNode) statusNode.textContent = 'Timed out verifying installed version of ' + pkgName + '.';
      } catch (e) {
        if (statusNode) statusNode.textContent = 'Verification failed: ' + (e.message || e);
      }
    }

    async function refreshPackageUpdateCache(targets, statusNode) {
      const ids = Array.isArray(targets) ? targets.filter(Boolean) : [];
      if (!ids.length) return;
      const doWait = ids.length <= 20;

      let done = 0;
      let okCount = 0;
      const total = ids.length;

      const setProgress = () => {
        if (!statusNode) return;
        const mode = doWait ? 'Refreshing update cache' : 'Queueing update cache refresh';
        statusNode.textContent = `${mode}: ${done}/${total} hosts (${okCount} ok)`;
      };
      setProgress();

      const work = ids.map(async function (aid) {
        const url = '/hosts/' + encodeURIComponent(aid) + '/packages/refresh?wait=' + (doWait ? 'true' : 'false');
        try {
          const r = await fetch(url, { method: 'POST' });
          if (r.ok) okCount += 1;
        } catch (_) { }
        done += 1;
        setProgress();
      });

      try {
        await Promise.allSettled(work);
      } catch (_) { }

      if (statusNode) {
        if (doWait) statusNode.textContent = `Update cache refreshed on ${okCount}/${total} hosts.`;
        else statusNode.textContent = `Refresh queued for ${okCount}/${total} hosts (background).`;
      }
    }

    async function upgradeSelected() {
      const pkgName = (pkgEl?.value || '').trim();
      const vulnVersion = (verEl?.value || '').trim();
      const cve = (cveEl?.value || '').trim().toUpperCase();
      const state = st();
      const agentIds = Array.from(state.selectedAgentIds || new Set());
      if (agentIds.length === 0) {
        if (upgradeStatusEl) upgradeStatusEl.textContent = 'Select at least one host.';
        setVulnOpen(true);
        return;
      }

      const isCveMode = !!cve && state.lastCveCheck && state.lastCveCheck.cve === cve && state.selectedCvePackages && state.selectedCvePackages.size > 0;
      let packagesByAgent = null;
      if (isCveMode) {
        packagesByAgent = {};
        for (const aid of agentIds) {
          const r = state.lastCveCheck?.resultsByAgentId?.[aid];
          const pk = Array.isArray(r?.packages) ? r.packages : [];
          const filtered = pk.filter(function (p) { return state.selectedCvePackages.has(p); });
          if (filtered.length) packagesByAgent[aid] = filtered;
        }
        if (Object.keys(packagesByAgent).length === 0) {
          if (upgradeStatusEl) upgradeStatusEl.textContent = 'No selected packages apply to the selected hosts.';
          return;
        }
      }

      if (!isCveMode && !pkgName) {
        if (upgradeStatusEl) upgradeStatusEl.textContent = 'Enter a package name (or run a CVE check to populate affected packages).';
        setVulnOpen(true);
        return;
      }

      if (upgradeStatusEl) {
        upgradeStatusEl.textContent = isCveMode
          ? 'Starting CVE upgrade on ' + agentIds.length + ' host(s)…'
          : 'Starting upgrade of ' + pkgName + ' on ' + agentIds.length + ' host(s)…';
      }
      if (upgradeBtn) upgradeBtn.disabled = true;

      try {
        const body = isCveMode
          ? { agent_ids: agentIds, packages_by_agent: packagesByAgent }
          : { agent_ids: agentIds, packages: [pkgName] };

        const resp = await fetch('/jobs/pkg-upgrade', {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
        });
        if (!resp.ok) {
          let msg = resp.statusText;
          try { const err = await resp.json(); msg = err.detail || err.message || msg; } catch (_) { }
          throw new Error(msg);
        }
        const out = await resp.json();
        const jobId = out.job_id;
        const targets = out.targets || agentIds;

        if (upgradeStatusEl) {
          const logsUrl = '/jobs/' + encodeURIComponent(jobId) + '/logs.zip';
          upgradeStatusEl.innerHTML = 'Upgrade job started (job_id: <code>' + escapeHtml(jobId) + '</code>). <a href="' + logsUrl + '" target="_blank" rel="noopener noreferrer">Download logs.zip</a>. Waiting…';
        }

        await pollUpgradeJob(jobId, targets, isCveMode ? 'cve' : pkgName, upgradeStatusEl);

        if (!isCveMode) {
          if (upgradeStatusEl) upgradeStatusEl.textContent = 'Upgrade finished. Verifying installed version of ' + pkgName + '…';
          await verifyPackageVersions(targets, pkgName, vulnVersion, upgradeStatusEl);
          await refreshPackageUpdateCache(targets, upgradeStatusEl);
          // Re-apply package vulnerability search so stale update rows disappear quickly.
          await applyVulnFilter();
        } else {
          await refreshPackageUpdateCache(targets, upgradeStatusEl);
          const prevCve = state.lastCveCheck?.cve || cve;
          setPatch({ lastCveUnionPackages: [], selectedCvePackages: new Set() });
          updateUpgradeControls();
          if (upgradeStatusEl) {
            const rerunId = 'rerun-cve-' + jobId;
            upgradeStatusEl.innerHTML = 'Upgrade finished. <a href="/jobs/' + encodeURIComponent(jobId) + '/logs.zip" target="_blank" rel="noopener noreferrer">Download logs.zip</a>. <button id="' + rerunId + '" class="btn btn-sm" type="button" style="margin-left:6px">Re-run CVE check</button>';
            setTimeout(function () {
              const btn = document.getElementById(rerunId);
              if (!btn) return;
              btn.onclick = async function () {
                try {
                  if (cveEl && prevCve) cveEl.value = prevCve;
                  await applyVulnFilter();
                } catch (e2) {
                  upgradeStatusEl.textContent = 'Re-run failed: ' + (e2.message || e2);
                }
              };
            }, 0);
          }
        }
      } catch (e) {
        if (upgradeStatusEl) upgradeStatusEl.textContent = 'Upgrade failed: ' + (e.message || e);
      } finally {
        updateUpgradeControls();
      }
    }

    applyBtn?.addEventListener('click', function (e) { e.preventDefault(); applyVulnFilter(); });
    clearBtn?.addEventListener('click', function (e) { e.preventDefault(); clearVulnFilter(); });
    upgradeBtn?.addEventListener('click', function (e) { e.preventDefault(); upgradeSelected(); });
    pkgEl?.addEventListener('input', function () { setPatch({ lastPkgVerification: null }); updateUpgradeControls(); applyHostFilters(); });
    cveEl?.addEventListener('input', function () { setPatch({ lastPkgVerification: null }); updateUpgradeControls(); applyHostFilters(); });

    updateUpgradeControls();

    return {
      updateUpgradeControls: updateUpgradeControls,
      applyVulnFilter: applyVulnFilter,
      clearVulnFilter: clearVulnFilter,
      upgradeSelected: upgradeSelected,
    };
  }

  w.phase3HostFiltersVuln = {
    initHostFiltersVuln: initHostFiltersVuln,
  };
})(window);

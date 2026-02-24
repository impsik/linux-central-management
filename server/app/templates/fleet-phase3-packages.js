(function (w) {
  function getState(ctx) {
    return (ctx && typeof ctx.getState === 'function') ? ctx.getState() : {};
  }

  function setState(ctx, patch) {
    if (!ctx || typeof ctx.setState !== 'function') return;
    ctx.setState(patch || {});
  }

  function initPackagesSearch(ctx) {
    const el = document.getElementById('packages-search');
    const checkBtn = document.getElementById('packages-check-updates');
    const clearBtn = document.getElementById('packages-search-clear');
    const updatesOnlyEl = document.getElementById('packages-updates-only');
    const cvesOnlyEl = document.getElementById('packages-cves-only');
    const selectVisibleEl = document.getElementById('select-visible-packages');
    const interactiveEl = document.getElementById('pkg-interactive-terminal');
    const upgradeBtn = document.getElementById('pkg-upgrade-selected');
    const reinstallBtn = document.getElementById('pkg-reinstall-selected');
    const statusEl = document.getElementById('pkg-actions-status');
    if (!el) return;

    function syncClearVisibility() {
      if (clearBtn) clearBtn.style.display = el.value ? 'inline-flex' : 'none';
    }

    function updatePkgActionControls() {
      const st = getState(ctx);
      const totalSelected = (st.selectedPackages instanceof Set) ? st.selectedPackages.size : 0;
      if (reinstallBtn) reinstallBtn.disabled = totalSelected === 0;
      if (upgradeBtn) upgradeBtn.disabled = totalSelected === 0;
      if (statusEl) statusEl.textContent = totalSelected ? `Selected: ${totalSelected} package(s).` : '';
    }

    el.addEventListener('input', () => {
      const st = getState(ctx);
      setState(ctx, { packagesSearchQuery: el.value || '' });
      syncClearVisibility();
      if (st.packagesSearchTimer) clearTimeout(st.packagesSearchTimer);
      const timer = setTimeout(() => {
        const s2 = getState(ctx);
        if (s2.currentAgentId && document.getElementById('packages-tab')?.classList.contains('active')) {
          void loadPackages(ctx, s2.currentAgentId);
        }
      }, 250);
      setState(ctx, { packagesSearchTimer: timer });
    });

    clearBtn?.addEventListener('click', () => {
      el.value = '';
      const st = getState(ctx);
      setState(ctx, { packagesSearchQuery: '' });
      syncClearVisibility();
      if (st.packagesSearchTimer) clearTimeout(st.packagesSearchTimer);
      if (st.currentAgentId && document.getElementById('packages-tab')?.classList.contains('active')) {
        void loadPackages(ctx, st.currentAgentId);
      }
    });

    syncClearVisibility();

    updatesOnlyEl?.addEventListener('change', () => {
      const st = getState(ctx);
      setState(ctx, { packagesUpdatesOnly: !!updatesOnlyEl.checked, currentPackageName: null });
      const infoEl = document.getElementById('package-info');
      if (infoEl) infoEl.innerHTML = '';
      if (st.currentAgentId && document.getElementById('packages-tab')?.classList.contains('active')) {
        void loadPackages(ctx, st.currentAgentId);
      }
    });

    cvesOnlyEl?.addEventListener('change', () => {
      const st = getState(ctx);
      setState(ctx, { packagesCvesOnly: !!cvesOnlyEl.checked, currentPackageName: null });
      const infoEl = document.getElementById('package-info');
      if (infoEl) infoEl.innerHTML = '';
      if (st.currentAgentId && document.getElementById('packages-tab')?.classList.contains('active')) {
        void loadPackages(ctx, st.currentAgentId);
      }
    });

    interactiveEl?.addEventListener('change', () => {
      const st = getState(ctx);
      setState(ctx, { pkgInteractiveTerminal: !!interactiveEl.checked });
      if (statusEl && !!interactiveEl.checked) statusEl.textContent = 'Interactive mode enabled.';
      else if (statusEl && !(st.selectedPackages instanceof Set && st.selectedPackages.size)) statusEl.textContent = '';
    });

    selectVisibleEl?.addEventListener('change', () => {
      let selected = new Set();
      if (selectVisibleEl.checked) {
        document.querySelectorAll('.package-checkbox[data-pkg]').forEach(cb => {
          const name = cb.getAttribute('data-pkg');
          if (!name) return;
          cb.checked = true;
          selected.add(name);
        });
      } else {
        document.querySelectorAll('.package-checkbox[data-pkg]').forEach(cb => { cb.checked = false; });
      }
      setState(ctx, { selectedPackages: selected });
      updatePkgActionControls();
    });

    checkBtn?.addEventListener('click', async (e) => {
      e.preventDefault();
      const st = getState(ctx);
      if (!st.currentAgentId) return;
      try {
        if (statusEl) statusEl.textContent = 'Checking updates…';
        const resp = await fetch(`/hosts/${st.currentAgentId}/packages/check-updates?refresh=true&wait=false`, { method: 'POST' });
        if (!resp.ok) throw new Error(resp.statusText);
        const out = await resp.json();
        await w.pollJob(out.job_id, statusEl, 180000);
        await loadPackages(ctx, st.currentAgentId);
      } catch (e2) {
        if (statusEl) statusEl.textContent = `Update check error: ${e2.message || e2}`;
      }
    });

    async function runPackageAction(action) {
      const st = getState(ctx);
      if (!st.currentAgentId) return;
      const selected = (st.selectedPackages instanceof Set) ? Array.from(st.selectedPackages) : [];
      if (!selected.length) {
        if (statusEl) statusEl.textContent = 'Select at least one package.';
        return;
      }

      try {
        if (st.pkgInteractiveTerminal && ctx && typeof ctx.runInteractivePackageCommand === 'function') {
          const ok = ctx.runInteractivePackageCommand(action, selected);
          if (ok) {
            if (statusEl) statusEl.textContent = `Interactive ${action} command sent to terminal.`;
            return;
          }
        }

        if (statusEl) statusEl.textContent = `${action} in progress…`;
        const r = await fetch(`/hosts/${encodeURIComponent(st.currentAgentId)}/packages/action`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ action, packages: selected }),
        });
        const raw = await r.text();
        let d = null; try { d = raw ? JSON.parse(raw) : null; } catch {}
        if (!r.ok) throw new Error((d && (d.detail || d.error)) || raw || `${action} failed (${r.status})`);
        await w.pollJob((d && d.job_id) || '', statusEl, 180000);

        // Refresh installed package inventory first (HostPackage.version), then update metadata.
        try {
          if (statusEl) statusEl.textContent = 'Refreshing package inventory…';
          const inv = await fetch(`/hosts/${encodeURIComponent(st.currentAgentId)}/packages/refresh?wait=false`, { method: 'POST', credentials: 'include' });
          const invRaw = await inv.text();
          let invData = null; try { invData = invRaw ? JSON.parse(invRaw) : null; } catch {}
          if (inv.ok && invData && invData.job_id) {
            await w.pollJob(invData.job_id, statusEl, 180000);
          }

          if (statusEl) statusEl.textContent = 'Refreshing package update state…';
          const r2 = await fetch(`/hosts/${encodeURIComponent(st.currentAgentId)}/packages/check-updates?refresh=true&wait=false`, { method: 'POST', credentials: 'include' });
          const raw2 = await r2.text();
          let d2 = null; try { d2 = raw2 ? JSON.parse(raw2) : null; } catch {}
          if (r2.ok && d2 && d2.job_id) {
            await w.pollJob(d2.job_id, statusEl, 180000);
          }
        } catch (_) {
          // Best-effort only; package action already succeeded.
        }

        setState(ctx, { selectedPackages: new Set() });
        const sel = document.getElementById('select-visible-packages');
        if (sel) sel.checked = false;
        await loadPackages(ctx, st.currentAgentId);

        // One delayed refresh to absorb any late-arriving inventory/update events.
        setTimeout(() => {
          const st3 = getState(ctx);
          if (st3.currentAgentId === st.currentAgentId && document.getElementById('packages-tab')?.classList.contains('active')) {
            void loadPackages(ctx, st.currentAgentId);
          }
        }, 1500);
      } catch (err) {
        if (statusEl) statusEl.textContent = `${action} failed: ${err.message || err}`;
      }
    }

    upgradeBtn?.addEventListener('click', (e) => { e.preventDefault(); void runPackageAction('upgrade'); });
    reinstallBtn?.addEventListener('click', (e) => { e.preventDefault(); void runPackageAction('reinstall'); });

    w.__updatePkgActionControls = updatePkgActionControls;
    updatePkgActionControls();
  }

  async function loadPackages(ctx, agentId) {
    const listEl = document.getElementById('packages-list');
    const metaEl = document.getElementById('packages-meta');
    const infoEl = document.getElementById('package-info');
    if (!listEl || !metaEl || !infoEl) return;

    const st = getState(ctx);
    listEl.innerHTML = '<div class="loading">Loading packages...</div>';
    metaEl.textContent = '';

    try {
      const q = (st.packagesSearchQuery || '').trim();
      const params = new URLSearchParams();
      if (q) params.set('search', q);
      if (st.packagesUpdatesOnly) params.set('upgradable_only', 'true');
      params.set('limit', '500');
      const resp = await fetch(`/hosts/${agentId}/packages?${params.toString()}`);
      if (!resp.ok) throw new Error(resp.statusText);

      const data = await resp.json();
      let pkgs = data.packages || [];
      // Defensive client-side filter: in "Updates only", hide rows where installed==candidate.
      if (st.packagesUpdatesOnly) {
        pkgs = pkgs.filter((p) => {
          const cand = (p && p.candidate_version != null) ? String(p.candidate_version).trim() : '';
          const inst = (p && p.version != null) ? String(p.version).trim() : '';
          return !!cand && cand !== inst;
        });
      }
      if (st.packagesCvesOnly) {
        pkgs = pkgs.filter((p) => Array.isArray(p && p.cves) && p.cves.length > 0);
      }
      const total = data.total ?? pkgs.length;
      const collectedAt = data.collected_at;
      const updatesCheckedAt = data.updates_checked_at;
      w.__lastPackagesList = pkgs;

      metaEl.textContent = `Showing ${pkgs.length} of ${total}${collectedAt ? ` (inventory: ${new Date(collectedAt).toLocaleString()})` : ''}${updatesCheckedAt ? ` • updates checked: ${new Date(updatesCheckedAt).toLocaleString()}` : ''}.`;

      const selected = (st.selectedPackages instanceof Set) ? st.selectedPackages : new Set();
      if (!pkgs.length) {
        listEl.innerHTML = '<div class="empty-state">No packages match your search</div>';
        return;
      }

      listEl.innerHTML = pkgs.map(p => {
        const name = w.escapeHtml(p.name || '');
        const version = w.escapeHtml(p.version || '');
        const arch = w.escapeHtml(p.arch || '');
        const isActive = st.currentPackageName === p.name;
        const up = !!p.update_available;
        const cand = p.candidate_version ? w.escapeHtml(p.candidate_version) : '';
        const checked = selected.has(p.name);
        const cveCount = Array.isArray(p.cves) ? p.cves.length : 0;
        return `
          <div class="package-card ${isActive ? 'active' : ''} ${up ? 'upgradable' : ''}" data-pkg="${name}">
            <div class="package-select-wrap">
              <input class="package-checkbox" type="checkbox" data-pkg="${name}" ${checked ? 'checked' : ''} />
              <div style="min-width:0;">
                <div class="package-name">${name}${up ? `<span class="pkg-up-arrow">↑</span>` : ''}${cveCount ? `<button type="button" class="btn" style="margin-left:0.4rem;padding:0.08rem 0.35rem;font-size:0.72rem;line-height:1.2;vertical-align:middle;" title="${cveCount} linked CVE(s)">CVE ${cveCount}</button>` : ''}</div>
                <div class="package-meta">${version}${cand ? ` → ${cand}` : ''}${arch ? ` • ${arch}` : ''}</div>
              </div>
            </div>
          </div>
        `;
      }).join('');

      document.querySelectorAll('.package-card[data-pkg]').forEach(card => {
        card.addEventListener('click', (e) => {
          e.preventDefault();
          const pkgName = card.getAttribute('data-pkg');
          if (!pkgName) return;
          void selectPackage(ctx, pkgName);
        });
      });

      document.querySelectorAll('.package-checkbox[data-pkg]').forEach(cb => {
        cb.addEventListener('click', (e) => e.stopPropagation());
        cb.addEventListener('change', (e) => {
          e.stopPropagation();
          const name = cb.getAttribute('data-pkg');
          if (!name) return;
          const st2 = getState(ctx);
          const next = (st2.selectedPackages instanceof Set) ? new Set(st2.selectedPackages) : new Set();
          if (cb.checked) next.add(name); else next.delete(name);
          setState(ctx, { selectedPackages: next });
          if (w.__updatePkgActionControls) w.__updatePkgActionControls(pkgs);
        });
      });

      if (w.__updatePkgActionControls) w.__updatePkgActionControls(pkgs);
    } catch (e) {
      listEl.innerHTML = `<div class="error">Error loading packages: ${w.escapeHtml(e.message || String(e))}</div>`;
    }
  }

  async function refreshPackagesNow(ctx, agentId) {
    const statusEl = document.getElementById('pkg-actions-status');
    try {
      if (statusEl) statusEl.textContent = 'Refreshing package inventory…';
      const resp = await fetch(`/hosts/${encodeURIComponent(agentId)}/packages/refresh?wait=false`, { method: 'POST' });
      if (!resp.ok) throw new Error(resp.statusText);
      const out = await resp.json();
      await w.pollJob(out.job_id, statusEl, 120000);
      const st = getState(ctx);
      if (document.getElementById('packages-tab')?.classList.contains('active') && st.currentAgentId === agentId) {
        if (statusEl) statusEl.textContent = 'Package inventory refreshed.';
        await loadPackages(ctx, agentId);
      }
    } catch (e) {
      if (statusEl) statusEl.textContent = `Package refresh failed: ${e.message || e}`;
    }
  }

  async function selectPackage(ctx, pkgName) {
    const st = getState(ctx);
    if (!st.currentAgentId) return;
    setState(ctx, { currentPackageName: pkgName });
    document.querySelectorAll('.package-card').forEach(el => {
      el.classList.toggle('active', el.getAttribute('data-pkg') === pkgName);
    });
    await loadPackageInfo(ctx, st.currentAgentId, pkgName);
  }

  async function loadPackageInfo(ctx, agentId, pkgName) {
    const infoEl = document.getElementById('package-info');
    if (!infoEl) return;
    infoEl.innerHTML = `<div class="loading">Loading package info for <code>${w.escapeHtml(pkgName)}</code>…</div>`;
    try {
      const resp = await fetch(`/hosts/${agentId}/packages/${encodeURIComponent(pkgName)}/info`);
      if (!resp.ok) throw new Error(resp.statusText);
      const data = await resp.json();
      const name = w.escapeHtml(data.name || pkgName);
      const installed = data.installed_version ? `<code>${w.escapeHtml(data.installed_version)}</code>` : '<code>not installed</code>';
      const candidate = data.candidate_version ? `<code>${w.escapeHtml(data.candidate_version)}</code>` : '<code>n/a</code>';
      const summary = w.escapeHtml(data.summary || '');
      const desc = w.escapeHtml(data.description || '');
      infoEl.innerHTML = `<h3>${name}</h3><p>${summary}</p><div>Installed: ${installed}</div><div><b>Candidate:</b> <b>${candidate}</b></div><pre>${desc}</pre>`;
    } catch (e) {
      infoEl.innerHTML = `<div class="error">${w.escapeHtml(e.message || String(e))}</div>`;
    }
  }

  w.phase3Packages = {
    initPackagesSearch,
    loadPackages,
    refreshPackagesNow,
    selectPackage,
    loadPackageInfo,
  };
})(window);

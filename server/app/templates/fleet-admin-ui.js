(function () {
  'use strict';

  function bind(ctx) {
    const setTableState = ctx.setTableState;
    const formatShortTime = ctx.formatShortTime;
    const safeJsonPreview = ctx.safeJsonPreview;
    const escapeHtml = ctx.escapeHtml;
    const showToast = ctx.showToast;
    const getCookie = ctx.getCookie;
    const currentPermissions = ctx.getCurrentPermissions();
    const currentUsername = ctx.getCurrentUsername();
    const adminUsername = ctx.getAdminUsername();
    const approvalActionFeedback = ctx.getApprovalActionFeedback();

    async function loadAdminAudit(showToastOnManual = false) {
      const tbody = document.getElementById('admin-audit-table');
      const statusEl = document.getElementById('admin-audit-status');
      if (!tbody) return;

      const action = (document.getElementById('audit-filter-action')?.value || '').trim();
      const actor = (document.getElementById('audit-filter-actor')?.value || '').trim();

      try {
        setTableState(tbody, 6, 'loading', 'Loading…');
        if (statusEl) statusEl.textContent = '';

        const qs = new URLSearchParams();
        if (action) qs.set('action', action);
        if (actor) qs.set('actor', actor);
        qs.set('limit', '200');

        const r = await fetch(`/audit?${qs.toString()}`, { credentials: 'include' });
        const raw = await r.text();
        let d = null; try { d = raw ? JSON.parse(raw) : null; } catch {}
        if (!r.ok) throw new Error((d && (d.detail || d.error)) || raw || `audit fetch failed (${r.status})`);

        const items = (d && d.items) ? d.items : [];
        if (!items.length) {
          setTableState(tbody, 6, 'empty', 'No events');
          return;
        }
        tbody.innerHTML = '';
        for (const ev of items) {
          const tr = document.createElement('tr');
          const when = formatShortTime(ev.created_at || '');
          const who = String(ev.actor || '');
          const actionName = String(ev.action || '');
          const target = (ev.target_type || ev.target_name) ? `${String(ev.target_type||'')}:${String(ev.target_name||'')}` : '';
          const ip = String(ev.ip || '');
          const meta = safeJsonPreview(ev.meta || {}, 160);
          tr.innerHTML = `
            <td class="status-muted">${escapeHtml(when)}</td>
            <td><a href="#" data-audit-id="${escapeHtml(String(ev.id||''))}" style="text-decoration:underline;color:inherit;"><code>${escapeHtml(actionName)}</code></a></td>
            <td>${escapeHtml(who)}</td>
            <td class="status-muted">${escapeHtml(target)}</td>
            <td class="status-muted"><code>${escapeHtml(ip)}</code></td>
            <td class="status-muted"><code>${escapeHtml(meta)}</code></td>
          `;
          tbody.appendChild(tr);
        }

        tbody.querySelectorAll('a[data-audit-id]').forEach(a => {
          a.addEventListener('click', async (e) => {
            e.preventDefault();
            const id = a.getAttribute('data-audit-id') || '';
            if (!id) return;
            try {
              const r2 = await fetch(`/audit/${encodeURIComponent(id)}`, { credentials: 'include' });
              const raw2 = await r2.text();
              let d2 = null; try { d2 = raw2 ? JSON.parse(raw2) : null; } catch {}
              if (!r2.ok) throw new Error((d2 && (d2.detail||d2.error)) || raw2 || 'Audit event load failed');

              const pretty = JSON.stringify(d2.meta || {}, null, 2);

              // Show in a large, copyable modal instead of alert().
              const modal = document.getElementById('audit-detail-modal');
              const titleEl = document.getElementById('audit-detail-modal-title');
              const outEl = document.getElementById('audit-detail-modal-output');
              const metaEl = document.getElementById('audit-detail-modal-meta');
              if (modal && titleEl && outEl && metaEl) {
                titleEl.textContent = `Audit event: ${d2.action || ''}`;
                metaEl.textContent = `Time: ${d2.created_at || ''} · Actor: ${d2.actor || ''} · Target: ${(d2.target_type||'')}:${(d2.target_name||'')} · IP: ${d2.ip || ''}`;
                outEl.value = pretty;
                modal.hidden = false;
                modal.classList.add('open');
                modal.setAttribute('aria-hidden', 'false');
              } else {
                alert(
                  `Audit event\n\n` +
                  `Time: ${d2.created_at || ''}\n` +
                  `Action: ${d2.action || ''}\n` +
                  `Actor: ${d2.actor || ''}\n` +
                  `Target: ${(d2.target_type||'')}:${(d2.target_name||'')}\n` +
                  `IP: ${d2.ip || ''}\n\n` +
                  `Meta:\n${pretty}`
                );
              }
            } catch (err) {
              showToast(err.message || String(err), 'error', 5000);
            }
          });
        });

        if (showToastOnManual) showToast('Audit refreshed', 'success');
      } catch (e) {
        setTableState(tbody, 6, 'error', e.message || String(e));
        if (statusEl) statusEl.textContent = e.message;
        if (showToastOnManual) showToast(e.message, 'error');
      }
    }

    async function loadAdminUsers(showToastOnManual = false) {
      const tbody = document.getElementById('admin-users-table');
      const statusEl = document.getElementById('admin-users-status');
      if (!tbody) return;

      try {
        setTableState(tbody, 8, 'loading', 'Loading…');
        if (statusEl) statusEl.textContent = '';
        const r = await fetch('/auth/admin/users', { credentials: 'include' });
        const raw = await r.text();
        let d = null; try { d = raw ? JSON.parse(raw) : null; } catch {}
        if (!r.ok) throw new Error((d && (d.detail || d.error)) || raw || `users list failed (${r.status})`);

        const items = (d && d.items) ? d.items : [];
        if (!items.length) {
          setTableState(tbody, 8, 'empty', 'No users');
          return;
        }
        tbody.innerHTML = '';
        for (const u of items) {
          const tr = document.createElement('tr');
          const source = String(u.auth_provider || 'local');
          const role = String(u.role || 'operator');
          const active = (u.active === false) ? 'no' : 'yes';
          const mfa = u.mfa_enabled ? 'enabled' : 'off';
          const created = formatShortTime(u.created_at || '');
          const uname = String(u.username || '');
          const bootstrap = String(adminUsername || 'admin');
          const canToggleActive = !!(currentPermissions && currentPermissions.can_delete_app_users) && uname && uname !== bootstrap && uname !== currentUsername;
          const canResetMfa = !!(currentPermissions && currentPermissions.can_manage_users) && uname && uname !== currentUsername;
          const isActive = (u.active !== false);

          tr.innerHTML = `
            <td><code>${escapeHtml(uname)}</code></td>
            <td>${escapeHtml(source)}</td>
            <td>${escapeHtml(role)}</td>
            <td>${escapeHtml(active)}</td>
            <td>${escapeHtml(mfa)}</td>
            <td>
              <div style="display:flex;gap:0.35rem;align-items:center;min-width:210px;">
                <input class="admin-input" data-user-team-scope="${escapeHtml(uname)}" type="text" placeholder="Linux, Database" style="margin:0;min-width:150px;" />
                <button class="btn" data-user-team-scope-save="${escapeHtml(uname)}" type="button">Save</button>
              </div>
            </td>
            <td class="status-muted">${escapeHtml(created)}</td>
            <td style="text-align:right;white-space:nowrap;display:flex;gap:0.4rem;justify-content:flex-end;">
              <button class="btn" data-user-mfa-reset="${escapeHtml(uname)}" ${canResetMfa ? '' : 'disabled'} title="${canResetMfa ? 'Reset MFA for this user' : 'Cannot reset your own MFA here'}">Reset MFA</button>
              <button class="btn" data-user-toggle-active="${escapeHtml(uname)}" data-user-active="${isActive ? '1' : '0'}" ${canToggleActive ? '' : 'disabled'} title="${canToggleActive ? (isActive ? 'Deactivate user' : 'Activate user') : 'Cannot change this user'}">${isActive ? 'Deactivate' : 'Activate'}</button>
            </td>
          `;
          tbody.appendChild(tr);
        }

        const teamScopeInputs = Array.from(tbody.querySelectorAll('input[data-user-team-scope]'));
        for (const input of teamScopeInputs) {
          const uname = input.getAttribute('data-user-team-scope') || '';
          if (!uname) continue;
          try {
            const rs = await fetch(`/auth/admin/users/${encodeURIComponent(uname)}/scopes`, { credentials: 'include' });
            if (!rs.ok) continue;
            const ds = await rs.json();
            const selectors = Array.isArray(ds?.selectors) ? ds.selectors : [];
            const teams = [];
            selectors.forEach((sel) => {
              const vals = Array.isArray(sel?.team) ? sel.team : (sel?.team ? [sel.team] : []);
              vals.forEach((v) => {
                String(v || '').split(',').forEach((part) => {
                  const item = part.trim();
                  if (item && !teams.includes(item)) teams.push(item);
                });
              });
            });
            input.value = teams.join(', ');
          } catch {}
        }

        tbody.querySelectorAll('button[data-user-team-scope-save]').forEach(btn => {
          btn.addEventListener('click', async (e) => {
            e.preventDefault();
            const uname = btn.getAttribute('data-user-team-scope-save') || '';
            const input = tbody.querySelector(`input[data-user-team-scope="${CSS.escape(uname)}"]`);
            if (!uname || !input) return;
            const teams = String(input.value || '').split(',').map(v => v.trim()).filter(Boolean);
            const selectors = teams.length ? [{ team: teams }] : [];
            try {
              const r3 = await fetch(`/auth/admin/users/${encodeURIComponent(uname)}/scopes`, {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': (getCookie('fleet_csrf') || '') },
                body: JSON.stringify({ selectors }),
              });
              const raw3 = await r3.text();
              let d3 = null; try { d3 = raw3 ? JSON.parse(raw3) : null; } catch {}
              if (!r3.ok) throw new Error((d3 && (d3.detail||d3.error)) || raw3 || 'Team scope save failed');
              showToast(`Teams updated for ${uname}`, 'success');
              loadAdminAudit();
            } catch (err) {
              showToast(err.message || String(err), 'error', 5000);
            }
          });
        });

        // Legacy JSON scope editor support, if a custom template still renders it.
        const scopeAreas = Array.from(tbody.querySelectorAll('textarea[data-user-scope]'));
        for (const ta of scopeAreas) {
          const uname = ta.getAttribute('data-user-scope') || '';
          if (!uname) continue;
          try {
            const rs = await fetch(`/auth/admin/users/${encodeURIComponent(uname)}/scopes`, { credentials: 'include' });
            if (!rs.ok) continue;
            const ds = await rs.json();
            ta.value = JSON.stringify((ds && ds.selectors) ? ds.selectors : [], null, 2);
          } catch {}
        }

        tbody.querySelectorAll('button[data-user-scope-save]').forEach(btn => {
          btn.addEventListener('click', async (e) => {
            e.preventDefault();
            const uname = btn.getAttribute('data-user-scope-save') || '';
            const ta = tbody.querySelector(`textarea[data-user-scope="${CSS.escape(uname)}"]`);
            if (!uname || !ta) return;
            let selectors = [];
            try {
              const raw = (ta.value || '').trim() || '[]';
              const parsed = JSON.parse(raw);
              if (!Array.isArray(parsed)) throw new Error('Scope must be a JSON array');
              selectors = parsed;
            } catch (err) {
              showToast(`Invalid scope JSON for ${uname}: ${err.message || err}`, 'error', 5000);
              return;
            }
            try {
              const r3 = await fetch(`/auth/admin/users/${encodeURIComponent(uname)}/scopes`, {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': (getCookie('fleet_csrf') || '') },
                body: JSON.stringify({ selectors }),
              });
              const raw3 = await r3.text();
              let d3 = null; try { d3 = raw3 ? JSON.parse(raw3) : null; } catch {}
              if (!r3.ok) throw new Error((d3 && (d3.detail||d3.error)) || raw3 || 'Scope save failed');
              showToast(`Scope updated for ${uname}`, 'success');
              loadAdminAudit();
            } catch (err) {
              showToast(err.message || String(err), 'error', 5000);
            }
          });
        });

        tbody.querySelectorAll('button[data-user-mfa-reset]').forEach(btn => {
          btn.addEventListener('click', async (e) => {
            e.preventDefault();
            const uname = btn.getAttribute('data-user-mfa-reset') || '';
            if (!uname) return;
            const reason = prompt(`Reset MFA for '${uname}'.\n\nOptional reason/ticket:`, '');
            if (reason === null) return;
            const ok = confirm(`Reset MFA for '${uname}' now?\n\nThis will revoke all active sessions and require re-enrollment at next login.`);
            if (!ok) return;
            try {
              const r2 = await fetch('/auth/mfa/admin/reset', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': (getCookie('fleet_csrf') || '') },
                body: JSON.stringify({ username: uname, reason: reason || '' }),
              });
              const raw2 = await r2.text();
              let d2 = null; try { d2 = raw2 ? JSON.parse(raw2) : null; } catch {}
              if (!r2.ok) throw new Error((d2 && (d2.detail||d2.error)) || raw2 || 'MFA reset failed');
              showToast(`MFA reset for '${uname}' (sessions revoked: ${d2 && d2.sessions_revoked != null ? d2.sessions_revoked : 0})`, 'success');
              loadAdminUsers();
              loadAdminAudit();
            } catch (err) {
              showToast(err.message || String(err), 'error', 5000);
            }
          });
        });

        tbody.querySelectorAll('button[data-user-toggle-active]').forEach(btn => {
          btn.addEventListener('click', async (e) => {
            e.preventDefault();
            const uname = btn.getAttribute('data-user-toggle-active') || '';
            const isActive = (btn.getAttribute('data-user-active') || '1') === '1';
            if (!uname) return;
            const action = isActive ? 'deactivate' : 'activate';
            const ok = confirm(`${isActive ? 'Deactivate' : 'Activate'} user '${uname}'?` + (isActive ? '\n\nThis will disable login and revoke sessions.' : ''));
            if (!ok) return;
            try {
              const endpoint = isActive ? `/auth/users/${encodeURIComponent(uname)}/delete` : `/auth/users/${encodeURIComponent(uname)}/activate`;
              const r2 = await fetch(endpoint, { method: 'POST', credentials: 'include', headers: { 'X-CSRF-Token': (getCookie('fleet_csrf')||'') } });
              const raw2 = await r2.text();
              let d2 = null; try { d2 = raw2 ? JSON.parse(raw2) : null; } catch {}
              if (!r2.ok) throw new Error((d2 && (d2.detail||d2.error)) || raw2 || `${action} failed`);
              showToast(`User '${uname}' ${isActive ? 'deactivated' : 'activated'}`, 'success');
              loadAdminUsers();
              loadAdminAudit();
            } catch (err) {
              showToast(err.message || String(err), 'error', 5000);
            }
          });
        });

        if (showToastOnManual) showToast('Users refreshed', 'success');
      } catch (e) {
        setTableState(tbody, 7, 'error', e.message || String(e));
        if (statusEl) statusEl.textContent = e.message;
        if (showToastOnManual) showToast(e.message, 'error');
      }
    }

    async function loadAdminAdSettings(showToastOnManual = false) {
      const statusEl = document.getElementById('ad-settings-status');
      const setStatus = (msg, type) => {
        if (!statusEl) return;
        statusEl.textContent = msg || '';
        statusEl.className = `admin-status ${type ? `status-${type}` : ''}`;
      };

      try {
        setStatus('Loading...', null);
        const r = await fetch('/auth/admin/ad-settings', { credentials: 'include', cache: 'no-store' });
        const raw = await r.text();
        let d = null; try { d = raw ? JSON.parse(raw) : null; } catch {}
        if (!r.ok) throw new Error((d && (d.detail || d.error)) || raw || `AD settings fetch failed (${r.status})`);

        document.getElementById('ad-enabled').checked = !!d.enabled;
        document.getElementById('ad-server-uri').value = d.server_uri || '';
        document.getElementById('ad-domain').value = d.domain || '';
        document.getElementById('ad-base-dn').value = d.base_dn || '';
        document.getElementById('ad-bind-dn').value = d.bind_dn || '';
        document.getElementById('ad-bind-password').value = '';
        document.getElementById('ad-bind-password').placeholder = d.bind_password_set ? 'Bind password already saved' : 'Bind password';
        document.getElementById('ad-user-filter').value = d.user_filter || '(sAMAccountName={username})';
        document.getElementById('ad-use-ssl').checked = d.use_ssl !== false;
        document.getElementById('ad-role').value = d.role || 'operator';
        setStatus(d.enabled ? 'Active Directory login is enabled.' : 'Active Directory login is disabled.', d.enabled ? 'success' : null);
        if (showToastOnManual) showToast('AD settings loaded', 'success');
      } catch (e) {
        setStatus(e.message || String(e), 'error');
        if (showToastOnManual) showToast(e.message || String(e), 'error');
      }
    }

    async function saveAdminAdSettings() {
      const btn = document.getElementById('ad-settings-save');
      const statusEl = document.getElementById('ad-settings-status');
      const setStatus = (msg, type) => {
        if (!statusEl) return;
        statusEl.textContent = msg || '';
        statusEl.className = `admin-status ${type ? `status-${type}` : ''}`;
      };
      if (!btn) return;

      const payload = {
        enabled: !!document.getElementById('ad-enabled')?.checked,
        server_uri: document.getElementById('ad-server-uri')?.value || '',
        domain: document.getElementById('ad-domain')?.value || '',
        base_dn: document.getElementById('ad-base-dn')?.value || '',
        bind_dn: document.getElementById('ad-bind-dn')?.value || '',
        bind_password: document.getElementById('ad-bind-password')?.value || '',
        user_filter: document.getElementById('ad-user-filter')?.value || '(sAMAccountName={username})',
        use_ssl: !!document.getElementById('ad-use-ssl')?.checked,
        role: document.getElementById('ad-role')?.value || 'operator',
      };

      btn.disabled = true;
      setStatus('Saving...', null);
      try {
        const r = await fetch('/auth/admin/ad-settings', {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': (getCookie('fleet_csrf') || '') },
          body: JSON.stringify(payload),
        });
        const raw = await r.text();
        let d = null; try { d = raw ? JSON.parse(raw) : null; } catch {}
        if (!r.ok) throw new Error((d && (d.detail || d.error)) || raw || `AD settings save failed (${r.status})`);
        document.getElementById('ad-bind-password').value = '';
        document.getElementById('ad-bind-password').placeholder = d.bind_password_set ? 'Bind password already saved' : 'Bind password';
        setStatus(d.enabled ? 'Saved. Active Directory login is enabled.' : 'Saved. Active Directory login is disabled.', 'success');
        showToast('AD settings saved', 'success');
        loadAdminAudit();
      } catch (e) {
        setStatus(e.message || String(e), 'error');
        showToast(e.message || String(e), 'error', 5000);
      } finally {
        btn.disabled = false;
      }
    }

    function initOidcMapPreview() {
      const card = document.getElementById('admin-oidc-map-preview-card');
      if (card) card.style.display = 'none';
    }

    async function loadAdminOidcEvents(showToastOnManual = false) {
      const card = document.getElementById('admin-oidc-events-card');
      const tbody = document.getElementById('admin-oidc-events-table');
      const statusEl = document.getElementById('admin-oidc-events-status');
      if (!card || !tbody) return;

      const isAdmin = (currentPermissions && String(currentPermissions.role || '').toLowerCase() === 'admin') || !!(currentPermissions && currentPermissions.can_manage_users);
      if (!isAdmin) {
        card.style.display = 'none';
        return;
      }
      card.style.display = 'block';

      try {
        setTableState(tbody, 6, 'loading', 'Loading…');
        if (statusEl) statusEl.textContent = '';

        const sinceHours = parseInt((document.getElementById('oidc-events-filter-hours')?.value || '24').trim(), 10) || 24;
        const status = (document.getElementById('oidc-events-filter-status')?.value || '').trim();

        const qs = new URLSearchParams();
        qs.set('limit', '100');
        qs.set('since_hours', String(sinceHours));
        if (status) qs.set('status', status);

        const r = await fetch(`/auth/admin/oidc/events?${qs.toString()}`, { credentials: 'include' });
        const raw = await r.text();
        let d = null; try { d = raw ? JSON.parse(raw) : null; } catch {}
        if (!r.ok) throw new Error((d && (d.detail || d.error)) || raw || `oidc events failed (${r.status})`);

        const items = (d && d.items) ? d.items : [];
        if (!items.length) {
          setTableState(tbody, 6, 'empty', 'No OIDC events in selected window');
          if (showToastOnManual) showToast('OIDC diagnostics refreshed', 'success');
          return;
        }

        tbody.innerHTML = '';
        for (const it of items) {
          const tr = document.createElement('tr');
          const st = String(it?.status || '').toLowerCase();
          const statusBadge = st === 'error'
            ? '<span class="badge badge-danger">error</span>'
            : '<span class="badge badge-success">success</span>';
          tr.innerHTML = `
            <td class="status-muted">${escapeHtml(formatShortTime(it.created_at || ''))}</td>
            <td><code>${escapeHtml(it.stage || '')}</code></td>
            <td>${statusBadge}</td>
            <td style="white-space:normal;overflow-wrap:anywhere;word-break:break-word;">${escapeHtml(it.error_code || '')}${it.error_message ? `<div class="status-muted" style="margin-top:0.25rem;">${escapeHtml(it.error_message)}</div>` : ''}</td>
            <td><code>${escapeHtml(it.correlation_id || '')}</code></td>
            <td style="white-space:normal;overflow-wrap:anywhere;word-break:break-word;">${escapeHtml(it.remediation_hint || '')}</td>
          `;
          tbody.appendChild(tr);
        }

        if (showToastOnManual) showToast('OIDC diagnostics refreshed', 'success');
      } catch (e) {
        setTableState(tbody, 6, 'error', e.message || String(e));
        if (statusEl) statusEl.textContent = e.message || String(e);
        if (showToastOnManual) showToast(e.message || String(e), 'error');
      }
    }

    async function loadAdminNotificationDedupe(showToastOnManual = false) {
      const card = document.getElementById('admin-dedupe-card');
      const tbody = document.getElementById('admin-dedupe-table');
      const statusEl = document.getElementById('admin-dedupe-status');
      if (!card || !tbody) return;

      const isAdmin = (currentPermissions && String(currentPermissions.role || '').toLowerCase() === 'admin') || !!(currentPermissions && currentPermissions.can_manage_users);
      if (!isAdmin) {
        card.style.display = 'none';
        return;
      }
      card.style.display = 'block';

      try {
        setTableState(tbody, 5, 'loading', 'Loading…');
        if (statusEl) statusEl.textContent = '';

        const kind = (document.getElementById('dedupe-filter-kind')?.value || '').trim();
        const minutes = (document.getElementById('dedupe-filter-minutes')?.value || '1440').trim();
        const qs = new URLSearchParams();
        qs.set('limit', '100');
        qs.set('minutes', minutes || '1440');
        if (kind) qs.set('kind', kind);

        const r = await fetch(`/dashboard/notifications/dedupe-state?${qs.toString()}`, { credentials: 'include' });
        const raw = await r.text();
        let d = null; try { d = raw ? JSON.parse(raw) : null; } catch {}
        if (!r.ok) throw new Error((d && (d.detail || d.error)) || raw || `dedupe state failed (${r.status})`);

        const items = (d && d.items) ? d.items : [];
        if (!items.length) {
          setTableState(tbody, 5, 'empty', 'No dedupe entries in selected window');
          if (showToastOnManual) showToast('Dedupe state refreshed', 'success');
          return;
        }

        tbody.innerHTML = '';
        for (const it of items) {
          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td class="status-muted">${escapeHtml(formatShortTime(it.last_emitted_at || ''))}</td>
            <td><code>${escapeHtml(it.kind || '')}</code></td>
            <td>${escapeHtml(it.severity || '')}</td>
            <td style="white-space:normal;overflow-wrap:anywhere;word-break:break-word;"><code>${escapeHtml(it.dedupe_key || '')}</code></td>
            <td style="color:var(--muted-2);white-space:normal;overflow-wrap:anywhere;word-break:break-word;">${escapeHtml(it.last_title || '')}</td>
          `;
          tbody.appendChild(tr);
        }

        if (showToastOnManual) showToast('Dedupe state refreshed', 'success');
      } catch (e) {
        setTableState(tbody, 5, 'error', e.message || String(e));
        if (statusEl) statusEl.textContent = e.message || String(e);
        if (showToastOnManual) showToast(e.message || String(e), 'error');
      }
    }

    async function refreshApprovalsIndicator() {
      const badge = document.getElementById('approvals-badge');
      if (!badge) return;
      const isAdmin = (currentPermissions && String(currentPermissions.role || '').toLowerCase() === 'admin') || !!(currentPermissions && currentPermissions.can_manage_users);
      if (!isAdmin) {
        badge.style.display = 'none';
        return;
      }
      try {
        const r = await fetch('/approvals/admin/pending', { credentials: 'include' });
        if (!r.ok) throw new Error(`approvals failed (${r.status})`);
        const d = await r.json();
        const count = ((d && d.items) ? d.items : []).length;
        badge.style.display = count > 0 ? 'inline' : 'none';
        badge.textContent = count > 0 ? `⚠${count > 9 ? '9+' : count}` : '⚠';
      } catch (_) {
        badge.style.display = 'none';
      }
    }

    async function loadAdminApprovals(showToastOnManual = false) {
      const card = document.getElementById('admin-approvals-card');
      const tbody = document.getElementById('admin-approvals-table');
      const statusEl = document.getElementById('admin-approvals-status');
      if (!card || !tbody) return;

      const isAdmin = (currentPermissions && String(currentPermissions.role || '').toLowerCase() === 'admin') || !!(currentPermissions && currentPermissions.can_manage_users);
      if (!isAdmin) {
        card.style.display = 'none';
        await refreshApprovalsIndicator();
        return;
      }
      card.style.display = 'block';

      try {
        setTableState(tbody, 5, 'loading', 'Loading…');
        if (statusEl) statusEl.textContent = '';

        const filterAction = (document.getElementById('approvals-filter-action')?.value || '').trim().toLowerCase();
        const filterRequester = (document.getElementById('approvals-filter-requester')?.value || '').trim().toLowerCase();
        const ageMins = parseInt((document.getElementById('approvals-filter-age')?.value || '').trim(), 10);
        const mode = (document.getElementById('approvals-filter-mode')?.value || 'pending').trim();
        const sortMode = (document.getElementById('approvals-filter-sort')?.value || 'created_desc').trim();
        const nowMs = Date.now();

        const qs = new URLSearchParams();
        qs.set('mode', mode === 'recent' ? 'recent' : 'pending');
        qs.set('hours', '24');
        const r = await fetch(`/approvals/admin/pending?${qs.toString()}`, { credentials: 'include' });
        const raw = await r.text();
        let d = null; try { d = raw ? JSON.parse(raw) : null; } catch {}
        if (!r.ok) throw new Error((d && (d.detail || d.error)) || raw || `approvals failed (${r.status})`);

        const items = (d && d.items) ? d.items : [];

        const filtered = items.filter((it) => {
          const act = String(it?.action || '').toLowerCase();
          const usr = String(it?.user || '').toLowerCase();
          if (filterAction && !act.includes(filterAction)) return false;
          if (filterRequester && !usr.includes(filterRequester)) return false;
          if (!Number.isNaN(ageMins) && ageMins > 0) {
            const ts = Date.parse(String(it?.created_at || ''));
            if (!Number.isNaN(ts)) {
              const age = (nowMs - ts) / 60000;
              if (age > ageMins) return false;
            }
          }
          return true;
        });

        filtered.sort((a, b) => {
          if (sortMode === 'created_asc') return Date.parse(String(a?.created_at || '')) - Date.parse(String(b?.created_at || ''));
          if (sortMode === 'action_asc') return String(a?.action || '').localeCompare(String(b?.action || ''));
          if (sortMode === 'requester_asc') return String(a?.user || '').localeCompare(String(b?.user || ''));
          return Date.parse(String(b?.created_at || '')) - Date.parse(String(a?.created_at || ''));
        });

        if (!filtered.length) {
          const emptyBase = (mode === 'recent') ? 'No approvals in last 24h' : 'No pending approvals';
          setTableState(tbody, 5, 'empty', items.length ? 'No requests match filters' : emptyBase);
          await refreshApprovalsIndicator();
          if (showToastOnManual) showToast('Approvals refreshed', 'success');
          return;
        }

        tbody.innerHTML = '';
        for (const it of filtered) {
          const payload = (it && typeof it.payload === 'object' && it.payload) ? it.payload : {};
          const targets = Array.isArray(payload.agent_ids) ? payload.agent_ids : [];
          const targetLabel = targets.length ? `${targets.slice(0, 3).join(', ')}${targets.length > 3 ? ` (+${targets.length - 3})` : ''}` : 'selector-based';
          const tr = document.createElement('tr');
          const isPending = String(it?.status || '') === 'pending';
          const execRef = String(it?.execution_ref || '');
          const feedback = String((approvalActionFeedback && approvalActionFeedback[it.id]) || '');
          tr.innerHTML = `
            <td class="status-muted">${escapeHtml(formatShortTime(it.created_at))}</td>
            <td>${escapeHtml(it.user || '')}<div class="status-muted" style="font-size:0.8rem;">${escapeHtml(String(it?.status || ''))}</div></td>
            <td><code>${escapeHtml(it.action || '')}</code>${execRef ? `<div class="status-muted" style="font-size:0.8rem;">${escapeHtml(execRef.slice(0, 16))}</div>` : ''}${feedback ? `<div class="status-ok" style="font-size:0.78rem;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(feedback)}">${escapeHtml(feedback)}</div>` : ''}</td>
            <td title="${escapeHtml(targets.join('\n'))}">${escapeHtml(targetLabel)}</td>
            <td style="text-align:right;white-space:nowrap;">
              <button class="btn" data-copy-id="${escapeHtml(it.id)}">Copy ID</button>
              <button class="btn" data-details-id="${escapeHtml(it.id)}">Details</button>
              <button class="btn btn-primary" data-approve-id="${escapeHtml(it.id)}" ${isPending ? '' : 'disabled'}>Approve</button>
              <button class="btn" data-reject-id="${escapeHtml(it.id)}" ${isPending ? '' : 'disabled'}>Reject</button>
            </td>
          `;
          tr.dataset.approvalPayload = JSON.stringify(it || {});
          tbody.appendChild(tr);
        }

        tbody.querySelectorAll('button[data-copy-id]').forEach(btn => {
          btn.addEventListener('click', async (e) => {
            e.preventDefault();
            const id = btn.getAttribute('data-copy-id') || '';
            if (!id) return;
            try {
              await navigator.clipboard.writeText(id);
              showToast('Request ID copied', 'success');
            } catch {
              showToast('Copy failed', 'error');
            }
          });
        });

        tbody.querySelectorAll('button[data-details-id]').forEach(btn => {
          btn.addEventListener('click', (e) => {
            e.preventDefault();
            const tr = btn.closest('tr');
            if (!tr) return;
            let row = null;
            try { row = JSON.parse(tr.dataset.approvalPayload || '{}'); } catch { row = null; }
            if (!row) return;
            const modal = document.getElementById('approval-detail-modal');
            const titleEl = document.getElementById('approval-detail-modal-title');
            const metaEl = document.getElementById('approval-detail-modal-meta');
            const outEl = document.getElementById('approval-detail-modal-output');
            if (!modal || !titleEl || !metaEl || !outEl) return;
            titleEl.textContent = `Approval request: ${row.action || ''}`;
            metaEl.textContent = `Requested: ${row.created_at || ''} · By: ${row.user || ''} · Status: ${row.status || ''} · ID: ${row.id || ''}`;
            outEl.value = JSON.stringify({
              request: {
                id: row.id || '',
                action: row.action || '',
                user: row.user || '',
                status: row.status || '',
                created_at: row.created_at || null,
                finished_at: row.finished_at || null,
                approved_by: row.approved_by || null,
                execution_ref: row.execution_ref || null,
                error: row.error || null,
              },
              payload: row.payload || {},
            }, null, 2);
            modal.hidden = false;
            modal.classList.add('open');
            modal.setAttribute('aria-hidden', 'false');
          });
        });

        tbody.querySelectorAll('button[data-approve-id]').forEach(btn => {
          btn.addEventListener('click', async (e) => {
            e.preventDefault();
            const id = btn.getAttribute('data-approve-id');
            if (!id) return;
            const r2 = await fetch(`/approvals/admin/${encodeURIComponent(id)}/approve`, { method: 'POST', credentials: 'include' });
            const raw2 = await r2.text();
            let d2 = null; try { d2 = raw2 ? JSON.parse(raw2) : null; } catch {}
            if (!r2.ok) {
              const msg = (d2 && (d2.detail || d2.error)) || raw2 || 'Approve failed';
              return showToast(msg, 'error');
            }
            const msg = (d2 && d2.summary && d2.summary.message) ? d2.summary.message : 'Approved and executed';
            approvalActionFeedback[id] = msg;
            showToast(msg, 'success');
            loadAdminApprovals();
            loadAdminAudit();
            refreshApprovalsIndicator();
          });
        });

        tbody.querySelectorAll('button[data-reject-id]').forEach(btn => {
          btn.addEventListener('click', async (e) => {
            e.preventDefault();
            const id = btn.getAttribute('data-reject-id');
            if (!id) return;
            const note = prompt('Reject note (optional):', '') || '';
            const r2 = await fetch(`/approvals/admin/${encodeURIComponent(id)}/reject`, {
              method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ note })
            });
            const raw2 = await r2.text();
            let d2 = null; try { d2 = raw2 ? JSON.parse(raw2) : null; } catch {}
            if (!r2.ok) {
              const msg = (d2 && (d2.detail || d2.error)) || raw2 || 'Reject failed';
              return showToast(msg, 'error');
            }
            const msg = (d2 && d2.summary && d2.summary.message) ? d2.summary.message : 'Rejected';
            approvalActionFeedback[id] = msg;
            showToast(msg, 'success');
            loadAdminApprovals();
            loadAdminAudit();
            refreshApprovalsIndicator();
          });
        });

        await refreshApprovalsIndicator();
        if (showToastOnManual) showToast('Approvals refreshed', 'success');
      } catch (e) {
        setTableState(tbody, 5, 'error', e.message || String(e));
        if (statusEl) statusEl.textContent = e.message || String(e);
        if (showToastOnManual) showToast(e.message || String(e), 'error');
        await refreshApprovalsIndicator();
      }
    }

    return {
      loadAdminAudit,
      loadAdminUsers,
      loadAdminAdSettings,
      saveAdminAdSettings,
      initOidcMapPreview,
      loadAdminOidcEvents,
      loadAdminNotificationDedupe,
      refreshApprovalsIndicator,
      loadAdminApprovals,
    };
  }

  window.fleetAdminUi = {
    loadAdminAudit(ctx, showToastOnManual = false) { return bind(ctx).loadAdminAudit(showToastOnManual); },
    loadAdminUsers(ctx, showToastOnManual = false) { return bind(ctx).loadAdminUsers(showToastOnManual); },
    loadAdminAdSettings(ctx, showToastOnManual = false) { return bind(ctx).loadAdminAdSettings(showToastOnManual); },
    saveAdminAdSettings(ctx) { return bind(ctx).saveAdminAdSettings(); },
    initOidcMapPreview(ctx) { return bind(ctx).initOidcMapPreview(); },
    loadAdminOidcEvents(ctx, showToastOnManual = false) { return bind(ctx).loadAdminOidcEvents(showToastOnManual); },
    loadAdminNotificationDedupe(ctx, showToastOnManual = false) { return bind(ctx).loadAdminNotificationDedupe(showToastOnManual); },
    refreshApprovalsIndicator(ctx) { return bind(ctx).refreshApprovalsIndicator(); },
    loadAdminApprovals(ctx, showToastOnManual = false) { return bind(ctx).loadAdminApprovals(showToastOnManual); },
  };
})();

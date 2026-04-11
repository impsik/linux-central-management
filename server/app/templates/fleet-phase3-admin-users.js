async function loadAdminUsers(showToastOnManual = false) {
  const tbody = document.getElementById('admin-users-table');
  const statusEl = document.getElementById('admin-users-status');
  if (!tbody) return;

  try {
    setTableState(tbody, 6, 'loading', 'Loading…');
    if (statusEl) statusEl.textContent = '';
    const r = await fetch('/auth/admin/users', { credentials: 'include' });
    const raw = await r.text();
    let d = null; try { d = raw ? JSON.parse(raw) : null; } catch {}
    if (!r.ok) throw new Error((d && (d.detail || d.error)) || raw || `users list failed (${r.status})`);

    const items = (d && d.items) ? d.items : [];
    if (!items.length) {
      setTableState(tbody, 6, 'empty', 'No users');
      return;
    }
    tbody.innerHTML = '';
    for (const u of items) {
      const tr = document.createElement('tr');
      const role = String(u.role || 'operator');
      const active = (u.active === false) ? 'no' : 'yes';
      const mfa = u.mfa_enabled ? 'enabled' : 'off';
      const created = formatShortTime(u.created_at || '');
      const uname = String(u.username || '');
      const bootstrap = String(adminUsername || 'admin');
      const canToggleActive = !!(currentPermissions && currentPermissions.can_delete_app_users) && uname && uname !== bootstrap && uname !== currentUsername;
      const canRemoveUser = !!(currentPermissions && currentPermissions.can_delete_app_users) && uname && uname !== bootstrap && uname !== currentUsername;
      const canResetMfa = !!(currentPermissions && currentPermissions.can_manage_users) && uname && uname !== currentUsername;
      const isActive = (u.active !== false);

      tr.innerHTML = `
        <td><code>${escapeHtml(uname)}</code></td>
        <td>${escapeHtml(role)}</td>
        <td>${escapeHtml(active)}</td>
        <td>${escapeHtml(mfa)}</td>
        <td class="status-muted">${escapeHtml(created)}</td>
        <td style="text-align:right;white-space:nowrap;display:flex;gap:0.4rem;justify-content:flex-end;">
          <button class="btn" data-user-rbac-explain="${escapeHtml(uname)}" title="Explain host access for this user">Explain</button>
          <button class="btn" data-user-mfa-reset="${escapeHtml(uname)}" ${canResetMfa ? '' : 'disabled'} title="${canResetMfa ? 'Reset MFA for this user' : 'Cannot reset your own MFA here'}">Reset MFA</button>
          <button class="btn" data-user-toggle-active="${escapeHtml(uname)}" data-user-active="${isActive ? '1' : '0'}" ${canToggleActive ? '' : 'disabled'} title="${canToggleActive ? (isActive ? 'Deactivate user' : 'Activate user') : 'Cannot change this user'}">${isActive ? 'Deactivate' : 'Activate'}</button>
          <button class="btn btn-danger" data-user-remove-enhanced="${escapeHtml(uname)}" ${canRemoveUser ? '' : 'disabled'} title="${canRemoveUser ? 'Permanently remove this user' : 'Cannot remove this user'}">Remove</button>
        </td>
      `;
      tbody.appendChild(tr);
    }

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

    tbody.querySelectorAll('button[data-user-rbac-explain]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const uname = btn.getAttribute('data-user-rbac-explain') || '';
        if (!uname) return;
        const userSel = document.getElementById('admin-rbac-user');
        if (userSel) {
          userSel.value = uname;
          userSel.dispatchEvent(new Event('change'));
        }
        document.getElementById('admin-rbac-explain-card')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
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
    setTableState(tbody, 6, 'error', e.message || String(e));
    if (statusEl) statusEl.textContent = e.message;
    if (showToastOnManual) showToast(e.message, 'error');
  }
}

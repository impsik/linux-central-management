(function (w) {
  const USERNAME_CELL_INDEX = 0;
  const ACTIONS_CELL_INDEX = 5;

  function getUsernameFromRow(tr) {
    const cell = tr?.children?.[USERNAME_CELL_INDEX];
    if (!cell) return '';
    const code = cell.querySelector('code');
    const raw = (code?.textContent || cell.textContent || '').trim();
    return raw;
  }

  async function fetchOwnerScope(username) {
    const resp = await fetch(`/auth/admin/users/${encodeURIComponent(username)}/scopes`, { credentials: 'include' });
    if (!resp.ok) throw new Error(`scope fetch failed (${resp.status})`);
    const data = await resp.json();
    const selectors = Array.isArray(data?.selectors) ? data.selectors : [];
    for (const sel of selectors) {
      if (!sel || typeof sel !== 'object') continue;
      const ownerVals = sel.owner;
      if (Array.isArray(ownerVals) && ownerVals.length) {
        return String(ownerVals[0] || '').trim();
      }
      if (typeof ownerVals === 'string' && ownerVals.trim()) {
        return ownerVals.trim();
      }
    }
    return '';
  }

  async function saveOwnerScope(username, owner) {
    const selectors = owner ? [{ owner: [owner] }] : [];
    const resp = await fetch(`/auth/admin/users/${encodeURIComponent(username)}/scopes`, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': (typeof w.getCookie === 'function' ? (w.getCookie('fleet_csrf') || '') : ''),
      },
      body: JSON.stringify({ selectors }),
    });
    const raw = await resp.text();
    let data = null;
    try { data = raw ? JSON.parse(raw) : null; } catch {}
    if (!resp.ok) {
      throw new Error((data && (data.detail || data.error)) || raw || `scope save failed (${resp.status})`);
    }
  }

  function buildControls(username) {
    const wrap = document.createElement('div');
    wrap.className = 'owner-scope-wrap';
    wrap.style.display = 'flex';
    wrap.style.flexDirection = 'column';
    wrap.style.gap = '0.35rem';
    wrap.style.minWidth = '220px';
    wrap.style.alignItems = 'stretch';
    wrap.style.marginRight = '0.4rem';

    const label = document.createElement('div');
    label.className = 'status-muted';
    label.style.fontSize = '0.78rem';
    label.textContent = 'Owner scope';

    const row = document.createElement('div');
    row.style.display = 'flex';
    row.style.gap = '0.35rem';
    row.style.alignItems = 'center';

    const input = document.createElement('input');
    input.type = 'text';
    input.className = 'host-search';
    input.placeholder = 'owner username';
    input.style.margin = '0';
    input.style.height = '30px';
    input.style.minWidth = '0';
    input.style.flex = '1 1 auto';
    input.setAttribute('data-owner-scope-input', username);

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn';
    btn.textContent = 'Save owner';
    btn.setAttribute('data-owner-scope-save', username);

    const status = document.createElement('div');
    status.className = 'status-muted';
    status.style.fontSize = '0.75rem';
    status.setAttribute('data-owner-scope-status', username);

    row.appendChild(input);
    row.appendChild(btn);
    wrap.appendChild(label);
    wrap.appendChild(row);
    wrap.appendChild(status);

    return { wrap, input, btn, status };
  }

  function wireRemoveButton(btn, username, tr) {
    if (!btn || btn.dataset.removeEnhancedBound === '1') return btn;
    btn.dataset.removeEnhancedBound = '1';
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      const ok = window.confirm(`Permanently remove user '${username}'?\n\nThis deletes the account and revokes sessions. This cannot be undone.`);
      if (!ok) return;
      try {
        const resp = await fetch(`/auth/users/${encodeURIComponent(username)}/remove`, {
          method: 'POST',
          credentials: 'include',
          headers: { 'X-CSRF-Token': (typeof w.getCookie === 'function' ? (w.getCookie('fleet_csrf') || '') : '') },
        });
        const raw = await resp.text();
        let data = null;
        try { data = raw ? JSON.parse(raw) : null; } catch {}
        if (!resp.ok) throw new Error((data && (data.detail || data.error)) || raw || `remove failed (${resp.status})`);
        if (typeof w.showToast === 'function') w.showToast(`User '${username}' removed`, 'success');
        tr.remove();
      } catch (err) {
        if (typeof w.showToast === 'function') w.showToast(err?.message || String(err), 'error', 5000);
      }
    });
    return btn;
  }

  function buildRemoveButton(username, tr) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn-danger';
    btn.textContent = 'Remove';
    btn.setAttribute('data-user-remove-enhanced', username);
    return wireRemoveButton(btn, username, tr);
  }

  async function enhanceUserRow(tr) {
    if (!tr || tr.dataset.ownerScopeEnhanced === '1') return;
    const username = getUsernameFromRow(tr);
    if (!username) return;
    const actionsCell = tr.children?.[ACTIONS_CELL_INDEX];
    if (!actionsCell) return;

    tr.dataset.ownerScopeEnhanced = '1';
    actionsCell.style.display = 'flex';
    actionsCell.style.gap = '0.5rem';
    actionsCell.style.alignItems = 'flex-start';
    actionsCell.style.justifyContent = 'flex-end';
    actionsCell.style.flexWrap = 'wrap';

    const controls = buildControls(username);
    actionsCell.prepend(controls.wrap);
    const existingRemoveBtn = actionsCell.querySelector(`[data-user-remove-enhanced="${CSS.escape(username)}"]`);
    if (existingRemoveBtn) wireRemoveButton(existingRemoveBtn, username, tr);
    else actionsCell.appendChild(buildRemoveButton(username, tr));

    try {
      controls.status.textContent = 'Loading…';
      const owner = await fetchOwnerScope(username);
      controls.input.value = owner;
      controls.status.textContent = owner ? `Restricted to owner: ${owner}` : 'No owner restriction';
    } catch (err) {
      controls.status.textContent = err?.message || String(err);
    }

    controls.btn.addEventListener('click', async (e) => {
      e.preventDefault();
      const owner = String(controls.input.value || '').trim();
      controls.btn.disabled = true;
      controls.status.textContent = 'Saving…';
      try {
        await saveOwnerScope(username, owner);
        controls.status.textContent = owner ? `Restricted to owner: ${owner}` : 'No owner restriction';
        if (typeof w.showToast === 'function') {
          w.showToast(owner ? `Owner scope updated for ${username}` : `Owner scope cleared for ${username}`, 'success');
        }
      } catch (err) {
        const msg = err?.message || String(err);
        controls.status.textContent = msg;
        if (typeof w.showToast === 'function') w.showToast(msg, 'error', 5000);
      } finally {
        controls.btn.disabled = false;
      }
    });
  }

  function enhanceUsersTable() {
    const tbody = document.getElementById('admin-users-table');
    if (!tbody) return;
    Array.from(tbody.querySelectorAll('tr')).forEach((tr) => {
      if (tr.querySelector('td')?.hasAttribute('colspan')) return;
      void enhanceUserRow(tr);
    });
  }

  function initOwnerScopeUi() {
    const tbody = document.getElementById('admin-users-table');
    if (!tbody || tbody.dataset.ownerScopeObserverBound === '1') return;
    tbody.dataset.ownerScopeObserverBound = '1';
    const observer = new MutationObserver(() => enhanceUsersTable());
    observer.observe(tbody, { childList: true, subtree: true });
    enhanceUsersTable();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initOwnerScopeUi, { once: true });
  } else {
    initOwnerScopeUi();
  }

  w.phase3OwnerScopeUi = { initOwnerScopeUi };
})(window);

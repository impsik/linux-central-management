function setAdminStatus(message, state) {
      const statusEl = document.getElementById('register-status');
      if (!statusEl) return;
      statusEl.textContent = message || '';
      statusEl.classList.remove('error', 'success');
      if (state === 'error') statusEl.classList.add('error');
      if (state === 'success') statusEl.classList.add('success');
    }

    function setResetStatus(message, state) {
      const statusEl = document.getElementById('reset-status');
      if (!statusEl) return;
      statusEl.textContent = message || '';
      statusEl.classList.remove('error', 'success');
      if (state === 'error') statusEl.classList.add('error');
      if (state === 'success') statusEl.classList.add('success');
    }

    function showToast(message, type = 'info', timeoutMs = 3500) {
      const container = document.getElementById('toast-container');
      if (!container) return;
      const toast = document.createElement('div');
      toast.className = `toast toast-${type}`;
      toast.textContent = message;
      container.appendChild(toast);
      requestAnimationFrame(() => toast.classList.add('show'));
      const remove = () => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 200);
      };
      setTimeout(remove, timeoutMs);
    }

    function updateSshKeysLabels() {
      const titleEl = document.getElementById('sshkeys-list-title');
      if (!titleEl) return;
      const isAdmin = (currentPermissions && String(currentPermissions.role||'').toLowerCase() === 'admin') || !!currentPermissions.can_manage_users;
      titleEl.textContent = isAdmin ? 'SSH Keys' : 'My keys';
    }

    async function loadAuthInfo() {
      const userEl = document.getElementById('current-user');
      const logoutBtn = document.getElementById('logout-btn');
      const adminMenuItem = document.getElementById('admin-menu-item');
      const adminNote = document.getElementById('admin-access-note');
      const adminTab = document.getElementById('admin-tab');
      if (!userEl) return;

      let meUser = null;
      let mePermissions = {};
      try {
        const resp = await fetch('/auth/me');
        if (resp.ok) {
          const data = await resp.json();
          meUser = data.username || null;
          mePermissions = data.permissions || {};
          window.__mfa = data.mfa || null;
        }
      } catch { }

      userEl.textContent = meUser ? `Signed in as ${meUser}` : 'Signed in';

      let admin = null;
      try {
        const resp = await fetch('/auth/admin-info');
        if (resp.ok) {
          const data = await resp.json();
          admin = data.admin_username || null;
        }
      } catch { }

      currentUsername = meUser;
      currentPermissions = mePermissions || {};
      adminUsername = admin;
      const isAdmin = (currentPermissions && String(currentPermissions.role||'').toLowerCase() === 'admin') || !!currentPermissions.can_manage_users || !!(meUser && admin && meUser === admin);

      // Forced MFA flow (for admin/operator).
      try {
        const mfa = window.__mfa || null;
        if (mfa && mfa.setup_required) {
          // Start enrollment (QR) and force modal open.
          await mfaEnrollStart();
        } else if (mfa && mfa.verify_required) {
          openMfaModal('verify');
        }
      } catch {}
      if (adminMenuItem) {
        adminMenuItem.style.display = isAdmin ? 'flex' : 'none';
      }
      if (adminNote) {
        adminNote.style.display = isAdmin ? 'none' : 'block';
      }
      if (adminTab) {
        adminTab.querySelectorAll('input, button').forEach(el => {
          if (el.id === 'admin-menu-item' || el.id === 'settings-btn') return;
          el.disabled = !isAdmin;
        });
      }
      if (logoutBtn) {
        logoutBtn.style.display = meUser ? 'flex' : 'none';
      }

      const usersAccessNote = document.getElementById('users-access-note');
      if (usersAccessNote) {
        usersAccessNote.style.display = currentPermissions.can_lock_users ? 'none' : 'block';
      }

      updateSshKeysLabels();
    }

    // Explicit exports for cross-file calls.
    window.loadAuthInfo = loadAuthInfo;
    window.showToast = showToast;


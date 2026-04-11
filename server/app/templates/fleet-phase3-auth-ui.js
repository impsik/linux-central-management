function initAdminPanel() {
      const panel = document.getElementById('admin-tab');
      if (!panel) return;

      const usernameInput = document.getElementById('register-username');
      const passwordInput = document.getElementById('register-password');
      const roleInput = document.getElementById('register-role');
      const button = document.getElementById('register-user-btn');
      if (!usernameInput || !passwordInput || !roleInput || !button) return;
      const resetUserInput = document.getElementById('reset-username');
      const resetPasswordInput = document.getElementById('reset-password');
      const resetButton = document.getElementById('reset-password-btn');

      const submit = async () => {
        const username = (usernameInput.value || '').trim();
        const password = passwordInput.value || '';
        const role = (roleInput.value || 'operator').trim();
        if (!username || !password) {
          setAdminStatus('Username and password required.', 'error');
          return;
        }

        button.disabled = true;
        setAdminStatus('Creating user...', null);
        try {
          const resp = await fetch('/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, role })
          });
          if (!resp.ok) {
            let msg = 'Failed to create user';
            try {
              const data = await resp.json();
              msg = data.detail || data.message || msg;
            } catch { }
            throw new Error(msg);
          }
          const data = await resp.json();
          const createdUser = data.username || username;
          const createdRole = data.role || role;
          setAdminStatus(`User ${createdUser} created as ${createdRole}.`, 'success');
          showToast(`User ${createdUser} created as ${createdRole}.`, 'success');
          passwordInput.value = '';
        } catch (e) {
          const msg = e.message || String(e);
          setAdminStatus(msg, 'error');
          showToast(msg, 'error');
        } finally {
          button.disabled = false;
        }
      };

      button.addEventListener('click', (e) => {
        e.preventDefault();
        submit();
      });

      passwordInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') submit();
      });

      if (resetUserInput && resetPasswordInput && resetButton) {
        const resetSubmit = async () => {
          const username = (resetUserInput.value || '').trim();
          const password = resetPasswordInput.value || '';
          if (!username || !password) {
            setResetStatus('Username and password required.', 'error');
            return;
          }

          resetButton.disabled = true;
          setResetStatus('Resetting password...', null);
          try {
            const resp = await fetch('/auth/reset-password', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ username, password })
            });
            if (!resp.ok) {
              let msg = 'Failed to reset password';
              try {
                const data = await resp.json();
                msg = data.detail || data.message || msg;
              } catch { }
              throw new Error(msg);
            }
            const data = await resp.json();
            const resetUser = data.username || username;
            setResetStatus(`Password updated for ${resetUser}.`, 'success');
            showToast(`Password updated for ${resetUser}.`, 'success');
            resetPasswordInput.value = '';
          } catch (e) {
            const msg = e.message || String(e);
            setResetStatus(msg, 'error');
            showToast(msg, 'error');
          } finally {
            resetButton.disabled = false;
          }
        };

        resetButton.addEventListener('click', (e) => {
          e.preventDefault();
          resetSubmit();
        });

        resetPasswordInput.addEventListener('keydown', (e) => {
          if (e.key === 'Enter') resetSubmit();
        });
      }
    }

    function initSettingsMenu() {
      const wrap = document.getElementById('settings-menu-wrap');
      const btn = document.getElementById('settings-btn');
      const dropdown = document.getElementById('settings-dropdown');
      const adminItem = document.getElementById('admin-menu-item');
      const changePasswordItem = document.getElementById('change-password-menu-item');
      const logoutItem = document.getElementById('logout-btn');
      if (!wrap || !btn || !dropdown) return;

      const closeMenu = () => {
        wrap.classList.remove('open');
        btn.setAttribute('aria-expanded', 'false');
      };

      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const willOpen = !wrap.classList.contains('open');
        if (willOpen) {
          wrap.classList.add('open');
          btn.setAttribute('aria-expanded', 'true');
        } else {
          closeMenu();
        }
      });

      adminItem?.addEventListener('click', (e) => {
        e.preventDefault();
        closeMenu();
        showAdminPage();
      });

      changePasswordItem?.addEventListener('click', async (e) => {
        e.preventDefault();
        closeMenu();
        const currentPassword = window.prompt('Current password:');
        if (currentPassword === null) return;
        const newPassword = window.prompt('New password (minimum 8 characters):');
        if (newPassword === null) return;
        const confirmPassword = window.prompt('Repeat new password:');
        if (confirmPassword === null) return;
        if (newPassword !== confirmPassword) {
          showToast('New passwords do not match', 'error');
          return;
        }
        try {
          const resp = await fetch('/auth/change-password', {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': (typeof getCookie === 'function' ? (getCookie('fleet_csrf') || '') : '') },
            body: JSON.stringify({ current_password: currentPassword, new_password: newPassword })
          });
          const raw = await resp.text();
          let data = null; try { data = raw ? JSON.parse(raw) : null; } catch {}
          if (!resp.ok) throw new Error((data && (data.detail || data.error)) || raw || 'Password change failed');
          showToast('Password changed successfully', 'success');
        } catch (err) {
          showToast(err.message || String(err), 'error', 5000);
        }
      });

      logoutItem?.addEventListener('click', async (e) => {
        e.preventDefault();
        closeMenu();
        logoutItem.disabled = true;
        let hadError = false;
        try {
          await fetch('/auth/logout', {
            method: 'POST',
            headers: { 'X-CSRF-Token': (typeof getCookie === 'function' ? (getCookie('fleet_csrf') || '') : '') }
          });
        } catch {
          hadError = true;
        }
        if (hadError) {
          showToast('Logout failed. Redirecting to login.', 'error');
        } else {
          showToast('Signed out.', 'success');
        }
        setTimeout(() => { window.location.href = '/login'; }, 500);
      });

      document.addEventListener('click', (e) => {
        if (!wrap.contains(e.target)) closeMenu();
      });

      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeMenu();
      });
    }


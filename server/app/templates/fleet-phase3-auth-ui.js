function initAdminPanel() {
      const panel = document.getElementById('admin-tab');
      if (!panel) return;

      const usernameInput = document.getElementById('register-username');
      const passwordInput = document.getElementById('register-password');
      const button = document.getElementById('register-user-btn');
      if (!usernameInput || !passwordInput || !button) return;
      const resetUserInput = document.getElementById('reset-username');
      const resetPasswordInput = document.getElementById('reset-password');
      const resetButton = document.getElementById('reset-password-btn');

      const submit = async () => {
        const username = (usernameInput.value || '').trim();
        const password = passwordInput.value || '';
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
            body: JSON.stringify({ username, password })
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
          setAdminStatus(`User ${createdUser} created.`, 'success');
          showToast(`User ${createdUser} created.`, 'success');
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

      logoutItem?.addEventListener('click', async (e) => {
        e.preventDefault();
        closeMenu();
        logoutItem.disabled = true;
        let hadError = false;
        try {
          await fetch('/auth/logout', { method: 'POST' });
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


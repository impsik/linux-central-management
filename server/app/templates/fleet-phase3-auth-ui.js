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


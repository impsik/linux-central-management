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
    if (typeof showAdminPage === 'function') showAdminPage();
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
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': (typeof getCookie === 'function' ? (getCookie('fleet_csrf') || '') : ''),
        },
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

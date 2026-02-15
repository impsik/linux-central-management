function openMfaModal(mode, otpauthUri = '') {
      const modal = document.getElementById('mfa-modal');
      const titleEl = document.getElementById('mfa-modal-title');
      const bodyEl = document.getElementById('mfa-modal-body');
      const statusEl = document.getElementById('mfa-modal-status');
      if (!modal || !titleEl || !bodyEl || !statusEl) return;

      statusEl.textContent = '';
      statusEl.classList.remove('error', 'success');

      if (mode === 'setup') {
        titleEl.textContent = 'Set up MFA (required)';
        bodyEl.innerHTML = `
          <div style="color:var(--muted-2);margin-bottom:0.5rem;">Scan this QR in Microsoft Authenticator / Google Authenticator, then enter the 6-digit code.</div>
          <div id="mfa-qr" style="background:var(--panel-2);border:1px solid var(--border);border-radius:12px;padding:12px;display:inline-block;"></div>
          <div style="margin-top:0.75rem;">
            <label style="display:block;color:var(--muted-2);font-size:0.85rem;margin-bottom:0.25rem;">Code</label>
            <input id="mfa-code" class="host-search" type="text" placeholder="123456" />
          </div>
          <div style="margin-top:0.75rem;display:flex;gap:0.5rem;flex-wrap:wrap;">
            <button class="btn btn-primary" id="mfa-confirm" type="button">Confirm</button>
            <button class="btn" id="mfa-start" type="button">Regenerate QR</button>
          </div>
          <div style="margin-top:0.75rem;color:var(--muted-2);font-size:0.85rem;">After confirmation, you will receive recovery codes (save them somewhere safe).</div>
        `;

        // Render QR using a tiny inline SVG (no external libs): use a simple link if QR generation isn't available.
        const qr = document.getElementById('mfa-qr');
        if (qr) {
          const safe = escapeHtml(otpauthUri || '');
          const imgUrl = (window.__mfa_qr_data_url || '');
          if (imgUrl) {
            qr.innerHTML = `<img src="${escapeHtml(imgUrl)}" alt="MFA QR" style="display:block;max-width:260px;max-height:260px;" />`;
          } else {
            qr.innerHTML = safe ? `<div style="font-size:0.9rem;"><div><b>otpauth URI</b></div><code style="display:block;max-width:520px;white-space:pre-wrap;word-break:break-all;">${safe}</code></div>` : '<div style="color:var(--muted-2);">(loading…)</div>';
          }
        }

        document.getElementById('mfa-start')?.addEventListener('click', async () => {
          await mfaEnrollStart();
        });
        document.getElementById('mfa-confirm')?.addEventListener('click', async () => {
          const code = document.getElementById('mfa-code')?.value || '';
          await mfaEnrollConfirm(code);
        });
      } else {
        titleEl.textContent = 'MFA verification required';
        bodyEl.innerHTML = `
          <div style="color:var(--muted-2);margin-bottom:0.5rem;">Enter the 6-digit code from your authenticator (or a recovery code).</div>
          <form id="mfa-verify-form" autocomplete="off">
            <label style="display:block;color:var(--muted-2);font-size:0.85rem;margin-bottom:0.25rem;">Code</label>
            <input id="mfa-verify-code" class="host-search" type="text" placeholder="123456" />
            <div style="margin-top:0.75rem;display:flex;gap:0.5rem;flex-wrap:wrap;">
              <button class="btn btn-primary" id="mfa-verify" type="submit">Verify</button>
            </div>
          </form>
        `;
        const verifyInput = document.getElementById('mfa-verify-code');
        const verifyForm = document.getElementById('mfa-verify-form');

        verifyForm?.addEventListener('submit', async (e) => {
          e.preventDefault();
          const code = verifyInput?.value || '';
          await mfaVerify(code);
        });

        // Focus the field when modal opens so user can type/paste immediately.
        verifyInput?.focus();
      }

      modal.hidden = false;
      modal.classList.add('open');
      modal.setAttribute('aria-hidden', 'false');
    }

    function closeMfaModal() {
      const modal = document.getElementById('mfa-modal');
      if (!modal) return;
      modal.classList.remove('open');
      modal.setAttribute('aria-hidden', 'true');
      modal.hidden = true;
    }

    async function mfaEnrollStart() {
      const statusEl = document.getElementById('mfa-modal-status');
      try {
        if (statusEl) statusEl.textContent = 'Generating…';
        const r = await fetch('/auth/mfa/enroll/start', { method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json', 'X-CSRF-Token': (getCookie('fleet_csrf')||'') }, body: '{}' });
        const raw = await r.text();
        let d = null; try { d = raw ? JSON.parse(raw) : null; } catch {}
        if (!r.ok) throw new Error((d && (d.detail||d.error)) || raw || 'MFA start failed');
        window.__mfa_qr_data_url = d.qr_data_url || '';
        openMfaModal('setup', d.otpauth_uri || '');
      } catch (e) {
        if (statusEl) statusEl.textContent = e.message;
      }
    }

    async function mfaEnrollConfirm(code) {
      const statusEl = document.getElementById('mfa-modal-status');
      try {
        if (statusEl) statusEl.textContent = 'Confirming…';
        const r = await fetch('/auth/mfa/enroll/confirm', { method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json', 'X-CSRF-Token': (getCookie('fleet_csrf')||'') }, body: JSON.stringify({ code }) });
        const raw = await r.text();
        let d = null; try { d = raw ? JSON.parse(raw) : null; } catch {}
        if (!r.ok) throw new Error((d && (d.detail||d.error)) || raw || 'MFA confirm failed');
        const codes = (d.recovery_codes || []).join('\n');

        // Show recovery codes in a selectable, copyable field.
        const bodyEl = document.getElementById('mfa-modal-body');
        if (bodyEl) {
          bodyEl.innerHTML = `
            <div style="color:var(--muted-2);margin-bottom:0.5rem;">MFA enabled. Save these recovery codes now (you won’t be shown them again).</div>
            <textarea id="mfa-recovery-codes" readonly style="width:100%;min-height:160px;padding:10px;border:1px solid var(--border);border-radius:10px;background:var(--panel-2);color:var(--text);font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;user-select:text;">${escapeHtml(codes || '')}</textarea>
            <div style="margin-top:0.75rem;display:flex;gap:0.5rem;flex-wrap:wrap;justify-content:flex-end;">
              <button class="btn" id="mfa-recovery-copy" type="button">Copy</button>
              <button class="btn btn-primary" id="mfa-recovery-done" type="button">I saved them</button>
            </div>
          `;

          document.getElementById('mfa-recovery-copy')?.addEventListener('click', async () => {
            try {
              const text = (codes || '');
              await navigator.clipboard.writeText(text);
              showToast('Recovery codes copied', 'success');
            } catch (e) {
              showToast('Copy failed (browser blocked clipboard). Select and copy manually.', 'error', 4500);
            }
          });

          document.getElementById('mfa-recovery-done')?.addEventListener('click', async () => {
            if (statusEl) statusEl.textContent = 'MFA enabled.';
            // Force a full reload so all gated API calls start working immediately.
            window.location.reload();
          });
        } else {
          // Fallback
          alert('MFA enabled. Save these recovery codes:\n\n' + (codes || '(none)'));
          if (statusEl) statusEl.textContent = 'MFA enabled.';
          await loadAuthInfo();
          closeMfaModal();
        }
      } catch (e) {
        if (statusEl) statusEl.textContent = e.message;
      }
    }

    async function mfaVerify(code) {
      const statusEl = document.getElementById('mfa-modal-status');
      try {
        if (statusEl) statusEl.textContent = 'Verifying…';
        const r = await fetch('/auth/mfa/verify', { method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json', 'X-CSRF-Token': (getCookie('fleet_csrf')||'') }, body: JSON.stringify({ code }) });
        const raw = await r.text();
        let d = null; try { d = raw ? JSON.parse(raw) : null; } catch {}
        if (!r.ok) throw new Error((d && (d.detail||d.error)) || raw || 'MFA verify failed');
        if (statusEl) statusEl.textContent = 'Verified.';
        // Force a full reload so previously blocked API calls work immediately.
        window.location.reload();
      } catch (e) {
        if (statusEl) statusEl.textContent = e.message;
      }
    }

    function getCookie(name) {
      const m = document.cookie.match('(?:^|; )' + name.replace(/([.$?*|{}()\[\]\\\/\+^])/g, '\\$1') + '=([^;]*)');
      return m ? decodeURIComponent(m[1]) : '';
    }

    // Explicit exports for cross-file calls (auth-state/login flows).
    window.openMfaModal = openMfaModal;
    window.closeMfaModal = closeMfaModal;
    window.mfaEnrollStart = mfaEnrollStart;
    window.mfaEnrollConfirm = mfaEnrollConfirm;
    window.mfaVerify = mfaVerify;
    window.getCookie = getCookie;


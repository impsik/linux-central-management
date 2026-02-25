function openSshKeyDeployApprovalModal(it) {
      const modal = document.getElementById('sshkey-approval-modal');
      const metaEl = document.getElementById('sshkey-approval-modal-meta');
      const targetsEl = document.getElementById('sshkey-approval-modal-targets');
      const stdoutBtn = document.getElementById('sshkey-approval-modal-download-stdout');
      const stderrBtn = document.getElementById('sshkey-approval-modal-download-stderr');
      const zipBtn = document.getElementById('sshkey-approval-modal-download-zip');
      if (!modal || !metaEl || !targetsEl) return;

      const targets = it.targets || (it.agent_ids || []).map(aid => ({ agent_id: String(aid), hostname: String(aid) }));
      const names = targets.map(t => t.hostname || t.agent_id).filter(Boolean);

      const keyShort = (String(it.key_id||'')).slice(0,8);
      const keyName = String(it.key_name || '').trim();
      const keyLabel = keyName ? `${keyName} (${keyShort})` : keyShort;
      let meta = `Requested by: ${it.user_name || it.user_id} · Key: ${keyLabel} · Created: ${formatShortTime(it.created_at)}`;
      if (it.job_id || it.jobId) meta += ` · Job: ${String(it.job_id || it.jobId).slice(0,8)}`;
      metaEl.textContent = meta;

      let body = names.length ? names.join('\n') : '(no targets)';
      if (it.job) {
        const runs = Array.isArray(it.job.runs) ? it.job.runs : [];
        const lines = runs.map(r => `- ${r.agent_id}: ${r.status}${r.exit_code != null ? ` (exit ${r.exit_code})` : ''}${r.error ? ` — ${r.error}` : ''}`);
        body += `\n\nJob result:\n${lines.join('\n') || '(no runs)'}`;
      }
      const jobId = String(it.job_id || it.jobId || '');
      const firstAgentId = (targets && targets.length) ? String(targets[0].agent_id || '') : '';

      // Wire up download buttons
      if (stdoutBtn) {
        if (jobId && firstAgentId) {
          stdoutBtn.href = `/jobs/${encodeURIComponent(jobId)}/runs/${encodeURIComponent(firstAgentId)}/stdout.txt`;
          stdoutBtn.style.display = 'inline-flex';
        } else {
          stdoutBtn.style.display = 'none';
        }
      }
      if (stderrBtn) {
        if (jobId && firstAgentId) {
          stderrBtn.href = `/jobs/${encodeURIComponent(jobId)}/runs/${encodeURIComponent(firstAgentId)}/stderr.txt`;
          stderrBtn.style.display = 'inline-flex';
        } else {
          stderrBtn.style.display = 'none';
        }
      }
      if (zipBtn) {
        if (jobId) {
          zipBtn.href = `/jobs/${encodeURIComponent(jobId)}/logs.zip`;
          zipBtn.style.display = 'inline-flex';
        } else {
          zipBtn.style.display = 'none';
        }
      }

      if (jobId) {
        body += `\n\nDownload logs: /jobs/${jobId}/logs.zip`;
      }
      targetsEl.textContent = body;

      modal.hidden = false;
      modal.classList.add('open');
      modal.setAttribute('aria-hidden', 'false');
    }

    async function openUserModal(agentId, username) {
      const modal = document.getElementById('user-modal');
      const metaEl = document.getElementById('user-modal-meta');
      const outEl = document.getElementById('user-modal-output');
      if (!modal || !metaEl || !outEl) return;

      // Robust close wiring for user modal.
      const closeBtn = document.getElementById('user-modal-close');
      if (closeBtn && !closeBtn.dataset.boundUserClose) {
        closeBtn.addEventListener('click', (e) => {
          e.preventDefault();
          closeUserModal();
        });
        closeBtn.dataset.boundUserClose = '1';
      }
      if (!modal.dataset.boundUserOverlayClose) {
        modal.addEventListener('click', (e) => {
          if (e.target && e.target.id === 'user-modal') closeUserModal();
        });
        modal.dataset.boundUserOverlayClose = '1';
      }

      const safe = (v) => escapeHtml(v == null ? '' : String(v));
      const kv = (k, v) => `<div class="kv-row"><strong>${safe(k)}:</strong> <code>${safe(v || '')}</code></div>`;

      outEl.innerHTML = '<div class="loading">Loading…</div>';
      metaEl.textContent = `Host: ${agentId}`;

      try {
        const r = await fetch(`/hosts/${encodeURIComponent(agentId)}/users/${encodeURIComponent(username)}`, { credentials: 'include' });
        const raw = await r.text();
        if (!r.ok) throw new Error(raw || `user details failed (${r.status})`);
        let d = null;
        try { d = raw ? JSON.parse(raw) : null; } catch { }
        const info = (d && d.user) ? d.user : d;

        const sudoRules = String(info.sudo_rules || '').trim();
        const hasSudoFlag = !!info.has_sudo;
        const deniedByRules = /not allowed to run sudo/i.test(sudoRules) || /may not run sudo/i.test(sudoRules);
        const sudoAllowed = hasSudoFlag && !deniedByRules;

        outEl.innerHTML = [
          kv('Username', info.username),
          kv('UID', info.uid),
          kv('GID', info.gid),
          kv('Home', info.home),
          kv('Shell', info.shell),
          kv('Groups', info.groups),
          kv('Locked', info.locked),
          `<div class="kv-row"><strong>Sudo access:</strong> <span class="status-badge ${sudoAllowed ? 'ok' : 'warn'}">${sudoAllowed ? 'allowed' : 'denied'}</span></div>`,
          kv('Password status', info.password_status),
          kv('Last login', info.last_login),
          sudoRules ? `<details style="margin-top:0.5rem;"><summary>Sudo check output</summary><pre class="pkg-raw" style="margin-top:0.4rem;">${safe(sudoRules)}</pre></details>` : '',
          '<div id="user-modal-timeline" style="margin-top:0.8rem;"></div>',
        ].join('');

        const timelineEl = document.getElementById('user-modal-timeline');
        if (timelineEl) {
          timelineEl.innerHTML = '<div class="loading">Loading recent user timeline…</div>';
          try {
            const tr = await fetch(`/hosts/${encodeURIComponent(agentId)}/timeline?limit=120`, { credentials: 'include' });
            if (!tr.ok) throw new Error(`timeline failed (${tr.status})`);
            const td = await tr.json();
            const items = Array.isArray(td?.items) ? td.items : [];
            const uname = String(info.username || username || '').trim();
            const userTypes = new Set(['query-user-details', 'user-lock', 'user-unlock']);
            const filtered = items.filter((it) => {
              const jt = String(it?.job_type || '').toLowerCase();
              if (!userTypes.has(jt)) return false;
              const pUser = String(it?.payload_username || '').trim();
              return pUser && pUser === uname;
            }).slice(0, 12);
            if (!filtered.length) {
              timelineEl.innerHTML = '<div class="status-muted" style="font-size:0.85rem;">No recent timeline entries for this user.</div>';
            } else {
              timelineEl.innerHTML = [
                '<div class="kv-row" style="margin-top:0.4rem;"><strong>Recent timeline</strong></div>',
                '<div style="display:grid;gap:0.35rem;">',
                filtered.map((it) => {
                  const t = it?.time ? new Date(it.time).toLocaleString() : 'n/a';
                  const st = String(it?.status || 'unknown');
                  const cls = st === 'success' ? 'status-ok' : (st === 'failed' ? 'status-error' : 'status-muted');
                  return `<div style="border:1px solid var(--border);border-radius:8px;padding:0.35rem 0.5rem;background:var(--panel-2);display:flex;justify-content:space-between;gap:0.4rem;align-items:center;">
                    <div style="font-size:0.82rem;">
                      <div><b>${safe(String(it?.job_type || 'job'))}</b></div>
                      <div class="status-muted">${safe(t)}</div>
                    </div>
                    <span class="${cls}" style="font-size:0.76rem;">${safe(st)}</span>
                  </div>`;
                }).join(''),
                '</div>',
              ].join('');
            }
          } catch (te) {
            timelineEl.innerHTML = `<div class="status-muted" style="font-size:0.85rem;">${safe(te?.message || String(te))}</div>`;
          }
        }
      } catch (e) {
        outEl.innerHTML = `<div class="error">${safe(e.message || String(e))}</div>`;
      }

      modal.hidden = false;
      modal.classList.add('open');
      modal.setAttribute('aria-hidden', 'false');
      const titleEl = document.getElementById('user-modal-title');
      if (titleEl) titleEl.textContent = `User details: ${username}`;
    }

    function closeUserModal() {
      const modal = document.getElementById('user-modal');
      if (!modal) return;
      modal.classList.remove('open');
      modal.setAttribute('aria-hidden', 'true');
      modal.hidden = true;
    }

    async function openServiceModal(agentId, serviceName) {
      const modal = document.getElementById('service-modal');
      const metaEl = document.getElementById('service-modal-meta');
      const outEl = document.getElementById('service-modal-output');
      if (!modal || !metaEl || !outEl) return;

      // Robust close wiring for service modal.
      const closeBtn = document.getElementById('service-modal-close');
      if (closeBtn && !closeBtn.dataset.boundServiceClose) {
        closeBtn.addEventListener('click', (e) => {
          e.preventDefault();
          closeServiceModal();
        });
        closeBtn.dataset.boundServiceClose = '1';
      }
      if (!modal.dataset.boundServiceOverlayClose) {
        modal.addEventListener('click', (e) => {
          if (e.target && e.target.id === 'service-modal') closeServiceModal();
        });
        modal.dataset.boundServiceOverlayClose = '1';
      }

      const safe = (v) => escapeHtml(v == null ? '' : String(v));
      const kv = (k, v) => `<div class="kv-row"><strong>${safe(k)}:</strong> <code>${safe(v || '')}</code></div>`;

      outEl.innerHTML = '<div class="loading">Loading…</div>';
      metaEl.textContent = `Host: ${agentId}`;

      try {
        const r = await fetch(`/hosts/${encodeURIComponent(agentId)}/services/${encodeURIComponent(serviceName)}`, { credentials: 'include' });
        const raw = await r.text();
        if (!r.ok) throw new Error(raw || `service details failed (${r.status})`);
        let d = null;
        try { d = raw ? JSON.parse(raw) : null; } catch { }
        const info = (d && d.service) ? d.service : d;

        const mem = info && (info.memory_current_human || info.memory_current);

        outEl.innerHTML = [
          kv('Path', info.fragment_path),
          kv('Memory usage', mem),
          kv('Requires', info.requires),
          kv('Wants', info.wants),
          kv('WantedBy', info.wanted_by),
          kv('ConsistsOf', info.consists_of),
          kv('Conflicts', info.conflicts),
          kv('Before', info.before),
          kv('After', info.after),
        ].join('');
      } catch (e) {
        outEl.innerHTML = `<div class="error">${safe(e.message || String(e))}</div>`;
      }

      modal.hidden = false;
      modal.classList.add('open');
      modal.setAttribute('aria-hidden', 'false');
      const titleEl = document.getElementById('service-modal-title');
      if (titleEl) titleEl.textContent = `Service details: ${serviceName}`;
    }

    function closeServiceModal() {
      const modal = document.getElementById('service-modal');
      if (!modal) return;
      modal.classList.remove('open');
      modal.setAttribute('aria-hidden', 'true');
      modal.hidden = true;
    }

    async function openDiskModal(agentId) {
      const modal = document.getElementById('disk-modal');
      const metaEl = document.getElementById('disk-modal-meta');
      const outEl = document.getElementById('disk-modal-output');
      const refreshBtn = document.getElementById('disk-modal-refresh');
      if (!modal || !metaEl || !outEl) return;

      const pctToColor = (pct) => {
        const p = Math.max(0, Math.min(100, Number(pct) || 0));
        const hue = 120 - (120 * (p / 100)); // 120=green → 0=red
        return `hsl(${hue} 85% 45%)`;
      };

      const parseDf = (stdout, showVirtual = false) => {
        const lines = String(stdout || '').split(/\r?\n/).filter(Boolean);
        if (!lines.length) return [];
        const rows = [];
        for (let i = 1; i < lines.length; i++) {
          const line = lines[i].trim();
          if (!line) continue;
          const parts = line.split(/\s+/);
          // Expected: source fstype size used avail pcent target
          if (parts.length < 7) continue;
          const [source, fstype, size, used, avail, pcent, ...rest] = parts;
          const target = rest.join(' ');
          const pctNum = Number(String(pcent).replace('%',''));

          const fstypeL = String(fstype || '').toLowerCase();
          const sourceL = String(source || '').toLowerCase();

          if (!showVirtual) {
            // Hide virtual/noise filesystems by default
            if (
              fstypeL === 'tmpfs' ||
              fstypeL === 'devtmpfs' ||
              fstypeL === 'overlay' ||
              fstypeL === 'squashfs' ||
              sourceL.startsWith('tmpfs') ||
              sourceL.startsWith('overlay') ||
              sourceL.startsWith('devtmpfs')
            ) {
              continue;
            }
          }

          rows.push({ source, fstype, size, used, avail, pcent, pctNum, target });
        }
        return rows;
      };

      let lastStdout = '';
      const virtualEl = document.getElementById('disk-modal-show-virtual');
      const getShowVirtual = () => !!(virtualEl && virtualEl.checked);

      const renderDfTable = (stdout) => {
        const rows = parseDf(stdout, getShowVirtual());
        if (!rows.length) {
          outEl.textContent = stdout || '(no output)';
          return;
        }
        const header = ['Filesystem','Type','Mounted','Used','Avail','Size','Use%'];
        const html = [];
        html.push(`<div style="overflow-x:auto;overflow-y:visible;">
          <table class="process-table" style="min-width:860px;">
            <thead><tr>${header.map(h=>`<th>${escapeHtml(h)}</th>`).join('')}</tr></thead>
            <tbody>
              ${rows.map(r => {
                const barColor = pctToColor(r.pctNum);
                return `
                  <tr>
                    <td style="font-family:monospace;">${escapeHtml(r.source)}</td>
                    <td>${escapeHtml(r.fstype)}</td>
                    <td style="font-family:monospace;">${escapeHtml(r.target)}</td>
                    <td>${escapeHtml(r.used)}</td>
                    <td>${escapeHtml(r.avail)}</td>
                    <td>${escapeHtml(r.size)}</td>
                    <td style="min-width:140px;">
                      <div style="display:flex;align-items:center;gap:10px;">
                        <div style="flex:1;height:10px;background:rgba(148,163,184,.25);border-radius:999px;overflow:hidden;">
                          <div style="width:${Math.max(0,Math.min(100,r.pctNum||0))}%;height:100%;background:${barColor};"></div>
                        </div>
                        <div style="width:44px;text-align:right;font-variant-numeric:tabular-nums;">${escapeHtml(r.pcent)}</div>
                      </div>
                    </td>
                  </tr>`;
              }).join('')}
            </tbody>
          </table>
        </div>`);
        outEl.innerHTML = html.join('');
      };

      const load = async () => {
        outEl.textContent = 'Loading…';
        try {
          const r = await fetch(`/hosts/${encodeURIComponent(agentId)}/df`, { credentials: 'include' });
          const raw = await r.text();
          if (!r.ok) throw new Error(raw || `df failed (${r.status})`);
          let data = null;
          try { data = raw ? JSON.parse(raw) : null; } catch { }
          lastStdout = (data && data.stdout) ? data.stdout : raw;
          renderDfTable(lastStdout);
        } catch (e) {
          outEl.textContent = e.message || String(e);
        }
      };

      metaEl.textContent = `Host: ${agentId}`;
      refreshBtn && (refreshBtn.onclick = (e) => { e.preventDefault(); load(); });
      if (virtualEl) virtualEl.onchange = () => { renderDfTable(lastStdout); };
      await load();

      modal.hidden = false;
      modal.classList.add('open');
      modal.setAttribute('aria-hidden', 'false');
    }

    function closeDiskModal() {
      const modal = document.getElementById('disk-modal');
      if (!modal) return;
      modal.classList.remove('open');
      modal.setAttribute('aria-hidden', 'true');
      modal.hidden = true;
    }

    function closeSshKeyDeployApprovalModal() {
      const modal = document.getElementById('sshkey-approval-modal');
      if (!modal) return;
      modal.classList.remove('open');
      modal.setAttribute('aria-hidden', 'true');
      modal.hidden = true;
    }


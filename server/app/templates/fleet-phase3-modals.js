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
        ].join('');
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
      const explainService = (svc) => {
        const n = String(svc || '').toLowerCase();
        const map = [
          { test: (x) => x === 'systemd-sysctl.service' || x === 'systemd-sysctl', what: 'Applies kernel sysctl settings from /etc/sysctl.conf and /etc/sysctl.d/*.conf.', why: 'Without it, required kernel/network hardening and tuning values may not be applied.' },
          { test: (x) => x === 'ssh.service' || x === 'sshd.service' || x === 'ssh' || x === 'sshd', what: 'Runs the OpenSSH server so you can connect remotely via SSH.', why: 'If stopped, remote shell access to this host may be unavailable.' },
          { test: (x) => x === 'cron.service' || x === 'crond.service' || x === 'cron', what: 'Executes scheduled cron jobs.', why: 'If stopped, scheduled maintenance and automation tasks will not run.' },
          { test: (x) => x === 'rsyslog.service' || x === 'rsyslog', what: 'Collects and writes system/application logs.', why: 'If stopped, centralized/local log capture can be incomplete.' },
          { test: (x) => x.startsWith('systemd-networkd'), what: 'Manages network interfaces and routing (systemd-networkd).', why: 'If restarted incorrectly, network connectivity can flap.' },
          { test: (x) => x.startsWith('networkmanager'), what: 'Manages network connections and interface profiles.', why: 'Restarting may briefly interrupt network connectivity.' },
          { test: (x) => x === 'systemd-timesyncd.service' || x === 'chronyd.service' || x === 'ntp.service', what: 'Keeps system time synchronized.', why: 'Time drift can break TLS, auth, logs and distributed systems.' },
          { test: (x) => x === 'docker.service', what: 'Runs Docker daemon for container workloads.', why: 'If down, containers and dependent apps may stop.' },
          { test: (x) => x === 'containerd.service', what: 'Runs containerd runtime used by Kubernetes/containers.', why: 'If down, pods/containers may fail to start or run.' },
          { test: (x) => x === 'crio.service' || x === 'cri-o.service', what: 'Runs CRI-O container runtime for Kubernetes workloads.', why: 'If down, kubelet cannot start/manage pods correctly.' },
          { test: (x) => x === 'kubelet.service', what: 'Kubernetes node agent managing pods on this host.', why: 'If down, node health degrades and pods stop reconciling.' },
          { test: (x) => x === 'kube-proxy.service', what: 'Maintains Kubernetes Service networking rules on the node.', why: 'If down, service-to-pod traffic may fail or become inconsistent.' },
          { test: (x) => x === 'etcd.service', what: 'Stores Kubernetes/control-plane state in a distributed key-value store.', why: 'If unhealthy, cluster control-plane operations can fail.' },
          { test: (x) => x === 'flanneld.service' || x === 'flannel.service', what: 'Provides pod network overlay (Flannel) for Kubernetes.', why: 'If down, pod-to-pod networking can break across nodes.' },
          { test: (x) => x.includes('calico'), what: 'Provides Kubernetes networking/policy components (Calico).', why: 'If unhealthy, network policy enforcement and pod networking may fail.' },
          { test: (x) => x.includes('coredns') || x === 'kube-dns.service', what: 'Handles DNS resolution for Kubernetes services and pods.', why: 'If down, service discovery and internal DNS lookups will fail.' },
          { test: (x) => x === 'node-exporter.service' || x === 'prometheus-node-exporter.service', what: 'Exports host metrics for Prometheus scraping.', why: 'If down, host monitoring visibility is reduced.' },
          { test: (x) => x === 'prometheus.service', what: 'Collects and stores time-series metrics from targets.', why: 'If down, monitoring and alert evaluations stop updating.' },
          { test: (x) => x === 'alertmanager.service', what: 'Routes, groups, and deduplicates alerts from Prometheus.', why: 'If down, critical alerts may not be delivered.' },
          { test: (x) => x === 'grafana-server.service' || x === 'grafana.service', what: 'Serves Grafana dashboards and visualizations.', why: 'If down, operational dashboards are unavailable.' },
          { test: (x) => x === 'loki.service', what: 'Aggregates and stores logs for querying (Grafana Loki).', why: 'If down, centralized log search and retention are impacted.' },
          { test: (x) => x === 'promtail.service', what: 'Collects local logs and ships them to Loki.', why: 'If down, new host logs will not reach centralized storage.' },
        ];
        return map.find((it) => it.test(n)) || null;
      };

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

        const svcName = String(info?.name || serviceName || '');
        const expl = explainService(svcName);
        const fallbackExpl = (() => {
          const n = svcName.toLowerCase();
          if (n.startsWith('systemd-')) {
            return {
              what: 'Core systemd unit that supports Linux boot/runtime system management tasks.',
              why: 'Stopping or masking it without understanding dependencies can impact boot flow or system stability.',
            };
          }
          return {
            what: 'Background system service managed by systemd.',
            why: 'If this service is required by other units, disabling/restarting it may affect dependent functionality.',
          };
        })();
        const explEff = expl || fallbackExpl;
        const explHtml = (`<div class="admin-card" style="margin:0 0 0.6rem 0;">` +
          `<div class="admin-card-title" style="padding:0.55rem 0.7rem;">What this service does</div>` +
          `<div class="admin-card-body" style="padding:0.6rem 0.7rem;display:grid;gap:0.35rem;">` +
          `<div><b>Purpose:</b> ${safe(explEff.what)}</div>` +
          `<div><b>Why it matters:</b> ${safe(explEff.why)}</div>` +
          `</div></div>`);

        outEl.innerHTML = [
          explHtml,
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


(function (w) {
  function esc(v) {
    const s = String(v == null ? '' : v);
    if (typeof w.escapeHtml === 'function') return w.escapeHtml(s);
    return s
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  async function loadAnsiblePlaybooks(ctx) {
    const selectEl = document.getElementById('ansible-playbook');
    const statusEl = document.getElementById('ansible-status');
    const runBtn = document.getElementById('ansible-open');
    if (!selectEl) return;
    try {
      if (statusEl) statusEl.textContent = 'Loading playbooks...';
      const resp = await ansibleApiFetch('/ansible/playbooks');
      if (!resp.ok) throw new Error(resp.statusText);
      const data = await resp.json();
      const list = Array.isArray(data)
        ? data
        : (Array.isArray(data?.playbooks) ? data.playbooks : (Array.isArray(data?.items) ? data.items : []));
      ctx.setAnsiblePlaybooks(list);
      const ansiblePlaybooks = ctx.getAnsiblePlaybooks();
      selectEl.innerHTML = '<option value="">Select playbook</option>' + ansiblePlaybooks.map(p => {
        const name = esc(p.name || '');
        return `<option value="${name}">${name}</option>`;
      }).join('');
      if (statusEl) {
        if (ansiblePlaybooks.length) statusEl.textContent = `Loaded ${ansiblePlaybooks.length} playbook(s).`;
        else statusEl.textContent = 'No playbooks found.';
      }
    } catch (e) {
      if (statusEl) statusEl.textContent = `Failed to load playbooks: ${e.message}`;
    } finally {
      if (runBtn) runBtn.disabled = !selectEl.value;
    }
  }

  function resolveAnsibleTargets(ctx) {
    const fromState = Array.from((ctx.getSelectedAgentIds && ctx.getSelectedAgentIds()) || []);
    if (fromState.length) return fromState;

    const checked = Array.from(document.querySelectorAll('.host-select:checked, .hosts-row-select:checked'))
      .map((el) => String(el.getAttribute('data-agent-id') || '').trim())
      .filter(Boolean);
    if (checked.length) return checked;

    const visible = Array.from((ctx.getLastRenderedAgentIds && ctx.getLastRenderedAgentIds()) || [])
      .map((v) => String(v || '').trim())
      .filter(Boolean);
    if (visible.length) return visible;

    if (ctx.getCurrentAgentId && ctx.getCurrentAgentId()) return [ctx.getCurrentAgentId()];
    return [];
  }

  function openAnsibleModal(ctx, playbookName) {
    const inlineStatus = document.getElementById('ansible-status');
    const modal = document.getElementById('ansible-modal');
    const formEl = document.getElementById('ansible-modal-form');
    const metaEl = document.getElementById('ansible-modal-meta');
    const statusEl = document.getElementById('ansible-modal-status');
    const outputEl = document.getElementById('ansible-modal-output');
    const logEl = document.getElementById('ansible-modal-log');
    if (!modal || !formEl || !metaEl || !statusEl || !outputEl || !logEl) {
      if (inlineStatus) inlineStatus.textContent = 'Ansible modal is not available (missing UI element).';
      return;
    }

    const playbook = (ctx.getAnsiblePlaybooks() || []).find(p => p.name === playbookName);
    if (!playbook) {
      if (inlineStatus) inlineStatus.textContent = 'Selected playbook not found in loaded list. Click Refresh.';
      return;
    }
    const targets = resolveAnsibleTargets(ctx);
    if (targets.length === 0) {
      if (inlineStatus) inlineStatus.textContent = 'Select at least one host.';
      return;
    }

    const prompts = Array.isArray(playbook.prompts) ? playbook.prompts : [];
    formEl.innerHTML = '';
    prompts.forEach(p => {
      const field = document.createElement('div');
      field.className = 'modal-field';
      const label = document.createElement('label');
      label.textContent = p.prompt || p.name;
      const input = document.createElement('input');
      input.type = p.private ? 'password' : 'text';
      input.setAttribute('data-var-name', p.name);
      if (p.name === 'server' || p.name === 'target_hosts') {
        input.value = targets.join(' ');
        if (p.name === 'server') input.readOnly = true;
      }
      field.appendChild(label);
      field.appendChild(input);
      formEl.appendChild(field);
    });
    if (prompts.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'modal-meta';
      empty.textContent = 'This playbook has no prompts.';
      formEl.appendChild(empty);
    }

    metaEl.textContent = `Playbook: ${playbook.name} · Targets: ${targets.length}`;
    statusEl.textContent = '';
    statusEl.classList.remove('error', 'success');
    logEl.textContent = '';
    outputEl.textContent = '';
    loadAnsibleLogs();
    modal.hidden = false;
    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
  }

  function closeAnsibleModal() {
    const modal = document.getElementById('ansible-modal');
    if (!modal) return;
    modal.classList.remove('open');
    modal.setAttribute('aria-hidden', 'true');
    modal.hidden = true;
  }

  async function waitForJobDone(jobId, timeoutMs = 60000) {
    const started = Date.now();
    let last = null;
    while (Date.now() - started < timeoutMs) {
      const r = await ansibleApiFetch(`/jobs/${encodeURIComponent(jobId)}`);
      if (!r.ok) throw new Error(`Job status fetch failed (${r.status})`);
      last = await r.json();
      if (last && last.done) return last;
      await new Promise(res => setTimeout(res, 1500));
    }
    return last || { job_id: jobId, done: false, runs: [] };
  }

  function getCookie(name) {
    const v = `; ${document.cookie || ''}`;
    const parts = v.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return '';
  }

  async function ansibleApiFetch(url, init) {
    const opts = init ? { ...init } : {};
    const method = String(opts.method || 'GET').toUpperCase();
    const headers = new Headers(opts.headers || {});
    if (!('credentials' in opts)) opts.credentials = 'include';
    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
      const csrf = getCookie('fleet_csrf');
      if (csrf && !headers.has('X-CSRF-Token')) headers.set('X-CSRF-Token', csrf);
    }
    opts.headers = headers;
    return fetch(url, opts);
  }

  async function runAnsiblePlaybook(ctx) {
    const modal = document.getElementById('ansible-modal');
    const statusEl = document.getElementById('ansible-modal-status');
    const outputEl = document.getElementById('ansible-modal-output');
    const runBtn = document.getElementById('ansible-modal-run');
    const selectEl = document.getElementById('ansible-playbook');
    const formEl = document.getElementById('ansible-modal-form');
    const logEl = document.getElementById('ansible-modal-log');
    const logsStatusEl = document.getElementById('ansible-logs-status');
    const logsListEl = document.getElementById('ansible-logs-list');
    if (!modal || !statusEl || !outputEl || !runBtn || !selectEl || !formEl || !logEl) return;

    const playbookName = selectEl.value;
    const targets = resolveAnsibleTargets(ctx);
    if (!playbookName || targets.length === 0) {
      statusEl.textContent = 'Select a playbook and at least one host.';
      statusEl.classList.add('error');
      return;
    }

    const extraVars = {};
    Array.from(formEl.querySelectorAll('input[data-var-name]')).forEach(input => {
      const name = input.getAttribute('data-var-name');
      if (!name) return;
      extraVars[name] = input.value;
    });

    runBtn.disabled = true;
    statusEl.textContent = 'Running...';
    statusEl.classList.remove('error', 'success');
    logEl.textContent = '';
    if (logsStatusEl) logsStatusEl.textContent = '';
    if (logsListEl) logsListEl.innerHTML = '';
    outputEl.textContent = '';
    try {
      const resp = await ansibleApiFetch('/ansible/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ playbook: playbookName, agent_ids: targets, extra_vars: extraVars }),
      });
      let data = null;
      const rawText = await resp.text();
      if (rawText) {
        try {
          data = JSON.parse(rawText);
        } catch (_) { }
      }
      if (!resp.ok || !data?.ok) {
        const detail = data?.stderr || data?.detail || rawText || '';
        if (resp.status === 401) {
          statusEl.textContent = 'Run failed: session expired. Please sign in again and retry.';
        } else if (resp.status === 403) {
          statusEl.textContent = `Run failed: access denied${detail ? ` (${detail})` : ' (check CSRF token/permissions).'}`;
        } else {
          statusEl.textContent = `Run failed${resp.status ? ` (${resp.status})` : ''}: ${detail || 'Playbook execution failed.'}`;
        }
        statusEl.classList.add('error');
      } else {
        statusEl.textContent = 'Completed successfully.';
        statusEl.classList.add('success');
      }
      if (data?.log_name) {
        const safeName = w.escapeHtml(data.log_name);
        const href = `/ansible/logs/${encodeURIComponent(data.log_name)}`;
        logEl.innerHTML = `Log saved: <a href="${href}" target="_blank" rel="noopener">${safeName}</a>`;
      }
      const combined = [data?.stdout || '', data?.stderr || ''].filter(Boolean).join('\n');
      outputEl.textContent = combined || '(no output)';
    } catch (e) {
      const msg = String(e?.message || e || 'Unknown error');
      if (/failed to fetch/i.test(msg)) {
        statusEl.textContent = 'Run failed: cannot reach API endpoint (/ansible/run). Check network, reverse proxy, login session, and browser console.';
      } else {
        statusEl.textContent = `Run failed: ${msg}`;
      }
      statusEl.classList.add('error');
    } finally {
      runBtn.disabled = false;
    }
  }

  async function loadAnsibleLogs() {
    const logsStatusEl = document.getElementById('ansible-logs-status');
    const logsListEl = document.getElementById('ansible-logs-list');
    if (!logsStatusEl || !logsListEl) return;
    logsStatusEl.textContent = 'Loading logs...';
    logsListEl.innerHTML = '';
    try {
      const resp = await ansibleApiFetch('/ansible/logs?limit=5');
      if (!resp.ok) throw new Error(resp.statusText);
      const data = await resp.json();
      if (!Array.isArray(data) || data.length === 0) {
        logsStatusEl.textContent = 'No logs found.';
        return;
      }
      logsStatusEl.textContent = `${data.length} log(s) (showing latest ${data.length})`;
      logsListEl.innerHTML = data.map(item => {
        const name = w.escapeHtml(item.name || '');
        const href = `/ansible/logs/${encodeURIComponent(item.name)}`;
        const mtime = w.escapeHtml((item.mtime || '').replace('T', ' ').replace('Z', ' UTC'));
        const size = typeof item.size === 'number' ? `${Math.round(item.size / 1024)} KB` : '';
        return `<div><a href="${href}" target="_blank" rel="noopener">${name}</a> · ${mtime} · ${size}</div>`;
      }).join('');
    } catch (e) {
      logsStatusEl.textContent = `Failed to load logs: ${e.message}`;
    }
  }

  function initAnsibleSection(ctx) {
    const selectEl = document.getElementById('ansible-playbook');
    const openBtn = document.getElementById('ansible-open');
    const refreshBtn = document.getElementById('ansible-refresh');
    const modalClose = document.getElementById('ansible-modal-close');
    const modal = document.getElementById('ansible-modal');
    const modalRun = document.getElementById('ansible-modal-run');
    const logsRefresh = document.getElementById('ansible-logs-refresh');
    const outputCopy = document.getElementById('ansible-output-copy');
    const outputEl = document.getElementById('ansible-modal-output');

    refreshBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      loadAnsiblePlaybooks(ctx);
    });

    const syncRunBtnState = () => {
      if (openBtn) openBtn.disabled = !(selectEl && selectEl.value);
    };
    selectEl?.addEventListener('change', syncRunBtnState);
    selectEl?.addEventListener('input', syncRunBtnState);

    openBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      if (!selectEl || !selectEl.value) return;
      openAnsibleModal(ctx, selectEl.value);
    });

    logsRefresh?.addEventListener('click', (e) => {
      e.preventDefault();
      loadAnsibleLogs();
    });

    outputCopy?.addEventListener('click', async (e) => {
      e.preventDefault();
      if (!outputEl) return;
      const text = outputEl.textContent || '';
      if (!text) return;
      try {
        if (navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(text);
          return;
        }
      } catch (_) { }
      try {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      } catch (_) { }
    });

    modalClose?.addEventListener('click', (e) => {
      e.preventDefault();
      closeAnsibleModal();
    });

    modal?.addEventListener('click', (e) => {
      if (e.target === modal) closeAnsibleModal();
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeAnsibleModal();
    });

    modalRun?.addEventListener('click', (e) => {
      e.preventDefault();
      runAnsiblePlaybook(ctx);
    });

    loadAnsiblePlaybooks(ctx);
  }

  w.phase3Ansible = {
    loadAnsiblePlaybooks,
    openAnsibleModal,
    closeAnsibleModal,
    waitForJobDone,
    runAnsiblePlaybook,
    loadAnsibleLogs,
    initAnsibleSection,
  };
})(window);

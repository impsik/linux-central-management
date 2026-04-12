(function (w) {
  function fitTerminalViewport(ctx) {
    const api = ctx || {};
    const term = api.getTerm?.();
    if (!term) return;
    const tab = document.getElementById('terminal-tab');
    if (!tab || !tab.classList.contains('active')) return;
    try {
      const fitAddon = api.getFitAddon?.();
      if (fitAddon && typeof fitAddon.fit === 'function') fitAddon.fit();
    } catch (_) {}
    try { term.focus(); } catch {}
  }

  function initTerminalOnce(ctx) {
    const api = ctx || {};
    if (api.getTerm?.()) return;
    const termEl = document.getElementById('terminal');
    if (!termEl) return;
    const term = new Terminal({
      convertEol: true,
      theme: {
        background: '#1e1e1e',
        foreground: '#d4d4d4',
        cursor: '#aeafad',
        selection: '#264f78',
        black: '#000000',
        red: '#cd3131',
        green: '#0dbc79',
        yellow: '#e5e510',
        blue: '#2472c8',
        magenta: '#bc3fbc',
        cyan: '#11a8cd',
        white: '#e5e5e5',
        brightBlack: '#666666',
        brightRed: '#f14c4c',
        brightGreen: '#23d18b',
        brightYellow: '#f5f543',
        brightBlue: '#3b8eea',
        brightMagenta: '#d670d6',
        brightCyan: '#29b8db',
        brightWhite: '#e5e5e5'
      }
    });
    api.setTerm?.(term);
    term.open(termEl);
    try {
      if (w.FitAddon && typeof w.FitAddon.FitAddon === 'function') {
        const fitAddon = new w.FitAddon.FitAddon();
        api.setFitAddon?.(fitAddon);
        term.loadAddon(fitAddon);
        fitAddon.fit();
      }
    } catch (_) {}
    try { term.focus(); } catch {}
    termEl.addEventListener('mousedown', () => { try { term.focus(); } catch {} });
    termEl.addEventListener('touchstart', () => { try { term.focus(); } catch {} }, { passive: true });
    w.addEventListener('resize', () => {
      w.requestAnimationFrame(() => fitTerminalViewport(api));
    });
  }

  function attachTerminalInputHandlerOnce(ctx) {
    const api = ctx || {};
    const term = api.getTerm?.();
    if (!term || api.getInputHandlerAttached?.()) return;
    api.setInputHandlerAttached?.(true);
    term.onData((data) => {
      const ws = api.getWs?.();
      if (ws && ws.readyState === 1) ws.send(new TextEncoder().encode(data));
    });
  }

  function updateTerminalPendingCmdButton(ctx) {
    const api = ctx || {};
    const btn = document.getElementById('terminal-run-pending-cmd');
    if (!btn) return;
    const pendingCmd = api.getPendingCmd?.();
    btn.style.display = pendingCmd ? 'inline-flex' : 'none';
    btn.disabled = !pendingCmd;
  }

  function runPendingInteractivePackageCommand(ctx) {
    const api = ctx || {};
    const pendingCmd = api.getPendingCmd?.();
    if (!pendingCmd) return;
    const ws = api.getWs?.();
    if (!(ws && ws.readyState === 1)) {
      api.showToast?.('Terminal not connected yet.', 'error', 3500);
      return;
    }
    try {
      ws.send(new TextEncoder().encode(pendingCmd + '\n'));
      api.setPendingCmd?.(null);
      updateTerminalPendingCmdButton(api);
      api.showToast?.('Sent pending package command to terminal', 'success');
    } catch (e) {
      api.showToast?.(`Failed to send pending command: ${e.message || e}`, 'error', 5000);
    }
  }

  function initTerminalPendingCmdButton(ctx) {
    const api = ctx || {};
    const btn = document.getElementById('terminal-run-pending-cmd');
    if (btn && btn.dataset.boundPendingCmd !== '1') {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        runPendingInteractivePackageCommand(api);
      });
      btn.dataset.boundPendingCmd = '1';
    }
    updateTerminalPendingCmdButton(api);
  }

  w.phase3TerminalRuntime = {
    fitTerminalViewport,
    initTerminalOnce,
    attachTerminalInputHandlerOnce,
    updateTerminalPendingCmdButton,
    runPendingInteractivePackageCommand,
    initTerminalPendingCmdButton,
  };
})(window);

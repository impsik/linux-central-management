(function () {
  'use strict';

  function fitTerminalViewport(ctx) {
    const term = ctx.getTerm();
    if (!term) return;
    const tab = document.getElementById('terminal-tab');
    if (!tab || !tab.classList.contains('active')) return;
    try {
      const termFitAddon = ctx.getTermFitAddon();
      if (termFitAddon && typeof termFitAddon.fit === 'function') {
        termFitAddon.fit();
      }
    } catch (_) { }
    try { term.focus(); } catch { }
  }

  function initTerminalOnce(ctx) {
    if (ctx.getTerm()) return;
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
    ctx.setTerm(term);
    term.open(termEl);
    try {
      if (window.FitAddon && typeof window.FitAddon.FitAddon === 'function') {
        const termFitAddon = new window.FitAddon.FitAddon();
        ctx.setTermFitAddon(termFitAddon);
        term.loadAddon(termFitAddon);
        termFitAddon.fit();
      }
    } catch (_) { }
    // Ensure keystrokes go to xterm immediately (otherwise onData won't fire until focused).
    try { term.focus(); } catch { }
    termEl.addEventListener('mousedown', () => { try { term.focus(); } catch { } });
    termEl.addEventListener('touchstart', () => { try { term.focus(); } catch { } }, { passive: true });
    window.addEventListener('resize', () => {
      window.requestAnimationFrame(() => fitTerminalViewport(ctx));
    });
  }

  function attachTerminalInputHandlerOnce(ctx) {
    const term = ctx.getTerm();
    if (!term || ctx.getTerminalInputHandlerAttached()) return;
    ctx.setTerminalInputHandlerAttached(true);
    term.onData(data => {
      const ws = ctx.getWs();
      if (ws && ws.readyState === 1) {
        ws.send(data);
      }
    });
  }

  function updateTerminalPendingCmdButton(ctx) {
    const btn = document.getElementById('terminal-run-pending-cmd');
    if (!btn) return;
    const pendingInteractivePackageCmd = ctx.getPendingInteractivePackageCmd();
    btn.style.display = pendingInteractivePackageCmd ? 'inline-flex' : 'none';
    btn.disabled = !pendingInteractivePackageCmd;
  }

  function runPendingInteractivePackageCommand(ctx) {
    const pendingInteractivePackageCmd = ctx.getPendingInteractivePackageCmd();
    if (!pendingInteractivePackageCmd) return;
    const ws = ctx.getWs();
    if (!(ws && ws.readyState === 1)) {
      ctx.showToast('Terminal not connected yet.', 'error', 3500);
      return;
    }
    try {
      ws.send(pendingInteractivePackageCmd + '\r');
      ctx.setPendingInteractivePackageCmd(null);
      updateTerminalPendingCmdButton(ctx);
      ctx.showToast('Sent pending package command to terminal', 'success');
    } catch (e) {
      ctx.showToast(`Failed to send pending command: ${e.message || e}`, 'error', 5000);
    }
  }

  function connect(ctx, agentId) {
    initTerminalOnce(ctx);
    const term = ctx.getTerm();
    if (!term) return;
    const run = window.connectTerminalSession;
    if (typeof run === 'function') {
      run({
        agentId,
        term,
        getWs: ctx.getWs,
        setWs: ctx.setWs,
        setCurrentAgentId: ctx.setCurrentAgentId
      });
      return;
    }

    ctx.setCurrentAgentId(agentId);
    const currentWs = ctx.getWs();
    if (currentWs) { try { currentWs.close(); } catch { } }
    if (typeof term.reset === 'function') term.reset();
    else term.clear();
    term.write(`Connecting to ${agentId}...\r\n`);
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${location.host}/ws/terminal/${agentId}`);
    ws.binaryType = "arraybuffer";
    ctx.setWs(ws);
  }

  function initTerminalPendingCmdButton(ctx) {
    const btn = document.getElementById('terminal-run-pending-cmd');
    if (btn) {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        runPendingInteractivePackageCommand(ctx);
      });
    }
    updateTerminalPendingCmdButton(ctx);
  }

  window.fleetTerminalUi = {
    fitTerminalViewport,
    initTerminalOnce,
    attachTerminalInputHandlerOnce,
    updateTerminalPendingCmdButton,
    runPendingInteractivePackageCommand,
    connect,
    initTerminalPendingCmdButton,
  };
})();

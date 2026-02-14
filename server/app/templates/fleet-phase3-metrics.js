(function (w) {
  function updateTopProcessesTable(processes) {
    const tbody = document.getElementById('top-processes-body');
    if (typeof w.renderTopProcessesTable === 'function') {
      w.renderTopProcessesTable(tbody, processes, w.escapeHtml);
      return;
    }
    if (!tbody) return;
    if (!processes || processes.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#a0aec0;">No process data</td></tr>';
      return;
    }
    tbody.innerHTML = processes.slice(0, 10).map(function (p) {
      const pid = p.pid ?? '';
      const user = w.escapeHtml(p.user ?? '');
      const cpu = (p.cpu_percent ?? p.cpu ?? 0);
      const mem = (p.mem_percent ?? p.mem ?? 0);
      const cmd = w.escapeHtml(p.command ?? '');
      return `
          <tr>
            <td>${pid}</td>
            <td>${user}</td>
            <td>${Number(cpu).toFixed(1)}</td>
            <td>${Number(mem).toFixed(1)}</td>
            <td>${cmd}</td>
          </tr>
        `;
    }).join('');
  }

  function redrawLoadGraph(ctx) {
    const canvas = document.getElementById('load-graph');
    const loadGraphData = ctx.getLoadGraphData();
    const loadTimeframeSeconds = ctx.getLoadTimeframeSeconds();
    if (!canvas || !loadGraphData || loadGraphData.length < 2) return;

    const paddingTop = 26, paddingBottom = 22, paddingLeft = 6, paddingRight = 6;
    const plotW = canvas.width - paddingLeft - paddingRight;
    const plotH = canvas.height - paddingTop - paddingBottom;

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const now = Date.now();
    const minAllowed = now - loadTimeframeSeconds * 1000;
    const data = loadGraphData.filter(p => p.time && p.time.getTime() >= minAllowed);
    if (data.length < 2) return;

    const maxLoad = Math.max(...data.map(d => d.load), 1) * 1.1;
    const minT = data[0].time.getTime();
    const maxT = data[data.length - 1].time.getTime();
    const rangeT = Math.max(1, maxT - minT);

    ctx.strokeStyle = '#e2e8f0';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 5; i++) {
      const y = paddingTop + (plotH / 5) * i;
      ctx.beginPath();
      ctx.moveTo(paddingLeft, y);
      ctx.lineTo(canvas.width - paddingRight, y);
      ctx.stroke();
    }

    ctx.strokeStyle = '#667eea';
    ctx.lineWidth = 2;
    ctx.beginPath();
    data.forEach((point, index) => {
      const t = point.time.getTime();
      const x = paddingLeft + ((t - minT) / rangeT) * plotW;
      const y = paddingTop + (plotH - (point.load / maxLoad) * plotH);
      if (index === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.stroke();

    ctx.fillStyle = '#718096';
    ctx.font = '11px sans-serif';
    ctx.textBaseline = 'top';
    ctx.textAlign = 'left';
    ctx.fillText(w.formatTimeLabel(new Date(minT), loadTimeframeSeconds), paddingLeft, canvas.height - paddingBottom + 4);
    ctx.textAlign = 'right';
    ctx.fillText(w.formatTimeLabel(new Date(maxT), loadTimeframeSeconds), canvas.width - paddingRight, canvas.height - paddingBottom + 4);

    const last = data[data.length - 1];
    ctx.fillStyle = '#667eea';
    ctx.font = '12px sans-serif';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'alphabetic';
    ctx.fillText(`Load: ${last.load.toFixed(2)} @ ${w.formatTimeLabel(last.time, loadTimeframeSeconds)}`, 10, 20);
  }

  function updateLoadGraph(ctx, loadValue) {
    const canvas = document.getElementById('load-graph');
    if (!canvas) return;
    const graphData = ctx.getLoadGraphData();
    const loadTimeframeSeconds = ctx.getLoadTimeframeSeconds();

    graphData.push({ time: new Date(), load: loadValue });

    const cutoff = Date.now() - (loadTimeframeSeconds * 1000) - 5000;
    while (graphData.length > 0 && graphData[0].time.getTime() < cutoff) graphData.shift();

    const cap = w.getLoadHistoryLimitForRange(loadTimeframeSeconds);
    if (graphData.length > cap) ctx.setLoadGraphData(graphData.slice(graphData.length - cap));

    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    redrawLoadGraph(canvas.getContext('2d'), ctx);
  }

  async function loadHistoricalLoadData(ctx, agentId) {
    try {
      const loadTimeframeSeconds = ctx.getLoadTimeframeSeconds();
      const limit = w.getLoadHistoryLimitForRange(loadTimeframeSeconds);
      const response = await fetch(`/hosts/${agentId}/load-history?since_seconds=${encodeURIComponent(loadTimeframeSeconds)}&limit=${encodeURIComponent(limit)}`);
      if (!response.ok) return;
      const data = await response.json();
      const history = data.history || [];
      ctx.setLoadGraphData(history.map(item => ({ time: new Date(item.time), load: item.load_1min })));

      if (ctx.getLoadGraphData().length > 0) {
        const canvas = document.getElementById('load-graph');
        if (canvas) {
          canvas.width = canvas.offsetWidth;
          canvas.height = canvas.offsetHeight;
          redrawLoadGraph(canvas.getContext('2d'), ctx);
        }
      }
    } catch (error) {
      console.error('Error loading historical load data:', error);
    }
  }

  async function loadTopProcesses(ctx, agentId, silent) {
    const metricsLifecycleState = ctx.getMetricsLifecycleState();
    if (metricsLifecycleState.get('currentMetricsAgentId') !== agentId) return;
    if (metricsLifecycleState.get('topProcessesInFlight')) return;
    metricsLifecycleState.set('topProcessesInFlight', true);
    try {
      const resp = await fetch(`/hosts/${agentId}/top-processes`);
      if (!resp.ok) throw new Error(resp.statusText);
      const data = await resp.json();
      if (metricsLifecycleState.get('currentMetricsAgentId') !== agentId) return;
      updateTopProcessesTable(data.top_processes || []);
    } catch (e) {
      if (!silent) console.error('Error loading top processes:', e);
    } finally {
      metricsLifecycleState.set('topProcessesInFlight', false);
    }
  }

  async function loadMetrics(ctx, agentId, silent) {
    const metricsLifecycleState = ctx.getMetricsLifecycleState();
    if (metricsLifecycleState.get('currentMetricsAgentId') !== agentId) return;

    if (!silent) {
      document.getElementById('disk-usage').textContent = 'Loading...';
      document.getElementById('memory-usage').textContent = 'Loading...';
      document.getElementById('vcpus').textContent = 'Loading...';
      document.getElementById('ip-addresses').textContent = 'Loading...';
    }

    try {
      const response = await fetch(`/hosts/${agentId}/metrics`);
      if (!response.ok) throw new Error(`Failed to load metrics: ${response.statusText}`);
      const data = await response.json();
      if (metricsLifecycleState.get('currentMetricsAgentId') !== agentId) return;

      const toNum = (v) => {
        if (v === null || v === undefined) return null;
        if (typeof v === 'string') {
          const n = parseFloat(v.replace(',', '.'));
          return Number.isFinite(n) ? n : null;
        }
        const n = Number(v);
        return Number.isFinite(n) ? n : null;
      };

      const disk = data.disk_usage || {};
      const diskUsed = toNum(disk.used_gb);
      const diskTotal = toNum(disk.total_gb);
      let diskPct = toNum(disk.percent_used);
      if (diskPct === null && diskUsed !== null && diskTotal && diskTotal > 0) {
        diskPct = (diskUsed / diskTotal) * 100;
      }
      if (diskPct !== null) {
        document.getElementById('disk-usage').textContent = `${diskPct.toFixed(1)}%`;
        if (diskUsed !== null && diskTotal !== null) {
          document.getElementById('disk-details').textContent = `${diskUsed.toFixed(1)} GB / ${diskTotal.toFixed(1)} GB used`;
        }
        document.getElementById('disk-bar').style.width = `${Math.max(0, Math.min(100, diskPct))}%`;
        const hue = 120 - (120 * (Math.max(0, Math.min(100, diskPct)) / 100));
        document.getElementById('disk-bar').style.background = `hsl(${hue} 85% 45%)`;
      }

      const memory = data.memory || {};
      const memUsed = toNum(memory.used_gb);
      const memTotal = toNum(memory.total_gb);
      let memPct = toNum(memory.percent_used);
      if (memPct === null && memUsed !== null && memTotal && memTotal > 0) {
        memPct = (memUsed / memTotal) * 100;
      }
      if (memPct !== null) {
        document.getElementById('memory-usage').textContent = `${memPct.toFixed(1)}%`;
        if (memUsed !== null && memTotal !== null) {
          document.getElementById('memory-details').textContent = `${memUsed.toFixed(2)} GB / ${memTotal.toFixed(2)} GB used`;
        }
        document.getElementById('memory-bar').style.width = `${Math.max(0, Math.min(100, memPct))}%`;
      }

      const cpu = data.cpu || {};
      const vcpus = toNum(cpu.vcpus ?? cpu.cores ?? data.vcpus ?? data.cpu_cores ?? data.cpu_count);
      if (vcpus !== null) document.getElementById('vcpus').textContent = String(vcpus);

      const ips = data.ip_addresses || [];
      if (ips.length > 0) {
        document.getElementById('ip-addresses').textContent = ips.length;
        document.getElementById('ip-list').innerHTML = ips.map(ip => `<div style="font-family: monospace; margin-top: 0.25rem;">${ip}</div>`).join('');
      } else {
        document.getElementById('ip-addresses').textContent = '0';
        document.getElementById('ip-list').innerHTML = '';
      }

      if (cpu.load_1min !== undefined) updateLoadGraph(ctx, cpu.load_1min);
      if (data.top_processes && data.top_processes.length) updateTopProcessesTable(data.top_processes || []);
    } catch (error) {
      console.error('Error loading metrics:', error);
      if (metricsLifecycleState.get('currentMetricsAgentId') === agentId && !silent) {
        // Keep previous values if any; only show hard error when nothing has been rendered yet.
        const diskEl = document.getElementById('disk-usage');
        const memEl = document.getElementById('memory-usage');
        const vcpuEl = document.getElementById('vcpus');
        const ipEl = document.getElementById('ip-addresses');
        if (diskEl && (!diskEl.textContent || diskEl.textContent === '-' || diskEl.textContent === 'Loading...')) diskEl.textContent = 'Error';
        if (memEl && (!memEl.textContent || memEl.textContent === '-' || memEl.textContent === 'Loading...')) memEl.textContent = 'Error';
        if (vcpuEl && (!vcpuEl.textContent || vcpuEl.textContent === '-' || vcpuEl.textContent === 'Loading...')) vcpuEl.textContent = 'Error';
        if (ipEl && (!ipEl.textContent || ipEl.textContent === '-' || ipEl.textContent === 'Loading...')) ipEl.textContent = 'Error';
      }
    }
  }

  w.phase3Metrics = { loadTopProcesses, loadMetrics, loadHistoricalLoadData, redrawLoadGraph, updateLoadGraph, updateTopProcessesTable };
})(window);

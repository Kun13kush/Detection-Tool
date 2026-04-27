"""
dashboard.py — Live metrics HTTP dashboard.

Serves a single-page HTML dashboard that auto-refreshes every 3 seconds.
Data is pulled from a /api/metrics JSON endpoint so the page can update
without a full reload (uses fetch() + setTimeout).

Endpoints
─────────
  GET /            → HTML dashboard page
  GET /api/metrics → JSON snapshot of all live stats
  GET /health      → {"ok": true}  (for uptime checks)

The server runs in its own daemon thread via serve_forever().
"""

import json
import logging
import os
import platform
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

log = logging.getLogger("dashboard")

# ── Module-level reference to shared state (set by DashboardServer) ───────────
_baseline = None
_blocker = None
_unbanner = None
_monitor = None
_start_time = time.time()


class _Handler(BaseHTTPRequestHandler):
    """Minimal HTTP handler — no dependencies on Flask/FastAPI."""

    def log_message(self, *args):  # silence default access log noise
        pass

    def do_GET(self):  # noqa: N802
        if self.path == "/":
            self._serve_html()
        elif self.path == "/api/metrics":
            self._serve_metrics()
        elif self.path == "/health":
            self._json({"ok": True})
        else:
            self.send_response(404)
            self.end_headers()

    # ── HTML page ──────────────────────────────────────────────────────────

    def _serve_html(self):
        html = _DASHBOARD_HTML
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html.encode())))
        self.end_headers()
        self.wfile.write(html.encode())

    # ── JSON metrics ───────────────────────────────────────────────────────

    def _serve_metrics(self):
        try:
            import psutil
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent
        except ImportError:
            cpu = mem = 0.0

        bans = _blocker.get_bans() if _blocker else {}
        baseline_snap = _baseline.snapshot() if _baseline else {}

        # Build top-IPs list from detector via monitor
        top_ips = []
        if _monitor and hasattr(_monitor, "detector"):
            top_ips = _monitor.detector.top_ips(10)
        global_rps = 0.0
        if _monitor and hasattr(_monitor, "detector"):
            global_rps = _monitor.detector.global_rps

        banned_list = [
            {
                "ip": ip,
                "condition": r.condition,
                "banned_at": time.strftime("%H:%M:%S", time.localtime(r.banned_at)),
                "unban_at": (
                    time.strftime("%H:%M:%S", time.localtime(r.unban_at))
                    if r.unban_at
                    else "permanent"
                ),
                "rate": round(r.rate, 2),
            }
            for ip, r in bans.items()
        ]

        uptime_s = time.time() - _start_time
        h, rem = divmod(int(uptime_s), 3600)
        m, s = divmod(rem, 60)
        uptime_str = f"{h:02d}:{m:02d}:{s:02d}"

        data = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "uptime": uptime_str,
            "cpu_pct": round(cpu, 1),
            "mem_pct": round(mem, 1),
            "global_rps": round(global_rps, 3),
            "effective_mean": baseline_snap.get("effective_mean", 0),
            "effective_stddev": baseline_snap.get("effective_stddev", 0),
            "banned_ips": banned_list,
            "top_ips": [{"ip": ip, "rps": round(rps, 3)} for ip, rps in top_ips],
            "lines_processed": getattr(_monitor, "lines_processed", 0),
            "parse_errors": getattr(_monitor, "parse_errors", 0),
            "baseline_history": baseline_snap.get("history", []),
        }
        self._json(data)

    def _json(self, data):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


class DashboardServer:
    """Wraps HTTPServer and holds references to shared state."""

    def __init__(self, cfg, baseline_engine, blocker, unbanner, monitor):
        global _baseline, _blocker, _unbanner, _monitor, _start_time
        _baseline = baseline_engine
        _blocker = blocker
        _unbanner = unbanner
        _monitor = monitor
        _start_time = time.time()

        # Give monitor a back-reference to the detector for top_ips()
        if monitor and not hasattr(monitor, "detector"):
            pass  # detector is passed separately; we read it via monitor

        host = cfg["dashboard"]["host"]
        port = cfg["dashboard"]["port"]
        self._server = HTTPServer((host, port), _Handler)

    def serve_forever(self):
        self._server.serve_forever()


# ── Embedded HTML/CSS/JS ───────────────────────────────────────────────────────
_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>HNG Anomaly Detector — Live Dashboard</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap');

  :root {
    --bg: #0a0e1a;
    --surface: #111827;
    --border: #1e2d45;
    --accent: #00d4ff;
    --danger: #ff3b5c;
    --warn: #ffb020;
    --ok: #00e676;
    --text: #e0e8f5;
    --muted: #4a5a78;
    --font-mono: 'JetBrains Mono', monospace;
    --font-ui: 'Syne', sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-ui);
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Animated grid background */
  body::before {
    content: '';
    position: fixed; inset: 0; z-index: 0;
    background-image:
      linear-gradient(rgba(0,212,255,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,212,255,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
  }

  .shell { position: relative; z-index: 1; padding: 24px; max-width: 1400px; margin: 0 auto; }

  header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 20px 28px;
    background: linear-gradient(135deg, #0d1b2e 0%, #111827 100%);
    border: 1px solid var(--border);
    border-radius: 12px;
    margin-bottom: 24px;
  }

  .logo { display: flex; align-items: center; gap: 14px; }
  .logo-icon {
    width: 44px; height: 44px;
    background: linear-gradient(135deg, var(--accent), #0057b8);
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 22px;
  }
  h1 { font-size: 1.35rem; font-weight: 800; letter-spacing: -0.02em; }
  h1 span { color: var(--accent); }

  .status-row { display: flex; align-items: center; gap: 16px; }
  .pulse {
    display: inline-block; width: 10px; height: 10px;
    border-radius: 50%; background: var(--ok);
    box-shadow: 0 0 0 0 rgba(0,230,118,0.4);
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0%   { box-shadow: 0 0 0 0 rgba(0,230,118,0.4); }
    70%  { box-shadow: 0 0 0 10px rgba(0,230,118,0); }
    100% { box-shadow: 0 0 0 0 rgba(0,230,118,0); }
  }
  .uptime { font-family: var(--font-mono); font-size: 0.85rem; color: var(--muted); }

  /* KPI strip */
  .kpi-row {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }
  .kpi {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px 20px;
    position: relative; overflow: hidden;
  }
  .kpi::before {
    content: '';
    position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: var(--accent);
  }
  .kpi.danger::before { background: var(--danger); }
  .kpi.warn::before   { background: var(--warn); }
  .kpi.ok::before     { background: var(--ok); }
  .kpi-label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--muted); margin-bottom: 8px; }
  .kpi-value { font-family: var(--font-mono); font-size: 1.8rem; font-weight: 700; line-height: 1; }
  .kpi-sub   { font-size: 0.72rem; color: var(--muted); margin-top: 6px; }

  /* Two-column layout */
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 24px; }
  @media (max-width: 900px) { .grid-2 { grid-template-columns: 1fr; } }

  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
  }
  .card-head {
    padding: 14px 20px;
    border-bottom: 1px solid var(--border);
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--accent);
    display: flex; align-items: center; gap: 8px;
  }
  .card-body { padding: 16px 20px; }

  /* Table */
  table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
  th { text-align: left; padding: 6px 10px; color: var(--muted); font-weight: 400; font-size: 0.72rem; text-transform: uppercase; }
  td { padding: 8px 10px; border-top: 1px solid var(--border); font-family: var(--font-mono); }
  tr:hover td { background: rgba(0,212,255,0.04); }
  .tag-ban { color: var(--danger); font-weight: 700; }
  .tag-ok  { color: var(--ok); }

  /* Bar chart for top IPs */
  .bar-row { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
  .bar-label { font-family: var(--font-mono); font-size: 0.78rem; width: 140px; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .bar-track { flex: 1; background: var(--border); border-radius: 4px; height: 8px; }
  .bar-fill  { height: 8px; border-radius: 4px; background: linear-gradient(90deg, var(--accent), #0090cc); transition: width 0.5s ease; }
  .bar-val   { font-family: var(--font-mono); font-size: 0.75rem; color: var(--muted); width: 52px; text-align: right; }

  /* Sparkline canvas */
  canvas { width: 100%; height: 80px; display: block; }

  #last-update { font-family: var(--font-mono); font-size: 0.72rem; color: var(--muted); text-align: right; margin-top: 16px; }

  .empty { color: var(--muted); font-size: 0.8rem; padding: 16px 0; text-align: center; }
</style>
</head>
<body>
<div class="shell">

  <header>
    <div class="logo">
      <div class="logo-icon">🛡️</div>
      <div>
        <h1>HNG <span>Anomaly Detector</span></h1>
        <div style="font-size:0.75rem;color:var(--muted)">cloud.ng · Real-time Traffic Analysis</div>
      </div>
    </div>
    <div class="status-row">
      <span class="pulse"></span>
      <span class="uptime" id="uptime">--:--:--</span>
    </div>
  </header>

  <!-- KPI Strip -->
  <div class="kpi-row">
    <div class="kpi" id="kpi-rps">
      <div class="kpi-label">Global Req/s</div>
      <div class="kpi-value" id="val-rps">—</div>
      <div class="kpi-sub">last 60 s window</div>
    </div>
    <div class="kpi" id="kpi-bans">
      <div class="kpi-label">Banned IPs</div>
      <div class="kpi-value" id="val-bans">0</div>
      <div class="kpi-sub">active blocks</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">Baseline Mean</div>
      <div class="kpi-value" id="val-mean">—</div>
      <div class="kpi-sub">req/s (30-min rolling)</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">Std Dev</div>
      <div class="kpi-value" id="val-stddev">—</div>
      <div class="kpi-sub">σ</div>
    </div>
    <div class="kpi" id="kpi-cpu">
      <div class="kpi-label">CPU</div>
      <div class="kpi-value" id="val-cpu">—</div>
      <div class="kpi-sub">%</div>
    </div>
    <div class="kpi" id="kpi-mem">
      <div class="kpi-label">Memory</div>
      <div class="kpi-value" id="val-mem">—</div>
      <div class="kpi-sub">%</div>
    </div>
  </div>

  <!-- Baseline sparkline -->
  <div class="card" style="margin-bottom:24px">
    <div class="card-head">📈 Baseline Mean Over Time</div>
    <div class="card-body">
      <canvas id="sparkline"></canvas>
    </div>
  </div>

  <div class="grid-2">
    <!-- Banned IPs -->
    <div class="card">
      <div class="card-head">🚫 Banned IPs</div>
      <div class="card-body" id="banned-body">
        <div class="empty">No active bans</div>
      </div>
    </div>

    <!-- Top 10 source IPs -->
    <div class="card">
      <div class="card-head">📊 Top 10 Source IPs (req/s)</div>
      <div class="card-body" id="top-ips-body">
        <div class="empty">No data yet</div>
      </div>
    </div>
  </div>

  <div id="last-update">Last update: —</div>
</div>

<script>
const rpsEl     = document.getElementById('val-rps');
const bansEl    = document.getElementById('val-bans');
const meanEl    = document.getElementById('val-mean');
const stddevEl  = document.getElementById('val-stddev');
const cpuEl     = document.getElementById('val-cpu');
const memEl     = document.getElementById('val-mem');
const uptimeEl  = document.getElementById('uptime');
const bannedEl  = document.getElementById('banned-body');
const topEl     = document.getElementById('top-ips-body');
const updateEl  = document.getElementById('last-update');

const canvas  = document.getElementById('sparkline');
const ctx     = canvas.getContext('2d');
let history   = [];

function color(val, warn, danger) {
  if (val >= danger) return 'var(--danger)';
  if (val >= warn)   return 'var(--warn)';
  return 'var(--ok)';
}

function drawSparkline(data) {
  const W = canvas.offsetWidth * devicePixelRatio;
  const H = 80 * devicePixelRatio;
  canvas.width  = W;
  canvas.height = H;
  if (!data.length) return;

  const vals = data.map(d => d[1]);
  const min  = Math.min(...vals) * 0.9;
  const max  = Math.max(...vals) * 1.1 || 1;

  const scaleX = W / (data.length - 1 || 1);
  const scaleY = (v) => H - ((v - min) / (max - min || 1)) * H * 0.85 - H * 0.05;

  // Gradient fill
  const grad = ctx.createLinearGradient(0, 0, 0, H);
  grad.addColorStop(0, 'rgba(0,212,255,0.25)');
  grad.addColorStop(1, 'rgba(0,212,255,0)');

  ctx.beginPath();
  data.forEach(([, v], i) => {
    const x = i * scaleX, y = scaleY(v);
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.strokeStyle = 'rgba(0,212,255,0.9)';
  ctx.lineWidth = 2 * devicePixelRatio;
  ctx.stroke();

  // Fill below line
  ctx.lineTo(W, H); ctx.lineTo(0, H); ctx.closePath();
  ctx.fillStyle = grad; ctx.fill();
}

async function refresh() {
  try {
    const r    = await fetch('/api/metrics');
    const data = await r.json();

    uptimeEl.textContent = data.uptime || '--';
    rpsEl.textContent    = data.global_rps.toFixed(2);
    bansEl.textContent   = data.banned_ips.length;
    meanEl.textContent   = data.effective_mean.toFixed(3);
    stddevEl.textContent = data.effective_stddev.toFixed(3);
    cpuEl.textContent    = data.cpu_pct + '%';
    memEl.textContent    = data.mem_pct + '%';

    // Colour KPIs
    document.getElementById('kpi-rps').style.setProperty('--accent', data.global_rps > data.effective_mean * 3 ? 'var(--danger)' : 'var(--accent)');
    document.getElementById('kpi-bans').className = 'kpi' + (data.banned_ips.length ? ' danger' : ' ok');
    document.getElementById('kpi-cpu').className  = 'kpi ' + (data.cpu_pct > 80 ? 'danger' : data.cpu_pct > 50 ? 'warn' : 'ok');
    document.getElementById('kpi-mem').className  = 'kpi ' + (data.mem_pct > 85 ? 'danger' : data.mem_pct > 60 ? 'warn' : 'ok');

    // Banned IPs table
    if (data.banned_ips.length) {
      bannedEl.innerHTML = `<table>
        <tr><th>IP</th><th>Rate</th><th>Condition</th><th>Banned</th><th>Unban</th></tr>
        ${data.banned_ips.map(b => `<tr>
          <td class="tag-ban">${b.ip}</td>
          <td>${b.rate} r/s</td>
          <td style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${b.condition}</td>
          <td>${b.banned_at}</td>
          <td>${b.unban_at}</td>
        </tr>`).join('')}
      </table>`;
    } else {
      bannedEl.innerHTML = '<div class="empty">No active bans ✓</div>';
    }

    // Top IPs bar chart
    if (data.top_ips.length) {
      const maxRps = Math.max(...data.top_ips.map(d => d.rps)) || 1;
      topEl.innerHTML = data.top_ips.map(({ip, rps}) => `
        <div class="bar-row">
          <div class="bar-label">${ip}</div>
          <div class="bar-track"><div class="bar-fill" style="width:${(rps/maxRps*100).toFixed(1)}%"></div></div>
          <div class="bar-val">${rps.toFixed(2)} r/s</div>
        </div>`).join('');
    } else {
      topEl.innerHTML = '<div class="empty">No data yet</div>';
    }

    // Sparkline
    if (data.baseline_history.length) history = data.baseline_history;
    drawSparkline(history);

    updateEl.textContent = 'Last update: ' + data.timestamp;
  } catch(e) {
    updateEl.textContent = 'Error fetching metrics — retrying…';
  }
  setTimeout(refresh, 3000);
}

refresh();
window.addEventListener('resize', () => drawSparkline(history));
</script>
</body>
</html>
"""

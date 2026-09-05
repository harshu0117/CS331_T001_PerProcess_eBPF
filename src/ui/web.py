"""
FastAPI Metrics Server, Live Web Dashboard, and REST API.
Includes embedded live background collector service for real-time monitoring and DB persistence.
"""
import os
import sys
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from src.config import TrackerConfig
from src.core.aggregator import FlowAggregator
from src.core.ebpf_loader import BCCBPFLoader, MockBPFLoader
from src.core.process_cache import ProcessCache
from src.storage.db import DatabaseManager
from src.storage.models import ProcessBandwidthSummary
from src.ui.cli import format_bytes, format_rate


class ConfigUpdateRequest(BaseModel):
    proto: Optional[str] = None
    sort_by: Optional[str] = None
    interval: Optional[float] = None


class BackgroundCollector:
    """Runs continuous flow polling, aggregation, and SQLite persistence."""

    def __init__(self, config: Optional[TrackerConfig] = None):
        self.config = config or TrackerConfig()
        self.db = DatabaseManager(self.config.db_path)
        self.process_cache = ProcessCache(ttl_seconds=15)
        self.aggregator = FlowAggregator(config=self.config, process_cache=self.process_cache)
        self.loader = None
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._latest_summaries: List[ProcessBandwidthSummary] = []
        self._last_poll_time = time.time()
        self._total_upload_rate = 0.0
        self._total_download_rate = 0.0
        self._cumulative_sent = 0
        self._cumulative_recv = 0
        self.is_mock_mode = False

    def start(self):
        with self._lock:
            if self.is_running:
                return
            self.is_running = True

            # Determine loader (BCC on Linux root, Mock on Windows or non-root)
            use_mock = (
                self.config.use_mock
                or sys.platform != "linux"
                or (hasattr(os, "geteuid") and os.geteuid() != 0)
            )
            self.is_mock_mode = use_mock

            if use_mock:
                self.loader = MockBPFLoader()
            else:
                try:
                    self.loader = BCCBPFLoader()
                except Exception as e:
                    print(f"[WARN] BCCBPFLoader init failed ({e}), falling back to MockBPFLoader")
                    self.loader = MockBPFLoader()
                    self.is_mock_mode = True

            try:
                self.loader.load()
            except Exception as e:
                print(f"[WARN] Failed to load eBPF probe ({e}), falling back to MockBPFLoader")
                self.loader = MockBPFLoader()
                self.loader.load()
                self.is_mock_mode = True

            self._thread = threading.Thread(target=self._run_loop, daemon=True)
            self._thread.start()
            print(f"[INFO] Background collector started (Mock Mode: {self.is_mock_mode})")

    def _run_loop(self):
        self._last_poll_time = time.time()
        while self.is_running:
            try:
                raw_metrics = self.loader.poll_flow_stats()
                now = time.time()
                elapsed_sec = max(now - self._last_poll_time, 0.001)
                self._last_poll_time = now

                # Ingest & calculate rates
                snapshots = self.aggregator.process_raw_metrics(raw_metrics, interval_sec=elapsed_sec)
                self.db.insert_snapshot_batch(snapshots)

                # Summarize with active filters
                summaries = self.aggregator.summarize_by_process(snapshots, interval_sec=elapsed_sec)

                tot_ul_rate = sum(s.send_rate_bps for s in summaries)
                tot_dl_rate = sum(s.recv_rate_bps for s in summaries)
                tot_sent = sum(s.total_bytes_sent for s in summaries)
                tot_recv = sum(s.total_bytes_recv for s in summaries)

                with self._lock:
                    self._latest_summaries = summaries
                    self._total_upload_rate = tot_ul_rate
                    self._total_download_rate = tot_dl_rate
                    self._cumulative_sent = tot_sent
                    self._cumulative_recv = tot_recv

            except Exception as e:
                print(f"[ERROR] Collector loop error: {e}")

            time.sleep(self.config.poll_interval_sec)

    def get_live_state(self) -> Dict[str, Any]:
        with self._lock:
            processes = []
            for s in self._latest_summaries:
                processes.append({
                    "pid": s.pid,
                    "comm": s.comm,
                    "protocol": s.protocol_label,
                    "remote_ips": s.remote_ips_str,
                    "upload_rate_bps": s.send_rate_bps,
                    "upload_rate_str": format_rate(s.send_rate_bps),
                    "download_rate_bps": s.recv_rate_bps,
                    "download_rate_str": format_rate(s.recv_rate_bps),
                    "total_sent_bytes": s.total_bytes_sent,
                    "total_sent_str": format_bytes(s.total_bytes_sent),
                    "total_recv_bytes": s.total_bytes_recv,
                    "total_recv_str": format_bytes(s.total_bytes_recv),
                })

            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "is_mock_mode": self.is_mock_mode,
                "protocol_filter": self.config.protocol_filter,
                "sort_by": self.config.sort_by,
                "poll_interval": self.config.poll_interval_sec,
                "process_count": len(processes),
                "total_upload_rate_bps": self._total_upload_rate,
                "total_upload_rate_str": format_rate(self._total_upload_rate),
                "total_download_rate_bps": self._total_download_rate,
                "total_download_rate_str": format_rate(self._total_download_rate),
                "cumulative_sent_bytes": self._cumulative_sent,
                "cumulative_sent_str": format_bytes(self._cumulative_sent),
                "cumulative_recv_bytes": self._cumulative_recv,
                "cumulative_recv_str": format_bytes(self._cumulative_recv),
                "processes": processes,
            }

    def stop(self):
        with self._lock:
            self.is_running = False
            if self.loader:
                try:
                    self.loader.cleanup()
                except Exception:
                    pass


collector = BackgroundCollector()


@asynccontextmanager
async def lifespan(app: FastAPI):
    collector.start()
    yield
    collector.stop()


app = FastAPI(
    title="eBPF Real-Time Network Usage Tracker",
    description="Real-Time process network bandwidth attribution & analytics",
    version="2.0.0",
    lifespan=lifespan,
)


@app.get("/api/v1/health")
def health_check():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat(), "mock_mode": collector.is_mock_mode}


@app.get("/api/v1/live")
def get_live_metrics():
    """Returns live instantaneous process bandwidth summaries."""
    return collector.get_live_state()


@app.get("/api/v1/top-processes")
def get_top_processes(
    hours: float = Query(default=1.0, ge=0.1, le=168.0),
    limit: int = Query(default=10, ge=1, le=100),
    proto: Optional[str] = Query(default="ALL"),
):
    """Queries top bandwidth consuming processes from SQLite."""
    start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
    records = collector.db.get_top_processes(start_time=start_time, limit=limit, proto=proto)
    formatted = []
    for r in records:
        dl = r.get("total_recv", 0)
        ul = r.get("total_sent", 0)
        tot = r.get("total_bytes", dl + ul)
        formatted.append({
            "pid": r.get("pid"),
            "comm": r.get("comm"),
            "download_bytes": dl,
            "download_str": format_bytes(dl),
            "upload_bytes": ul,
            "upload_str": format_bytes(ul),
            "total_bytes": tot,
            "total_str": format_bytes(tot),
            "distinct_ips": r.get("distinct_ips", 1),
        })
    return {
        "time_window_hours": hours,
        "proto": proto,
        "count": len(formatted),
        "processes": formatted,
    }


@app.get("/api/v1/ip-breakdown")
def get_ip_breakdown(
    pid: Optional[int] = None,
    hours: float = Query(default=1.0, ge=0.1, le=168.0),
    limit: int = Query(default=20, ge=1, le=100),
):
    """Returns remote IP breakdown from SQLite."""
    start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
    records = collector.db.get_remote_ip_breakdown(pid=pid, start_time=start_time, limit=limit)
    formatted = []
    for r in records:
        b = r.get("total_bytes", 0)
        formatted.append({
            "remote_ip": r.get("remote_ip"),
            "proto": r.get("proto"),
            "total_bytes": b,
            "total_str": format_bytes(b),
            "total_packets": r.get("total_packets", 0),
        })
    return {"pid": pid, "time_window_hours": hours, "remotes": formatted}


@app.get("/api/v1/protocol-stats")
def get_protocol_stats(hours: float = Query(default=1.0, ge=0.1, le=168.0)):
    """Returns protocol byte distribution (TCP vs UDP) from SQLite."""
    start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
    raw_dist = collector.db.get_protocol_distribution(start_time=start_time)
    total = sum(raw_dist.values()) or 1
    stats = {}
    for proto, bytes_val in raw_dist.items():
        stats[proto] = {
            "bytes": bytes_val,
            "formatted": format_bytes(bytes_val),
            "percentage": round((bytes_val / total) * 100, 1),
        }
    return {"time_window_hours": hours, "total_bytes": total, "total_str": format_bytes(total), "protocols": stats}


@app.post("/api/v1/config")
def update_config(req: ConfigUpdateRequest):
    """Dynamically updates live filtering or sorting parameters."""
    if req.proto:
        collector.config.protocol_filter = req.proto.upper()
    if req.sort_by:
        collector.config.sort_by = req.sort_by.lower()
    if req.interval:
        collector.config.poll_interval_sec = max(0.2, min(req.interval, 10.0))
    return {
        "status": "updated",
        "proto": collector.config.protocol_filter,
        "sort_by": collector.config.sort_by,
        "interval": collector.config.poll_interval,
    }


@app.get("/", response_class=HTMLResponse)
def get_web_dashboard():
    """Renders the comprehensive single-page dashboard."""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>eBPF Real-Time Network Tracker</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #090d16;
            --bg-card: #111827;
            --bg-card-hover: #1e293b;
            --border-color: #1f293d;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent-cyan: #38bdf8;
            --accent-green: #22c55e;
            --accent-magenta: #e879f9;
            --accent-yellow: #facc15;
            --accent-red: #f43f5e;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', -apple-system, sans-serif;
            background-color: var(--bg-base);
            color: var(--text-primary);
            padding: 24px;
            line-height: 1.5;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 24px;
        }

        .title-group h1 {
            font-size: 1.5rem;
            font-weight: 700;
            color: #ffffff;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .badge-live {
            background: rgba(34, 197, 94, 0.15);
            color: var(--accent-green);
            font-size: 0.75rem;
            font-weight: 600;
            padding: 3px 8px;
            border-radius: 9999px;
            border: 1px solid rgba(34, 197, 94, 0.3);
            display: inline-flex;
            align-items: center;
            gap: 5px;
        }

        .badge-live::before {
            content: '';
            width: 7px;
            height: 7px;
            background-color: var(--accent-green);
            border-radius: 50%;
            display: inline-block;
            box-shadow: 0 0 8px var(--accent-green);
        }

        .badge-mode {
            background: rgba(56, 189, 248, 0.12);
            color: var(--accent-cyan);
            font-size: 0.75rem;
            font-weight: 600;
            padding: 3px 10px;
            border-radius: 9999px;
            border: 1px solid rgba(56, 189, 248, 0.25);
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 16px 20px;
            position: relative;
            overflow: hidden;
        }

        .stat-card .label {
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 600;
            margin-bottom: 6px;
        }

        .stat-card .value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.55rem;
            font-weight: 700;
        }

        .stat-card.upload .value { color: var(--accent-magenta); }
        .stat-card.download .value { color: var(--accent-green); }
        .stat-card.sent .value { color: #c084fc; }
        .stat-card.recv .value { color: #4ade80; }
        .stat-card.procs .value { color: var(--accent-cyan); }

        .toolbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 12px 18px;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 12px;
        }

        .search-box {
            background: #0f172a;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 8px 14px;
            color: #fff;
            font-family: inherit;
            font-size: 0.88rem;
            width: 280px;
            outline: none;
        }

        .search-box:focus {
            border-color: var(--accent-cyan);
        }

        .filter-group {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .btn-filter {
            background: #0f172a;
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            font-weight: 600;
            font-size: 0.8rem;
            padding: 6px 14px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.15s ease;
        }

        .btn-filter:hover {
            color: #fff;
            border-color: #475569;
        }

        .btn-filter.active {
            background: rgba(56, 189, 248, 0.18);
            border-color: var(--accent-cyan);
            color: var(--accent-cyan);
        }

        .select-sort {
            background: #0f172a;
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            font-weight: 500;
            font-size: 0.8rem;
            padding: 6px 12px;
            border-radius: 8px;
            outline: none;
            cursor: pointer;
        }

        .table-container {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            margin-bottom: 28px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-family: 'Inter', sans-serif;
            font-size: 0.88rem;
        }

        th {
            background: #0d1322;
            color: var(--text-muted);
            font-size: 0.76rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-color);
            text-align: left;
            font-weight: 600;
        }

        td {
            padding: 12px 16px;
            border-bottom: 1px solid #172033;
            color: var(--text-primary);
        }

        tr:last-child td {
            border-bottom: none;
        }

        tr:hover td {
            background-color: var(--bg-card-hover);
        }

        .font-mono {
            font-family: 'JetBrains Mono', monospace;
        }

        .td-pid { color: var(--accent-cyan); font-weight: 600; text-align: right; width: 80px; }
        .td-comm { font-weight: 600; color: #ffffff; }
        .td-proto { text-align: center; width: 90px; }
        .td-ip { color: #38bdf8; font-size: 0.82rem; }
        .td-upload { color: var(--accent-magenta); text-align: right; font-weight: 600; width: 120px; }
        .td-download { color: var(--accent-green); text-align: right; font-weight: 600; width: 120px; }
        .td-sent { color: var(--text-secondary); text-align: right; width: 110px; }
        .td-recv { color: var(--text-secondary); text-align: right; width: 110px; }

        .proto-badge {
            font-size: 0.7rem;
            font-weight: 700;
            padding: 2px 7px;
            border-radius: 4px;
        }
        .proto-tcp { background: rgba(250, 204, 21, 0.15); color: var(--accent-yellow); border: 1px solid rgba(250, 204, 21, 0.3); }
        .proto-udp { background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3); }

        .bottom-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
        }

        .panel {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
        }

        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }

        .panel-title {
            font-size: 1rem;
            font-weight: 700;
            color: #ffffff;
        }

        .time-tabs {
            display: flex;
            gap: 6px;
        }

        .tab-btn {
            background: #0f172a;
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            font-size: 0.75rem;
            padding: 4px 10px;
            border-radius: 6px;
            cursor: pointer;
        }

        .tab-btn.active {
            background: rgba(56, 189, 248, 0.2);
            border-color: var(--accent-cyan);
            color: var(--accent-cyan);
            font-weight: 600;
        }

        .progress-bar-container {
            background: #0f172a;
            border-radius: 9999px;
            height: 12px;
            overflow: hidden;
            display: flex;
            margin: 12px 0;
        }

        .progress-tcp { background: var(--accent-yellow); height: 100%; transition: width 0.3s ease; }
        .progress-udp { background: #c084fc; height: 100%; transition: width 0.3s ease; }

        @media (max-width: 900px) {
            .bottom-grid { grid-template-columns: 1fr; }
            .toolbar { flex-direction: column; align-items: stretch; }
            .search-box { width: 100%; }
        }
    </style>
</head>
<body>

    <header>
        <div class="title-group">
            <h1>🚀 eBPF Real-Time Network Usage Tracker</h1>
            <div style="display: flex; gap: 8px; margin-top: 6px;">
                <span class="badge-live">LIVE MONITORING</span>
                <span id="mode-badge" class="badge-mode">Initializing...</span>
            </div>
        </div>
        <div style="display: flex; align-items: center; gap: 12px;">
            <label style="font-size: 0.8rem; color: var(--text-muted); font-weight: 500;">Auto-Refresh:</label>
            <select id="select-refresh" class="select-sort" onchange="updateRefreshInterval(this.value)">
                <option value="1000">1.0s</option>
                <option value="2000">2.0s</option>
                <option value="5000">5.0s</option>
                <option value="0">Pause</option>
            </select>
        </div>
    </header>

    <!-- Top Summary Stat Cards -->
    <div class="stats-grid">
        <div class="stat-card upload">
            <div class="label">Total Upload Speed</div>
            <div id="stat-upload" class="value">0.0 B/s</div>
        </div>
        <div class="stat-card download">
            <div class="label">Total Download Speed</div>
            <div id="stat-download" class="value">0.0 B/s</div>
        </div>
        <div class="stat-card sent">
            <div class="label">Cumulative Sent</div>
            <div id="stat-sent" class="value">0.0 B</div>
        </div>
        <div class="stat-card recv">
            <div class="label">Cumulative Recv</div>
            <div id="stat-recv" class="value">0.0 B</div>
        </div>
        <div class="stat-card procs">
            <div class="label">Active Processes</div>
            <div id="stat-procs" class="value">0</div>
        </div>
    </div>

    <!-- Filter & Sort Toolbar -->
    <div class="toolbar">
        <input type="text" id="search-input" class="search-box" placeholder="Search by PID, name or remote IP..." oninput="renderTable()">
        
        <div class="filter-group">
            <span style="font-size: 0.8rem; color: var(--text-muted); font-weight: 500;">Protocol:</span>
            <button class="btn-filter active" onclick="setProtocolFilter('ALL', this)">ALL</button>
            <button class="btn-filter" onclick="setProtocolFilter('TCP', this)">TCP</button>
            <button class="btn-filter" onclick="setProtocolFilter('UDP', this)">UDP</button>
        </div>

        <div class="filter-group">
            <span style="font-size: 0.8rem; color: var(--text-muted); font-weight: 500;">Sort By:</span>
            <select id="select-sort" class="select-sort" onchange="setSortBy(this.value)">
                <option value="total">Total Rate</option>
                <option value="upload">Upload Rate</option>
                <option value="download">Download Rate</option>
                <option value="sent">Total Sent</option>
                <option value="recv">Total Recv</option>
                <option value="pid">PID</option>
                <option value="comm">Process Name</option>
            </select>
        </div>
    </div>

    <!-- Live Process Network Bandwidth Table -->
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th style="text-align: right;">PID</th>
                    <th>Process Name</th>
                    <th style="text-align: center;">Protocol</th>
                    <th>Remote IP Address</th>
                    <th style="text-align: right;">Upload Rate</th>
                    <th style="text-align: right;">Download Rate</th>
                    <th style="text-align: right;">Total Sent</th>
                    <th style="text-align: right;">Total Recv</th>
                </tr>
            </thead>
            <tbody id="table-body">
                <tr>
                    <td colspan="8" style="text-align: center; color: var(--text-muted); padding: 30px;">
                        Fetching live socket streams...
                    </td>
                </tr>
            </tbody>
        </table>
    </div>

    <!-- Bottom Analytics: Historical Rollup & Protocol Breakdown -->
    <div class="bottom-grid">
        <div class="panel">
            <div class="panel-header">
                <div class="panel-title">📜 Historical Network Usage (SQLite)</div>
                <div class="time-tabs">
                    <button class="tab-btn active" onclick="loadHistory(1, this)">1h</button>
                    <button class="tab-btn" onclick="loadHistory(6, this)">6h</button>
                    <button class="tab-btn" onclick="loadHistory(24, this)">24h</button>
                    <button class="tab-btn" onclick="loadHistory(168, this)">7d</button>
                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Process</th>
                        <th style="text-align: right;">PID</th>
                        <th style="text-align: right;">Download</th>
                        <th style="text-align: right;">Upload</th>
                        <th style="text-align: right;">Total Bandwidth</th>
                    </tr>
                </thead>
                <tbody id="history-body">
                    <tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Loading historical logs...</td></tr>
                </tbody>
            </table>
        </div>

        <div class="panel">
            <div class="panel-header">
                <div class="panel-title">📊 Protocol Distribution</div>
            </div>
            <div id="proto-summary-text" style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 8px;">
                Computing traffic share...
            </div>
            <div class="progress-bar-container">
                <div id="bar-tcp" class="progress-tcp" style="width: 50%;"></div>
                <div id="bar-udp" class="progress-udp" style="width: 50%;"></div>
            </div>
            <div style="display: flex; justify-content: space-between; font-size: 0.78rem; font-weight: 600; margin-top: 12px;">
                <span style="color: var(--accent-yellow);">● TCP: <span id="tcp-share">0%</span></span>
                <span style="color: #c084fc;">● UDP: <span id="udp-share">0%</span></span>
            </div>

            <div style="margin-top: 28px;">
                <div class="panel-title" style="margin-bottom: 12px; font-size: 0.92rem;">🏆 Top 3 Talkers (Past 1h)</div>
                <div id="top-talkers-list" style="font-size: 0.85rem; display: flex; flex-direction: column; gap: 8px;">
                    Loading...
                </div>
            </div>
        </div>
    </div>

    <script>
        let liveProcesses = [];
        let currentProtoFilter = 'ALL';
        let currentSort = 'total';
        let refreshTimer = null;
        let refreshInterval = 1000;

        async function fetchLiveMetrics() {
            try {
                const res = await fetch('/api/v1/live');
                if (!res.ok) return;
                const data = await res.json();

                // Update Badges
                const modeBadge = document.getElementById('mode-badge');
                if (data.is_mock_mode) {
                    modeBadge.innerText = 'SIMULATION (12 ACTIVE PROCESSES)';
                    modeBadge.style.color = '#38bdf8';
                } else {
                    modeBadge.innerText = 'LINUX KERNEL eBPF PROBE';
                    modeBadge.style.color = '#22c55e';
                }

                // Update Stats
                document.getElementById('stat-upload').innerText = data.total_upload_rate_str;
                document.getElementById('stat-download').innerText = data.total_download_rate_str;
                document.getElementById('stat-sent').innerText = data.cumulative_sent_str;
                document.getElementById('stat-recv').innerText = data.cumulative_recv_str;
                document.getElementById('stat-procs').innerText = data.process_count;

                liveProcesses = data.processes || [];
                renderTable();
            } catch (err) {
                console.error("Live fetch error:", err);
            }
        }

        function renderTable() {
            const tbody = document.getElementById('table-body');
            const search = document.getElementById('search-input').value.toLowerCase().trim();

            let filtered = liveProcesses.filter(p => {
                if (currentProtoFilter !== 'ALL' && p.protocol !== currentProtoFilter) return false;
                if (search) {
                    const matchName = p.comm.toLowerCase().includes(search);
                    const matchPid = String(p.pid).includes(search);
                    const matchIp = p.remote_ips.toLowerCase().includes(search);
                    return matchName || matchPid || matchIp;
                }
                return true;
            });

            if (filtered.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 24px;">No processes matching filter.</td></tr>';
                return;
            }

            let html = '';
            filtered.forEach(p => {
                const protoBadge = p.protocol === 'TCP' 
                    ? '<span class="proto-badge proto-tcp">TCP</span>'
                    : '<span class="proto-badge proto-udp">UDP</span>';

                html += `
                    <tr>
                        <td class="td-pid font-mono">${p.pid}</td>
                        <td class="td-comm">${p.comm}</td>
                        <td class="td-proto">${protoBadge}</td>
                        <td class="td-ip font-mono">${p.remote_ips}</td>
                        <td class="td-upload font-mono">${p.upload_rate_str}</td>
                        <td class="td-download font-mono">${p.download_rate_str}</td>
                        <td class="td-sent font-mono">${p.total_sent_str}</td>
                        <td class="td-recv font-mono">${p.total_recv_str}</td>
                    </tr>
                `;
            });
            tbody.innerHTML = html;
        }

        async function setProtocolFilter(proto, btn) {
            currentProtoFilter = proto;
            document.querySelectorAll('.btn-filter').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            await fetch('/api/v1/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ proto: proto })
            });
            fetchLiveMetrics();
        }

        async function setSortBy(sortBy) {
            currentSort = sortBy;
            await fetch('/api/v1/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sort_by: sortBy })
            });
            fetchLiveMetrics();
        }

        function updateRefreshInterval(val) {
            refreshInterval = parseInt(val);
            if (refreshTimer) clearInterval(refreshTimer);
            if (refreshInterval > 0) {
                refreshTimer = setInterval(fetchLiveMetrics, refreshInterval);
            }
        }

        async function loadHistory(hours, btn) {
            if (btn) {
                document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
            }
            try {
                const res = await fetch(`/api/v1/top-processes?hours=${hours}&limit=8`);
                const data = await res.json();
                const tbody = document.getElementById('history-body');
                if (!data.processes || data.processes.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No historical records found for this window.</td></tr>';
                    return;
                }
                let html = '';
                data.processes.forEach(p => {
                    html += `
                        <tr>
                            <td class="td-comm">${p.comm}</td>
                            <td class="td-pid font-mono">${p.pid}</td>
                            <td style="color: var(--accent-green); text-align: right;" class="font-mono">${p.download_str}</td>
                            <td style="color: var(--accent-magenta); text-align: right;" class="font-mono">${p.upload_str}</td>
                            <td style="color: var(--accent-yellow); text-align: right; font-weight: 600;" class="font-mono">${p.total_str}</td>
                        </tr>
                    `;
                });
                tbody.innerHTML = html;
            } catch (err) {
                console.error("History fetch error:", err);
            }
        }

        async function loadProtocolStats() {
            try {
                const res = await fetch('/api/v1/protocol-stats?hours=1');
                const data = await res.json();
                const tcpBytes = (data.protocols && data.protocols.TCP) ? data.protocols.TCP.bytes : 0;
                const udpBytes = (data.protocols && data.protocols.UDP) ? data.protocols.UDP.bytes : 0;
                const total = tcpBytes + udpBytes;

                if (total > 0) {
                    const tcpPct = Math.round((tcpBytes / total) * 100);
                    const udpPct = 100 - tcpPct;
                    document.getElementById('bar-tcp').style.width = tcpPct + '%';
                    document.getElementById('bar-udp').style.width = udpPct + '%';
                    document.getElementById('tcp-share').innerText = `${tcpPct}% (${data.protocols.TCP.formatted})`;
                    document.getElementById('udp-share').innerText = `${udpPct}% (${data.protocols.UDP.formatted})`;
                    document.getElementById('proto-summary-text').innerText = `Total Monitored: ${data.total_str}`;
                }

                // Top 3 Talkers
                const topRes = await fetch('/api/v1/top-processes?hours=1&limit=3');
                const topData = await topRes.json();
                const topList = document.getElementById('top-talkers-list');
                if (topData.processes && topData.processes.length > 0) {
                    let html = '';
                    topData.processes.forEach((p, idx) => {
                        html += `
                            <div style="display: flex; justify-content: space-between; padding: 6px 10px; background: #0f172a; border-radius: 6px; border: 1px solid var(--border-color);">
                                <span><b>#${idx+1}</b> ${p.comm} <span style="color: var(--text-muted); font-size: 0.75rem;">(PID ${p.pid})</span></span>
                                <span style="font-weight: 600; color: var(--accent-yellow);" class="font-mono">${p.total_str}</span>
                            </div>
                        `;
                    });
                    topList.innerHTML = html;
                }
            } catch (err) {
                console.error("Proto stats error:", err);
            }
        }

        // Initialize
        fetchLiveMetrics();
        loadHistory(1);
        loadProtocolStats();
        refreshTimer = setInterval(fetchLiveMetrics, refreshInterval);
        setInterval(loadProtocolStats, 5000);
    </script>
</body>
</html>
    """

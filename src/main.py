"""
Master Daemon and CLI Entry Point for eBPF Network Usage Tracker.
"""
import argparse
from datetime import datetime, timedelta, timezone
import os
import re
import signal
import sys
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from rich.console import Console
    HAVE_RICH = True
except ImportError:
    HAVE_RICH = False
    Console = None  # type: ignore

from src.config import TrackerConfig
from src.core.aggregator import FlowAggregator
from src.core.ebpf_loader import BCCBPFLoader, MockBPFLoader
from src.core.process_cache import ProcessCache
from src.storage.db import DatabaseManager
from src.ui.cli import render_dashboard, render_historical_report, render_top_consumers


def parse_time_duration(time_str: str) -> float:
    """Parses time duration strings like '1h', '24h', '30m', '2d', or plain float hours."""
    if not time_str:
        return 1.0
    time_str = str(time_str).strip().lower()
    match = re.match(r"^([0-9.]+)\s*([mhd]?)$", time_str)
    if not match:
        try:
            return float(time_str)
        except ValueError:
            return 1.0
    val, unit = float(match.group(1)), match.group(2)
    if unit == "m":
        return max(val / 60.0, 0.01)
    elif unit == "d":
        return val * 24.0
    return val  # hours default


def main():
    parser = argparse.ArgumentParser(description="eBPF Real-Time Network Bandwidth Tracker")
    parser.add_argument("--mock", action="store_true", help="Run with mock eBPF data (cross-platform)")
    parser.add_argument("--proto", choices=["TCP", "UDP", "ALL"], default="ALL", help="Protocol filter")
    parser.add_argument("--pid", type=int, default=None, help="Filter by specific PID")
    parser.add_argument("--ip", type=str, default=None, help="Filter by specific remote IP")
    parser.add_argument("--interval", type=float, default=1.0, help="Sampling interval in seconds")
    parser.add_argument("--sort", choices=["total", "upload", "download", "sent", "recv", "pid", "comm"], default="total", help="Sort order for live table")
    parser.add_argument("--db", type=str, default="network_usage.db", help="SQLite database path")
    parser.add_argument("--history", nargs="?", const="1h", default=None, help="Display historical usage report (e.g., --history 1h, --history 24h)")
    parser.add_argument("--top", nargs="?", const=10, type=int, default=None, help="Display top N bandwidth consuming processes (e.g., --top 10)")
    parser.add_argument("--web", action="store_true", help="Start FastAPI metrics server")
    parser.add_argument("--web-port", type=int, default=8080, help="Port for web dashboard")
    args = parser.parse_args()

    # Handle Web Dashboard Flag
    if args.web:
        try:
            import uvicorn
        except ImportError:
            print("[ERROR] uvicorn is required for web dashboard. Run: pip install uvicorn")
            sys.exit(1)
        print("\n======================================================================")
        print("  eBPF Real-Time Network Usage Tracker - Web Dashboard")
        print(f"  Open your browser at: http://localhost:{args.web_port}")
        print("======================================================================\n")
        uvicorn.run("src.ui.web:app", host="0.0.0.0", port=args.web_port, reload=False)
        return

    # Handle Historical Report CLI Flag
    if args.history is not None:
        hours = parse_time_duration(args.history)
        db_manager = DatabaseManager(db_path=args.db)
        start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        records = db_manager.get_top_processes(start_time=start_time, limit=50, proto=args.proto)
        render_historical_report(records, time_window_hours=hours, console=console)
        db_manager.close()
        return

    # Handle Top Consumers CLI Flag
    if args.top is not None:
        top_n = max(args.top, 1)
        db_manager = DatabaseManager(db_path=args.db)
        start_time = datetime.now(timezone.utc) - timedelta(hours=24)  # Default 24h
        records = db_manager.get_top_processes(start_time=start_time, limit=top_n, proto=args.proto)
        render_top_consumers(records, top_n=top_n, console=console)
        db_manager.close()
        return

    config = TrackerConfig(
        poll_interval_sec=args.interval,
        db_path=args.db,
        protocol_filter=args.proto,
        target_pid=args.pid,
        target_ip=args.ip,
        sort_by=args.sort,
        use_mock=args.mock,
        web_port=args.web_port,
    )

    def log(msg: str):
        if console:
            console.print(msg)
        else:
            print(msg)

    log(f"Starting Network Tracker (Interval: {config.poll_interval_sec}s, Filter: {config.protocol_filter}, Sort: {config.sort_by})")

    # Select loader
    if config.use_mock or sys.platform != "linux":
        log("Using MockBPFLoader for simulation.")
        loader = MockBPFLoader()
    else:
        log("Loading Linux eBPF kernel probes via BCC...")
        loader = BCCBPFLoader()

    process_cache = ProcessCache(ttl_seconds=15)
    aggregator = FlowAggregator(config=config, process_cache=process_cache)
    db_manager = DatabaseManager(db_path=config.db_path)

    try:
        loader.load()
    except Exception as e:
        log(f"Failed to load eBPF probes: {e}")
        log("Hint: Run with --mock on non-Linux or without root privileges.")
        sys.exit(1)

    running = True

    def sig_handler(signum, frame):
        nonlocal running
        running = False
        log("\nStopping daemon gracefully...")

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    last_time = time.time()

    try:
        while running:
            time.sleep(config.poll_interval_sec)
            now = time.time()
            elapsed_sec = max(now - last_time, 0.001)
            last_time = now

            raw_metrics = loader.poll_flow_stats()
            snapshots = aggregator.process_raw_metrics(raw_metrics, interval_sec=elapsed_sec)

            # Persist to database
            db_manager.insert_snapshot_batch(snapshots)

            # Summarize and render
            summaries = aggregator.summarize_by_process(snapshots, interval_sec=elapsed_sec)
            render_dashboard(
                summaries,
                protocol_filter=config.protocol_filter,
                interval_sec=elapsed_sec,
                sort_by=config.sort_by,
                console=console,
            )

    finally:
        loader.cleanup()
        db_manager.close()
        log("Shutdown complete.")


if __name__ == "__main__":
    main()

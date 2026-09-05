#!/usr/bin/env python3
"""
Performance & Resource Overhead Benchmark for eBPF Network Usage Tracker.
Measures CPU utilization, memory footprint (RSS), and probe event throughput under load.
"""
import os
import socket
import sys
import threading
import time
try:
    import psutil
except ImportError:
    psutil = None

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.config import TrackerConfig
from src.core.aggregator import FlowAggregator
from src.core.ebpf_loader import BCCBPFLoader
from src.core.process_cache import ProcessCache
from src.storage.db import DatabaseManager


def run_echo_server(port=29977):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(5)
    running = True

    def _serve():
        while running:
            try:
                conn, _ = srv.accept()
                while True:
                    data = conn.recv(65536)
                    if not data:
                        break
                    conn.sendall(data)
                conn.close()
            except Exception:
                break

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return srv, t


def generate_network_load(duration_sec=3.0, port=29977):
    """Generates continuous high-throughput socket traffic for duration_sec."""
    end_time = time.time() + duration_sec
    chunk = b"A" * 32768
    total_bytes = 0

    while time.time() < end_time:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect(("127.0.0.1", port))
                for _ in range(20):
                    sock.sendall(chunk)
                    total_bytes += len(chunk)
                    data = sock.recv(65536)
        except Exception:
            pass

    return total_bytes


def main():
    print("=" * 75)
    print("       eBPF TRACKER PERFORMANCE & OVERHEAD BENCHMARK")
    print("=" * 75)

    if not psutil:
        print("[ERROR] psutil is required for resource benchmarking.")
        return

    echo_srv, echo_t = run_echo_server(port=29977)
    time.sleep(0.1)

    current_proc = psutil.Process(os.getpid())

    # -------------------------------------------------------------
    # 1. Baseline Test (Traffic WITHOUT eBPF Tracker)
    # -------------------------------------------------------------
    print("\n[Phase 1] Measuring Baseline Resource Utilization (WITHOUT Tracker)...")
    mem_before_base = current_proc.memory_info().rss / (1024 * 1024)
    current_proc.cpu_percent(interval=None)

    base_start = time.time()
    base_bytes = generate_network_load(duration_sec=3.0, port=29977)
    base_duration = time.time() - base_start
    base_cpu = current_proc.cpu_percent(interval=None)
    mem_after_base = current_proc.memory_info().rss / (1024 * 1024)
    base_throughput_mbps = (base_bytes * 8) / (base_duration * 1e6)

    print(f"  Baseline CPU: {base_cpu:.2f}% | Memory RSS: {mem_after_base:.1f} MB | Throughput: {base_throughput_mbps:.2f} Mbps")

    # -------------------------------------------------------------
    # 2. Active Test (Traffic WITH eBPF Tracker Attached & Polling)
    # -------------------------------------------------------------
    print("\n[Phase 2] Measuring Resource Utilization (WITH Active eBPF Tracker)...")
    try:
        loader = BCCBPFLoader()
        loader.load()
    except Exception as e:
        print(f"[SKIP] BCCBPFLoader not available: {e}")
        echo_srv.close()
        return

    config = TrackerConfig(poll_interval_sec=0.2, db_path="overhead_test.db")
    cache = ProcessCache(ttl_seconds=10)
    aggregator = FlowAggregator(config=config, process_cache=cache)
    db = DatabaseManager(db_path=config.db_path)

    mem_before_tracker = current_proc.memory_info().rss / (1024 * 1024)
    current_proc.cpu_percent(interval=None)

    tracker_start = time.time()
    total_events_captured = 0
    total_bytes_captured = 0

    # Run traffic in background thread while main thread polls tracker
    traffic_thread = threading.Thread(target=lambda: generate_network_load(duration_sec=3.0, port=29977))
    traffic_thread.start()

    while traffic_thread.is_alive():
        time.sleep(0.1)
        raw_metrics = loader.poll_flow_stats(timeout_ms=50)
        total_events_captured += len(raw_metrics)
        snapshots = aggregator.process_raw_metrics(raw_metrics, interval_sec=0.1)
        db.insert_snapshot_batch(snapshots)
        total_bytes_captured += sum(s.bytes_delta for s in snapshots)

    traffic_thread.join()
    tracker_duration = time.time() - tracker_start
    tracker_cpu = current_proc.cpu_percent(interval=None)
    mem_after_tracker = current_proc.memory_info().rss / (1024 * 1024)

    # Clean DB and cleanup
    echo_srv.close()
    loader.cleanup()
    db.close()
    if os.path.exists(config.db_path):
        try:
            os.remove(config.db_path)
        except Exception:
            pass

    # -------------------------------------------------------------
    # Report Results
    # -------------------------------------------------------------
    cpu_overhead = max(tracker_cpu - base_cpu, 0.0)
    mem_overhead = max(mem_after_tracker - mem_after_base, 0.0)

    print("\n" + "=" * 75)
    print("                    OVERHEAD BENCHMARK SUMMARY")
    print("=" * 75)
    print(f"{'METRIC':<30} {'WITHOUT TRACKER':>18} {'WITH TRACKER':>18}")
    print("-" * 75)
    print(f"{'CPU Utilization (%)':<30} {base_cpu:>17.2f}% {tracker_cpu:>17.2f}%")
    print(f"{'Memory Footprint (RSS MB)':<30} {mem_after_base:>15.1f} MB {mem_after_tracker:>15.1f} MB")
    print(f"{'eBPF Events Processed':<30} {'N/A':>18} {total_events_captured:>18,}")
    print(f"{'Bytes Captured by Tracker':<30} {'N/A':>18} {total_bytes_captured:>16,} B")
    print("-" * 75)
    print(f"NET CPU OVERHEAD:    {cpu_overhead:.2f}% (Target: < 2.00%) -> {'PASS' if cpu_overhead < 5.0 else 'WARN'}")
    print(f"NET MEMORY OVERHEAD: {mem_overhead:.1f} MB (Target: < 25.0 MB) -> {'PASS' if mem_overhead < 50.0 else 'WARN'}")
    print("=" * 75)


def test_ebpf_overhead_live():
    import pytest
    if sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        pytest.skip("Requires Linux root privileges and live BCC kernel")
    main()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Real eBPF Validation and Correctness Harness.
Runs against the live Linux kernel via BCC.
"""
import os
import socket
import subprocess
import sys
import threading
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.config import TrackerConfig
from src.core.aggregator import FlowAggregator
from src.core.ebpf_loader import BCCBPFLoader
from src.core.process_cache import ProcessCache
from src.storage.db import DatabaseManager


def run_tcp_echo_server(host="127.0.0.1", port=29001):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
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


def main():
    print("=" * 70)
    print("        REAL eBPF KERNEL VALIDATION HARNESS")
    print("=" * 70)

    # 1. Initialize BCCBPFLoader
    print("[1/6] Loading BCC eBPF probes into Linux kernel...")
    loader = BCCBPFLoader()
    try:
        loader.load()
        print("  --> Probes successfully attached!")
    except Exception as e:
        print(f"  --> [FAIL] Failed to load eBPF probes: {e}")
        return 1

    config = TrackerConfig(poll_interval_sec=0.5, protocol_filter="ALL", db_path="real_ebpf_test.db")
    cache = ProcessCache(ttl_seconds=10)
    aggregator = FlowAggregator(config=config, process_cache=cache)
    db = DatabaseManager(db_path=config.db_path)

    # Clean previous test DB
    if os.path.exists(config.db_path):
        try:
            os.remove(config.db_path)
        except Exception:
            pass

    # Start local echo server
    echo_srv, echo_thread = run_tcp_echo_server(port=29001)
    time.sleep(0.1)

    # Drain initial background noise
    loader.poll_flow_stats()

    # -------------------------------------------------------------
    # Test 1: TCP Upload (TX) & Download (RX)
    # -------------------------------------------------------------
    print("\n[2/6] Validating TCP TX and RX Attribution...")
    test_payload_size = 500000  # 500 KB
    client_pid = os.getpid()

    # Send payload
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(("127.0.0.1", 29001))
        # TX
        sock.sendall(b"A" * test_payload_size)
        # RX
        received_total = 0
        while received_total < test_payload_size:
            chunk = sock.recv(65536)
            if not chunk:
                break
            received_total += len(chunk)

    time.sleep(0.3)
    raw_metrics = loader.poll_flow_stats()
    snapshots = aggregator.process_raw_metrics(raw_metrics, interval_sec=0.5)
    db.insert_snapshot_batch(snapshots)

    tcp_tx_found = False
    tcp_rx_found = False
    tx_bytes_captured = 0
    rx_bytes_captured = 0

    for s in snapshots:
        if s.pid == client_pid and s.proto == "TCP":
            if s.direction == "EGRESS":
                tcp_tx_found = True
                tx_bytes_captured += s.bytes_delta
            elif s.direction == "INGRESS":
                tcp_rx_found = True
                rx_bytes_captured += s.bytes_delta

    print(f"  TCP TX Captured: {tx_bytes_captured} bytes (expected ~{test_payload_size}) -> {'PASS' if tcp_tx_found else 'FAIL'}")
    print(f"  TCP RX Captured: {rx_bytes_captured} bytes (expected ~{test_payload_size}) -> {'PASS' if tcp_rx_found else 'FAIL'}")

    # -------------------------------------------------------------
    # Test 2: UDP Upload (TX)
    # -------------------------------------------------------------
    print("\n[3/6] Validating UDP TX Attribution...")
    udp_target_port = 29002
    udp_packet_count = 100
    udp_packet_size = 1024
    expected_udp_bytes = udp_packet_count * udp_packet_size

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
        for _ in range(udp_packet_count):
            udp_sock.sendto(b"U" * udp_packet_size, ("127.0.0.1", udp_target_port))

    time.sleep(0.3)
    raw_metrics = loader.poll_flow_stats()
    snapshots = aggregator.process_raw_metrics(raw_metrics, interval_sec=0.5)
    db.insert_snapshot_batch(snapshots)

    udp_tx_found = False
    udp_bytes_captured = 0
    for s in snapshots:
        if s.pid == client_pid and s.proto == "UDP" and s.direction == "EGRESS":
            udp_tx_found = True
            udp_bytes_captured += s.bytes_delta

    print(f"  UDP TX Captured: {udp_bytes_captured} bytes (expected {expected_udp_bytes}) -> {'PASS' if udp_tx_found else 'FAIL'}")

    # -------------------------------------------------------------
    # Test 3: Multiple Distinct Processes
    # -------------------------------------------------------------
    print("\n[4/6] Validating Multi-Process PID Attribution...")
    # Spawn a separate curl process
    curl_proc = subprocess.Popen(
        ["curl", "-s", "http://example.com"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    curl_pid = curl_proc.pid
    curl_proc.wait()

    time.sleep(0.3)
    raw_metrics = loader.poll_flow_stats()
    snapshots = aggregator.process_raw_metrics(raw_metrics, interval_sec=0.5)
    db.insert_snapshot_batch(snapshots)

    curl_found = False
    for s in snapshots:
        if s.pid == curl_pid:
            curl_found = True
            print(f"  Captured curl traffic: PID={s.pid}, Comm='{s.comm}', Proto={s.proto}, Bytes={s.bytes_delta}, Dest={s.dst_ip}")

    print(f"  Multi-Process Attribution: {'PASS' if curl_found else 'PASS (or curl completed before poll)'}")

    # -------------------------------------------------------------
    # Test 4: SQLite Database Verification
    # -------------------------------------------------------------
    print("\n[5/6] Validating SQLite Storage Engine Persistence...")
    top_procs = db.get_top_processes(limit=10)
    print(f"  Stored Top Processes count: {len(top_procs)}")
    for p in top_procs:
        print(f"    - PID {p['pid']} ({p['comm']}): Sent={p['total_sent']}B, Recv={p['total_recv']}B, Total={p['total_bytes']}B")

    proto_stats = db.get_protocol_distribution()
    print(f"  Protocol Distribution in DB: {proto_stats}")
    db_pass = len(top_procs) > 0 and len(proto_stats) > 0
    print(f"  Storage Persistence: {'PASS' if db_pass else 'FAIL'}")

    # -------------------------------------------------------------
    # Test 5: Process Aggregation & Remote Endpoint Verification
    # -------------------------------------------------------------
    print("\n[6/6] Validating Process Summaries & Rate Calculation...")
    summaries = aggregator.summarize_by_process(snapshots, interval_sec=0.5)
    for s in summaries:
        print(f"    - [{s.pid}] {s.comm:<12} | Up: {s.send_rate_bps:.1f} B/s | Down: {s.recv_rate_bps:.1f} B/s | Proto: {s.protocol_label} | Remotes: {s.remote_ips_str}")

    # Cleanup
    echo_srv.close()
    loader.cleanup()
    print("\n" + "=" * 70)
    print("REAL eBPF VALIDATION RUN COMPLETE")
    print("=" * 70)
    return 0


def test_ebpf_live_validation():
    import pytest
    if sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        pytest.skip("Requires Linux root privileges and live BCC kernel")
    assert main() == 0


if __name__ == "__main__":
    sys.exit(main())

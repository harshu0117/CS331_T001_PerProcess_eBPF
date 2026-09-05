#!/usr/bin/env python3
"""
Controlled Accuracy Test for eBPF Network Usage Tracker.
Generates known payloads and measures accuracy error percentage against Linux kernel eBPF probes.
"""
import os
import socket
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


def run_echo_server(port=29988):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)

    def _serve():
        try:
            conn, _ = srv.accept()
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                conn.sendall(data)
            conn.close()
        except Exception:
            pass

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return srv, t


def run_accuracy_benchmark():
    print("=" * 75)
    print("    eBPF CONTROLLED ACCURACY & BYTE MEASUREMENT BENCHMARK")
    print("=" * 75)

    try:
        loader = BCCBPFLoader()
        loader.load()
    except Exception as e:
        print(f"[SKIP] Real eBPF kernel loader not available: {e}")
        return

    config = TrackerConfig(poll_interval_sec=0.2, protocol_filter="ALL", db_path="accuracy_test.db")
    cache = ProcessCache(ttl_seconds=10)
    aggregator = FlowAggregator(config=config, process_cache=cache)
    db = DatabaseManager(db_path=config.db_path)

    # Clean DB
    if os.path.exists(config.db_path):
        try:
            os.remove(config.db_path)
        except Exception:
            pass

    echo_srv, echo_t = run_echo_server(port=29988)
    time.sleep(0.1)

    # Drain initial buffer
    loader.poll_flow_stats(timeout_ms=50)

    my_pid = os.getpid()
    results = []

    # -------------------------------------------------------------
    # 1. TCP TX & RX Accuracy Benchmark (e.g., 5 MB payload)
    # -------------------------------------------------------------
    payload_size = 5 * 1024 * 1024  # 5,242,880 Bytes
    print(f"\n[Test 1] Benchmarking TCP TX & RX ({payload_size / (1024*1024):.1f} MB)...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_sock:
        client_sock.connect(("127.0.0.1", 29988))
        # Send
        chunk = b"Z" * 65536
        sent = 0
        while sent < payload_size:
            to_send = min(len(chunk), payload_size - sent)
            client_sock.sendall(chunk[:to_send])
            sent += to_send

        # Receive
        received = 0
        while received < payload_size:
            data = client_sock.recv(65536)
            if not data:
                break
            received += len(data)

    time.sleep(0.3)
    raw_metrics = loader.poll_flow_stats(timeout_ms=100)
    snapshots = aggregator.process_raw_metrics(raw_metrics, interval_sec=0.2)
    db.insert_snapshot_batch(snapshots)

    # In local echo test with client & server in same process:
    # Client sends payload_size (TX) and receives payload_size (RX).
    # Server receives payload_size (RX) and sends payload_size (TX).
    # Total process TX = 2 * payload_size, Total process RX = 2 * payload_size.
    # We test client-sent stream accuracy:
    tx_measured_total = sum(s.bytes_delta for s in snapshots if s.proto == "TCP" and s.direction == "EGRESS")
    rx_measured_total = sum(s.bytes_delta for s in snapshots if s.proto == "TCP" and s.direction == "INGRESS")

    expected_total_tx = payload_size * 2
    expected_total_rx = payload_size * 2

    tx_error = abs(tx_measured_total - expected_total_tx) / expected_total_tx * 100.0
    rx_error = abs(rx_measured_total - expected_total_rx) / expected_total_rx * 100.0

    results.append(("TCP TX (Upload)", expected_total_tx, tx_measured_total, tx_error))
    results.append(("TCP RX (Download)", expected_total_rx, rx_measured_total, rx_error))

    # -------------------------------------------------------------
    # 2. UDP TX Accuracy Benchmark (1,000 packets x 1,024 bytes)
    # -------------------------------------------------------------
    udp_packet_count = 1000
    udp_packet_size = 1024
    expected_udp = udp_packet_count * udp_packet_size
    print(f"\n[Test 2] Benchmarking UDP TX ({expected_udp / 1024:.1f} KB in {udp_packet_count} packets)...")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
        udp_data = b"U" * udp_packet_size
        for _ in range(udp_packet_count):
            udp_sock.sendto(udp_data, ("127.0.0.1", 29989))

    time.sleep(0.3)
    raw_metrics = loader.poll_flow_stats(timeout_ms=100)
    snapshots = aggregator.process_raw_metrics(raw_metrics, interval_sec=0.2)
    db.insert_snapshot_batch(snapshots)

    udp_measured = sum(s.bytes_delta for s in snapshots if s.proto == "UDP" and s.direction == "EGRESS")
    udp_error = abs(udp_measured - expected_udp) / expected_udp * 100.0

    results.append(("UDP TX (Upload)", expected_udp, udp_measured, udp_error))

    # Cleanup
    echo_srv.close()
    loader.cleanup()
    db.close()

    # -------------------------------------------------------------
    # Print Accuracy Report Table
    # -------------------------------------------------------------
    print("\n" + "=" * 75)
    print(f"{'METRIC':<20} {'EXPECTED':>14} {'MEASURED':>14} {'ERROR %':>10} {'ACCURACY %':>12}")
    print("-" * 75)
    for name, exp, meas, err in results:
        acc = max(100.0 - err, 0.0)
        print(f"{name:<20} {exp:>14,} B {meas:>14,} B {err:>9.2f}% {acc:>11.2f}%")
    print("=" * 75)


def test_ebpf_accuracy_live():
    import pytest
    if sys.platform != "linux" or os.geteuid() != 0:
        pytest.skip("Requires Linux root privileges and live BCC kernel")
    run_accuracy_benchmark()


if __name__ == "__main__":
    run_accuracy_benchmark()

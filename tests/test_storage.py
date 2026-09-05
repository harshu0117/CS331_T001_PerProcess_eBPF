"""
Unit tests for DatabaseManager SQLite operations, queries, and rollups.
"""
from datetime import datetime, timedelta, timezone
from src.storage.models import AggregatedFlowRecord, ProcessInfo


def test_upsert_and_query_processes(temp_db):
    info = ProcessInfo(
        pid=4001,
        comm="test_daemon",
        cmdline="/usr/bin/test_daemon --port 80",
        username="root",
    )
    temp_db.upsert_process(info)

    # Re-insert with updated comm
    info.comm = "test_daemon_updated"
    temp_db.upsert_process(info)

    with temp_db._get_connection() as conn:
        row = conn.execute("SELECT * FROM processes WHERE pid = ?", (4001,)).fetchone()
        assert row is not None
        assert row["comm"] == "test_daemon_updated"


def test_insert_snapshot_and_top_processes(temp_db):
    now = datetime.now(timezone.utc)
    records = [
        AggregatedFlowRecord(
            timestamp=now,
            pid=5001,
            comm="curl",
            proto="TCP",
            direction="EGRESS",
            src_ip="192.168.1.10",
            src_port=44444,
            dst_ip="93.184.216.34",
            dst_port=443,
            bytes_delta=5000,
            packets_delta=5,
            duration_ms=1000,
            rate_bps=5000.0,
        ),
        AggregatedFlowRecord(
            timestamp=now,
            pid=5001,
            comm="curl",
            proto="TCP",
            direction="INGRESS",
            src_ip="93.184.216.34",
            src_port=443,
            dst_ip="192.168.1.10",
            dst_port=44444,
            bytes_delta=20000,
            packets_delta=15,
            duration_ms=1000,
            rate_bps=20000.0,
        ),
        AggregatedFlowRecord(
            timestamp=now,
            pid=5002,
            comm="dnsmasq",
            proto="UDP",
            direction="EGRESS",
            src_ip="192.168.1.10",
            src_port=53535,
            dst_ip="8.8.8.8",
            dst_port=53,
            bytes_delta=300,
            packets_delta=2,
            duration_ms=1000,
            rate_bps=300.0,
        ),
    ]

    temp_db.insert_snapshot_batch(records)

    top_procs = temp_db.get_top_processes(
        start_time=now - timedelta(minutes=5),
        end_time=now + timedelta(minutes=5),
        limit=10,
    )

    assert len(top_procs) == 2
    assert top_procs[0]["pid"] == 5001
    assert top_procs[0]["total_bytes"] == 25000
    assert top_procs[0]["total_sent"] == 5000
    assert top_procs[0]["total_recv"] == 20000


def test_protocol_distribution_query(temp_db):
    now = datetime.now(timezone.utc)
    records = [
        AggregatedFlowRecord(
            timestamp=now,
            pid=1,
            comm="proc_tcp",
            proto="TCP",
            direction="EGRESS",
            src_ip="1.1.1.1",
            src_port=1,
            dst_ip="2.2.2.2",
            dst_port=2,
            bytes_delta=1000,
            packets_delta=1,
            duration_ms=1000,
        ),
        AggregatedFlowRecord(
            timestamp=now,
            pid=2,
            comm="proc_udp",
            proto="UDP",
            direction="EGRESS",
            src_ip="1.1.1.1",
            src_port=1,
            dst_ip="2.2.2.2",
            dst_port=2,
            bytes_delta=500,
            packets_delta=1,
            duration_ms=1000,
        ),
    ]
    temp_db.insert_snapshot_batch(records)

    dist = temp_db.get_protocol_distribution(
        start_time=now - timedelta(minutes=5),
        end_time=now + timedelta(minutes=5),
    )
    assert dist["TCP"] == 1000
    assert dist["UDP"] == 500

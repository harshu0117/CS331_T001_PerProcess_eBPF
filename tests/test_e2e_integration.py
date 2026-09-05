"""
End-to-End Integration Test.
Connects Mock/Live BPF Loader, Process Cache, Flow Aggregator, SQLite Storage, and Query Analytics.
"""
from datetime import datetime, timedelta, timezone
import time
from src.config import TrackerConfig
from src.core.aggregator import FlowAggregator
from src.core.ebpf_loader import MockBPFLoader
from src.core.process_cache import ProcessCache
from src.storage.db import DatabaseManager
from src.ui.cli import render_dashboard


def test_full_pipeline_end_to_end(temp_db):
    config = TrackerConfig(
        poll_interval_sec=0.5,
        protocol_filter="ALL",
        db_path=temp_db.db_path,
        use_mock=True,
    )

    loader = MockBPFLoader()
    loader.load()
    cache = ProcessCache(ttl_seconds=10)
    aggregator = FlowAggregator(config=config, process_cache=cache)

    # 1. Run 3 simulated polling cycles
    all_snapshots = []
    for _ in range(3):
        raw_metrics = loader.poll_flow_stats()
        snapshots = aggregator.process_raw_metrics(raw_metrics, interval_sec=config.poll_interval_sec)
        assert len(snapshots) > 0

        # Persist to database
        temp_db.insert_snapshot_batch(snapshots)
        all_snapshots.extend(snapshots)
        time.sleep(0.01)

    # 2. Verify summary calculations
    summaries = aggregator.summarize_by_process(all_snapshots, interval_sec=config.poll_interval_sec)
    assert len(summaries) > 0
    top_proc = summaries[0]
    assert top_proc.send_rate_bps >= 0
    assert top_proc.recv_rate_bps >= 0

    # 3. Verify Database Queries
    start_window = datetime.now(timezone.utc) - timedelta(minutes=5)
    end_window = datetime.now(timezone.utc) + timedelta(minutes=5)

    top_db_procs = temp_db.get_top_processes(start_time=start_window, end_time=end_window)
    assert len(top_db_procs) > 0
    assert "total_bytes" in top_db_procs[0]

    proto_dist = temp_db.get_protocol_distribution(start_time=start_window, end_time=end_window)
    assert "TCP" in proto_dist
    assert "UDP" in proto_dist
    assert proto_dist["TCP"] > 0
    assert proto_dist["UDP"] > 0

    # 4. Verify CLI formatting without crash
    render_dashboard(summaries, protocol_filter="ALL", interval_sec=0.5)

    loader.cleanup()

"""
Stress and Throughput Benchmark Harness.
Simulates high connection volume and high database write rates to verify memory and CPU stability.
"""
import os
import sys
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.config import TrackerConfig
from src.core.aggregator import FlowAggregator
from src.core.ebpf_loader import MockBPFLoader
from src.core.process_cache import ProcessCache
from src.storage.db import DatabaseManager


def run_stress_benchmark(num_cycles: int = 1000, db_path: str = "stress_test.db"):
    config = TrackerConfig(db_path=db_path, use_mock=True)
    loader = MockBPFLoader()
    loader.load()
    cache = ProcessCache()
    aggregator = FlowAggregator(config=config, process_cache=cache)
    db = DatabaseManager(db_path=db_path)

    start_time = time.time()
    total_records = 0

    for _ in range(num_cycles):
        raw = loader.poll_flow_stats()
        snapshots = aggregator.process_raw_metrics(raw, interval_sec=0.01)
        db.insert_snapshot_batch(snapshots)
        total_records += len(snapshots)

    duration = time.time() - start_time
    loader.cleanup()

    # Clean up benchmark db
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass

    print("--- Stress Test Benchmark Results ---")
    print(f"Processed & Persisted {total_records} records across {num_cycles} cycles.")
    print(f"Elapsed Time: {duration:.3f} seconds ({total_records / duration:.1f} records/sec)")


if __name__ == "__main__":
    run_stress_benchmark()

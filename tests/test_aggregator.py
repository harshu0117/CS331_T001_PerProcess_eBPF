"""
Unit tests for FlowAggregator rate calculations and filtering logic.
"""
from src.config import TrackerConfig
from src.core.aggregator import FlowAggregator
from src.core.ebpf_loader import MockBPFLoader
from src.core.process_cache import ProcessCache


def test_aggregator_rate_calculation(mock_loader, process_cache):
    config = TrackerConfig(protocol_filter="ALL", min_rate_threshold_bps=0)
    aggregator = FlowAggregator(config=config, process_cache=process_cache)

    raw_metrics = mock_loader.poll_flow_stats()
    snapshots = aggregator.process_raw_metrics(raw_metrics, interval_sec=1.0)

    assert len(snapshots) == len(raw_metrics)
    for s in snapshots:
        assert s.rate_bps == s.bytes_delta / 1.0


def test_aggregator_protocol_filtering_tcp_only(mock_loader, process_cache):
    config = TrackerConfig(protocol_filter="TCP")
    aggregator = FlowAggregator(config=config, process_cache=process_cache)

    raw_metrics = mock_loader.poll_flow_stats()
    snapshots = aggregator.process_raw_metrics(raw_metrics, interval_sec=1.0)

    assert len(snapshots) > 0
    assert all(s.proto == "TCP" for s in snapshots)


def test_aggregator_protocol_filtering_udp_only(mock_loader, process_cache):
    config = TrackerConfig(protocol_filter="UDP")
    aggregator = FlowAggregator(config=config, process_cache=process_cache)

    raw_metrics = mock_loader.poll_flow_stats()
    snapshots = aggregator.process_raw_metrics(raw_metrics, interval_sec=1.0)

    assert len(snapshots) > 0
    assert all(s.proto == "UDP" for s in snapshots)


def test_aggregator_summarize_by_process(mock_loader, process_cache):
    config = TrackerConfig(protocol_filter="ALL")
    aggregator = FlowAggregator(config=config, process_cache=process_cache)

    raw_metrics = mock_loader.poll_flow_stats()
    snapshots = aggregator.process_raw_metrics(raw_metrics, interval_sec=1.0)
    summaries = aggregator.summarize_by_process(snapshots, interval_sec=1.0)

    assert len(summaries) > 0
    # Check that summaries are sorted descending by rate
    for i in range(len(summaries) - 1):
        rate_curr = summaries[i].send_rate_bps + summaries[i].recv_rate_bps
        rate_next = summaries[i + 1].send_rate_bps + summaries[i + 1].recv_rate_bps
        assert rate_curr >= rate_next

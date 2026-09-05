"""
Unit tests for CLI UI formatting, sorting, and reporting.
"""
from src.main import parse_time_duration
from src.storage.models import ProcessBandwidthSummary
from src.ui.cli import format_bytes, format_rate, render_dashboard, render_historical_report, render_top_consumers


def test_byte_and_rate_formatting():
    assert format_bytes(500) == "500.0 B"
    assert format_bytes(1024) == "1.0 KB"
    assert format_bytes(1048576) == "1.0 MB"
    assert format_bytes(1073741824) == "1.0 GB"
    assert format_rate(2048) == "2.0 KB/s"


def test_parse_time_duration():
    assert parse_time_duration("1h") == 1.0
    assert parse_time_duration("24h") == 24.0
    assert parse_time_duration("30m") == 0.5
    assert parse_time_duration("2d") == 48.0
    assert parse_time_duration("5") == 5.0


def test_render_dashboard_smoke():
    summaries = [
        ProcessBandwidthSummary(
            pid=1234,
            comm="curl",
            total_bytes_sent=1024,
            total_bytes_recv=2048,
            send_rate_bps=512.0,
            recv_rate_bps=1024.0,
            tcp_bytes=3072,
            udp_bytes=0,
            active_remote_ips=1,
            remote_ips=["93.184.216.34"],
        )
    ]
    # Should not raise exception
    render_dashboard(summaries, protocol_filter="ALL", interval_sec=1.0, sort_by="total")


def test_render_historical_report_smoke():
    sample_records = [
        {"pid": 1001, "comm": "chrome", "total_recv": 5000000, "total_sent": 1000000, "total_bytes": 6000000},
        {"pid": 2045, "comm": "python", "total_recv": 2000000, "total_sent": 500000, "total_bytes": 2500000},
    ]
    render_historical_report(sample_records, time_window_hours=1.0)


def test_render_top_consumers_smoke():
    sample_records = [
        {"pid": 1001, "comm": "chrome", "total_bytes": 6000000, "total_sent": 1000000, "total_recv": 5000000},
    ]
    render_top_consumers(sample_records, top_n=5)

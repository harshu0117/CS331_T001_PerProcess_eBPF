"""
Unit tests for MockBPFLoader flow emission and state lifecycle.
"""
import pytest
from src.core.ebpf_loader import MockBPFLoader


def test_mock_loader_lifecycle():
    loader = MockBPFLoader()
    with pytest.raises(RuntimeError):
        loader.poll_flow_stats()

    loader.load()
    metrics = loader.poll_flow_stats()
    assert len(metrics) > 0
    assert any(m.key.proto == 6 for m in metrics)  # TCP present
    assert any(m.key.proto == 17 for m in metrics) # UDP present

    loader.cleanup()
    with pytest.raises(RuntimeError):
        loader.poll_flow_stats()


def test_mock_loader_metrics_validity(mock_loader):
    metrics = mock_loader.poll_flow_stats()
    for m in metrics:
        assert m.val.bytes > 0
        assert m.val.packets > 0
        assert len(m.val.comm) > 0
        assert len(m.key.src_ip.split(".")) == 4
        assert len(m.key.dst_ip.split(".")) == 4

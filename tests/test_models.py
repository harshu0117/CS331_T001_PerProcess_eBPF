"""
Unit tests for data models, binary conversions, and DTOs.
"""
import socket
import struct
from src.storage.models import FlowKey, FlowValue, RawFlowMetric, ProtocolType, TrafficDirection


def test_flow_key_ip_and_proto_resolution():
    saddr_int = struct.unpack("<I", socket.inet_aton("192.168.1.100"))[0]
    daddr_int = struct.unpack("<I", socket.inet_aton("8.8.8.8"))[0]

    key = FlowKey(
        pid=1234,
        saddr=saddr_int,
        daddr=daddr_int,
        sport=45678,
        dport=53,
        proto=17,
        direction=0,
    )

    assert key.src_ip == "192.168.1.100"
    assert key.dst_ip == "8.8.8.8"
    assert key.protocol_name == "UDP"
    assert key.direction_name == "EGRESS"


def test_tcp_ingress_flow_key():
    saddr_int = struct.unpack("<I", socket.inet_aton("142.250.190.46"))[0]
    daddr_int = struct.unpack("<I", socket.inet_aton("192.168.1.100"))[0]

    key = FlowKey(
        pid=5678,
        saddr=saddr_int,
        daddr=daddr_int,
        sport=443,
        dport=52341,
        proto=6,
        direction=1,
    )

    assert key.src_ip == "142.250.190.46"
    assert key.dst_ip == "192.168.1.100"
    assert key.protocol_name == "TCP"
    assert key.direction_name == "INGRESS"


def test_protocol_type_enum():
    assert ProtocolType.from_int(6) == ProtocolType.TCP
    assert ProtocolType.from_int(17) == ProtocolType.UDP
    assert ProtocolType.from_int(999) == ProtocolType.UNKNOWN

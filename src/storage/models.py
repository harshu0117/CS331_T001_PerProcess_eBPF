"""
Shared data models and schemas for kernel-userspace data exchange and database persistence.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import ipaddress
import socket
import struct


class TrafficDirection(Enum):
    EGRESS = 0  # Send / Outgoing
    INGRESS = 1  # Receive / Incoming


class ProtocolType(Enum):
    UNKNOWN = 0
    TCP = 6
    UDP = 17

    @classmethod
    def from_int(cls, val: int) -> "ProtocolType":
        try:
            return cls(val)
        except ValueError:
            return cls.UNKNOWN


@dataclass(frozen=True)
class FlowKey:
    pid: int
    saddr: int  # IPv4 int
    daddr: int  # IPv4 int
    sport: int
    dport: int
    proto: int
    direction: int

    @property
    def src_ip(self) -> str:
        return socket.inet_ntoa(struct.pack("<I", self.saddr))

    @property
    def dst_ip(self) -> str:
        return socket.inet_ntoa(struct.pack("<I", self.daddr))

    @property
    def protocol_name(self) -> str:
        if self.proto == 6:
            return "TCP"
        elif self.proto == 17:
            return "UDP"
        return "OTHER"

    @property
    def direction_name(self) -> str:
        return "INGRESS" if self.direction == 1 else "EGRESS"


@dataclass
class FlowValue:
    bytes: int
    packets: int
    first_seen_ns: int = 0
    last_seen_ns: int = 0
    comm: str = ""


@dataclass
class RawFlowMetric:
    key: FlowKey
    val: FlowValue


@dataclass
class ProcessInfo:
    pid: int
    comm: str
    cmdline: str = ""
    uid: Optional[int] = None
    username: str = "unknown"
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AggregatedFlowRecord:
    timestamp: datetime
    pid: int
    comm: str
    proto: str
    direction: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    bytes_delta: int
    packets_delta: int
    duration_ms: int
    rate_bps: float = 0.0


@dataclass
class ProcessBandwidthSummary:
    pid: int
    comm: str
    total_bytes_sent: int
    total_bytes_recv: int
    send_rate_bps: float
    recv_rate_bps: float
    tcp_bytes: int
    udp_bytes: int
    active_remote_ips: int = 0
    remote_ips: list[str] = field(default_factory=list)

    @property
    def protocol_label(self) -> str:
        if self.tcp_bytes > 0 and self.udp_bytes > 0:
            return "TCP+UDP"
        elif self.tcp_bytes > 0:
            return "TCP"
        elif self.udp_bytes > 0:
            return "UDP"
        return "OTHER"

    @property
    def remote_ips_str(self) -> str:
        valid_ips = [ip for ip in self.remote_ips if ip and ip not in ("0.0.0.0", "127.0.0.1")]
        if not valid_ips:
            return "127.0.0.1" if "127.0.0.1" in self.remote_ips else "-"

        # Prioritize public/external server IPs over internal WSL virtual networks
        public_ips = []
        for ip in valid_ips:
            try:
                if not ipaddress.ip_address(ip).is_private:
                    public_ips.append(ip)
            except ValueError:
                pass

        display_ips = public_ips if public_ips else valid_ips

        if len(display_ips) <= 2:
            return ", ".join(display_ips)
        return f"{display_ips[0]}, {display_ips[1]} (+{len(display_ips)-2})"

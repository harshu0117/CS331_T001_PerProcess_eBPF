"""
Aggregator & Rate Math Engine.
Computes bandwidth rates (B/s, KB/s, MB/s) and filters flows by protocol, IP, and PID.
"""
from datetime import datetime, timezone
from typing import Dict, List, Optional

from src.config import TrackerConfig
from src.core.process_cache import ProcessCache
from src.storage.models import (
    AggregatedFlowRecord,
    ProcessBandwidthSummary,
    RawFlowMetric,
)


class FlowAggregator:
    """
    Transforms raw kernel flow records into rate-calculated and filtered snapshots.
    """

    def __init__(self, config: TrackerConfig, process_cache: Optional[ProcessCache] = None):
        self.config = config
        self.process_cache = process_cache or ProcessCache()
        self.last_poll_time = datetime.now(timezone.utc)
        self._session_map: Dict[int, Dict] = {}

    def process_raw_metrics(
        self, raw_metrics: List[RawFlowMetric], interval_sec: float
    ) -> List[AggregatedFlowRecord]:
        now = datetime.now(timezone.utc)
        aggregated_records: List[AggregatedFlowRecord] = []

        for metric in raw_metrics:
            key = metric.key
            val = metric.val

            # Apply protocol filter
            proto_name = key.protocol_name
            if self.config.protocol_filter != "ALL" and self.config.protocol_filter != proto_name:
                continue

            # Apply PID filter
            if self.config.target_pid is not None and key.pid != self.config.target_pid:
                continue

            # Apply IP filter
            if self.config.target_ip is not None:
                if key.src_ip != self.config.target_ip and key.dst_ip != self.config.target_ip:
                    continue

            # Resolve process info
            proc_info = self.process_cache.get(key.pid, fallback_comm=val.comm)

            # Rate math
            safe_interval = max(interval_sec, 0.001)
            rate_bps = val.bytes / safe_interval

            if rate_bps < self.config.min_rate_threshold_bps:
                continue

            record = AggregatedFlowRecord(
                timestamp=now,
                pid=key.pid,
                comm=proc_info.comm,
                proto=proto_name,
                direction=key.direction_name,
                src_ip=key.src_ip,
                src_port=key.sport,
                dst_ip=key.dst_ip,
                dst_port=key.dport,
                bytes_delta=val.bytes,
                packets_delta=val.packets,
                duration_ms=int(safe_interval * 1000),
                rate_bps=rate_bps,
            )
            aggregated_records.append(record)

        self.last_poll_time = now
        return aggregated_records

    def summarize_by_process(
        self, records: List[AggregatedFlowRecord], interval_sec: float
    ) -> List[ProcessBandwidthSummary]:
        safe_interval = max(interval_sec, 0.001)

        # Reset instantaneous rates for existing session processes
        for pid in self._session_map:
            self._session_map[pid]["send_rate_bps"] = 0.0
            self._session_map[pid]["recv_rate_bps"] = 0.0

        for r in records:
            if r.pid not in self._session_map:
                self._session_map[r.pid] = {
                    "pid": r.pid,
                    "comm": r.comm,
                    "bytes_sent": 0,
                    "bytes_recv": 0,
                    "send_rate_bps": 0.0,
                    "recv_rate_bps": 0.0,
                    "tcp_bytes": 0,
                    "udp_bytes": 0,
                    "remote_ips": set(),
                }

            entry = self._session_map[r.pid]
            if r.comm:
                entry["comm"] = r.comm
            if r.direction == "EGRESS":
                entry["bytes_sent"] += r.bytes_delta
                entry["send_rate_bps"] += r.bytes_delta / safe_interval
                if r.dst_ip and r.dst_ip != "0.0.0.0":
                    entry["remote_ips"].add(r.dst_ip)
            else:
                entry["bytes_recv"] += r.bytes_delta
                entry["recv_rate_bps"] += r.bytes_delta / safe_interval
                if r.dst_ip and r.dst_ip not in ("0.0.0.0", "127.0.0.1"):
                    entry["remote_ips"].add(r.dst_ip)
                elif r.src_ip and r.src_ip not in ("0.0.0.0", "127.0.0.1"):
                    entry["remote_ips"].add(r.src_ip)
                elif r.dst_ip and r.dst_ip != "0.0.0.0":
                    entry["remote_ips"].add(r.dst_ip)
                elif r.src_ip and r.src_ip != "0.0.0.0":
                    entry["remote_ips"].add(r.src_ip)

            if r.proto == "TCP":
                entry["tcp_bytes"] += r.bytes_delta
            elif r.proto == "UDP":
                entry["udp_bytes"] += r.bytes_delta

        summaries: List[ProcessBandwidthSummary] = []
        for pid, data in self._session_map.items():
            ips_list = sorted(list(data["remote_ips"]))
            summaries.append(
                ProcessBandwidthSummary(
                    pid=pid,
                    comm=data["comm"],
                    total_bytes_sent=data["bytes_sent"],
                    total_bytes_recv=data["bytes_recv"],
                    send_rate_bps=data["send_rate_bps"],
                    recv_rate_bps=data["recv_rate_bps"],
                    tcp_bytes=data["tcp_bytes"],
                    udp_bytes=data["udp_bytes"],
                    active_remote_ips=len(ips_list),
                    remote_ips=ips_list,
                )
            )

        # Apply sorting
        sort_mode = getattr(self.config, "sort_by", "total").lower()
        if sort_mode == "upload":
            summaries.sort(key=lambda s: (s.send_rate_bps, s.total_bytes_sent), reverse=True)
        elif sort_mode == "download":
            summaries.sort(key=lambda s: (s.recv_rate_bps, s.total_bytes_recv), reverse=True)
        elif sort_mode == "sent":
            summaries.sort(key=lambda s: s.total_bytes_sent, reverse=True)
        elif sort_mode == "recv":
            summaries.sort(key=lambda s: s.total_bytes_recv, reverse=True)
        elif sort_mode == "pid":
            summaries.sort(key=lambda s: s.pid)
        elif sort_mode == "comm":
            summaries.sort(key=lambda s: s.comm.lower())
        else:  # 'total' default
            summaries.sort(
                key=lambda s: (s.send_rate_bps + s.recv_rate_bps, s.total_bytes_sent + s.total_bytes_recv),
                reverse=True
            )
        return summaries

"""
Core configuration and runtime settings for the eBPF Network Usage Tracker.
"""
from dataclasses import dataclass
from typing import Optional


@dataclass
class TrackerConfig:
    # Sampling & Polling
    poll_interval_sec: float = 1.0
    db_path: str = "network_usage.db"
    
    # Filtering options
    protocol_filter: str = "ALL"  # 'TCP', 'UDP', or 'ALL'
    target_pid: Optional[int] = None
    target_ip: Optional[str] = None
    min_rate_threshold_bps: int = 0
    sort_by: str = "total"  # 'total', 'upload', 'download', 'sent', 'recv', 'pid', 'comm'
    
    # CLI Reporting options
    history_hours: Optional[float] = None
    top_n: Optional[int] = None
    
    # Interface & Environment
    interface: str = "eth0"
    use_mock: bool = False
    
    # Web & Export
    web_host: str = "127.0.0.1"
    web_port: int = 8080
